//! The one process-wide activity gate, and the pump that drains it (dig-app#312).
//!
//! [`gate`] is deliberately a singleton. The whole point of #312 is that #306, #305 and #300 share
//! ONE timing rule; three gates would coalesce nothing and would each independently decide the
//! person had arrived. Callers reach it through [`hold`](crate::notify::shared::hold) and never construct their own.
//!
//! # The pump costs nothing while there is nothing to deliver
//!
//! [`pump`](crate::notify::shared::pump) is called from the tray's twice-a-second tick, so its cost in the ordinary case — an
//! empty gate — is a mutex acquisition and an `is_empty`. **The presence probe only runs when
//! something is actually waiting**, which matters because the macOS backend is a subprocess: a
//! machine with no pending notification never spawns `ioreg` at all.
//!
//! Showing a toast is likewise moved off the caller's thread. Two of the three native backends are
//! subprocesses and the tray tick must not block on one, so a release hands the notification to a
//! short-lived worker, guarded by an in-flight flag that stops a slow backend stacking threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use super::gate::{ActivityGate, HoldKey, HoldPolicy};
use super::presence::{self, Presence};
use super::Notification;

/// The process's activity gate.
fn gate() -> &'static Mutex<ActivityGate> {
    static GATE: OnceLock<Mutex<ActivityGate>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(ActivityGate::new(HoldPolicy::default())))
}

/// Whether a release is currently being drawn.
fn drawing() -> &'static AtomicBool {
    static DRAWING: AtomicBool = AtomicBool::new(false);
    &DRAWING
}

/// Offer a notification to the shared gate, detected now.
///
/// Returns whether it was taken; a refusal is the ordinary repeat suppression and is not an error.
/// **The caller decides WHETHER to notify at all** — a condition that must stay silent must never
/// reach this function.
pub fn hold(key: HoldKey, notification: Notification) -> bool {
    let Ok(mut gate) = gate().lock() else {
        // A poisoned gate has lost its timing state; dropping the notification is the honest
        // outcome, since delivering it now would be delivering it at an unknown hour.
        tracing::debug!("the activity gate is poisoned; the notification was dropped");
        return false;
    };
    gate.hold(Instant::now(), key, notification)
}

/// Expire what is stale, and deliver what is due if the person is here. Never blocks.
///
/// Call it on whatever cadence the host already repaints at.
pub fn pump() {
    pump_with(&|| presence::presence(), &draw);
}

/// [`pump`](crate::notify::shared::pump) with its two effects injected, so the empty-gate short-circuit and the release path can
/// be tested without a machine anybody has to stop touching and without drawing a real toast.
fn pump_with(sense: &dyn Fn() -> Presence, show: &dyn Fn(Notification)) {
    let Ok(mut gate) = gate().lock() else {
        return;
    };
    if gate.is_empty() {
        return; // The common case: no lock held long, no probe, no subprocess.
    }
    let now = Instant::now();
    if let Some(notification) = gate.poll(now, sense()) {
        drop(gate);
        show(notification);
    }
}

/// Clears the in-flight draw flag however the draw ends — including by panic.
///
/// # Why this is a guard and not a `store` at the end of the worker
///
/// A plain store at the end of the thread body is skipped when the body unwinds, and the flag is
/// process-wide and never reset anywhere else. So ONE panic inside a platform notification backend
/// would leave it `true` forever, every later release would be dropped at the in-flight check, and
/// the gate would go on CLEARING its held set — conditions consumed and never shown, for the life of
/// the process, with nothing anywhere reporting it. That is the exact failure this whole module
/// exists to prevent, arriving by the back door.
///
/// The flag itself is doing a real job (a slow backend must not stack threads) and is kept.
struct DrawGuard;

impl Drop for DrawGuard {
    fn drop(&mut self) {
        drawing().store(false, Ordering::SeqCst);
    }
}

/// Draw a released notification on a worker, at most one at a time.
fn draw(notification: Notification) {
    draw_with(notification, |notification| {
        super::native_notifier().show(&notification);
    });
}

/// [`draw`] with the rendering step injected, returning the worker so a test can join it.
///
/// Separated for one reason: the property that matters here — the flag is released even when the
/// backend panics — cannot be observed through the real backend, because a test run must not draw a
/// toast and must not be able to make a platform API panic on demand.
fn draw_with<F>(notification: Notification, show: F) -> Option<std::thread::JoinHandle<()>>
where
    F: FnOnce(Notification) + Send + 'static,
{
    if drawing().swap(true, Ordering::SeqCst) {
        return None;
    }
    Some(std::thread::spawn(move || {
        // Released on every exit path, panic included. See `DrawGuard`.
        let _release = DrawGuard;
        show(notification);
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// The gate is process-wide, so two tests driving it at once would each see the other's
    /// entries. This serializes them — and each case drains before it starts, so neither depends on
    /// the order they run in.
    fn exclusively() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn note(title: &str) -> Notification {
        Notification {
            title: title.to_string(),
            body: "body".to_string(),
            route: None,
        }
    }

    /// Empty the shared gate, whatever a previous case left in it.
    fn drain() {
        pump_with(&|| Presence::Present, &|_| {});
    }

    /// **An empty gate never asks whether anybody is there.**
    ///
    /// The probe counter is the assertion: on macOS the probe is a subprocess, and a tray ticking
    /// twice a second would otherwise spawn `ioreg` 172,800 times a day to answer a question about
    /// nothing. The pump is exercised repeatedly so a single stray probe is visible.
    #[test]
    fn an_empty_gate_costs_no_presence_probe() {
        let _exclusive = exclusively();
        drain();
        let probes = AtomicUsize::new(0);
        let sense = || {
            probes.fetch_add(1, Ordering::SeqCst);
            Presence::Present
        };
        let shown = Mutex::new(Vec::new());
        for _ in 0..50 {
            pump_with(&sense, &|n| shown.lock().unwrap().push(n));
        }
        assert_eq!(probes.load(Ordering::SeqCst), 0, "nothing to deliver");
        assert!(shown.lock().unwrap().is_empty());
    }

    /// **A backend that panics MUST NOT silence every future notification.**
    ///
    /// The flag is process-wide and is reset nowhere else, so without the drop guard one panic makes
    /// every later release a no-op while the gate goes on clearing its held set — conditions consumed
    /// and never shown, for the life of the process.
    ///
    /// The second draw is the assertion that makes this load-bearing: asserting only that the flag is
    /// `false` would also pass against an implementation that never set it, and asserting only that
    /// the first thread panicked would prove nothing about recovery.
    #[test]
    fn a_panicking_backend_releases_the_in_flight_flag_and_the_next_draw_still_runs() {
        let _exclusive = exclusively();

        // A panic in a worker prints a backtrace that reads like a test failure; silence it for the
        // duration of the deliberate one, then restore whatever was there.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let first = draw_with(note("boom"), |_| panic!("the platform backend fell over"))
            .expect("no draw was in flight");
        assert!(first.join().is_err(), "the deliberate panic happened");
        std::panic::set_hook(previous);

        assert!(
            !drawing().load(Ordering::SeqCst),
            "the guard released the flag on unwind"
        );

        let drawn = Mutex::new(Vec::new());
        let (tx, rx) = std::sync::mpsc::channel();
        let second = draw_with(note("after"), move |n| {
            tx.send(n).expect("the receiver outlives the worker");
        })
        .expect("a later draw is not blocked by the earlier panic");
        second.join().expect("the second draw completed");
        drawn.lock().unwrap().push(rx.recv().expect("it drew"));

        assert_eq!(drawn.lock().unwrap()[0].title, "after");
        assert!(
            !drawing().load(Ordering::SeqCst),
            "and it released the flag too"
        );
    }

    /// **The shipping `pump` is safe to call on an empty gate**, which is what the tray tick does
    /// hundreds of times an hour. It runs the REAL presence probe only if something is waiting, so
    /// on an empty gate this must complete without drawing anything or touching the platform.
    #[test]
    fn the_real_pump_is_a_no_op_on_an_empty_gate() {
        let _exclusive = exclusively();
        drain();
        for _ in 0..10 {
            pump();
        }
        assert!(
            gate().lock().unwrap().is_empty(),
            "nothing was invented to deliver"
        );
    }

    /// **A held notification reaches the renderer through the shared gate, exactly once.**
    ///
    /// This runs against the real process-wide singleton, so it also proves `hold` and `pump` are
    /// talking to the same gate — the defect a per-caller gate would introduce, and the one no
    /// unit test of `ActivityGate` alone could see.
    #[test]
    fn a_held_notification_is_drawn_once_through_the_shared_gate() {
        let _exclusive = exclusively();
        drain();
        let shown = Mutex::new(Vec::new());
        let show = |n: Notification| shown.lock().unwrap().push(n);

        assert!(hold(
            HoldKey::OutOfFunds,
            Notification {
                title: "A spend was skipped".into(),
                body: "body".into(),
                route: None,
            }
        ));
        pump_with(&|| Presence::Present, &show);
        pump_with(&|| Presence::Present, &show);

        let drawn = shown.lock().unwrap();
        assert_eq!(drawn.len(), 1, "released once, not once per tick");
        assert_eq!(drawn[0].title, "A spend was skipped");
        assert!(
            drawn[0].body.contains("detected"),
            "the copy must say when the condition arose: {}",
            drawn[0].body
        );
    }
}
