//! Claiming the global shortcut from the OS (dig_ecosystem#1839) — the platform half.
//!
//! Everything decidable lives in [`dig_app_core::hotkey`]: which chord, whether it is expressible, what
//! the app says about it. This module does one thing that cannot be tested from a `cargo test` process —
//! ask Windows for the chord and deliver the presses — and it is deliberately the whole of what is not
//! covered by a unit test, in the same spirit as the tray's `render`.
//!
//! # Why a dedicated thread with its own message loop
//!
//! `RegisterHotKey(NULL, …)` posts `WM_HOTKEY` to the message queue of the **thread that registered it**,
//! and it is a THREAD message with no window attached, so it never reaches a window procedure. Handing it
//! to tao's event loop would mean depending on tao forwarding a message it has no reason to surface, and
//! would couple the launcher's latency to the tray's 500 ms repaint tick — a launcher that opens a third
//! of a second after the keystroke feels broken.
//!
//! So the shortcut owns a thread: it registers, then pumps its own queue and hands each press to a
//! WORKER. The tray's loop is never blocked by a user standing at the bar.
//!
//! # Why the press is not handled on the message loop
//!
//! It used to be, on the reasoning that the bar "runs its own modal message loop on whatever thread
//! calls it". That stopped being true when the branded GUI replaced the native dialogs
//! (dig_ecosystem#2038): every DIG window is now drawn on ONE shared prompt thread, and the caller
//! merely BLOCKS on a channel — for as long as five minutes, since that is the input window's
//! deadline plus its grace.
//!
//! Calling that inline meant the hotkey thread stopped pumping `GetMessageW` for the whole life of a
//! prompt. Windows kept posting `WM_HOTKEY` into a queue nobody was reading, so a user who pressed
//! the chord again while a bar was up got nothing at the time and then a BURST of bars, one after
//! another, when the first finally closed (dig_ecosystem#2074). Off-thread, the loop keeps reading:
//! presses during a prompt are DROPPED, which is what a launcher should do with a double-press.
//!
//! # Release
//!
//! Windows unregisters a thread's hotkeys when the thread ends, and this thread ends only with the
//! process, so quitting DIG releases the chord — there is no state to unwind and no path on which the
//! chord outlives the app.

use dig_app_core::hotkey::{Hotkey, HotkeyError, HotkeyState};

/// Claim `shortcut` system-wide and call `on_press` on each press.
///
/// Returns what to tell the user ([`HotkeyState`]), which is the whole point of the return value: this
/// **never fails the caller**. A chord another application already owns, a desktop with no global-shortcut
/// mechanism, and a config file with a typo all produce a state the tray reports in `Status` while the
/// `Open URL…` row goes on working exactly as before. Starting the app must never depend on a shortcut.
///
/// `shortcut` arrives as a `Result` rather than a `Hotkey` so a MALFORMED setting keeps its own error
/// message all the way to the user — see [`dig_app_core::config::AgentConfig::open_bar_shortcut`].
pub fn install(
    shortcut: Result<Hotkey, HotkeyError>,
    on_press: impl Fn() + Send + Sync + 'static,
) -> HotkeyState {
    let hotkey = match shortcut {
        Ok(hotkey) => hotkey,
        // Nothing was attempted, so there is no chord to report as unavailable — only a setting to fix.
        Err(e) => {
            tracing::warn!(error = %e, "the configured shortcut could not be understood");
            return HotkeyState::Unsupported {
                reason: format!("the shortcut in your settings is not valid — {e}"),
            };
        }
    };
    let state = claim(hotkey, on_press);
    match &state {
        HotkeyState::Registered(hotkey) => tracing::info!(%hotkey, "the DIG bar shortcut is live"),
        // Not an error: another launcher holding the chord is an ordinary desktop, and the tray route is
        // untouched. Logged at warn so it is findable when a user asks why the chord does nothing.
        other => tracing::warn!(summary = %other.summary(), "no DIG bar shortcut"),
    }
    state
}

/// Ask the platform for the chord. Windows only, so far.
#[cfg(not(windows))]
fn claim(_hotkey: Hotkey, _on_press: impl Fn() + Send + Sync + 'static) -> HotkeyState {
    // Honest rather than aspirational. macOS needs a `CGEventTap`/`NSEvent` global monitor, which requires
    // the user to grant Accessibility permission — a consent flow, not a function call. Under Wayland a
    // global grab is simply not available to an ordinary client at all; the compositor owns shortcuts. Both
    // are real work with real user-visible consent steps, and claiming otherwise here would ship a chord
    // that silently does nothing on two of three platforms.
    HotkeyState::Unsupported {
        reason: "global shortcuts are not available on this platform yet".to_string(),
    }
}

/// Hand `on_press` to a worker, and give the caller a non-blocking way to trigger it.
///
/// The returned closure is what the message loop calls. It NEVER blocks and it never queues: while a
/// press is being served, further presses are dropped on the floor. See [`serve_presses`]'s two
/// requirements below — both come from what a stuck bar did to the tray (dig_ecosystem#2074).
///
/// * **Never block the caller.** The message loop must keep reading `GetMessageW`, or Windows piles
///   `WM_HOTKEY` into a queue nobody drains and the user gets a burst of bars later.
/// * **Never queue.** A person who presses the chord three times because nothing appeared wants ONE
///   bar, not three in a row — and a launcher that opens a window per historical keystroke is a
///   worse failure than one that ignores the extra presses.
///
/// Only Windows claims a chord today, so only Windows has presses to serve — but the rules above are
/// plain threads and channels, so the tests run everywhere and will still be here when a second
/// platform grows a `claim` that delivers presses.
#[cfg(any(windows, test))]
fn serve_presses(on_press: impl Fn() + Send + Sync + 'static) -> impl Fn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;

    let (wake, presses) = mpsc::channel::<()>();
    // Read by the message loop to decide whether to bother, and cleared by the worker when the
    // press it is serving is finished.
    let busy = Arc::new(AtomicBool::new(false));

    // Shared so the inline fallback below still has a way to run it if the worker cannot start.
    let on_press = Arc::new(on_press);
    let worker_press = on_press.clone();
    let serving = busy.clone();
    // Detached: it lives as long as the hotkey thread, which lives as long as the process. When the
    // sender goes the loop ends, so there is nothing to join.
    let started = std::thread::Builder::new()
        .name("dig-bar-press".to_string())
        .spawn(move || {
            while presses.recv().is_ok() {
                // `busy` is released by a DROP GUARD, not by a statement after the call. There are
                // two ways one press can cost the whole shortcut, and they need different answers:
                //
                // * the thread DIES — every later press then finds a dead channel, and because
                //   `started` is still true the inline fallback below is unreachable. That is
                //   dig_ecosystem#2074's own shape (a shared serving thread dies, a cached sender
                //   outlives it, the surface silently stops working), one thread over. The
                //   `catch_unwind` answers it.
                // * `busy` STAYS SET — every later press short-circuits at the swap below and never
                //   even reaches the dead-worker check, so the chord is equally dead and the log
                //   says nothing. Measured on the unguarded version: after one panicking press, five
                //   further presses reached the handler zero times.
                //
                // A guard covers the second whatever happens to the first, including a future
                // refactor that moves or removes the `catch_unwind` above it.
                let _release = Release(&serving);
                struct Release<'a>(&'a AtomicBool);
                impl Drop for Release<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::SeqCst);
                    }
                }

                // `on_press` opens the DIG bar through the very prompt path this change hardens, so
                // it is not exotic code: it can panic.
                let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker_press();
                }));
                if served.is_err() {
                    tracing::error!(
                        "the DIG bar handler panicked; the press was dropped and the shortcut \
                         stays live"
                    );
                }
            }
        })
        .map_err(|e| {
            // A worker that will not spawn must not silently swallow the chord. Serving presses
            // inline is what this did before, and a message loop that stalls while the bar is up is
            // worse than one that does not — but both are better than a shortcut that does nothing.
            tracing::warn!(error = %e, "the DIG bar press worker could not start; presses will be served on the message loop");
        })
        .is_ok();

    move || {
        if !started {
            on_press();
            return;
        }
        // `swap` rather than load-then-store: two presses that arrive together must not both see
        // "not busy" and both wake the worker.
        if busy.swap(true, Ordering::SeqCst) {
            tracing::debug!("the DIG bar is already open; ignoring the extra press");
            return;
        }
        if wake.send(()).is_err() {
            // The worker is gone despite the guard around it. Nothing here can bring it back — but
            // a shortcut that silently stops working is the defect this whole change is about, so
            // it says so and names the only remedy.
            tracing::error!(
                "the DIG bar press worker is gone; the keyboard shortcut will not open the bar \
                 again until DIG is restarted"
            );
            busy.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(windows)]
fn claim(hotkey: Hotkey, on_press: impl Fn() + Send + Sync + 'static) -> HotkeyState {
    use std::sync::mpsc;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, HOT_KEY_MODIFIERS};
    use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

    /// This process's id for the chord. Any value in 0x0000–0xBFFF is ours to choose; there is only one.
    const HOTKEY_ID: i32 = 1;

    let (report, registered) = mpsc::channel();
    std::thread::Builder::new()
        .name("dig-bar-hotkey".to_string())
        .spawn(move || {
            // SAFETY: `RegisterHotKey` with a null window registers against THIS thread's queue, which is
            // the queue pumped below. Both arguments come from the unit-tested `hotkey` model.
            let claimed = unsafe {
                RegisterHotKey(
                    HWND::default(),
                    HOTKEY_ID,
                    HOT_KEY_MODIFIERS(hotkey.modifiers()),
                    hotkey.virtual_key(),
                )
            };
            // Report BEFORE pumping: the caller is blocked on this, and the loop below never returns.
            let _ = report.send(claimed.as_ref().err().map(|e| e.message()));
            if claimed.is_err() {
                return;
            }
            let presses = serve_presses(on_press);
            let mut message = MSG::default();
            // SAFETY: a documented message loop over this thread's own queue with a valid out-param.
            while unsafe { GetMessageW(&mut message, HWND::default(), 0, 0) }.as_bool() {
                if message.message == WM_HOTKEY {
                    presses();
                }
            }
        })
        // A thread that will not spawn is not a chord that is taken — say what happened rather than
        // implying another application holds it.
        .map_err(|e| e.to_string())
        .and_then(|_| registered.recv().map_err(|e| e.to_string()))
        .map_or_else(
            |reason| HotkeyState::Unavailable { hotkey, reason },
            |failure| match failure {
                None => HotkeyState::Registered(hotkey),
                // The overwhelmingly common cause, and the one the OS error text does not name: Windows
                // says only "Hot key is already registered", never by whom.
                Some(message) => HotkeyState::Unavailable {
                    hotkey,
                    reason: format!("{message} — another application is probably using it"),
                },
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    /// Wait for `condition`, or give up. Returns whether it came true.
    ///
    /// Polled rather than slept: the worker is a real thread, and a fixed sleep would either be
    /// flaky on a loaded CI box or slow on an idle one.
    fn within(limit: Duration, condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        condition()
    }

    /// Press until the handler has served `want` presses in total, or give up.
    ///
    /// A press made while the previous one is still in flight is DROPPED — that is the whole point
    /// of `serve_presses`, and it includes the window in which a panicking handler is still
    /// unwinding. So pressing once and waiting asserts a RACE: the counter is bumped INSIDE the
    /// handler, before the press has finished and before the drop guard releases `busy`. CI caught
    /// exactly that, three retries in a row on a slower box, where the second press landed while
    /// the first was still unwinding and was correctly dropped.
    ///
    /// Retrying is also what a person does when nothing appears, so this asserts the property that
    /// matters — the chord RECOVERS — instead of a timing assumption. A dead worker and a latched
    /// `busy` both never recover, so the mutations these tests exist to catch still fail.
    fn press_until(press: &impl Fn(), served: &AtomicUsize, want: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            press();
            if within(Duration::from_millis(250), || {
                served.load(Ordering::SeqCst) >= want
            }) {
                return true;
            }
        }
        false
    }

    /// **A press returns to the message loop immediately, however long the bar takes.**
    ///
    /// This is the whole point of the worker. `WM_HOTKEY` is a THREAD message: it is delivered to
    /// the queue of the thread that registered the chord, and if that thread stops calling
    /// `GetMessageW` the messages pile up unread. Handling a press inline stalled the loop for as
    /// long as the bar was up — up to five minutes, since the bar is drawn on the one shared prompt
    /// thread and the caller just blocks on a channel (dig_ecosystem#2074).
    ///
    /// Asserted as a TIME bound against a press that does not finish: a handler that ran inline
    /// could not return before the barrier is released, so this cannot pass by accident.
    #[test]
    fn a_press_does_not_block_the_message_loop_while_the_bar_is_up() {
        let holding = Arc::new(Barrier::new(2));
        let held = holding.clone();
        let press = serve_presses(move || {
            held.wait();
        });

        let started = Instant::now();
        press();
        let returned = started.elapsed();

        // Let the handler finish so the worker thread is not left parked on the barrier.
        holding.wait();
        assert!(
            returned < Duration::from_millis(500),
            "the message loop was held for {returned:?} by a press that had not finished — \
             WM_HOTKEY would queue up unread behind an open bar"
        );
    }

    /// **A press while the bar is already up is DROPPED, not queued.**
    ///
    /// Someone who presses the chord three times because nothing appeared wants one bar. Queueing
    /// gives them three, one after another, minutes after they gave up — which is what the unread
    /// `WM_HOTKEY` backlog did.
    #[test]
    fn presses_while_the_bar_is_open_are_dropped_rather_than_queued() {
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = opened.clone();
        let holding = Arc::new(Barrier::new(2));
        let held = holding.clone();
        let press = serve_presses(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            held.wait();
        });

        press();
        // The first press must be IN the handler before the extras arrive, or this would be
        // asserting on a race rather than on the drop rule.
        assert!(
            within(Duration::from_secs(5), || opened.load(Ordering::SeqCst)
                == 1),
            "the first press never reached the handler"
        );
        for _ in 0..5 {
            press();
        }
        holding.wait();

        // Give any wrongly-queued press time to be served, so this fails on a queue rather than
        // passing because the extras had not been processed yet.
        assert!(
            !within(Duration::from_millis(300), || opened.load(Ordering::SeqCst)
                > 1),
            "presses made while the bar was open were queued and replayed: the handler ran {} \
             times for one bar",
            opened.load(Ordering::SeqCst)
        );
    }

    /// **A handler that PANICS costs one press, not the shortcut.**
    ///
    /// Unguarded, an unwind out of `on_press` ends the worker's closure, kills the thread and drops
    /// the receiver — after which every press finds a dead channel and returns, `started` is still
    /// true so the inline fallback is unreachable, and the chord is gone for the life of the
    /// process with nothing logged. That is dig_ecosystem#2074's own shape (a shared serving thread
    /// dies, a cached sender outlives it, the surface silently stops working), reintroduced one
    /// thread over. `on_press` opens the DIG bar through the very prompt path this change hardens,
    /// so it is not exotic code: it can panic.
    ///
    /// Both halves matter. The press after the panic must reach the handler, AND `busy` must have
    /// been cleared on the panicking path — a latched `busy` ignores every later press just as
    /// permanently as a dead thread, and the second assertion is what separates them.
    #[test]
    fn a_panicking_handler_costs_one_press_and_not_the_shortcut() {
        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        let press = serve_presses(move || {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("the DIG bar handler blew up (dig_ecosystem#2074)");
            }
        });

        assert!(
            press_until(&press, &served, 1),
            "the first press never reached the handler"
        );
        assert!(
            press_until(&press, &served, 2),
            "the press after a panicking one never reached the handler — one bad press took the \
             whole shortcut down for the life of the process"
        );
        // A third, to prove the recovery is not a one-off unlatching.
        assert!(
            press_until(&press, &served, 3),
            "the shortcut stopped working two presses after a panic"
        );
    }

    /// **The chord still works on the press AFTER one finishes.**
    ///
    /// The other half of the drop rule, and the one that would break if `busy` were latched and
    /// never cleared: dropping every press after the first would be a launcher that works once.
    #[test]
    fn the_chord_works_again_once_the_bar_closes() {
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = opened.clone();
        let press = serve_presses(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        for nth in 1..=3 {
            assert!(
                press_until(&press, &opened, nth),
                "press {nth} of 3 never reached the handler — the shortcut stopped working after \
                 {} press(es)",
                opened.load(Ordering::SeqCst)
            );
        }
    }
}
