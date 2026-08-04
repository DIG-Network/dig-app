//! Liveness for the tray's own event loop — the one thread nothing else was watching.
//!
//! # Why this exists
//!
//! Four times now a tray defect has been reported as *"I click and nothing happens"*, and four times
//! the log has said nothing at all about it (dig_ecosystem#69, #78, #83, and dig-app#86). The most
//! recent one is the clearest case: the process stayed alive, the node kept writing heartbeats, the
//! prompt renderer kept working — and every tray item was dead, with not one line written about it.
//!
//! The reason the log was silent is that **every diagnostic the tray has lives inside the tao user
//! closure**, and the closure was not running. #83's two new WARNs — an unmapped menu id, and a click
//! ignored while another action is in flight — are both inside the `menu_events.try_recv()` drain, so
//! a loop that has stopped iterating cannot report that it has stopped iterating. Silence was
//! indistinguishable from health.
//!
//! This module is the outside observer. The pump stamps where it is; a thread that is not the pump
//! reads the stamp and says so when it goes stale.
//!
//! # Why a PHASE and not a set of call spans
//!
//! The obvious instrument wraps each blocking OS call the tick makes (`set_tooltip`, `set_icon`,
//! `set_menu`) and reports the one that is outstanding. That instrument would have reported **nothing**
//! for the defect actually being chased, because the leading hypothesis is a block *outside* the
//! closure entirely: `tray-icon`'s `show_tray_menu` runs `TrackPopupMenu`, a nested modal message loop,
//! inside the tray window proc inside tao's dispatch — upstream of every call the closure makes.
//!
//! So [`Phase::BetweenTicks`](crate::pump_vigil::Phase::BetweenTicks) is a real, named value rather
//! than the absence of one. A stale stamp
//! reading `BetweenTicks` means the pump is blocked in platform dispatch; a stale stamp naming a call
//! means the pump is blocked in that call. Those are different bugs with different fixes, and telling
//! them apart is the whole job.
//!
//! # What this module deliberately does not do
//!
//! It does not recover anything. It observes and it reports. A watchdog that also acts is a watchdog
//! that can be wrong in two ways, and the reclaim ladder belongs to the window service (dig-app#86),
//! which is a later step. This is the cheapest possible thing that turns a silent permanent wedge into
//! a named one, and it is worth shipping on its own.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Where the tray's event loop was when it last said anything.
///
/// Ordered by where they occur in one tick, so a reader of the log can place a stall in the sequence
/// without consulting the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Inside tao's own dispatch, with the user closure returned.
    ///
    /// The healthy resting state, and also the signature of the failure mode that motivated this
    /// module: a nested modal loop (`TrackPopupMenu` for the tray's context menu) runs here, where no
    /// diagnostic the closure owns can see it.
    BetweenTicks = 0,
    /// Inside the user closure, before anything that can block.
    Tick = 1,
    /// Clearing an expired clipboard copy of a recovery phrase.
    ClipboardClear = 2,
    /// Draining the menu-event channel and handing actions to the worker.
    DrainClicks = 3,
    /// Reading the shared session and the agent's status to build the next view.
    ReadState = 4,
    /// Updating the tray icon and tooltip — `Shell_NotifyIcon`, an unbounded `SendMessage` to the
    /// shell.
    Presence = 5,
    /// Rebuilding and re-attaching the native menu.
    Repaint = 6,
    /// The tray's context menu is up, and the loop is inside `TrackPopupMenu`.
    ///
    /// # Why this is worth telling apart from [`Phase::BetweenTicks`]
    ///
    /// Measured on a real Windows process (dig-app#86): while the tray menu is open the tao user
    /// closure **does not run at all**, so the pump goes silent for exactly as long as the person
    /// takes to read the menu. Without this phase every such pause is reported as an unexplained
    /// stall in platform dispatch — a diagnostic that is loudly wrong several times a day teaches
    /// its reader to skip it, which is how the log became useless in the first place.
    ///
    /// So the menu names itself, gets a patience measured against a *person reading*, and leaves
    /// [`Phase::BetweenTicks`] meaning what it should: blocked somewhere nobody expected.
    ///
    /// Stamped from `tray-icon`'s event handler, which runs synchronously in the tray window proc on
    /// this same thread, immediately BEFORE `show_tray_menu` — the last moment anything of ours runs
    /// before the modal loop takes the thread.
    TrayMenu = 7,
}

impl Phase {
    /// The phase's name as it appears in the log. Stable — it is a diagnostic contract, and support
    /// notes will quote it.
    pub fn name(self) -> &'static str {
        match self {
            Self::BetweenTicks => "between-ticks (inside the platform's own dispatch)",
            Self::Tick => "tick",
            Self::ClipboardClear => "clipboard-clear",
            Self::DrainClicks => "drain-clicks",
            Self::ReadState => "read-state",
            Self::Presence => "presence (set_icon/set_tooltip)",
            Self::Repaint => "repaint (set_menu)",
            Self::TrayMenu => "tray-menu (inside TrackPopupMenu)",
        }
    }

    /// How long this phase may last before it is a fault.
    ///
    /// Two bands, because the phases differ in kind and not merely in degree. Every in-closure phase
    /// is code that should complete in microseconds, so ten seconds there is already twenty missed
    /// ticks and unambiguous. [`Phase::TrayMenu`] is a **person reading a menu**, so its bound has to
    /// be measured against human dithering; two minutes is far longer than anyone browses a tray menu
    /// and far shorter than "permanent".
    fn patience(self) -> Duration {
        match self {
            Self::TrayMenu => TRAY_MENU_PATIENCE,
            _ => PATIENCE,
        }
    }

    /// What to tell the reader about a stall in this phase — the likely cause, in one clause.
    ///
    /// Held beside [`Phase::name`] so the two cannot drift, and returned as a value so the choice is
    /// testable without capturing a log.
    fn advice(self) -> &'static str {
        match self {
            Self::TrayMenu => {
                "the tray's context menu has not dismissed. A tracked popup whose \
                 SetForegroundWindow was refused cannot be dismissed by clicking away or by Escape, \
                 and it holds this loop for as long as it is up"
            }
            Self::BetweenTicks => {
                "the loop is blocked in the platform's own dispatch, outside anything this shell \
                 measures"
            }
            _ => "the loop is blocked inside the call this phase names",
        }
    }

    /// Rebuild a phase from the byte an [`AtomicU8`] round-tripped.
    ///
    /// Total rather than fallible: the only writer is [`Heartbeat::enter`], which always writes a
    /// discriminant this understands, and a diagnostic that could itself fail is a diagnostic that
    /// needs a diagnostic. An impossible byte reports the resting state, which is the reading that
    /// claims least.
    fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Tick,
            2 => Self::ClipboardClear,
            3 => Self::DrainClicks,
            4 => Self::ReadState,
            5 => Self::Presence,
            6 => Self::Repaint,
            7 => Self::TrayMenu,
            _ => Self::BetweenTicks,
        }
    }
}

/// The stamp the pump writes and the watcher reads.
///
/// Two atomics rather than a mutex, deliberately: the watcher must be able to read this while the pump
/// is blocked, and a lock the pump could be holding when it blocks would take the watcher down with it
/// — reintroducing, in the observer, the exact coupling being diagnosed.
#[derive(Debug)]
struct Stamp {
    /// Milliseconds since [`Heartbeat::base`] at the last mark.
    at: AtomicU64,
    /// The [`Phase`] discriminant the pump is in.
    phase: AtomicU8,
}

/// The pump's end of the instrument: stamp where you are, cheaply, often.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    stamp: Arc<Stamp>,
    /// The zero point milliseconds are measured from. `Instant` is not representable in an atomic, and
    /// a `Mutex<Instant>` would defeat the point (see [`Stamp`]).
    base: Instant,
}

/// What the pump is doing right now, restored to the enclosing phase when it finishes.
///
/// `Drop` is the fast path and is deliberately **not** the only path: a phase that is never left is
/// precisely the thing being detected, and it is the watcher's clock — not this guard — that reports
/// it. (dig-app#86: `hotkey.rs:123` and `ActionWorker::busy` are both correct `Drop` releases that do
/// not survive a call which never returns.)
#[must_use = "the phase reverts when this guard is dropped, so it must be held for the call it names"]
pub struct InPhase<'a> {
    beat: &'a Heartbeat,
    restore_to: Phase,
}

impl Drop for InPhase<'_> {
    fn drop(&mut self) {
        self.beat.mark(self.restore_to);
    }
}

impl Heartbeat {
    /// A heartbeat whose clock starts at `base`, resting in [`Phase::BetweenTicks`].
    ///
    /// The base is taken rather than read so a test drives the whole instrument on fixture time. A
    /// wall-clock-only API is how a timing test comes to assert the path it was not aiming at.
    pub fn starting_at(base: Instant) -> Self {
        Self {
            stamp: Arc::new(Stamp {
                at: AtomicU64::new(0),
                phase: AtomicU8::new(Phase::BetweenTicks as u8),
            }),
            base,
        }
    }

    /// A heartbeat on real time.
    pub fn now() -> Self {
        Self::starting_at(Instant::now())
    }

    /// Record that the pump is in `phase`, as of `now`.
    pub fn mark_at(&self, phase: Phase, now: Instant) {
        // Saturating rather than wrapping: a clock that somehow ran backwards must not read as a
        // heartbeat from the far future, which would report a wedged pump as healthy forever.
        let millis = now.saturating_duration_since(self.base).as_millis();
        self.stamp
            .at
            .store(millis.min(u128::from(u64::MAX)) as u64, Ordering::Release);
        self.stamp.phase.store(phase as u8, Ordering::Release);
    }

    /// Record that the pump is in `phase`, now.
    pub fn mark(&self, phase: Phase) {
        self.mark_at(phase, Instant::now());
    }

    /// Enter `phase` for the duration of the returned guard, reverting to the current phase after.
    ///
    /// Nesting is honest: wrapping a call inside a tick restores the tick's phase, not the resting
    /// state, so a stall in the remainder of the tick is not misreported as a stall in dispatch.
    pub fn enter(&self, phase: Phase) -> InPhase<'_> {
        let restore_to = self.phase();
        self.mark(phase);
        InPhase {
            beat: self,
            restore_to,
        }
    }

    /// The phase last stamped.
    pub fn phase(&self) -> Phase {
        Phase::from_byte(self.stamp.phase.load(Ordering::Acquire))
    }

    /// How long since the pump last said anything, as of `now`.
    fn silent_for(&self, now: Instant) -> Duration {
        let marked = Duration::from_millis(self.stamp.at.load(Ordering::Acquire));
        now.saturating_duration_since(self.base)
            .saturating_sub(marked)
    }
}

/// What the watcher concluded on one look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The pump is marking time, or has already been reported and is inside its backoff.
    Quiet,
    /// The pump has gone silent, and this is the report to make.
    Stalled {
        /// Where it stopped. The whole reason the instrument exists.
        phase: Phase,
        /// How long it has been silent.
        silent_for: Duration,
        /// Whether this is a re-statement of a stall already reported.
        ///
        /// A latch was the wrong shape for `Vigil` and is the wrong shape here for the same reason:
        /// the case that matters most is the permanent one, and reporting it once and then going
        /// quiet forever recreates, for the worst case specifically, the silence being removed.
        again: bool,
    },
    /// The pump was stalled and is marking time again. Reported once, because a stall that ended is a
    /// different and much less alarming fact than one that did not.
    Recovered {
        /// How long the stall lasted, measured to the moment it was last observed.
        lasted: Duration,
    },
}

/// The observing end: holds only the reporting state, so [`Watcher::look`] is a pure function of the
/// stamp, the clock and this.
#[derive(Debug)]
pub struct Watcher {
    /// Scales every phase's own [`Phase::patience`]. `1.0` in production; a test shrinks it so the
    /// whole ladder — including the deliberate gap between the two bands — is exercised in
    /// milliseconds without redefining the relationship being tested.
    scale: f64,
    /// How long to wait before re-stating a stall that has not cleared.
    restate_after: Duration,
    /// When to re-state, and therefore whether a stall is currently being reported at all.
    restate_at: Option<Instant>,
    /// The longest silence observed during the stall in progress, so a recovery can report its length.
    worst: Duration,
}

/// How long the tray's loop may be silent before it is a stall.
///
/// The loop's own `ControlFlow::WaitUntil` is 500 ms, so it stamps at least twice a second while it is
/// healthy. Ten seconds is twenty missed ticks: far beyond any scheduling hiccup, a shell call that is
/// merely slow, or a user holding the context menu open, and far below the "did anyone notice?"
/// threshold of a person clicking a dead tray.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// How long the tray's context menu may be up before it is a fault.
///
/// A different KIND of bound from [`PATIENCE`]: this one is measured against a person reading a
/// menu, not against code that should return in microseconds. Two minutes is far beyond anyone
/// browsing a nine-item tray menu, and far below the "permanent" that the defect actually is
/// (dig-app#86 held a wedged popup for 180 s and would have held it forever).
pub const TRAY_MENU_PATIENCE: Duration = Duration::from_secs(120);

/// How long before a continuing stall is stated again.
const RESTATE_AFTER: Duration = Duration::from_secs(30);

/// How often the watcher looks.
///
/// Coarse: it is detecting a ten-second silence, so sub-second resolution buys nothing and costs a
/// wakeup for the life of the process.
const LOOK_EVERY: Duration = Duration::from_secs(1);

impl Watcher {
    /// A watcher with the shipped thresholds.
    pub fn new() -> Self {
        Self::scaled(1.0, RESTATE_AFTER)
    }

    /// A watcher whose per-phase patiences are all `scale`d, so a test drives the whole ladder in
    /// milliseconds without flattening the difference between the bands it is checking.
    pub fn scaled(scale: f64, restate_after: Duration) -> Self {
        Self {
            scale,
            restate_after,
            restate_at: None,
            worst: Duration::ZERO,
        }
    }

    /// How long `phase` may be silent before this watcher calls it a stall.
    fn patience_for(&self, phase: Phase) -> Duration {
        phase.patience().mul_f64(self.scale)
    }

    /// Look at `beat` as of `now` and decide what, if anything, to say.
    pub fn look(&mut self, beat: &Heartbeat, now: Instant) -> Verdict {
        let silent_for = beat.silent_for(now);
        // The phase is read BEFORE the comparison, because it chooses which bound applies.
        let phase = beat.phase();
        if silent_for < self.patience_for(phase) {
            return match self.restate_at.take() {
                // It was stalled and is not any more. Say so once; `take` is what makes it once.
                Some(_) => Verdict::Recovered {
                    lasted: std::mem::replace(&mut self.worst, Duration::ZERO),
                },
                None => Verdict::Quiet,
            };
        }

        self.worst = self.worst.max(silent_for);
        match self.restate_at {
            None => {
                self.restate_at = Some(now + self.restate_after);
                Verdict::Stalled {
                    phase,
                    silent_for,
                    again: false,
                }
            }
            Some(due) if now >= due => {
                self.restate_at = Some(now + self.restate_after);
                Verdict::Stalled {
                    phase,
                    silent_for,
                    again: true,
                }
            }
            // Reported, and inside the backoff.
            Some(_) => Verdict::Quiet,
        }
    }
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Write `verdict` to the log.
///
/// Separate from [`Watcher::look`] so the decision is testable as a value. A test that asserts a
/// diagnostic was *produced* by inspecting the thing that produces it proves nothing about whether it
/// ever *arrives*; here the decision is asserted directly and the emission is a total match over it.
pub fn report(verdict: Verdict) {
    match verdict {
        Verdict::Quiet => {}
        Verdict::Stalled {
            phase,
            silent_for,
            again: false,
        } => tracing::error!(
            phase = phase.name(),
            silent_for_ms = silent_for.as_millis() as u64,
            cause = phase.advice(),
            "the DIG tray's event loop has stopped running; menu clicks are being dropped before \
             they reach any handler"
        ),
        Verdict::Stalled {
            phase,
            silent_for,
            again: true,
        } => tracing::error!(
            phase = phase.name(),
            silent_for_ms = silent_for.as_millis() as u64,
            cause = phase.advice(),
            "the DIG tray's event loop is STILL not running; the tray will stay unresponsive until \
             DIG is restarted"
        ),
        Verdict::Recovered { lasted } => tracing::warn!(
            stalled_for_ms = lasted.as_millis() as u64,
            "the DIG tray's event loop is running again after a stall"
        ),
    }
}

/// Whether a stall in `phase` is one this process can do anything about.
///
/// Only the tray menu is. A modal menu loop can be broken from another thread with a posted
/// `WM_CANCELMODE` (measured, dig-app#86), and breaking one chooses nothing — a dismissed menu has
/// selected no item, so no consent can be manufactured by it.
///
/// Every other phase is either a call into the shell that will return or will not, or a block in
/// platform dispatch we cannot name. There is nothing safe to poke, and a watchdog that pokes
/// anyway is a watchdog that can be wrong in a second way.
fn is_breakable(phase: Phase) -> bool {
    matches!(phase, Phase::TrayMenu)
}

/// Decide whether `verdict` calls for the breaker, having already reported it.
///
/// Split from the loop so the decision is a value a test can assert on. Returns the phase to break,
/// or `None`.
fn breakable(verdict: Verdict) -> Option<Phase> {
    match verdict {
        Verdict::Stalled { phase, .. } if is_breakable(phase) => Some(phase),
        _ => None,
    }
}

/// Watch `beat` forever, reporting every stall and — where there is something safe to do — asking
/// `breaker` to clear it.
///
/// Spawned beside the tray loop. Failing to spawn it costs diagnostics and nothing else, so the
/// caller may ignore the result — a machine that cannot start an observer thread must still get a
/// tray.
///
/// The breaker runs on THIS thread, which is the point: the tray loop is by definition not running
/// when it is needed, so a rescue dispatched from the tray loop is a rescue that never happens.
pub fn watch(
    beat: Heartbeat,
    breaker: impl Fn(Phase) + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("dig-tray-vigil".to_owned())
        .spawn(move || {
            let mut watcher = Watcher::new();
            loop {
                std::thread::sleep(LOOK_EVERY);
                let verdict = watcher.look(&beat, Instant::now());
                report(verdict);
                if let Some(phase) = breakable(verdict) {
                    breaker(phase);
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed zero point. Every test drives the clock from here explicitly rather than sleeping, so
    /// no assertion depends on how long the suite takes to run.
    fn base() -> Instant {
        Instant::now()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Every test below runs the SHIPPED patience ladder, shrunk by a factor of 100 — so
    /// [`PATIENCE`] reads as 100 ms and [`TRAY_MENU_PATIENCE`] as 1200 ms, and the *relationship*
    /// between the bands is what the tests exercise. Hard-coded test thresholds would have kept
    /// passing after a production constant changed underneath them.
    const SCALE: f64 = 0.01;

    fn watcher() -> Watcher {
        Watcher::scaled(SCALE, ms(1000))
    }

    #[test]
    fn a_pump_that_keeps_marking_is_quiet() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        let mut watcher = watcher();
        for step in 1..20u64 {
            let now = base + ms(step * 50);
            beat.mark_at(Phase::BetweenTicks, now);
            assert_eq!(
                watcher.look(&beat, now),
                Verdict::Quiet,
                "a pump marking every 50ms under a 100ms patience must never be called stalled"
            );
        }
    }

    /// The bound, from BOTH sides. A threshold tested only from beyond it cannot tell a correct
    /// comparison from one that fires early.
    #[test]
    fn the_patience_bound_holds_from_both_sides() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::Tick, base);

        assert_eq!(
            watcher().look(&beat, base + ms(99)),
            Verdict::Quiet,
            "one millisecond under the patience must NOT be a stall"
        );
        assert!(
            matches!(
                watcher().look(&beat, base + ms(100)),
                Verdict::Stalled { .. }
            ),
            "exactly at the patience MUST be a stall"
        );
    }

    /// The load-bearing assertion of the whole module: the report NAMES where the pump stopped.
    ///
    /// The nearest wrong implementation reports a stall with a constant phase — the resting state, or
    /// whatever was stamped first. So this asserts a phase that is neither the default nor the first
    /// thing marked, and the sibling test below asserts a DIFFERENT one, so a constant cannot pass
    /// both.
    #[test]
    fn a_stall_names_the_phase_the_pump_stopped_in() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::Tick, base);
        beat.mark_at(Phase::Presence, base);

        assert_eq!(
            watcher().look(&beat, base + ms(200)),
            Verdict::Stalled {
                phase: Phase::Presence,
                silent_for: ms(200),
                again: false,
            },
            "a pump that stopped inside the shell call must be reported as stopped THERE"
        );
    }

    /// The discriminator this module exists for, and the one an entry/exit-span instrument cannot
    /// express: a pump blocked OUTSIDE the closure, in platform dispatch.
    ///
    /// Paired with the test above so no constant-phase implementation satisfies both.
    #[test]
    fn a_stall_outside_the_closure_is_reported_as_between_ticks() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        // A whole healthy tick: enter every in-closure phase and leave it again, exactly as the loop
        // does, so the resting state is REACHED rather than merely never departed from. A fixture
        // that only ever stamps the default could not tell the two apart.
        beat.mark_at(Phase::Tick, base);
        {
            let _inside = beat.enter(Phase::Repaint);
            assert_eq!(beat.phase(), Phase::Repaint);
        }
        assert_eq!(
            beat.phase(),
            Phase::Tick,
            "leaving a call must restore the ENCLOSING phase, not the resting state"
        );
        beat.mark_at(Phase::BetweenTicks, base);

        assert_eq!(
            watcher().look(&beat, base + ms(300)),
            Verdict::Stalled {
                phase: Phase::BetweenTicks,
                silent_for: ms(300),
                again: false,
            },
            "a pump blocked in platform dispatch (a tracked popup menu) must be reported as such, \
             not as healthy and not as blocked in the last call it made"
        );
    }

    /// A permanent stall must keep saying so — and must NOT say so every second.
    ///
    /// Both halves are asserted. Reporting once is the latch bug `Vigil` had; reporting every look
    /// floods the log. A test of only one half passes for an implementation that gets the other wrong.
    #[test]
    fn a_continuing_stall_restates_on_the_backoff_and_not_before() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::DrainClicks, base);
        let mut watcher = watcher();

        assert!(
            matches!(
                watcher.look(&beat, base + ms(200)),
                Verdict::Stalled { again: false, .. }
            ),
            "the first report is a fresh stall"
        );
        for step in 1..10u64 {
            assert_eq!(
                watcher.look(&beat, base + ms(200) + ms(step * 50)),
                Verdict::Quiet,
                "inside the backoff the stall must not be restated"
            );
        }
        assert!(
            matches!(
                watcher.look(&beat, base + ms(1200)),
                Verdict::Stalled { again: true, .. }
            ),
            "once the backoff elapses the stall must be stated again, flagged as a restatement"
        );

        // A SECOND restatement, and a third. One restatement is not the property: `Vigil` latched
        // after its first line and went quiet forever, and the case that matters most — a permanent
        // lockout — is precisely the one that then went unreported. Found by mutation: multiplying
        // the backoff only on the restate branch left the single-restatement version of this test
        // green (dig-app#86).
        for restatement in 2..=3u64 {
            let due = ms(200) + ms(1000) * restatement as u32;
            assert_eq!(
                watcher.look(&beat, base + due - ms(50)),
                Verdict::Quiet,
                "restatement {restatement} must wait out its own backoff too"
            );
            assert!(
                matches!(
                    watcher.look(&beat, base + due),
                    Verdict::Stalled { again: true, .. }
                ),
                "a permanent stall must keep saying so — restatement {restatement} is missing"
            );
        }
    }

    /// A stall that ends is reported ONCE as a recovery, then nothing.
    #[test]
    fn a_recovered_pump_says_so_once() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::BetweenTicks, base);
        let mut watcher = watcher();

        assert!(matches!(
            watcher.look(&beat, base + ms(250)),
            Verdict::Stalled { .. }
        ));

        beat.mark_at(Phase::BetweenTicks, base + ms(300));
        assert_eq!(
            watcher.look(&beat, base + ms(300)),
            Verdict::Recovered { lasted: ms(250) },
            "recovery reports how long the stall lasted, measured at its worst observation"
        );

        beat.mark_at(Phase::BetweenTicks, base + ms(350));
        assert_eq!(
            watcher.look(&beat, base + ms(350)),
            Verdict::Quiet,
            "a recovery is stated once, not on every later look"
        );
    }

    /// A second stall after a recovery is a fresh stall, not a restatement — the backoff state must
    /// have been cleared by the recovery.
    #[test]
    fn a_stall_after_a_recovery_is_fresh() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::BetweenTicks, base);
        let mut watcher = watcher();

        assert!(matches!(
            watcher.look(&beat, base + ms(200)),
            Verdict::Stalled { again: false, .. }
        ));
        beat.mark_at(Phase::BetweenTicks, base + ms(250));
        assert!(matches!(
            watcher.look(&beat, base + ms(250)),
            Verdict::Recovered { .. }
        ));

        assert!(
            matches!(
                watcher.look(&beat, base + ms(400)),
                Verdict::Stalled { again: false, .. }
            ),
            "the second stall is a NEW problem and must be reported as one"
        );
    }

    /// Every phase round-trips through the atomic byte, so a stall can name any of them. Without this
    /// a mis-numbered discriminant would silently collapse two phases into one reading.
    #[test]
    fn every_phase_round_trips_and_has_a_distinct_name() {
        let all = [
            Phase::BetweenTicks,
            Phase::Tick,
            Phase::ClipboardClear,
            Phase::DrainClicks,
            Phase::ReadState,
            Phase::Presence,
            Phase::Repaint,
            Phase::TrayMenu,
        ];
        let beat = Heartbeat::starting_at(base());
        for phase in all {
            beat.mark(phase);
            assert_eq!(beat.phase(), phase, "{phase:?} did not round-trip");
        }
        let mut names: Vec<_> = all.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        let distinct = names.len();
        names.dedup();
        assert_eq!(names.len(), distinct, "two phases share a log name");
    }

    /// A person reading the tray menu is not a fault.
    ///
    /// Measured (dig-app#86): the tao closure does not run at all while `TrackPopupMenu` is up, so
    /// every open menu is a pump silence. At the general patience that is an ERROR saying the tray
    /// needs restarting — several times a day, wrongly — and a diagnostic that is loudly wrong in a
    /// common case is one its reader learns to skip.
    ///
    /// The nearest wrong implementation applies ONE patience to every phase. This test and the next
    /// share a single instant, so a uniform patience of either length fails one of them.
    #[test]
    fn an_open_tray_menu_is_tolerated_where_the_same_silence_elsewhere_is_not() {
        let base = base();
        // 400 ms: four times the scaled general patience, still a third of the scaled menu patience.
        let observed_at = base + ms(400);

        let menu = Heartbeat::starting_at(base);
        menu.mark_at(Phase::TrayMenu, base);
        assert_eq!(
            watcher().look(&menu, observed_at),
            Verdict::Quiet,
            "a person reading the tray menu for a moment must not be reported as a wedged tray"
        );

        let dispatch = Heartbeat::starting_at(base);
        dispatch.mark_at(Phase::BetweenTicks, base);
        assert!(
            matches!(
                watcher().look(&dispatch, observed_at),
                Verdict::Stalled {
                    phase: Phase::BetweenTicks,
                    ..
                }
            ),
            "the SAME silence with no menu open is the unexplained stall, and must be reported"
        );
    }

    /// The menu's own bound, from both sides — a tolerance that never expires is not a tolerance,
    /// and the wedge this module exists for presents exactly as a menu that never closes.
    #[test]
    fn the_tray_menu_bound_holds_from_both_sides() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        beat.mark_at(Phase::TrayMenu, base);
        let bound = TRAY_MENU_PATIENCE.mul_f64(SCALE);

        assert_eq!(
            watcher().look(&beat, base + bound - ms(1)),
            Verdict::Quiet,
            "one millisecond under the menu bound must NOT be a stall"
        );
        assert!(
            matches!(
                watcher().look(&beat, base + bound),
                Verdict::Stalled {
                    phase: Phase::TrayMenu,
                    ..
                }
            ),
            "a menu still up at its bound is the wedge, and must be reported as a menu"
        );
    }

    /// A stall report carries the cause of the phase it names, and the tray menu's cause is its own.
    ///
    /// Asserted as a value rather than by capturing a log: a test that inspects the thing which
    /// produces a diagnostic proves nothing about whether the diagnostic ever arrives, so the choice
    /// is checked here and `report` is a total match over it.
    #[test]
    fn each_phase_carries_its_own_cause_and_the_menus_is_distinct() {
        assert_ne!(
            Phase::TrayMenu.advice(),
            Phase::BetweenTicks.advice(),
            "a stuck menu and an unexplained dispatch block need different advice"
        );
        assert!(
            Phase::TrayMenu.advice().contains("SetForegroundWindow"),
            "the menu's advice must name the measured cause, so the reader is not left guessing"
        );
        assert_ne!(
            Phase::Presence.advice(),
            Phase::BetweenTicks.advice(),
            "a block inside a named call is not a block in platform dispatch"
        );
    }

    /// The breaker is offered a stuck tray menu and nothing else.
    ///
    /// The nearest wrong implementation breaks on any stall. That is not merely untidy: the other
    /// phases are a shell call that will return or will not, and a block in platform dispatch we
    /// cannot name — there is nothing safe to poke, and poking anyway gives the watchdog a second
    /// way to be wrong. So a non-menu stall is asserted to yield `None`, not merely left untested.
    #[test]
    fn only_a_stuck_tray_menu_is_offered_to_the_breaker() {
        let stall = |phase| Verdict::Stalled {
            phase,
            silent_for: ms(1),
            again: false,
        };

        assert_eq!(breakable(stall(Phase::TrayMenu)), Some(Phase::TrayMenu));

        for unbreakable in [
            Phase::BetweenTicks,
            Phase::Tick,
            Phase::ClipboardClear,
            Phase::DrainClicks,
            Phase::ReadState,
            Phase::Presence,
            Phase::Repaint,
        ] {
            assert_eq!(
                breakable(stall(unbreakable)),
                None,
                "{unbreakable:?} has nothing safe to poke and must not be broken"
            );
        }
    }

    /// A healthy pump is never broken. Both non-stall verdicts, because a breaker fired on a
    /// RECOVERY would dismiss the menu of a user who is using it perfectly normally.
    #[test]
    fn a_pump_that_is_not_stalled_is_never_broken() {
        assert_eq!(breakable(Verdict::Quiet), None);
        assert_eq!(
            breakable(Verdict::Recovered { lasted: ms(500) }),
            None,
            "a recovered pump is working; breaking its menu would close it under the user"
        );
    }

    /// A restatement is still a stall, so a menu that survived the first break is offered again.
    /// Breaking once and then giving up silently is the latch failure in another costume.
    #[test]
    fn a_restated_stall_is_offered_to_the_breaker_again() {
        assert_eq!(
            breakable(Verdict::Stalled {
                phase: Phase::TrayMenu,
                silent_for: ms(1),
                again: true,
            }),
            Some(Phase::TrayMenu),
        );
    }

    /// A mark that cannot be placed on the clock must age like the base, never like the present.
    ///
    /// `mark_at` clamps a mark that precedes the base to zero. The direction of that clamp is the
    /// whole point: zero means "as old as the process", so the pump goes stale and the watcher
    /// complains. Clamping the other way — treating an unplaceable mark as *now* — would report a
    /// genuinely wedged pump as healthy for the life of the process, which is the failure this module
    /// exists to remove.
    #[test]
    fn an_unplaceable_mark_ages_from_the_base_rather_than_reading_as_fresh() {
        let base = base();
        let beat = Heartbeat::starting_at(base);
        // Before the base — the clamped case.
        beat.mark_at(Phase::Presence, base - ms(5_000));

        assert_eq!(
            watcher().look(&beat, base + ms(400)),
            Verdict::Stalled {
                phase: Phase::Presence,
                silent_for: ms(400),
                again: false,
            },
            "an unplaceable mark must age from the base, so the pump still goes stale"
        );
    }
}
