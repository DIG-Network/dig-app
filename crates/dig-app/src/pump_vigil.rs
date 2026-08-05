//! Liveness for the shell's two loops — the threads nothing else was watching.
//!
//! Not tray-gated: it is two atomics and a clock with no desktop dependency, and the property
//! worth pinning — that a loop which stops running is named rather than silent — is checkable in
//! every build.
//!
//! # Why this exists
//!
//! Four times now a tray defect has been reported as *"I click and nothing happens"*, and four times
//! the log has said nothing at all about it (dig_ecosystem#69, #78, #83, and dig-app#86). The most
//! recent one is the clearest case: the process stayed alive, the node kept writing heartbeats, the
//! prompt renderer kept working — and every tray item was dead, with not one line written about it.
//!
//! The reason the log was silent is that **every diagnostic the shell had lived inside the loop that
//! had stopped**. #83's two new WARNs — an unmapped menu id, and a click ignored while another action
//! is in flight — are both inside the `menu_events.try_recv()` drain, so a loop that has stopped
//! iterating cannot report that it has stopped iterating. Silence was indistinguishable from health.
//!
//! This module is the outside observer. A loop stamps where it is; a thread that is neither loop
//! reads the stamps and says so when one goes stale.
//!
//! # Both loops are watched, because the work split across both (dig-app#90, #97)
//!
//! The shell has two threads that can freeze a user out, and they freeze them out of different
//! things:
//!
//! - the **state loop** (`dig-app-tick`) owns every deadline the app owes a person — the clipboard
//!   timeout, the idle auto-lock, the dispatch of a menu click. It stalls silently, and everything
//!   the user is waiting on stops.
//! - the **render loop** (the tao thread) owns the native objects — `Shell_NotifyIcon` for the icon
//!   and tooltip, `set_menu` for the menu. It stalls when the Windows shell stops answering, and the
//!   tray freezes on whatever it last drew.
//!
//! Watching only the first is what dig-app#97 caught: the isolation moved the native calls to the
//! render loop and left the watchdog looking at the thread they had left, so a render loop wedged in
//! `Shell_NotifyIcon` against a hung shell froze the tray permanently with **zero log lines** — the
//! exact condition this module exists to make impossible, reintroduced by moving the work rather
//! than the instrument. So each loop carries its own [`Heartbeat`] and both are read by one
//! [`watch`] thread that is neither of them.
//!
//! # Why a PHASE and not a set of call spans
//!
//! The obvious instrument wraps each blocking OS call a loop makes and reports the one that is
//! outstanding. That instrument would have reported **nothing** for the defect actually chased here,
//! because the block was *outside* every call the loop made — in the platform's own dispatch. Any
//! future block there will be just as invisible to a call-span instrument, which is why a named
//! resting value outlived the specific defect that motivated it.
//!
//! So each loop's resting state is a real, named value rather than the absence of one, and the two
//! resting states are deliberately **not** the same kind of fact:
//!
//! - [`Phase::BetweenTicks`] is the state loop asleep for `REFRESH`, which always ends. It is
//!   BOUNDED, and a stamp stuck there is a state loop wedged upstream of anything it calls.
//! - [`Phase::Waiting`] is the render loop inside tao's dispatch — idle with nothing to draw, or
//!   parked in the nested modal loop `TrackPopupMenu` runs while a person reads the menu. It is
//!   UNBOUNDED, because a person reading a menu is not a fault and a watchdog that says it is has
//!   taught the reader to ignore it.
//!
//! **That tolerance is honestly bought, and here is its price:** a render loop wedged in tao dispatch
//! for some reason that is *not* a menu also reads as [`Phase::Waiting`] and is not reported. Nothing
//! available here tells a tracked popup apart from any other block in dispatch — `tray-icon` calls
//! `TrackPopupMenu` from inside its own window proc and offers no hook. The reportable class is
//! therefore "wedged in a native call the renderer itself makes", which is the class dig-app#97
//! named, and the gap is stated rather than papered over.
//!
//! # What this module deliberately does not do
//!
//! It observes and reports, and it recovers nothing at all. It used to recover exactly one thing: a
//! tray context menu still up past a two-minute bound, which it asked to close with a posted
//! `WM_CANCELMODE`. That exception existed because the menu ran a nested modal loop on the *state*
//! loop's own thread, so a menu that would not dismiss was an app that would not run — the rescue was
//! the difference between a lost menu and a lost process.
//!
//! The tray draws on a thread of its own now (dig-app#90). A wedged menu costs the user the menu, the
//! state loop keeps ticking, and there is nothing left here that is both stuck and safe to poke. So
//! the exception is gone with the condition that earned it: a watchdog that acts where there is
//! nothing safe to do is a watchdog with a second way to be wrong, and the general reclaim ladder
//! belongs to the window service.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Which of the shell's two loops a [`Phase`] belongs to.
///
/// Carried so a report can name the right thread and the right consequence. Getting that wrong is
/// not cosmetic: an ERROR that tells a user to restart DIG when the remedy is elsewhere is worse
/// than no line at all, and dig-app#97 found exactly that wording surviving the thread split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loop {
    /// `dig-app-tick` — the deadlines the app owes a person.
    State,
    /// The tao thread — the native objects the user looks at.
    Render,
}

impl Loop {
    /// What a fresh stall of this loop costs the user, in one sentence.
    fn first_report(self) -> &'static str {
        match self {
            Self::State => {
                "the DIG tray's state loop has stopped running; menu clicks are being dropped \
                 before they reach any handler, and the clipboard timeout and idle auto-lock have \
                 stopped with it"
            }
            Self::Render => {
                "the DIG tray's render loop is stuck inside a call to the Windows shell; the tray \
                 icon, tooltip and menu have stopped updating"
            }
        }
    }

    /// The same stall, still unresolved — and what, if anything, the reader can do about it.
    ///
    /// The two remedies genuinely differ, which is why this is not one string with the loop's name
    /// substituted in. Restarting DIG rebuilds the state loop; it does not fix a shell that has
    /// stopped answering, and telling someone otherwise sends them round a loop of their own.
    fn restatement(self) -> &'static str {
        match self {
            Self::State => {
                "the DIG tray's state loop is STILL not running; the tray will stay unresponsive \
                 until DIG is restarted"
            }
            Self::Render => {
                "the DIG tray's render loop is STILL stuck in the Windows shell; the tray cannot \
                 redraw until the shell answers, and restarting DIG will not help if the shell \
                 itself is hung"
            }
        }
    }

    /// The stall ended.
    fn recovery(self) -> &'static str {
        match self {
            Self::State => "the DIG tray's state loop is running again after a stall",
            Self::Render => "the DIG tray's render loop is drawing again after a stall",
        }
    }
}

/// Where one of the shell's loops was when it last said anything.
///
/// Grouped by loop and, within a loop, ordered by where they occur in one pass — so a reader of the
/// log can place a stall in the sequence without consulting the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// STATE LOOP, resting: asleep for `REFRESH` between two ticks.
    ///
    /// Bounded like everything else, because the sleep always ends: a stamp stuck here is a state
    /// loop blocked upstream of every call it makes, which is invisible to any instrument that only
    /// spans those calls.
    BetweenTicks = 0,
    /// STATE LOOP: inside a tick, before anything that can block.
    Tick = 1,
    /// STATE LOOP: clearing an expired clipboard copy of a recovery phrase.
    ClipboardClear = 2,
    /// STATE LOOP: draining the menu-event channel and handing actions to the worker.
    DrainClicks = 3,
    /// STATE LOOP: reading the shared session and the agent's status to build the next view.
    ReadState = 4,
    /// RENDER LOOP, resting: inside tao's dispatch, with the user closure returned.
    ///
    /// Two very different situations share this value, and neither is a fault: the loop is idle with
    /// nothing to draw, or it is parked in the nested modal loop `TrackPopupMenu` runs while a person
    /// reads the menu. Hence [`Phase::patience`] returns nothing for it. See the module docs for what
    /// that tolerance costs.
    Waiting = 5,
    /// RENDER LOOP: updating the tray icon and tooltip — `Shell_NotifyIcon`, an unbounded
    /// `SendMessage` to the shell.
    Presence = 6,
    /// RENDER LOOP: rebuilding and re-attaching the native menu — `set_menu`.
    Repaint = 7,
}

impl Phase {
    /// Every phase, so a test can range over the whole set without restating it and drifting.
    ///
    /// A hand-written list in each test is how a phase gets ADDED without acquiring the assertions
    /// that keep it honest — which is the shape dig-app#97 found here, two variants that no
    /// production code stamped still appearing in a test that read as full coverage. The compiler
    /// checks the length; the tests below check that every entry is reachable on some loop.
    #[cfg(test)]
    const ALL: [Self; 8] = [
        Self::BetweenTicks,
        Self::Tick,
        Self::ClipboardClear,
        Self::DrainClicks,
        Self::ReadState,
        Self::Waiting,
        Self::Presence,
        Self::Repaint,
    ];

    /// The phase's name as it appears in the log. Stable — it is a diagnostic contract, and support
    /// notes will quote it.
    pub fn name(self) -> &'static str {
        match self {
            Self::BetweenTicks => "between-ticks (asleep until the next tick)",
            Self::Tick => "tick",
            Self::ClipboardClear => "clipboard-clear",
            Self::DrainClicks => "drain-clicks",
            Self::ReadState => "read-state",
            Self::Waiting => "waiting (inside the platform's own dispatch)",
            Self::Presence => "presence (set_icon/set_tooltip)",
            Self::Repaint => "repaint (set_menu)",
        }
    }

    /// Which loop stamps this phase.
    fn owner(self) -> Loop {
        match self {
            Self::BetweenTicks
            | Self::Tick
            | Self::ClipboardClear
            | Self::DrainClicks
            | Self::ReadState => Loop::State,
            Self::Waiting | Self::Presence | Self::Repaint => Loop::Render,
        }
    }

    /// How long this phase may last before it is a fault, or `None` where no duration is one.
    ///
    /// ONE bound governs every phase that has one. There used to be two bands, because the tray's
    /// context menu was a phase of the state loop and had to be measured against a person reading
    /// rather than against code that should return in microseconds.
    ///
    /// The menu is not a phase of the state loop any more (dig-app#90) — but it did not stop
    /// existing, it moved. It is now part of [`Phase::Waiting`], which is why that one phase is
    /// exempt outright rather than merely patient: a bound measured against a person reading is a
    /// bound with no honest value, and the previous attempt at picking one (two minutes) is what
    /// dig-app#93 reported. Everything else here is code that should complete in microseconds, and
    /// ten seconds is already twenty missed ticks.
    fn patience(self) -> Option<Duration> {
        match self {
            Self::Waiting => None,
            _ => Some(PATIENCE),
        }
    }

    /// What to tell the reader about a stall in this phase — the likely cause, in one clause.
    ///
    /// Held beside [`Phase::name`] so the two cannot drift, and returned as a value so the choice is
    /// testable without capturing a log.
    fn advice(self) -> &'static str {
        match self {
            Self::BetweenTicks => {
                "the loop is blocked between ticks, outside anything this shell measures — its \
                 sleep should always end"
            }
            // Unreachable in a report: an unbounded phase never becomes a stall. Answered anyway,
            // because a diagnostic that can itself fail is a diagnostic that needs a diagnostic.
            Self::Waiting => {
                "the loop is inside the platform's own dispatch, which is where it rests"
            }
            _ => "the loop is blocked inside the call this phase names",
        }
    }

    /// Rebuild a phase from the byte an [`AtomicU8`] round-tripped, for a heartbeat resting at
    /// `resting`.
    ///
    /// Total rather than fallible: the only writer is [`Heartbeat::mark_at`], which always writes a
    /// discriminant this understands, and a diagnostic that could itself fail is a diagnostic that
    /// needs a diagnostic.
    ///
    /// Anything unreadable — an impossible byte, or a phase belonging to the OTHER loop — reads as
    /// this heartbeat's own resting state, which is the reading that claims least. The second case
    /// is not pedantry: the render loop rests at an UNBOUNDED phase, so a stray byte resolving to a
    /// state-loop phase would make an idle renderer look stalled after ten seconds, every time.
    fn from_byte(byte: u8, resting: Self) -> Self {
        let read = match byte {
            0 => Self::BetweenTicks,
            1 => Self::Tick,
            2 => Self::ClipboardClear,
            3 => Self::DrainClicks,
            4 => Self::ReadState,
            5 => Self::Waiting,
            6 => Self::Presence,
            7 => Self::Repaint,
            _ => return resting,
        };
        if read.owner() == resting.owner() {
            read
        } else {
            resting
        }
    }
}

/// The stamp a watched loop writes and the watcher reads.
///
/// Two atomics rather than a mutex, deliberately: the watcher must be able to read this while the loop
/// is blocked, and a lock the loop could be holding when it blocks would take the watcher down with it
/// — reintroducing, in the observer, the exact coupling being diagnosed.
#[derive(Debug)]
struct Stamp {
    /// Milliseconds since [`Heartbeat::base`] at the last mark.
    at: AtomicU64,
    /// The [`Phase`] discriminant the loop is in.
    phase: AtomicU8,
}

/// A loop's end of the instrument: stamp where you are, cheaply, often.
///
/// One per watched loop. Which loop a heartbeat belongs to is fixed at construction by its resting
/// phase and never inferred from what it happens to contain — see [`Phase::from_byte`].
#[derive(Debug, Clone)]
pub struct Heartbeat {
    stamp: Arc<Stamp>,
    /// The zero point milliseconds are measured from. `Instant` is not representable in an atomic, and
    /// a `Mutex<Instant>` would defeat the point (see [`Stamp`]).
    base: Instant,
    /// Where this loop sits when it is between pieces of work. Every guard restores to it, and an
    /// unreadable stamp reads as it.
    resting: Phase,
}

/// What the watched loop is doing right now, restored to the enclosing phase when it finishes.
///
/// `Drop` is the fast path and is deliberately **not** the only path: a phase that is never left is
/// precisely the thing being detected, and it is the watcher's clock — not this guard — that reports
/// it. (dig-app#86: `hotkey.rs:123` and `ActionWorker::busy` are both correct `Drop` releases that do
/// not survive a call which never returns.)
///
/// # Nesting is through the guard, and that is what makes a stranded phase impossible
///
/// A guard restores the phase of the guard it was created FROM — a value carried in this struct, set
/// when that outer guard was built — and a guard created from the [`Heartbeat`] itself restores
/// [`Phase::BetweenTicks`]. Neither restore target is ever read back out of the shared atomic, so no
/// stamp made outside a guard can become one. See [`Heartbeat::enter`] for the defect this replaced.
#[must_use = "the phase reverts when this guard is dropped, so it must be held for the call it names"]
pub struct InPhase<'a> {
    beat: &'a Heartbeat,
    /// The phase this guard entered — what a guard nested inside it restores to.
    phase: Phase,
    /// The phase to restore when this guard is dropped.
    restore_to: Phase,
}

impl<'a> InPhase<'a> {
    /// Enter `phase` for the duration of the returned guard, reverting to THIS guard's phase after.
    ///
    /// The only way to nest. Wrapping a blocking call inside a tick restores the tick's phase rather
    /// than the resting state, so a stall in the remainder of the tick is not misreported as a stall
    /// in platform dispatch.
    pub fn enter(&self, phase: Phase) -> InPhase<'a> {
        self.beat.mark(phase);
        InPhase {
            beat: self.beat,
            phase,
            restore_to: self.phase,
        }
    }
}

impl Drop for InPhase<'_> {
    fn drop(&mut self) {
        self.beat.mark(self.restore_to);
    }
}

impl Heartbeat {
    /// A heartbeat for a loop that rests at `resting`, whose clock starts at `base`.
    ///
    /// The base is taken rather than read so a test drives the whole instrument on fixture time. A
    /// wall-clock-only API is how a timing test comes to assert the path it was not aiming at.
    pub fn resting_at(resting: Phase, base: Instant) -> Self {
        Self {
            stamp: Arc::new(Stamp {
                at: AtomicU64::new(0),
                phase: AtomicU8::new(resting as u8),
            }),
            base,
            resting,
        }
    }

    /// A heartbeat for the state loop, on real time.
    pub fn state_loop() -> Self {
        Self::resting_at(Phase::BetweenTicks, Instant::now())
    }

    /// A heartbeat for the render loop, on real time.
    pub fn render_loop() -> Self {
        Self::resting_at(Phase::Waiting, Instant::now())
    }

    /// Record that the loop is in `phase`, as of `now`.
    ///
    /// Private, and that is the fix for dig-app#93 — see [`Heartbeat::enter`].
    fn mark_at(&self, phase: Phase, now: Instant) {
        // Saturating rather than wrapping: a clock that somehow ran backwards must not read as a
        // heartbeat from the far future, which would report a wedged loop as healthy forever.
        let millis = now.saturating_duration_since(self.base).as_millis();
        self.stamp
            .at
            .store(millis.min(u128::from(u64::MAX)) as u64, Ordering::Release);
        self.stamp.phase.store(phase as u8, Ordering::Release);
    }

    /// Record that the loop is in `phase`, now.
    ///
    /// Private, for the reason given on [`Heartbeat::enter`].
    fn mark(&self, phase: Phase) {
        self.mark_at(phase, Instant::now());
    }

    /// Begin a unit of work: enter `phase` until the returned guard drops, then rest.
    ///
    /// This is the OUTERMOST guard. Nesting goes through [`InPhase::enter`], which restores the
    /// enclosing guard's phase.
    ///
    /// # Why the resting state is this heartbeat's own constant rather than whatever was last stamped
    ///
    /// It used to read the current phase back out of the atomic and restore that, which let a phase
    /// stamped from OUTSIDE any guard become a resting state and then be re-adopted by every tick
    /// after it — one tray click pinned a phase for the life of a perfectly healthy process, along
    /// with the two-minute tolerance that phase carried, which is why dig-app#93's first ERROR
    /// arrived at `silent_for_ms=120141` instead of at ten seconds.
    ///
    /// There is no longer any stamp from outside a guard (dig-app#90 moved the tray menu off the
    /// state loop entirely), so nothing can reach that state today. The fixed target stays anyway,
    /// because it is what makes the state UNREPRESENTABLE rather than merely unreached: a restore
    /// target that is either this heartbeat's resting phase or a phase held by a live guard is
    /// bounded by a scope by construction. That property is what the private `mark` above enforces —
    /// outside this module there is no way to set a phase that nothing will clear.
    pub fn enter(&self, phase: Phase) -> InPhase<'_> {
        self.mark(phase);
        InPhase {
            beat: self,
            phase,
            restore_to: self.resting,
        }
    }

    /// Run `work` stamped as `phase`, then rest again.
    ///
    /// The scoped form of [`Heartbeat::enter`], and the one to prefer where the phase names exactly
    /// one call: the guard's lifetime becomes the call's lifetime by construction, so the two cannot
    /// drift apart as the call site grows. This is how the render loop stamps its two native calls —
    /// see `render::draw`.
    pub fn during<T>(&self, phase: Phase, work: impl FnOnce() -> T) -> T {
        let _in_phase = self.enter(phase);
        work()
    }

    /// The phase last stamped.
    pub fn phase(&self) -> Phase {
        Phase::from_byte(self.stamp.phase.load(Ordering::Acquire), self.resting)
    }

    /// How long since the loop last said anything, as of `now`.
    fn silent_for(&self, now: Instant) -> Duration {
        let marked = Duration::from_millis(self.stamp.at.load(Ordering::Acquire));
        now.saturating_duration_since(self.base)
            .saturating_sub(marked)
    }
}

/// What the watcher concluded on one look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The loop is marking time, or has already been reported and is inside its backoff.
    Quiet,
    /// The loop has gone silent, and this is the report to make.
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
    /// The loop was stalled and is marking time again. Reported once, because a stall that ended is a
    /// different and much less alarming fact than one that did not.
    Recovered {
        /// Where the loop is now it is moving again — carried so the recovery names the same loop
        /// the stall did, without this enum needing a second way to say which one.
        phase: Phase,
        /// How long the stall lasted, measured to the moment it was last observed.
        lasted: Duration,
    },
}

/// The observing end: holds only the reporting state, so [`Watcher::look`] is a pure function of the
/// stamp, the clock and this.
#[derive(Debug)]
pub struct Watcher {
    /// Scales every phase's own [`Phase::patience`]. `1.0` in production; a test shrinks it so the
    /// bound is exercised in milliseconds without redefining it. Scaling deliberately cannot turn an
    /// EXEMPT phase into a bounded one — [`Phase::Waiting`] has nothing to multiply — so a test that
    /// runs fast cannot accidentally test a different rule than the one that ships.
    scale: f64,
    /// How long to wait before re-stating a stall that has not cleared.
    restate_after: Duration,
    /// When to re-state, and therefore whether a stall is currently being reported at all.
    restate_at: Option<Instant>,
    /// The longest silence observed during the stall in progress, so a recovery can report its length.
    worst: Duration,
}

/// How long a bounded phase may be silent before it is a stall.
///
/// Sized from the state loop, which is the one that stamps on a schedule: its `REFRESH` sleep is
/// 500 ms, so it marks at least twice a second while it is healthy, and ten seconds is twenty missed
/// ticks — far beyond any scheduling hiccup and far below the "did anyone notice?" threshold of a
/// person clicking a dead tray.
///
/// The render loop stamps only when it draws, so this is not a missed-tick count there; it is how
/// long a single `Shell_NotifyIcon` or `set_menu` may take before a hung shell is the likelier
/// explanation than a slow one. Ten seconds is generous for both readings, which is why one constant
/// serves. [`Phase::Waiting`] is exempt outright rather than given a longer value — see
/// [`Phase::patience`].
pub const PATIENCE: Duration = Duration::from_secs(10);

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

    /// How long `phase` may be silent before this watcher calls it a stall, or `None` where no
    /// silence is long enough.
    fn patience_for(&self, phase: Phase) -> Option<Duration> {
        Some(phase.patience()?.mul_f64(self.scale))
    }

    /// Look at `beat` as of `now` and decide what, if anything, to say.
    pub fn look(&mut self, beat: &Heartbeat, now: Instant) -> Verdict {
        let silent_for = beat.silent_for(now);
        // The phase is read BEFORE the comparison, because it chooses which bound applies — and
        // whether one applies at all.
        let phase = beat.phase();
        let stalled = self
            .patience_for(phase)
            .is_some_and(|bound| silent_for >= bound);
        if !stalled {
            return match self.restate_at.take() {
                // It was stalled and is not any more. Say so once; `take` is what makes it once.
                Some(_) => Verdict::Recovered {
                    phase,
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
            again,
        } => tracing::error!(
            phase = phase.name(),
            silent_for_ms = silent_for.as_millis() as u64,
            cause = phase.advice(),
            "{}",
            if again {
                phase.owner().restatement()
            } else {
                phase.owner().first_report()
            }
        ),
        Verdict::Recovered { phase, lasted } => tracing::warn!(
            stalled_for_ms = lasted.as_millis() as u64,
            "{}",
            phase.owner().recovery()
        ),
    }
}

/// Watch both of the shell's loops forever, reporting every stall and every recovery.
///
/// One observer thread for two heartbeats, rather than one each. Not thrift: the thread's whole
/// qualification is that it is NEITHER watched loop, and that stays true for both of them at once —
/// whereas having each loop watch the other would make the loss of one loop the loss of the report
/// about it, which is the failure being removed.
///
/// Failing to spawn costs diagnostics and nothing else, so the caller may ignore the result — a
/// machine that cannot start an observer thread must still get a tray.
///
/// # Why it only reports
///
/// It used to also RECOVER one thing: a tray context menu still up past a two-minute bound, which it
/// asked to close with a posted `WM_CANCELMODE`. That existed because the menu ran a nested modal
/// loop on the state loop's own thread, so a menu that would not dismiss was an app that would not
/// run. The tray draws on its own thread now (dig-app#90) and a wedged menu costs the user the menu
/// alone, so there is nothing left here that is both stuck and safe to poke — and a watchdog that
/// acts where there is nothing safe to do is a watchdog with a second way to be wrong.
pub fn watch(state: Heartbeat, render: Heartbeat) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("dig-tray-vigil".to_owned())
        .spawn(move || {
            // One watcher per loop: the backoff and the worst-silence tally are per-stall state, so
            // sharing one would let a stalled state loop silence a stalled render loop.
            let mut watchers = [(state, Watcher::new()), (render, Watcher::new())];
            loop {
                std::thread::sleep(LOOK_EVERY);
                let now = Instant::now();
                for (beat, watcher) in &mut watchers {
                    report(watcher.look(beat, now));
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// A fixed zero point. Every test drives the clock from here explicitly rather than sleeping, so
    /// no assertion depends on how long the suite takes to run.
    fn base() -> Instant {
        Instant::now()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Every test below runs the SHIPPED [`PATIENCE`], shrunk by a factor of 100, so it reads as
    /// 100 ms. Derived from the production constant rather than hard-coded: a literal threshold
    /// keeps passing after the constant it was chosen to match has moved underneath it.
    const SCALE: f64 = 0.01;

    /// The shipped bound as these tests see it.
    fn bound() -> Duration {
        PATIENCE.mul_f64(SCALE)
    }

    fn watcher() -> Watcher {
        Watcher::scaled(SCALE, ms(1000))
    }

    /// A heartbeat for the loop that owns `phase`, so a fixture cannot accidentally stamp a phase on
    /// the wrong loop and then assert about a reading [`Phase::from_byte`] deliberately discards.
    fn beat_for(phase: Phase, base: Instant) -> Heartbeat {
        Heartbeat::resting_at(
            match phase.owner() {
                Loop::State => Phase::BetweenTicks,
                Loop::Render => Phase::Waiting,
            },
            base,
        )
    }

    #[test]
    fn a_loop_that_keeps_marking_is_quiet() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
        let mut watcher = watcher();
        for step in 1..20u64 {
            let now = base + ms(step * 50);
            beat.mark_at(Phase::BetweenTicks, now);
            assert_eq!(
                watcher.look(&beat, now),
                Verdict::Quiet,
                "a loop marking every 50ms under a 100ms patience must never be called stalled"
            );
        }
    }

    /// The bound, from BOTH sides. A threshold tested only from beyond it cannot tell a correct
    /// comparison from one that fires early.
    #[test]
    fn the_patience_bound_holds_from_both_sides() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
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

    /// The load-bearing assertion of the whole module: the report NAMES where the loop stopped.
    ///
    /// The nearest wrong implementation reports a stall with a constant phase — the resting state, or
    /// whatever was stamped first. So this asserts a phase that is neither the default nor the first
    /// thing marked, and the sibling tests below assert DIFFERENT ones, so a constant cannot pass
    /// them all.
    #[test]
    fn a_stall_names_the_phase_the_loop_stopped_in() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
        beat.mark_at(Phase::Tick, base);
        beat.mark_at(Phase::ReadState, base);

        assert_eq!(
            watcher().look(&beat, base + ms(200)),
            Verdict::Stalled {
                phase: Phase::ReadState,
                silent_for: ms(200),
                again: false,
            },
            "a loop that stopped while reading shared state must be reported as stopped THERE"
        );
    }

    /// The discriminator this module exists for, and the one an entry/exit-span instrument cannot
    /// express: a state loop that stopped between its ticks, upstream of every call it makes.
    ///
    /// Paired with the test above so no constant-phase implementation satisfies both.
    #[test]
    fn a_state_loop_stopped_between_ticks_is_reported_as_such() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
        // A whole healthy tick: enter every in-tick phase and leave it again, exactly as the loop
        // does, so the resting state is REACHED rather than merely never departed from. A fixture
        // that only ever stamps the default could not tell the two apart.
        {
            let tick = beat.enter(Phase::Tick);
            {
                let _inside = tick.enter(Phase::ClipboardClear);
                assert_eq!(beat.phase(), Phase::ClipboardClear);
            }
            assert_eq!(
                beat.phase(),
                Phase::Tick,
                "leaving a call must restore the ENCLOSING phase, not the resting state"
            );
        }
        assert_eq!(
            beat.phase(),
            Phase::BetweenTicks,
            "leaving the outermost guard must rest between ticks"
        );
        beat.mark_at(Phase::BetweenTicks, base);

        assert_eq!(
            watcher().look(&beat, base + ms(300)),
            Verdict::Stalled {
                phase: Phase::BetweenTicks,
                silent_for: ms(300),
                again: false,
            },
            "a loop blocked outside every call it makes must be reported as such, not as healthy \
             and not as blocked in the last call it made"
        );
    }

    /// **dig-app#97: a renderer wedged in a shell call is reported.**
    ///
    /// The condition this test exists for is the one the thread split created and left unwatched:
    /// `Shell_NotifyIcon` is an unbounded `SendMessage` to the shell, so a hung shell freezes the
    /// render loop inside [`Phase::Presence`] forever. Before this fix that produced no log line at
    /// all, because the only heartbeat in the process belonged to the thread the call had LEFT.
    ///
    /// Both sides of the bound, on the render loop specifically: an implementation that watched the
    /// render loop but never bounded any of its phases would pass a stalled-only assertion by never
    /// firing, and one that bounded them too tightly would fire on an ordinary slow draw.
    #[test]
    fn a_renderer_wedged_in_a_shell_call_is_reported() {
        for phase in [Phase::Presence, Phase::Repaint] {
            let base = base();
            let beat = Heartbeat::resting_at(Phase::Waiting, base);
            beat.mark_at(phase, base);

            assert_eq!(
                watcher().look(&beat, base + bound() - ms(1)),
                Verdict::Quiet,
                "{phase:?} one millisecond under the bound is a slow draw, not a wedge"
            );
            assert_eq!(
                watcher().look(&beat, base + bound()),
                Verdict::Stalled {
                    phase,
                    silent_for: bound(),
                    again: false,
                },
                "a render loop stuck in {phase:?} must be REPORTED, and must name that call; \
                 dig-app#97 is exactly this going unreported"
            );
        }
    }

    /// **dig-app#97, the other direction: a person reading a menu is not a fault.**
    ///
    /// `TrackPopupMenu` runs a nested modal loop inside tao's dispatch, so a menu held open reads as
    /// [`Phase::Waiting`] for as long as the person leaves it open — which on a locked workstation is
    /// hours. Reporting that as a stall is not a harmless false alarm: it teaches whoever is reading
    /// the log to skip the one line that means something.
    ///
    /// The durations are chosen from what actually happens rather than from what is convenient: the
    /// bound itself, ten times it, the two-minute band this module used to carry for exactly this
    /// case (dig-app#93), and an hour.
    ///
    /// **The control is the whole point, and it is what makes the quiet load-bearing.** A watcher
    /// that reported nothing at all for a render heartbeat — the nearest wrong fix to dig-app#97 —
    /// would satisfy every assertion above it. So the SAME heartbeat and the SAME watcher are then
    /// driven into a shell call and MUST speak.
    #[test]
    fn a_renderer_parked_in_a_menu_is_never_reported_however_long_it_lasts() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::Waiting, base);
        let mut watcher = watcher();
        beat.mark_at(Phase::Waiting, base);

        for held in [
            bound(),
            bound() * 10,
            // The band the state loop used to carry for a tracked menu, before the menu moved.
            Duration::from_secs(120).mul_f64(SCALE),
            Duration::from_secs(3600).mul_f64(SCALE),
        ] {
            assert_eq!(
                watcher.look(&beat, base + held),
                Verdict::Quiet,
                "a menu held open for {held:?} is a person reading, and MUST NOT be reported as a \
                 stall"
            );
        }

        // The control. Same heartbeat, same watcher: the only thing that changes is that the
        // renderer is now inside a call it owes an answer for.
        let now = base + Duration::from_secs(3600).mul_f64(SCALE);
        beat.mark_at(Phase::Presence, now);
        assert!(
            matches!(
                watcher.look(&beat, now + bound()),
                Verdict::Stalled {
                    phase: Phase::Presence,
                    ..
                }
            ),
            "the tolerance must belong to the WAITING phase, not to the render loop; a watcher that \
             is simply silent about this heartbeat proves nothing above"
        );
    }

    /// The whole instrument, end to end, against a thread that is genuinely blocked.
    ///
    /// The tests above drive the stamp directly, which proves the decision but not that a guard held
    /// across a call that never returns leaves the phase visible to another thread. This one wedges
    /// a real thread inside [`Heartbeat::during`] — the call the render loop makes — and reads it
    /// from outside.
    ///
    /// # What this fixture is careful about
    ///
    /// **The CLOCK is supplied even though the thread is real.** [`Watcher::look`] takes `now`, so
    /// the verdict is sampled at a chosen instant rather than by sleeping past a deadline. A fixture
    /// that slept would be a timing race on CI, and its failure mode would be a hang rather than a
    /// red — which names nothing.
    ///
    /// **The thread is released before anything is asserted**, so a failed assertion cannot leave it
    /// wedged and the `join` cannot hang on it.
    #[test]
    fn a_thread_blocked_inside_a_guard_is_visible_from_outside_it() {
        let beat = Heartbeat::resting_at(Phase::Waiting, Instant::now());
        let wedged = Arc::new(AtomicBool::new(true));

        let renderer = {
            let beat = beat.clone();
            let wedged = Arc::clone(&wedged);
            std::thread::spawn(move || {
                beat.during(Phase::Presence, || {
                    while wedged.load(Ordering::SeqCst) {
                        std::thread::sleep(ms(1));
                    }
                })
            })
        };

        // Bounded: a `during` that never stamped would leave this spinning forever, and a hang is
        // not a failure report.
        let deadline = Instant::now() + Duration::from_secs(10);
        while beat.phase() != Phase::Presence && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let seen_while_wedged = beat.phase();
        let verdict = watcher().look(&beat, Instant::now() + bound() + ms(50));

        wedged.store(false, Ordering::SeqCst);
        renderer.join().expect("the renderer thread");

        assert_eq!(
            seen_while_wedged,
            Phase::Presence,
            "a thread blocked inside `during` must be readable as being in that phase from another \
             thread; that is the entire instrument"
        );
        assert!(
            matches!(
                verdict,
                Verdict::Stalled {
                    phase: Phase::Presence,
                    ..
                }
            ),
            "and the watcher must call it a stall, having only the stamp to go on; got {verdict:?}"
        );
        assert_eq!(
            beat.phase(),
            Phase::Waiting,
            "and once the call returns the renderer must be resting again — a guard that restored \
             anything else would leave a healthy idle renderer looking wedged"
        );
    }

    /// A permanent stall must keep saying so — and must NOT say so every second.
    ///
    /// Both halves are asserted. Reporting once is the latch bug `Vigil` had; reporting every look
    /// floods the log. A test of only one half passes for an implementation that gets the other wrong.
    #[test]
    fn a_continuing_stall_restates_on_the_backoff_and_not_before() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
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
    fn a_recovered_loop_says_so_once() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
        beat.mark_at(Phase::BetweenTicks, base);
        let mut watcher = watcher();

        assert!(matches!(
            watcher.look(&beat, base + ms(250)),
            Verdict::Stalled { .. }
        ));

        beat.mark_at(Phase::BetweenTicks, base + ms(300));
        assert_eq!(
            watcher.look(&beat, base + ms(300)),
            Verdict::Recovered {
                phase: Phase::BetweenTicks,
                lasted: ms(250)
            },
            "recovery reports how long the stall lasted, measured at its worst observation"
        );

        beat.mark_at(Phase::BetweenTicks, base + ms(350));
        assert_eq!(
            watcher.look(&beat, base + ms(350)),
            Verdict::Quiet,
            "a recovery is stated once, not on every later look"
        );
    }

    /// A wedged render loop that comes back is reported as the RENDER loop recovering.
    ///
    /// Recovery carries the phase for one reason only — so the line names the same loop the stall
    /// did. An implementation that hard-coded the state loop's wording would pass every other
    /// recovery test in this module.
    #[test]
    fn a_recovered_renderer_is_named_as_the_renderer() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::Waiting, base);
        beat.mark_at(Phase::Repaint, base);
        let mut watcher = watcher();

        assert!(matches!(
            watcher.look(&beat, base + ms(250)),
            Verdict::Stalled { .. }
        ));

        beat.mark_at(Phase::Waiting, base + ms(300));
        let Verdict::Recovered { phase, .. } = watcher.look(&beat, base + ms(300)) else {
            panic!("a renderer that drew again must be reported as recovered");
        };
        assert_eq!(
            phase.owner(),
            Loop::Render,
            "the recovery line must name the loop that recovered"
        );
    }

    /// A second stall after a recovery is a fresh stall, not a restatement — the backoff state must
    /// have been cleared by the recovery.
    #[test]
    fn a_stall_after_a_recovery_is_fresh() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::BetweenTicks, base);
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

    /// Every phase round-trips through the atomic byte on ITS OWN loop's heartbeat, so a stall can
    /// name any of them. Without this a mis-numbered discriminant would silently collapse two phases
    /// into one reading.
    #[test]
    fn every_phase_round_trips_and_has_a_distinct_name() {
        for phase in Phase::ALL {
            let beat = beat_for(phase, base());
            beat.mark(phase);
            assert_eq!(beat.phase(), phase, "{phase:?} did not round-trip");
        }
        let mut names: Vec<_> = Phase::ALL.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        let distinct = names.len();
        names.dedup();
        assert_eq!(names.len(), distinct, "two phases share a log name");
    }

    /// A byte belonging to the OTHER loop reads as this heartbeat's resting state.
    ///
    /// Not defensive tidiness: the render loop rests at an UNBOUNDED phase, so a render heartbeat
    /// that resolved a stray byte to a state-loop phase would report an idle renderer as stalled ten
    /// seconds later, and keep doing it. The direction of the fallback is the property — it must
    /// claim LESS, never more.
    #[test]
    fn a_byte_from_the_other_loop_reads_as_this_loops_resting_state() {
        assert_eq!(
            Phase::from_byte(Phase::Tick as u8, Phase::Waiting),
            Phase::Waiting,
            "a state-loop phase in a render heartbeat must not be believed"
        );
        assert_eq!(
            Phase::from_byte(Phase::Repaint as u8, Phase::BetweenTicks),
            Phase::BetweenTicks,
            "nor the reverse"
        );
        assert_eq!(
            Phase::from_byte(u8::MAX, Phase::Waiting),
            Phase::Waiting,
            "and an impossible byte reads as the state that claims least"
        );
        assert_eq!(
            Phase::from_byte(Phase::Presence as u8, Phase::Waiting),
            Phase::Presence,
            "while a phase this loop really can be in must round-trip, or the fallback above is \
             swallowing everything"
        );
    }

    /// ONE bound governs every phase that HAS one, checked from both sides — and
    /// [`Phase::Waiting`] has none at all.
    ///
    /// Every phase is asserted, not a representative: the defect this replaces was one phase quietly
    /// carrying a tolerance twelve times the others (dig-app#93), which any single-phase test passes.
    ///
    /// The exemption is asserted as an exemption rather than as a very large number. Those are
    /// different claims, and only one of them is true: there is no duration for which a menu the user
    /// has not closed becomes a fault.
    #[test]
    fn every_bounded_phase_holds_its_bound_from_both_sides_and_waiting_has_none() {
        for phase in Phase::ALL {
            let base = base();
            let beat = beat_for(phase, base);
            beat.mark_at(phase, base);

            if phase.patience().is_none() {
                assert_eq!(
                    phase,
                    Phase::Waiting,
                    "only the render loop's resting phase is exempt; a new exemption needs its own \
                     reason, stated where the exemption is"
                );
                assert_eq!(
                    watcher().look(&beat, base + bound() * 1000),
                    Verdict::Quiet,
                    "{phase:?} is exempt, so no elapsed time makes it a stall"
                );
                continue;
            }

            assert_eq!(
                watcher().look(&beat, base + bound() - ms(1)),
                Verdict::Quiet,
                "{phase:?} one millisecond under the bound must NOT be a stall"
            );
            assert!(
                matches!(
                    watcher().look(&beat, base + bound()),
                    Verdict::Stalled { .. }
                ),
                "{phase:?} at the bound must be reported; a phase with a longer private tolerance \
                 is exactly the defect dig-app#93 reported"
            );
        }
    }

    /// Exactly one phase is exempt, and it is the render loop's resting state.
    ///
    /// Stated as its own assertion so that adding an exemption is a deliberate act with a test to
    /// change, rather than something a `match` arm can acquire quietly.
    #[test]
    fn only_the_render_loops_resting_phase_is_exempt_from_the_bound() {
        let exempt: Vec<_> = Phase::ALL
            .into_iter()
            .filter(|p| p.patience().is_none())
            .collect();
        assert_eq!(exempt, vec![Phase::Waiting]);
    }

    /// A stall report carries the cause of the phase it names.
    ///
    /// Asserted as a value rather than by capturing a log: a test that inspects the thing which
    /// produces a diagnostic proves nothing about whether the diagnostic ever arrives, so the choice
    /// is checked here and `report` is a total match over it.
    #[test]
    fn a_named_call_and_a_block_upstream_of_every_call_are_told_apart() {
        assert_ne!(
            Phase::ReadState.advice(),
            Phase::BetweenTicks.advice(),
            "a block inside a named call is not a block between ticks"
        );
        assert_ne!(
            Phase::Presence.advice(),
            Phase::Waiting.advice(),
            "nor is a wedged shell call the same as resting in platform dispatch"
        );
    }

    /// Each phase is attributed to the loop that actually stamps it, and the two loops' reports say
    /// different things.
    ///
    /// This is the wording half of dig-app#97. The ERROR that survived the thread split told the
    /// reader the *event loop* had stopped and that *restarting DIG* would be needed — naming the
    /// wrong thread and asserting a remedy that does not apply to the other one. A user-facing line
    /// that is confidently wrong about the fix is worse than no line.
    #[test]
    fn each_loop_reports_its_own_consequence_and_its_own_remedy() {
        assert_eq!(Phase::BetweenTicks.owner(), Loop::State);
        assert_eq!(Phase::ReadState.owner(), Loop::State);
        assert_eq!(Phase::Waiting.owner(), Loop::Render);
        assert_eq!(Phase::Presence.owner(), Loop::Render);
        assert_eq!(Phase::Repaint.owner(), Loop::Render);

        for say in [Loop::first_report, Loop::restatement, Loop::recovery] {
            assert_ne!(
                say(Loop::State),
                say(Loop::Render),
                "the two loops fail differently and are fixed differently; one shared sentence is \
                 how the wrong remedy gets printed"
            );
        }
        assert!(
            Loop::restatement(Loop::State).contains("restarted"),
            "a state loop that will not come back does need DIG restarting"
        );
        assert!(
            Loop::restatement(Loop::Render).contains("shell"),
            "a render loop wedged in the shell must not be reported as something restarting DIG \
             fixes"
        );
    }

    /// A unit of work rests at its OWN loop's resting phase, whatever was stamped before it.
    ///
    /// This is dig-app#93's regression guard, kept after the defect became unreachable, and extended
    /// for dig-app#97's second heartbeat. `enter` used to read the phase back out of the atomic and
    /// restore THAT, so any phase stamped outside a guard was adopted by the next tick as its resting
    /// state and re-adopted by every tick after it — pinning a label, and the tolerance that label
    /// carried, for the life of a healthy process.
    ///
    /// The render loop is the load-bearing half now. Its resting state is EXEMPT from the bound, so a
    /// guard that restored the state loop's constant instead would leave every finished paint sitting
    /// in a bounded phase — and an idle renderer would be reported as stalled ten seconds later,
    /// forever. A single shared constant is the nearest wrong implementation and this is the input
    /// that sees it.
    ///
    /// The second unit of work is load-bearing too: the wrong implementation is self-sustaining, so a
    /// single-pass fixture cannot tell "cleared once" from "cleared for good".
    ///
    /// # Why this reads the RAW byte and not [`Heartbeat::phase`]
    ///
    /// Two independent mechanisms keep an idle renderer out of a bounded phase: the guard restores
    /// this heartbeat's own resting phase, and [`Phase::from_byte`] discards a byte belonging to the
    /// other loop. Either one alone produces the right answer from `phase()` — which was measured,
    /// not assumed: restoring a shared `BetweenTicks` constant left every assertion in this module
    /// green, because the owner filter corrected the reading on the way back out. Reading the stamp
    /// directly is what separates the two, so each is pinned by a test that fails when it alone is
    /// removed.
    #[test]
    fn a_unit_of_work_rests_at_its_own_loops_resting_phase() {
        for (resting, stamped, working) in [
            (Phase::BetweenTicks, Phase::ReadState, Phase::Tick),
            (Phase::Waiting, Phase::Repaint, Phase::Presence),
        ] {
            let beat = Heartbeat::resting_at(resting, base());
            let stamped_byte = || beat.stamp.phase.load(Ordering::Acquire);

            beat.mark_at(stamped, base());
            assert_eq!(
                beat.phase(),
                stamped,
                "the stamp must take effect, or this test is asserting nothing"
            );

            drop(beat.enter(working));
            assert_eq!(
                stamped_byte(),
                resting as u8,
                "a {resting:?} loop must WRITE {resting:?} when a guard drops, never a constant \
                 belonging to the other loop"
            );
            assert_eq!(
                beat.phase(),
                resting,
                "a {resting:?} loop must rest at {resting:?}, never in whatever it happened to find"
            );

            drop(beat.enter(working));
            assert_eq!(stamped_byte(), resting as u8);
        }
    }

    /// A mark that cannot be placed on the clock must age like the base, never like the present.
    ///
    /// `mark_at` clamps a mark that precedes the base to zero. The direction of that clamp is the
    /// whole point: zero means "as old as the process", so the loop goes stale and the watcher
    /// complains. Clamping the other way — treating an unplaceable mark as *now* — would report a
    /// genuinely wedged loop as healthy for the life of the process, which is the failure this module
    /// exists to remove.
    #[test]
    fn an_unplaceable_mark_ages_from_the_base_rather_than_reading_as_fresh() {
        let base = base();
        let beat = Heartbeat::resting_at(Phase::Waiting, base);
        // Before the base — the clamped case.
        beat.mark_at(Phase::Presence, base - ms(5_000));

        assert_eq!(
            watcher().look(&beat, base + ms(400)),
            Verdict::Stalled {
                phase: Phase::Presence,
                silent_for: ms(400),
                again: false,
            },
            "an unplaceable mark must age from the base, so the loop still goes stale"
        );
    }
}
