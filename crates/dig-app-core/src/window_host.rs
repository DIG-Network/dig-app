//! Whether this host can actually open the app window — probed once, then corrected by reality.
//!
//! # Why a static probe is not enough, and what it would cost
//!
//! The tray trim (dig_ecosystem#2253) removes twenty-five verbs from the menu and puts the window in
//! their place. That is safe only while the window opens. A host that *reports* it can draw one and
//! then fails — a panicking shell, a wedged prompt thread, a display server that went away after
//! start-up — leaves a person with a four-row tray and no route to `ExplainUnopenable`,
//! `FixMissingPhrase` or `RemoveAccount`. Those are the documented ways out of a wedged account, so
//! the failure mode is not "the window did not open", it is "the escape hatches are gone".
//!
//! `confirm::gui::available()` cannot answer this. It answers *could a window host exist* — cheaply
//! and statically, because a start-up probe may not steal focus by opening a real window. So this
//! module starts from that answer and **degrades on the first OBSERVED failure**, which puts the whole
//! menu back automatically. It is the difference between a trim and a trap, and it costs one atomic.
//!
//! # It only ever degrades
//!
//! There is no path back to [`WindowHost::Available`] within a process. A host that failed once may
//! well fail again, and a menu that grew and shrank as attempts succeeded and failed would move rows
//! under the cursor — the instability a FIXED spine exists to prevent
//! ([`crate::tray_menu::build`]). Restarting the app re-probes, which is the honest reset.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::tray_menu::WindowHost;

/// The observed answer for one process.
///
/// A type rather than a bare static so the rule can be tested against an instance a test owns.
/// Asserting a process-global latch means the first test to trip it decides what every later test
/// sees, and the suite's answer then depends on the order it happened to run in.
#[derive(Debug, Default)]
pub struct HostObservation {
    /// Set the first time an attempt to open the window is seen to fail. Never cleared.
    failed: AtomicBool,
}

impl HostObservation {
    /// A host that has not been seen to fail yet.
    pub const fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
        }
    }

    /// Record that an attempt to open the window failed. Idempotent.
    ///
    /// Called from the two places a failure is genuinely observed: the queue refusing the request,
    /// and `run_native` returning an error or the shell job panicking.
    pub fn note_failure(&self) {
        if !self.failed.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                "the DIG app window could not be opened; the tray menu is going back to its full \
                 form so nothing becomes unreachable"
            );
        }
    }

    /// Whether a failure has been observed.
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    /// This host's answer right now, given what the static probe said.
    pub fn verdict(&self, probe: WindowHost) -> WindowHost {
        combine(probe, self.has_failed())
    }
}

/// The rule itself: a window host is available only if the probe said so AND nothing has failed.
///
/// A free function taking both inputs, so every combination is exercised by `cargo test` on every
/// platform. A rule reading a `cfg!` or a global would leave three of its four cases unfalsifiable on
/// the one CI host that ran it.
pub fn combine(probe: WindowHost, observed_failure: bool) -> WindowHost {
    match (probe, observed_failure) {
        (WindowHost::Available, false) => WindowHost::Available,
        _ => WindowHost::Unavailable,
    }
}

/// The process's own observation, shared by the tray and the window host.
static OBSERVED: HostObservation = HostObservation::new();

/// Record that opening the app window failed, for this whole process.
pub fn note_open_failure() {
    OBSERVED.note_failure();
}

/// What the tray should assume about the window right now.
///
/// The static half is [`probe`]; the dynamic half is every failure [`note_open_failure`] has seen.
pub fn observed() -> WindowHost {
    OBSERVED.verdict(probe())
}

/// The cheap, static half of the answer: could a window host exist on this machine at all.
///
/// macOS is excluded by target rather than by probe because the reason is structural — the tray owns
/// the main thread and macOS forbids a window-server connection off it — so there is nothing to
/// measure. Everywhere else the question is whether a display server is reachable, which
/// [`crate::confirm::gui::available`] already answers, and a Linux session with neither
/// `WAYLAND_DISPLAY` nor `DISPLAY` lands in exactly the same place macOS does. Keying on the runtime
/// predicate rather than the target triple is what stops this being a macOS special case that ships
/// the same trap on Linux.
pub fn probe() -> WindowHost {
    match !cfg!(target_os = "macos") && crate::confirm::gui::available() {
        true => WindowHost::Available,
        false => WindowHost::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All four combinations, on every platform. The rule is the trim's safety property, so a case
    /// that only one CI host can reach is a case nobody checks.
    #[test]
    fn a_host_is_available_only_when_the_probe_agrees_and_nothing_has_failed() {
        assert_eq!(
            combine(WindowHost::Available, false),
            WindowHost::Available,
            "a probed host with no failures is available"
        );
        assert_eq!(
            combine(WindowHost::Available, true),
            WindowHost::Unavailable,
            "an observed failure must beat the probe, or the trim becomes a trap"
        );
        assert_eq!(
            combine(WindowHost::Unavailable, false),
            WindowHost::Unavailable
        );
        assert_eq!(
            combine(WindowHost::Unavailable, true),
            WindowHost::Unavailable
        );
    }

    #[test]
    fn a_fresh_observation_defers_to_the_probe() {
        let observation = HostObservation::new();
        assert!(!observation.has_failed());
        assert_eq!(
            observation.verdict(WindowHost::Available),
            WindowHost::Available
        );
    }

    /// The behaviour the whole module exists for: one observed failure restores the full menu.
    #[test]
    fn one_observed_failure_degrades_the_host_for_good() {
        let observation = HostObservation::new();
        observation.note_failure();
        assert!(observation.has_failed());
        assert_eq!(
            observation.verdict(WindowHost::Available),
            WindowHost::Unavailable,
            "after a failure the tray must go back to offering everything itself"
        );
        // Idempotent, and still degraded — there is deliberately no way back up.
        observation.note_failure();
        assert_eq!(
            observation.verdict(WindowHost::Available),
            WindowHost::Unavailable
        );
    }

    /// Two observations do not share a latch, which is what makes the tests above independent of the
    /// order they run in.
    #[test]
    fn observations_are_independent_of_one_another() {
        let failed = HostObservation::new();
        let fine = HostObservation::new();
        failed.note_failure();
        assert_eq!(
            failed.verdict(WindowHost::Available),
            WindowHost::Unavailable
        );
        assert_eq!(fine.verdict(WindowHost::Available), WindowHost::Available);
    }

    /// The probe must answer without a display and without panicking. Its VALUE is host-dependent, so
    /// asserting one would fail on a CI host with no display and pass on a developer's desktop.
    #[test]
    fn the_probe_is_answerable_on_any_host() {
        let _ = probe();
        let _ = observed();
    }
}
