//! Whether a consent surface is on screen right now, readable from any thread.
//!
//! # Why this exists
//!
//! A consent prompt is the one window in this app whose *foreground* is load-bearing. Everything
//! else can lose focus and cost the user nothing; a prompt that loses focus mid-read is a prompt the
//! user may re-focus and answer having lost their place — they were reading an origin and a payload,
//! and they come back to a window that looks the same but that they have stopped reading.
//!
//! So the tray's foreground claim ([`crate::confirm`]'s caller in `dig-app`) has to be able to ask
//! "is a prompt up?" from a thread that is not the prompt thread. That question cannot be answered
//! by a handle or a lock — the asker is a Win32 event handler running inside a window proc, it must
//! not block, and it must not be able to touch the prompt at all. An atomic count is the whole of
//! what it needs and the whole of what it may have.
//!
//! # Why a count and not a flag
//!
//! A flag makes "cleared while another surface is still up" expressible, and that is the bug this
//! would otherwise ship with: the second surface's exit would clear the first's. A count cannot be
//! wrong that way. The renderer draws one window at a time today, so the count is normally 0 or 1 —
//! it is a count so that staying correct does not depend on that remaining true.
//!
//! # Why the guard, and not a pair of calls
//!
//! [`Raised`] restores on drop, so every way out of a draw — returning, an early `?`, a panic
//! unwinding out of a foreign GL frame — lowers the count. A `raise()`/`lower()` pair would make
//! "forgot to lower" expressible, and a prompt thread that panicked once would then report a consent
//! surface forever, silently disabling the tray's foreground claim for the life of the process.

use std::sync::atomic::{AtomicUsize, Ordering};

/// How many consent surfaces are being drawn right now, process-wide.
///
/// A `static` rather than an injected handle because the reader is a bare Win32 window proc with
/// nowhere to put captured state, and because there is exactly one screen to be in front of.
static RAISED: AtomicUsize = AtomicUsize::new(0);

/// Whether a consent surface — one of THIS app's own prompt windows — is on screen.
///
/// Cheap and non-blocking by construction: callers ask from inside a window proc, where blocking is
/// how a tray stops responding.
///
/// # What it counts
///
/// Anything wrapped in a [`Raised`]: this process's own prompt windows, for the span of each draw,
/// AND the whole of a `gated_consent` gate — which includes the platform-owned authenticator UI
/// raised after the app's window has closed, such as the Windows Hello `UserConsentVerifier` prompt
/// (dig-app#100). It does not count a consent UI some OTHER process is showing; nothing here can see
/// one. Do not read this as "no consent is being asked for anywhere".
pub fn consent_surface_is_up() -> bool {
    RAISED.load(Ordering::Acquire) > 0
}

/// A consent surface is on screen for as long as this value lives.
///
/// Hold it across the span the user is being asked over — a draw, or a whole consent gate — and
/// nothing else. Its whole contract is in [`Drop`]: see the module docs for why the lowering may not
/// be a separate call.
#[derive(Debug)]
#[must_use = "the surface is only counted as raised for as long as this guard is held"]
pub struct Raised(());

impl Raised {
    /// Count one more consent surface as being on screen.
    pub fn now() -> Self {
        RAISED.fetch_add(1, Ordering::AcqRel);
        Self(())
    }
}

impl Drop for Raised {
    fn drop(&mut self) {
        RAISED.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serializes every test that RAISES a surface or ASSERTS on the count.
///
/// [`RAISED`] is process-global, and `cargo test` runs test threads in parallel, so a test asserting
/// "nothing is up" reads a count another test is legitimately holding. That is not a hypothetical:
/// it turned this module's own assertions red on CI while passing locally, because the machine that
/// runs eight prompt lanes at once is the one with eight cores.
///
/// **Every raiser inside this crate now takes it, with ONE named exception.** Since dig-app#100,
/// `gated_consent` raises the count for its whole span, which makes every test that
/// calls it a raiser — including the ones driving nothing but test doubles. Those all take this lock.
/// What does not:
///
/// - `confirm::offload`'s `a_timed_out_verification_does_not_authorize_the_gated_action` calls
///   `gated_consent` and so raises for the ~50ms its verifier stalls, without holding this. That file
///   is deliberately frozen — its safety comes from never naming `VerifyOutcome::Verified` — so the
///   exclusion was not added there in the same change. Filed as dig-app#102.
/// - `dig-app`'s `tray_popup` raises from a DIFFERENT crate, where this mutex is not reachable at
///   all: it is `pub(crate)` to `dig-app-core`. `cargo test` gives that crate its own process, and it
///   is the only count-touching test in that binary, so nothing can run beside it — a property of
///   that test set, not of the design. The comment at its raise says so.
///
/// This doc states what the lock actually provides, because a comment claiming an exclusion the code
/// does not enforce is how the next person writes a test that races and cannot see why.
///
/// A plain `Mutex` rather than `serial_test`: the dependency would be carried for a handful of tests.
#[cfg(test)]
pub(crate) static ONE_SURFACE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`ONE_SURFACE_AT_A_TIME`], recovering rather than propagating a poisoning — a test that
/// panicked while holding it must not red every later test as well.
#[cfg(test)]
pub(crate) fn one_surface_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_SURFACE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exclusively<T>(body: impl FnOnce() -> T) -> T {
        let _held = one_surface_at_a_time();
        body()
    }

    #[test]
    fn nothing_is_up_until_something_is_raised() {
        exclusively(|| {
            assert!(
                !consent_surface_is_up(),
                "a process with no prompt on screen must not claim one; the tray's claim is \
                 disabled while this reads true, so a stuck `true` costs every menu its foreground"
            );
            let raised = Raised::now();
            assert!(consent_surface_is_up(), "a raised surface must be visible");
            drop(raised);
            assert!(
                !consent_surface_is_up(),
                "the guard must lower the count when it is dropped"
            );
        });
    }

    /// The nearest wrong implementation is a `bool`, and this is the input that tells them apart: a
    /// flag set twice and cleared once reads FALSE here while a surface is still on screen.
    ///
    /// Two surfaces, dropped in the order they were raised — not one, because one cannot express the
    /// bug.
    #[test]
    fn an_inner_surface_closing_does_not_report_the_outer_one_gone() {
        exclusively(|| {
            let outer = Raised::now();
            let inner = Raised::now();
            drop(inner);
            assert!(
                consent_surface_is_up(),
                "the outer surface is STILL on screen; a bool flag would read false here and hand \
                 the tray back its foreground claim over a live prompt"
            );
            drop(outer);
            assert!(!consent_surface_is_up(), "and now genuinely nothing is up");
        });
    }

    /// A panic unwinding out of a draw must lower the count.
    ///
    /// This is the failure a `raise()`/`lower()` pair ships: the prompt renderer catches panics and
    /// keeps serving, so a leaked count would not crash anything — it would silently disable the
    /// tray's foreground claim for the rest of the process, which is indistinguishable from the
    /// claim working.
    #[test]
    fn a_panicking_draw_still_lowers_the_count() {
        exclusively(|| {
            let panicked = std::panic::catch_unwind(|| {
                let _raised = Raised::now();
                panic!("a prompt window panicked mid-draw");
            });
            assert!(panicked.is_err(), "the fixture must actually have panicked");
            assert!(
                !consent_surface_is_up(),
                "an unwind past the guard must still lower the count"
            );
        });
    }
}
