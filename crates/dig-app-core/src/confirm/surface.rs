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
/// # What it does not count
///
/// Only windows this process draws and wraps in a [`Raised`]. A platform-owned consent UI — the
/// Windows Hello `UserConsentVerifier` prompt, raised after the app's own window has closed — is not
/// counted, so this reads `false` while it is up and the tray will claim the foreground off it. That
/// is a denial nuisance and not an authorization defect: a Hello prompt that loses focus and is
/// cancelled maps to a refusal, never an approval. Do not read this as "no consent is being asked
/// for anywhere".
pub fn consent_surface_is_up() -> bool {
    RAISED.load(Ordering::Acquire) > 0
}

/// A consent surface is on screen for as long as this value lives.
///
/// Hold it across the draw and nothing else. Its whole contract is in [`Drop`]: see the module docs
/// for why the lowering may not be a separate call.
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
/// **It does NOT cover every raiser, and the gap is known rather than theoretical.** Two live tests
/// raise the count without holding it, so this serialises the tests that DO take it against each
/// other and nothing more:
///
/// - `gui::window`'s `three_real_prompt_windows_in_a_row_are_all_answered` drives `serve`, which
///   raises at `window.rs:429`. It is `#[ignore]`d — it opens real windows — so the collision is
///   latent, not live. Filed as dig-app#99.
/// - `dig-app`'s `tray_popup` raises from a DIFFERENT crate, where this mutex is not reachable at
///   all: it is `pub(crate)` to `dig-app-core`.
///
/// Closing the gap means exporting the exclusion across the crate boundary and taking it in both
/// places, which is dig-app#99's job. Until then this doc states what the lock actually provides,
/// because a comment claiming an exclusion the code does not enforce is how the next person writes a
/// test that races and cannot see why.
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
