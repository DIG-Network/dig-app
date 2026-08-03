//! The Windows native confirmer (SIGN-3): a topmost Win32 consent window + Windows Hello.
//!
//! The confirm window is drawn by [`windows_input`](super::windows_input) — the same hand-built,
//! DPI-scaled window that takes typed input, minus the field. The biometric step is the WinRT
//! [`UserConsentVerifier`], which raises the secure Windows Hello prompt (fingerprint / face / PIN — the
//! PIN/password being the built-in fallback, §5.6.1). The FFI call reduces to a result code, and the
//! code→outcome mapping is a pure function unit-tested here.
//!
//! # Why this is no longer a `MessageBoxW`
//!
//! It was, until dig_ecosystem#1832. A message box cannot relabel its buttons, so every two-choice window
//! had to spell its choice out in a sentence beneath the body: the retention claim explained in a paragraph
//! what a button reading "Yes, I have them" says by itself, and the destroy window's way out was a button
//! labelled "Cancel" — which names the dialog, not the outcome a hesitating person is looking for. The
//! labels were in the content all along; macOS and Linux put them on their buttons and only Windows threw
//! them away. It also could not be styled, scaled, or given the DIG mark.
//!
//! An interactive user on Windows always has a window station, so [`confirmer`] returns the backend
//! unconditionally; a session-0 service host degrades naturally (the confirm window cannot be created and
//! `UserConsentVerifier` reports the device unavailable, which fails closed via [`VerifyOutcome`]).

use std::time::Duration;

use windows::core::HSTRING;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, PostQuitMessage, TranslateMessage, MSG, PM_REMOVE, WM_QUIT,
};

use super::offload::verify_off_thread;
use super::{BackedConfirmer, BiometricVerifier, NativeConfirmer, VerifyOutcome};

/// How long to wait for Windows Hello before giving up and failing closed.
///
/// Generous, because the person may have to find their fingerprint reader or type a PIN, but finite: an
/// authenticator that never answers must cost the user one refused action, never a permanently wedged
/// tray. Hello's own prompt expires well inside this. It lives here rather than beside the offload
/// because it is THIS backend's policy, not a property of running work on another thread.
const VERIFY_DEADLINE: Duration = Duration::from_secs(180);

/// The most messages one idle tick will dispatch before returning to check for Hello's answer.
///
/// Bounded so a busy window cannot starve the check: the caller must come back and notice that
/// verification finished, however much repainting the desktop is asking for.
const PUMP_BUDGET: usize = 64;

/// A [`BiometricVerifier`] backed by the WinRT [`UserConsentVerifier`] (Windows Hello).
///
/// # Why the call is not made here
///
/// [`UserConsentVerifier::RequestVerificationAsync`] returns an `IAsyncOperation`, and `get()` BLOCKS
/// the thread it is called on. This verifier is reached from the tray's menu dispatch, which runs
/// inside the tray's event loop — so `get()` used to block the very UI thread Windows Hello needs to
/// raise its prompt. The thread waited for Hello, Hello waited for the thread, and every custody
/// action in the app hung the tray permanently (dig_ecosystem#1926).
///
/// So the WinRT call runs on its own thread via [`verify_off_thread`], where it is free to block, and
/// the caller waits by pumping its messages. Nothing about the DECISION changes: only a `Verified`
/// delivered by that thread within the deadline authorizes anything.
struct HelloVerifier;

impl BiometricVerifier for HelloVerifier {
    fn verify(&self, reason: &str) -> VerifyOutcome {
        let message = format!("Confirm to {reason} with your DIG identity");
        verify_off_thread(&message, request_consent, pump_pending, VERIFY_DEADLINE)
    }
}

/// Raise the Windows Hello prompt and report what it said. Runs on the worker thread.
///
/// The thread joins the multi-threaded apartment first: a freshly spawned thread belongs to no
/// apartment, and WinRT activation from one fails outright. The MTA is also what makes the blocking
/// `get()` legal — the completion is delivered directly rather than through a message pump this thread
/// does not have.
fn request_consent(message: String) -> VerifyOutcome {
    // SAFETY: called once on a thread that has just been created and has no apartment; the matching
    // `RoUninitialize` below runs before the thread ends.
    let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.is_ok();

    let outcome = match UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
        .and_then(|op| op.get())
    {
        Ok(result) => outcome_from_consent(result),
        // A failure to even start verification (no authenticator, RPC error, no apartment) fails closed.
        Err(_) => VerifyOutcome::Unavailable,
    };

    if initialized {
        // SAFETY: balances the successful `RoInitialize` above, on the same thread.
        unsafe { RoUninitialize() };
    }
    outcome
}

/// Dispatch the messages already waiting for this thread, so the tray keeps painting while Hello is up.
///
/// A `WM_QUIT` is put back rather than consumed: it belongs to the event loop that owns this thread,
/// and swallowing it here would leave the app unable to exit.
fn pump_pending() {
    let mut message = MSG::default();
    for _ in 0..PUMP_BUDGET {
        // SAFETY: a plain message-queue read on the calling thread's own queue.
        unsafe {
            if !PeekMessageW(&mut message, HWND::default(), 0, 0, PM_REMOVE).as_bool() {
                return;
            }
            if message.message == WM_QUIT {
                PostQuitMessage(message.wParam.0 as i32);
                return;
            }
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

/// Map a [`UserConsentVerificationResult`] to a verification outcome. Only [`Verified`] authorizes;
/// an explicit cancel is a denial, and every device/enrollment problem fails closed as unavailable.
///
/// [`Verified`]: UserConsentVerificationResult::Verified
fn outcome_from_consent(result: UserConsentVerificationResult) -> VerifyOutcome {
    match result {
        UserConsentVerificationResult::Verified => VerifyOutcome::Verified,
        UserConsentVerificationResult::Canceled => VerifyOutcome::Declined,
        UserConsentVerificationResult::RetriesExhausted => VerifyOutcome::Failed,
        // DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy / DeviceBusy — no usable Hello.
        _ => VerifyOutcome::Unavailable,
    }
}

/// The Windows confirmer (always available for an interactive user; see the module docs).
///
/// Both windows come from [`windows_input`](super::windows_input): the consent window and the typed-input
/// window are one implementation parameterised by whether it has a field, so the DPI scaling, the type
/// hierarchy and the keyboard behaviour cannot drift apart between them (dig_ecosystem#1832).
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    // The branded GUI (dig_ecosystem#2038) draws every window; Windows Hello still authorises.
    // The hand-built Win32 GDI dialog it replaces is gone — there is exactly one way a DIG prompt
    // is drawn, on every platform that can draw one.
    Some(Box::new(BackedConfirmer::new(
        super::gui::BrandedWindow::default(),
        HelloVerifier,
        super::gui::BrandedInput::default(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_result_maps_only_verified_to_success() {
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::Verified),
            VerifyOutcome::Verified
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::Canceled),
            VerifyOutcome::Declined
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::RetriesExhausted),
            VerifyOutcome::Failed
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::DeviceNotPresent),
            VerifyOutcome::Unavailable
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::DisabledByPolicy),
            VerifyOutcome::Unavailable
        );
    }

    #[test]
    fn confirmer_is_constructed() {
        assert!(confirmer().is_some());
    }
}
