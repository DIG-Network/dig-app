//! The Windows native confirmer (SIGN-3): a topmost Win32 consent window + Windows Hello.
//!
//! The confirm window is a real, foreground-forced `MessageBoxW` (topmost + system-modal) showing the
//! decoded transaction and vouched origin with an approve/cancel choice; the biometric step is the
//! WinRT [`UserConsentVerifier`], which raises the secure Windows Hello prompt (fingerprint / face /
//! PIN — the PIN/password being the built-in fallback, §5.6.1). The two FFI calls each reduce to a
//! result code, and the code→decision mapping is a pure function unit-tested here.
//!
//! An interactive user on Windows always has a window station, so [`confirmer`] returns the backend
//! unconditionally; a session-0 service host degrades naturally (the confirm window cannot show and
//! `UserConsentVerifier` reports the device unavailable, which fails closed via [`VerifyOutcome`]).

use windows::core::{HSTRING, PCWSTR};
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDOK, MB_ICONWARNING, MB_OKCANCEL, MB_SETFOREGROUND, MB_SYSTEMMODAL, MB_TOPMOST,
};

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundWindow, NativeConfirmer,
    VerifyOutcome, WindowIntent,
};

/// A [`ForegroundWindow`] drawn as a topmost, system-modal message box.
struct MessageBoxWindow;

impl ForegroundWindow for MessageBoxWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        // `MessageBoxW` cannot relabel its buttons, so the choice is spelled out in the body — using the
        // content's OWN `choice_hint` rather than one template for every prompt, because an
        // authorization ("Choose OK to Sign") and an acknowledgement ("Choose OK — I have written these
        // down") cannot share a sentence and stay readable (#1752).
        let text = HSTRING::from(format!(
            "{}\n\n{}\n\n{}",
            content.heading, content.body, content.choice_hint
        ));
        let caption = HSTRING::from(content.title.as_str());
        // SAFETY: the two pointers reference `HSTRING`s that outlive the (blocking) call, and the flags
        // are valid `MESSAGEBOX_STYLE` bits. `MessageBoxW` draws its own window and does not retain them.
        let result = unsafe {
            MessageBoxW(
                None,
                PCWSTR(text.as_ptr()),
                PCWSTR(caption.as_ptr()),
                MB_OKCANCEL | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST | MB_SYSTEMMODAL,
            )
        };
        intent_from_messagebox(result.0)
    }
}

/// A [`BiometricVerifier`] backed by the WinRT [`UserConsentVerifier`] (Windows Hello).
struct HelloVerifier;

impl BiometricVerifier for HelloVerifier {
    fn verify(&self, reason: &str) -> VerifyOutcome {
        let message = HSTRING::from(format!("Confirm to {reason} with your DIG identity"));
        match UserConsentVerifier::RequestVerificationAsync(&message).and_then(|op| op.get()) {
            Ok(result) => outcome_from_consent(result),
            // A failure to even start verification (no authenticator, RPC error) fails closed.
            Err(_) => VerifyOutcome::Unavailable,
        }
    }
}

/// Map a `MessageBoxW` return value to the user's intent. `IDOK` is approve; anything else (Cancel,
/// close, or a `0` creation failure) is a non-approval, so the confirm does not proceed.
fn intent_from_messagebox(result: i32) -> WindowIntent {
    if result == IDOK.0 {
        WindowIntent::Approve
    } else {
        WindowIntent::Deny
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
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    Some(Box::new(BackedConfirmer::new(
        MessageBoxWindow,
        HelloVerifier,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messagebox_ok_approves_everything_else_denies() {
        assert_eq!(intent_from_messagebox(IDOK.0), WindowIntent::Approve);
        assert_eq!(intent_from_messagebox(0), WindowIntent::Deny);
        assert_eq!(intent_from_messagebox(2), WindowIntent::Deny);
    }

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
