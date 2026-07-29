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

use windows::core::HSTRING;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

use super::{BackedConfirmer, BiometricVerifier, NativeConfirmer, VerifyOutcome};

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
    Some(Box::new(BackedConfirmer::new(
        super::windows_input::DialogWindow,
        HelloVerifier,
        super::windows_input::InputWindow,
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
