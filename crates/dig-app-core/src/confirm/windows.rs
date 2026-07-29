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
    MessageBoxW, IDOK, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_OKCANCEL, MB_SETFOREGROUND,
    MB_SYSTEMMODAL, MB_TOPMOST, MESSAGEBOX_STYLE,
};

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundWindow, NativeConfirmer,
    Presentation, VerifyOutcome, WindowIntent,
};

/// The style bits every DIG window shares: force it to the foreground, above everything, across desktops.
/// The consent window is worthless if the browser that triggered it can sit on top of it.
const FOREGROUND: MESSAGEBOX_STYLE =
    MESSAGEBOX_STYLE(MB_SETFOREGROUND.0 | MB_TOPMOST.0 | MB_SYSTEMMODAL.0);

/// A [`ForegroundWindow`] drawn as a topmost, system-modal message box.
struct MessageBoxWindow;

impl ForegroundWindow for MessageBoxWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        let text = HSTRING::from(message_text(content));
        let caption = HSTRING::from(content.title.as_str());
        // SAFETY: the two pointers reference `HSTRING`s that outlive the (blocking) call, and the flags
        // are valid `MESSAGEBOX_STYLE` bits. `MessageBoxW` draws its own window and does not retain them.
        let result = unsafe {
            MessageBoxW(
                None,
                PCWSTR(text.as_ptr()),
                PCWSTR(caption.as_ptr()),
                buttons_and_icon(&content.presentation) | FOREGROUND,
            )
        };
        intent_from_messagebox(result.0)
    }
}

/// The buttons and icon for a presentation.
///
/// **This is the dig_ecosystem#1773 fix.** Every window used to be `MB_OKCANCEL | MB_ICONWARNING`, so
/// "Your DIG ID is on the clipboard" arrived as a warning triangle with a Cancel button that no caller
/// read. A notice gets ONE button and the information icon; only a genuine either/or gets two buttons, and
/// the warning icon there is honest — refusing an authorization or a retention claim has a real cost.
fn buttons_and_icon(presentation: &Presentation) -> MESSAGEBOX_STYLE {
    match presentation {
        Presentation::Acknowledge => MESSAGEBOX_STYLE(MB_OK.0 | MB_ICONINFORMATION.0),
        Presentation::Decide { .. } => MESSAGEBOX_STYLE(MB_OKCANCEL.0 | MB_ICONWARNING.0),
    }
}

/// The body text `MessageBoxW` shows.
///
/// `MessageBoxW` cannot relabel its buttons, so a two-choice window has to spell the choice out in the
/// body — using the content's OWN sentence rather than one template for every prompt, because an
/// authorization ("Choose OK to Sign") and a claim ("Choose OK — I have written these down") cannot share a
/// sentence and stay readable (#1752). A one-button window appends nothing: there is no choice to explain,
/// and "Choose OK" under a lone OK button is noise.
fn message_text(content: &ConfirmContent) -> String {
    match &content.presentation {
        Presentation::Acknowledge => format!("{}\n\n{}", content.heading, content.body),
        Presentation::Decide { choice_hint } => {
            format!("{}\n\n{}\n\n{choice_hint}", content.heading, content.body)
        }
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

    // ---- dig_ecosystem#1773: the presentation of a notice vs a decision. ----
    //
    // These assert on the STYLE BITS rather than on a rendered window, because the bits are the whole
    // defect: every code path here was already correct, and the bug was visible only as a warning triangle
    // and a stray Cancel in a screenshot. The bits are what a screenshot is a picture of, so pinning them
    // is pinning the observation — and the paired live screenshots on the PR are the observation itself.

    fn notice() -> ConfirmContent {
        ConfirmContent::notice(&crate::confirm::NoticePrompt {
            title: "DIG — DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "abc123",
            acknowledge: "OK",
        })
    }

    fn authorization() -> ConfirmContent {
        ConfirmContent::reveal(&crate::confirm::RevealPrompt {
            secret: "your recovery phrase",
        })
    }

    /// **Regression (#1773).** An informational window must not wear the warning icon, and must not offer a
    /// Cancel that nothing reads.
    #[test]
    fn a_notice_gets_one_button_and_the_information_icon() {
        let style = buttons_and_icon(&notice().presentation);

        assert_eq!(style.0 & MB_OKCANCEL.0, 0, "a notice has nothing to cancel");
        assert_eq!(
            style.0 & MB_ICONWARNING.0,
            0,
            "'your DIG ID is on the clipboard' is not a warning"
        );
        assert_ne!(style.0 & MB_ICONINFORMATION.0, 0);
    }

    /// The control that makes the test above load-bearing: a GENUINE either/or still gets two buttons and
    /// the warning icon. Without this pair, flattening every window to a single OK — destroying the reveal
    /// gate's and the retention claim's real way out — would pass just as happily.
    #[test]
    fn an_authorization_keeps_both_buttons_and_the_warning_icon() {
        let style = buttons_and_icon(&authorization().presentation);

        assert_ne!(
            style.0 & MB_OKCANCEL.0,
            0,
            "declining a reveal must stay possible"
        );
        assert_ne!(style.0 & MB_ICONWARNING.0, 0);
    }

    /// Every window, whichever kind, must still be forced to the foreground: a consent window the
    /// triggering browser can cover is not a consent window.
    #[test]
    fn both_presentations_are_forced_to_the_foreground() {
        for content in [notice(), authorization()] {
            let style = buttons_and_icon(&content.presentation) | FOREGROUND;
            assert_ne!(style.0 & MB_SETFOREGROUND.0, 0);
            assert_ne!(style.0 & MB_TOPMOST.0, 0);
            assert_ne!(style.0 & MB_SYSTEMMODAL.0, 0);
        }
    }

    /// A one-button window must not print "Choose OK … or Cancel" under a lone OK button — the sentence
    /// would describe a button that is not there.
    #[test]
    fn only_a_two_choice_window_explains_its_buttons() {
        let notice_text = message_text(&notice());
        assert!(
            !notice_text.contains("Cancel"),
            "a notice has no Cancel to name: {notice_text}"
        );
        assert!(notice_text.contains("Your DIG ID is on the clipboard."));

        let decide_text = message_text(&authorization());
        assert!(
            decide_text.contains("Cancel to reject"),
            "MessageBoxW cannot relabel buttons, so a real choice must be spelled out: {decide_text}"
        );
    }
}
