//! The macOS native confirmer (SIGN-3): a floating `NSAlert` consent window + Touch ID.
//!
//! The confirm window is an AppKit [`NSAlert`] raised to the front showing the decoded transaction and
//! vouched origin with an approve/cancel choice; the biometric step is `LocalAuthentication`'s
//! [`LAContext`] evaluating [`LAPolicy::DeviceOwnerAuthentication`], which presents Touch ID with the
//! login password as the built-in fallback (§5.6.1). `evaluatePolicy` answers asynchronously via a
//! completion block, which [`block2`] bridges to a blocking call over a channel. The AppKit dialog
//! requires the main thread, so [`confirmer`] returns the backend only when constructed there; off the
//! main thread it returns [`None`] and the caller falls back to the fail-closed confirmer.
//!
//! Both FFI calls reduce to a result the pure mappers below turn into a [`WindowIntent`] /
//! [`VerifyOutcome`]; those mappers are unit-tested here.

use std::sync::mpsc;

use block2::RcBlock;
use dispatch2::run_on_main;
use objc2::runtime::Bool;
use objc2_app_kit::{NSAlert, NSApplication};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundWindow, NativeConfirmer,
    Presentation, VerifyOutcome, WindowIntent,
};

/// AppKit's `NSModalResponse` for the first (default) alert button — the approve action.
const NS_ALERT_FIRST_BUTTON_RETURN: isize = 1000;

/// A [`ForegroundWindow`] drawn as a front-most modal [`NSAlert`].
///
/// A confirmer is shared across the loopback server's worker tasks (`Send + Sync`), but AppKit MUST be
/// touched on the main thread. Rather than store the `!Send` [`MainThreadMarker`], each `show` hops to
/// the main thread with [`run_on_main`] (the tray shell pumps the main run loop), so this stays a
/// zero-field `Send + Sync` unit while the AppKit calls remain statically main-thread-checked.
struct AlertWindow;

impl ForegroundWindow for AlertWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        // Move owned, `Send` copies of the display text onto the main thread (a borrow of `content`
        // could not cross the thread hop).
        let heading = content.heading.clone();
        let body = content.body.clone();
        let action = content.action;
        let offers_a_way_out = alert_offers_cancel(&content.presentation);
        run_on_main(move |mtm| {
            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&heading));
            alert.setInformativeText(&NSString::from_str(&body));
            alert.addButtonWithTitle(&NSString::from_str(action));
            // A Cancel is added ONLY when refusing means something (dig_ecosystem#1773). AppKit relabels
            // buttons freely, so the affirmative one already reads correctly either way ("Sign", "OK") —
            // what a notice must not have is a second button offering a decision no caller reads.
            if offers_a_way_out {
                alert.addButtonWithTitle(&NSString::from_str("Cancel"));
            }
            // Bring the app forward so the consent window is truly foreground, never hidden behind the
            // browser that triggered it.
            NSApplication::sharedApplication(mtm).activate();
            intent_from_alert_response(alert.runModal())
        })
    }
}

/// Whether this window needs a second, declining button. Pure so the rule is tested on every platform
/// rather than only where AppKit can run.
fn alert_offers_cancel(presentation: &Presentation) -> bool {
    matches!(presentation, Presentation::Decide { .. })
}

/// A [`BiometricVerifier`] backed by `LAContext` device-owner authentication (Touch ID + password).
struct TouchIdVerifier;

impl BiometricVerifier for TouchIdVerifier {
    fn verify(&self, reason: &str) -> VerifyOutcome {
        // SAFETY: `LAContext::new` and `evaluatePolicy…` are the standard LocalAuthentication FFI; the
        // reply block is kept alive by `reply` until it fires, and the channel outlives the block.
        let context = unsafe { LAContext::new() };
        let (tx, rx) = mpsc::channel::<bool>();
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = tx.send(success.as_bool());
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(&format!("confirm to {reason} with your DIG identity")),
                &reply,
            );
        }
        match rx.recv() {
            Ok(true) => VerifyOutcome::Verified,
            Ok(false) => VerifyOutcome::Declined,
            // The channel dropped without a reply — no authenticator answered; fail closed.
            Err(_) => VerifyOutcome::Unavailable,
        }
    }
}

/// Map an `NSAlert` modal response to the user's intent. The first button is the approve action;
/// every other response (Cancel, dismissed) is a non-approval so the confirm does not proceed.
fn intent_from_alert_response(response: isize) -> WindowIntent {
    if response == NS_ALERT_FIRST_BUTTON_RETURN {
        WindowIntent::Approve
    } else {
        WindowIntent::Deny
    }
}

/// The macOS confirmer. Always available: the window hops to the main thread on demand
/// ([`AlertWindow`]) and the biometric evaluates off any thread.
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    Some(Box::new(BackedConfirmer::new(AlertWindow, TouchIdVerifier)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_first_button_approves_everything_else_denies() {
        assert_eq!(
            intent_from_alert_response(NS_ALERT_FIRST_BUTTON_RETURN),
            WindowIntent::Approve
        );
        assert_eq!(intent_from_alert_response(1001), WindowIntent::Deny);
        assert_eq!(intent_from_alert_response(0), WindowIntent::Deny);
    }

    /// **Regression (#1773).** A notice must be a one-button alert; a real either/or keeps its way out.
    /// Both directions in one test, because a rule tested from one side only cannot tell "notices lose
    /// Cancel" from "nothing ever has Cancel" — and the second would silently remove the reveal gate's
    /// decline.
    #[test]
    fn only_a_two_choice_alert_adds_cancel() {
        assert!(!alert_offers_cancel(&Presentation::Acknowledge));
        assert!(alert_offers_cancel(&Presentation::Decide {
            choice_hint: "Choose OK to Sign, or Cancel to reject.".into(),
        }));
    }
}
