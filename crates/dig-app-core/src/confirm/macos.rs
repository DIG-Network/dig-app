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
use objc2::runtime::Bool;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSAlert, NSApplication};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundWindow, NativeConfirmer,
    VerifyOutcome, WindowIntent,
};

/// AppKit's `NSModalResponse` for the first (default) alert button — the approve action.
const NS_ALERT_FIRST_BUTTON_RETURN: isize = 1000;

/// A [`ForegroundWindow`] drawn as a front-most modal [`NSAlert`]. Holds a [`MainThreadMarker`] so the
/// AppKit calls are statically guaranteed to run on the main thread.
struct AlertWindow {
    mtm: MainThreadMarker,
}

impl ForegroundWindow for AlertWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        let alert = NSAlert::new(self.mtm);
        alert.setMessageText(&NSString::from_str(&content.heading));
        alert.setInformativeText(&NSString::from_str(&content.body));
        alert.addButtonWithTitle(&NSString::from_str(content.action));
        alert.addButtonWithTitle(&NSString::from_str("Cancel"));
        // Bring the app forward so the consent window is truly foreground, never hidden behind the
        // browser that triggered it.
        NSApplication::sharedApplication(self.mtm).activate();
        intent_from_alert_response(alert.runModal())
    }
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

/// The macOS confirmer, or [`None`] when not on the main thread (AppKit requires it) so the caller
/// falls back to the fail-closed confirmer.
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    let mtm = MainThreadMarker::new()?;
    Some(Box::new(BackedConfirmer::new(
        AlertWindow { mtm },
        TouchIdVerifier,
    )))
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
}
