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
use objc2::rc::Retained;
use objc2::runtime::Bool;
// `MainThreadOnly` is what supplies `alloc(mtm)` for a main-thread-only AppKit class; without it in scope
// `NSTextField::alloc` does not resolve.
use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSAlert, NSApplication, NSControl, NSSecureTextField, NSTextField, NSView};
use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use zeroize::Zeroizing;

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundInput, ForegroundWindow,
    InputContent, InputOutcome, NativeConfirmer, Presentation, VerifyOutcome, WindowIntent,
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
        let refusal_is_default = alert_defaults_to_refusal(&content.presentation);
        run_on_main(move |mtm| {
            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&heading));
            alert.setInformativeText(&NSString::from_str(&body));
            // `addButtonWithTitle` hands back the button it made, which is why no walk of `alert.buttons()`
            // is needed to find them again.
            let affirmative = alert.addButtonWithTitle(&NSString::from_str(action));
            // A Cancel is added ONLY when refusing means something (dig_ecosystem#1773). AppKit relabels
            // buttons freely, so the affirmative one already reads correctly either way ("Sign", "OK") —
            // what a notice must not have is a second button offering a decision no caller reads.
            if offers_a_way_out {
                let cancel = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
                // `NSAlert` gives Return to its FIRST button, so a destroy window would confirm irreversible
                // key destruction on a bare Return (dig_ecosystem#1799). Moving the Return key equivalent
                // onto Cancel makes the safe answer the default, matching `MB_DEFBUTTON2` on Windows.
                if refusal_is_default {
                    affirmative.setKeyEquivalent(&NSString::from_str(""));
                    cancel.setKeyEquivalent(&NSString::from_str("\r"));
                }
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

/// Whether the REFUSING button must carry the Return key. Pure for the same reason.
fn alert_defaults_to_refusal(presentation: &Presentation) -> bool {
    matches!(
        presentation,
        Presentation::Decide {
            refusal_is_default: true,
            ..
        }
    )
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

/// The size of the text field an [`NSAlert`] accessory view gets.
///
/// AppKit sizes an alert to its accessory, so the width here is what makes a 24-word recovery phrase
/// readable while typing rather than scrolling past the left edge of a default-width field.
const FIELD_WIDTH: f64 = 420.0;

/// The height of the field. One value: the field is always single-line, because a masked field must be
/// (`SPEC.md` §3.1d requires secret entry to be maskable, and a multiline field cannot be), and the reveal
/// affordance rather than extra rows is what makes 24 words checkable.
const FIELD_HEIGHT: f64 = 24.0;

/// A [`ForegroundInput`] drawn as an [`NSAlert`] with a text field as its accessory view
/// (dig_ecosystem#1798).
///
/// `NSAlert` is the same window type every other DIG prompt on macOS uses, so the input window is
/// visually and behaviourally consistent with them — and AppKit gives it Return-to-submit, Esc-to-cancel
/// and keyboard focus for free, which a hand-built window would have to reimplement.
///
/// Hops to the main thread per call for the same reason [`AlertWindow`] does: AppKit is main-thread-only
/// while the confirmer is shared across threads.
struct AlertInput;

impl ForegroundInput for AlertInput {
    fn ask(&self, content: &InputContent) -> InputOutcome {
        // Owned, `Send` copies of the display text, since a borrow of `content` cannot cross the hop.
        let heading = content.heading.clone();
        let body = format!("{}\n\n{}", content.body, content.field_label);
        let submit = content.submit;
        let masked = content.masked;
        run_on_main(move |mtm| {
            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&heading));
            alert.setInformativeText(&NSString::from_str(&body));
            alert.addButtonWithTitle(&NSString::from_str(submit));
            // Cancel is REQUIRED here, unlike a notice: abandoning a restore is a real outcome the caller
            // branches on, and a window demanding a recovery phrase with no way out is the trap §6.1
            // forbids.
            alert.addButtonWithTitle(&NSString::from_str("Cancel"));

            // `revealable` is deliberately NOT honoured here: offering a checkbox beside the field needs a
            // custom accessory view hierarchy rather than a bare control, and `SPEC.md` §3.1d is explicit
            // that a backend which cannot offer the reveal affordance keeps the MASKED default rather than
            // relaxing it to compensate. Recorded in §3.1d's platform-limits note.
            let field = AccessoryField::new(mtm, masked);
            alert.setAccessoryView(Some(field.as_view()));
            NSApplication::sharedApplication(mtm).activate();

            let response = alert.runModal();
            if response != NS_ALERT_FIRST_BUTTON_RETURN {
                return InputOutcome::Cancelled;
            }
            InputOutcome::Provided(field.take())
        })
    }
}

/// The accessory text field, in its two flavours.
///
/// An enum rather than a `Retained<NSView>` because the two classes have different superclass chains, and
/// erasing them to `NSView` at construction would throw away the `stringValue` accessor the caller needs.
/// The variants exist ONLY to be built differently; everything after that is shared below.
enum AccessoryField {
    /// A normal, echoing field — what a recovery phrase is typed into (24 words cannot be typed blind).
    Plain(Retained<NSTextField>),
    /// A masked field — a passphrase.
    Masked(Retained<NSSecureTextField>),
}

impl AccessoryField {
    /// Build the field: masked or plain.
    fn new(mtm: MainThreadMarker, masked: bool) -> Self {
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(FIELD_WIDTH, FIELD_HEIGHT),
        );
        match masked {
            true => Self::Masked(NSSecureTextField::initWithFrame(
                NSSecureTextField::alloc(mtm),
                frame,
            )),
            false => Self::Plain(NSTextField::initWithFrame(NSTextField::alloc(mtm), frame)),
        }
    }

    /// The field as the view an [`NSAlert`] accessory must be.
    ///
    /// Both classes declare `NSView` in their superclass chain, so `objc2` generates an `AsRef` for it and
    /// this is an upcast, not a conversion. Written as an ANNOTATED `AsRef` rather than a chain of
    /// `as_super()` calls, because the number of links differs between the two variants
    /// (`NSSecureTextField` descends from `NSTextField`) and a miscounted chain is a compile error that
    /// only a macOS runner can see.
    fn as_view(&self) -> &NSView {
        match self {
            Self::Plain(field) => field.as_ref(),
            Self::Masked(field) => field.as_ref(),
        }
    }

    /// The field as the `NSControl` that owns `stringValue`/`setStringValue`.
    fn as_control(&self) -> &NSControl {
        match self {
            Self::Plain(field) => field.as_ref(),
            Self::Masked(field) => field.as_ref(),
        }
    }

    /// Read what the user typed, then overwrite the control's OWN copy so the phrase does not linger in an
    /// AppKit buffer after the window closes.
    fn take(&self) -> Zeroizing<String> {
        let control = self.as_control();
        let value = Zeroizing::new(control.stringValue().to_string());
        control.setStringValue(&NSString::from_str(""));
        value
    }
}

/// The macOS confirmer. Always available: the windows hop to the main thread on demand
/// ([`AlertWindow`], [`AlertInput`]) and the biometric evaluates off any thread.
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    Some(Box::new(BackedConfirmer::new(
        AlertWindow,
        TouchIdVerifier,
        AlertInput,
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

    /// **Regression (#1773).** A notice must be a one-button alert; a real either/or keeps its way out.
    /// Both directions in one test, because a rule tested from one side only cannot tell "notices lose
    /// Cancel" from "nothing ever has Cancel" — and the second would silently remove the reveal gate's
    /// decline.
    #[test]
    fn only_a_two_choice_alert_adds_cancel() {
        assert!(!alert_offers_cancel(&Presentation::Acknowledge));
        assert!(alert_offers_cancel(&decision(false)));
        assert!(alert_offers_cancel(&decision(true)));
    }

    /// **Regression (#1799).** Only a window that ASKS for it gets its refusal as the default.
    ///
    /// `NSAlert` gives Return to its FIRST button, so a destroy window would confirm the destruction of key
    /// material on a bare Return. Both directions are asserted: always defaulting to the refusal would make
    /// every signature need an extra deliberate click, and never doing it leaves the destroy window armed.
    #[test]
    fn only_a_destroy_alert_defaults_to_its_refusal() {
        assert!(alert_defaults_to_refusal(&decision(true)));
        assert!(!alert_defaults_to_refusal(&decision(false)));
        assert!(!alert_defaults_to_refusal(&Presentation::Acknowledge));
    }

    /// A two-choice presentation whose refusal is, or is not, the default.
    fn decision(refusal_is_default: bool) -> Presentation {
        Presentation::Decide {
            choice_hint: "Choose OK to Sign, or Cancel to reject.".into(),
            refusal_is_default,
        }
    }
}
