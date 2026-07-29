//! The user-facing account **journeys** — the flows the tray menu triggers (dig_ecosystem#1752).
//!
//! The pieces underneath are deliberately narrow: [`recovery`](crate::account::recovery) knows words and
//! seeds, [`lifecycle`](crate::account::lifecycle) knows enrolment, [`phrase_vault`](crate::account::phrase_vault)
//! knows at-rest, and [`confirm`](crate::confirm) knows how to draw an OS-owned window. This module is
//! the only place that knows the ORDER those happen in for a human, which is where the safety rules live:
//!
//! - **Setup shows the words, then asks twice.** One acknowledgement is a reflex; the second screen is
//!   what makes "I have written these down" an actual claim. Either refusal abandons setup, and
//!   [`open_or_enroll`](crate::account::lifecycle::open_or_enroll) then leaves nothing enrolled.
//! - **A re-reveal is gated like a signature.** [`reveal_phrase`] asks the OS to re-authenticate the
//!   human (`confirm_reveal`) BEFORE the vault is even opened, so a passer-by at an unlocked machine
//!   cannot read the account off a tray menu.
//! - **Nothing here logs, returns, or persists the words.** They travel from the vault to the window and
//!   are dropped; the functions return an outcome, never a phrase.

use crate::account::boot::DiscardOutcome;
use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
use crate::account::phrase_vault::PhraseVault;
use crate::account::recovery::RecoveryPhrase;
use crate::confirm::{
    ClaimPrompt, ConfirmDecision, DestroyPrompt, InputOutcome, InputPrompt, NativeConfirmer,
    NoticePrompt, RevealPrompt,
};
use crate::sealer::ProfileSealer;

/// How the user's own phrase is described to them, in one place so setup and reveal agree.
const PHRASE_NAME: &str = "your 24-word DIG recovery phrase";

/// What happened when the user asked to see their recovery phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealOutcome {
    /// The words were shown.
    Shown,
    /// The user (or the OS authenticator) refused, or no confirm surface exists. Nothing was read.
    Refused,
    /// This account has no stored phrase — it was enrolled before recovery phrases existed and cannot
    /// be recovered from words. The tray offers the remedy rather than pretending otherwise.
    NoPhraseStored,
    /// The vault could not be opened (the account locked, or the file is damaged).
    Unavailable,
}

/// The production [`PhrasePresenter`]: draws a fresh phrase in an OS-owned window and takes the user's
/// retention claim.
///
/// Borrowed rather than owned because the shell already holds the one process-wide confirmer.
pub struct WindowedPresenter<'a> {
    confirmer: &'a dyn NativeConfirmer,
}

impl<'a> WindowedPresenter<'a> {
    /// Present through `confirmer` (in production, [`native_confirmer`](crate::confirm::native_confirmer)).
    pub fn new(confirmer: &'a dyn NativeConfirmer) -> Self {
        Self { confirmer }
    }
}

impl PhrasePresenter for WindowedPresenter<'_> {
    fn present_new_phrase(&self, phrase: &RecoveryPhrase) -> RetentionDecision {
        let words = phrase.numbered_lines();
        // Both enrolment screens are CLAIMS, not notices: backing out of either abandons setup, so the
        // declining choice is load-bearing and must be offered as a real, labelled way out
        // (dig_ecosystem#1773 — this is the one place a two-button window is correct in this flow).
        let shown = self.confirmer.confirm_claim(&ClaimPrompt {
            title: "DIG — Your recovery phrase",
            heading: "Write these 24 words down, in order, and keep them somewhere safe.",
            body: &format!(
                "{}\nThese words ARE your DIG Account. Anyone who has them can take it, and \
                 nobody — including DIG — can recover your account without them.",
                *words
            ),
            affirm: "I have written these down",
        });
        if shown != ConfirmDecision::Approve {
            return decision_for(shown);
        }

        // The second screen is not a formality: it is the moment the user is asked to make a claim about
        // the world (the words are somewhere other than this screen) rather than to dismiss a dialog.
        let confirmed = self.confirmer.confirm_claim(&ClaimPrompt {
            title: "DIG — Confirm you saved it",
            heading: "Do you have your 24 words written down somewhere safe?",
            body: "If you continue without them and later lose this computer, your DIG Account, its \
                   address and everything sealed under it are gone for good. You can view the words \
                   again later from the DIG tray menu.",
            affirm: "Yes, I have them",
        });
        decision_for(confirmed)
    }
}

/// Map a notice outcome onto a retention ruling. A dismissal is a decline; anything the OS could not
/// show is [`RetentionDecision::Unavailable`], which refuses to enrol at all.
fn decision_for(decision: ConfirmDecision) -> RetentionDecision {
    match decision {
        ConfirmDecision::Approve => RetentionDecision::Confirmed,
        ConfirmDecision::Deny => RetentionDecision::Declined,
        ConfirmDecision::Timeout | ConfirmDecision::Unavailable => RetentionDecision::Unavailable,
    }
}

/// Show the account's stored recovery phrase again, behind an OS re-authentication.
///
/// The order is load-bearing and is what this function exists to guarantee: the confirm runs FIRST, so a
/// refusal means the vault was never opened and the words were never decrypted — not merely that they
/// were decrypted and then not displayed.
pub fn reveal_phrase<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &PhraseVault<S>,
) -> RevealOutcome {
    if confirmer.confirm_reveal(&RevealPrompt {
        secret: PHRASE_NAME,
    }) != ConfirmDecision::Approve
    {
        return RevealOutcome::Refused;
    }

    let phrase = match vault.load() {
        Ok(Some(phrase)) => phrase,
        Ok(None) => return RevealOutcome::NoPhraseStored,
        Err(e) => {
            tracing::warn!(error = %e, "could not open the recovery-phrase vault");
            return RevealOutcome::Unavailable;
        }
    };

    let words = phrase.numbered_lines();
    match confirmer.show_notice(&NoticePrompt {
        title: "DIG — Your recovery phrase",
        heading: "These 24 words are your DIG Account. Keep them secret.",
        body: &words,
        acknowledge: "Done",
    }) {
        ConfirmDecision::Approve | ConfirmDecision::Deny => RevealOutcome::Shown,
        // The window itself could not be drawn, so nothing reached the screen.
        ConfirmDecision::Timeout | ConfirmDecision::Unavailable => RevealOutcome::Unavailable,
    }
}

/// What a phrase-less (legacy) account is told.
///
/// This function ONLY informs — it changes nothing. What it must do, and what it failed to do before
/// dig_ecosystem#1800, is name a remedy the user can actually reach: it used to explain that the only fix
/// was a new account while every control that could create one was greyed out, which is a dead end dressed
/// as advice. The copy now names the exact menu path, and the menu really offers it.
pub fn explain_missing_phrase(confirmer: &dyn NativeConfirmer) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — No recovery phrase",
        heading: "This DIG Account has no recovery phrase.",
        body: "It was created before DIG had recovery phrases, so its key exists only on this \
               computer: if you lose this machine, the account, its address and everything sealed \
               under it cannot be recovered — not by you and not by DIG.\n\n\
               Words cannot be added to an existing account. To get a recoverable account, replace \
               this one: in the DIG menu choose \"Manage my DIG Account\" then \"Replace this account \
               with a NEW one…\". You will be shown 24 words to write down, and you will get a NEW \
               identity and address — this account's data stays sealed to its old key and becomes \
               unreadable.\n\n\
               Nothing has changed yet. Your account still works exactly as before.",
        acknowledge: "I understand",
    })
}

/// What the user asked a destructive account verb to do — and, for a replace, what comes after.
///
/// A type rather than a pair of booleans so a caller cannot express "remove it and then restore from a
/// phrase", which is not a thing, and so the warning copy for each is chosen in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Discard this account and enrol a brand-new one, with a fresh recovery phrase.
    WithNewAccount,
    /// Discard this account and enrol the one the user's typed recovery phrase describes.
    FromPhrase,
    /// Discard this account and leave the host with none.
    Nothing,
}

impl Replacement {
    /// What the destroy window tells the user happens after the account is gone.
    fn promise(self) -> &'static str {
        match self {
            Self::WithNewAccount => {
                "A brand-new DIG Account will be created in its place, with a new recovery phrase, a \
                 new identity and a new address."
            }
            Self::FromPhrase => {
                "The account your recovery phrase describes will be set up in its place. Check the \
                 words are the right ones before you continue — a different phrase gives a different, \
                 empty account."
            }
            Self::Nothing => {
                "This computer will be left with no DIG Account. You can set one up again, or restore \
                 one, from the DIG menu at any time."
            }
        }
    }
}

/// The user's answer to a destructive account verb, BEFORE anything is destroyed.
///
/// Returned rather than acted on so the decision and the destruction stay separable — which is what lets
/// the placement rule ("nothing is destroyed until this says [`Authorized`](Self::Authorized)") be tested
/// without a real keystore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyRuling {
    /// The user saw exactly what is lost and re-authenticated. The caller may destroy.
    Authorized,
    /// The user declined, or the OS could not authorize. **Nothing may be destroyed.**
    Refused,
}

/// Put a destructive account verb to the user, offering to show their recovery phrase first.
///
/// # The order, which is the whole point
///
/// 1. **Offer the phrase first.** The commonest reason a replace goes wrong is a user who believes they
///    have their words and does not. Offering the reveal BEFORE the destroy — through the ordinary
///    [`reveal_phrase`] gate, so it is authorized and audited exactly as it always is — is the cheapest
///    possible way to turn that mistake into a non-event. Skipped when the account has no phrase to show.
/// 2. **Then authorize the destruction**, through [`confirm_destroy`](NativeConfirmer::confirm_destroy):
///    a foreground window naming the irreversible loss, then an OS re-authentication. Never a notice
///    (one button, no decision) and never a claim (two buttons, no biometric) — a passer-by at an
///    unlocked machine must not be able to destroy an account by clicking twice.
///
/// Returns [`DestroyRuling::Refused`] for anything other than an explicit, authenticated approval, so the
/// fail-closed direction is the default rather than a branch a caller has to remember.
pub fn authorize_destroy<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    what: Replacement,
    vault: Option<&PhraseVault<S>>,
) -> DestroyRuling {
    let recoverable = vault.is_some_and(|vault| vault.is_recoverable());
    if recoverable {
        offer_a_last_look(confirmer, vault);
    }

    let approved = confirmer.confirm_destroy(&DestroyPrompt {
        subject: "the DIG Account on this computer",
        replacement: what.promise(),
        recoverable,
    });
    match approved {
        ConfirmDecision::Approve => DestroyRuling::Authorized,
        _ => DestroyRuling::Refused,
    }
}

/// Ask whether the user wants to see their words one last time, and show them if so.
///
/// A CLAIM, not a notice: the answer decides whether the reveal runs, so both choices are real. Declining
/// costs nothing and does not abandon the verb — the user may simply already have the words on paper.
fn offer_a_last_look<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: Option<&PhraseVault<S>>,
) {
    let wants_to_see = confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Before you destroy this account",
        heading: "Do you want to see this account's recovery phrase first?",
        body: "Once the account is destroyed, these 24 words are the ONLY way to get it back — and \
               only somewhere else, since it will be gone from this computer. If you are not certain \
               you have them written down, look now.",
        affirm: "Show me the words first",
    });
    if wants_to_see != ConfirmDecision::Approve {
        return;
    }
    if let Some(vault) = vault {
        // Through the ordinary gate: this is a reveal like any other, so it re-authenticates and warns
        // about the surroundings on its own. A separate, laxer path here would be a way around that gate.
        reveal_phrase(confirmer, vault);
    }
}

/// Ask the user for a recovery phrase in a native window and parse it, re-asking on a bad phrase.
///
/// # Why it loops
///
/// A mistyped word is the normal case, not the exceptional one, and a window that closes on the first
/// mistake and leaves the user to find the menu item again is the kind of surface people give up on. So a
/// rejected phrase is re-asked, with the REASON in the window ("that is 23 words, not 24") — and the loop
/// is BOUNDED, so a broken dialog backend cannot spin a window forever.
///
/// Returns `None` when the user cancels, when no input window could be drawn, or when the attempts run
/// out; the caller then changes nothing.
pub fn ask_for_phrase(confirmer: &dyn NativeConfirmer, purpose: &str) -> Option<RecoveryPhrase> {
    let mut problem = String::new();
    for _ in 0..PHRASE_ATTEMPTS {
        let body = format!(
            "{problem}Type or paste all 24 words in order, separated by spaces. Capitals do not \
             matter.\n\n\
             Use the words DIG gave you. A recovery phrase from a Chia wallet such as Sage is NOT a \
             DIG recovery phrase — DIG would accept it and build a DIFFERENT, empty account from it."
        );
        let typed = match confirmer.request_input(&InputPrompt {
            title: "DIG — Recovery phrase",
            heading: purpose,
            body: &body,
            field_label: "Your 24 words:",
            submit: "Continue",
            // Masked by DEFAULT (`SPEC.md` §3.1d): the words already exist on paper, so someone watching
            // the screen is the live risk and a typo costs only a retry. `revealable` is §3.1d's own escape
            // from that rule — 24 words typed entirely blind cannot be checked, so the window offers a
            // deliberate un-mask rather than defaulting to clear text.
            masked: true,
            revealable: true,
        }) {
            InputOutcome::Provided(text) => text,
            // Cancelled or undrawable: either way the user has not supplied a phrase, so stop. Retrying an
            // Unavailable would loop against a backend that cannot draw at all.
            InputOutcome::Cancelled | InputOutcome::Unavailable => return None,
        };

        match RecoveryPhrase::parse(&typed) {
            Ok(phrase) => return Some(phrase),
            Err(why) => problem = format!("That is not a valid DIG recovery phrase: {why}.\n\n"),
        }
    }
    // Out of attempts. Say so rather than closing silently, so the user knows the app heard them.
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — Recovery phrase",
        heading: "Those words were not a valid DIG recovery phrase.",
        body: "Nothing has been changed on this computer. Check the words against what you wrote \
               down — all 24, in the original order — and try again from the DIG menu.",
        acknowledge: "OK",
    });
    None
}

/// The host effects a destructive account verb has, behind a trait so the ORDER can be tested.
///
/// # Why this trait exists (a review finding, dig_ecosystem#1799)
///
/// The first implementation put the ordering — authorize, collect the replacement, lock, discard, enrol —
/// in `dig-app`'s `bin` target behind `#[cfg(feature = "tray")]`, where **no test can reach it**. The
/// consequence was measured: inverting one character in that function so that a REFUSED destroy destroyed
/// the account and an AUTHORIZED one aborted left `cargo test --workspace` green and clippy silent. The
/// gate's own words were *"the custody proof is vacuous at the only place custody is destroyed"*.
///
/// So the ordering lives here, in the library, and the untestable parts — which directory, which credential
/// store, which live session — are behind these four methods. The shell implements them and holds no
/// ordering logic at all.
pub trait AccountCustodian {
    /// Drop the live session's key material, before the seed it guards is deleted.
    ///
    /// Called even when there is no live session (a no-op then): the caller must not have to know, and
    /// "lock before discard" is a rule about ORDER, not about whether a session happens to exist.
    fn lock_current(&self);

    /// **Irreversibly** discard the account's custody root. The one destructive step.
    fn discard(&self) -> DiscardOutcome;

    /// Enrol a brand-new account, showing and confirming its recovery phrase. `true` on success.
    fn enrol_new(&self) -> bool;

    /// Enrol the account `phrase` describes. `true` on success.
    fn enrol_from(&self, phrase: &RecoveryPhrase) -> bool;

    /// Re-open the account that is still here after a FAILED discard, so the user is not left with a
    /// working account the tray reports as locked forever.
    fn reopen(&self);
}

/// What a destructive account verb did. Every variant states whether custody was destroyed, because that is
/// the only fact a caller — or a reader — actually needs from this flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// Destroyed, and the replacement is enrolled and live.
    Replaced,
    /// Destroyed, and nothing was put in its place, as asked.
    Removed,
    /// **Nothing destroyed.** The user declined the authorization, or the OS could not authorize.
    RefusedByUser,
    /// **Nothing destroyed.** The user was authorized but supplied no replacement phrase, so the flow
    /// stopped before the point of no return — which is the whole reason the phrase is collected first.
    AbandonedAtPhrase,
    /// **Nothing destroyed.** The discard itself failed; the account is still here and has been re-opened.
    DiscardFailed,
    /// **Destroyed**, but the replacement could not be enrolled. The worst outcome available, and the one
    /// the user must be told about most clearly.
    EnrolFailed,
}

impl ReplaceOutcome {
    /// Whether custody was destroyed. The single question every one of this flow's tests turns on.
    pub fn destroyed_custody(self) -> bool {
        matches!(self, Self::Replaced | Self::Removed | Self::EnrolFailed)
    }
}

/// Run a destructive account verb: authorize, collect the replacement, lock, discard, enrol.
///
/// # The order IS the safety property
///
/// 1. **Authorize** ([`authorize_destroy`]) — offers a last look at the recovery phrase where one exists,
///    then puts the destruction through the biometric authorization gate. Anything other than
///    [`DestroyRuling::Authorized`] returns [`ReplaceOutcome::RefusedByUser`] **without calling a single
///    method on `custodian`**.
/// 2. **Collect the replacement phrase FIRST**, while the old account is still intact. Asking afterwards
///    would leave a user who cancels — or mistypes past the retry bound — with no account at all.
///    Destroying something before knowing its replacement is good is the one ordering mistake this flow
///    must not make.
/// 3. **Lock**, so the residency is not holding key material for a seed about to be deleted.
/// 4. **Discard**, and only then enrol.
///
/// Every step the user needs to hear about ends in a window, because they pressed a button and are waiting.
pub fn replace_account<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    custodian: &dyn AccountCustodian,
    what: Replacement,
    vault: Option<&PhraseVault<S>>,
) -> ReplaceOutcome {
    if authorize_destroy(confirmer, what, vault) != DestroyRuling::Authorized {
        // Declining is a normal outcome, not an error, and the user already saw the window they declined —
        // so nothing more is said. Nothing was changed.
        return ReplaceOutcome::RefusedByUser;
    }

    let replacement = match what {
        Replacement::FromPhrase => match ask_for_phrase(
            confirmer,
            "Type the recovery phrase of the account you want on this computer.",
        ) {
            Some(phrase) => Some(phrase),
            None => {
                // The existing account is untouched, which is the point of asking before destroying. Say so
                // explicitly, because the user DID approve a destruction and would otherwise assume it ran.
                notify(
                    confirmer,
                    "DIG — Nothing was changed",
                    "Your existing DIG Account is still here.",
                    "No recovery phrase was entered, so nothing was replaced or removed.",
                );
                return ReplaceOutcome::AbandonedAtPhrase;
            }
        },
        Replacement::WithNewAccount | Replacement::Nothing => None,
    };

    custodian.lock_current();

    match custodian.discard() {
        DiscardOutcome::Discarded | DiscardOutcome::NothingToDiscard => {}
        DiscardOutcome::Failed => {
            notify(
                confirmer,
                "DIG — Nothing was changed",
                "Your DIG Account could not be removed.",
                "It is still here and still works — it is now locked, so unlock it from the DIG menu. \
                 The log folder (in the DIG menu) has the details.",
            );
            custodian.reopen();
            return ReplaceOutcome::DiscardFailed;
        }
    }

    // Past this line custody is GONE. Every path below must leave the user knowing that.
    match (what, replacement) {
        (Replacement::WithNewAccount, _) => match custodian.enrol_new() {
            true => ReplaceOutcome::Replaced,
            false => {
                notify(
                    confirmer,
                    "DIG — Setup not completed",
                    "The previous account was removed, and a new one was not created.",
                    "This computer now has no DIG Account. Set one up, or restore one from its 24 \
                     words, from the DIG menu whenever you are ready.",
                );
                ReplaceOutcome::EnrolFailed
            }
        },
        (Replacement::FromPhrase, Some(phrase)) => match custodian.enrol_from(&phrase) {
            true => {
                notify(
                    confirmer,
                    "DIG — Account replaced",
                    "The DIG Account from your recovery phrase is now on this computer.",
                    "The account that was here before is gone and its data is no longer readable.",
                );
                ReplaceOutcome::Replaced
            }
            false => {
                notify(
                    confirmer,
                    "DIG — Restore did not complete",
                    "The previous account was removed, but the new one could not be set up.",
                    "Your 24 words are still valid — try \"Restore from a recovery phrase…\" in the DIG \
                     menu. The log folder has the details.",
                );
                ReplaceOutcome::EnrolFailed
            }
        },
        // Unreachable by construction (step 2 returns early without a phrase), but expressed as a REFUSAL to
        // enrol rather than an `unwrap`: a future edit that reordered the collection must not turn into a
        // panic in the one flow that has already destroyed the user's key material.
        (Replacement::FromPhrase, None) => ReplaceOutcome::EnrolFailed,
        (Replacement::Nothing, _) => {
            notify(
                confirmer,
                "DIG — Account removed",
                "Your DIG Account has been removed from this computer.",
                "Nothing on this computer can open it any more. If you kept its 24 words you can restore \
                 it here, or anywhere else, from the DIG menu.",
            );
            ReplaceOutcome::Removed
        }
    }
}

/// Draw a plain informational window, so every message this module shows goes through the same OS-owned
/// surface rather than a mix of dialogs and silence.
fn notify(confirmer: &dyn NativeConfirmer, title: &str, heading: &str, body: &str) {
    confirmer.show_notice(&NoticePrompt {
        title,
        heading,
        body,
        acknowledge: "OK",
    });
}

/// How many times a user may retype a phrase before the window gives up.
///
/// Bounded so a dialog backend that returns instantly (a misconfigured helper, a scripted double) cannot
/// spin windows forever; generous enough that a person correcting one word twice is not shut out.
const PHRASE_ATTEMPTS: usize = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::recovery::PHRASE_WORDS;
    use crate::confirm::{ConnectPrompt, PairPrompt, SignPrompt};
    use crate::sealer::SealError;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// A confirmer that plays a SCRIPT of decisions and records every window it drew.
    ///
    /// A script (not a single fixed answer) is what lets the tests distinguish "asked twice" from
    /// "asked once and reused the answer" — a double that could only return one value could not express
    /// a user who acknowledges the words and then backs out of the confirmation.
    struct ScriptedConfirmer {
        reveal: Mutex<Vec<ConfirmDecision>>,
        /// Answers for the DESTROY gate, on its own script so a test can approve every ordinary window and
        /// still refuse the destruction — the combination that distinguishes "asked" from "acted".
        destroy: Mutex<Vec<ConfirmDecision>>,
        /// What the user "types", per input window. `None` models a cancel.
        typed: Mutex<Vec<Option<String>>>,
        notices: Mutex<Vec<ConfirmDecision>>,
        drawn: Mutex<Vec<String>>,
        /// Which SEAM each window came through, in order — `"notice"` (one button) or `"claim"` (two).
        ///
        /// Recorded because the seam IS the user-visible presentation (dig_ecosystem#1773): a screen sent
        /// through `show_notice` gets one button and an information icon on every platform, and a screen sent
        /// through `confirm_claim` gets a real way out. A test that only inspected the drawn TEXT could not
        /// tell the two apart, which is exactly how every tray message came to be drawn as a warning with a
        /// meaningless Cancel.
        kinds: Mutex<Vec<&'static str>>,
    }

    impl ScriptedConfirmer {
        fn new(reveal: Vec<ConfirmDecision>, notices: Vec<ConfirmDecision>) -> Self {
            Self {
                reveal: Mutex::new(reveal),
                destroy: Mutex::new(Vec::new()),
                typed: Mutex::new(Vec::new()),
                notices: Mutex::new(notices),
                drawn: Mutex::new(Vec::new()),
                kinds: Mutex::new(Vec::new()),
            }
        }

        /// A confirmer that approves every ordinary window, answers the destroy gate with `destroy`, and
        /// hands back `typed` from successive input windows.
        fn destroying(destroy: Vec<ConfirmDecision>, typed: Vec<Option<String>>) -> Self {
            Self {
                destroy: Mutex::new(destroy),
                typed: Mutex::new(typed),
                reveal: Mutex::new(vec![ConfirmDecision::Approve; 4]),
                notices: Mutex::new(vec![ConfirmDecision::Approve; 8]),
                drawn: Mutex::new(Vec::new()),
                kinds: Mutex::new(Vec::new()),
            }
        }

        /// The seams every window was drawn through, in order.
        fn kinds(&self) -> Vec<&'static str> {
            self.kinds.lock().unwrap().clone()
        }

        fn notices() -> Self {
            Self::new(vec![], vec![ConfirmDecision::Approve; 4])
        }

        /// Everything ever drawn, concatenated — used to assert the words did (or did not) reach a
        /// window.
        fn drawn(&self) -> String {
            self.drawn.lock().unwrap().join("\n")
        }

        fn windows_drawn(&self) -> usize {
            self.drawn.lock().unwrap().len()
        }
    }

    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_reveal(&self, prompt: &RevealPrompt<'_>) -> ConfirmDecision {
            self.kinds.lock().unwrap().push("REVEAL-GATE");
            self.drawn
                .lock()
                .unwrap()
                .push(format!("REVEAL-GATE {}", prompt.secret));
            let mut script = self.reveal.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }
        fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
            self.record("notice", prompt.title, prompt.heading, prompt.body);
            self.next_window_answer()
        }

        fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.record("claim", prompt.title, prompt.heading, prompt.body);
            self.next_window_answer()
        }

        fn confirm_destroy(&self, prompt: &DestroyPrompt<'_>) -> ConfirmDecision {
            // Recorded under its OWN seam name, because the seam IS the security property under test: an
            // implementation that routed a destroy through `show_notice` would look identical in the drawn
            // TEXT and be catastrophically weaker (one button, no biometric).
            self.record(
                "DESTROY-GATE",
                "DIG - Destroy",
                prompt.subject,
                prompt.replacement,
            );
            let mut script = self.destroy.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }

        fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
            self.record("input", prompt.title, prompt.heading, prompt.body);
            let mut script = self.typed.lock().unwrap();
            if script.is_empty() {
                InputOutcome::Cancelled
            } else {
                match script.remove(0) {
                    Some(text) => InputOutcome::Provided(zeroize::Zeroizing::new(text)),
                    None => InputOutcome::Cancelled,
                }
            }
        }
    }

    impl ScriptedConfirmer {
        /// Note that a window was drawn, through which seam, and what it displayed.
        fn record(&self, kind: &'static str, title: &str, heading: &str, body: &str) {
            self.kinds.lock().unwrap().push(kind);
            self.drawn
                .lock()
                .unwrap()
                .push(format!("{title}\n{heading}\n{body}"));
        }

        /// The next scripted answer for a drawn window.
        ///
        /// Notices and claims share ONE script on purpose: the flows under test draw them in a fixed
        /// sequence, and a shared script keeps "the third window the user saw" expressible whichever kind it
        /// was — which is what lets `setup_shows_the_words_and_asks_twice…` distinguish two screens from one.
        /// Running dry answers `Deny`, so an unexpected extra window fails rather than passing silently.
        fn next_window_answer(&self) -> ConfirmDecision {
            let mut script = self.notices.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }
    }

    /// A sealer good enough to exercise the vault end of the journey; cross-profile isolation is proven
    /// in the vault's own tests, so this one only needs to round-trip and to be lockable.
    /// It also COUNTS decryptions, which is the load-bearing part. "The gate runs before the vault is
    /// opened" is a statement about PLACEMENT, and a test that only checks the returned outcome — or even
    /// that no words reached a window — is satisfied identically by a gate placed AFTER the decryption.
    /// Only the decryption count changes when the guard moves.
    #[derive(Default)]
    struct PassthroughSealer {
        locked: Mutex<bool>,
        opens: Mutex<usize>,
    }

    impl PassthroughSealer {
        fn opens(&self) -> usize {
            *self.opens.lock().unwrap()
        }
    }

    impl ProfileSealer for PassthroughSealer {
        fn seal(&self, _did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
            if *self.locked.lock().unwrap() {
                return Err(SealError::Seal("locked".into()));
            }
            Ok(plaintext.to_vec())
        }
        fn open(&self, _did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            *self.opens.lock().unwrap() += 1;
            if *self.locked.lock().unwrap() {
                return Err(SealError::Open);
            }
            Ok(Zeroizing::new(ciphertext.to_vec()))
        }
    }

    const DID: &str = "did:chia:journey";

    fn vault(dir: &std::path::Path) -> PhraseVault<PassthroughSealer> {
        PhraseVault::new(PassthroughSealer::default(), dir, DID)
    }

    #[test]
    fn setup_shows_the_words_and_asks_twice_before_confirming_retention() {
        let confirmer = ScriptedConfirmer::notices();
        let phrase = RecoveryPhrase::generate();

        let decision = WindowedPresenter::new(&confirmer).present_new_phrase(&phrase);

        assert_eq!(decision, RetentionDecision::Confirmed);
        assert_eq!(
            confirmer.windows_drawn(),
            2,
            "one acknowledgement is a reflex; the retention claim needs its own screen"
        );
        // Matched as the whole numbered block, not per word: a per-word presence check would be satisfied
        // by prompt copy that happens to contain a BIP-39 word (`act` sits inside "redacted", `cover`
        // inside "recovery"), so it could pass without the phrase ever being drawn.
        assert!(
            drew_the_words(&confirmer, &phrase),
            "the generated words must reach the screen, in full and in order"
        );
    }

    /// Backing out of the FIRST screen declines. The fixture scripts a decline followed by an approve,
    /// so an implementation that ignored the first answer and used the second would fail here.
    #[test]
    fn dismissing_the_words_screen_declines() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Deny, ConfirmDecision::Approve],
        );

        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Declined
        );
        assert_eq!(
            confirmer.windows_drawn(),
            1,
            "the second screen must not be shown after a decline"
        );
    }

    /// Backing out of the SECOND screen also declines — the case a single-screen flow could not express,
    /// and the reason the second screen exists.
    #[test]
    fn backing_out_of_the_retention_screen_declines() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Approve, ConfirmDecision::Deny],
        );

        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Declined
        );
        assert_eq!(confirmer.windows_drawn(), 2);
    }

    /// A host with no confirm surface reports `Unavailable`, NOT `Declined` — the distinction matters
    /// because enrolment refuses on both, but only one of them is the user's choice.
    #[test]
    fn a_host_that_cannot_draw_the_words_reports_unavailable() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Unavailable]);
        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Unavailable
        );
    }

    #[test]
    fn revealing_shows_the_stored_words_after_the_gate_approves() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Shown);
        // The control for the placement test below: an APPROVED reveal decrypts exactly once, so a count
        // of zero there is a real observation rather than a counter that never moves.
        assert_eq!(vault.sealer_for_test().opens(), 1);
        assert!(
            drew_the_words(&confirmer, &phrase),
            "the stored words must reach a window"
        );
    }

    /// **A placement assertion, and it needs the right observable.** "The gate runs before the vault is
    /// opened" is a statement about WHERE the guard sits, and the tempting assertions — the outcome is
    /// `Refused`, no words reached a window — are satisfied IDENTICALLY by a gate placed after the
    /// decryption. Moving the guard below `vault.load()` leaves both of those green.
    ///
    /// The one observable that moves is whether the ciphertext was decrypted at all, which is why the test
    /// sealer counts its `open` calls. Verified by reverting exactly that ordering: with the count
    /// asserted the test fails, without it the test passes on the wrong placement.
    #[test]
    fn a_refused_gate_never_opens_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();
        let confirmer =
            ScriptedConfirmer::new(vec![ConfirmDecision::Deny], vec![ConfirmDecision::Approve]);

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Refused);
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "a refused gate must run BEFORE the phrase is decrypted, not after"
        );
        assert_eq!(
            confirmer.windows_drawn(),
            1,
            "only the gate should have been drawn — no words window"
        );
        assert!(
            !drew_the_words(&confirmer, &phrase),
            "the words leaked past a refused gate"
        );
    }

    /// Whether the words window was drawn, matched on the WHOLE phrase as one numbered block.
    ///
    /// A per-word substring search over everything drawn is quietly wrong: BIP-39 words are ordinary
    /// English, and several are substrings of the prompt copy itself — `cover` sits inside "recovery",
    /// `over` inside "recover". Such a check reports a leak at random depending on which words were
    /// generated. Matching the rendered block is exact.
    fn drew_the_words(confirmer: &ScriptedConfirmer, phrase: &RecoveryPhrase) -> bool {
        confirmer.drawn().contains(&*phrase.numbered_lines())
    }

    /// An unavailable authenticator refuses too — a machine with no Hello/Touch ID must not become a
    /// machine where anyone can read the phrase.
    #[test]
    fn an_unavailable_authenticator_refuses_the_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Unavailable],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Refused);
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "an unavailable authenticator must not decrypt the phrase either"
        );
    }

    /// A legacy account is distinguished from a broken one, because the tray offers different things.
    #[test]
    fn an_account_with_no_stored_phrase_reports_it_distinctly() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(
            reveal_phrase(&confirmer, &vault(dir.path())),
            RevealOutcome::NoPhraseStored
        );
    }

    #[test]
    fn a_locked_vault_reports_unavailable_rather_than_no_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        *vault_sealer_lock(&vault) = true;
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(
            reveal_phrase(&confirmer, &vault),
            RevealOutcome::Unavailable
        );
    }

    /// Reach into the test sealer's lock flag. A helper rather than a method on the vault, because
    /// production code has no business locking a sealer from the outside.
    fn vault_sealer_lock<'a>(
        vault: &'a PhraseVault<PassthroughSealer>,
    ) -> std::sync::MutexGuard<'a, bool> {
        vault.sealer_for_test().locked.lock().unwrap()
    }

    /// **Regression (#1773).** Both enrolment screens are real either/ors, so both must go through the
    /// two-button CLAIM seam — a Cancel here abandons setup, which is a decision the user must be able to
    /// make.
    ///
    /// This asserts the SEAM, not the returned decision: `RetentionDecision::Declined` comes back
    /// identically whichever seam drew the window, so an implementation that routed these through
    /// `show_notice` — one button, nothing to decline, the user trapped into "yes" — would leave every
    /// other test in this module green. Only the seam changes.
    #[test]
    fn both_enrolment_screens_offer_a_real_way_out() {
        let confirmer = ScriptedConfirmer::notices();

        WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate());

        assert_eq!(
            confirmer.kinds(),
            vec!["claim", "claim"],
            "declining either enrolment screen abandons setup, so neither may be a one-button notice"
        );
    }

    /// The control that makes the test above load-bearing: the purely informational screens go through the
    /// ONE-button notice seam. Without this pair, routing every window through `confirm_claim` — the old
    /// behaviour, a Cancel on "here are your words" that no caller reads — would satisfy the test above.
    #[test]
    fn the_informational_screens_are_one_button_notices() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Shown);
        assert_eq!(
            confirmer.kinds(),
            vec!["REVEAL-GATE", "notice"],
            "the reveal is gated (two choices), then the words are merely displayed (one)"
        );

        let explainer = ScriptedConfirmer::notices();
        explain_missing_phrase(&explainer);
        assert_eq!(
            explainer.kinds(),
            vec!["notice"],
            "an explanation asks nothing, so it offers one dismissal"
        );
    }

    /// The legacy explainer must name the CONSEQUENCE and must not act. Asserting the copy mentions the
    /// irreversibility is the only machine-checkable part of "told honestly"; the "does not act" half is
    /// structural — the function returns a decision and touches no store.
    #[test]
    fn the_missing_phrase_explainer_names_the_consequence_and_changes_nothing() {
        let confirmer = ScriptedConfirmer::notices();

        assert_eq!(explain_missing_phrase(&confirmer), ConfirmDecision::Approve);
        let drawn = confirmer.drawn().to_lowercase();
        assert!(drawn.contains("cannot be recovered"));
        assert!(drawn.contains("new identity and address"));
        assert!(drawn.contains("nothing has changed yet"));
    }

    // ---- The destructive verbs (dig_ecosystem#1799). ----

    /// **The custody guard.** Destroying an account MUST go through the AUTHORIZATION seam — a window plus
    /// a biometric — never a notice or a claim.
    ///
    /// Asserted on the SEAM the window was drawn through, not on its text, because that is the property: a
    /// destroy routed through `show_notice` would display the same warning, offer one button, run no
    /// biometric, and be catastrophically weaker. A text-only assertion cannot tell the two apart, which is
    /// exactly how eleven tray messages came to be drawn as warnings with a meaningless Cancel (#1773).
    #[test]
    fn destroying_an_account_is_authorized_through_the_biometric_gate() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        let ruling = authorize_destroy(
            &confirmer,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(ruling, DestroyRuling::Authorized);
        assert!(
            confirmer.kinds().contains(&"DESTROY-GATE"),
            "the destroy must ride the authorization seam, not a notice: {:?}",
            confirmer.kinds()
        );
        assert!(
            !confirmer.kinds().contains(&"notice"),
            "a notice cannot authorize anything: {:?}",
            confirmer.kinds()
        );
    }

    /// A refused destroy must return REFUSED for every non-approving answer, so fail-closed is the default
    /// rather than one branch. Iterating all three non-approvals is what makes this load-bearing — a rule
    /// that mapped only `Deny` would let a TIMEOUT destroy an account.
    #[test]
    fn every_non_approval_refuses_the_destruction() {
        for answer in [
            ConfirmDecision::Deny,
            ConfirmDecision::Timeout,
            ConfirmDecision::Unavailable,
        ] {
            let confirmer = ScriptedConfirmer::destroying(vec![answer], vec![]);
            assert_eq!(
                authorize_destroy(
                    &confirmer,
                    Replacement::Nothing,
                    None::<&PhraseVault<PassthroughSealer>>
                ),
                DestroyRuling::Refused,
                "{answer:?} must not authorize destroying an account"
            );
        }
    }

    /// A recoverable account is offered a LAST LOOK at its words before they become the only copy — and the
    /// offer must come BEFORE the destroy gate, which is a statement about ORDER that only the recorded
    /// sequence can prove. A test asserting merely that both windows appeared would pass for an
    /// implementation that offered the phrase after the account was already gone.
    #[test]
    fn a_recoverable_account_is_offered_its_phrase_before_the_destroy_gate() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);

        authorize_destroy(&confirmer, Replacement::WithNewAccount, Some(&vault));

        let kinds = confirmer.kinds();
        let gate = kinds
            .iter()
            .position(|kind| *kind == "DESTROY-GATE")
            .expect("the destroy gate must run");
        let look = kinds
            .iter()
            .position(|kind| *kind == "claim")
            .expect("the last-look offer must be a claim, so declining it is a real choice");
        assert!(
            look < gate,
            "the words must be offered BEFORE the point of no return: {kinds:?}"
        );
    }

    /// The control that proves the offer reads the vault rather than always appearing: an account with NO
    /// phrase has nothing to show, so it goes straight to the gate.
    #[test]
    fn a_phrase_less_account_is_not_offered_a_look_at_words_it_does_not_have() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        authorize_destroy(
            &confirmer,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(
            confirmer.kinds(),
            vec!["DESTROY-GATE"],
            "one window, the authorization — there are no words to look at"
        );
    }

    /// Each destructive verb must tell the user what happens AFTER, in its own words — "a new account will
    /// be created" and "this computer will be left with no account" are different outcomes, and a user must
    /// not have to guess which one they picked.
    #[test]
    fn each_destructive_verb_states_its_own_consequence() {
        assert!(Replacement::WithNewAccount.promise().contains("new"));
        assert!(Replacement::FromPhrase
            .promise()
            .contains("recovery phrase"));
        assert!(Replacement::Nothing.promise().contains("no DIG Account"));
        // And they must genuinely DIFFER — three identical strings would satisfy the checks above.
        let promises = [
            Replacement::WithNewAccount.promise(),
            Replacement::FromPhrase.promise(),
            Replacement::Nothing.promise(),
        ];
        for (index, first) in promises.iter().enumerate() {
            for second in &promises[index + 1..] {
                assert_ne!(first, second, "each verb needs its own sentence");
            }
        }
    }

    // ---- Typing a recovery phrase in a native window (dig_ecosystem#1798). ----

    /// A valid phrase typed into the native window comes back parsed — no terminal, no command.
    #[test]
    fn a_typed_phrase_is_accepted_from_the_native_input_window() {
        let phrase = RecoveryPhrase::generate();
        let words = phrase.words().join(" ");
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![Some(words.clone())]);

        let parsed = ask_for_phrase(&confirmer, "Restore your DIG Account").expect("valid words");
        assert_eq!(parsed.words().join(" "), words);
        assert!(
            confirmer.kinds().contains(&"input"),
            "the words must be taken in a native INPUT window: {:?}",
            confirmer.kinds()
        );
    }

    /// **The reason the loop exists.** A mistyped phrase must be re-asked WITH THE REASON, not silently
    /// dropped — and the second attempt must be accepted.
    ///
    /// The fixture supplies a wrong phrase first and a valid one second, which is what distinguishes
    /// "re-asks" from "gives up on the first mistake": a single-answer double could not express a user who
    /// corrects a typo.
    #[test]
    fn a_bad_phrase_is_re_asked_with_the_reason_and_the_correction_is_accepted() {
        let good = RecoveryPhrase::generate().words().join(" ");
        let confirmer = ScriptedConfirmer::destroying(
            vec![],
            vec![Some("not even close".to_string()), Some(good.clone())],
        );

        let parsed = ask_for_phrase(&confirmer, "Restore your DIG Account");
        assert_eq!(
            parsed
                .expect("the correction must be accepted")
                .words()
                .join(" "),
            good
        );

        let drawn = confirmer.drawn();
        assert!(
            drawn.contains("not a valid DIG recovery phrase"),
            "the second window must say WHAT was wrong: {drawn}"
        );
        assert_eq!(
            confirmer.kinds(),
            vec!["input", "input"],
            "exactly two windows: the mistake and the correction"
        );
    }

    /// A cancelled input window returns nothing and must NOT be retried — the user said no.
    #[test]
    fn cancelling_the_phrase_window_returns_nothing_and_asks_once() {
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![None]);
        assert!(ask_for_phrase(&confirmer, "Restore your DIG Account").is_none());
        assert_eq!(
            confirmer.kinds(),
            vec!["input"],
            "a cancel must not be re-asked: {:?}",
            confirmer.kinds()
        );
    }

    /// The retry loop is BOUNDED: past its limit it ends with an explanation rather than another window, so
    /// a backend that answers instantly cannot spin forever.
    ///
    /// Pinned at the bound rather than merely "stops eventually" — a loop that gave up after one attempt
    /// would also "stop", and would be the give-up-on-the-first-typo behaviour this loop exists to avoid.
    #[test]
    fn the_retry_loop_stops_exactly_at_its_bound_and_says_nothing_was_lost() {
        let wrong = vec![Some("wrong words here".to_string()); PHRASE_ATTEMPTS + 3];
        let confirmer = ScriptedConfirmer::destroying(vec![], wrong);

        assert!(ask_for_phrase(&confirmer, "Restore your DIG Account").is_none());
        let inputs = confirmer
            .kinds()
            .iter()
            .filter(|kind| **kind == "input")
            .count();
        assert_eq!(
            inputs, PHRASE_ATTEMPTS,
            "the loop must offer exactly its bound of attempts, no more and no fewer"
        );
        assert!(
            confirmer.drawn().contains("Nothing has been changed"),
            "the user must be told the attempt is over and nothing was lost: {}",
            confirmer.drawn()
        );
    }

    /// The phrase window must WARN that a Sage/Chia phrase is not a DIG phrase. DIG would happily accept one
    /// and build a different, empty account from it, which is the most expensive silent mistake available on
    /// this screen.
    #[test]
    fn the_phrase_window_warns_that_a_chia_wallet_phrase_is_a_different_account() {
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![None]);
        ask_for_phrase(&confirmer, "Restore your DIG Account");

        let drawn = confirmer.drawn();
        assert!(drawn.contains("Sage"), "{drawn}");
        assert!(drawn.contains("DIFFERENT"), "{drawn}");
        assert!(
            drawn.contains(&PHRASE_WORDS.to_string()),
            "the window must say how many words are expected: {drawn}"
        );
    }

    /// The phrase-less explainer must name a remedy the MENU actually offers, by its real label. Before
    /// #1800 it advised creating a new account while every control that could was greyed out — advice that
    /// is a dead end is worse than no advice.
    #[test]
    fn the_phrase_less_explainer_names_the_menu_path_to_its_remedy() {
        let confirmer = ScriptedConfirmer::notices();
        explain_missing_phrase(&confirmer);

        let drawn = confirmer.drawn();
        assert!(drawn.contains("Manage my DIG Account"), "{drawn}");
        assert!(
            drawn.contains("Replace this account with a NEW one"),
            "the remedy must be named by the label the user will see: {drawn}"
        );
        assert!(
            drawn.contains("Nothing has changed yet"),
            "the explainer changes nothing and must say so: {drawn}"
        );
    }

    // ---- The net under the destroy PATH (review finding, dig_ecosystem#1799). ----
    //
    // The seam test above proves `authorize_destroy` reaches `confirm_destroy`. It does NOT prove that the
    // code which destroys custody HONOURS that answer — and while that code lived in `dig-app`'s `bin`
    // target behind `#[cfg(feature = "tray")]`, nothing could: inverting one character so a REFUSED destroy
    // destroyed the account and an AUTHORIZED one aborted left the whole workspace green. These tests are
    // that missing net, and they are what makes moving the ordering into this module worth doing.

    /// A custodian that RECORDS what it was asked to do, in order, and never touches a real account.
    ///
    /// Recording the SEQUENCE rather than a set of counters is deliberate: "lock before discard" is a claim
    /// about order, and counters cannot express it.
    #[derive(Default)]
    struct RecordingCustodian {
        steps: Mutex<Vec<&'static str>>,
        /// What [`AccountCustodian::discard`] reports. Varied so the failure branch is reachable.
        discard: Mutex<Option<DiscardOutcome>>,
        /// Whether the enrolments succeed. A separate field from `discard`, because the interesting case is
        /// a SUCCESSFUL discard followed by a FAILED enrol — a double that could only vary one of the two
        /// could not express it, and that is the one path where custody is gone and nothing replaces it.
        enrol_succeeds: Mutex<bool>,
    }

    impl RecordingCustodian {
        fn new() -> Self {
            Self {
                steps: Mutex::new(Vec::new()),
                discard: Mutex::new(Some(DiscardOutcome::Discarded)),
                enrol_succeeds: Mutex::new(true),
            }
        }

        fn failing_discard() -> Self {
            let custodian = Self::new();
            *custodian.discard.lock().unwrap() = Some(DiscardOutcome::Failed);
            custodian
        }

        fn failing_enrol() -> Self {
            let custodian = Self::new();
            *custodian.enrol_succeeds.lock().unwrap() = false;
            custodian
        }

        fn steps(&self) -> Vec<&'static str> {
            self.steps.lock().unwrap().clone()
        }

        /// How many times the one destructive step ran. THE assertion of this whole group.
        fn discards(&self) -> usize {
            self.steps().iter().filter(|s| **s == "DISCARD").count()
        }

        fn note(&self, step: &'static str) {
            self.steps.lock().unwrap().push(step);
        }
    }

    impl AccountCustodian for RecordingCustodian {
        fn lock_current(&self) {
            self.note("lock");
        }
        fn discard(&self) -> DiscardOutcome {
            self.note("DISCARD");
            self.discard.lock().unwrap().unwrap()
        }
        fn enrol_new(&self) -> bool {
            self.note("enrol_new");
            *self.enrol_succeeds.lock().unwrap()
        }
        fn enrol_from(&self, _phrase: &RecoveryPhrase) -> bool {
            self.note("enrol_from");
            *self.enrol_succeeds.lock().unwrap()
        }
        fn reopen(&self) {
            self.note("reopen");
        }
    }

    /// A confirmer that answers the destroy gate with `answer` and types `words` into every input window.
    fn gate(answer: ConfirmDecision, words: Option<String>) -> ScriptedConfirmer {
        ScriptedConfirmer::destroying(vec![answer], vec![words])
    }

    /// **THE GATING TEST (#1799).** A REFUSED destroy MUST NOT destroy anything — asserted on the
    /// custodian, which is the only thing that can actually destroy custody.
    ///
    /// This is the test whose absence made the whole design's strongest part unprotected: with the ordering
    /// in an untestable `bin` target, inverting `!=` to `==` here — so a refusal destroys and an
    /// authorization aborts — passed the entire suite. Run over ALL THREE verbs and ALL THREE non-approvals,
    /// because a rule that honoured only `Deny`, or only one verb, is the same defect in milder form.
    #[test]
    fn a_refused_destroy_never_touches_the_account() {
        for what in [
            Replacement::WithNewAccount,
            Replacement::FromPhrase,
            Replacement::Nothing,
        ] {
            for answer in [
                ConfirmDecision::Deny,
                ConfirmDecision::Timeout,
                ConfirmDecision::Unavailable,
            ] {
                let custodian = RecordingCustodian::new();
                let outcome = replace_account(
                    &gate(answer, None),
                    &custodian,
                    what,
                    None::<&PhraseVault<PassthroughSealer>>,
                );

                assert_eq!(
                    outcome,
                    ReplaceOutcome::RefusedByUser,
                    "{what:?}/{answer:?}"
                );
                assert!(!outcome.destroyed_custody(), "{what:?}/{answer:?}");
                assert_eq!(
                    custodian.discards(),
                    0,
                    "{what:?}/{answer:?}: a refusal MUST NOT discard the account"
                );
                assert_eq!(
                    custodian.steps(),
                    Vec::<&str>::new(),
                    "{what:?}/{answer:?}: a refusal must not touch the host at all"
                );
            }
        }
    }

    /// **The control that makes the test above load-bearing.** An AUTHORIZED destroy MUST actually destroy —
    /// for all three verbs. Without this pair, a `replace_account` that never discarded anything would
    /// satisfy the refusal test perfectly, and the polarity inversion would still not be caught.
    #[test]
    fn an_authorized_destroy_discards_exactly_once_for_every_verb() {
        let words = RecoveryPhrase::generate().words().join(" ");
        for (what, expected_enrol) in [
            (Replacement::WithNewAccount, Some("enrol_new")),
            (Replacement::FromPhrase, Some("enrol_from")),
            (Replacement::Nothing, None),
        ] {
            let custodian = RecordingCustodian::new();
            let outcome = replace_account(
                &gate(ConfirmDecision::Approve, Some(words.clone())),
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            assert!(
                outcome.destroyed_custody(),
                "{what:?}: an authorized destroy must destroy: {outcome:?}"
            );
            assert_eq!(
                custodian.discards(),
                1,
                "{what:?}: exactly once — never twice, never not at all"
            );
            match expected_enrol {
                Some(step) => assert!(custodian.steps().contains(&step), "{what:?}"),
                None => assert!(
                    !custodian.steps().iter().any(|s| s.starts_with("enrol")),
                    "{what:?}: removal enrols nothing"
                ),
            }
        }
    }

    /// The lock MUST come before the discard: the residency must not be holding key material for a seed that
    /// is being deleted underneath it. Asserted on the recorded ORDER, which is the only way to see it — a
    /// test that merely checked both happened would pass for the reverse sequence.
    #[test]
    fn the_session_is_locked_before_the_seed_is_deleted() {
        let custodian = RecordingCustodian::new();
        replace_account(
            &gate(ConfirmDecision::Approve, None),
            &custodian,
            Replacement::Nothing,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        let steps = custodian.steps();
        let lock = steps.iter().position(|s| *s == "lock").expect("must lock");
        let discard = steps
            .iter()
            .position(|s| *s == "DISCARD")
            .expect("must discard");
        assert!(lock < discard, "lock must precede the discard: {steps:?}");
    }

    /// **The ordering rule that protects a user from losing everything to a typo.** A replace-from-phrase
    /// that is abandoned at the phrase window MUST leave the account intact — the phrase is collected while
    /// the old account is still there precisely so this is survivable.
    ///
    /// The fixture authorizes the destroy and THEN cancels the phrase window, which is the only combination
    /// that can distinguish "collects first" from "destroys first": a refused authorization would never
    /// reach the phrase window at all.
    #[test]
    fn abandoning_the_phrase_window_leaves_the_account_intact() {
        let custodian = RecordingCustodian::new();
        let outcome = replace_account(
            &gate(ConfirmDecision::Approve, None),
            &custodian,
            Replacement::FromPhrase,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(outcome, ReplaceOutcome::AbandonedAtPhrase);
        assert!(!outcome.destroyed_custody());
        assert_eq!(
            custodian.discards(),
            0,
            "the replacement was never supplied, so nothing may be destroyed"
        );
    }

    /// A FAILED discard must report itself, re-open the account, and enrol nothing — the account is still
    /// here, so leaving it locked forever or stacking a second account on top of it would both be wrong.
    #[test]
    fn a_failed_discard_reopens_the_account_and_enrols_nothing() {
        let confirmer = gate(ConfirmDecision::Approve, None);
        let custodian = RecordingCustodian::failing_discard();
        let outcome = replace_account(
            &confirmer,
            &custodian,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(outcome, ReplaceOutcome::DiscardFailed);
        assert!(!outcome.destroyed_custody());
        assert!(custodian.steps().contains(&"reopen"));
        assert!(
            !custodian.steps().iter().any(|s| s.starts_with("enrol")),
            "nothing was destroyed, so nothing may replace it: {:?}",
            custodian.steps()
        );
        assert!(
            confirmer.drawn().contains("still here"),
            "the user must be told their account survived: {}",
            confirmer.drawn()
        );
    }

    /// The worst outcome available — custody destroyed and the replacement failed — MUST be reported, not
    /// swallowed. A user left with no account and no message would have no idea what state their machine is
    /// in, which is the one situation where silence is unforgivable.
    #[test]
    fn a_failed_enrolment_after_a_successful_discard_says_so_plainly() {
        // Each verb's own sentence, because the two situations differ: after a failed NEW account the host
        // has nothing, while after a failed restore the user's words are still good and the message must
        // say so. Asserting one shared substring would let either message drift into the other's wording.
        for (what, words, expected) in [
            (
                Replacement::WithNewAccount,
                None,
                "This computer now has no DIG Account",
            ),
            (
                Replacement::FromPhrase,
                Some(RecoveryPhrase::generate().words().join(" ")),
                "Your 24 words are still valid",
            ),
        ] {
            let confirmer = gate(ConfirmDecision::Approve, words);
            let custodian = RecordingCustodian::failing_enrol();
            let outcome = replace_account(
                &confirmer,
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            assert_eq!(outcome, ReplaceOutcome::EnrolFailed, "{what:?}");
            assert!(
                outcome.destroyed_custody(),
                "{what:?}: the discard DID happen and the outcome must admit it"
            );
            assert_eq!(custodian.discards(), 1, "{what:?}");
            assert!(
                confirmer.drawn().contains(expected),
                "{what:?}: the user must be told what state their machine is in: {}",
                confirmer.drawn()
            );
        }
    }

    /// `destroyed_custody` is what every test above turns on, so it is pinned directly: it MUST be true for
    /// exactly the three outcomes that ran a discard, and false for the three that did not. A classifier
    /// that always answered `false` would quietly disarm the whole group.
    #[test]
    fn the_outcome_classifier_names_exactly_the_destructive_results() {
        for destructive in [
            ReplaceOutcome::Replaced,
            ReplaceOutcome::Removed,
            ReplaceOutcome::EnrolFailed,
        ] {
            assert!(destructive.destroyed_custody(), "{destructive:?}");
        }
        for safe in [
            ReplaceOutcome::RefusedByUser,
            ReplaceOutcome::AbandonedAtPhrase,
            ReplaceOutcome::DiscardFailed,
        ] {
            assert!(!safe.destroyed_custody(), "{safe:?}");
        }
    }
}
