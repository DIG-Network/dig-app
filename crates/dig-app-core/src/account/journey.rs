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

use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
use crate::account::phrase_vault::PhraseVault;
use crate::account::recovery::RecoveryPhrase;
use crate::confirm::{ConfirmDecision, NativeConfirmer, NoticePrompt, RevealPrompt};
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
        let shown = self.confirmer.show_notice(&NoticePrompt {
            title: "DIG — Your recovery phrase",
            heading: "Write these 24 words down, in order, and keep them somewhere safe.",
            body: &format!(
                "{}\nThese words ARE your DIG Account. Anyone who has them can take it, and \
                 nobody — including DIG — can recover your account without them.",
                &*words
            ),
            acknowledge: "I have written these down",
        });
        if shown != ConfirmDecision::Approve {
            return decision_for(shown);
        }

        // The second screen is not a formality: it is the moment the user is asked to make a claim about
        // the world (the words are somewhere other than this screen) rather than to dismiss a dialog.
        let confirmed = self.confirmer.show_notice(&NoticePrompt {
            title: "DIG — Confirm you saved it",
            heading: "Do you have your 24 words written down somewhere safe?",
            body: "If you continue without them and later lose this computer, your DIG Account, its \
                   address and everything sealed under it are gone for good. You can view the words \
                   again later from the DIG tray menu.",
            acknowledge: "Yes, I have them",
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

/// What a phrase-less (legacy) account is told, and what it is offered.
///
/// There is exactly one honest remedy and it is destructive, so this function ONLY informs — it never
/// acts. The account keeps working untouched; replacing it is a separate, explicitly-confirmed step the
/// user must ask for again (see the tray's `FixMissingPhrase` handler).
pub fn explain_missing_phrase(confirmer: &dyn NativeConfirmer) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — No recovery phrase",
        heading: "This DIG Account has no recovery phrase.",
        body: "It was created before DIG had recovery phrases, so its key exists only on this \
               computer: if you lose this machine, the account, its address and everything sealed \
               under it cannot be recovered — not by you and not by DIG.\n\n\
               Words cannot be added to an existing account. The only way to get a recoverable \
               account is to create a NEW one, which gives you a NEW identity and address — the old \
               account's data stays sealed to the old key.\n\n\
               Nothing has changed yet. Your account still works exactly as before.",
        acknowledge: "I understand",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        notices: Mutex<Vec<ConfirmDecision>>,
        drawn: Mutex<Vec<String>>,
    }

    impl ScriptedConfirmer {
        fn new(reveal: Vec<ConfirmDecision>, notices: Vec<ConfirmDecision>) -> Self {
            Self {
                reveal: Mutex::new(reveal),
                notices: Mutex::new(notices),
                drawn: Mutex::new(Vec::new()),
            }
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
            self.drawn.lock().unwrap().push(format!(
                "{}\n{}\n{}",
                prompt.title, prompt.heading, prompt.body
            ));
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
        let drawn = confirmer.drawn();
        for word in phrase.words() {
            assert!(
                drawn.contains(word),
                "the word {word:?} never reached a window"
            );
        }
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
}
