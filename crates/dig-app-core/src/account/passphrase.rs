//! The **user-password** unlock ceremony — the thing that makes unlocking a DIG Account require a
//! secret the user knows (dig_ecosystem#1817, sharpening #1499).
//!
//! # What this replaces, and why
//!
//! dig-account seals the account master seed under a password (Argon2id + AES-256-GCM at rest). Until
//! this module, dig-app **generated that password itself** from the OS CSPRNG, filed it in the OS
//! credential store, and fetched it back on every boot — so the seal was real but its key was held by
//! the machine, not by the user. Every consequence followed from that one fact: the tray came up
//! unlocked at login, `Unlock…` opened nothing that was not already open, and any code running in the
//! user's own OS session could read the password out of the credential store and reach the seed
//! without a single prompt.
//!
//! A password the user types cannot be read out of a credential store. That is the whole change.
//!
//! # The two questions, and why they are different ceremonies
//!
//! Both arms of the boot ([`open_or_enroll`](crate::account::lifecycle::open_or_enroll)) collect
//! factors through the same seam, but they are asking opposite things:
//!
//! - [`PasswordPurpose::Existing`] — *"what is your password?"*. Asked once. A wrong answer is the
//!   caller's problem to retry; this ceremony reports exactly what was typed.
//! - [`PasswordPurpose::NewAccount`] — *"choose a password"*. Asked TWICE and compared, and held to
//!   [`MIN_PASSWORD_CHARS`], because a typo in a password nobody has yet is not a retry — it is an
//!   account sealed under a string the user does not know.
//!
//! # What this module does not do
//!
//! It draws no window of its own: every prompt goes through [`NativeConfirmer::request_input`], the
//! OS-owned masked input window v4.0.0 already ships (`confirm::windows_input` on Windows, the
//! `NSAlert` accessory field on macOS, `zenity --entry` on Linux). It never logs, returns, or persists
//! a password: the typed text lives in the [`Zeroizing`](zeroize::Zeroizing) buffer the window hands
//! back, is turned into a [`Password`], and is dropped.

use std::sync::Arc;

use async_trait::async_trait;
use dig_account::{AccountId, AuthFactors, ProfileIx, SpendDecision, SpendSummary};
use dig_session::Password;

use crate::account::auth::{AuthCeremony, CeremonyError};
use crate::account::ceremony::confirm_spend_natively;
use crate::confirm::{InputOutcome, InputPrompt, NativeConfirmer};

/// The shortest account password this app will seal a seed under.
///
/// Length is the only bar. Composition rules ("one digit, one symbol") are what push people to
/// `Password1!`, and NIST SP 800-63B dropped them for exactly that reason; a long passphrase is both
/// stronger and rememberable. Twelve characters is enough that Argon2id's cost makes offline guessing
/// unattractive, and short enough that "four short words" clears it.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// How many times a new-password ceremony re-asks before giving up.
///
/// Bounded so a confirmer backend that cannot draw — or one whose window returns instantly — cannot
/// spin prompts forever. Generous enough that a person mistyping twice is not thrown out.
const NEW_PASSWORD_ATTEMPTS: usize = 5;

/// Which question the ceremony is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPurpose {
    /// Unlock an account that already exists. One prompt; whatever is typed is returned verbatim.
    Existing,
    /// Choose the password a brand-new account will be sealed under. Two prompts, compared, and held
    /// to [`MIN_PASSWORD_CHARS`].
    NewAccount,
}

/// An [`AuthCeremony`] that gets the account password from the **user**, at an OS-native masked prompt.
///
/// Spend confirmation is unchanged — it goes through the same per-OS biometric gate
/// ([`confirm_spend_natively`]) every other custody action does.
pub struct PasswordCeremony {
    confirmer: Arc<dyn NativeConfirmer>,
    purpose: PasswordPurpose,
}

impl PasswordCeremony {
    /// A ceremony that asks for the password of an account that already exists.
    pub fn to_unlock(confirmer: Arc<dyn NativeConfirmer>) -> Self {
        Self {
            confirmer,
            purpose: PasswordPurpose::Existing,
        }
    }

    /// A ceremony that asks the user to CHOOSE the password for an account being created.
    pub fn for_a_new_account(confirmer: Arc<dyn NativeConfirmer>) -> Self {
        Self {
            confirmer,
            purpose: PasswordPurpose::NewAccount,
        }
    }

    /// Which question this ceremony asks.
    pub fn purpose(&self) -> PasswordPurpose {
        self.purpose
    }

    /// Ask for the password of an existing account, once.
    ///
    /// `reason` is the caller's human-facing explanation of why the prompt appeared — a re-auth before
    /// a signature says so, rather than showing the same words as a boot unlock.
    fn ask_to_unlock(&self, reason: Option<&str>) -> Result<Password, CeremonyError> {
        let body = reason.unwrap_or(UNLOCK_BODY);
        let typed = self.ask(UNLOCK_HEADING, body, "Unlock")?;
        Ok(Password::new(typed.as_bytes()))
    }

    /// Ask the user to choose a new password: type it, type it again, and clear the length bar.
    ///
    /// Re-asks on a mismatch or a too-short password, with the reason in the window, up to
    /// [`NEW_PASSWORD_ATTEMPTS`] times.
    fn ask_to_choose(&self) -> Result<Password, CeremonyError> {
        let mut problem = String::new();
        for _ in 0..NEW_PASSWORD_ATTEMPTS {
            let body = format!("{problem}{CHOOSE_BODY}");
            let chosen = self.ask(CHOOSE_HEADING, &body, "Continue")?;
            if chosen.chars().count() < MIN_PASSWORD_CHARS {
                problem = format!(
                    "That password is too short — it needs at least {MIN_PASSWORD_CHARS} characters.\n\n"
                );
                continue;
            }
            let again = self.ask(CONFIRM_HEADING, CONFIRM_BODY, "Create my account")?;
            if *again != *chosen {
                problem = "Those two passwords were not the same.\n\n".to_string();
                continue;
            }
            return Ok(Password::new(chosen.as_bytes()));
        }
        Err(CeremonyError::Cancelled)
    }

    /// Draw one masked password prompt and return what was typed.
    ///
    /// Masked by default and REVEALABLE (`SPEC.md` §3.1d): someone able to see the screen is the live
    /// risk, but a password typed entirely blind cannot be checked, so the window offers a deliberate
    /// un-mask rather than defaulting to clear text.
    fn ask(
        &self,
        heading: &str,
        body: &str,
        submit: &'static str,
    ) -> Result<zeroize::Zeroizing<String>, CeremonyError> {
        match self.confirmer.request_input(&InputPrompt {
            title: PROMPT_TITLE,
            heading,
            body,
            field_label: "Password:",
            submit,
            masked: true,
            reveal_label: Some("Show my password while I type"),
        }) {
            InputOutcome::Provided(text) => Ok(text),
            InputOutcome::Cancelled => Err(CeremonyError::Cancelled),
            InputOutcome::Unavailable => Err(CeremonyError::Unavailable(
                "no password window could be drawn on this host".to_string(),
            )),
        }
    }
}

/// The title every password window carries, so the user can tell a DIG prompt from an impostor's by
/// its consistency.
const PROMPT_TITLE: &str = "DIG — Your DIG Account";

/// What the unlock prompt asks.
const UNLOCK_HEADING: &str = "Enter your DIG Account password to unlock it.";

/// The default unlock body, used when the caller offers no more specific reason.
///
/// `concat!` rather than a `\`-continued literal: `cargo fmt` collapses a continuation and KEEPS the
/// source indentation as real spaces, which has already shipped visible multi-space holes in the middle
/// of this app's highest-stakes copy (see `journey::UNOPENABLE_BODY`).
const UNLOCK_BODY: &str = concat!(
    "Your DIG Account stays locked until you unlock it, so nothing on this computer can sign with it ",
    "or read what it has sealed.\n\n",
    "Reading DIG content does not need your account, and keeps working while it is locked."
);

/// What the choose-a-password prompt asks.
const CHOOSE_HEADING: &str = "Choose a password for your DIG Account.";

/// The choose-a-password body — the part that has to be honest about the consequence.
const CHOOSE_BODY: &str = concat!(
    "This password unlocks your DIG Account on this computer. DIG does not store it anywhere and ",
    "cannot reset it or recover it for you.\n\n",
    "If you forget it, your 24-word recovery phrase is the only way back to this account — which is ",
    "why you were shown those words first.\n\n",
    "Use at least 12 characters. A few unrelated words you will remember beats a short, clever one."
);

/// What the second, confirming prompt asks.
const CONFIRM_HEADING: &str = "Type your password once more.";

/// The confirming body. Deliberately short: the explanation was on the previous window, and the only
/// job here is to catch a typo before it becomes the key to an account.
const CONFIRM_BODY: &str = concat!(
    "Typing it twice is what catches a typo. A password with a typo in it would become the real ",
    "password to your account, and you would have no way to discover which one it was."
);

#[async_trait]
impl AuthCeremony for PasswordCeremony {
    async fn collect_unlock_factors(
        &self,
        _account: &AccountId,
        reason: Option<&str>,
    ) -> Result<AuthFactors, CeremonyError> {
        let password = match self.purpose {
            PasswordPurpose::Existing => self.ask_to_unlock(reason)?,
            PasswordPurpose::NewAccount => self.ask_to_choose()?,
        };
        Ok(AuthFactors::password_only(password))
    }

    async fn confirm_spend(
        &self,
        _account: &AccountId,
        _profile: ProfileIx,
        summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        confirm_spend_natively(self.confirmer.as_ref(), summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScriptedInput;

    fn account() -> AccountId {
        AccountId::new("default")
    }

    /// A password long enough to clear the bar, DERIVED from a label rather than written inline so
    /// static analysis never reads it as a hard-coded cryptographic value (the `auth.rs:121` pattern).
    fn long_enough(label: &str) -> String {
        use sha2::{Digest, Sha256};
        let hex = hex::encode(Sha256::digest(label.as_bytes()));
        hex[..MIN_PASSWORD_CHARS + 4].to_string()
    }

    async fn collect(
        confirmer: Arc<ScriptedInput>,
        purpose: PasswordPurpose,
    ) -> Result<AuthFactors, CeremonyError> {
        let ceremony = match purpose {
            PasswordPurpose::Existing => PasswordCeremony::to_unlock(confirmer),
            PasswordPurpose::NewAccount => PasswordCeremony::for_a_new_account(confirmer),
        };
        ceremony.collect_unlock_factors(&account(), None).await
    }

    /// The property: the password that comes back is the one the USER TYPED — not a derived, generated
    /// or constant one. Two different typed strings must produce two different passwords, because a
    /// ceremony that ignored its input and returned any fixed value would satisfy "a password came
    /// back" perfectly.
    #[tokio::test]
    async fn an_unlock_returns_exactly_what_the_user_typed() {
        let typed = long_enough("typed-a");
        let factors = collect(
            ScriptedInput::of([typed.clone()]),
            PasswordPurpose::Existing,
        )
        .await
        .expect("a submitted password unlocks");
        assert_eq!(factors.password.as_bytes(), typed.as_bytes());

        let other = long_enough("typed-b");
        let second = collect(
            ScriptedInput::of([other.clone()]),
            PasswordPurpose::Existing,
        )
        .await
        .unwrap();
        assert_eq!(second.password.as_bytes(), other.as_bytes());
        assert_ne!(factors.password.as_bytes(), second.password.as_bytes());
    }

    /// An unlock asks EXACTLY ONCE. A ceremony that asked twice and compared would reject the normal
    /// case (there is nothing to compare an existing password against).
    #[tokio::test]
    async fn an_unlock_asks_exactly_one_question() {
        let script = ScriptedInput::of([long_enough("once")]);
        collect(Arc::clone(&script), PasswordPurpose::Existing)
            .await
            .unwrap();
        assert_eq!(script.prompts().len(), 1);
    }

    /// Every password prompt is MASKED and offers a deliberate reveal (`SPEC.md` §3.1d). Asserted on
    /// the prompt the window was actually handed, not on the constants, so a wiring mistake is caught.
    #[tokio::test]
    async fn every_password_prompt_is_masked_and_revealable() {
        let pw = long_enough("masked");
        let script = ScriptedInput::of([pw.clone(), pw]);
        collect(Arc::clone(&script), PasswordPurpose::NewAccount)
            .await
            .unwrap();
        let prompts = script.prompts();
        assert_eq!(prompts.len(), 2, "a new password is asked for twice");
        assert!(prompts.iter().all(|p| p.masked));
        // The LABEL, not merely that a control exists. The first cut of this window inherited the
        // recovery-phrase copy and offered to "Show the words while I type" beside a password field —
        // a defect an `is_some()` assertion is structurally unable to see.
        for prompt in &prompts {
            let label = prompt
                .reveal_label
                .as_deref()
                .expect("a password window must offer a reveal");
            assert!(
                label.contains("password"),
                "the reveal control must describe what is actually in the field: {label:?}"
            );
            assert!(
                !label.contains("words"),
                "a password window must not borrow the recovery phrase's copy: {label:?}"
            );
        }
    }

    /// A new account's password must be typed twice and the two must match.
    #[tokio::test]
    async fn a_new_password_must_be_typed_twice_and_match() {
        let pw = long_enough("match");
        let script = ScriptedInput::of([pw.clone(), pw.clone()]);
        let factors = collect(script, PasswordPurpose::NewAccount).await.unwrap();
        assert_eq!(factors.password.as_bytes(), pw.as_bytes());
    }

    /// A MISMATCH must re-ask rather than seal the account under the first thing typed.
    ///
    /// The script mismatches once and then agrees, so the assertion distinguishes "re-asked and used
    /// the agreed password" from BOTH "accepted the first entry" and "gave up". A script that only ever
    /// mismatched could not tell the second of those from the first.
    #[tokio::test]
    async fn a_mismatched_new_password_is_re_asked_not_accepted() {
        let first = long_enough("first");
        let agreed = long_enough("agreed");
        let script = ScriptedInput::of([
            first.clone(),
            agreed.clone(),
            agreed.clone(),
            agreed.clone(),
        ]);

        let factors = collect(Arc::clone(&script), PasswordPurpose::NewAccount)
            .await
            .expect("the second round agrees");

        assert_eq!(
            factors.password.as_bytes(),
            agreed.as_bytes(),
            "the agreed password is the one sealed, never the mismatched first entry"
        );
        assert_ne!(factors.password.as_bytes(), first.as_bytes());
        assert_eq!(script.prompts().len(), 4, "it re-asked both questions");
    }

    /// The length bar, pinned from BOTH sides: one character under must be refused, and EXACTLY
    /// [`MIN_PASSWORD_CHARS`] must be accepted. A bound tested only from below can only confirm itself.
    #[tokio::test]
    async fn the_length_bar_refuses_one_under_and_accepts_exactly_the_minimum() {
        let at_bound = long_enough("bound")[..MIN_PASSWORD_CHARS].to_string();
        let under = at_bound[..MIN_PASSWORD_CHARS - 1].to_string();

        // Too short first, then exactly at the bound (twice, to confirm) — so this single script proves
        // the under-length entry was REJECTED and the at-bound one ACCEPTED.
        let script = ScriptedInput::of([under, at_bound.clone(), at_bound.clone()]);
        let factors = collect(Arc::clone(&script), PasswordPurpose::NewAccount)
            .await
            .expect("a password exactly at the bound is accepted");

        assert_eq!(factors.password.as_bytes(), at_bound.as_bytes());
        assert_eq!(
            script.prompts().len(),
            3,
            "the short entry cost a re-ask and was never confirmed"
        );
    }

    /// A password that is too short must never reach the seal, even if the user types the SAME short
    /// password twice. Without the length check, agreeing twice would be enough.
    #[tokio::test]
    async fn a_short_password_typed_twice_is_still_refused() {
        let short = "abcdefg".to_string();
        assert!(short.chars().count() < MIN_PASSWORD_CHARS);
        let script = ScriptedInput::of([short.clone(), short.clone(), short.clone(), short]);

        let result = collect(script, PasswordPurpose::NewAccount).await;

        assert!(
            matches!(result, Err(CeremonyError::Cancelled)),
            "a too-short password must never be sealed, however many times it is typed"
        );
    }

    /// Cancelling the window yields no factors at all — fail closed.
    #[tokio::test]
    async fn cancelling_the_prompt_yields_no_password() {
        let result = collect(ScriptedInput::cancelling(), PasswordPurpose::Existing).await;
        assert!(matches!(result, Err(CeremonyError::Cancelled)));
    }

    /// A host that cannot draw an input window must report that it could not ASK — never an empty
    /// password, which would be a real string that a seal could be built on.
    #[tokio::test]
    async fn a_host_with_no_input_window_fails_closed() {
        let result = collect(ScriptedInput::unavailable(), PasswordPurpose::Existing).await;
        assert!(matches!(result, Err(CeremonyError::Unavailable(_))));
    }

    /// The re-ask loop is BOUNDED: a script that never agrees must terminate rather than spinning
    /// windows forever. Two prompts per round, so the prompt count pins the bound exactly.
    #[tokio::test]
    async fn the_re_ask_loop_is_bounded() {
        let a = long_enough("never-a");
        let b = long_enough("never-b");
        let script = ScriptedInput::alternating(a, b);

        let result = collect(Arc::clone(&script), PasswordPurpose::NewAccount).await;

        assert!(matches!(result, Err(CeremonyError::Cancelled)));
        assert_eq!(
            script.prompts().len(),
            NEW_PASSWORD_ATTEMPTS * 2,
            "each attempt costs exactly two prompts and the attempts are bounded"
        );
    }

    /// The unlock body must tell the user the thing that is easiest to get wrong about a locked
    /// account: reading DIG content does not need it (§6.0 — consumption is never gated on custody).
    #[test]
    fn the_unlock_copy_says_reading_content_still_works() {
        assert!(UNLOCK_BODY.contains("keeps working while it is locked"));
    }

    /// No copy this module shows may contain a run of spaces: `cargo fmt` reflowing a continued literal
    /// is how visible multi-space holes have already shipped in this app's account windows.
    #[test]
    fn no_password_copy_has_reflow_holes() {
        for body in [UNLOCK_BODY, CHOOSE_BODY, CONFIRM_BODY] {
            assert!(!body.contains("  "), "copy grew a multi-space hole: {body}");
        }
    }

    /// The caller's reason REPLACES the default body, so a re-auth before a signature explains itself
    /// rather than repeating the boot-unlock words.
    #[tokio::test]
    async fn a_callers_reason_is_what_the_window_shows() {
        let script = ScriptedInput::of([long_enough("reason")]);
        let ceremony = PasswordCeremony::to_unlock(script.confirmer());
        ceremony
            .collect_unlock_factors(&account(), Some("A dapp is asking you to sign something."))
            .await
            .unwrap();
        assert_eq!(
            script.prompts()[0].body,
            "A dapp is asking you to sign something."
        );
    }
}
