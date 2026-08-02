//! The unlock ceremonies — how the app obtains the password that opens the account master seed.
//!
//! dig-account unlocks the account master seed with a PASSWORD (Argon2id over the DIGOP1 blob). Two
//! ceremonies supply one, and only one of them is a custody boundary a user actually holds:
//!
//! - **[`PromptedCeremony`] — the production ceremony (dig_ecosystem#1817).** It ASKS the user, in the
//!   app's own native masked window ([`password`](crate::account::password)). The password exists only
//!   in the user's head, so unlocking is a real gate: code running in the user's OS session cannot type
//!   it.
//! - **[`CredentialCeremony`] — the RETIRED zero-prompt ceremony, kept only to REPRODUCE the pre-#1817
//!   password model in tests.** It keeps a machine-generated password in the OS credential store and
//!   hands it over with no prompt, which is precisely the defect #1817 exists to remove: any code
//!   running as the logged-in user could read it, so there was no user-known secret protecting custody
//!   at all. Production has moved off it entirely — no boot path reaches for it, and
//!   [`migration`](crate::account::migration) reads the retired machine password DIRECTLY
//!   ([`PreCollectedPassword`]) rather than through this ceremony. It survives so migration's own tests
//!   can seal a realistic account under the old zero-prompt model — the same generation real machines
//!   once used — and prove the re-seal path opens and rescues it. It is NOT a fallback: a path needing
//!   no password would defeat the whole change.
//!
//! Spend confirmation (#1548, slice C — money goes live) is gated on the per-OS native confirmer: the
//! money path calls [`confirm_spend`](AuthCeremony::confirm_spend), which renders the independently
//! re-derived [`SpendSummary`] (recipients / fee / tier — never raw bytes) and requires the user to
//! authorize it at the OS biometric/passphrase prompt (Windows Hello / macOS Touch ID / Linux polkit).
//! A headless host has no confirmer, so a spend confirmation fails closed there (`Unavailable`). Both
//! ceremonies share that path exactly (`confirm_spend_natively`), so the money gate cannot differ
//! between them.

use std::sync::Arc;

use async_trait::async_trait;
use dig_account::{AccountId, AuthFactors, ProfileIx, SpendDecision, SpendSummary};
use dig_session::Password;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::account::auth::{AuthCeremony, CeremonyError};
use crate::account::password::{establish_password, request_password, PasswordOutcome};
use crate::confirm::{native_confirmer, ConfirmDecision, NativeConfirmer, SignPrompt};
use crate::keystore::CredentialStore;

/// The number of random bytes in a generated account master password before hex-encoding — 32 bytes
/// (256 bits) of CSPRNG entropy, well beyond any Argon2id-stretched brute-force reach.
const GENERATED_PASSWORD_BYTES: usize = 32;

/// The RETIRED zero-prompt [`AuthCeremony`]: it sources the account password from an OS
/// [`CredentialStore`], generating + persisting one on first run.
///
/// **A test-only reproduction of the pre-#1817 model.** A password the machine invents and the machine
/// keeps is not a custody secret — anything running as the logged-in user can read it — so no boot,
/// unlock, or sign path uses this any more, and production [`migration`](crate::account::migration)
/// reads the retired machine password DIRECTLY ([`PreCollectedPassword`]) rather than through this
/// ceremony. It survives so migration's tests can seal a realistic account under the old zero-prompt
/// model — the same generation real machines once used — and then prove the re-seal path opens and
/// rescues it. Reaching for it in production anywhere would reinstate a no-password path and undo
/// dig_ecosystem#1817.
///
/// Generic over the credential backend so it is unit-testable with an in-memory double and swaps the
/// real `OsCredentialStore` (a Windows/macOS-only type) in production.
pub struct CredentialCeremony<C: CredentialStore> {
    store: C,
    /// The terminal human gate for a spend confirmation — the per-OS native biometric/passphrase
    /// confirmer (or the fail-closed headless default). Unlock factors come zero-prompt from the
    /// credential store; a SPEND, by contrast, always requires the human at this gate.
    confirmer: Arc<dyn NativeConfirmer>,
}

impl<C: CredentialStore> CredentialCeremony<C> {
    /// Wrap `store` as the zero-prompt password source, gating spend confirmations on the host's
    /// [`native_confirmer`] (the per-OS biometric prompt, or the fail-closed headless default).
    pub fn new(store: C) -> Self {
        Self {
            store,
            confirmer: Arc::from(native_confirmer()),
        }
    }

    /// Build the ceremony with an explicit spend `confirmer` — the production path can pass the tray's
    /// shared confirmer, and tests inject a scripted double to assert the confirm gate.
    pub fn with_confirmer(store: C, confirmer: Arc<dyn NativeConfirmer>) -> Self {
        Self { store, confirmer }
    }

    /// The credential-store key the account's master password is filed under — see
    /// [`machine_password_key`].
    fn password_key(account: &AccountId) -> String {
        machine_password_key(account)
    }

    /// Fetch the stored master password for `account`, or generate + persist one on first run.
    ///
    /// The generated password is 256 bits of CSPRNG entropy, hex-encoded so it round-trips through the
    /// credential store's string values without encoding loss.
    fn password_for(&self, account: &AccountId) -> Result<Password, CeremonyError> {
        let key = Self::password_key(account);
        if let Some(existing) = self
            .store
            .get(&key)
            .map_err(|e| CeremonyError::Unavailable(e.to_string()))?
        {
            return Ok(Password::new(existing.as_bytes()));
        }
        let generated = generate_password();
        self.store
            .set(&key, &generated)
            .map_err(|e| CeremonyError::Unavailable(e.to_string()))?;
        Ok(Password::new(generated.as_bytes()))
    }
}

/// The credential-store key a MACHINE-GENERATED account password is filed under.
///
/// Stable across restarts (that is how the retired zero-prompt boot found it) and namespaced per account
/// so several accounts never collide. It is public to the crate because its PRESENCE is now the signal
/// that an account still needs migrating off the machine password
/// ([`migration`](crate::account::migration)) — and because that migration is the one thing that
/// legitimately deletes it.
pub(crate) fn machine_password_key(account: &AccountId) -> String {
    format!("{account}.master-password")
}

/// Generate a hex-encoded 256-bit account password from the OS CSPRNG, holding the raw bytes in a
/// scrubbing buffer so only the (equally sensitive, but credential-store-bound) hex string escapes.
fn generate_password() -> String {
    let mut raw = Zeroizing::new([0u8; GENERATED_PASSWORD_BYTES]);
    rand_core::OsRng.fill_bytes(&mut *raw);
    hex::encode(*raw)
}

#[async_trait]
impl<C: CredentialStore + Send + Sync> AuthCeremony for CredentialCeremony<C> {
    async fn collect_unlock_factors(
        &self,
        account: &AccountId,
        _reason: Option<&str>,
    ) -> Result<AuthFactors, CeremonyError> {
        Ok(AuthFactors::password_only(self.password_for(account)?))
    }

    async fn confirm_spend(
        &self,
        _account: &AccountId,
        _profile: ProfileIx,
        summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        confirm_spend_natively(&*self.confirmer, summary)
    }
}

/// An [`AuthCeremony`] over a password the caller ALREADY holds.
///
/// It asks nothing and decides nothing — it hands over the bytes it was given. That makes it the right
/// seam for the two callers that legitimately have a password in hand and no user to ask:
///
/// - [`migration`](crate::account::migration), which has just read the retired machine password out of
///   the credential store and needs to open the account with it once;
/// - tests, which stand in for a person typing.
///
/// It is deliberately NOT a way to skip the password prompt: it cannot obtain a password, only relay
/// one, so anything using it must already have solved the custody question elsewhere. It refuses spend
/// confirmations outright, so it can never become a silent money path.
#[doc(hidden)]
pub struct PreCollectedPassword(Zeroizing<Vec<u8>>);

impl PreCollectedPassword {
    /// Relay `password` on every unlock. The bytes are held in a scrubbing buffer.
    pub fn new(password: impl AsRef<[u8]>) -> Self {
        Self(Zeroizing::new(password.as_ref().to_vec()))
    }
}

#[async_trait]
impl AuthCeremony for PreCollectedPassword {
    async fn collect_unlock_factors(
        &self,
        _account: &AccountId,
        _reason: Option<&str>,
    ) -> Result<AuthFactors, CeremonyError> {
        Ok(AuthFactors::password_only(Password::new(&self.0)))
    }

    async fn confirm_spend(
        &self,
        _account: &AccountId,
        _profile: ProfileIx,
        _summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        // Refusing (rather than approving) keeps this unusable as a money path if it is ever wired
        // somewhere it does not belong.
        Err(CeremonyError::Unavailable(
            "a pre-collected password does not authorize spends".to_string(),
        ))
    }
}

/// Which password question a [`PromptedCeremony`] puts to the user.
///
/// A ceremony cannot work this out for itself: `open_or_enroll` calls the SAME
/// [`collect_unlock_factors`](AuthCeremony::collect_unlock_factors) whether it is about to enrol a new
/// account or unlock one that exists, and the two questions are not interchangeable. Asking "enter your
/// password" while creating an account invites a password nobody has yet; asking someone to "choose a
/// password" twice to open an account they already own is a demand they cannot satisfy. So the caller —
/// which knows which it is doing — states it here.
pub enum PasswordIntent {
    /// A NEW custody root is being sealed: ask the user to choose a password, typed twice.
    Establish {
        /// What the password is being set for, in the user's terms ("Set a password for your new DIG
        /// account.").
        purpose: String,
    },
    /// An EXISTING account is being opened: ask for the password once.
    Unlock {
        /// Why the account is being opened right now ("DIG needs to sign a request."), so the window
        /// is never an unexplained demand for a secret.
        reason: String,
    },
}

/// The production [`AuthCeremony`]: it ASKS THE USER for the account password (dig_ecosystem#1817).
///
/// This is what makes `Unlock…` a real ceremony rather than a no-op. The password never touches disk,
/// the credential store, or a log — it goes from the native window into
/// [`AuthFactors`] and is zeroized with them.
pub struct PromptedCeremony {
    confirmer: Arc<dyn NativeConfirmer>,
    intent: PasswordIntent,
}

impl PromptedCeremony {
    /// Ask through `confirmer` — in production the host's [`native_confirmer`], in tests a scripted
    /// double — for the password `intent` describes.
    pub fn new(confirmer: Arc<dyn NativeConfirmer>, intent: PasswordIntent) -> Self {
        Self { confirmer, intent }
    }

    /// Establish a NEW password for an account being created or re-sealed, through the host's own
    /// confirmer.
    pub fn establishing(purpose: impl Into<String>) -> Self {
        Self::new(
            Arc::from(native_confirmer()),
            PasswordIntent::Establish {
                purpose: purpose.into(),
            },
        )
    }

    /// Ask for the password of an account that already exists, through the host's own confirmer.
    pub fn unlocking(reason: impl Into<String>) -> Self {
        Self::new(
            Arc::from(native_confirmer()),
            PasswordIntent::Unlock {
                reason: reason.into(),
            },
        )
    }
}

#[async_trait]
impl AuthCeremony for PromptedCeremony {
    async fn collect_unlock_factors(
        &self,
        _account: &AccountId,
        _reason: Option<&str>,
    ) -> Result<AuthFactors, CeremonyError> {
        let outcome = match &self.intent {
            PasswordIntent::Establish { purpose } => establish_password(&*self.confirmer, purpose),
            PasswordIntent::Unlock { reason } => request_password(&*self.confirmer, reason),
        };
        match outcome {
            PasswordOutcome::Provided(text) => {
                Ok(AuthFactors::password_only(Password::new(text.as_bytes())))
            }
            // Fail-closed, and DISTINCTLY: a cancellation is the user's choice, while an undrawable
            // window is the host's inability — the boot reports them differently.
            PasswordOutcome::Cancelled => Err(CeremonyError::Cancelled),
            PasswordOutcome::Unavailable => Err(CeremonyError::Unavailable(
                "no window to ask for the account password".to_string(),
            )),
        }
    }

    async fn confirm_spend(
        &self,
        _account: &AccountId,
        _profile: ProfileIx,
        summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        confirm_spend_natively(&*self.confirmer, summary)
    }
}

/// Put a spend to the human at `confirmer`'s native gate and map the answer.
///
/// Shared by both ceremonies so the money gate is ONE implementation: an unlock ceremony that differed
/// here would mean the spend confirmation a user gets depends on how their account happens to be
/// sealed, which is exactly the kind of divergence a second copy produces.
///
/// Renders the re-derived effect of the spend (recipients / fee / tier) — NEVER raw bytes. The summary
/// is dig-account's independently re-derived structure, so the prompt shows exactly what the signature
/// will authorize.
fn confirm_spend_natively(
    confirmer: &dyn NativeConfirmer,
    summary: &SpendSummary,
) -> Result<SpendDecision, CeremonyError> {
    let body = render_spend(summary);
    let prompt = SignPrompt {
        origin: SPEND_CONFIRM_ORIGIN,
        payload_type: SPEND_PAYLOAD_TYPE,
        decoded_tx: Some(&body),
    };
    Ok(match confirmer.confirm_sign(&prompt) {
        ConfirmDecision::Approve => SpendDecision::Approve,
        ConfirmDecision::Deny => {
            SpendDecision::Decline(Some("declined at the confirm prompt".to_string()))
        }
        ConfirmDecision::Timeout => {
            SpendDecision::Decline(Some("the confirm prompt timed out".to_string()))
        }
        // No native confirmer (a headless host) — fail closed as a ceremony error, so the spend
        // aborts with no key touched rather than silently declining as if the user chose to.
        ConfirmDecision::Unavailable => {
            return Err(CeremonyError::Unavailable(
                "no native confirmer for the spend prompt".to_string(),
            ))
        }
    })
}

/// The origin label shown on a local wallet spend confirmation — a fixed, non-dapp source (the spend
/// originates in the user's own app, not a vouched web origin).
const SPEND_CONFIRM_ORIGIN: &str = "dig-app (local wallet)";

/// The payload tag naming what the confirm prompt is authorizing (parallels the §5.6.5 dapp sign tags).
const SPEND_PAYLOAD_TYPE: &str = "wallet.spend";

/// Render a [`SpendSummary`] as the plain-text confirm body: the custody tier, each recipient +
/// amount, and the fee. Uses the summary's own [`Display`](std::fmt::Display) — the recipients + fee
/// are dig-account's independently re-derived figures, so the body cannot disagree with what is signed.
/// Plain text only (the per-OS confirmers neutralize markup), never key material.
fn render_spend(summary: &SpendSummary) -> String {
    format!("Approve this {:?}-tier spend?\n\n{}", summary.tier, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KeystoreError;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// An in-memory [`CredentialStore`] double that persists across a "restart" (a second ceremony
    /// over the same shared map), so first-run generation vs a returning fetch can both be asserted.
    #[derive(Clone, Default)]
    struct MemCred(Arc<Mutex<HashMap<String, String>>>);

    impl CredentialStore for MemCred {
        fn get(&self, account: &str) -> Result<Option<String>, KeystoreError> {
            Ok(self.0.lock().unwrap().get(account).cloned())
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().insert(account.into(), secret.into());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    fn account() -> AccountId {
        AccountId::new("primary")
    }

    #[tokio::test]
    async fn first_run_generates_and_persists_a_password() {
        let cred = MemCred::default();
        let ceremony = CredentialCeremony::new(cred.clone());

        let factors = ceremony
            .collect_unlock_factors(&account(), None)
            .await
            .unwrap();

        // The password was persisted to the credential store under the namespaced key.
        let stored = cred
            .get(&CredentialCeremony::<MemCred>::password_key(&account()))
            .unwrap()
            .expect("first run must persist a generated password");
        assert_eq!(factors.password.as_bytes(), stored.as_bytes());
        // 32 random bytes hex-encoded ⇒ 64 hex chars.
        assert_eq!(stored.len(), GENERATED_PASSWORD_BYTES * 2);
    }

    #[tokio::test]
    async fn a_returning_boot_returns_the_same_stored_password() {
        let cred = MemCred::default();

        let first = CredentialCeremony::new(cred.clone())
            .collect_unlock_factors(&account(), None)
            .await
            .unwrap();
        // A fresh ceremony over the SAME store (a "restart") must return the SAME password, so the
        // enrolled seed unlocks — never a freshly generated one that would fail the AEAD tag.
        let second = CredentialCeremony::new(cred)
            .collect_unlock_factors(&account(), None)
            .await
            .unwrap();
        assert_eq!(first.password.as_bytes(), second.password.as_bytes());
    }

    #[tokio::test]
    async fn distinct_accounts_get_distinct_passwords() {
        let cred = MemCred::default();
        let ceremony = CredentialCeremony::new(cred);

        let a = ceremony
            .collect_unlock_factors(&AccountId::new("a"), None)
            .await
            .unwrap();
        let b = ceremony
            .collect_unlock_factors(&AccountId::new("b"), None)
            .await
            .unwrap();
        assert_ne!(a.password.as_bytes(), b.password.as_bytes());
    }

    #[tokio::test]
    async fn a_backend_error_fails_closed() {
        struct Broken;
        impl CredentialStore for Broken {
            fn get(&self, _: &str) -> Result<Option<String>, KeystoreError> {
                Err(KeystoreError::CredentialStore("backend down".into()))
            }
            fn set(&self, _: &str, _: &str) -> Result<(), KeystoreError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), KeystoreError> {
                Ok(())
            }
        }
        let result = CredentialCeremony::new(Broken)
            .collect_unlock_factors(&account(), None)
            .await;
        assert!(matches!(result, Err(CeremonyError::Unavailable(_))));
    }

    /// A [`NativeConfirmer`] double returning a fixed decision + recording the confirm body it was
    /// shown, so a test can assert the ceremony routed the spend through the native gate with the
    /// re-derived summary (never raw bytes).
    struct ScriptedConfirmer {
        decision: ConfirmDecision,
        last_body: Mutex<Option<String>>,
    }
    impl ScriptedConfirmer {
        fn new(decision: ConfirmDecision) -> Self {
            Self {
                decision,
                last_body: Mutex::new(None),
            }
        }
    }
    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _prompt: &crate::confirm::PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("the spend ceremony never pairs")
        }
        fn confirm_connect(&self, _prompt: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("the spend ceremony never connects")
        }
        fn confirm_sign(&self, prompt: &SignPrompt<'_>) -> ConfirmDecision {
            *self.last_body.lock().unwrap() = prompt.decoded_tx.map(str::to_string);
            self.decision
        }
    }

    fn sample_summary() -> SpendSummary {
        use dig_account::{SpendRecipient, SpendTier};
        SpendSummary::new(
            SpendTier::Vault,
            vec![SpendRecipient {
                address: "xch1recipient".into(),
                amount_mojos: 5_000_000,
                asset_id: None,
            }],
            10,
        )
    }

    #[tokio::test]
    async fn an_approved_native_confirm_approves_the_spend_and_shows_the_summary() {
        let confirmer = Arc::new(ScriptedConfirmer::new(ConfirmDecision::Approve));
        let ceremony = CredentialCeremony::with_confirmer(MemCred::default(), confirmer.clone());
        let decision = ceremony
            .confirm_spend(&account(), ProfileIx::ROOT, &sample_summary())
            .await
            .unwrap();
        assert_eq!(decision, SpendDecision::Approve);
        let body = confirmer.last_body.lock().unwrap().clone().unwrap();
        assert!(
            body.contains("xch1recipient") && body.contains("Vault"),
            "the native prompt shows the re-derived summary: {body}"
        );
    }

    #[tokio::test]
    async fn a_denied_native_confirm_declines_the_spend() {
        let confirmer = Arc::new(ScriptedConfirmer::new(ConfirmDecision::Deny));
        let ceremony = CredentialCeremony::with_confirmer(MemCred::default(), confirmer);
        let decision = ceremony
            .confirm_spend(&account(), ProfileIx::ROOT, &sample_summary())
            .await
            .unwrap();
        assert!(matches!(decision, SpendDecision::Decline(_)));
    }

    #[tokio::test]
    async fn a_timed_out_native_confirm_declines_the_spend() {
        let confirmer = Arc::new(ScriptedConfirmer::new(ConfirmDecision::Timeout));
        let ceremony = CredentialCeremony::with_confirmer(MemCred::default(), confirmer);
        let decision = ceremony
            .confirm_spend(&account(), ProfileIx::ROOT, &sample_summary())
            .await
            .unwrap();
        assert!(matches!(decision, SpendDecision::Decline(_)));
    }

    /// A confirmer that answers a fixed script of typed entries and records what it was asked, so the
    /// prompted ceremony's two intents can be told apart by the QUESTIONS they put — not merely by
    /// the password that comes back.
    struct TypingConfirmer {
        entries: Mutex<std::collections::VecDeque<crate::confirm::InputOutcome>>,
        headings: Mutex<Vec<String>>,
    }

    impl TypingConfirmer {
        fn typing(entries: &[&str]) -> Self {
            Self {
                entries: Mutex::new(
                    entries
                        .iter()
                        .map(|t| {
                            crate::confirm::InputOutcome::Provided(Zeroizing::new((*t).to_string()))
                        })
                        .collect(),
                ),
                headings: Mutex::new(Vec::new()),
            }
        }

        fn refusing(outcome: crate::confirm::InputOutcome) -> Self {
            Self {
                entries: Mutex::new([outcome].into()),
                headings: Mutex::new(Vec::new()),
            }
        }
    }

    impl NativeConfirmer for TypingConfirmer {
        fn confirm_pair(&self, _p: &crate::confirm::PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("an unlock never pairs")
        }
        fn confirm_connect(&self, _p: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("an unlock never connects")
        }
        fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
            unreachable!("these tests never spend")
        }
        fn show_notice(&self, _p: &crate::confirm::NoticePrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn request_input(
            &self,
            prompt: &crate::confirm::InputPrompt<'_>,
        ) -> crate::confirm::InputOutcome {
            self.headings.lock().unwrap().push(prompt.title.to_string());
            self.entries
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(crate::confirm::InputOutcome::Cancelled)
        }
    }

    /// A password chosen by a person, long enough to clear the floor.
    const TYPED: &str = "a-passphrase-i-chose";

    /// The whole point of #1817: the password that reaches dig-account is the one the USER typed.
    #[tokio::test]
    async fn the_prompted_ceremony_returns_the_password_the_user_typed() {
        let confirmer = Arc::new(TypingConfirmer::typing(&[TYPED]));
        let ceremony = PromptedCeremony::new(
            confirmer.clone(),
            PasswordIntent::Unlock {
                reason: "DIG needs to sign.".into(),
            },
        );

        let factors = ceremony
            .collect_unlock_factors(&account(), None)
            .await
            .unwrap();

        assert_eq!(factors.password.as_bytes(), TYPED.as_bytes());
        assert_eq!(
            confirmer.headings.lock().unwrap().len(),
            1,
            "unlocking asks once"
        );
    }

    /// Establishing asks a DIFFERENT question from unlocking — twice, and with a "choose" title. A
    /// test that only checked the returned password could not tell the two intents apart at all,
    /// which is how an enrol path ends up asking someone to enter a password they do not yet have.
    #[tokio::test]
    async fn establishing_asks_the_choose_question_twice() {
        let confirmer = Arc::new(TypingConfirmer::typing(&[TYPED, TYPED]));
        let ceremony = PromptedCeremony::new(
            confirmer.clone(),
            PasswordIntent::Establish {
                purpose: "Set a password for your new DIG account.".into(),
            },
        );

        let factors = ceremony
            .collect_unlock_factors(&account(), None)
            .await
            .unwrap();

        assert_eq!(factors.password.as_bytes(), TYPED.as_bytes());
        let titles = confirmer.headings.lock().unwrap().clone();
        assert_eq!(titles.len(), 2, "a new password is typed twice");
        assert!(
            titles[0].contains("Choose") && titles[1].contains("Confirm"),
            "establishing must ask the choose-then-confirm pair, got {titles:?}"
        );
    }

    /// A user who backs out must yield no factors at all — never an empty password, which would
    /// unlock nothing but would also mask the cancellation as a wrong-password failure.
    #[tokio::test]
    async fn a_cancelled_password_prompt_fails_closed_as_cancelled() {
        let ceremony = PromptedCeremony::new(
            Arc::new(TypingConfirmer::refusing(
                crate::confirm::InputOutcome::Cancelled,
            )),
            PasswordIntent::Unlock { reason: "r".into() },
        );
        assert!(matches!(
            ceremony.collect_unlock_factors(&account(), None).await,
            Err(CeremonyError::Cancelled)
        ));
    }

    /// A host with no window reports UNAVAILABLE, distinctly from a cancellation: one is the user's
    /// decision and the other is the machine's limitation, and the tray says different things about
    /// them.
    #[tokio::test]
    async fn a_host_that_cannot_ask_fails_closed_as_unavailable() {
        let ceremony = PromptedCeremony::new(
            Arc::new(TypingConfirmer::refusing(
                crate::confirm::InputOutcome::Unavailable,
            )),
            PasswordIntent::Unlock { reason: "r".into() },
        );
        assert!(matches!(
            ceremony.collect_unlock_factors(&account(), None).await,
            Err(CeremonyError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn a_headless_host_fails_the_spend_confirm_closed() {
        // No native confirmer (Unavailable) -> a ceremony ERROR (not a silent decline), so the money
        // path aborts fail-closed with no key touched.
        let confirmer = Arc::new(ScriptedConfirmer::new(ConfirmDecision::Unavailable));
        let ceremony = CredentialCeremony::with_confirmer(MemCred::default(), confirmer);
        let result = ceremony
            .confirm_spend(&account(), ProfileIx::ROOT, &sample_summary())
            .await;
        assert!(matches!(result, Err(CeremonyError::Unavailable(_))));
    }
}
