//! The zero-prompt OS-credential-store unlock ceremony (#1547, custody switchover).
//!
//! dig-account unlocks the account master seed with a PASSWORD (Argon2id over the DIGOP1 blob). To
//! preserve the retired model's zero-prompt boot on Windows/macOS — where the OS credential store's
//! per-application ACL is the confidentiality boundary — this ceremony keeps a high-entropy account
//! password IN the OS credential store and hands it to dig-account on every unlock:
//!
//! - **First run** — no stored password: generate one from the OS CSPRNG, persist it in the
//!   credential store, and return it (so the enrol path seals the seed under it).
//! - **Later boots** — fetch the stored password and return it, unlocking with no user prompt.
//!
//! This is a strict improvement on the retired vault, which stored the unlock password ALONGSIDE the
//! ciphertext in one entry: here the password lives in the OS credential store while the sealed seed
//! lives in a separate file backend, so a raw at-rest file dump no longer carries its own key. The
//! honest guarantee is unchanged in kind — the OS ACL gates the password (see `SPEC.md` §7 for the
//! password-splitting follow-up), and Linux (no per-application ACL) stays deferred to a passphrase
//! ceremony, exactly as the old path deferred it.
//!
//! Spend confirmation (#1548, slice C — money goes live) is gated on the per-OS native confirmer: the
//! money path calls [`confirm_spend`](AuthCeremony::confirm_spend), which renders the independently
//! re-derived [`SpendSummary`] (recipients / fee / tier — never raw bytes) and requires the user to
//! authorize it at the OS biometric/passphrase prompt (Windows Hello / macOS Touch ID / Linux polkit).
//! A headless host has no confirmer, so a spend confirmation fails closed there (`Unavailable`).

use std::sync::Arc;

use async_trait::async_trait;
use dig_account::{AccountId, AuthFactors, ProfileIx, SpendDecision, SpendSummary};
use dig_session::Password;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::account::auth::{AuthCeremony, CeremonyError};
use crate::confirm::{native_confirmer, ConfirmDecision, NativeConfirmer, SignPrompt};
use crate::keystore::CredentialStore;

/// The number of random bytes in a generated account master password before hex-encoding — 32 bytes
/// (256 bits) of CSPRNG entropy, well beyond any Argon2id-stretched brute-force reach.
const GENERATED_PASSWORD_BYTES: usize = 32;

/// A zero-prompt [`AuthCeremony`] that sources the account password from an OS
/// [`CredentialStore`], generating + persisting one on first run.
///
/// Generic over the credential backend so it is unit-testable with an in-memory double and swaps the
/// real [`OsCredentialStore`](crate::keystore::OsCredentialStore) in production.
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

    /// The credential-store key the account's master password is filed under. Stable across restarts
    /// (that is how a later boot finds it) and namespaced per account so multiple accounts never
    /// collide.
    fn password_key(account: &AccountId) -> String {
        format!("{account}.master-password")
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
        // Render the re-derived effect of the spend (recipients / fee / tier) as the confirm body —
        // NEVER raw bytes — and require the human at the OS biometric/passphrase gate. The summary is
        // dig-account's independently re-derived structure, so the prompt shows exactly what the
        // signature will authorize.
        let body = render_spend(summary);
        let prompt = SignPrompt {
            origin: SPEND_CONFIRM_ORIGIN,
            payload_type: SPEND_PAYLOAD_TYPE,
            decoded_tx: Some(&body),
        };
        Ok(match self.confirmer.confirm_sign(&prompt) {
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
