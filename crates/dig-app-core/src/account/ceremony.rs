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
//! Spend confirmation is deliberately fail-closed here: the money-path confirm UI is wired in the
//! #1548 slice (sub-c), so until then no programmatic spend can be confirmed through this ceremony.

use async_trait::async_trait;
use dig_account::{AccountId, AuthFactors, ProfileIx, SpendDecision, SpendSummary};
use dig_session::Password;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::account::auth::{AuthCeremony, CeremonyError};
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
}

impl<C: CredentialStore> CredentialCeremony<C> {
    /// Wrap `store` as the zero-prompt password source.
    pub fn new(store: C) -> Self {
        Self { store }
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
    hex::encode(&*raw)
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
        _summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        // Fail-closed: the money-path confirm UI is wired in #1548 (sub-c). Until then this ceremony
        // never approves a spend — the identity-sign path (which does NOT route through confirm_spend)
        // is unaffected.
        Ok(SpendDecision::Decline(Some(
            "spend confirmation is not yet wired (pending #1548)".to_string(),
        )))
    }
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

    #[tokio::test]
    async fn spend_confirmation_is_fail_closed_until_the_money_path_lands() {
        let ceremony = CredentialCeremony::new(MemCred::default());
        let summary = SpendSummary::new(dig_account::SpendTier::Confirm, vec![], 0);
        let decision = ceremony
            .confirm_spend(&account(), ProfileIx::ROOT, &summary)
            .await
            .unwrap();
        assert!(matches!(decision, SpendDecision::Decline(_)));
    }
}
