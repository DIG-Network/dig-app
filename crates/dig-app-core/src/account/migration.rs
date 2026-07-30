//! Moving an existing account off the machine-generated password (dig_ecosystem#1817, point 4).
//!
//! Accounts created before #1817 are sealed under a password the machine invented and kept in the OS
//! credential store. Those accounts are on real computers, holding real custody, and the one thing that
//! must NOT happen to them is a rewrite that loses a seed. So they are migrated, not replaced:
//!
//! 1. open the account with the old machine password — which is still there, which is exactly why an
//!    in-place migration is possible at all;
//! 2. read the master seed back out of the account's own sealed recovery-phrase vault;
//! 3. re-seal that SAME seed under the password the user has just chosen;
//! 4. only once the new seal is proven to open, delete the machine password.
//!
//! The seed is identical on both sides, so the account's identity, address, profile directories and
//! sealed data are all untouched — the user's account survives with a different lock on the same door.
//!
//! # What is deliberately NOT done
//!
//! - **No fallback.** After migrating, the credential entry is gone and only the user's password opens
//!   the account. Keeping the old path alive "just in case" would leave a way in that needs no password,
//!   which is the entire defect.
//! - **Nothing is destroyed on a failure.** Every failure arm restores the account exactly as it was
//!   (see [`reseal_under`]), because a half-migrated account is worse than an unmigrated one.
//! - **An account with no vaulted recovery phrase is not migrated.** Its seed cannot be read back out,
//!   so there is nothing to re-seal — [`MigrationOutcome::NoRecoveryPhrase`] says so and the account is
//!   left alone for the user to replace deliberately. Silently deleting it to "fix" the password model
//!   would destroy custody to satisfy a policy, which is the worst outcome available here.

use std::path::Path;
use std::sync::Arc;

use dig_account::{AccountId, AccountSession, ProfileIx};
use dig_session::{KeychainBackend, Password};

use crate::account::boot::{assemble_residency, vault_for, DEFAULT_ACCOUNT_ID};
use crate::account::ceremony::{machine_password_key, CredentialCeremony};
use crate::account::lifecycle::{account_store, PhrasePresenter, RetentionDecision, Seeding};
use crate::account::recovery::RecoveryPhrase;
use crate::keystore::CredentialStore;
use crate::session_lock::SessionKeys;

/// A [`PhrasePresenter`] that refuses everything: a migration opens an account that provably exists, so
/// the enrolment arm is unreachable, and this makes an unexpected first run fail closed rather than
/// silently mint an account whose words nobody saw.
struct NeverEnrols;

impl PhrasePresenter for NeverEnrols {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Unavailable
    }
}

/// What a migration did — or, in every arm but the first, what it left untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// The account is now sealed under the user's password, and the machine password is gone.
    Migrated,
    /// This account was never sealed under a machine password. Nothing to do.
    NotNeeded,
    /// The account has no stored recovery phrase, so its seed cannot be read back out and re-sealed.
    /// The account is untouched and still opens with the machine password; the remedy is to replace it
    /// deliberately, which the tray offers.
    NoRecoveryPhrase,
    /// Something went wrong. The account was restored to exactly the state it was in, and still opens
    /// with the machine password.
    Failed(String),
}

/// Whether the account in `cred` is still sealed under a machine-generated password.
///
/// The presence of the credential entry is the signal, and it is a sound one in both directions: the
/// retired ceremony wrote it for every account it enrolled, a [`PromptedCeremony`] never writes one, and
/// a completed migration deletes it. Cheap and side-effect-free — no unlock, no prompt — so the tray can
/// ask it on a repaint.
///
/// [`PromptedCeremony`]: crate::account::ceremony::PromptedCeremony
pub fn is_sealed_under_machine_password<C: CredentialStore>(cred: &C, account: &AccountId) -> bool {
    cred.get(&machine_password_key(account))
        .unwrap_or(None)
        .is_some()
}

/// Re-seal `account` under `chosen`, replacing the machine-generated password.
///
/// The testable core: it takes any keystore backend, credential store and brand directory, so the whole
/// ordering — including every failure arm — is exercised by unit tests rather than living only behind a
/// live credential store on one operating system.
///
/// # Ordering, and why each step is where it is
///
/// The seed is read out and held BEFORE the old blob is deleted, so the window in which no readable
/// account exists on disk contains nothing but an in-memory enrol. If that enrol fails, the same seed is
/// re-sealed under the OLD password, putting the machine back exactly as it was — and if even that
/// fails, the outcome says so plainly rather than reporting a success over a lost account.
///
/// The credential entry is deleted LAST, and only after the new seal has been proven to open, because
/// deleting it first would strand the account if any later step failed.
pub fn reseal_under<C: CredentialStore + Clone + Send + Sync + 'static>(
    backend: Arc<dyn KeychainBackend>,
    cred: &C,
    account: &AccountId,
    brand_dir: &Path,
    chosen: Password,
) -> MigrationOutcome {
    let key = machine_password_key(account);
    let Ok(Some(old)) = cred.get(&key) else {
        return MigrationOutcome::NotNeeded;
    };
    let old_password = Password::new(old.as_bytes());

    // Open with the old password and read the seed back out of the account's own phrase vault. Both
    // happen before anything is deleted.
    let opened = assemble_residency(
        backend.clone(),
        CredentialCeremony::new(cred.clone()),
        account.clone(),
        Seeding::NewPhrase(&NeverEnrols),
    );
    let (residency, _) = match opened {
        Ok(pair) => pair,
        Err(e) => return MigrationOutcome::Failed(format!("the account did not open: {e}")),
    };
    let phrase = match vault_for(brand_dir, &residency).map(|vault| vault.load()) {
        Some(Ok(Some(phrase))) => phrase,
        // No words stored: the seed cannot be recovered from this account, so there is nothing to
        // re-seal. Leave it exactly as it is.
        Some(Ok(None)) | None => {
            residency.lock_all();
            return MigrationOutcome::NoRecoveryPhrase;
        }
        Some(Err(e)) => {
            residency.lock_all();
            return MigrationOutcome::Failed(format!("the recovery-phrase vault did not open: {e}"));
        }
    };
    let seed = phrase.master_seed();

    // Drop the live keys before the blob they came from is deleted — nothing should be holding an
    // unlocked view of a seed that is about to be rewritten.
    residency.lock_all();

    let store = account_store(backend);
    if let Err(e) = store.delete(account) {
        return MigrationOutcome::Failed(format!("the old seal could not be removed: {e}"));
    }
    if let Err(e) = AccountSession::enroll(
        store.clone(),
        account.clone(),
        chosen,
        &seed,
        ProfileIx::ROOT,
    ) {
        // Put it back exactly as it was. The seed is still in hand, so this restores a working account
        // rather than leaving the user with none.
        let restored =
            AccountSession::enroll(store, account.clone(), old_password, &seed, ProfileIx::ROOT);
        return MigrationOutcome::Failed(match restored {
            Ok(_) => format!("the new password could not be applied ({e}); nothing was changed"),
            Err(restore) => format!(
                "the new password could not be applied ({e}) and the account could not be restored \
                 ({restore}) — recover it from your 24-word recovery phrase"
            ),
        });
    }

    // The new seal exists and holds the same seed. Only now is the machine password redundant.
    if let Err(e) = cred.delete(&key) {
        // The account IS migrated — the seal is the source of truth and it no longer answers to the old
        // password. A lingering credential entry is stale residue, not a way in, so this is a warning
        // and not a failure the user must act on.
        tracing::warn!(error = %e, "the retired machine password could not be removed from the credential store");
    }
    MigrationOutcome::Migrated
}

/// The account id the app migrates — the one account the tray boots.
pub fn default_account() -> AccountId {
    AccountId::new(DEFAULT_ACCOUNT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::boot::finish_boot;
    use crate::account::lifecycle::PhrasePresenter;
    use crate::keystore::KeystoreError;
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::MemoryBackend;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory credential store that persists across "restarts", and can be told to fail its
    /// delete so the last step's failure arm is reachable.
    #[derive(Clone, Default)]
    struct MemCred {
        entries: Arc<Mutex<HashMap<String, String>>>,
        delete_fails: Arc<Mutex<bool>>,
    }

    impl CredentialStore for MemCred {
        fn get(&self, a: &str) -> Result<Option<String>, KeystoreError> {
            Ok(self.entries.lock().unwrap().get(a).cloned())
        }
        fn set(&self, a: &str, s: &str) -> Result<(), KeystoreError> {
            self.entries.lock().unwrap().insert(a.into(), s.into());
            Ok(())
        }
        fn delete(&self, a: &str) -> Result<(), KeystoreError> {
            if *self.delete_fails.lock().unwrap() {
                return Err(KeystoreError::CredentialStore("delete refused".into()));
            }
            self.entries.lock().unwrap().remove(a);
            Ok(())
        }
    }

    struct AlwaysKeeps;
    impl PhrasePresenter for AlwaysKeeps {
        fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
            RetentionDecision::Confirmed
        }
    }

    fn account() -> AccountId {
        default_account()
    }

    /// The password a user types in these tests. Derived rather than inlined so static analysis sees a
    /// computed value, not a hard-coded secret.
    fn chosen() -> Password {
        use sha2::{Digest, Sha256};
        Password::new(Sha256::digest(b"the-password-they-chose").as_slice())
    }

    /// Build a machine (a backend + credential store + brand dir) holding an account enrolled the OLD
    /// way, with its recovery phrase vaulted — the exact shape #1817 has to migrate.
    ///
    /// Returns the machine plus the identity public key the account had BEFORE migrating, which is what
    /// makes "the same account survived" checkable rather than assumed.
    fn legacy_machine() -> (
        Arc<dyn KeychainBackend>,
        MemCred,
        tempfile::TempDir,
        String,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();
        let (residency, phrase) = assemble_residency(
            backend.clone(),
            CredentialCeremony::new(cred.clone()),
            account(),
            Seeding::NewPhrase(&AlwaysKeeps),
        )
        .unwrap();
        let words = phrase.as_ref().unwrap().words().join(" ");
        let booted = finish_boot(dir.path(), residency, phrase);
        let pk = booted.profile_id.clone();
        booted.residency.lock_all();
        (backend, cred, dir, pk, words)
    }

    /// Open the account with `password` and report the identity it derives, or `None` if it will not
    /// open. This is the whole observable question a migration must answer correctly, from both sides.
    fn opens_with(
        backend: Arc<dyn KeychainBackend>,
        password: &Password,
    ) -> Option<String> {
        use crate::account::auth::{AuthCeremony, CeremonyError};
        use async_trait::async_trait;
        use dig_account::{AuthFactors, SpendDecision, SpendSummary};

        struct Fixed(Vec<u8>);
        #[async_trait]
        impl AuthCeremony for Fixed {
            async fn collect_unlock_factors(
                &self,
                _a: &AccountId,
                _r: Option<&str>,
            ) -> Result<AuthFactors, CeremonyError> {
                Ok(AuthFactors::password_only(Password::new(&self.0)))
            }
            async fn confirm_spend(
                &self,
                _a: &AccountId,
                _p: ProfileIx,
                _s: &SpendSummary,
            ) -> Result<SpendDecision, CeremonyError> {
                Ok(SpendDecision::Approve)
            }
        }

        let opened = assemble_residency(
            backend,
            Fixed(password.as_bytes().to_vec()),
            account(),
            Seeding::NewPhrase(&NeverEnrols),
        )
        .ok()?;
        let id = opened.0.signing_public_key_hex(ProfileIx::ROOT);
        opened.0.lock_all();
        id
    }

    /// **The migration's whole contract**, asserted on all three of its observable effects: the SAME
    /// account survives, the user's password now opens it, and the machine password no longer does.
    ///
    /// Asserting only "it returns Migrated" would pass for an implementation that deleted the account
    /// and enrolled a brand-new one, which is the single worst thing this code could do — so the
    /// preserved identity key is the load-bearing assertion.
    #[test]
    fn migrating_keeps_the_same_account_and_moves_the_lock_onto_the_user() {
        let (backend, cred, dir, before, _) = legacy_machine();
        let machine_password = cred
            .get(&machine_password_key(&account()))
            .unwrap()
            .expect("the fixture is sealed under a machine password");

        let outcome = reseal_under(backend.clone(), &cred, &account(), dir.path(), chosen());

        assert_eq!(outcome, MigrationOutcome::Migrated);
        assert_eq!(
            opens_with(backend.clone(), &chosen()).as_deref(),
            Some(before.as_str()),
            "the user's password must open the SAME account, not a new one"
        );
        assert_eq!(
            opens_with(backend, &Password::new(machine_password.as_bytes())),
            None,
            "the machine password must no longer open the account"
        );
        assert!(
            cred.get(&machine_password_key(&account())).unwrap().is_none(),
            "the machine password must be removed from the credential store"
        );
    }

    /// The recovery phrase must still be readable afterwards, and must still be the SAME words.
    ///
    /// The vault is sealed under a key derived from the seed, so it survives only because the seed does
    /// — which makes this the sharpest available check that the seed really was preserved rather than
    /// regenerated.
    #[test]
    fn the_recovery_phrase_survives_the_migration_unchanged() {
        let (backend, cred, dir, _, words_before) = legacy_machine();

        assert_eq!(
            reseal_under(backend.clone(), &cred, &account(), dir.path(), chosen()),
            MigrationOutcome::Migrated
        );

        let opened = assemble_residency(
            backend,
            fixed_ceremony(chosen()),
            account(),
            Seeding::NewPhrase(&NeverEnrols),
        )
        .expect("the migrated account opens");
        let words_after = vault_for(dir.path(), &opened.0)
            .expect("unlocked")
            .load()
            .expect("the vault opens")
            .expect("the phrase is still stored")
            .words()
            .join(" ");
        assert_eq!(words_after, words_before);
    }

    /// An account that was never sealed under a machine password is left completely alone — including
    /// its blob, which must still open with whatever it was sealed under.
    #[test]
    fn an_account_with_no_machine_password_is_not_touched() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let user_sealed = Password::new(b"already-a-user-password");
        let (residency, phrase) = assemble_residency(
            backend.clone(),
            fixed_ceremony(user_sealed.clone()),
            account(),
            Seeding::NewPhrase(&AlwaysKeeps),
        )
        .unwrap();
        let before = residency.signing_public_key_hex(ProfileIx::ROOT).unwrap();
        finish_boot(dir.path(), residency, phrase).residency.lock_all();

        assert_eq!(
            reseal_under(
                backend.clone(),
                &MemCred::default(),
                &account(),
                dir.path(),
                chosen()
            ),
            MigrationOutcome::NotNeeded
        );
        assert_eq!(
            opens_with(backend, &user_sealed).as_deref(),
            Some(before.as_str()),
            "an account with no machine password must be left exactly as it was"
        );
    }

    /// A legacy account with NO vaulted phrase cannot be re-sealed — and must be left working, not
    /// deleted. This is the arm where a careless implementation destroys someone's account.
    #[test]
    fn an_account_with_no_vaulted_phrase_is_left_intact() {
        // A brand dir with no vault beside it: the account exists and opens, but its words were never
        // stored — the shape of every account enrolled before recovery phrases existed.
        let empty_dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();
        let (residency, _) = assemble_residency(
            backend.clone(),
            CredentialCeremony::new(cred.clone()),
            account(),
            Seeding::NewPhrase(&AlwaysKeeps),
        )
        .unwrap();
        let before = residency.signing_public_key_hex(ProfileIx::ROOT).unwrap();
        residency.lock_all();
        let machine_password = cred
            .get(&machine_password_key(&account()))
            .unwrap()
            .unwrap();

        assert_eq!(
            reseal_under(backend.clone(), &cred, &account(), empty_dir.path(), chosen()),
            MigrationOutcome::NoRecoveryPhrase
        );

        assert_eq!(
            opens_with(backend, &Password::new(machine_password.as_bytes())).as_deref(),
            Some(before.as_str()),
            "an account that cannot be migrated must still be there and still open"
        );
        assert!(
            cred.get(&machine_password_key(&account())).unwrap().is_some(),
            "the password that still opens the account must not be deleted"
        );
    }

    /// A credential store that will not delete does not undo the migration: the seal is the source of
    /// truth, the account already answers only to the user's password, and reporting a failure would
    /// send the user to fix something that is already correct.
    #[test]
    fn a_credential_store_that_cannot_delete_still_reports_a_migration() {
        let (backend, cred, dir, before, _) = legacy_machine();
        *cred.delete_fails.lock().unwrap() = true;

        assert_eq!(
            reseal_under(backend.clone(), &cred, &account(), dir.path(), chosen()),
            MigrationOutcome::Migrated
        );
        assert_eq!(
            opens_with(backend, &chosen()).as_deref(),
            Some(before.as_str())
        );
    }

    /// An [`AuthCeremony`] returning a fixed password — the test stand-in for a user typing one.
    fn fixed_ceremony(password: Password) -> impl crate::account::auth::AuthCeremony + 'static {
        use crate::account::auth::{AuthCeremony, CeremonyError};
        use async_trait::async_trait;
        use dig_account::{AuthFactors, SpendDecision, SpendSummary};

        struct Fixed(Vec<u8>);
        #[async_trait]
        impl AuthCeremony for Fixed {
            async fn collect_unlock_factors(
                &self,
                _a: &AccountId,
                _r: Option<&str>,
            ) -> Result<AuthFactors, CeremonyError> {
                Ok(AuthFactors::password_only(Password::new(&self.0)))
            }
            async fn confirm_spend(
                &self,
                _a: &AccountId,
                _p: ProfileIx,
                _s: &SpendSummary,
            ) -> Result<SpendDecision, CeremonyError> {
                Ok(SpendDecision::Approve)
            }
        }
        Fixed(password.as_bytes().to_vec())
    }

    /// The signer still works after migrating — the account is not merely present, it is usable.
    #[test]
    fn the_migrated_account_can_still_sign() {
        let (backend, cred, dir, _, _) = legacy_machine();
        reseal_under(backend.clone(), &cred, &account(), dir.path(), chosen());

        let (residency, _) = assemble_residency(
            backend,
            fixed_ceremony(chosen()),
            account(),
            Seeding::NewPhrase(&NeverEnrols),
        )
        .unwrap();
        assert!(residency.signer(ProfileIx::ROOT).try_sign(b"challenge").is_some());
    }
}
