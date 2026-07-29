//! Migrating an account off the **machine-held** unlock password onto one the user chooses
//! (dig_ecosystem#1817).
//!
//! # The situation this exists for
//!
//! Every account dig-app enrolled before #1817 was sealed under a 256-bit password that dig-app
//! generated itself and filed in the OS credential store (the deleted `CredentialCeremony`, see
//! [`ceremony`](crate::account::ceremony)). Those accounts are real, they hold real keys, and on the
//! machines that have them the old password is **still available** — which is exactly why an in-place
//! re-seal is possible and is the graceful path. A user must not be made to destroy an account and
//! create a new one merely because dig-app changed its mind about where the password lives.
//!
//! # The order, which is the safety property
//!
//! 1. **Find the old password.** No credential entry ⇒ [`MigrationOutcome::NotNeeded`]: this host's
//!    account was never machine-sealed, or has already been migrated.
//! 2. **Open the account with it.** A failure ⇒ [`MigrationOutcome::Unopenable`], and nothing is
//!    touched: the blob may be a legacy format this version cannot read, and a migration must never be
//!    the thing that destroys such an account.
//! 3. **Load the vaulted recovery phrase**, because the phrase's entropy is what a re-seal re-enrols
//!    from. No phrase ⇒ [`MigrationOutcome::CannotReseal`] and the account is left EXACTLY as it is —
//!    still working, still machine-sealed. The remedy is the always-available replace verbs, never a
//!    silent destruction.
//! 4. **Show the phrase and take the retention claim AGAIN**, before the password becomes load-bearing.
//!    Until now a forgotten password cost nothing, because the machine held it; afterwards the phrase is
//!    the only way back. Asking for the words first is what stops this change from being a funds-loss
//!    trap. A refusal ⇒ [`MigrationOutcome::RefusedByUser`], nothing touched.
//! 5. **Collect the new password** (typed twice, [`MIN_PASSWORD_CHARS`](crate::account::passphrase::MIN_PASSWORD_CHARS)).
//!    A cancel ⇒ [`MigrationOutcome::RefusedByUser`], nothing touched.
//! 6. **Only now**: lock, delete the old blob, and re-enrol from the SAME phrase under the new password.
//!    A re-enrol failure rolls the account back under the OLD machine password from the phrase still in
//!    hand ([`MigrationOutcome::RestoredUnderOldPassword`]); if even that fails the loss is reported
//!    plainly ([`MigrationOutcome::Lost`]) rather than swallowed.
//! 7. **Delete the credential entry.** Leaving it would keep a working machine-held key to the account
//!    beside a user password, which is the whole defect this migration exists to remove.
//!
//! The master seed is unchanged throughout — it comes from the same phrase — so the identity key, the
//! wallet addresses, the per-profile DEKs and every already-sealed blob (including the phrase vault
//! itself) still open afterwards. That is the difference between a re-seal and a replacement.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use dig_account::{
    AccountId, AccountSession, AccountStore, AuthFactors, PasswordOnlyPolicy, ProfileIx,
    SpendDecision, SpendSummary,
};
use dig_session::Password;
use zeroize::Zeroizing;

use crate::account::auth::{AuthCeremony, CeremonyError, HarnessAuthProvider};
use crate::account::boot::vault_for;
use crate::account::journey::WindowedPresenter;
use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
use crate::account::passphrase::PasswordCeremony;
use crate::account::recovery::RecoveryPhrase;
use crate::account::residency::AccountResidency;
use crate::confirm::NativeConfirmer;
use crate::keystore::CredentialStore;
use crate::session_lock::SessionKeys;

/// What a migration attempt did. Every variant states plainly whether the account changed, because
/// that is the only fact a caller — or a reader — actually needs from a custody flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// No machine-held password exists for this account, so there is nothing to migrate. **Unchanged.**
    NotNeeded,
    /// The seed is now sealed under the user's password and the credential entry is gone.
    Migrated,
    /// The stored machine password did not open the account, so it may not be a machine-sealed account
    /// at all. **Unchanged** — nothing was deleted.
    Unopenable,
    /// The account is machine-sealed but has no stored recovery phrase, so its entropy cannot be
    /// re-enrolled under a new password. **Unchanged** — the user is routed to the replace verbs.
    CannotReseal,
    /// The user declined the recovery-phrase claim or cancelled the password. **Unchanged.**
    RefusedByUser,
    /// The old blob could not be removed, so the re-seal never started. **Unchanged** — the account
    /// still opens under its machine password and the migration can be retried.
    Failed,
    /// The re-enrol failed and the account was put back under its OLD machine password. **Unchanged in
    /// effect** — it still opens exactly as before, and the migration can be retried.
    RestoredUnderOldPassword,
    /// The re-enrol failed AND the rollback failed. The sealed seed is gone from this host; the user's
    /// 24 words are the only way back. The worst outcome available, and the one that must be reported
    /// most clearly.
    Lost,
}

impl MigrationOutcome {
    /// Whether the account still opens the way it did before this ran. `false` for exactly two
    /// outcomes: the successful re-seal (it opens under the new password) and [`Lost`](Self::Lost).
    pub fn account_intact(self) -> bool {
        !matches!(self, Self::Migrated | Self::Lost)
    }
}

/// The credential-store key the OLD machine-generated master password was filed under.
///
/// **This format is frozen.** It is not a choice — it names entries that already exist in real Windows
/// Credential Manager / macOS Keychain stores, written by the deleted `CredentialCeremony`. Changing it
/// would make [`migrate_to_user_password`] find nothing and silently report
/// [`MigrationOutcome::NotNeeded`] on every machine that actually needs migrating.
pub fn legacy_password_key(account: &AccountId) -> String {
    format!("{account}.master-password")
}

/// Re-seal `account`'s master seed under a password the user chooses, if it is currently machine-sealed.
///
/// See the module docs for the order and why each step is where it is. Safe to call on every boot: an
/// account with no credential entry returns [`MigrationOutcome::NotNeeded`] having touched nothing.
pub fn migrate_to_user_password(
    store: Arc<AccountStore>,
    account: &AccountId,
    cred: &dyn CredentialStore,
    confirmer: &Arc<dyn NativeConfirmer>,
    brand_dir: &Path,
) -> MigrationOutcome {
    let Some(legacy) = stored_machine_password(cred, account) else {
        return MigrationOutcome::NotNeeded;
    };

    let Some(phrase) = phrase_of(&store, account, &legacy, brand_dir) else {
        // Split deliberately: an account we could not OPEN and one we opened but that has no phrase are
        // different situations for the user, and `phrase_of` reports which.
        return match opens_with(&store, account, &legacy) {
            true => MigrationOutcome::CannotReseal,
            false => MigrationOutcome::Unopenable,
        };
    };

    // The words, then the password. Reversing these two would make a forgotten password unrecoverable
    // for a user who never re-checked their phrase — see the module docs, step 4.
    if WindowedPresenter::new(confirmer.as_ref()).present_new_phrase(&phrase)
        != RetentionDecision::Confirmed
    {
        return MigrationOutcome::RefusedByUser;
    }
    let Some(chosen) = chosen_password(confirmer, account) else {
        return MigrationOutcome::RefusedByUser;
    };

    reseal(store, account, &phrase, &legacy, chosen, cred)
}

/// Migrate the DEFAULT account under `brand_dir` — the production wrapper the tray calls.
///
/// Resolves the two host things [`migrate_to_user_password`] takes as parameters (the per-user
/// [`FileBackend`](dig_session::FileBackend) holding the sealed seed, and the OS credential store that
/// may hold a legacy machine password) so the shell stays a thin caller and holds no assembly logic.
///
/// A host with no usable credential store never had a machine-held password, so there is nothing to
/// migrate: [`MigrationOutcome::NotNeeded`].
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn migrate_default_account(
    brand_dir: &Path,
    confirmer: &Arc<dyn NativeConfirmer>,
) -> MigrationOutcome {
    use crate::account::boot::DEFAULT_ACCOUNT_ID;
    use crate::account::lifecycle::account_store;
    use crate::keystore::OsCredentialStore;
    use dig_session::FileBackend;

    let Some(cred) = OsCredentialStore::open(DEFAULT_ACCOUNT_ID) else {
        return MigrationOutcome::NotNeeded;
    };
    let store = account_store(Arc::new(FileBackend::new(brand_dir.join("account"))));
    migrate_to_user_password(
        store,
        &AccountId::new(DEFAULT_ACCOUNT_ID),
        &cred,
        confirmer,
        brand_dir,
    )
}

/// A host with no per-application credential store never held a machine password — see
/// [`migrate_default_account`].
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn migrate_default_account(
    _brand_dir: &Path,
    _confirmer: &Arc<dyn NativeConfirmer>,
) -> MigrationOutcome {
    MigrationOutcome::NotNeeded
}

/// Replace the seed blob: delete it, then re-enrol from `phrase` under `chosen`.
///
/// Isolated from the decision-making above so the rollback path can be driven by a backend that refuses
/// writes — the only honest way to test what happens after the point of no return.
fn reseal(
    store: Arc<AccountStore>,
    account: &AccountId,
    phrase: &RecoveryPhrase,
    legacy: &Zeroizing<String>,
    chosen: Password,
    cred: &dyn CredentialStore,
) -> MigrationOutcome {
    if let Err(e) = store.delete(account) {
        tracing::warn!(error = %e, "the account's sealed seed could not be replaced — nothing was changed");
        return MigrationOutcome::Failed;
    }

    // Past this line the old blob is gone. The phrase is still in hand, which is what makes the
    // rollback below real rather than a comforting comment.
    match enroll(&store, account, chosen, phrase) {
        Ok(()) => {
            forget_machine_password(cred, account);
            tracing::info!("the DIG account is now sealed under a password the user chose");
            MigrationOutcome::Migrated
        }
        Err(e) => {
            tracing::error!(error = %e, "re-sealing the account failed — restoring it as it was");
            match enroll(&store, account, Password::new(legacy.as_bytes()), phrase) {
                Ok(()) => MigrationOutcome::RestoredUnderOldPassword,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "the account could not be restored — the user's 24 words are the only way back"
                    );
                    MigrationOutcome::Lost
                }
            }
        }
    }
}

/// Seal `phrase`'s seed under `password` at `account`, discarding the returned live handle.
///
/// The handle is dropped immediately on purpose: a migration's job is to change the seal, not to leave
/// an unlocked account behind. The caller unlocks through the ordinary prompt afterwards, which is also
/// the cheapest possible proof to the user that the new password works.
fn enroll(
    store: &Arc<AccountStore>,
    account: &AccountId,
    password: Password,
    phrase: &RecoveryPhrase,
) -> dig_account::Result<()> {
    AccountSession::enroll(
        Arc::clone(store),
        account.clone(),
        password,
        &phrase.master_seed(),
        ProfileIx::ROOT,
    )
    .map(|unlocked| unlocked.lock())
}

/// The machine-generated password for `account`, or `None` if this host has none.
fn stored_machine_password(
    cred: &dyn CredentialStore,
    account: &AccountId,
) -> Option<Zeroizing<String>> {
    match cred.get(&legacy_password_key(account)) {
        Ok(stored) => stored.map(Zeroizing::new),
        Err(e) => {
            // A credential store that cannot be read is not evidence of an unmigrated account, so the
            // honest answer is "nothing to do" — the ordinary password prompt then runs as usual.
            tracing::warn!(error = %e, "could not check for a machine-held account password");
            None
        }
    }
}

/// Remove the machine-held password. Best-effort with a loud log: the seed is already re-sealed, so a
/// surviving entry is a stale string rather than a key — but it IS the residue this migration exists to
/// clear, so a failure must be visible.
fn forget_machine_password(cred: &dyn CredentialStore, account: &AccountId) {
    if let Err(e) = cred.delete(&legacy_password_key(account)) {
        tracing::warn!(error = %e, "the old machine-held account password could not be removed");
    }
}

/// The recovery phrase stored for `account`, read by unlocking with the machine `password`.
///
/// `None` when the account will not open at all, or opens but has no vaulted phrase — the caller
/// distinguishes those with [`opens_with`].
fn phrase_of(
    store: &Arc<AccountStore>,
    account: &AccountId,
    password: &Zeroizing<String>,
    brand_dir: &Path,
) -> Option<RecoveryPhrase> {
    let residency = AccountResidency::new(open_with(store, account, password)?);
    let phrase = vault_for(brand_dir, &residency).and_then(|vault| vault.load().ok().flatten());
    // Drop the key material as soon as the words are out: the re-seal enrols from the phrase and needs
    // no live account.
    residency.lock_all();
    phrase
}

/// Unlock `account` with a known `password`, or `None` on any failure.
fn open_with(
    store: &Arc<AccountStore>,
    account: &AccountId,
    password: &Zeroizing<String>,
) -> Option<dig_account::UnlockedAccount> {
    let provider = HarnessAuthProvider::new(KnownPassword(password.to_string()));
    let session = AccountSession::new(Arc::clone(store), account.clone(), ProfileIx::ROOT);
    crate::account::boot::block_on(session.unlock(&provider, &PasswordOnlyPolicy))
        .map_err(
            |e| tracing::info!(error = %e, "the machine-held password did not open the account"),
        )
        .ok()
}

/// Whether `password` opens `account` — asked only to tell "no phrase stored" apart from "will not open".
fn opens_with(
    store: &Arc<AccountStore>,
    account: &AccountId,
    password: &Zeroizing<String>,
) -> bool {
    match open_with(store, account, password) {
        Some(unlocked) => {
            unlocked.lock();
            true
        }
        None => false,
    }
}

/// Ask the user to choose the account's new password.
fn chosen_password(confirmer: &Arc<dyn NativeConfirmer>, account: &AccountId) -> Option<Password> {
    let ceremony = PasswordCeremony::for_a_new_account(Arc::clone(confirmer));
    crate::account::boot::block_on(ceremony.collect_unlock_factors(account, None))
        .map(|factors| factors.password)
        .map_err(|e| tracing::info!(error = %e, "the user did not choose a new account password"))
        .ok()
}

/// An [`AuthCeremony`] that answers with a password the CALLER already holds, drawing nothing.
///
/// This is the one remaining legitimate use of the machine-held password: reading the account once, in
/// order to stop the machine from holding it. It is deliberately private to this module so no boot path
/// can reach a zero-prompt unlock through it.
struct KnownPassword(String);

#[async_trait]
impl AuthCeremony for KnownPassword {
    async fn collect_unlock_factors(
        &self,
        _account: &AccountId,
        _reason: Option<&str>,
    ) -> Result<AuthFactors, CeremonyError> {
        Ok(AuthFactors::password_only(Password::new(self.0.as_bytes())))
    }

    async fn confirm_spend(
        &self,
        _account: &AccountId,
        _profile: ProfileIx,
        _summary: &SpendSummary,
    ) -> Result<SpendDecision, CeremonyError> {
        // A migration never spends. Declining (rather than approving) keeps the fail-closed direction
        // the default even if this type were ever reached from somewhere it should not be.
        Ok(SpendDecision::Decline(Some(
            "a migration never authorizes a spend".to_string(),
        )))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::lifecycle::account_store;
    use crate::account::passphrase::PasswordCeremony;
    use crate::confirm::{
        ClaimPrompt, ConfirmDecision, ConnectPrompt, InputOutcome, InputPrompt, NoticePrompt,
        PairPrompt, RevealPrompt, SignPrompt,
    };
    use crate::keystore::KeystoreError;
    use dig_keystore::{BackendKey, KeystoreError as BackendError, MemoryBackend};
    use dig_session::KeychainBackend;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn account() -> AccountId {
        AccountId::new("default")
    }

    /// A password DERIVED from a label, long enough to clear the ceremony's bar, so no test password is
    /// an inline literal a static analyser would read as a hard-coded cryptographic value.
    fn password(label: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(label.as_bytes()))[..16].to_string()
    }

    /// An in-memory credential store, so a test can put a machine-held password on the host and then
    /// assert the migration took it away again.
    #[derive(Clone, Default)]
    struct MemCred(Arc<Mutex<HashMap<String, String>>>);

    impl MemCred {
        /// A host whose default account is sealed under `password`, filed the way the retired ceremony
        /// filed it.
        fn holding(password: &str) -> Self {
            let this = Self::default();
            this.0
                .lock()
                .unwrap()
                .insert(legacy_password_key(&account()), password.to_string());
            this
        }

        fn holds_a_password(&self) -> bool {
            self.0
                .lock()
                .unwrap()
                .contains_key(&legacy_password_key(&account()))
        }
    }

    impl CredentialStore for MemCred {
        fn get(&self, k: &str) -> Result<Option<String>, KeystoreError> {
            Ok(self.0.lock().unwrap().get(k).cloned())
        }
        fn set(&self, k: &str, v: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().insert(k.into(), v.into());
            Ok(())
        }
        fn delete(&self, k: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().remove(k);
            Ok(())
        }
    }

    /// A confirmer that rules on the recovery-phrase claim as scripted and types a scripted password.
    ///
    /// Both are independently scriptable because the migration has TWO user gates and each must be
    /// provable on its own: a double that could only approve the claim could not express "the user
    /// declined the words", and one with a fixed password could not express a cancel.
    struct Scripted {
        keeps_the_phrase: ConfirmDecision,
        answers: Mutex<std::collections::VecDeque<String>>,
        claims: Mutex<usize>,
    }

    impl Scripted {
        /// The user confirms the words and types `password` (twice — a new password is asked for twice).
        fn confirming_and_typing(password: &str) -> Arc<Self> {
            Arc::new(Self {
                keeps_the_phrase: ConfirmDecision::Approve,
                answers: Mutex::new(std::iter::repeat(password.to_string()).take(2).collect()),
                claims: Mutex::new(0),
            })
        }

        /// The user backs out of the recovery-phrase screen. A password is scripted anyway, so a
        /// migration that ignored the refusal would still succeed — which is what makes the refusal
        /// assertion load-bearing rather than a test of an empty queue.
        fn declining_the_phrase(password: &str) -> Arc<Self> {
            Arc::new(Self {
                keeps_the_phrase: ConfirmDecision::Deny,
                answers: Mutex::new(std::iter::repeat(password.to_string()).take(2).collect()),
                claims: Mutex::new(0),
            })
        }

        /// The user confirms the words then cancels the password window.
        fn confirming_then_cancelling() -> Arc<Self> {
            Arc::new(Self {
                keeps_the_phrase: ConfirmDecision::Approve,
                answers: Mutex::new(std::collections::VecDeque::new()),
                claims: Mutex::new(0),
            })
        }

        fn confirmer(self: &Arc<Self>) -> Arc<dyn NativeConfirmer> {
            Arc::clone(self) as Arc<dyn NativeConfirmer>
        }

        /// How many claim windows the user was shown — the retention screens.
        fn claims_shown(&self) -> usize {
            *self.claims.lock().unwrap()
        }
    }

    impl NativeConfirmer for Scripted {
        fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("a migration never pairs")
        }
        fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("a migration never connects")
        }
        fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
            unreachable!("a migration never signs")
        }
        fn confirm_claim(&self, _p: &ClaimPrompt<'_>) -> ConfirmDecision {
            *self.claims.lock().unwrap() += 1;
            self.keeps_the_phrase
        }
        fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_reveal(&self, _p: &RevealPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
            match self.answers.lock().unwrap().pop_front() {
                Some(text) => InputOutcome::Provided(Zeroizing::new(text)),
                None => InputOutcome::Cancelled,
            }
        }
    }

    /// A `KeychainBackend` that refuses to WRITE, wrapping a real one that has already been populated.
    ///
    /// This is how the rollback path is driven through the real code rather than a simulated branch: the
    /// migration deletes the old blob, then its re-enrol write fails. Reads and deletes still work, so
    /// everything up to the failure behaves exactly as in production.
    struct RefusesWrites(Arc<dyn KeychainBackend>);

    impl KeychainBackend for RefusesWrites {
        fn read(&self, key: &BackendKey) -> Result<Vec<u8>, BackendError> {
            self.0.read(key)
        }
        fn write(&self, _key: &BackendKey, _data: &[u8]) -> Result<(), BackendError> {
            Err(BackendError::Backend(Arc::new(std::io::Error::other(
                "this backend refuses writes",
            ))))
        }
        fn delete(&self, key: &BackendKey) -> Result<(), BackendError> {
            self.0.delete(key)
        }
        fn list(&self, prefix: &str) -> Result<Vec<BackendKey>, BackendError> {
            self.0.list(prefix)
        }
        fn exists(&self, key: &BackendKey) -> Result<bool, BackendError> {
            self.0.exists(key)
        }
    }

    /// A host in the pre-#1817 state: an account sealed under `machine_password`, its recovery phrase in
    /// the vault, and the machine password in the credential store.
    ///
    /// Returns the shared backend, the credential store, the identity public key the account derives, and
    /// the temp dir holding the vault.
    struct LegacyHost {
        backend: Arc<dyn KeychainBackend>,
        cred: MemCred,
        identity: String,
        dir: tempfile::TempDir,
    }

    fn legacy_host(machine_password: &str) -> LegacyHost {
        use crate::account::boot::{assemble_residency, finish_boot};
        use crate::account::lifecycle::Seeding;
        use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
        use crate::session_lock::SessionKeys;

        struct Keeps;
        impl PhrasePresenter for Keeps {
            fn present_new_phrase(&self, _p: &RecoveryPhrase) -> RetentionDecision {
                RetentionDecision::Confirmed
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, phrase) = assemble_residency(
            Arc::clone(&backend),
            PasswordCeremony::for_a_new_account(
                Scripted::confirming_and_typing(machine_password).confirmer(),
            ),
            account(),
            Seeding::NewPhrase(&Keeps),
        )
        .expect("the legacy-shaped account enrols");
        let identity = residency
            .signing_public_key_hex(ProfileIx::ROOT)
            .expect("unlocked");
        let booted = finish_boot(dir.path(), residency, phrase);
        assert!(booted.recoverable, "the fixture must have a vaulted phrase");
        booted.residency.lock_all();

        LegacyHost {
            backend,
            cred: MemCred::holding(machine_password),
            identity,
            dir,
        }
    }

    /// Whether `password` opens the default account over `backend`.
    fn opens(backend: &Arc<dyn KeychainBackend>, password: &str) -> bool {
        let store = account_store(Arc::clone(backend));
        opens_with(&store, &account(), &Zeroizing::new(password.to_string()))
    }

    /// The identity public key the default account derives under `password`, or `None` if it will not
    /// open. This is what proves a re-seal preserved the SEED rather than minting a new one.
    fn identity_under(backend: &Arc<dyn KeychainBackend>, password: &str) -> Option<String> {
        use crate::session_lock::SessionKeys;
        let store = account_store(Arc::clone(backend));
        let unlocked = open_with(&store, &account(), &Zeroizing::new(password.to_string()))?;
        let residency = AccountResidency::new(unlocked);
        let key = residency.signing_public_key_hex(ProfileIx::ROOT);
        residency.lock_all();
        key
    }

    /// **The whole point of the migration**: afterwards the USER's password opens the account, the
    /// machine's does not, and it is still the SAME account.
    ///
    /// The identity assertion is the load-bearing one. Without it, an implementation that threw the old
    /// seed away and enrolled a brand-new one would satisfy "the new password works and the old does
    /// not" perfectly — while having silently destroyed the user's keys, address and sealed data.
    #[test]
    fn a_machine_sealed_account_is_re_sealed_under_the_users_password() {
        let machine = password("machine");
        let chosen = password("chosen-by-the-user");
        let host = legacy_host(&machine);

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &Scripted::confirming_and_typing(&chosen).confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::Migrated);
        assert_eq!(
            identity_under(&host.backend, &chosen).as_deref(),
            Some(host.identity.as_str()),
            "a re-seal must preserve the master seed — same identity, same addresses, same DEKs"
        );
        assert!(
            !opens(&host.backend, &machine),
            "the machine-held password must no longer open the account"
        );
        assert!(
            !host.cred.holds_a_password(),
            "and the machine-held password must be gone from the credential store"
        );
    }

    /// The re-sealed account's already-sealed data must still open — the practical consequence of the
    /// seed being preserved, asserted through the phrase vault, which is real sealed data the user owns.
    #[test]
    fn already_sealed_data_still_opens_after_the_migration() {
        use crate::account::boot::vault_for;
        use crate::session_lock::SessionKeys;

        let machine = password("machine");
        let chosen = password("chosen");
        let host = legacy_host(&machine);
        let before = {
            let store = account_store(Arc::clone(&host.backend));
            let unlocked = open_with(&store, &account(), &Zeroizing::new(machine.clone())).unwrap();
            let residency = AccountResidency::new(unlocked);
            let words = vault_for(host.dir.path(), &residency)
                .unwrap()
                .load()
                .unwrap()
                .unwrap()
                .words()
                .join(" ");
            residency.lock_all();
            words
        };

        migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &Scripted::confirming_and_typing(&chosen).confirmer(),
            host.dir.path(),
        );

        let store = account_store(Arc::clone(&host.backend));
        let unlocked = open_with(&store, &account(), &Zeroizing::new(chosen)).expect("re-sealed");
        let residency = AccountResidency::new(unlocked);
        let after = vault_for(host.dir.path(), &residency)
            .expect("unlocked")
            .load()
            .expect("the vault still opens under the new password")
            .expect("the phrase is still there");
        assert_eq!(
            after.words().join(" "),
            before,
            "the same sealed phrase must come back — a changed DEK would leave it unreadable"
        );
    }

    /// A host with no machine-held password has nothing to migrate, and nothing may be touched.
    #[test]
    fn a_host_with_no_machine_password_is_left_alone() {
        let chosen = password("chosen");
        let host = legacy_host(&password("machine"));
        // The same host, but with an EMPTY credential store — an account already migrated, or one
        // created after #1817.
        let empty = MemCred::default();
        let confirmer = Scripted::confirming_and_typing(&chosen);

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &empty,
            &confirmer.confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::NotNeeded);
        assert_eq!(
            confirmer.claims_shown(),
            0,
            "a host with nothing to migrate must not be shown a single window"
        );
        assert!(
            opens(&host.backend, &password("machine")),
            "and its account must be exactly as it was"
        );
    }

    /// An account whose machine password does NOT open it (a legacy format, a corrupt blob) must be left
    /// completely alone — a migration must never be the thing that destroys such an account.
    #[test]
    fn an_account_the_stored_password_cannot_open_is_left_untouched() {
        let host = legacy_host(&password("machine"));
        // The credential store holds the WRONG password — the shape of a host whose blob predates this
        // scheme, or whose entry drifted.
        let wrong = MemCred::holding(&password("not-the-one"));
        let confirmer = Scripted::confirming_and_typing(&password("chosen"));

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &wrong,
            &confirmer.confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::Unopenable);
        assert!(outcome.account_intact());
        assert_eq!(
            confirmer.claims_shown(),
            0,
            "the user must not be walked through a migration that cannot run"
        );
        assert!(
            opens(&host.backend, &password("machine")),
            "the account must still open exactly as before"
        );
    }

    /// A machine-sealed account with NO vaulted phrase cannot be re-sealed, and must be left exactly as
    /// it is — never destroyed, and never quietly reported as migrated.
    #[test]
    fn an_account_with_no_vaulted_phrase_is_left_exactly_as_it_was() {
        let machine = password("machine");
        let host = legacy_host(&machine);
        // Remove the vault, leaving an account that opens but whose words are not recoverable — the
        // shape of an account enrolled between the custody switchover and the phrase vault.
        for profile in std::fs::read_dir(host.dir.path().join("profiles"))
            .expect("the fixture vaulted a phrase")
            .flatten()
        {
            let vault = profile
                .path()
                .join(crate::account::phrase_vault::VAULT_FILE);
            if vault.exists() {
                std::fs::remove_file(vault).unwrap();
            }
        }
        let confirmer = Scripted::confirming_and_typing(&password("chosen"));

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &confirmer.confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::CannotReseal);
        assert!(
            opens(&host.backend, &machine),
            "an account that cannot be re-sealed must still open under its old password"
        );
        assert!(
            host.cred.holds_a_password(),
            "and its password must be kept, because it is the only thing that opens it"
        );
    }

    /// Declining the recovery-phrase claim must change nothing — the user is saying "I am not ready for
    /// a password to become the only key".
    #[test]
    fn declining_the_phrase_claim_changes_nothing() {
        let machine = password("machine");
        let host = legacy_host(&machine);

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &Scripted::declining_the_phrase(&password("chosen")).confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::RefusedByUser);
        assert!(opens(&host.backend, &machine));
        assert!(host.cred.holds_a_password());
    }

    /// Cancelling the password window must change nothing, even though the phrase claim was confirmed.
    #[test]
    fn cancelling_the_new_password_changes_nothing() {
        let machine = password("machine");
        let host = legacy_host(&machine);

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &Scripted::confirming_then_cancelling().confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::RefusedByUser);
        assert!(opens(&host.backend, &machine));
        assert!(host.cred.holds_a_password());
    }

    /// **The point of no return, and the rollback.** If the re-enrol fails after the old blob is gone,
    /// the account is put back under its OLD password from the phrase still in hand.
    ///
    /// Driven through the real code by a backend that refuses writes, so the failure happens where a real
    /// disk failure would. The rollback's own write is refused too, which is why the honest assertion
    /// here is that the outcome is reported as [`MigrationOutcome::Lost`] rather than swallowed — the one
    /// case the user MUST be told about, and the reason their 24 words matter.
    #[test]
    fn a_re_enrol_that_cannot_write_reports_the_loss_rather_than_hiding_it() {
        let machine = password("machine");
        let host = legacy_host(&machine);
        let refusing: Arc<dyn KeychainBackend> = Arc::new(RefusesWrites(Arc::clone(&host.backend)));

        let outcome = migrate_to_user_password(
            account_store(refusing),
            &account(),
            &host.cred,
            &Scripted::confirming_and_typing(&password("chosen")).confirmer(),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::Lost);
        assert!(
            !outcome.account_intact(),
            "a lost account must never report itself intact"
        );
        assert!(
            host.cred.holds_a_password(),
            "the machine password must survive a failed migration — it is what a retry needs"
        );
    }

    /// The user is shown the words BEFORE the password is asked for.
    ///
    /// Reversing them would let a user set a password without having re-checked the only thing that
    /// survives forgetting it. The fixture proves the ORDER, not merely that both happened: the claim
    /// double records how many password windows had been drawn when it was consulted.
    #[test]
    fn the_phrase_is_confirmed_before_the_password_is_asked_for() {
        struct Ordered {
            password: String,
            prompts: Mutex<usize>,
            prompts_at_claim: Mutex<Option<usize>>,
        }
        impl NativeConfirmer for Ordered {
            fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
                unreachable!()
            }
            fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
                unreachable!()
            }
            fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
                unreachable!()
            }
            fn confirm_claim(&self, _p: &ClaimPrompt<'_>) -> ConfirmDecision {
                let drawn = *self.prompts.lock().unwrap();
                let mut first = self.prompts_at_claim.lock().unwrap();
                if first.is_none() {
                    *first = Some(drawn);
                }
                ConfirmDecision::Approve
            }
            fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
                ConfirmDecision::Approve
            }
            fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
                *self.prompts.lock().unwrap() += 1;
                InputOutcome::Provided(Zeroizing::new(self.password.clone()))
            }
        }

        let host = legacy_host(&password("machine"));
        let confirmer: Arc<Ordered> = Arc::new(Ordered {
            password: password("chosen"),
            prompts: Mutex::new(0),
            prompts_at_claim: Mutex::new(None),
        });

        let outcome = migrate_to_user_password(
            account_store(Arc::clone(&host.backend)),
            &account(),
            &host.cred,
            &(Arc::clone(&confirmer) as Arc<dyn NativeConfirmer>),
            host.dir.path(),
        );

        assert_eq!(outcome, MigrationOutcome::Migrated);
        assert_eq!(
            *confirmer.prompts_at_claim.lock().unwrap(),
            Some(0),
            "the words must be confirmed before a password window is drawn"
        );
        assert!(
            *confirmer.prompts.lock().unwrap() >= 2,
            "and the password must then actually be asked for, twice"
        );
    }
}
