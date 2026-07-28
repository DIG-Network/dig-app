//! The production account BOOT glue — assembles the master-HD unlock/enroll flow the tray shell mounts
//! (#1547, custody switchover).
//!
//! [`open_account`] is the production journey: enrol-or-unlock, and on a FIRST run show the user their
//! 24-word recovery phrase, require them to confirm they kept it, and seal a copy into the phrase vault
//! so the tray can show it again (dig_ecosystem#1752).
//!
//! [`assemble_residency`] is the testable core: over any keystore backend + credential store it
//! enrols-or-unlocks the account (through [`open_or_enroll`](crate::account::lifecycle::open_or_enroll)
//! with a [`CredentialCeremony`](crate::account::ceremony::CredentialCeremony)) and houses the result
//! in an [`AccountResidency`]. [`open_account`] / [`boot_existing_account`] / [`reunlock_into`] are the thin, cfg-gated
//! production wrappers that wire the host's real [`OsCredentialStore`](crate::keystore::OsCredentialStore)
//! (Windows/macOS zero-prompt) + a per-user [`FileBackend`](dig_session::FileBackend) — deferring on
//! Linux exactly as the retired path did (no per-application-ACL credential store to unlock without a
//! prompt).
//!
//! This is the ONE place the app turns "a brand directory" into "a live, lockable unlocked account",
//! so the tray shell stays a thin caller and every piece underneath (lifecycle, ceremony, residency)
//! is unit-tested on its own.

use std::sync::Arc;

use dig_account::{AccountId, PasswordOnlyPolicy, ProfileIx, Result as AccountResult};

/// A [`PhrasePresenter`] that can never approve an enrolment — used on paths where enrolment is
/// impossible by construction (a RE-unlock of an account that already exists), so an unexpected
/// first-run would fail closed instead of creating an account with an unseen recovery phrase.
struct NeverEnrols;

impl PhrasePresenter for NeverEnrols {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Unavailable
    }
}
use dig_session::KeychainBackend;

use crate::account::auth::HarnessAuthProvider;
use crate::account::ceremony::CredentialCeremony;
use crate::account::lifecycle::{
    account_store, open_or_enroll, Opened, PhrasePresenter, RetentionDecision, Seeding,
};
use crate::account::phrase_vault::PhraseVault;
use crate::account::recovery::RecoveryPhrase;
use crate::account::residency::{AccountResidency, ResidencySealer};
use crate::keystore::CredentialStore;

/// The single-account id the app boots by default. The account model supports many accounts (the
/// [`registry`](crate::account::registry)); the tray boot currently opens the one default account, so
/// its id is fixed here rather than derived from key material (an app-local handle, not a DID).
pub const DEFAULT_ACCOUNT_ID: &str = "default";

/// Enrol-or-unlock `account` over `backend` + `cred`, returning what the boot did.
///
/// The password is sourced zero-prompt from `cred` ([`CredentialCeremony`]); a first run settles its
/// custody root from `seeding` (a shown-and-confirmed new recovery phrase, or one the user is restoring
/// from) and seals it, a later boot unlocks it. Fail-closed: any ceremony/keystore error — or a
/// recovery phrase the user did not confirm — yields no account at all.
pub fn unlock_account<C>(
    backend: Arc<dyn KeychainBackend>,
    cred: C,
    account: AccountId,
    seeding: Seeding<'_>,
) -> AccountResult<Opened>
where
    C: CredentialStore + Send + Sync + 'static,
{
    let store = account_store(backend);
    let provider = HarnessAuthProvider::new(CredentialCeremony::new(cred));
    block_on(open_or_enroll(
        store,
        account,
        &provider,
        &PasswordOnlyPolicy,
        ProfileIx::ROOT,
        seeding,
    ))
}

/// Enrol-or-unlock `account` and house it in a fresh [`AccountResidency`] — the boot-time assembly.
///
/// The second element is the enrolment phrase, present ONLY on a first run. The caller must vault it
/// (see [`vault_for`]) so the account can show its phrase again later; dropping it instead leaves an
/// account that works but can never re-display its words.
pub fn assemble_residency<C>(
    backend: Arc<dyn KeychainBackend>,
    cred: C,
    account: AccountId,
    seeding: Seeding<'_>,
) -> AccountResult<(AccountResidency, Option<RecoveryPhrase>)>
where
    C: CredentialStore + Send + Sync + 'static,
{
    match unlock_account(backend, cred, account, seeding)? {
        Opened::Existing(unlocked) => Ok((AccountResidency::new(unlocked), None)),
        Opened::Enrolled { account, phrase } => Ok((AccountResidency::new(account), Some(phrase))),
    }
}

/// The root profile's stable id for a live `residency` — the handle the per-profile directories, the
/// connect advertisement, and the phrase vault are all keyed by.
///
/// It is the seed-derived identity public key in hex, because there is no on-chain DID mint yet (see
/// [`crate::tray_menu`] for what the user is told about that). Returns `None` when the account is
/// locked.
pub fn root_profile_id(residency: &AccountResidency) -> Option<String> {
    residency.signing_public_key_hex(ProfileIx::ROOT)
}

/// The phrase vault for the root profile of a live `residency`, or `None` when it is locked.
///
/// The vault seals through the residency's LIVE-view sealer, so it fails closed the instant the account
/// locks — a reveal can never outlive an unlock.
pub fn vault_for(
    brand_dir: &std::path::Path,
    residency: &AccountResidency,
) -> Option<PhraseVault<ResidencySealer>> {
    let profile_id = root_profile_id(residency)?;
    Some(PhraseVault::new(
        residency.production_sealer(ProfileIx::ROOT),
        brand_dir,
        &profile_id,
    ))
}

/// Re-unlock `account` and INSTALL it into an existing `residency` — the sign-path re-auth after a
/// lock (a zero-prompt re-unlock on Windows/macOS). Returns whether the re-unlock succeeded.
pub fn reunlock_into<C>(
    backend: Arc<dyn KeychainBackend>,
    cred: C,
    account: AccountId,
    residency: &AccountResidency,
) -> bool
where
    C: CredentialStore + Send + Sync + 'static,
{
    // A re-unlock is never an enrolment: the account provably exists (we just locked it), so the
    // seeding arm is unreachable. `NeverEnrols` makes that a type-level guarantee rather than a comment
    // — if the invariant ever broke, this path would refuse rather than silently mint a second account
    // with a phrase nobody saw.
    match unlock_account(backend, cred, account, Seeding::NewPhrase(&NeverEnrols)) {
        Ok(opened) => {
            residency.install(opened.into_account());
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "account re-unlock failed — sign stays locked");
            false
        }
    }
}

/// Block on `fut` on a private current-thread runtime. The unlock flow is async (the auth ceremony is
/// an `async` seam), but the tray boot is synchronous; this bridges the two without requiring the shell
/// to own a runtime. Cheap — it runs exactly one enrol/unlock to completion then drops.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread tokio runtime for the account unlock")
        .block_on(fut)
}

/// A booted account: the live residency plus the two facts the tray needs to describe it honestly.
pub struct BootedAccount {
    /// The live, unlocked account.
    pub residency: AccountResidency,
    /// The root profile's stable id (see [`root_profile_id`]).
    pub profile_id: String,
    /// Whether this account has a recovery phrase stored. `false` means it was enrolled before recovery
    /// phrases existed and **cannot be recovered from words** — the tray says so plainly rather than
    /// implying a safety that is not there.
    pub recoverable: bool,
}

/// Whether the default account is already enrolled on this host.
///
/// A pure existence check on the sealed-seed blob — no unlock, no credential store, no prompt — so the
/// shell can decide between "unlock the account we have" and "offer to set one up" without any side
/// effect. This is what keeps first-run setup a DELIBERATE tray action rather than a modal that ambushes
/// the user at login.
pub fn account_exists(brand_dir: &std::path::Path) -> bool {
    use dig_session::FileBackend;

    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    account_store(backend)
        .exists(&AccountId::new(DEFAULT_ACCOUNT_ID))
        .unwrap_or(false)
}

/// Open the default account from `brand_dir`, enrolling it from `seeding` if it does not exist yet.
///
/// Uses the host's [`OsCredentialStore`](crate::keystore::OsCredentialStore) for the zero-prompt
/// password and a per-user [`FileBackend`](dig_session::FileBackend) under `<brand_dir>/account` for the
/// sealed master seed. On a first run the phrase is shown, retention is confirmed, and a copy is sealed
/// into the phrase vault so the tray can show it again later.
///
/// Returns `None` when there is no usable OS credential store, when the user cancels setup, or on any
/// keystore failure — in every case leaving the host exactly as it was.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn open_account(brand_dir: &std::path::Path, seeding: Seeding<'_>) -> Option<BootedAccount> {
    use crate::keystore::OsCredentialStore;
    use dig_session::FileBackend;

    let Some(cred) = OsCredentialStore::open(DEFAULT_ACCOUNT_ID) else {
        tracing::info!("account boot deferred: no usable OS credential store on this host");
        return None;
    };
    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    let assembled = assemble_residency(backend, cred, AccountId::new(DEFAULT_ACCOUNT_ID), seeding);
    let (residency, fresh_phrase) = match assembled {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "account not opened");
            return None;
        }
    };
    Some(finish_boot(brand_dir, residency, fresh_phrase))
}

/// Unlock the default account only if it ALREADY exists — the boot-time path.
///
/// Never enrols: a host with no account yet gets `None` and a tray that offers to set one up, rather
/// than a recovery-phrase window nobody asked for.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn boot_existing_account(brand_dir: &std::path::Path) -> Option<BootedAccount> {
    if !account_exists(brand_dir) {
        tracing::info!("no DIG account on this host yet — the tray will offer to set one up");
        return None;
    }
    open_account(brand_dir, Seeding::NewPhrase(&NeverEnrols))
}

/// Linux (and any host without a per-application-ACL credential store) defers zero-prompt unlock, so
/// the account boot yields no account — mirroring the retired path's Linux deferral.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn open_account(_brand_dir: &std::path::Path, _seeding: Seeding<'_>) -> Option<BootedAccount> {
    tracing::info!("account boot deferred: no zero-prompt credential store on this OS yet");
    None
}

/// Linux stub — see [`open_account`].
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn boot_existing_account(_brand_dir: &std::path::Path) -> Option<BootedAccount> {
    None
}

/// Complete a boot: vault a first run's phrase and read back whether the account is recoverable.
///
/// Public so the integration suite can drive it on any platform (the cfg-gated [`boot_account`] above
/// is the only production caller).
///
/// Split out (and platform-independent) so the vaulting rule — *a fresh phrase is sealed immediately,
/// while the account is unlocked and the words are still in hand* — is unit-tested rather than living
/// only inside the cfg-gated production path.
pub fn finish_boot(
    brand_dir: &std::path::Path,
    residency: AccountResidency,
    fresh_phrase: Option<RecoveryPhrase>,
) -> BootedAccount {
    let profile_id = root_profile_id(&residency).unwrap_or_default();
    let vault = vault_for(brand_dir, &residency);

    if let (Some(phrase), Some(vault)) = (&fresh_phrase, &vault) {
        // A vault write failure must not abandon the account the user just created — they have the
        // words on paper, which is the copy that matters. It DOES mean the tray must report the account
        // as not-recoverable, which `is_recoverable` below does on its own.
        if let Err(e) = vault.store(phrase) {
            tracing::warn!(error = %e, "could not store the recovery phrase for later display");
        }
    }

    BootedAccount {
        recoverable: vault.map(|v| v.is_recoverable()).unwrap_or(false),
        residency,
        profile_id,
    }
}

/// Re-unlock the default account into `residency` from `brand_dir` — the production sign-path re-auth.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn reboot_reunlock(brand_dir: &std::path::Path, residency: &AccountResidency) -> bool {
    use crate::keystore::OsCredentialStore;
    use dig_session::FileBackend;

    let Some(cred) = OsCredentialStore::open(DEFAULT_ACCOUNT_ID) else {
        return false;
    };
    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    reunlock_into(backend, cred, AccountId::new(DEFAULT_ACCOUNT_ID), residency)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn reboot_reunlock(_brand_dir: &std::path::Path, _residency: &AccountResidency) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KeystoreError;
    use crate::session_lock::SessionKeys;
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::MemoryBackend;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory credential store that persists across a "restart" (a second call over the same
    /// shared map), so first-run enrol vs a returning unlock are both exercised.
    #[derive(Clone, Default)]
    struct MemCred(Arc<Mutex<HashMap<String, String>>>);
    impl CredentialStore for MemCred {
        fn get(&self, a: &str) -> Result<Option<String>, KeystoreError> {
            Ok(self.0.lock().unwrap().get(a).cloned())
        }
        fn set(&self, a: &str, s: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().insert(a.into(), s.into());
            Ok(())
        }
        fn delete(&self, a: &str) -> Result<(), KeystoreError> {
            self.0.lock().unwrap().remove(a);
            Ok(())
        }
    }

    fn account() -> AccountId {
        AccountId::new(DEFAULT_ACCOUNT_ID)
    }

    /// A presenter that always confirms — the fixture for "the user wrote the words down".
    struct AlwaysKeeps;

    impl PhrasePresenter for AlwaysKeeps {
        fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
            RetentionDecision::Confirmed
        }
    }

    /// Assemble over a shared backend + credential store, confirming any recovery phrase.
    fn assemble(
        backend: Arc<dyn KeychainBackend>,
        cred: MemCred,
    ) -> (AccountResidency, Option<RecoveryPhrase>) {
        assemble_residency(backend, cred, account(), Seeding::NewPhrase(&AlwaysKeeps)).unwrap()
    }

    #[test]
    fn assemble_first_run_then_returning_boot_derive_the_same_key() {
        // A shared backend + credential store models one machine across a restart. Both boots must
        // yield the SAME master-seed-derived identity — proving zero-prompt enrol-then-unlock.
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();

        let (first, first_phrase) = assemble(backend.clone(), cred.clone());
        let first_pk = first
            .signing_public_key_hex(ProfileIx::ROOT)
            .expect("unlocked");
        assert!(
            first_phrase.is_some(),
            "a first run must hand back the phrase it enrolled from"
        );

        let (second, second_phrase) = assemble(backend, cred);
        assert_eq!(
            second.signing_public_key_hex(ProfileIx::ROOT),
            Some(first_pk),
            "a returning boot must recover the enrolled seed's identity"
        );
        assert!(
            second_phrase.is_none(),
            "a returning boot holds no phrase — it never saw the words"
        );
    }

    /// A cancelled setup must leave the machine exactly as it was, so the user can try again.
    #[test]
    fn a_declined_phrase_yields_no_account() {
        struct AlwaysDeclines;
        impl PhrasePresenter for AlwaysDeclines {
            fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
                RetentionDecision::Declined
            }
        }
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());

        assert!(assemble_residency(
            backend.clone(),
            MemCred::default(),
            account(),
            Seeding::NewPhrase(&AlwaysDeclines),
        )
        .is_err());
        assert!(
            !account_store(backend).exists(&account()).unwrap(),
            "no seed blob may be left behind"
        );
    }

    /// The vaulting rule: a first run's phrase is sealed immediately, so the tray can show it again —
    /// and the SAME words come back, not merely *some* words.
    #[test]
    fn a_first_run_vaults_the_phrase_it_showed() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, phrase) = assemble(backend, MemCred::default());
        let shown = phrase.as_ref().unwrap().words().join(" ");

        let booted = finish_boot(dir.path(), residency, phrase);

        assert!(booted.recoverable, "a fresh account must be recoverable");
        let stored = vault_for(dir.path(), &booted.residency)
            .expect("unlocked")
            .load()
            .expect("the vault opens")
            .expect("a phrase is stored");
        assert_eq!(stored.words().join(" "), shown);
    }

    /// A LEGACY account — one whose seed was enrolled with no phrase — must be reported as NOT
    /// recoverable rather than quietly treated as safe. The fixture models it exactly: an account that
    /// exists at rest, booted with no fresh phrase to vault.
    #[test]
    fn an_account_with_no_vaulted_phrase_is_reported_unrecoverable() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();
        // Enrol, then boot AGAIN so the second boot carries no phrase — the shape of every account
        // enrolled before recovery phrases existed.
        let _ = assemble(backend.clone(), cred.clone());
        let (residency, phrase) = assemble(backend, cred);
        assert!(phrase.is_none());

        let booted = finish_boot(dir.path(), residency, phrase);
        assert!(
            !booted.recoverable,
            "an account with no vaulted phrase must be reported unrecoverable"
        );
    }

    /// The root profile id must be stable across boots — the per-profile directories and the phrase
    /// vault are keyed by it, so a changing id would orphan a user's sealed data.
    #[test]
    fn the_root_profile_id_is_stable_across_boots() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();

        let (first, _) = assemble(backend.clone(), cred.clone());
        let (second, _) = assemble(backend, cred);

        assert_eq!(root_profile_id(&first), root_profile_id(&second));
        assert!(root_profile_id(&first).is_some());
    }

    #[test]
    fn a_locked_residency_has_no_profile_id_and_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, _) = assemble(backend, MemCred::default());
        residency.lock_all();

        assert!(root_profile_id(&residency).is_none());
        assert!(
            vault_for(dir.path(), &residency).is_none(),
            "a locked account exposes no phrase vault"
        );
    }

    #[test]
    fn reunlock_refills_a_locked_residency() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();

        let (residency, _) = assemble(backend.clone(), cred.clone());
        let signer = residency.signer(ProfileIx::ROOT);
        residency.lock_all();
        assert!(signer.try_sign(b"m").is_none(), "locked");

        assert!(reunlock_into(backend, cred, account(), &residency));
        assert!(
            signer.try_sign(b"m").is_some(),
            "re-unlock must refill the residency so the live signer works again"
        );
    }

    #[test]
    fn reunlock_fails_closed_when_the_password_is_gone() {
        // Enrol under one credential store, then attempt a re-unlock with an EMPTY one: the ceremony
        // would generate a NEW password, so the keystore unlock fails the AEAD tag — fail-closed.
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, _) = assemble(backend.clone(), MemCred::default());
        residency.lock_all();

        assert!(
            !reunlock_into(backend, MemCred::default(), account(), &residency),
            "a re-unlock with the wrong (freshly-generated) password must fail closed"
        );
        assert!(!residency.is_any_unlocked());
    }

    /// A re-unlock must never ENROL. The fixture is an EMPTY backend, so a re-unlock would have to
    /// first-run — and `NeverEnrols` must refuse rather than mint an account from a phrase nobody saw.
    #[test]
    fn reunlock_refuses_to_enrol_a_missing_account() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let residency = AccountResidency::empty();

        assert!(!reunlock_into(
            backend.clone(),
            MemCred::default(),
            account(),
            &residency
        ));
        assert!(
            !account_store(backend).exists(&account()).unwrap(),
            "a re-unlock must never create an account"
        );
    }
}
