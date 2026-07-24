//! The production account BOOT glue — assembles the master-HD unlock/enroll flow the tray shell mounts
//! (#1547, custody switchover).
//!
//! [`assemble_residency`] is the testable core: over any keystore backend + credential store it
//! enrols-or-unlocks the account (through [`open_or_enroll`](crate::account::lifecycle::open_or_enroll)
//! with a [`CredentialCeremony`](crate::account::ceremony::CredentialCeremony)) and houses the result
//! in an [`AccountResidency`]. [`boot_residency`] / [`reunlock_into`] are the thin, cfg-gated
//! production wrappers that wire the host's real [`OsCredentialStore`](crate::keystore::OsCredentialStore)
//! (Windows/macOS zero-prompt) + a per-user [`FileBackend`](dig_session::FileBackend) — deferring on
//! Linux exactly as the retired path did (no per-application-ACL credential store to unlock without a
//! prompt).
//!
//! This is the ONE place the app turns "a brand directory" into "a live, lockable unlocked account",
//! so the tray shell stays a thin caller and every piece underneath (lifecycle, ceremony, residency)
//! is unit-tested on its own.

use std::sync::Arc;

use dig_account::{
    AccountId, PasswordOnlyPolicy, ProfileIx, Result as AccountResult, UnlockedAccount,
};
use dig_session::KeychainBackend;

use crate::account::auth::HarnessAuthProvider;
use crate::account::ceremony::CredentialCeremony;
use crate::account::lifecycle::{account_store, open_or_enroll};
use crate::account::residency::AccountResidency;
use crate::keystore::CredentialStore;

/// The single-account id the app boots by default. The account model supports many accounts (the
/// [`registry`](crate::account::registry)); the tray boot currently opens the one default account, so
/// its id is fixed here rather than derived from key material (an app-local handle, not a DID).
pub const DEFAULT_ACCOUNT_ID: &str = "default";

/// Enrol-or-unlock `account` over `backend` + `cred`, returning the live unlocked account.
///
/// The password is sourced zero-prompt from `cred` ([`CredentialCeremony`]); a first run generates +
/// seals a fresh master seed, a later boot unlocks it. Fail-closed: any ceremony/keystore error yields
/// no [`UnlockedAccount`].
pub fn unlock_account<C>(
    backend: Arc<dyn KeychainBackend>,
    cred: C,
    account: AccountId,
) -> AccountResult<UnlockedAccount>
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
    ))
}

/// Enrol-or-unlock `account` and house it in a fresh [`AccountResidency`] — the boot-time assembly.
pub fn assemble_residency<C>(
    backend: Arc<dyn KeychainBackend>,
    cred: C,
    account: AccountId,
) -> AccountResult<AccountResidency>
where
    C: CredentialStore + Send + Sync + 'static,
{
    Ok(AccountResidency::new(unlock_account(
        backend, cred, account,
    )?))
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
    match unlock_account(backend, cred, account) {
        Ok(unlocked) => {
            residency.install(unlocked);
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

/// Boot the default account into a live residency from `brand_dir` — the production tray entry point.
///
/// Uses the host's [`OsCredentialStore`](crate::keystore::OsCredentialStore) for the zero-prompt
/// password and a per-user [`FileBackend`](dig_session::FileBackend) under `<brand_dir>/account` for
/// the sealed master seed. Returns `None` when there is no usable OS credential store (⇒ the signing
/// channel defers, as the retired path did).
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn boot_residency(brand_dir: &std::path::Path) -> Option<AccountResidency> {
    use crate::keystore::OsCredentialStore;
    use dig_session::FileBackend;

    let Some(cred) = OsCredentialStore::open(DEFAULT_ACCOUNT_ID) else {
        tracing::info!("account boot deferred: no usable OS credential store on this host");
        return None;
    };
    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    match assemble_residency(backend, cred, AccountId::new(DEFAULT_ACCOUNT_ID)) {
        Ok(residency) => Some(residency),
        Err(e) => {
            tracing::warn!(error = %e, "account boot failed — signing channel not started");
            None
        }
    }
}

/// Linux (and any host without a per-application-ACL credential store) defers zero-prompt unlock, so
/// the account boot yields no residency — mirroring the retired path's Linux deferral.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn boot_residency(_brand_dir: &std::path::Path) -> Option<AccountResidency> {
    tracing::info!("account boot deferred: no zero-prompt credential store on this OS yet");
    None
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

    #[test]
    fn assemble_first_run_then_returning_boot_derive_the_same_key() {
        // A shared backend + credential store models one machine across a restart. Both boots must
        // yield the SAME master-seed-derived identity — proving zero-prompt enrol-then-unlock.
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();

        let first = assemble_residency(backend.clone(), cred.clone(), account()).unwrap();
        let first_pk = first
            .signing_public_key_hex(ProfileIx::ROOT)
            .expect("unlocked");

        let second = assemble_residency(backend, cred, account()).unwrap();
        assert_eq!(
            second.signing_public_key_hex(ProfileIx::ROOT),
            Some(first_pk),
            "a returning boot must recover the enrolled seed's identity"
        );
    }

    #[test]
    fn reunlock_refills_a_locked_residency() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = MemCred::default();

        let residency = assemble_residency(backend.clone(), cred.clone(), account()).unwrap();
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
        let residency = assemble_residency(backend.clone(), MemCred::default(), account()).unwrap();
        residency.lock_all();

        assert!(
            !reunlock_into(backend, MemCred::default(), account(), &residency),
            "a re-unlock with the wrong (freshly-generated) password must fail closed"
        );
        assert!(!residency.is_any_unlocked());
    }
}
