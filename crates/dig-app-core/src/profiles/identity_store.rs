//! Cross-session identity persistence (U6, security-critical) — the bridge between a profile's
//! on-disk sealed identity (U4 [`ProfileVault`]) and the in-memory [`UnlockedIdentities`] session
//! store the [`KeystoreSealer`](super::keystore_sealer::KeystoreSealer) seals/opens under.
//!
//! # The gap this closes
//!
//! U5 registered a freshly provisioned identity ONLY in the in-memory session store, so a restarted
//! app had no key to derive a profile's DEK from — every profile's sealed data was unreadable after
//! exit. U6 persists each profile's identity **sealed at rest** (DIGOP1, under the user's root
//! unlock, in the per-user AppData — NC-2/NC-3) via [`ProfileVault`], and re-unlocks every owned
//! profile on boot so its DEK is available again.
//!
//! # Two operations, one session store
//!
//! - [`IdentityStore::persist_and_unlock`] — on profile creation, seal the identity at rest AND
//!   register it unlocked. The manager calls this only AFTER it has validated the DID (the F-1
//!   property), so a rejected DID never persists or clobbers anything.
//! - [`IdentityStore::unlock_persisted`] — on boot, re-derive a profile's identity from its sealed
//!   material and register it unlocked. Run for every profile in the registry, a restarted app can
//!   open all of its sealed data once the user supplies the root unlock.
//!
//! Cross-profile isolation is unchanged and still cryptographic: each profile is sealed and
//! re-unlocked under its OWN identity, so its DEK stays distinct — persistence never lets one
//! profile's key open another's blob.

use std::path::Path;

#[cfg(test)]
use dig_keystore::KdfParams;

use crate::keystore::{IdentitySecrets, KeystoreError, ProfileVault};

use super::keystore_sealer::UnlockedIdentities;

/// How the user's root unlock is supplied for a profile's sealed identity.
///
/// The root unlock opens the DIGOP1-sealed identity blob (SPEC §3.1). Its form is platform-decided:
/// the OS credential store releases it with no prompt on Windows/macOS, while Linux (and any
/// no-credential-store host) uses a user passphrase.
#[derive(Debug, Clone, Copy)]
pub enum RootUnlock<'a> {
    /// The OS credential store (Windows Credential Manager / macOS Keychain) releases the unlock —
    /// no passphrase is needed.
    OsKeychain,
    /// A user passphrase (Linux primary, or the fallback anywhere the OS store is unavailable).
    Passphrase(&'a str),
}

impl<'a> RootUnlock<'a> {
    /// The passphrase to hand [`ProfileVault`], or `None` to use the OS-credential-store path.
    fn passphrase(self) -> Option<&'a str> {
        match self {
            RootUnlock::OsKeychain => None,
            RootUnlock::Passphrase(p) => Some(p),
        }
    }
}

/// Builds the per-profile [`ProfileVault`] used to seal / unlock a profile's identity at rest.
///
/// A seam so tests inject an in-memory credential backend and a cheap KDF, while production
/// auto-detects the host's real OS credential store ([`OsVaultFactory`]).
pub trait VaultFactory: Send + Sync {
    /// Open the identity vault for the profile keyed by `did_hash`, whose sealed material lives in
    /// `profile_dir`.
    fn open_vault(&self, did_hash: &str, profile_dir: &Path) -> ProfileVault;
}

/// The production [`VaultFactory`]: [`ProfileVault::open`] auto-detects the OS credential store
/// (Windows/macOS primary) or falls back to the passphrase-sealed file (Linux primary / fallback),
/// with the production Argon2 cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsVaultFactory;

impl VaultFactory for OsVaultFactory {
    fn open_vault(&self, did_hash: &str, profile_dir: &Path) -> ProfileVault {
        ProfileVault::open(did_hash, profile_dir.to_path_buf())
    }
}

/// Persists profile identities sealed at rest and re-unlocks them into the shared session store.
///
/// Holds the SAME [`UnlockedIdentities`] the [`KeystoreSealer`](super::keystore_sealer::KeystoreSealer)
/// reads, so an identity this store unlocks is immediately usable to seal/open that profile's data.
pub struct IdentityStore {
    session: UnlockedIdentities,
    factory: Box<dyn VaultFactory>,
}

impl IdentityStore {
    /// Builds a store that registers unlocked identities into `session` and seals them at rest
    /// through vaults built by `factory`.
    pub fn new(session: UnlockedIdentities, factory: Box<dyn VaultFactory>) -> Self {
        Self { session, factory }
    }

    /// The production store over `session`, using the host's real OS credential store / sealed file.
    pub fn production(session: UnlockedIdentities) -> Self {
        Self::new(session, Box::new(OsVaultFactory))
    }

    /// Seal `secrets` at rest for `did` (NC-2/NC-3) under the root unlock, then register it as the
    /// unlocked identity for `did` so its data can be sealed/opened this session.
    ///
    /// The manager calls this ONLY after it has validated the DID and confirmed no profile already
    /// owns it (the F-1 property), so this never overwrites an existing profile's sealed identity or
    /// clobbers a live session identity.
    pub fn persist_and_unlock(
        &self,
        did: &str,
        did_hash: &str,
        profile_dir: &Path,
        secrets: IdentitySecrets,
        root: RootUnlock<'_>,
    ) -> Result<(), KeystoreError> {
        let vault = self.factory.open_vault(did_hash, profile_dir);
        // Seal at rest FIRST: only a durably persisted identity is registered as unlocked, so the
        // session never advertises a profile whose key would vanish on the next restart.
        vault.create(&secrets, root.passphrase())?;
        self.session.unlock(did.to_string(), secrets);
        Ok(())
    }

    /// Re-derive `did`'s identity from its sealed material and register it unlocked — the boot-time
    /// re-unlock that makes a restarted profile's sealed data readable again.
    ///
    /// Fails closed ([`KeystoreError::Unlock`] / [`KeystoreError::NotInitialized`]) on a wrong root
    /// unlock, a tampered blob, or a profile that was never persisted; the session is left untouched
    /// in that case.
    pub fn unlock_persisted(
        &self,
        did: &str,
        did_hash: &str,
        profile_dir: &Path,
        root: RootUnlock<'_>,
    ) -> Result<(), KeystoreError> {
        let vault = self.factory.open_vault(did_hash, profile_dir);
        let secrets = vault.unlock(root.passphrase())?;
        self.session.unlock(did.to_string(), secrets);
        Ok(())
    }

    /// Roll back a persisted+unlocked identity: lock it out of the session and delete its sealed
    /// material. Used when a later step of profile creation fails, so a half-created profile leaves
    /// no dangling sealed identity or live session key. Idempotent.
    pub fn forget(
        &self,
        did: &str,
        did_hash: &str,
        profile_dir: &Path,
    ) -> Result<(), KeystoreError> {
        self.session.lock_profile(did);
        self.factory.open_vault(did_hash, profile_dir).remove()
    }
}

/// A test-only [`VaultFactory`] building passphrase-sealed-FILE vaults with the cheap test KDF.
///
/// File-mode identities persist as a durable file in each profile's directory, so a "restart"
/// (a fresh [`IdentityStore`] over the same directory tree) recovers them with the passphrase —
/// modelling the Linux custody primary without a host credential store.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FileVaultFactory;

#[cfg(test)]
impl VaultFactory for FileVaultFactory {
    fn open_vault(&self, did_hash: &str, profile_dir: &Path) -> ProfileVault {
        ProfileVault::with_backend(
            did_hash,
            profile_dir.to_path_buf(),
            None,
            KdfParams::FAST_TEST,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::keystore::CredentialStore;

    const DID: &str = "did:chia:profile-a";
    const HASH: &str = "hash-a";

    /// A fresh file-backed store — models one app run; a second `store()` over the same directory
    /// tree models a restart (nothing unlocked until it re-unlocks from the durable sealed file).
    fn store() -> IdentityStore {
        IdentityStore::new(UnlockedIdentities::new(), Box::new(FileVaultFactory))
    }

    /// The core round-trip: persist an identity, then a FRESH store over the same directory (a
    /// restart) re-unlocks it with the passphrase and can seal/open that profile's data again.
    #[test]
    fn persist_then_reunlock_across_a_restart_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join(HASH);
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();

        // First run: persist + unlock.
        let first = store();
        first
            .persist_and_unlock(
                DID,
                HASH,
                &profile_dir,
                secrets,
                RootUnlock::Passphrase("pw"),
            )
            .unwrap();
        assert!(first.session.is_unlocked(DID));

        // Restart: a brand-new session + store over the same directory has nothing unlocked …
        let second = store();
        assert!(!second.session.is_unlocked(DID));
        // … until it re-unlocks the persisted identity, recovering the SAME key.
        second
            .unlock_persisted(DID, HASH, &profile_dir, RootUnlock::Passphrase("pw"))
            .unwrap();
        assert!(second.session.is_unlocked(DID));
        assert_eq!(second.session.signing_public_key(DID).unwrap(), pk);
    }

    /// A wrong root unlock fails closed and leaves the session untouched (no half-unlocked profile).
    #[test]
    fn reunlock_with_a_wrong_passphrase_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join(HASH);
        store()
            .persist_and_unlock(
                DID,
                HASH,
                &profile_dir,
                IdentitySecrets::generate(),
                RootUnlock::Passphrase("right"),
            )
            .unwrap();

        let restarted = store();
        assert!(matches!(
            restarted.unlock_persisted(DID, HASH, &profile_dir, RootUnlock::Passphrase("wrong")),
            Err(KeystoreError::Unlock)
        ));
        assert!(
            !restarted.session.is_unlocked(DID),
            "no profile is unlocked after a failed unlock"
        );
    }

    /// Re-unlocking a profile that was never persisted is `NotInitialized`, not a panic.
    #[test]
    fn reunlock_of_an_unpersisted_profile_is_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            store().unlock_persisted(
                DID,
                HASH,
                &dir.path().join(HASH),
                RootUnlock::Passphrase("pw"),
            ),
            Err(KeystoreError::NotInitialized)
        ));
    }

    /// `forget` locks the session identity AND deletes the sealed file, so a rolled-back profile
    /// cannot be re-unlocked afterward. Idempotent.
    #[test]
    fn forget_locks_the_session_and_removes_the_sealed_identity() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join(HASH);
        let s = store();
        s.persist_and_unlock(
            DID,
            HASH,
            &profile_dir,
            IdentitySecrets::generate(),
            RootUnlock::Passphrase("pw"),
        )
        .unwrap();

        s.forget(DID, HASH, &profile_dir).unwrap();
        assert!(!s.session.is_unlocked(DID));
        // The sealed identity is gone, so a fresh store can no longer unlock it.
        assert!(matches!(
            store().unlock_persisted(DID, HASH, &profile_dir, RootUnlock::Passphrase("pw")),
            Err(KeystoreError::NotInitialized)
        ));
        // Forgetting again is a no-op.
        s.forget(DID, HASH, &profile_dir).unwrap();
    }

    /// The OS-credential-store path round-trips across a restart when the backend persists (modelled
    /// by a shared in-memory store) — the Windows/macOS custody primary, no passphrase.
    #[test]
    fn os_keychain_path_round_trips_across_a_restart() {
        #[derive(Clone, Default)]
        struct SharedStore(Arc<Mutex<HashMap<String, String>>>);
        impl CredentialStore for SharedStore {
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
        struct OsFactory(SharedStore);
        impl VaultFactory for OsFactory {
            fn open_vault(&self, did_hash: &str, profile_dir: &Path) -> ProfileVault {
                ProfileVault::with_backend(
                    did_hash,
                    profile_dir.to_path_buf(),
                    Some(Box::new(self.0.clone())),
                    KdfParams::FAST_TEST,
                )
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join(HASH);
        let backend = SharedStore::default();
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();

        let first = IdentityStore::new(
            UnlockedIdentities::new(),
            Box::new(OsFactory(backend.clone())),
        );
        first
            .persist_and_unlock(DID, HASH, &profile_dir, secrets, RootUnlock::OsKeychain)
            .unwrap();

        // Restart: fresh session, SAME credential backend.
        let second = IdentityStore::new(UnlockedIdentities::new(), Box::new(OsFactory(backend)));
        second
            .unlock_persisted(DID, HASH, &profile_dir, RootUnlock::OsKeychain)
            .unwrap();
        assert_eq!(second.session.signing_public_key(DID).unwrap(), pk);
    }
}
