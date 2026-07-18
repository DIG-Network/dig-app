//! [`ProfileVault`] — the at-rest sealed store for one profile's identity, and the create / unlock
//! / rotate flows over it.
//!
//! The vault ties the pieces together: it DIGOP1-seals an [`IdentitySecrets`] (`secrets.rs`) and
//! persists the sealed blob, choosing its storage by the U4 precedence:
//!
//! - **OS credential store present (primary):** the sealed blob and its random unlock password are
//!   kept in ONE credential entry. A single entry means password rotation is a single atomic
//!   overwrite — a crash mid-rotation can never brick the profile — and the login session releases
//!   the entry with no prompt. The stored value is DIGOP1 ciphertext plus its wrapping password.
//! - **No credential store (fallback):** the sealed blob is a file in the profile's AppData
//!   directory, written atomically (temp file + rename), unlocked by a user passphrase that is
//!   never persisted.
//!
//! In both modes the identity private key is DIGOP1 ciphertext at rest and is reconstructed only in
//! memory, only after a correct unlock.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dig_keystore::{opaque, KdfParams, Password};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::credential::CredentialStore;
use super::secrets::IdentitySecrets;
use super::{KeystoreError, UnlockSource};

/// The file name of the sealed identity blob in the fallback (no-credential-store) path.
const SEALED_IDENTITY_FILE: &str = "identity.digop1";

/// The number of random bytes in a generated OS-credential-store unlock password. 32 bytes = 256
/// bits of entropy, far beyond brute-force reach even though the value never leaves the OS store.
const UNLOCK_PASSWORD_BYTES: usize = 32;

/// The value stored under a profile's OS credential-store entry: the sealed identity blob and the
/// random password that opens it, both base64. Serializing them together makes create/rotate a
/// single atomic write.
///
/// `password` holds live secret material (the base64 unlock password), so the struct is
/// [`ZeroizeOnDrop`] — the decoded/serialized copies of the password are scrubbed from memory the
/// moment this value is dropped, rather than left in freed heap.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredIdentity {
    /// Base64 of the DIGOP1-sealed identity blob.
    blob: String,
    /// Base64 of the random unlock password (the DIGOP1 password bytes).
    password: String,
}

/// The sealed identity store for a single profile, keyed by its DID hash.
///
/// Construct with [`ProfileVault::open`] in production (auto-detects the OS credential store) or
/// [`ProfileVault::with_backend`] to inject a store (tests, or a host that resolved its own).
pub struct ProfileVault {
    did_hash: String,
    profile_dir: PathBuf,
    credentials: Option<Box<dyn CredentialStore>>,
    kdf: KdfParams,
}

impl ProfileVault {
    /// Open the vault for the profile identified by `did_hash`, whose sealed data lives under
    /// `profile_dir`.
    ///
    /// On Windows/macOS this auto-detects the OS credential store and uses it as the custody
    /// primary; if none is usable, the vault falls back to the sealed file under `profile_dir`. On
    /// Linux the sealed file is ALWAYS the primary — keyutils is not a safe custody store (same-UID
    /// readable + non-persistent), so no OS store is consulted (see the `keystore` module docs).
    pub fn open(did_hash: impl Into<String>, profile_dir: impl Into<PathBuf>) -> Self {
        let did_hash = did_hash.into();
        let credentials = Self::detect_os_store(&did_hash);
        Self::with_backend(did_hash, profile_dir, credentials, KdfParams::DEFAULT)
    }

    /// Resolve the OS credential-store backend for this host, or `None` to use the sealed-file
    /// primary. On Windows/macOS this probes the platform credential store.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn detect_os_store(did_hash: &str) -> Option<Box<dyn CredentialStore>> {
        super::credential::OsCredentialStore::open(&Self::entry_account(did_hash))
            .map(|store| Box::new(store) as Box<dyn CredentialStore>)
    }

    /// On Linux (and any non-Windows/macOS target) there is deliberately no OS credential-store
    /// primary — the passphrase-sealed file is used instead (keyutils is same-UID-readable and
    /// non-persistent, so unsafe for custody; see the `keystore` module docs).
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn detect_os_store(_did_hash: &str) -> Option<Box<dyn CredentialStore>> {
        None
    }

    /// Construct a vault with an explicit credential-store backend (`Some` = OS-store mode, `None`
    /// = sealed-file fallback) and KDF parameters. Used by tests and by callers that resolve their
    /// own backend; production code uses [`ProfileVault::open`].
    pub fn with_backend(
        did_hash: impl Into<String>,
        profile_dir: impl Into<PathBuf>,
        credentials: Option<Box<dyn CredentialStore>>,
        kdf: KdfParams,
    ) -> Self {
        Self {
            did_hash: did_hash.into(),
            profile_dir: profile_dir.into(),
            credentials,
            kdf,
        }
    }

    /// `true` if a sealed identity already exists for this profile.
    pub fn is_initialized(&self) -> Result<bool, KeystoreError> {
        match &self.credentials {
            Some(store) => Ok(store.get(&self.account())?.is_some()),
            None => Ok(self.sealed_file().exists()),
        }
    }

    /// Seal `secrets` at rest for the first time, returning which [`UnlockSource`] was used.
    ///
    /// In OS-store mode a random unlock password is generated and stored with the blob (no
    /// passphrase needed — pass `None`). In the file-fallback mode `passphrase` is required and
    /// becomes the DIGOP1 password.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::PassphraseRequired`] in fallback mode with no passphrase; propagates seal /
    /// credential-store / I/O errors.
    pub fn create(
        &self,
        secrets: &IdentitySecrets,
        passphrase: Option<&str>,
    ) -> Result<UnlockSource, KeystoreError> {
        let plaintext = secrets.to_sealed_bytes();
        self.seal_and_store(&*plaintext, passphrase)
    }

    /// Unlock the sealed identity into memory.
    ///
    /// In OS-store mode the unlock password is read from the store (pass `None`); in fallback mode
    /// `passphrase` is required. Fails closed on any wrong passphrase / tampered blob.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::NotInitialized`] if nothing is sealed; [`KeystoreError::Unlock`] on a bad
    /// unlock; [`KeystoreError::PassphraseRequired`] in fallback mode with no passphrase.
    pub fn unlock(&self, passphrase: Option<&str>) -> Result<IdentitySecrets, KeystoreError> {
        let (blob, password) = self.load_blob_and_password(passphrase)?;
        let plaintext = opaque::open(&password, &blob).map_err(|_| KeystoreError::Unlock)?;
        IdentitySecrets::from_sealed_bytes(&plaintext)
    }

    /// Re-seal the identity under a fresh wrapping secret (a new random password in OS mode, or the
    /// supplied `new_passphrase` in fallback mode), atomically replacing the old sealed blob. The
    /// identity keys are unchanged; only the at-rest wrapping rotates, so the previous ciphertext
    /// is no longer openable afterward.
    ///
    /// # Errors
    ///
    /// Propagates unlock errors for `current_passphrase`, then the same errors as
    /// [`create`](Self::create) for the re-seal.
    pub fn rotate(
        &self,
        current_passphrase: Option<&str>,
        new_passphrase: Option<&str>,
    ) -> Result<UnlockSource, KeystoreError> {
        let secrets = self.unlock(current_passphrase)?;
        let plaintext = secrets.to_sealed_bytes();
        self.seal_and_store(&*plaintext, new_passphrase)
    }

    /// Permanently delete the sealed identity for this profile (profile removal). Idempotent.
    pub fn remove(&self) -> Result<(), KeystoreError> {
        match &self.credentials {
            Some(store) => store.delete(&self.account()),
            None => match std::fs::remove_file(self.sealed_file()) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
        }
    }

    // --- internals -------------------------------------------------------------------------------

    /// Seal `plaintext` and persist it via the active backend, returning the unlock source used.
    fn seal_and_store(
        &self,
        plaintext: &[u8],
        passphrase: Option<&str>,
    ) -> Result<UnlockSource, KeystoreError> {
        match &self.credentials {
            Some(store) => {
                let password_bytes = random_password();
                let blob = opaque::seal(&Password::new(&password_bytes[..]), plaintext, self.kdf)
                    .map_err(KeystoreError::Seal)?;
                let stored = StoredIdentity {
                    blob: BASE64.encode(&blob),
                    password: BASE64.encode(&password_bytes[..]),
                };
                // The serialized value carries the unlock password, so scrub it once written.
                let value = Zeroizing::new(
                    serde_json::to_string(&stored).expect("StoredIdentity always serializes"),
                );
                store.set(&self.account(), &value)?;
                Ok(UnlockSource::OsKeychain)
            }
            None => {
                let passphrase = passphrase.ok_or(KeystoreError::PassphraseRequired)?;
                let blob = opaque::seal(&Password::from(passphrase), plaintext, self.kdf)
                    .map_err(KeystoreError::Seal)?;
                self.write_sealed_file(&blob)?;
                Ok(UnlockSource::Passphrase)
            }
        }
    }

    /// Load the sealed blob and the [`Password`] that opens it for the active backend.
    fn load_blob_and_password(
        &self,
        passphrase: Option<&str>,
    ) -> Result<(Vec<u8>, Password), KeystoreError> {
        match &self.credentials {
            Some(store) => {
                let value = store
                    .get(&self.account())?
                    .ok_or(KeystoreError::NotInitialized)?;
                let stored: StoredIdentity =
                    serde_json::from_str(&value).map_err(|_| KeystoreError::MalformedSecret)?;
                let blob = BASE64
                    .decode(stored.blob.as_bytes())
                    .map_err(|_| KeystoreError::MalformedSecret)?;
                // The decoded unlock password is live secret material — hold it in a scrubbing
                // buffer so the base64-decoded copy never lingers in freed memory.
                let password_bytes = Zeroizing::new(
                    BASE64
                        .decode(stored.password.as_bytes())
                        .map_err(|_| KeystoreError::MalformedSecret)?,
                );
                Ok((blob, Password::new(&password_bytes[..])))
            }
            None => {
                let blob = match std::fs::read(self.sealed_file()) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(KeystoreError::NotInitialized)
                    }
                    Err(e) => return Err(e.into()),
                };
                let passphrase = passphrase.ok_or(KeystoreError::PassphraseRequired)?;
                Ok((blob, Password::from(passphrase)))
            }
        }
    }

    /// Write the sealed blob to the fallback file durably AND atomically: write a temp file in the
    /// same directory, fsync it, rename it over the final path, then fsync the parent directory. The
    /// rename gives atomicity (a reader never sees a half-written blob); the two fsyncs give
    /// durability — on Linux the sealed file is the custody PRIMARY, so the identity must survive a
    /// crash/power-loss immediately after `create`/`rotate`, not linger only in the page cache.
    fn write_sealed_file(&self, blob: &[u8]) -> Result<(), KeystoreError> {
        use std::io::Write;

        std::fs::create_dir_all(&self.profile_dir)?;
        let final_path = self.sealed_file();
        let temp_path = final_path.with_extension("digop1.tmp");

        // Write + flush + fsync the temp file so its bytes are on stable storage before the rename.
        let mut temp = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        temp.write_all(blob)?;
        temp.flush()?;
        temp.sync_all()?;
        drop(temp);

        std::fs::rename(&temp_path, &final_path)?;

        // fsync the parent directory so the rename (the directory entry) is itself durable. Only
        // meaningful (and only permitted) on Unix — Windows cannot open a directory handle for
        // fsync, and its rename metadata durability is handled by the filesystem.
        #[cfg(unix)]
        std::fs::File::open(&self.profile_dir)?.sync_all()?;
        Ok(())
    }

    fn sealed_file(&self) -> PathBuf {
        self.profile_dir.join(SEALED_IDENTITY_FILE)
    }

    /// The OS credential-store account name for this profile's identity entry.
    fn account(&self) -> String {
        Self::entry_account(&self.did_hash)
    }

    fn entry_account(did_hash: &str) -> String {
        format!("identity:{did_hash}")
    }
}

/// Generate a fresh high-entropy unlock password from the OS CSPRNG, in a scrubbing buffer so the
/// raw password bytes are erased from memory when the caller is done with them.
fn random_password() -> Zeroizing<[u8; UNLOCK_PASSWORD_BYTES]> {
    let mut bytes = Zeroizing::new([0u8; UNLOCK_PASSWORD_BYTES]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::verify_signature;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;

    /// An in-memory [`CredentialStore`] double so the OS-store path is exercised deterministically,
    /// without touching the host's real Credential Manager / Keychain / keyring.
    #[derive(Default)]
    struct MemoryCredentialStore {
        entries: Mutex<HashMap<String, String>>,
    }

    impl CredentialStore for MemoryCredentialStore {
        fn get(&self, account: &str) -> Result<Option<String>, KeystoreError> {
            Ok(self.entries.lock().unwrap().get(account).cloned())
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), KeystoreError> {
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_string(), secret.to_string());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), KeystoreError> {
            self.entries.lock().unwrap().remove(account);
            Ok(())
        }
    }

    fn os_vault(dir: &Path) -> ProfileVault {
        ProfileVault::with_backend(
            "did-os",
            dir,
            Some(Box::<MemoryCredentialStore>::default()),
            KdfParams::FAST_TEST,
        )
    }

    fn file_vault(dir: &Path) -> ProfileVault {
        ProfileVault::with_backend("did-file", dir, None, KdfParams::FAST_TEST)
    }

    #[test]
    fn os_mode_create_then_unlock_round_trips_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let vault = os_vault(dir.path());
        let secrets = IdentitySecrets::generate();
        let expected_pk = secrets.signing_public_key();

        assert!(!vault.is_initialized().unwrap());
        let source = vault.create(&secrets, None).unwrap();
        assert_eq!(source, UnlockSource::OsKeychain);
        assert!(vault.is_initialized().unwrap());

        let unlocked = vault.unlock(None).unwrap();
        assert_eq!(unlocked.signing_public_key(), expected_pk);
    }

    #[test]
    fn os_mode_writes_no_plaintext_key_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vault = os_vault(dir.path());
        vault.create(&IdentitySecrets::generate(), None).unwrap();
        // Nothing is written to the profile dir in OS mode — the blob lives in the credential store.
        assert!(!dir.path().join(SEALED_IDENTITY_FILE).exists());
    }

    #[test]
    fn file_mode_seals_ciphertext_never_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        let secrets = IdentitySecrets::generate();
        let raw_seed = secrets.to_sealed_bytes();

        vault
            .create(&secrets, Some("correct horse battery staple"))
            .unwrap();

        let on_disk = std::fs::read(dir.path().join(SEALED_IDENTITY_FILE)).unwrap();
        // The 64-byte plaintext key must NOT appear anywhere in the sealed file.
        assert!(!on_disk.windows(raw_seed.len()).any(|w| w == &raw_seed[..]));
    }

    #[test]
    fn file_mode_create_then_unlock_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        let secrets = IdentitySecrets::generate();
        let source = vault.create(&secrets, Some("pw")).unwrap();
        assert_eq!(source, UnlockSource::Passphrase);

        let unlocked = vault.unlock(Some("pw")).unwrap();
        let sig = unlocked.sign(b"m");
        assert!(verify_signature(&secrets.signing_public_key(), b"m", &sig));
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        vault
            .create(&IdentitySecrets::generate(), Some("right"))
            .unwrap();
        assert!(matches!(
            vault.unlock(Some("wrong")),
            Err(KeystoreError::Unlock)
        ));
    }

    #[test]
    fn file_mode_requires_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        assert!(matches!(
            vault.create(&IdentitySecrets::generate(), None),
            Err(KeystoreError::PassphraseRequired)
        ));
    }

    #[test]
    fn unlock_before_create_is_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            os_vault(dir.path()).unlock(None),
            Err(KeystoreError::NotInitialized)
        ));
        assert!(matches!(
            file_vault(dir.path()).unlock(Some("x")),
            Err(KeystoreError::NotInitialized)
        ));
    }

    #[test]
    fn rotation_invalidates_the_old_wrapping_in_file_mode() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();
        vault.create(&secrets, Some("old")).unwrap();

        vault.rotate(Some("old"), Some("new")).unwrap();

        // The old passphrase no longer opens the blob; the new one recovers the SAME identity.
        assert!(matches!(
            vault.unlock(Some("old")),
            Err(KeystoreError::Unlock)
        ));
        assert_eq!(vault.unlock(Some("new")).unwrap().signing_public_key(), pk);
    }

    #[test]
    fn rotation_in_os_mode_reseals_and_preserves_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let vault = os_vault(dir.path());
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();
        vault.create(&secrets, None).unwrap();

        vault.rotate(None, None).unwrap();
        assert_eq!(vault.unlock(None).unwrap().signing_public_key(), pk);
    }

    #[test]
    fn remove_deletes_the_sealed_identity_in_os_mode() {
        let dir = tempfile::tempdir().unwrap();
        let vault = os_vault(dir.path());
        vault.create(&IdentitySecrets::generate(), None).unwrap();
        vault.remove().unwrap();
        assert!(!vault.is_initialized().unwrap());
        // Removing again is a no-op.
        vault.remove().unwrap();
    }

    #[test]
    fn remove_deletes_the_sealed_identity_in_file_mode() {
        let dir = tempfile::tempdir().unwrap();
        let vault = file_vault(dir.path());
        vault
            .create(&IdentitySecrets::generate(), Some("p"))
            .unwrap();
        vault.remove().unwrap();
        assert!(!vault.is_initialized().unwrap());
        vault.remove().unwrap();
    }

    #[test]
    fn production_open_uses_the_real_backend_end_to_end() {
        // `ProfileVault::open` auto-detects the host backend. On a host WITH an OS credential store
        // (dev machines, CI runners) this exercises the real store; on a host without one it uses
        // the sealed file under `profile_dir`. Either way, create → unlock must round-trip. The
        // unique did_hash + `remove()` guarantee no leftover state in a real credential store.
        let dir = tempfile::tempdir().unwrap();
        let did_hash = format!("prodtest-{}", std::process::id());
        let vault = ProfileVault::open(did_hash, dir.path());
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();

        // In file-fallback mode a passphrase is required; in OS mode it is ignored. Supplying one
        // is correct for both, so this test is host-agnostic.
        let source = match vault.create(&secrets, Some("prod-pass")) {
            Ok(s) => s,
            Err(e) => panic!("create failed: {e}"),
        };
        let unlocked = match source {
            UnlockSource::OsKeychain => vault.unlock(None).unwrap(),
            UnlockSource::Passphrase => vault.unlock(Some("prod-pass")).unwrap(),
        };
        assert_eq!(unlocked.signing_public_key(), pk);
        vault.remove().unwrap();
    }

    #[test]
    fn identity_recovers_from_the_durable_file_after_a_simulated_store_loss() {
        // F1 regression (custody durability): the file-primary path seals the identity into a
        // DURABLE file, so it survives a process restart / a volatile keyring losing its entries on
        // reboot. The key stays RECOVERABLE — this is why Linux uses the file, not keyutils, as its
        // custody primary.
        let dir = tempfile::tempdir().unwrap();
        let secrets = IdentitySecrets::generate();
        let pk = secrets.signing_public_key();

        // Seal via one vault instance, then drop it — modelling shutdown / a keyring that would have
        // dropped its volatile entries on reboot.
        file_vault(dir.path()).create(&secrets, Some("pw")).unwrap();
        assert!(dir.path().join(SEALED_IDENTITY_FILE).exists());

        // A brand-new vault over the SAME directory (a fresh boot) still finds and opens the file
        // with the passphrase, recovering the identical identity.
        let recovered = file_vault(dir.path()).unlock(Some("pw")).unwrap();
        assert_eq!(recovered.signing_public_key(), pk);
    }

    /// On Linux (and any non-Windows/macOS target) the vault MUST use the passphrase-sealed file as
    /// its custody primary — never the kernel keyutils session keyring, which is same-UID-readable
    /// and non-persistent. These tests assert `ProfileVault::open` resolves to the file backend on
    /// such a host, so an unprivileged same-UID process has no OS-store entry to read AND the
    /// identity survives a reboot.
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    mod linux_uses_file_primary {
        use super::*;

        #[test]
        fn open_resolves_to_the_file_backend_requiring_a_passphrase() {
            let dir = tempfile::tempdir().unwrap();
            let vault = ProfileVault::open("did-linux", dir.path());
            // No OS store is consulted, so create with no passphrase fails-closed on the file path
            // rather than silently sealing into a same-UID-readable keyring.
            assert!(matches!(
                vault.create(&IdentitySecrets::generate(), None),
                Err(KeystoreError::PassphraseRequired)
            ));
        }

        #[test]
        fn open_seals_to_a_durable_file_that_survives_a_reboot() {
            let dir = tempfile::tempdir().unwrap();
            let secrets = IdentitySecrets::generate();
            let pk = secrets.signing_public_key();

            let source = ProfileVault::open("did-linux", dir.path())
                .create(&secrets, Some("pw"))
                .unwrap();
            assert_eq!(source, UnlockSource::Passphrase);
            // The identity is a durable on-disk file — no dependency on a volatile keyring.
            assert!(dir.path().join(SEALED_IDENTITY_FILE).exists());

            // A fresh `open` (a reboot) recovers the identity from that file.
            let recovered = ProfileVault::open("did-linux", dir.path())
                .unlock(Some("pw"))
                .unwrap();
            assert_eq!(recovered.signing_public_key(), pk);
        }
    }

    #[test]
    fn a_corrupt_os_entry_is_malformed_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let store = Box::<MemoryCredentialStore>::default();
        store.set("identity:did-os", "not json").unwrap();
        let vault =
            ProfileVault::with_backend("did-os", dir.path(), Some(store), KdfParams::FAST_TEST);
        assert!(matches!(
            vault.unlock(None),
            Err(KeystoreError::MalformedSecret)
        ));
    }
}
