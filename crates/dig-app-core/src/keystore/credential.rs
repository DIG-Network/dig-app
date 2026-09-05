//! The OS credential-store abstraction — a LEGACY, migration-only seam (Windows Credential Manager ·
//! macOS Keychain), no longer a custody primary.
//!
//! # What actually protects custody today
//!
//! The shipped custody root is NOT this store. The account master seed is sealed (DIGOP1 / Argon2id)
//! in a per-user [`FileBackend`](dig_session::FileBackend), and the password that opens it comes from
//! the **user's head** — collected at unlock by the production
//! [`PromptedCeremony`](crate::account::ceremony::PromptedCeremony) in the app's own native masked
//! window (dig_ecosystem#1817, wired live in [`account::boot`](crate::account::boot)). The password is
//! never persisted — not on disk, not in this credential store, not in a log — so the honest guarantee
//! is strong: an attacker who dumps the sealed seed file obtains only Argon2id-hardened ciphertext, and
//! one who dumps this credential store obtains no seed. The two are separated because neither the
//! password nor the ciphertext lives beside the other.
//!
//! # Why this seam still exists (migration only)
//!
//! Accounts created BEFORE #1817 were sealed under a password the machine generated and kept in this
//! credential store — a zero-prompt model whose defect is precisely that any code running as the
//! logged-in user could read the password, so no user-known secret protected custody. That model is
//! RETIRED: no boot, unlock, or sign path sources a password from here any more. This seam survives
//! solely so [`migration`](crate::account::migration) can open such an account with the old machine
//! password ONCE and re-seal the SAME seed under a password the user chooses — never deleting a seed —
//! and so [`discard_account`](crate::account::boot::discard_account) can clean up a leftover entry. The
//! per-application access ACL (scoped to the logged-in user, released by the login session) is what
//! gated the old machine password; it was never a substitute for a user-known secret, which is the gap
//! #1817 closed.
//!
//! **Linux never used this store.** The kernel keyutils session keyring is readable by ANY same-UID
//! process (no per-application ACL) and is non-persistent across reboot/logout, so it was never a safe
//! custody primary. Accordingly `OsCredentialStore` and the `keyring` dependency are compiled only on
//! Windows/macOS; Linux's account boot defers until its passphrase unlock UX lands (dig_ecosystem#962).
//!
//! Everything here is expressed against the small [`CredentialStore`] trait so the migration logic is
//! testable without touching the real OS store, using an in-memory double.
//!
//! # Why this is NOT centralized onto `dig_keystore::OsKeychainBackend` (dig-app#253)
//!
//! It looks like a rival implementation of that backend, and the rival-implementation sweep
//! (dig_ecosystem#3140) will keep noticing that it looks like one. It is not, and the two reasons are
//! recorded here so the question is answered by reading rather than by re-deriving it:
//!
//! 1. **The crate FORBIDS this content.** `OsKeychainBackend`'s caller obligation (dig-keystore
//!    `SPEC.md` §10.5) is that callers "MUST NOT write an unlock password, passphrase, mnemonic, raw
//!    seed, or any other plaintext secret to this backend — only blobs this crate has already sealed."
//!    The single value this seam holds is a plaintext machine-generated UNLOCK PASSWORD. Storing it
//!    there is the one thing that backend tells its callers not to do, so "retire this onto
//!    `OsKeychainBackend`" is not a cheaper shape — it is a contract violation.
//!
//! 2. **The value shapes are not byte-compatible ON WINDOWS, and fail silently.** This seam writes
//!    with `keyring`'s STRING api (`set_password`/`get_password`); `OsKeychainBackend` is a byte-blob
//!    KV that writes with `set_secret`/`get_secret`. On macOS those coincide — `set_password` stores
//!    `password.as_bytes()`, so a legacy entry reads back identically and a macOS-only test would
//!    PASS. On Windows they do not: `keyring` converts the string to UTF-16LE before storing
//!    (`windows.rs`, "Password strings are converted to UTF-16"), so `get_secret` on a legacy entry
//!    returns twice the bytes, NUL-interleaved. [`migration::reseal_under`] would then hand
//!    `Password::new` the wrong bytes, the account would not open, and the user would be told the
//!    migration failed on an account that is perfectly intact — permanently, since
//!    `is_sealed_under_machine_password` would keep reporting it as needing one. A dead end that
//!    presents as a broken account is the worst available outcome for the one path this seam exists
//!    to serve.
//!
//! The encoding half of that is pinned by the `legacy_entries_are_string_encoded_not_byte_blobs`
//! test below, so the swap cannot be made quietly on a macOS or Linux runner.
//!
//! **The terminal end state is still DELETION, not adoption** — this seam goes when the pre-#1817
//! migration window closes at the §3.7 launch revisit, together with the direct `keyring` dependency.
//! Until then a live account may still be sealed under a machine password, and the migration is
//! user-triggered, so no app update can close the window on the user's behalf.
//!
//! [`migration::reseal_under`]: crate::account::migration::reseal_under
//! [`is_sealed_under_machine_password`]: crate::account::migration::is_sealed_under_machine_password

use super::KeystoreError;

/// A named-secret store keyed by `(service, account)` string pairs. The real implementation is
/// `OsCredentialStore` (a Windows/macOS-only type); the vault's tests use an in-memory double.
///
/// Values are opaque byte strings (the vault stores base64 of DIGOP1 ciphertext / the unlock
/// password), so this trait deliberately knows nothing about DIG key formats.
pub trait CredentialStore {
    /// Fetch the secret stored under `account`, or `None` if no entry exists. An entry that exists
    /// but cannot be read (a backend error) is a [`KeystoreError::CredentialStore`], distinct from
    /// "absent".
    fn get(&self, account: &str) -> Result<Option<String>, KeystoreError>;

    /// Store `secret` under `account`, overwriting any existing entry.
    fn set(&self, account: &str, secret: &str) -> Result<(), KeystoreError>;

    /// Delete the entry under `account`. Deleting an absent entry is a no-op (idempotent), so
    /// rotation and profile removal need not special-case a missing entry.
    fn delete(&self, account: &str) -> Result<(), KeystoreError>;
}

/// The service name every DIG user-app credential-store entry is filed under (the credential
/// store's namespace for this application). Never drift this literal — it is how the app finds its
/// own entries across restarts.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub const CREDENTIAL_SERVICE: &str = "dig-app";

/// The real OS credential store on Windows/macOS, backed by the [`keyring`] crate.
///
/// On construction it probes the platform backend with a throwaway lookup; if the backend is
/// unavailable (a locked keychain, an unreachable Credential Manager), construction returns `None`.
/// This keeps "is the OS store usable?" a single decision made once, rather than a failure surfacing
/// mid-unlock. (Compiled only on Windows/macOS — Linux never uses an OS credential store; see the
/// module docs.)
///
/// **`None` means the two migration-only callers do nothing, and nothing else changes.** Earlier
/// versions of this doc said the caller "falls back to the sealed-file path". There is no such
/// fallback and there never was one: the sentence described the pre-#1817 world, where this store WAS
/// the custody primary and a missing backend would have needed one. Today the password comes from the
/// user's head, so a `None` here costs a leftover credential entry at discard and a skipped migration
/// check, nothing more.
///
/// The phantom cost real investigation time on dig_ecosystem#2128, where it read as a live code path
/// that might be silently persisting a key somewhere else — and the first attempt to remove it fixed
/// only the copies in this file while `SPEC.md`'s module table still called this store the custody
/// PRIMARY. That was the copy doing the damage, because §4.2 makes `SPEC.md` the authoritative
/// contract: a reader who checks the spec to resolve a doubtful comment must not find the doubtful
/// comment restated as normative. Both are corrected; if this claim is ever revisited, search the
/// SPEC and the docs, not only the source.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub struct OsCredentialStore {
    service: String,
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl OsCredentialStore {
    /// Open the OS credential store, or return `None` if this host has no usable backend. The
    /// `probe_account` is looked up only to detect backend availability; its presence or absence is
    /// irrelevant.
    pub fn open(probe_account: &str) -> Option<Self> {
        let store = Self {
            service: CREDENTIAL_SERVICE.to_string(),
        };
        // A `NoEntry` result proves the backend is reachable and simply has no such entry; only a
        // hard backend error means "no usable store here".
        match store
            .entry(probe_account)
            .and_then(|e| match e.get_password() {
                Ok(_) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e),
            }) {
            Ok(()) => Some(store),
            Err(_) => None,
        }
    }

    fn entry(&self, account: &str) -> keyring::Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account)
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl CredentialStore for OsCredentialStore {
    fn get(&self, account: &str) -> Result<Option<String>, KeystoreError> {
        match self.entry(account).and_then(|e| e.get_password()) {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeystoreError::CredentialStore(e.to_string())),
        }
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), KeystoreError> {
        self.entry(account)
            .and_then(|e| e.set_password(secret))
            .map_err(|e| KeystoreError::CredentialStore(e.to_string()))
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        match self.entry(account).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeystoreError::CredentialStore(e.to_string())),
        }
    }
}

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod tests {
    use super::*;

    /// Exercise the REAL OS credential store end-to-end where a backend exists (Windows Credential
    /// Manager · macOS Keychain). Self-skips on a host with no usable backend so it is never flaky —
    /// a host without one simply has no migration to run and no entry to clean up.
    /// The entry is namespaced and always cleaned up so it cannot pollute a developer's real store.
    #[test]
    fn os_store_set_get_delete_round_trips_where_available() {
        let account = format!("dig-app-test:{}", std::process::id());
        let Some(store) = OsCredentialStore::open(&account) else {
            eprintln!(
                "no OS credential store on this host — skipping (nothing here is load-bearing)"
            );
            return;
        };

        // Absent entry reads as None, not an error.
        assert_eq!(store.get(&account).unwrap(), None);

        store.set(&account, "sealed-value-v1").unwrap();
        assert_eq!(
            store.get(&account).unwrap().as_deref(),
            Some("sealed-value-v1")
        );

        // Overwrite replaces the value.
        store.set(&account, "sealed-value-v2").unwrap();
        assert_eq!(
            store.get(&account).unwrap().as_deref(),
            Some("sealed-value-v2")
        );

        store.delete(&account).unwrap();
        assert_eq!(store.get(&account).unwrap(), None);
        // Deleting an absent entry is a no-op.
        store.delete(&account).unwrap();
    }

    /// **Proves:** a legacy entry this seam wrote is STRING-encoded, and on Windows its raw
    /// credential blob is NOT the bytes that were stored -- so a byte-blob reader cannot recover the
    /// value.
    ///
    /// **Why it matters:** dig-app#253 proposes retiring this seam onto
    /// `dig_keystore::OsKeychainBackend`. That backend is a byte-blob KV: it writes with
    /// `keyring`'s `set_secret` and reads with `get_secret`, while this seam uses
    /// `set_password`/`get_password`. On macOS the two coincide -- `set_password` stores
    /// `password.as_bytes()` -- so the swap would look correct on a macOS runner and on any
    /// review that only read the macOS path. On Windows `keyring` converts the string to UTF-16LE
    /// before storing it (`windows.rs`, "Password strings are converted to UTF-16"), so `get_secret`
    /// returns twice the bytes, NUL-interleaved.
    ///
    /// A swap made on that false equivalence would hand
    /// [`reseal_under`](crate::account::migration::reseal_under) the wrong password bytes on every
    /// Windows host. The account would refuse to open, the user would be told the migration failed
    /// on an account that is perfectly intact, and
    /// [`is_sealed_under_machine_password`](crate::account::migration::is_sealed_under_machine_password)
    /// would keep reporting it as still needing one -- a permanent dead end presenting as a broken
    /// account.
    ///
    /// Self-skips where no backend exists, exactly like the round-trip test above.
    #[test]
    fn legacy_entries_are_string_encoded_not_byte_blobs() {
        let account = format!("dig-app-encoding-test:{}", std::process::id());
        let Some(store) = OsCredentialStore::open(&account) else {
            eprintln!("no OS credential store on this host - skipping");
            return;
        };

        // A 64-char hex string is the exact shape the retired ceremony generated.
        let value = "0123456789abcdef".repeat(4);
        store.set(&account, &value).unwrap();

        let raw = keyring::Entry::new(CREDENTIAL_SERVICE, &account)
            .and_then(|e| e.get_secret())
            .expect("the entry was just written, so its raw blob must be readable");

        store.delete(&account).unwrap();

        if cfg!(target_os = "windows") {
            assert_ne!(
                raw,
                value.as_bytes(),
                "a byte-blob read of a legacy entry must not return the stored string"
            );
            assert_eq!(
                raw.len(),
                value.len() * 2,
                "Windows stores the string as UTF-16LE, so the blob is exactly twice as long"
            );
        } else {
            assert_eq!(
                raw,
                value.as_bytes(),
                "on macOS the bytes coincide, which is why a macOS-only test cannot justify the swap"
            );
        }
    }
}
