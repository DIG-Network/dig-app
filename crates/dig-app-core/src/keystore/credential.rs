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
/// unavailable (a locked keychain, an unreachable Credential Manager), construction returns `None`
/// so the caller falls back to the sealed-file path. This keeps "is the OS store usable?" a single
/// decision made once, rather than a failure surfacing mid-unlock. (Compiled only on Windows/macOS
/// — Linux never uses an OS credential store; see the module docs.)
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub struct OsCredentialStore {
    service: String,
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl OsCredentialStore {
    /// Open the OS credential store, or return `None` if this host has no usable backend (⇒ the
    /// caller uses the sealed-file fallback). The `probe_account` is looked up only to detect
    /// backend availability; its presence or absence is irrelevant.
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
    /// Manager · macOS Keychain). Self-skips on a host with no usable backend so
    /// it is never flaky — the sealed-file fallback is what covers that case (see `vault::tests`).
    /// The entry is namespaced and always cleaned up so it cannot pollute a developer's real store.
    #[test]
    fn os_store_set_get_delete_round_trips_where_available() {
        let account = format!("dig-app-test:{}", std::process::id());
        let Some(store) = OsCredentialStore::open(&account) else {
            eprintln!("no OS credential store on this host — skipping (fallback path covers it)");
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
}
