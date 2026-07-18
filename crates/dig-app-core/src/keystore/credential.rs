//! The OS credential store abstraction — the PRIMARY home for a profile's at-rest key material on
//! the platforms whose credential store gates access PER-APPLICATION.
//!
//! Per the U4 directive, on **Windows (Credential Manager)** and **macOS (Keychain)** the sealed
//! identity blob and its DIGOP1 unlock password live TOGETHER in one OS credential-store entry when
//! one is available. The security of this path rests on the OS store's **per-application access
//! ACL** (scoped to the logged-in user, released by the login session) — that ACL is what keeps
//! another process from reading the entry. The DIGOP1 sealing is defense-in-depth UNDER that ACL,
//! NOT a second independent secret: because the unlock password rides in the same entry as the
//! ciphertext, an attacker who defeats the ACL and dumps the entry obtains BOTH and can open the
//! blob. (Splitting the password away from the ciphertext is a separate follow-up hardening; see
//! `SPEC.md` §7.) So the honest guarantee here is "the OS ACL gates access; DIGOP1 adds a layer
//! against a raw at-rest artifact but not against a full-entry dump."
//!
//! **Linux is deliberately excluded.** The kernel keyutils session keyring is readable by ANY
//! same-UID process in the session (it has no per-application ACL) and is non-persistent across
//! reboot/logout — so it is unsafe as a custody primary (same-UID key theft) and would lose the
//! identity on logout. On Linux the vault therefore uses the passphrase-sealed file as its primary
//! (home-directory-ACL'd, persistent, and — needing a user passphrase — not harvestable by a
//! same-UID background process). Accordingly [`OsCredentialStore`] and the `keyring` dependency are
//! compiled only on Windows/macOS.
//!
//! Everything here is expressed against the small [`CredentialStore`] trait so the key-management
//! logic is testable without touching the real OS store, and so the file-fallback path can be
//! exercised deterministically by presenting no backend (`None`) to the vault.

use super::KeystoreError;

/// A named-secret store keyed by `(service, account)` string pairs. The real implementation is
/// [`OsCredentialStore`]; the vault's tests use an in-memory double.
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
