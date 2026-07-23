//! The OS credential-store seam — the zero-prompt source of the master-HD account's unlock password
//! (security-critical).
//!
//! dig-app is the sole holder of the user's private keys (§2 of `SPEC.md`); the identity-agnostic
//! engine never sees them. The at-rest crypto (DIGOP1 sealing, KDF, key generation, the master-HD
//! signers) lives in the **`dig-account`** custody crate, consumed through the
//! [`AccountResidency`](crate::account::residency::AccountResidency). This module owns only the piece
//! that is inherently app-side: the [`CredentialStore`] seam over the platform credential store.
//!
//! The credential store is a safe custody primary only where it gates access per-application, so its
//! use is PLATFORM-DEPENDENT:
//!
//! - **Windows / macOS — the OS credential store is the custody primary** (Windows Credential Manager
//!   · macOS Keychain). It holds the account's random unlock password; the login session releases it
//!   with zero prompt, and the store gates access per-application. [`OsCredentialStore`] is the entry
//!   point; the master seed itself is sealed (DIGOP1) in a per-user file backend under that password.
//! - **Linux — deferred.** The kernel keyutils session keyring is readable by any same-UID process
//!   (no per-app ACL) and non-persistent, so there is no zero-prompt custody primary; the account boot
//!   defers there ([`boot_residency`](crate::account::boot::boot_residency)) until a passphrase UX
//!   lands.

mod credential;

pub use credential::CredentialStore;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use credential::{OsCredentialStore, CREDENTIAL_SERVICE};

/// Errors from the credential-store seam. Wrapped into [`crate::Error::Keystore`].
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The OS credential store backend returned an error (distinct from "no entry", which is not
    /// an error).
    #[error("OS credential store error: {0}")]
    CredentialStore(String),
}
