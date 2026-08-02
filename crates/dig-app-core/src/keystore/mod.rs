//! The OS credential-store seam — a LEGACY, migration-only credential abstraction (security-critical).
//!
//! dig-app is the sole holder of the user's private keys (§2 of `SPEC.md`); the identity-agnostic
//! engine never sees them. The at-rest crypto (DIGOP1 sealing, KDF, key generation, the master-HD
//! signers) lives in the **`dig-account`** custody crate, consumed through the
//! [`AccountResidency`](crate::account::residency::AccountResidency). This module owns only the piece
//! that is inherently app-side: the [`CredentialStore`] seam over the platform credential store.
//!
//! **This store is no longer a custody primary.** The shipped custody root is a master seed sealed
//! (DIGOP1 / Argon2id) in a per-user file backend, opened by a password the USER types at unlock —
//! never persisted anywhere (dig_ecosystem#1817). The credential store held a machine-generated
//! password under the earlier zero-prompt model, which is retired precisely because any code running
//! as the logged-in user could read it. `OsCredentialStore` (Windows Credential Manager · macOS
//! Keychain) is now reached only to MIGRATE a pre-#1817 account off that machine password
//! ([`migration`](crate::account::migration)) and to clean up a leftover entry on discard; see the
//! `credential` module docs for the full posture. Linux never used it and its account boot defers
//! until a passphrase unlock UX lands (dig_ecosystem#962).

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
