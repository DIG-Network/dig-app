//! Key management — hold / unlock / **sign with** the DIG identity keys (U4, security-critical).
//!
//! dig-app is the sole holder of the user's private keys (§2 of `SPEC.md`); the identity-agnostic
//! engine never sees them. This module implements the three-level key hierarchy of `SPEC.md` §3,
//! rooted at the user's identity key:
//!
//! 1. **Bootstrap unlock** — the DIGOP1 password that opens a profile's sealed identity blob. On
//!    Windows/macOS its primary home is the OS credential store ([`OsCredentialStore`]); on Linux,
//!    and as the fallback anywhere the OS store is unavailable, it is a user passphrase.
//! 2. **Root** — the unlocked profile identity ([`IdentitySecrets`]): the Ed25519 signing key
//!    (slot `0x0010`) and the X25519 encryption key (slot `0x0011`).
//! 3. **Per-profile DEK** — HKDF-derived from the identity, sealing every OTHER per-profile blob
//!    (wallet, subscriptions, prefs) via [`IdentitySecrets::seal_data`]. Profiles never share a DEK.
//!
//! At-rest sealing always goes through the audited **dig-keystore `opaque`** module (DIGOP1 =
//! AES-256-GCM + Argon2id) — the crate hand-rolls no cipher, KDF, or key generation. The private
//! key never touches disk in the clear and never crosses the IPC boundary to the engine.
//!
//! The at-rest storage precedence (the U4 directive) is PLATFORM-DEPENDENT, because a credential
//! store is only a safe custody primary where it gates access per-application:
//!
//! - **Windows / macOS — the OS credential store is primary** (Windows Credential Manager · macOS
//!   Keychain). The sealed blob AND its random unlock password live there; the login session
//!   releases them with zero prompt, the store gates access per-application, and the stored blob is
//!   itself DIGOP1 ciphertext. Fallback is the passphrase-sealed file if the store is unavailable.
//! - **Linux — the passphrase-sealed file is primary.** The kernel keyutils session keyring is NOT
//!   used: it is readable by any same-UID process (no per-app ACL ⇒ same-UID key theft) and is
//!   non-persistent across reboot/logout (identity data-loss). Instead the sealed blob is a
//!   DIGOP1 file in the profile's home-ACL'd AppData directory, unlocked by a user passphrase
//!   (Argon2id) that is never persisted — persistent, home-ACL'd, and not harvestable by a
//!   background same-UID process.
//!
//! Either way the private key is never plaintext at rest. [`ProfileVault`] is the entry point.

mod credential;
mod secrets;
mod vault;

pub use credential::CredentialStore;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use credential::{OsCredentialStore, CREDENTIAL_SERVICE};
pub use secrets::{verify_signature, IdentitySecrets, SEALED_SECRET_LEN, SIGNATURE_LEN};
pub use vault::ProfileVault;

/// How a profile's bootstrap secret is unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockSource {
    /// The OS credential store (Windows Credential Manager / macOS Keychain), released by the login
    /// session — the default, zero-prompt path on those platforms. The sealed blob and its random
    /// unlock password both live in the store.
    OsKeychain,
    /// A user passphrase — the primary on Linux (keyutils is not a safe custody store) and the
    /// fallback anywhere the OS credential store is unavailable. The sealed blob lives as a file in
    /// the profile's AppData directory; the passphrase is never stored.
    Passphrase,
}

/// Errors from the key-management subsystem. Wrapped into [`crate::Error::Keystore`].
///
/// The unlock-failure variants ([`KeystoreError::Unlock`], [`KeystoreError::DataUnlock`]) are
/// deliberately opaque: they never reveal whether a wrong passphrase or a corrupt/foreign
/// ciphertext caused the failure, so an attacker learns nothing from the error.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Unlock failed — a wrong passphrase, a tampered blob, or a foreign key. Fail-closed: no
    /// plaintext is produced and the cause is not distinguished.
    #[error("unlock failed")]
    Unlock,

    /// Opening a per-profile data blob failed (wrong DEK / tampered / foreign profile). Fail-closed.
    #[error("could not open sealed profile data")]
    DataUnlock,

    /// No profile identity is sealed yet for this vault — create one before unlocking.
    #[error("no sealed identity exists for this profile")]
    NotInitialized,

    /// The passphrase fallback path was taken but no passphrase was supplied. (The OS-credential
    /// path needs none; only the file fallback requires a passphrase.)
    #[error("a passphrase is required when no OS credential store is available")]
    PassphraseRequired,

    /// A sealed blob opened successfully but did not contain a well-formed identity — an
    /// incompatible on-disk version, not tampering (tampering fails the AEAD tag first).
    #[error("sealed identity has an unexpected layout")]
    MalformedSecret,

    /// The OS credential store backend returned an error (distinct from "no entry", which is not
    /// an error).
    #[error("OS credential store error: {0}")]
    CredentialStore(String),

    /// A DIGOP1 seal operation failed (an allocation/parameter error from dig-keystore).
    #[error("sealing failed: {0}")]
    Seal(dig_keystore::KeystoreError),

    /// An I/O error reading or writing the sealed-file fallback.
    #[error("sealed-file I/O error: {0}")]
    Io(#[from] std::io::Error),
}
