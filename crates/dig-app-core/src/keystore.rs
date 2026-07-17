//! Key management — hold / unlock / **sign with** the DIG identity + wallet keys (U4).
//!
//! *This module is a U1 skeleton; U4 (SECURITY-CRITICAL) implements it to `SPEC.md` under the dual
//! review + loop-security gate.*
//!
//! dig-app is the sole holder of the user's private keys. Keys are sealed at rest with dig-keystore
//! DIGOP1 (AES-256-GCM + Argon2id) — never hand-rolled — under a three-level hierarchy rooted at
//! the user's key:
//!
//! 1. **Bootstrap unlock** — a DIGOP1 password in the OS keychain (Windows DPAPI / macOS Keychain /
//!    Linux Secret Service), released by the login session; passphrase-prompt fallback. Opens the
//!    active profile's sealed identity blob.
//! 2. **Root** — the unlocked profile identity key.
//! 3. **DEK** — HKDF-derived from the identity, seals every other per-profile blob. Per-profile;
//!    profiles never share a DEK.
//!
//! Signing happens IN this process: dig-app builds a payload, signs with the in-memory unlocked
//! key, and hands finished bytes to the engine — the private key never crosses the IPC boundary.
//! Identity rotation re-derives the DEK and re-seals all of that profile's blobs in one transaction.

/// How a profile's bootstrap secret is unlocked. U4 wires each backend to dig-keystore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockSource {
    /// The OS keychain (Windows DPAPI / macOS Keychain / Linux Secret Service), released by the
    /// login session — the default, zero-prompt path.
    OsKeychain,
    /// A passphrase prompt — the fallback when the keychain is unavailable or declined.
    Passphrase,
}
