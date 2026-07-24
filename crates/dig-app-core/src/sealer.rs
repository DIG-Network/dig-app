//! The per-profile sealing seam — the boundary between the app's at-rest persistence and the custody
//! crypto that supplies each profile's data-encryption key.
//!
//! # Why a trait
//!
//! The persistence layers (pairings, whitelist, wallet state) own *which* bytes are sealed and *where*
//! they live on disk; they MUST NOT own the crypto. Sealing is dig-keystore **DIGOP1** (AES-256-GCM +
//! Argon2id/HKDF) under a **per-profile DEK** derived from the master-HD account
//! ([`AccountResidency`](crate::account::residency::AccountResidency), SPEC §3.1). So the persistence
//! layers depend on this narrow trait rather than on a concrete cipher, keeping the crypto in exactly
//! one place.
//!
//! # The per-profile-key contract (security-critical)
//!
//! A [`ProfileSealer`] is addressed by a profile DID. The implementation MUST seal and open using
//! **only** the DEK of the named profile, and profiles MUST NOT share a DEK (SPEC §3.1). Two
//! consequences the persistence layers rely on:
//!
//! - **At-rest ciphertext** — [`ProfileSealer::seal`] returns AEAD ciphertext, never plaintext, so a
//!   sealed blob on disk reveals nothing.
//! - **Cross-profile isolation** — opening profile A's ciphertext under profile B's DID MUST fail
//!   (AEAD authentication rejects the wrong key), so one profile can never read another's data.
//! - **Zeroized plaintext** — [`ProfileSealer::open`] returns the decrypted bytes in a
//!   [`Zeroizing`] buffer, so decrypted secret-bearing content is scrubbed from memory on drop.
//!
//! # The production implementation
//!
//! The production implementation is the live-view
//! [`ResidencySealer`](crate::account::residency::ResidencySealer): it derives the named profile's DEK
//! from the unlocked master-HD account on every call and DIGOP1-seals through the
//! [`AccountSealer`](crate::account::sealer::AccountSealer), failing closed the instant the account is
//! locked. Every persistence store is generic over any `ProfileSealer`, so the seam stays testable in
//! isolation.

use zeroize::Zeroizing;

/// A failure sealing or unsealing a per-profile blob.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The plaintext could not be sealed (e.g. the account is locked).
    #[error("could not seal profile data: {0}")]
    Seal(String),

    /// The ciphertext could not be opened: a corrupt blob, or — the security-relevant case — an
    /// attempt to open it under a profile whose DEK did not seal it (AEAD authentication failed).
    #[error("could not open sealed profile data: wrong key or corrupt ciphertext")]
    Open,
}

/// Seals and opens a profile's secret-bearing blobs under that profile's own data-encryption key.
///
/// Implementations are addressed by the profile's `did:chia:` DID; see the module docs for the
/// per-profile-key contract every implementation MUST honour.
pub trait ProfileSealer {
    /// Seals `plaintext` under the DEK of the profile named by `profile_did`, returning AEAD
    /// ciphertext safe to persist at rest.
    fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError>;

    /// Opens `ciphertext` that was sealed under the DEK of the profile named by `profile_did`,
    /// returning the plaintext in a [`Zeroizing`] buffer so it is scrubbed from memory on drop.
    ///
    /// Returns [`SealError::Open`] when `ciphertext` was not sealed by this profile's DEK — the
    /// mechanism that keeps one profile from reading another's data.
    fn open(&self, profile_did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError>;
}
