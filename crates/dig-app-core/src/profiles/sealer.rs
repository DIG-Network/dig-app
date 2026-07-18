//! The per-profile sealing seam — the boundary between profile management (U5) and key management
//! (U4, [`crate::keystore`]).
//!
//! # Why a trait
//!
//! U5 owns *which* bytes are sealed and *where* they live on disk; it MUST NOT own the crypto.
//! Sealing is dig-keystore **DIGOP1** (AES-256-GCM + Argon2id/HKDF) under a **per-profile DEK**
//! derived from that profile's unlocked identity key (`DEK = HKDF(identity key)`, SPEC §3.1) — and
//! that derivation lives in U4. So U5 depends on this narrow trait rather than on a concrete cipher,
//! keeping the crypto in exactly one place and letting the two work units land independently.
//!
//! # The per-profile-key contract (security-critical)
//!
//! A [`ProfileSealer`] is addressed by a profile DID. The implementation MUST seal and open using
//! **only** the DEK of the named profile, and profiles MUST NOT share a DEK (SPEC §3.1). Two
//! consequences the profile layer relies on:
//!
//! - **At-rest ciphertext** — [`ProfileSealer::seal`] returns AEAD ciphertext, never plaintext, so a
//!   sealed blob on disk reveals nothing (§10, test 2).
//! - **Cross-profile isolation** — opening profile A's ciphertext under profile B's DID MUST fail
//!   (AEAD authentication rejects the wrong key), so one profile can never read another's data
//!   (§10, test 3).
//! - **Zeroized plaintext** — [`ProfileSealer::open`] returns the decrypted bytes in a
//!   [`Zeroizing`] buffer (the F-3 property), so a profile's decrypted secret-bearing content is
//!   scrubbed from memory when the caller drops it rather than lingering in freed heap.
//!
//! # U4 integration point
//!
//! The production implementation is [`KeystoreSealer`](super::keystore_sealer::KeystoreSealer): it
//! resolves the named profile's unlocked U4 [`IdentitySecrets`](crate::keystore::IdentitySecrets) and
//! DIGOP1-seals under that identity's DEK, so `seal(did, pt)` seals `pt` for exactly that profile.
//! The profile manager is generic over any `ProfileSealer`, so the seam stays testable in isolation.

use zeroize::Zeroizing;

/// A failure sealing or unsealing a per-profile blob.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The plaintext could not be sealed (e.g. the profile's key is not unlocked).
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
