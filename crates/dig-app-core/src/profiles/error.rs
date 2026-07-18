//! Errors surfaced by profile management.
//!
//! Profile errors are their own type so the module stays self-contained; the crate-level
//! [`crate::Error`] wraps them via `#[from]` so a caller can handle profile failures alongside the
//! rest of the agent's I/O.

use crate::profiles::sealer::SealError;

/// A failure creating, selecting, listing, or editing a profile.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// No profile with the given DID exists in the registry.
    #[error("no profile found for DID {0}")]
    NotFound(String),

    /// A profile with the given DID already exists — creation must not clobber it.
    #[error("a profile already exists for DID {0}")]
    AlreadyExists(String),

    /// The provisioner returned a DID that is not a canonical `did:chia:` identifier, so it cannot
    /// be trusted as an identity anchor.
    #[error("provisioned identity is not a canonical did:chia DID: {0}")]
    InvalidDid(String),

    /// Provisioning a new identity (mint the DID + generate its keys) failed.
    #[error("could not provision a new identity: {0}")]
    Provision(String),

    /// Sealing or unsealing a per-profile blob failed. An unseal failure for a blob written by a
    /// *different* profile's key is the expected cross-profile isolation signal (§10, test 3).
    #[error(transparent)]
    Seal(#[from] SealError),

    /// Reading or writing the on-disk registry or a sealed blob failed.
    #[error("profile storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The registry or a decrypted profile blob could not be (de)serialized.
    #[error("profile data is malformed: {0}")]
    Codec(#[from] serde_json::Error),

    /// A stored public key was not valid hex/32 bytes, or the canonical dig-identity profile tree
    /// could not be built for the profile's on-chain representation.
    #[error("profile identity format error: {0}")]
    Identity(String),
}

/// The profile-management result type.
pub type Result<T> = core::result::Result<T, ProfileError>;
