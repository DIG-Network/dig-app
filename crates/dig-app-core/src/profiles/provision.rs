//! The identity-provisioning seam — the boundary between profile management (U5/U6) and the
//! on-chain DID mint + key generation it depends on.
//!
//! Creating a profile mints a new `did:chia:` DID singleton, pairs it with a chip35 DataLayer store,
//! and generates the profile's signing (slot `0x0010`) + encryption (slot `0x0011`) keys. Minting is
//! a wallet/engine spend and key generation is U4's keystore — neither belongs in the profile layer.
//! So U5 depends on this narrow trait and receives back a [`Provisioned`]: the public
//! [`ProvisionedIdentity`] the manager records, PLUS the freshly generated secret material the
//! manager commits (persists sealed + unlocks) once it has validated the DID.
//!
//! # Why provisioning has no side effects (the F-1 property, security-critical)
//!
//! `provision` MUST NOT persist the identity or register it as unlocked. It only *produces* the
//! identity; the [`ProfileManager`](super::manager::ProfileManager) validates the returned DID
//! (canonical + not already owned) and only THEN commits it via
//! [`IdentityStore`](super::identity_store::IdentityStore). If provisioning registered the identity
//! itself, a minter that returned a DID clashing with an existing profile would clobber that
//! profile's live in-session identity before the duplicate was ever detected. Keeping `provision`
//! effect-free makes a rejected DID a pure no-op — the returned [`Provisioned`] is simply dropped,
//! zeroizing its secret material.
//!
//! # Integration point
//!
//! The production implementation is
//! [`KeygenProvisioner`](super::keygen_provisioner::KeygenProvisioner): it generates the key pair
//! with U4 (`IdentitySecrets::generate`) and delegates the on-chain DID mint (build + sign +
//! broadcast the spend, create the paired chip35 store) to the
//! [`DidMinter`](super::keygen_provisioner::DidMinter) wallet/engine seam.

use crate::keystore::IdentitySecrets;

/// The public identifiers of a newly minted identity handed back to the profile layer.
///
/// The private keys never appear here — they live in the sibling `secrets` field of [`Provisioned`]
/// until the manager commits them. This carries only what the plaintext registry records: the DID,
/// the two public keys, and the paired store id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedIdentity {
    /// The canonical `did:chia:` DID string of the newly minted identity singleton.
    pub did: String,
    /// The 32-byte Ed25519 signing public key (dig-identity slot `0x0010`).
    pub signing_public_key: [u8; 32],
    /// The 32-byte X25519 encryption public key (dig-identity slot `0x0011`).
    pub encryption_public_key: [u8; 32],
    /// The launcher id of the paired chip35 DataLayer store holding the profile SMT, if one was
    /// created at mint time.
    pub paired_store_id: Option<String>,
}

/// A freshly provisioned identity: its public identifiers plus the secret material the manager will
/// commit (seal at rest + register unlocked) once the DID is validated.
///
/// Not `Clone`/`Debug`: the `secrets` field is private key material, so this value is meant to be
/// consumed exactly once — committed by the manager, or dropped (which zeroizes the secrets) if the
/// DID is rejected.
pub struct Provisioned {
    /// The public identifiers recorded in the plaintext registry.
    pub identity: ProvisionedIdentity,
    /// The generated private keys, committed by the manager after DID validation. Crate-visible so
    /// only the manager (same crate, the trusted key holder) can move them into the identity store;
    /// the seam's external callers never touch the private material (SPEC §2.3).
    pub(crate) secrets: IdentitySecrets,
}

/// Mints a new identity (DID + paired store) and generates its keys, WITHOUT any side effect.
///
/// A single call is one atomic "make me a new identity" operation from the profile layer's point of
/// view; the private keys never cross this boundary in the clear (SPEC §2.3) — they ride home inside
/// the returned [`Provisioned`], which only the manager (same crate) can open.
pub trait ProfileProvisioner {
    /// Provisions a brand-new identity, returning its public identifiers and secret material.
    ///
    /// MUST be free of side effects: nothing is persisted or unlocked here (the F-1 property).
    fn provision(&self) -> Result<Provisioned, ProvisionError>;
}

/// A failure minting the DID or generating its keys.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Provisioning failed with the given reason (a failed spend, an unavailable keystore, …).
    #[error("{0}")]
    Failed(String),
}
