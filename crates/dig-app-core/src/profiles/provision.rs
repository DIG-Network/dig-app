//! The identity-provisioning seam — the boundary between profile management (U5) and the on-chain
//! DID mint + key generation it depends on.
//!
//! Creating a profile mints a new `did:chia:` DID singleton, pairs it with a chip35 DataLayer store,
//! and generates the profile's signing (slot `0x0010`) + encryption (slot `0x0011`) keys. Minting is
//! a wallet/engine spend and key generation is U4's keystore — neither belongs in the profile layer.
//! So U5 depends on this narrow trait and receives back the finished [`ProvisionedIdentity`]; the
//! profile manager records it and seals its initial data.
//!
//! # Integration point
//!
//! The production implementation is
//! [`KeygenProvisioner`](super::keygen_provisioner::KeygenProvisioner): it generates the key pair
//! with U4 (`IdentitySecrets::generate`) and delegates the on-chain DID mint (build + sign +
//! broadcast the spend, create the paired chip35 store) to the
//! [`DidMinter`](super::keygen_provisioner::DidMinter) wallet/engine seam.

/// A newly minted identity handed back to the profile layer.
///
/// The private keys live in the keystore (U4); this carries only the public identifiers the profile
/// layer records (the DID and the two public keys) plus the paired store id.
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

/// Mints a new identity (DID + paired store) and generates its keys.
///
/// A single call is one atomic "create me a new identity" operation from the profile layer's point
/// of view; the private keys never cross this boundary (SPEC §2.3) — only the public
/// [`ProvisionedIdentity`] returns.
pub trait ProfileProvisioner {
    /// Provisions a brand-new identity, returning its public identifiers.
    fn provision(&self) -> Result<ProvisionedIdentity, ProvisionError>;
}

/// A failure minting the DID or generating its keys.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Provisioning failed with the given reason (a failed spend, an unavailable keystore, …).
    #[error("{0}")]
    Failed(String),
}
