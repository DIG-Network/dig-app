//! The REAL [`ProfileProvisioner`] — U4 key generation composed with the on-chain DID mint.
//!
//! Provisioning a profile is two steps with different owners:
//!
//! 1. **Key generation (U4).** A fresh [`IdentitySecrets`] — the Ed25519 signing key (slot `0x0010`)
//!    and the X25519 encryption key (slot `0x0011`) — generated from the OS CSPRNG. The private
//!    material never leaves the identity layer; only the two public keys are published.
//! 2. **DID mint (wallet/engine).** Minting the `did:chia:` singleton (and any paired chip35 store)
//!    for that key pair is an on-chain spend built + signed by the wallet/engine. That is the
//!    [`DidMinter`] seam: this crate does not build spends (SPEC §2.3), it supplies the freshly
//!    generated public keys and records the DID the mint returns.
//!
//! On success the generated identity is registered into the shared [`UnlockedIdentities`] session
//! store so the [`KeystoreSealer`](super::keystore_sealer::KeystoreSealer) can immediately seal the
//! new profile's data under its own DEK — a created profile is unlocked for the rest of the session.

use crate::keystore::IdentitySecrets;

use super::keystore_sealer::UnlockedIdentities;
use super::provision::{ProfileProvisioner, ProvisionError, ProvisionedIdentity};

/// The result of minting a DID for a freshly generated key pair.
///
/// Carries only the public on-chain identifiers — the DID string and the launcher id of the paired
/// chip35 store, if one was created at mint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedDid {
    /// The canonical `did:chia:` DID string of the newly minted identity singleton.
    pub did: String,
    /// The launcher id of the paired chip35 DataLayer store, if one was created.
    pub paired_store_id: Option<String>,
}

/// Mints a `did:chia:` DID singleton for a generated key pair — the wallet/engine on-chain spend.
///
/// The signing and encryption public keys are handed in so the mint can anchor them into the DID's
/// initial profile SMT; the private keys never cross this boundary.
pub trait DidMinter {
    /// Builds, signs, and broadcasts the DID-mint spend for the given public key pair, returning the
    /// minted DID once it is confirmable.
    fn mint(
        &self,
        signing_public_key: &[u8; 32],
        encryption_public_key: &[u8; 32],
    ) -> Result<MintedDid, ProvisionError>;
}

/// The production [`ProfileProvisioner`]: generates a profile's keys (U4) and mints its DID through
/// the injected [`DidMinter`] (wallet/engine), then registers the unlocked identity so its data can
/// be sealed.
pub struct KeygenProvisioner<M: DidMinter> {
    identities: UnlockedIdentities,
    minter: M,
}

impl<M: DidMinter> KeygenProvisioner<M> {
    /// Builds a provisioner that registers each generated identity into `identities` and mints its
    /// DID via `minter`.
    pub fn new(identities: UnlockedIdentities, minter: M) -> Self {
        Self { identities, minter }
    }
}

impl<M: DidMinter> ProfileProvisioner for KeygenProvisioner<M> {
    fn provision(&self) -> Result<ProvisionedIdentity, ProvisionError> {
        let secrets = IdentitySecrets::generate();
        let signing_public_key = secrets.signing_public_key();
        let encryption_public_key = secrets.encryption_public_key();

        let minted = self
            .minter
            .mint(&signing_public_key, &encryption_public_key)?;

        // The mint succeeded: register the identity so the new profile is unlocked and its data can
        // be sealed under its own DEK. Done AFTER the mint so a failed mint leaves no dangling key.
        self.identities.unlock(&minted.did, secrets);

        Ok(ProvisionedIdentity {
            did: minted.did,
            signing_public_key,
            encryption_public_key,
            paired_store_id: minted.paired_store_id,
        })
    }
}
