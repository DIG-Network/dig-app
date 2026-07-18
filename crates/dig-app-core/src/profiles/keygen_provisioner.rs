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
//! Provisioning is **side-effect free** (the F-1 property, [`super::provision`]): it returns a
//! [`Provisioned`] carrying the generated [`IdentitySecrets`] and does NOT persist or unlock them.
//! The [`ProfileManager`](super::manager::ProfileManager) validates the minted DID and only then
//! commits the identity (seals it at rest + registers it unlocked), so a duplicate/invalid DID never
//! clobbers an existing profile's live identity.

use crate::keystore::IdentitySecrets;

use super::provision::{ProfileProvisioner, ProvisionError, Provisioned, ProvisionedIdentity};

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

/// The production [`DidMinter`] seam placeholder — the on-chain DID mint is HELD on dig-identity
/// #771 (the canonical DID + paired-store mint spend builder).
///
/// This is a deliberate SEAM, not an implementation: it lets the production provisioner
/// ([`KeygenProvisioner`]) be constructed and composed today (key generation + persistence wire up
/// cleanly around it), while the actual mint fails loudly and explicitly until #771 ships the spend
/// builder. Swap this for the real wallet/engine minter when #771 lands — no other code changes,
/// because it is addressed only through the [`DidMinter`] trait.
#[derive(Debug, Default, Clone, Copy)]
pub struct HeldDidMinter;

impl DidMinter for HeldDidMinter {
    fn mint(
        &self,
        _signing_public_key: &[u8; 32],
        _encryption_public_key: &[u8; 32],
    ) -> Result<MintedDid, ProvisionError> {
        Err(ProvisionError::Failed(
            "on-chain DID mint is not yet available (gated on dig-identity #771)".to_string(),
        ))
    }
}

/// The production [`ProfileProvisioner`]: generates a profile's keys (U4) and mints its DID through
/// the injected [`DidMinter`] (wallet/engine), returning both to the manager to commit.
///
/// Holds no session store and persists nothing — provisioning is side-effect free (F-1).
pub struct KeygenProvisioner<M: DidMinter> {
    minter: M,
}

impl<M: DidMinter> KeygenProvisioner<M> {
    /// Builds a provisioner that mints each generated identity's DID via `minter`.
    pub fn new(minter: M) -> Self {
        Self { minter }
    }
}

impl Default for KeygenProvisioner<HeldDidMinter> {
    /// The production default: real key generation with the mint held on #771 ([`HeldDidMinter`]).
    fn default() -> Self {
        Self::new(HeldDidMinter)
    }
}

impl<M: DidMinter> ProfileProvisioner for KeygenProvisioner<M> {
    fn provision(&self) -> Result<Provisioned, ProvisionError> {
        let secrets = IdentitySecrets::generate();
        let signing_public_key = secrets.signing_public_key();
        let encryption_public_key = secrets.encryption_public_key();

        // The mint is attempted BEFORE building the result but produces no local state, so a failed
        // mint simply drops the freshly generated (still-unpersisted) secrets — nothing to roll back.
        let minted = self
            .minter
            .mint(&signing_public_key, &encryption_public_key)?;

        Ok(Provisioned {
            identity: ProvisionedIdentity {
                did: minted.did,
                signing_public_key,
                encryption_public_key,
                paired_store_id: minted.paired_store_id,
            },
            secrets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production seam refuses to mint until #771 lands, surfacing an explicit held error rather
    /// than silently succeeding — so a released build cannot appear to mint a DID it cannot anchor.
    #[test]
    fn held_minter_reports_the_mint_is_gated_on_771() {
        let err = HeldDidMinter.mint(&[1; 32], &[2; 32]).unwrap_err();
        let ProvisionError::Failed(msg) = err;
        assert!(
            msg.contains("#771"),
            "held error should name the gating issue"
        );
    }

    /// Provisioning generates a real key pair and, with the mint held, surfaces the held error
    /// without persisting anything (the default production wiring composes cleanly).
    #[test]
    fn default_provisioner_composes_but_mint_is_held() {
        let prov = KeygenProvisioner::default();
        assert!(matches!(prov.provision(), Err(ProvisionError::Failed(_))));
    }
}
