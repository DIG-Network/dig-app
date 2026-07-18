//! The dapp connect-whitelist — which origins a profile has authorized to request signatures
//! (SIGN-2, `SPEC.md` §5.6.4, **security-critical**).
//!
//! Before a dapp origin may request a sign it MUST be *connected* (whitelisted) for the active
//! profile (§5.6.4). Connecting is a one-time native confirm (§5.6.1); on approval a per-origin entry
//! is recorded, DIGOP1-sealed at rest under the active profile's DEK (NC-2) through the same
//! [`ProfileSealer`] seam the pairing store uses. Thereafter a `sign.request` from a whitelisted
//! origin passes the connect gate (`CONNECT_REQUIRED` otherwise); an un-whitelisted origin is refused
//! before any decode or confirm.
//!
//! The whitelist is connect-time convenience memory ONLY — it records that the user connected an
//! origin, and it NEVER waives the per-sign native confirm (§5.6.4). Revoking an origin returns it to
//! `CONNECT_REQUIRED`.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::profiles::sealer::{ProfileSealer, SealError};

/// One authorized dapp origin, as persisted DIGOP1-sealed per profile (§5.6.4). Records what the user
/// granted at connect time; it is convenience memory, not sign authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// The dapp's true committed tab origin the extension vouched for (e.g. `https://dapp.example`).
    pub origin: String,
    /// The profile DID this grant belongs to (also the sealing DEK owner — cross-profile isolated).
    pub profile_did: String,
    /// The permissions granted at connect (the `window.chia` scope). Empty means the base connect only.
    pub granted_permissions: Vec<String>,
    /// Unix-epoch seconds when the origin was connected.
    pub connected_at: u64,
}

/// The outcome of a successful [`WhitelistStore::grant`]: the recorded entry plus the sealed at-rest
/// bytes the caller persists (NC-2). Ciphertext at rest; only the active profile's DEK can reopen it.
pub struct GrantOutcome {
    /// The live entry now gating `sign.request` for its origin.
    pub entry: WhitelistEntry,
    /// The DIGOP1-sealed [`WhitelistEntry`] bytes to persist at rest.
    pub sealed_record: Vec<u8>,
}

/// The per-profile store of connected dapp origins. Seals new grants at rest through the
/// [`ProfileSealer`] seam (NC-2) and answers the connect gate for every `sign.request`.
/// Interior-mutable ([`Mutex`]) so the loopback server can share one store behind an `Arc`.
pub struct WhitelistStore<S: ProfileSealer> {
    sealer: S,
    profile_did: String,
    live: Mutex<HashMap<String, WhitelistEntry>>,
}

impl<S: ProfileSealer> WhitelistStore<S> {
    /// Build a store that seals grants under `profile_did`'s DEK via `sealer`.
    pub fn new(sealer: S, profile_did: impl Into<String>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Whitelist `origin` with `permissions`: register it live and seal the [`WhitelistEntry`] at rest
    /// under the active profile's DEK. The caller invokes the native connect confirm (§5.6.4) BEFORE
    /// calling this — the store records only an already-approved grant. A re-grant of the same origin
    /// replaces the prior entry.
    ///
    /// # Errors
    ///
    /// [`SealError`] if the profile is locked or sealing fails; no live entry is registered on error.
    pub fn grant(
        &self,
        origin: &str,
        permissions: Vec<String>,
        connected_at: u64,
    ) -> Result<GrantOutcome, SealError> {
        let entry = WhitelistEntry {
            origin: origin.to_string(),
            profile_did: self.profile_did.clone(),
            granted_permissions: permissions,
            connected_at,
        };
        // Seal FIRST: if sealing fails (locked profile) we register nothing, so a live grant never
        // exists without a durable at-rest counterpart (parity with the pairing store).
        let plaintext = serde_json::to_vec(&entry).map_err(|e| SealError::Seal(e.to_string()))?;
        let sealed_record = self.sealer.seal(&self.profile_did, &plaintext)?;

        self.lock().insert(origin.to_string(), entry.clone());
        Ok(GrantOutcome {
            entry,
            sealed_record,
        })
    }

    /// Restore a grant from its sealed at-rest bytes (app restart): open under the active profile's
    /// DEK and register it live. Returns the restored origin.
    ///
    /// # Errors
    ///
    /// [`SealError::Open`] if the bytes were not sealed by this profile's DEK or are corrupt.
    pub fn restore_sealed(&self, sealed_record: &[u8]) -> Result<String, SealError> {
        let plaintext = self.sealer.open(&self.profile_did, sealed_record)?;
        let entry: WhitelistEntry =
            serde_json::from_slice(&plaintext).map_err(|_| SealError::Open)?;
        let origin = entry.origin.clone();
        self.lock().insert(origin.clone(), entry);
        Ok(origin)
    }

    /// Whether `origin` is connected for the active profile — the `sign.request` connect gate.
    pub fn is_whitelisted(&self, origin: &str) -> bool {
        self.lock().contains_key(origin)
    }

    /// The live entry for `origin`, if connected (for the connect-response handle).
    pub fn get(&self, origin: &str) -> Option<WhitelistEntry> {
        self.lock().get(origin).cloned()
    }

    /// Revoke `origin` (the `connect.revoke` surface, §5.6.4). Returns whether an entry was present;
    /// afterward that origin returns to `CONNECT_REQUIRED`. The caller separately deletes the sealed
    /// at-rest record.
    pub fn revoke(&self, origin: &str) -> bool {
        self.lock().remove(origin).is_some()
    }

    /// A poisoned mutex means another thread panicked mid-update — fail loudly rather than gate a sign
    /// against half-updated whitelist state.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, WhitelistEntry>> {
        self.live.lock().expect("whitelist-store mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::IdentitySecrets;
    use crate::profiles::keystore_sealer::{KeystoreSealer, UnlockedIdentities};
    use dig_keystore::KdfParams;

    const DID: &str = "did:chia:whitelist-test";
    const ORIGIN: &str = "https://dapp.example";

    /// A store whose active profile is unlocked with a fresh identity, sealing under the fast test KDF.
    fn store() -> WhitelistStore<KeystoreSealer> {
        let identities = UnlockedIdentities::new();
        identities.unlock(DID, IdentitySecrets::generate());
        WhitelistStore::new(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            DID,
        )
    }

    #[test]
    fn an_ungranted_origin_is_not_whitelisted() {
        assert!(!store().is_whitelisted(ORIGIN));
    }

    #[test]
    fn granting_an_origin_whitelists_it_and_seals_the_record() {
        let store = store();
        let out = store
            .grant(ORIGIN, vec!["addresses".to_string()], 1_700_000_000)
            .unwrap();

        assert!(store.is_whitelisted(ORIGIN));
        assert_eq!(out.entry.origin, ORIGIN);
        assert_eq!(out.entry.profile_did, DID);
        assert_eq!(out.entry.granted_permissions, ["addresses"]);
        // The sealed record is ciphertext — the origin does not appear in the clear.
        assert!(!out.sealed_record.is_empty());
        assert!(!String::from_utf8_lossy(&out.sealed_record).contains(ORIGIN));
    }

    #[test]
    fn a_sealed_grant_round_trips_through_restore() {
        let store = store();
        let out = store.grant(ORIGIN, vec![], 42).unwrap();
        store.revoke(ORIGIN);
        assert!(!store.is_whitelisted(ORIGIN));

        let restored = store.restore_sealed(&out.sealed_record).unwrap();
        assert_eq!(restored, ORIGIN);
        assert!(store.is_whitelisted(ORIGIN));
    }

    #[test]
    fn revoking_returns_the_origin_to_unconnected() {
        let store = store();
        store.grant(ORIGIN, vec![], 1).unwrap();
        assert!(store.revoke(ORIGIN));
        assert!(!store.revoke(ORIGIN));
        assert!(!store.is_whitelisted(ORIGIN));
    }

    #[test]
    fn a_foreign_profile_cannot_restore_a_sealed_grant() {
        // NC-2 cross-profile isolation: the sealed grant is bound to the sealing profile's DEK.
        let store_a = store();
        let out = store_a.grant(ORIGIN, vec![], 1).unwrap();

        let identities = UnlockedIdentities::new();
        identities.unlock("did:chia:other", IdentitySecrets::generate());
        let store_b = WhitelistStore::new(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            "did:chia:other",
        );
        assert!(matches!(
            store_b.restore_sealed(&out.sealed_record),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn a_locked_profile_fails_closed_on_grant() {
        let identities = UnlockedIdentities::new();
        // DID is NOT unlocked in this store — sealing must fail closed.
        let store = WhitelistStore::new(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            DID,
        );
        assert!(matches!(
            store.grant(ORIGIN, vec![], 1),
            Err(SealError::Seal(_))
        ));
        assert!(
            !store.is_whitelisted(ORIGIN),
            "a failed grant registers nothing"
        );
    }
}
