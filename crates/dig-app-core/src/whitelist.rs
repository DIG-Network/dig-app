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

use crate::live::{belongs_to_active_profile, ConsentError, ConsentedProfile, LiveDid};
use crate::sealer::{ProfileSealer, SealError};

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
    /// The DID this store seals under, read at each grant/restore rather than captured — see
    /// [`LiveDid`], and [`PairingStore`](crate::pairing::PairingStore) for the same field and the
    /// same reason.
    profile_did: LiveDid,
    live: Mutex<HashMap<String, WhitelistEntry>>,
}

impl<S: ProfileSealer> WhitelistStore<S> {
    /// Build a store that seals grants under `profile_did`'s DEK via `sealer`. A `&str`/`String`
    /// converts to a FIXED DID; production passes a [`LiveDid::read`] so the store follows a switch.
    pub fn new(sealer: S, profile_did: impl Into<LiveDid>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// The DID to seal under right now, or a fail-closed [`SealError`] when no profile is active.
    /// See [`PairingStore::seal_as`](crate::pairing::PairingStore) for why refusing beats a
    /// placeholder.
    fn seal_as(&self) -> Result<String, SealError> {
        self.profile_did
            .get()
            .ok_or_else(|| SealError::Seal("no active profile — the account is locked".to_string()))
    }

    /// Read the profile a connect confirm is about to be answered under. Take this BEFORE raising the
    /// confirm and hand it to [`grant`](Self::grant); see [`ConsentedProfile`].
    pub fn consent_now(&self) -> ConsentedProfile {
        ConsentedProfile::reading(&self.profile_did)
    }

    /// Whitelist `origin` with `permissions`: register it live and seal the [`WhitelistEntry`] at rest
    /// under the active profile's DEK. The caller invokes the native connect confirm (§5.6.4) BEFORE
    /// calling this — the store records only an already-approved grant. A re-grant of the same origin
    /// replaces the prior entry.
    ///
    /// `consent`, taken before that confirm, is what makes the grant belong to the profile whose owner
    /// approved it: a switch landing in between is refused rather than recorded under whoever arrived.
    ///
    /// # Errors
    ///
    /// [`ConsentError::ProfileMoved`] if the active profile changed since `consent` was taken;
    /// [`ConsentError::Seal`] if the profile is locked or sealing fails. No live entry is registered on
    /// either error.
    pub fn grant(
        &self,
        consent: &ConsentedProfile,
        origin: &str,
        permissions: Vec<String>,
        connected_at: u64,
    ) -> Result<GrantOutcome, ConsentError> {
        let profile_did = self.seal_as()?;
        if !consent.still_holds(&profile_did) {
            return Err(ConsentError::ProfileMoved);
        }
        let entry = WhitelistEntry {
            origin: origin.to_string(),
            profile_did: profile_did.clone(),
            granted_permissions: permissions,
            connected_at,
        };
        // Seal FIRST: if sealing fails (locked profile) we register nothing, so a live grant never
        // exists without a durable at-rest counterpart (parity with the pairing store).
        let plaintext = serde_json::to_vec(&entry).map_err(|e| SealError::Seal(e.to_string()))?;
        // `seal_bound`, not `seal`: the DID and the sealer's DEK used to be two independent
        // reads, so a switch landing between them tagged one profile's key with the other's
        // name — undetectable downstream (dig-app#255). The sealer now re-resolves the DID
        // from the acquisition that yields the key and refuses when they disagree.
        let sealed_record = self.sealer.seal_bound(&profile_did, &plaintext)?;

        self.lock().insert(origin.to_string(), entry.clone());
        Ok(GrantOutcome {
            entry,
            sealed_record,
        })
    }

    /// Drop every live grant, so a reload can repopulate from what is at rest for the profile that is
    /// active NOW — the whitelist half of
    /// [`PairingStore::clear_live`](crate::pairing::PairingStore::clear_live), which carries the
    /// reasoning.
    ///
    /// Registered grants only: nothing at rest is touched, so this is recoverable by the reload that
    /// follows it. Fail-closed if that reload restores nothing, because an empty map authorizes
    /// nothing — the worst outcome of clearing is a dapp asked to connect again.
    pub fn clear_live(&self) {
        self.lock().clear();
    }

    /// Restore a grant from its sealed at-rest bytes (app restart): open under the active profile's
    /// DEK and register it live. Returns the restored origin.
    ///
    /// # Errors
    ///
    /// [`SealError::Open`] if the bytes were not sealed by this profile's DEK or are corrupt, and
    /// [`SealError::Seal`] if no profile is active — which is what a locked account reads as, and
    /// which `seal_as` raises before any byte is opened.
    pub fn restore_sealed(&self, sealed_record: &[u8]) -> Result<String, SealError> {
        let plaintext = self.sealer.open(&self.seal_as()?, sealed_record)?;
        let entry: WhitelistEntry =
            serde_json::from_slice(&plaintext).map_err(|_| SealError::Open)?;
        let origin = entry.origin.clone();
        self.lock().insert(origin.clone(), entry);
        Ok(origin)
    }

    /// Whether `origin` is connected FOR THE PROFILE NOW ACTIVE — the `sign.request` connect gate.
    pub fn is_whitelisted(&self, origin: &str) -> bool {
        self.get(origin).is_some()
    }

    /// The live entry for `origin` if it is connected for the profile now active (for the
    /// connect-response handle).
    pub fn get(&self, origin: &str) -> Option<WhitelistEntry> {
        self.lock()
            .get(origin)
            .filter(|entry| self.belongs_to_active(&entry.profile_did))
            .cloned()
    }

    /// Revoke `origin` (the `connect.revoke` surface, §5.6.4). Returns whether an entry for the active
    /// profile was present; afterward that origin returns to `CONNECT_REQUIRED`. The caller separately
    /// deletes the sealed at-rest record.
    ///
    /// A grant belonging to a DIFFERENT profile is left alone rather than removed: the at-rest half of
    /// this revoke goes to the ACTIVE profile's directory, so deleting another profile's live entry here
    /// would drop access that the next boot restores anyway — a revoke that reads as done and is not.
    /// A LOCKED account is the same case for the same reason, and its caller
    /// (`handle_connect_revoke`) refuses `LOCKED` on the durable half regardless.
    pub fn revoke(&self, origin: &str) -> bool {
        let mut live = self.lock();
        match live.get(origin) {
            Some(entry) if self.belongs_to_active(&entry.profile_did) => {
                live.remove(origin);
                true
            }
            _ => false,
        }
    }

    /// Whether a recorded grant tagged `entry_did` is one the profile NOW ACTIVE may act on — the
    /// predicate that stops a grant surviving a profile switch, and stops a LOCKED account honouring
    /// one at all. See [`belongs_to_active_profile`](crate::live::belongs_to_active_profile).
    fn belongs_to_active(&self, entry_did: &str) -> bool {
        belongs_to_active_profile(self.profile_did.get().as_deref(), entry_did)
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
    use crate::account::sealer::AccountSealer;
    use crate::test_support::test_sealer;

    const DID: &str = "did:chia:whitelist-test";
    const ORIGIN: &str = "https://dapp.example";

    /// A store sealing under a fresh profile DEK (the fast test KDF).
    fn store() -> WhitelistStore<AccountSealer> {
        WhitelistStore::new(test_sealer(DID), DID)
    }

    #[test]
    fn an_ungranted_origin_is_not_whitelisted() {
        assert!(!store().is_whitelisted(ORIGIN));
    }

    #[test]
    fn granting_an_origin_whitelists_it_and_seals_the_record() {
        let store = store();
        let out = store
            .grant(
                &store.consent_now(),
                ORIGIN,
                vec!["addresses".to_string()],
                1_700_000_000,
            )
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
        let out = store
            .grant(&store.consent_now(), ORIGIN, vec![], 42)
            .unwrap();
        store.revoke(ORIGIN);
        assert!(!store.is_whitelisted(ORIGIN));

        let restored = store.restore_sealed(&out.sealed_record).unwrap();
        assert_eq!(restored, ORIGIN);
        assert!(store.is_whitelisted(ORIGIN));
    }

    #[test]
    fn revoking_returns_the_origin_to_unconnected() {
        let store = store();
        store
            .grant(&store.consent_now(), ORIGIN, vec![], 1)
            .unwrap();
        assert!(store.revoke(ORIGIN));
        assert!(!store.revoke(ORIGIN));
        assert!(!store.is_whitelisted(ORIGIN));
    }

    #[test]
    fn a_foreign_profile_cannot_restore_a_sealed_grant() {
        // NC-2 cross-profile isolation: the sealed grant is bound to the sealing profile's DEK.
        let store_a = store();
        let out = store_a
            .grant(&store_a.consent_now(), ORIGIN, vec![], 1)
            .unwrap();

        // A DISTINCT profile DEK (a different label) cannot open A's sealed grant — isolation is
        // cryptographic (the AEAD tag), not by DID string.
        let store_b = WhitelistStore::new(test_sealer("did:chia:other"), "did:chia:other");
        assert!(matches!(
            store_b.restore_sealed(&out.sealed_record),
            Err(SealError::Open)
        ));
    }

    /// **Locking the account withdraws every grant's authority, not just its key.**
    ///
    /// A lock is not a quiet moment on the same profile: `SetActiveProfile` reads the registry from
    /// disk and switches deliberately while locked, and the sign path's re-auth gate then unlocks into
    /// whatever is active by then. So a grant that still answered "yes" here would be one profile's
    /// consent honoured by another profile's key.
    ///
    /// The control is the same store one line earlier, while unlocked: without it a store that never
    /// registered the grant at all would produce the same refusal.
    #[test]
    fn a_locked_account_authorizes_no_origin_it_granted_while_unlocked() {
        use crate::account::boot::live_profile_did;
        use crate::account::residency::AccountResidency;
        use crate::session_lock::SessionKeys;
        use dig_keystore::KdfParams;

        let residency = crate::test_support::test_residency();
        let store = WhitelistStore::new(
            residency.sealer(KdfParams::FAST_TEST),
            live_profile_did(&residency),
        );
        store
            .grant(&store.consent_now(), ORIGIN, vec![], 1)
            .expect("an unlocked profile grants");
        assert!(
            store.is_whitelisted(ORIGIN),
            "control: the grant authorizes while the account is unlocked"
        );

        AccountResidency::lock_all(&residency);

        assert!(
            !store.is_whitelisted(ORIGIN),
            "a locked account cannot say whose consent this is, so it must honour none of it"
        );
        assert!(
            store.get(ORIGIN).is_none(),
            "and the entry itself must not be handed out — the connect handle is built from it"
        );
    }

    /// **A grant is refused when the profile moved between the consent and the write.**
    ///
    /// The store is the enforcement point, so it is asserted here as well as through the router: a
    /// consent read under A, presented while B is active, must record nothing — not under B, whose
    /// owner never saw the modal, and not under A, which is no longer the profile being written for.
    ///
    /// The control is the SAME consent presented while A is still active, which must grant: without it
    /// a store that refused every grant would look identical.
    #[test]
    fn a_grant_is_refused_when_the_profile_moved_since_the_consent() {
        use crate::live::Live;
        use std::sync::Arc;

        let active = Arc::new(Mutex::new("did:chia:consenting".to_string()));
        let source = Arc::clone(&active);
        let store = WhitelistStore::new(
            test_sealer(DID),
            Live::read(move || Some(source.lock().expect("test mutex").clone())),
        );

        let consent = store.consent_now();
        *active.lock().expect("test mutex") = "did:chia:arrived-after".to_string();

        let moved = store.grant(&consent, ORIGIN, vec![], 1).err();
        assert!(
            matches!(moved, Some(ConsentError::ProfileMoved)),
            "a grant written for a profile nobody consented for must be refused: {moved:?}"
        );
        assert!(
            !store.is_whitelisted(ORIGIN),
            "and a refused grant registers nothing for the profile that arrived"
        );

        *active.lock().expect("test mutex") = "did:chia:consenting".to_string();
        assert!(
            !store.is_whitelisted(ORIGIN),
            "nor for the profile that consented — the grant did not half-land"
        );
        assert!(
            store.grant(&consent, ORIGIN, vec![], 2).is_ok(),
            "control: the same consent grants once its own profile is active again"
        );
        assert!(store.is_whitelisted(ORIGIN));
    }

    #[test]
    fn a_locked_profile_fails_closed_on_grant() {
        use crate::account::residency::AccountResidency;
        use crate::session_lock::SessionKeys;
        use dig_keystore::KdfParams;

        // A live-view sealer over a LOCKED residency must fail closed on seal.
        let residency = crate::test_support::test_residency();
        let sealer = residency.sealer(KdfParams::FAST_TEST);
        AccountResidency::lock_all(&residency);
        let store = WhitelistStore::new(sealer, DID);
        assert!(matches!(
            store.grant(&store.consent_now(), ORIGIN, vec![], 1),
            Err(ConsentError::Seal(SealError::Seal(_)))
        ));
        assert!(
            !store.is_whitelisted(ORIGIN),
            "a failed grant registers nothing"
        );
    }
}
