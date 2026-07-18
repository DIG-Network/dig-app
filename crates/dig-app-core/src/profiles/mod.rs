//! Profiles — multi-DID identity, one active at a time (U5, SECURITY-CRITICAL).
//!
//! A **profile** is `{ DID (did:chia singleton), keys (signing 0x0010 + encryption 0x0011), paired
//! chip35 DataLayer store, local data (config / subscriptions / prefs / cached metadata) }`. dig-app
//! supports multiple profiles with exactly one **active** at a time and:
//!
//! - **creates** them — provisions a DID + keys through the [`provision`] seam (mint on-chain +
//!   generate keys in the keystore), then seals the profile's initial data;
//! - **selects** the active one — loads that profile's sealed data into memory;
//! - **lists** them — from the plaintext registry, before any profile is unlocked;
//! - **edits** them — updates persona fields and recomputes the canonical dig-identity SMT root.
//!
//! # What this layer owns — and what it delegates
//!
//! U5 owns *which* bytes are sealed and *where* they live; it delegates the crypto and the minting:
//!
//! - **Format** — profile metadata maps onto the canonical `dig-identity` (dig_ecosystem#771) SMT of
//!   standard slots ([`metadata`]); U5 never reinvents the tree or the slot map.
//! - **Sealing** — every per-profile secret blob is DIGOP1-sealed under that profile's own DEK via
//!   the [`sealer`] seam; the production implementation is [`keystore_sealer::KeystoreSealer`], which
//!   derives each DEK from that profile's U4 identity key. Profiles never share a DEK, so they are
//!   cryptographically isolated on disk (NC-2/NC-3, SPEC §3.1).
//! - **Provisioning** — generating keys (U4) + minting the DID (wallet/engine) goes through the
//!   [`provision`] seam; the production implementation is [`keygen_provisioner::KeygenProvisioner`].
//!
//! The [`ProfileManager`] ties these together. It holds no private key and seals nothing with a
//! shared key.

pub mod data;
pub mod error;
pub mod keygen_provisioner;
pub mod keystore_sealer;
pub mod manager;
pub mod metadata;
pub mod provision;
pub mod sealer;

pub use data::{did_hash, ProfileData, ProfilePrefs, ProfileRecord, ProfileRegistry};
pub use error::ProfileError;
pub use keygen_provisioner::{DidMinter, KeygenProvisioner, MintedDid};
pub use keystore_sealer::{KeystoreSealer, UnlockedIdentities};
pub use manager::ProfileManager;
pub use metadata::ProfileMetadata;
pub use provision::{ProfileProvisioner, ProvisionError, ProvisionedIdentity};
pub use sealer::{ProfileSealer, SealError};

/// A local reference to a profile — the DID plus (via the registry) its cached metadata.
///
/// This lightweight handle is what the agent status surface ([`crate::agent`]) and the IPC layer
/// key on; the full record is [`ProfileRecord`] and the sealed state is [`ProfileData`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRef {
    /// The profile's `did:chia:` decentralized identifier (the on-chain singleton launcher id).
    pub did: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::provision::ProvisionError;
    use chia_sdk_utils::Address;
    use dig_identity::{Bytes32, Did};
    use dig_keystore::KdfParams;
    use std::cell::Cell;

    // --- Real U4-backed harness -----------------------------------------------------------------
    //
    // These tests exercise the REAL sealer (`KeystoreSealer`, U4 DIGOP1 under each profile's
    // identity-derived DEK) and the REAL key-generating provisioner (`KeygenProvisioner`). The only
    // seam still stubbed is the on-chain DID mint (a wallet/engine spend, U6/U7) — supplied here by a
    // `CountingMinter` that returns canonical `did:chia:` strings. So the crypto under test is
    // production crypto; only the chain interaction is faked.

    /// A [`DidMinter`] that returns a fresh canonical `did:chia:` per call — stands in for the
    /// wallet/engine on-chain mint (U6/U7) without touching mainnet.
    #[derive(Default)]
    struct CountingMinter {
        counter: Cell<u8>,
    }

    impl DidMinter for CountingMinter {
        fn mint(
            &self,
            _signing: &[u8; 32],
            _encryption: &[u8; 32],
        ) -> Result<MintedDid, ProvisionError> {
            let n = self.counter.get() + 1;
            self.counter.set(n);
            Ok(MintedDid {
                did: canonical_did([n; 32]),
                paired_store_id: Some(format!("store-{n}")),
            })
        }
    }

    /// A minter that always fails — for the create-error path (a rejected mint spend).
    struct FailingMinter;
    impl DidMinter for FailingMinter {
        fn mint(
            &self,
            _signing: &[u8; 32],
            _encryption: &[u8; 32],
        ) -> Result<MintedDid, ProvisionError> {
            Err(ProvisionError::Failed("mint spend rejected".into()))
        }
    }

    /// A minter that returns a non-canonical DID string — for the DID-validation path.
    struct BadDidMinter;
    impl DidMinter for BadDidMinter {
        fn mint(
            &self,
            _signing: &[u8; 32],
            _encryption: &[u8; 32],
        ) -> Result<MintedDid, ProvisionError> {
            Ok(MintedDid {
                did: "not-a-did".into(),
                paired_store_id: None,
            })
        }
    }

    /// A minter that always returns the SAME DID — for the duplicate-DID path.
    struct FixedMinter;
    impl DidMinter for FixedMinter {
        fn mint(
            &self,
            _signing: &[u8; 32],
            _encryption: &[u8; 32],
        ) -> Result<MintedDid, ProvisionError> {
            Ok(MintedDid {
                did: canonical_did([9; 32]),
                paired_store_id: None,
            })
        }
    }

    /// Encodes a launcher id as its canonical `did:chia:1…` bech32m string (the real DID format).
    fn canonical_did(launcher: [u8; 32]) -> String {
        Address::new(Bytes32::from(launcher), "did:chia:".to_string())
            .encode()
            .expect("valid did encoding")
    }

    /// A manager over `dir` whose real [`KeystoreSealer`] shares an [`UnlockedIdentities`] session
    /// store with the provisioner, so a created profile is immediately unlockable for sealing.
    /// Returns the manager plus the shared store (for isolation tests that seal/open directly).
    fn harness(dir: &std::path::Path) -> (ProfileManager<KeystoreSealer>, UnlockedIdentities) {
        let identities = UnlockedIdentities::new();
        let sealer = KeystoreSealer::with_kdf(identities.clone(), KdfParams::FAST_TEST);
        (ProfileManager::new(dir.to_path_buf(), sealer), identities)
    }

    fn manager(dir: &std::path::Path) -> ProfileManager<KeystoreSealer> {
        harness(dir).0
    }

    /// A real key-generating provisioner sharing `identities`, minting DIDs via a fresh
    /// [`CountingMinter`].
    fn provisioner(identities: &UnlockedIdentities) -> KeygenProvisioner<CountingMinter> {
        KeygenProvisioner::new(identities.clone(), CountingMinter::default())
    }

    fn named(name: &str) -> ProfileMetadata {
        ProfileMetadata {
            display_name: Some(name.to_string()),
            ..ProfileMetadata::default()
        }
    }

    // --- create / list / active ----------------------------------------------------------------

    #[test]
    fn create_then_list_round_trips_both_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = provisioner(&ids);

        let a = mgr.create_profile(&prov, named("Ada")).unwrap();
        let b = mgr.create_profile(&prov, named("Bob")).unwrap();

        let listed = mgr.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].did, a.did);
        assert_eq!(listed[1].did, b.did);
        assert_eq!(listed[0].display_name.as_deref(), Some("Ada"));
    }

    #[test]
    fn first_created_profile_becomes_active() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = provisioner(&ids);

        let a = mgr.create_profile(&prov, named("Ada")).unwrap();
        mgr.create_profile(&prov, named("Bob")).unwrap();

        // Creating more profiles does not steal the active pointer.
        assert_eq!(mgr.active_did().unwrap(), Some(a.did));
    }

    #[test]
    fn a_profile_binds_a_did_and_its_two_public_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(&ids), named("Ada"))
            .unwrap();

        assert!(Did::parse(&record.did).is_some(), "DID is canonical");
        // 32 bytes rendered as 64 hex chars, and the two keys are distinct.
        assert_eq!(record.signing_public_key.len(), 64);
        assert_eq!(record.encryption_public_key.len(), 64);
        assert_ne!(record.signing_public_key, record.encryption_public_key);
        assert_eq!(record.paired_store_id.as_deref(), Some("store-1"));
    }

    // --- select / persistence ------------------------------------------------------------------

    #[test]
    fn select_loads_the_profiles_own_data_and_persists_the_active_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = provisioner(&ids);
        let a = mgr.create_profile(&prov, named("Ada")).unwrap();
        let b = mgr.create_profile(&prov, named("Bob")).unwrap();

        let data_b = mgr.select_profile(&b.did).unwrap();
        assert_eq!(data_b.metadata.display_name.as_deref(), Some("Bob"));
        assert!(data_b.prefs.auto_tip, "auto-tip defaults on");

        // A fresh manager over the same dir sees the persisted active pointer (read from the
        // plaintext registry, no unlock needed). Its sealer shares the same unlocked identities the
        // user re-unlocked this session, so it can also open a profile's sealed data.
        let reopened = ProfileManager::new(
            dir.path(),
            KeystoreSealer::with_kdf(ids, KdfParams::FAST_TEST),
        );
        assert_eq!(reopened.active_did().unwrap(), Some(b.did));

        // And selecting A back loads A's own data, not B's.
        let data_a = reopened.select_profile(&a.did).unwrap();
        assert_eq!(data_a.metadata.display_name.as_deref(), Some("Ada"));
    }

    // --- at-rest sealing + cross-profile isolation (security-critical) -------------------------

    #[test]
    fn per_profile_data_is_ciphertext_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(&ids), named("SecretName"))
            .unwrap();

        let seal_path = dir
            .path()
            .join("profiles")
            .join(&record.did_hash)
            .join("identity.seal");
        let on_disk = std::fs::read(&seal_path).unwrap();

        // The plaintext display name must not appear anywhere in the sealed bytes.
        assert!(
            !contains(&on_disk, b"SecretName"),
            "plaintext leaked into the sealed blob"
        );
        // And the bytes differ from the plaintext serialization.
        let plaintext = serde_json::to_vec(&ProfileData {
            metadata: named("SecretName"),
            ..ProfileData::default()
        })
        .unwrap();
        assert_ne!(on_disk, plaintext);
    }

    #[test]
    fn one_profile_cannot_open_anothers_sealed_blob() {
        // The F1 property, against the REAL DIGOP1 sealer: A's blob is sealed under A's
        // identity-derived DEK; B holds a different identity hence a different DEK, so the AEAD tag
        // rejects B's open. Isolation is cryptographic, not a filesystem convention.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = provisioner(&ids);
        let a = mgr.create_profile(&prov, named("Ada")).unwrap();
        let b = mgr.create_profile(&prov, named("Bob")).unwrap();

        let a_bytes = std::fs::read(
            dir.path()
                .join("profiles")
                .join(&a.did_hash)
                .join("identity.seal"),
        )
        .unwrap();

        // Both profiles are unlocked in the session, so the difference is purely the DEK.
        let sealer = KeystoreSealer::with_kdf(ids, KdfParams::FAST_TEST);
        assert!(
            sealer.open(&a.did, &a_bytes).is_ok(),
            "A opens its own blob"
        );
        assert!(
            matches!(sealer.open(&b.did, &a_bytes), Err(SealError::Open)),
            "B must not open A's blob"
        );
    }

    // --- edit ----------------------------------------------------------------------------------

    #[test]
    fn edit_updates_metadata_reseals_and_changes_the_smt_root() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(&ids), named("Ada"))
            .unwrap();

        let root_before = mgr.edit_profile(&record.did, |_| {}).unwrap();
        let root_after = mgr
            .edit_profile(&record.did, |m| {
                m.bio = Some("builds DIG".into());
                m.xch_address = None;
            })
            .unwrap();
        assert_ne!(root_before, root_after, "editing a field changes the root");

        // The edit is reflected in the sealed data and the cached display name.
        let reloaded = mgr.load_profile_data(&record.did).unwrap();
        assert_eq!(reloaded.metadata.bio.as_deref(), Some("builds DIG"));
        let cached = mgr.list().unwrap()[0].display_name.clone();
        assert_eq!(cached.as_deref(), Some("Ada"));
    }

    #[test]
    fn edit_can_change_the_cached_display_name() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(&ids), named("Ada"))
            .unwrap();

        mgr.edit_profile(&record.did, |m| m.display_name = Some("Ada L.".into()))
            .unwrap();
        assert_eq!(
            mgr.list().unwrap()[0].display_name.as_deref(),
            Some("Ada L.")
        );
    }

    // --- error paths ---------------------------------------------------------------------------

    #[test]
    fn provisioning_failure_surfaces_as_a_provision_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = KeygenProvisioner::new(ids, FailingMinter);
        let err = mgr.create_profile(&prov, named("Ada")).unwrap_err();
        assert!(matches!(err, ProfileError::Provision(_)));
        assert!(mgr.list().unwrap().is_empty());
    }

    #[test]
    fn a_non_canonical_did_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        let prov = KeygenProvisioner::new(ids, BadDidMinter);
        let err = mgr.create_profile(&prov, named("Ada")).unwrap_err();
        assert!(matches!(err, ProfileError::InvalidDid(_)));
    }

    #[test]
    fn creating_a_duplicate_did_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, ids) = harness(dir.path());
        // A minter that returns the SAME DID twice (distinct keys, but a clashing identity anchor).
        let prov = KeygenProvisioner::new(ids, FixedMinter);
        mgr.create_profile(&prov, named("Ada")).unwrap();
        let err = mgr.create_profile(&prov, named("Ada again")).unwrap_err();
        assert!(matches!(err, ProfileError::AlreadyExists(_)));
        assert_eq!(mgr.list().unwrap().len(), 1);
    }

    #[test]
    fn selecting_or_editing_an_unknown_profile_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = manager(dir.path());
        let missing = canonical_did([7; 32]);
        assert!(matches!(
            mgr.select_profile(&missing).unwrap_err(),
            ProfileError::NotFound(_)
        ));
        assert!(matches!(
            mgr.edit_profile(&missing, |_| {}).unwrap_err(),
            ProfileError::NotFound(_)
        ));
    }

    #[test]
    fn did_hash_is_stable_and_distinct_per_did() {
        let a = canonical_did([1; 32]);
        let b = canonical_did([2; 32]);
        assert_eq!(did_hash(&a), did_hash(&a));
        assert_ne!(did_hash(&a), did_hash(&b));
    }

    #[test]
    fn metadata_maps_onto_canonical_dig_identity_slots() {
        use dig_identity::slot::standard;
        let meta = ProfileMetadata {
            display_name: Some("Ada".into()),
            xch_address: None,
            ..ProfileMetadata::default()
        };
        let profile = meta.to_identity_profile(&[3; 32], &[4; 32]);
        assert_eq!(profile.display_name(), Some("Ada"));
        assert!(profile.get(standard::XCH_ADDRESS).is_none());
        let keys = profile.resolve_keys();
        assert_eq!(keys.signing_public_key, Some([3; 32]));
        assert_eq!(keys.encryption_public_key, Some([4; 32]));
    }

    /// Substring search over raw bytes (no `str` assumption on ciphertext).
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
