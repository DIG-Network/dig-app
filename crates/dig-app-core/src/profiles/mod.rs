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
pub mod identity_store;
pub mod keygen_provisioner;
pub mod keystore_sealer;
pub mod manager;
pub mod metadata;
pub mod provision;
pub mod sealer;

pub use data::{did_hash, ProfileData, ProfilePrefs, ProfileRecord, ProfileRegistry};
pub use error::ProfileError;
pub use identity_store::{IdentityStore, OsVaultFactory, RootUnlock, VaultFactory};
pub use keygen_provisioner::{DidMinter, HeldDidMinter, KeygenProvisioner, MintedDid};
pub use keystore_sealer::{KeystoreSealer, UnlockedIdentities};
pub use manager::ProfileManager;
pub use metadata::ProfileMetadata;
pub use provision::{ProfileProvisioner, ProvisionError, Provisioned, ProvisionedIdentity};
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
    use crate::profiles::identity_store::FileVaultFactory;
    use crate::profiles::provision::ProvisionError;
    use chia_sdk_utils::Address;
    use dig_identity::{Bytes32, Did};
    use dig_keystore::KdfParams;
    use std::cell::Cell;
    use std::path::Path;

    // --- Real U4/U6-backed harness ---------------------------------------------------------------
    //
    // These tests exercise the REAL sealer (`KeystoreSealer`, U4 DIGOP1 under each profile's
    // identity-derived DEK), the REAL key-generating provisioner (`KeygenProvisioner`), and the REAL
    // cross-session `IdentityStore` (U6) sealing each identity to a passphrase-backed file vault. The
    // only seam still stubbed is the on-chain DID mint (a wallet/engine spend, held on #771) —
    // supplied here by a `CountingMinter` that returns canonical `did:chia:` strings. So the crypto
    // under test is production crypto; only the chain interaction is faked.

    /// The root unlock every test seals identities under — a passphrase, since the file-backed test
    /// vault is the no-credential-store (Linux-style) custody path.
    const PW: &str = "correct horse battery staple";
    fn root() -> RootUnlock<'static> {
        RootUnlock::Passphrase(PW)
    }

    /// A [`DidMinter`] that returns a fresh canonical `did:chia:` per call — stands in for the
    /// wallet/engine on-chain mint (held on #771) without touching mainnet.
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

    /// A minter that always returns the SAME DID — for the duplicate-DID / F-1 clobber path.
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

    /// A manager over `dir` wired to a real [`KeystoreSealer`] and a real file-backed
    /// [`IdentityStore`] that SHARE one [`UnlockedIdentities`] session — the production wiring, with
    /// the cheap test KDF. Returns the manager plus the shared session (for direct seal/open checks).
    /// A second `harness` over the SAME `dir` models a process restart (a fresh, empty session).
    fn harness(dir: &Path) -> (ProfileManager<KeystoreSealer>, UnlockedIdentities) {
        let session = UnlockedIdentities::new();
        let sealer = KeystoreSealer::with_kdf(session.clone(), KdfParams::FAST_TEST);
        let store = IdentityStore::new(session.clone(), Box::new(FileVaultFactory));
        (
            ProfileManager::new(dir.to_path_buf(), sealer, store),
            session,
        )
    }

    fn manager(dir: &Path) -> ProfileManager<KeystoreSealer> {
        harness(dir).0
    }

    /// A real key-generating provisioner minting DIDs via a fresh [`CountingMinter`].
    fn provisioner() -> KeygenProvisioner<CountingMinter> {
        KeygenProvisioner::new(CountingMinter::default())
    }

    fn named(name: &str) -> ProfileMetadata {
        ProfileMetadata {
            display_name: Some(name.to_string()),
            ..ProfileMetadata::default()
        }
    }

    // --- create / list / active ------------------------------------------------------------------

    #[test]
    fn create_then_list_round_trips_both_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = provisioner();

        let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();

        let listed = mgr.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].did, a.did);
        assert_eq!(listed[1].did, b.did);
        assert_eq!(listed[0].display_name.as_deref(), Some("Ada"));
    }

    #[test]
    fn first_created_profile_becomes_active() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = provisioner();

        let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        mgr.create_profile(&prov, named("Bob"), root()).unwrap();

        // Creating more profiles does not steal the active pointer.
        assert_eq!(mgr.active_did().unwrap(), Some(a.did));
    }

    #[test]
    fn a_profile_binds_a_did_and_its_two_public_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(), named("Ada"), root())
            .unwrap();

        assert!(Did::parse(&record.did).is_some(), "DID is canonical");
        // 32 bytes rendered as 64 hex chars, and the two keys are distinct.
        assert_eq!(record.signing_public_key.len(), 64);
        assert_eq!(record.encryption_public_key.len(), 64);
        assert_ne!(record.signing_public_key, record.encryption_public_key);
        assert_eq!(record.paired_store_id.as_deref(), Some("store-1"));
    }

    // --- select / same-session persistence -------------------------------------------------------

    #[test]
    fn select_loads_the_profiles_own_data_and_persists_the_active_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = provisioner();
        let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();

        let data_b = mgr.select_profile(&b.did).unwrap();
        assert_eq!(data_b.metadata.display_name.as_deref(), Some("Bob"));
        assert!(data_b.prefs.auto_tip, "auto-tip defaults on");

        // Selecting A back loads A's own data, not B's.
        let data_a = mgr.select_profile(&a.did).unwrap();
        assert_eq!(data_a.metadata.display_name.as_deref(), Some("Ada"));
        assert_eq!(mgr.active_did().unwrap(), Some(a.did));
    }

    // --- cross-session persistence (the U6 core) -------------------------------------------------

    #[test]
    fn a_restarted_app_reopens_every_profile_after_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (a_did, b_did) = {
            let (mgr, _s) = harness(dir.path());
            let prov = provisioner();
            let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
            let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();
            (a.did, b.did)
        };

        // Restart: a brand-new manager + empty session over the same directory. Before unlocking,
        // the plaintext registry still lists both profiles, but neither is unlockable yet.
        let (restarted, session) = harness(dir.path());
        assert_eq!(restarted.list().unwrap().len(), 2);
        assert!(!session.is_unlocked(&a_did));
        assert!(
            restarted.select_profile(&a_did).is_err(),
            "sealed data cannot be opened before the root unlock"
        );

        // The user supplies the root unlock: every persisted identity is re-derived …
        assert_eq!(restarted.unlock_all(root()).unwrap(), 2);
        assert!(session.is_unlocked(&a_did) && session.is_unlocked(&b_did));

        // … so both profiles' sealed data opens again, each its own.
        assert_eq!(
            restarted
                .select_profile(&a_did)
                .unwrap()
                .metadata
                .display_name
                .as_deref(),
            Some("Ada")
        );
        assert_eq!(
            restarted
                .select_profile(&b_did)
                .unwrap()
                .metadata
                .display_name
                .as_deref(),
            Some("Bob")
        );
    }

    // --- single-profile re-unlock (the sign-path re-auth, dig_ecosystem#973) --------------------

    #[test]
    fn unlock_profile_reopens_only_the_named_profile_leaving_the_others_locked() {
        // The sign-path re-auth re-unlocks ONLY the profile about to sign, so a re-auth for A must
        // NOT repopulate B's DEK — B stays absent from the session (residency reduction, #973).
        let dir = tempfile::tempdir().unwrap();
        let (a_did, b_did) = {
            let (mgr, _s) = harness(dir.path());
            let prov = provisioner();
            let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
            let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();
            (a.did, b.did)
        };

        // Restart: a fresh manager + empty session over the same directory, nothing unlocked yet.
        let (restarted, session) = harness(dir.path());
        assert!(!session.is_unlocked(&a_did) && !session.is_unlocked(&b_did));

        // Re-unlock ONLY A — A opens, B stays locked.
        restarted.unlock_profile(&a_did, root()).unwrap();
        assert!(session.is_unlocked(&a_did), "the named profile is unlocked");
        assert!(
            !session.is_unlocked(&b_did),
            "the other profile stays locked — its DEK is never repopulated"
        );
        // A's own sealed data opens; B's still cannot (its key was never derived).
        assert!(restarted.select_profile(&a_did).is_ok());
        assert!(restarted.select_profile(&b_did).is_err());
    }

    #[test]
    fn unlock_profile_of_an_unknown_did_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        mgr.create_profile(&provisioner(), named("Ada"), root())
            .unwrap();
        assert!(matches!(
            mgr.unlock_profile("did:chia:absent", root()),
            Err(ProfileError::NotFound(_))
        ));
    }

    #[test]
    fn unlock_profile_with_a_wrong_root_unlock_fails_closed() {
        // A failed single-profile re-unlock leaves the profile locked (fail-closed → LOCKED, #973).
        let dir = tempfile::tempdir().unwrap();
        let did = {
            let (mgr, _s) = harness(dir.path());
            mgr.create_profile(&provisioner(), named("Ada"), root())
                .unwrap()
                .did
        };
        let (restarted, session) = harness(dir.path());
        assert!(matches!(
            restarted.unlock_profile(&did, RootUnlock::Passphrase("wrong")),
            Err(ProfileError::Persist(_))
        ));
        assert!(
            !session.is_unlocked(&did),
            "a failed re-unlock leaves the profile locked"
        );
    }

    #[test]
    fn unlock_all_with_a_wrong_root_unlock_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mgr, _s) = harness(dir.path());
            mgr.create_profile(&provisioner(), named("Ada"), root())
                .unwrap();
        }
        let (restarted, _s) = harness(dir.path());
        assert!(matches!(
            restarted.unlock_all(RootUnlock::Passphrase("wrong")),
            Err(ProfileError::Persist(_))
        ));
    }

    #[test]
    fn the_identity_is_sealed_at_rest_not_plaintext() {
        // NC-2: the persisted identity key material is DIGOP1 ciphertext on disk, never the raw key.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, session) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(), named("Ada"), root())
            .unwrap();

        let identity_file = dir
            .path()
            .join("profiles")
            .join(&record.did_hash)
            .join("identity.digop1");
        let on_disk = std::fs::read(&identity_file).unwrap();
        // The public key is known; assert the file is not the 64-byte raw secret layout by checking
        // the (public) signing key bytes do not appear — a proxy that the blob is sealed, not raw.
        let pk = session.signing_public_key(&record.did).unwrap();
        assert!(
            !contains(&on_disk, &pk),
            "identity file must be sealed, not raw key bytes"
        );
    }

    // --- at-rest sealing + cross-profile isolation (security-critical) ---------------------------

    #[test]
    fn per_profile_data_is_ciphertext_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(), named("SecretName"), root())
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
        // The isolation property, against the REAL DIGOP1 sealer: A's blob is sealed under A's
        // identity-derived DEK; B holds a different identity hence a different DEK, so the AEAD tag
        // rejects B's open. Isolation is cryptographic, not a filesystem convention.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, session) = harness(dir.path());
        let prov = provisioner();
        let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();

        let a_bytes = std::fs::read(
            dir.path()
                .join("profiles")
                .join(&a.did_hash)
                .join("identity.seal"),
        )
        .unwrap();

        // Both profiles are unlocked in the session, so the difference is purely the DEK.
        let sealer = KeystoreSealer::with_kdf(session, KdfParams::FAST_TEST);
        assert!(
            sealer.open(&a.did, &a_bytes).is_ok(),
            "A opens its own blob"
        );
        assert!(
            matches!(sealer.open(&b.did, &a_bytes), Err(SealError::Open)),
            "B must not open A's blob"
        );
    }

    #[test]
    fn cross_profile_isolation_survives_a_restart_and_reunlock() {
        // The isolation property must hold across persistence: after a restart re-unlocks BOTH
        // profiles from their sealed identities, A's re-derived DEK still cannot open B's blob.
        let dir = tempfile::tempdir().unwrap();
        let (a_did, b_did, a_hash) = {
            let (mgr, _s) = harness(dir.path());
            let prov = provisioner();
            let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
            let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();
            (a.did, b.did, a.did_hash)
        };

        let (restarted, session) = harness(dir.path());
        restarted.unlock_all(root()).unwrap();

        let a_bytes = std::fs::read(
            dir.path()
                .join("profiles")
                .join(&a_hash)
                .join("identity.seal"),
        )
        .unwrap();
        let sealer = KeystoreSealer::with_kdf(session, KdfParams::FAST_TEST);
        assert!(
            sealer.open(&a_did, &a_bytes).is_ok(),
            "A re-opens its own blob post-restart"
        );
        assert!(
            matches!(sealer.open(&b_did, &a_bytes), Err(SealError::Open)),
            "B's re-derived DEK still cannot open A's blob after a restart"
        );
    }

    // --- F-1: a duplicate DID must not clobber the existing profile ------------------------------

    #[test]
    fn a_duplicate_did_does_not_clobber_the_existing_profiles_identity() {
        // F-1 (from the U5 triple-gate): provisioning is side-effect free, and the manager validates
        // + dedup-checks the DID BEFORE committing the identity. So a second create that mints the
        // SAME DID is rejected WITHOUT touching the first profile's live session identity or its
        // sealed data — the first profile stays fully intact and openable.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, session) = harness(dir.path());
        let prov = KeygenProvisioner::new(FixedMinter);

        let first = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        let pk_before = session.signing_public_key(&first.did).unwrap();

        let err = mgr
            .create_profile(&prov, named("Mallory"), root())
            .unwrap_err();
        assert!(matches!(err, ProfileError::AlreadyExists(_)));

        // The existing profile's session identity is UNCHANGED (not overwritten by the dup attempt).
        assert_eq!(session.signing_public_key(&first.did).unwrap(), pk_before);
        // And its sealed data still opens and still says "Ada", never "Mallory".
        assert_eq!(
            mgr.select_profile(&first.did)
                .unwrap()
                .metadata
                .display_name
                .as_deref(),
            Some("Ada")
        );
        assert_eq!(mgr.list().unwrap().len(), 1);
    }

    // --- configurable default profile (#986 SG-0) ------------------------------------------------

    #[test]
    fn default_did_falls_back_to_the_first_profile_when_unset() {
        // Unset default → the first profile (creation order) is the sensible fallback, even before
        // the user selects an active one.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = provisioner();
        let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        mgr.create_profile(&prov, named("Bob"), root()).unwrap();

        assert_eq!(mgr.default_did().unwrap(), Some(a.did));
    }

    #[test]
    fn default_did_is_none_with_no_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = manager(dir.path());
        assert_eq!(mgr.default_did().unwrap(), None);
    }

    #[test]
    fn set_default_did_persists_and_round_trips_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (b_did, a_did) = {
            let (mgr, _s) = harness(dir.path());
            let prov = provisioner();
            let a = mgr.create_profile(&prov, named("Ada"), root()).unwrap();
            let b = mgr.create_profile(&prov, named("Bob"), root()).unwrap();
            // Default to Bob even though Ada is active + first — the user's choice wins.
            mgr.set_default_did(&b.did).unwrap();
            assert_eq!(mgr.default_did().unwrap().as_ref(), Some(&b.did));
            (b.did, a.did)
        };

        // A restarted app (fresh manager over the same dir) still reports the persisted default,
        // without any profile being unlocked (the default lives in the plaintext registry).
        let (restarted, _s) = harness(dir.path());
        assert_eq!(restarted.default_did().unwrap(), Some(b_did));
        assert_eq!(restarted.active_did().unwrap(), Some(a_did));
    }

    #[test]
    fn set_default_did_rejects_an_unknown_profile() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        mgr.create_profile(&provisioner(), named("Ada"), root())
            .unwrap();
        let missing = canonical_did([7; 32]);
        assert!(matches!(
            mgr.set_default_did(&missing).unwrap_err(),
            ProfileError::NotFound(_)
        ));
        // The rejected set left no default behind (it falls back, not to the bad DID).
        assert_ne!(
            mgr.default_did().unwrap().as_deref(),
            Some(missing.as_str())
        );
    }

    #[test]
    fn a_stale_default_falls_back_instead_of_returning_a_gone_profile() {
        // If the configured default no longer names a known profile (e.g. hand-edited registry or a
        // future removal), resolution ignores it and falls back rather than returning a dangling DID.
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let a = mgr
            .create_profile(&provisioner(), named("Ada"), root())
            .unwrap();

        // Point the default at a DID that was never created, by editing the plaintext registry on
        // disk directly (a hand-edit / a future removal that stranded the pointer).
        let ghost = canonical_did([42; 32]);
        let registry_path = dir.path().join("profiles").join("registry.json");
        let mut registry: ProfileRegistry =
            serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
        registry.default = Some(ghost.clone());
        std::fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
        // The stale default is ignored; the fallback (the only real profile) is returned.
        assert_eq!(mgr.default_did().unwrap(), Some(a.did));
    }

    // --- edit ------------------------------------------------------------------------------------

    #[test]
    fn edit_updates_metadata_reseals_and_changes_the_smt_root() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(), named("Ada"), root())
            .unwrap();

        let root_before = mgr.edit_profile(&record.did, |_| {}).unwrap();
        let root_after = mgr
            .edit_profile(&record.did, |m| {
                m.bio = Some("builds DIG".into());
                m.xch_address = None;
            })
            .unwrap();
        assert_ne!(root_before, root_after, "editing a field changes the root");

        let reloaded = mgr.load_profile_data(&record.did).unwrap();
        assert_eq!(reloaded.metadata.bio.as_deref(), Some("builds DIG"));
        let cached = mgr.list().unwrap()[0].display_name.clone();
        assert_eq!(cached.as_deref(), Some("Ada"));
    }

    #[test]
    fn edit_can_change_the_cached_display_name() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let record = mgr
            .create_profile(&provisioner(), named("Ada"), root())
            .unwrap();

        mgr.edit_profile(&record.did, |m| m.display_name = Some("Ada L.".into()))
            .unwrap();
        assert_eq!(
            mgr.list().unwrap()[0].display_name.as_deref(),
            Some("Ada L.")
        );
    }

    // --- error paths -----------------------------------------------------------------------------

    #[test]
    fn provisioning_failure_surfaces_as_a_provision_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = KeygenProvisioner::new(FailingMinter);
        let err = mgr.create_profile(&prov, named("Ada"), root()).unwrap_err();
        assert!(matches!(err, ProfileError::Provision(_)));
        assert!(mgr.list().unwrap().is_empty());
    }

    #[test]
    fn a_non_canonical_did_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = KeygenProvisioner::new(BadDidMinter);
        let err = mgr.create_profile(&prov, named("Ada"), root()).unwrap_err();
        assert!(matches!(err, ProfileError::InvalidDid(_)));
        // Nothing was persisted or listed for the rejected DID.
        assert!(mgr.list().unwrap().is_empty());
    }

    #[test]
    fn creating_a_duplicate_did_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _s) = harness(dir.path());
        let prov = KeygenProvisioner::new(FixedMinter);
        mgr.create_profile(&prov, named("Ada"), root()).unwrap();
        let err = mgr
            .create_profile(&prov, named("Ada again"), root())
            .unwrap_err();
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
