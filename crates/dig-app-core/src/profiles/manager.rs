//! The profile manager — create / select / list / edit multi-DID profiles, persisting each
//! profile's identity and secret-bearing state sealed at rest under its own DEK, and re-unlocking
//! every profile on boot so a restarted app can reopen its data (U5 + U6).
//!
//! [`ProfileManager`] is the security-critical heart of the profile layer. It owns the on-disk
//! layout (the plaintext registry + the per-profile sealed blobs) and delegates all crypto to the
//! seams around it: per-profile data sealing to [`ProfileSealer`] (U4), identity minting +
//! key-generation to [`ProfileProvisioner`] (U4 + wallet/engine), and cross-session identity
//! persistence + re-unlock to [`IdentityStore`] (U6). It never *retains* a private key — the freshly
//! provisioned secret material passes straight through [`create_profile`](ProfileManager::create_profile)
//! into the identity store — and never seals with a shared key: every per-profile blob is sealed
//! under that profile's own DEK, so profiles are cryptographically isolated from one another on disk
//! and stay isolated across a restart (SPEC §3.1/§3.2, §10 tests 2–3).

use std::path::PathBuf;

use dig_identity::Did;

use crate::profiles::data::{did_hash, ProfileData, ProfileRecord, ProfileRegistry};
use crate::profiles::error::{ProfileError, Result};
use crate::profiles::identity_store::{IdentityStore, RootUnlock};
use crate::profiles::metadata::ProfileMetadata;
use crate::profiles::provision::ProfileProvisioner;
use crate::profiles::sealer::ProfileSealer;

/// The subdirectory under the brand data dir that holds all profile state.
const PROFILES_SUBDIR: &str = "profiles";
/// The plaintext registry file name (the profile list + active pointer).
const REGISTRY_FILE: &str = "registry.json";
/// The sealed per-profile identity/data blob file name.
const SEAL_FILE: &str = "identity.seal";

/// Manages the user's profiles under a resolved brand data directory.
///
/// Generic over its [`ProfileSealer`] so the run-time crypto (U4's keystore) and a test fake are
/// interchangeable without reshaping the manager. It also owns an [`IdentityStore`] — the
/// cross-session persistence collaborator (U6) that seals each profile's identity at rest and
/// re-unlocks it on boot. The sealer and the identity store share one [`UnlockedIdentities`](crate::profiles::UnlockedIdentities) session
/// (the manager's caller wires them to the same session), so an identity the store unlocks is
/// immediately usable to seal/open that profile's data.
pub struct ProfileManager<S: ProfileSealer> {
    brand_dir: PathBuf,
    sealer: S,
    identities: IdentityStore,
}

impl<S: ProfileSealer> ProfileManager<S> {
    /// Builds a manager over `brand_dir` (the per-user AppData root, [`crate::storage`]) using
    /// `sealer` for per-profile data sealing and `identities` for cross-session identity
    /// persistence + re-unlock. Both MUST share the same [`UnlockedIdentities`](crate::profiles::UnlockedIdentities) session.
    pub fn new(brand_dir: impl Into<PathBuf>, sealer: S, identities: IdentityStore) -> Self {
        Self {
            brand_dir: brand_dir.into(),
            sealer,
            identities,
        }
    }

    /// Lists every known profile (non-secret records), in creation order. Reads only the plaintext
    /// registry — no profile need be unlocked.
    pub fn list(&self) -> Result<Vec<ProfileRecord>> {
        Ok(self.load_registry()?.profiles)
    }

    /// The DID of the active profile, if one is selected.
    pub fn active_did(&self) -> Result<Option<String>> {
        Ok(self.load_registry()?.active)
    }

    /// The DID of the profile presented by DEFAULT — the user's persisted preferred identity (the one
    /// the social selector and "primary identity" surfaces default to).
    ///
    /// Resolves in a fixed precedence so a caller always gets a sensible answer while any profile
    /// exists:
    ///
    /// 1. the explicitly-configured default, IF it still names a known profile (a stale default —
    ///    e.g. the chosen profile was since removed — is ignored, never returned);
    /// 2. otherwise the active profile, if one is selected and known;
    /// 3. otherwise the first profile in creation order;
    /// 4. `None` only when no profile exists at all.
    pub fn default_did(&self) -> Result<Option<String>> {
        let registry = self.load_registry()?;
        Ok(Self::resolve_default(&registry))
    }

    /// Resolves the default DID from a loaded registry (the precedence documented on
    /// [`default_did`](Self::default_did)), pure so the fallback logic is directly testable.
    fn resolve_default(registry: &ProfileRegistry) -> Option<String> {
        registry
            .default
            .as_deref()
            .filter(|did| registry.find(did).is_some())
            .or(registry
                .active
                .as_deref()
                .filter(|did| registry.find(did).is_some()))
            .map(str::to_string)
            .or_else(|| registry.profiles.first().map(|p| p.did.clone()))
    }

    /// Sets `did` as the user's configured default profile and persists it.
    ///
    /// The DID MUST name an existing profile — setting a default the user cannot present would be a
    /// silent no-op, so an unknown DID is rejected with [`ProfileError::NotFound`] and nothing is
    /// written.
    pub fn set_default_did(&self, did: &str) -> Result<()> {
        let mut registry = self.load_registry()?;
        if registry.find(did).is_none() {
            tracing::warn!(did, "set default rejected: no such profile");
            return Err(ProfileError::NotFound(did.to_string()));
        }
        registry.default = Some(did.to_string());
        self.save_registry(&registry)?;
        tracing::info!(did, "default profile changed");
        Ok(())
    }

    /// Creates a new profile: provisions an identity (mint DID + generate keys via the seam),
    /// persists that identity sealed at rest and unlocks it, seals its initial [`ProfileData`] under
    /// the new profile's DEK, records it, and — when it is the first profile — makes it active.
    ///
    /// `root` is the user's root unlock ([`RootUnlock`]) under which the identity is sealed at rest,
    /// so a later restart can re-open it ([`unlock_all`](Self::unlock_all)).
    ///
    /// # Ordering is security-critical (the F-1 property)
    ///
    /// The DID is validated (canonical) and checked for a duplicate BEFORE the provisioned identity
    /// is persisted or registered as unlocked. `provision` is side-effect-free ([`ProfileProvisioner`]),
    /// so a rejected DID drops the freshly generated secrets untouched — creation can never clobber
    /// an existing profile's sealed data or its live in-session identity. If sealing the initial data
    /// or saving the registry then fails, the just-committed identity is rolled back
    /// ([`IdentityStore::forget`]) so no half-created profile is left behind.
    pub fn create_profile(
        &self,
        provisioner: &dyn ProfileProvisioner,
        metadata: ProfileMetadata,
        root: RootUnlock<'_>,
    ) -> Result<ProfileRecord> {
        let provisioned = provisioner
            .provision()
            .map_err(|e| ProfileError::Provision(e.to_string()))?;
        let identity = &provisioned.identity;

        // Validate BEFORE committing anything: a bad or duplicate DID returns here, dropping
        // `provisioned` (and zeroizing its secrets) without touching persisted or session state.
        if Did::parse(&identity.did).is_none() {
            tracing::warn!(did = %identity.did, "profile creation rejected: invalid DID");
            return Err(ProfileError::InvalidDid(identity.did.clone()));
        }
        let mut registry = self.load_registry()?;
        if registry.find(&identity.did).is_some() {
            tracing::warn!(did = %identity.did, "profile creation rejected: DID already exists");
            return Err(ProfileError::AlreadyExists(identity.did.clone()));
        }

        let did = identity.did.clone();
        let hash = did_hash(&did);
        let record = ProfileRecord {
            did: did.clone(),
            did_hash: hash.clone(),
            signing_public_key: hex::encode(identity.signing_public_key),
            paired_store_id: identity.paired_store_id.clone(),
            display_name: metadata.display_name.clone(),
        };

        // Commit the identity (seal at rest + unlock) now that the DID is validated + unique. From
        // here on, any failure rolls the identity back so creation is all-or-nothing.
        let profile_dir = self.profile_dir(&hash);
        self.identities
            .persist_and_unlock(&did, &hash, &profile_dir, provisioned.secrets, root)?;

        let data = ProfileData {
            metadata,
            ..ProfileData::default()
        };
        if let Err(e) = self.seal_and_write(&did, &hash, &data).and_then(|()| {
            if registry.active.is_none() {
                registry.active = Some(did.clone());
            }
            registry.profiles.push(record.clone());
            self.save_registry(&registry)
        }) {
            // Roll back the sealed + unlocked identity so a failed create leaves nothing dangling.
            tracing::warn!(did = %did, error = %e, "profile creation failed — rolling back identity");
            let _ = self.identities.forget(&did, &hash, &profile_dir);
            return Err(e);
        }
        tracing::info!(did = %did, did_hash = %hash, "profile created");
        Ok(record)
    }

    /// Re-unlocks every profile's persisted identity into the session, so a restarted app can open
    /// all of its sealed data once the user supplies the root unlock (U6 boot path).
    ///
    /// Reads the plaintext registry (no unlock needed to enumerate), then re-derives each profile's
    /// identity from its sealed material under `root`. Returns how many profiles were unlocked. Fails
    /// closed on a bad root unlock (a wrong passphrase surfaces the opaque unlock error); profiles
    /// unlocked before the failing one stay unlocked, since each profile's identity is independent.
    pub fn unlock_all(&self, root: RootUnlock<'_>) -> Result<usize> {
        let registry = self.load_registry()?;
        let mut unlocked = 0;
        for record in &registry.profiles {
            let profile_dir = self.profile_dir(&record.did_hash);
            self.identities
                .unlock_persisted(&record.did, &record.did_hash, &profile_dir, root)
                .map_err(|e| {
                    // NEVER log the root unlock secret — only which profile failed and how many
                    // preceding ones already succeeded (each profile's identity is independent).
                    tracing::warn!(did = %record.did, unlocked_so_far = unlocked, error = %e, "profile re-unlock failed");
                    e
                })?;
            unlocked += 1;
        }
        tracing::info!(profiles_unlocked = unlocked, "boot re-unlock complete");
        Ok(unlocked)
    }

    /// Re-unlocks a SINGLE profile's persisted identity into the session — the sign-path re-auth
    /// path (dig_ecosystem#973), which needs ONLY the profile about to sign, not every profile's DEK.
    ///
    /// Unlike [`unlock_all`](Self::unlock_all), this re-derives just the identity for `did` from its
    /// sealed material under `root`, leaving every other profile locked (its DEK stays absent from the
    /// session) — the smallest key residency that authorizes the sign. Fails closed (the profile stays
    /// locked) on a bad root unlock, a tampered blob, or a DID no profile owns.
    pub fn unlock_profile(&self, did: &str, root: RootUnlock<'_>) -> Result<()> {
        let registry = self.load_registry()?;
        let record = registry
            .find(did)
            .ok_or_else(|| ProfileError::NotFound(did.to_string()))?;
        let profile_dir = self.profile_dir(&record.did_hash);
        self.identities
            .unlock_persisted(&record.did, &record.did_hash, &profile_dir, root)
            .map_err(|e| {
                // NEVER log the root unlock secret — only which profile failed to re-unlock.
                tracing::warn!(did = %record.did, error = %e, "single-profile re-unlock failed");
                e
            })?;
        tracing::info!(did = %record.did, "single-profile re-unlock complete");
        Ok(())
    }

    /// Selects `did` as the active profile and loads its sealed data into memory.
    ///
    /// The blob is opened *before* the active pointer is persisted, so a profile whose DEK cannot
    /// open its data never becomes the active profile.
    pub fn select_profile(&self, did: &str) -> Result<ProfileData> {
        let mut registry = self.load_registry()?;
        if registry.find(did).is_none() {
            tracing::warn!(did, "profile select rejected: not found");
            return Err(ProfileError::NotFound(did.to_string()));
        }
        let data = self.load_profile_data(did)?;
        registry.active = Some(did.to_string());
        self.save_registry(&registry)?;
        tracing::info!(did, "active profile changed");
        Ok(data)
    }

    /// Opens and deserializes a profile's sealed data. Requires the profile's DEK (via the sealer);
    /// opening under any other profile's DEK fails with [`ProfileError::Seal`] — the cross-profile
    /// isolation boundary.
    pub fn load_profile_data(&self, did: &str) -> Result<ProfileData> {
        let path = self.seal_path(&did_hash(did));
        let ciphertext = std::fs::read(&path)?;
        // `plaintext` is a zeroizing buffer (F-3): the decrypted profile content is scrubbed from
        // memory when it drops at the end of this call, right after deserialization.
        let plaintext = self.sealer.open(did, &ciphertext)?;
        Ok(serde_json::from_slice(&plaintext[..])?)
    }

    /// Edits a profile's persona metadata in place, re-seals the updated data, refreshes the cached
    /// display name, and returns the new dig-identity SMT root the edit produces.
    ///
    /// The returned root is the canonical on-chain representation ([`ProfileMetadata::to_identity_profile`]);
    /// broadcasting the SMT write on-chain (chip35 delegation) is the wallet/engine seam and is NOT
    /// done here — U5 keeps the authoritative local cache and computes the root the write will use.
    pub fn edit_profile(
        &self,
        did: &str,
        edit: impl FnOnce(&mut ProfileMetadata),
    ) -> Result<[u8; 32]> {
        let mut registry = self.load_registry()?;
        let record = registry
            .find(did)
            .ok_or_else(|| ProfileError::NotFound(did.to_string()))?
            .clone();

        let mut data = self.load_profile_data(did)?;
        edit(&mut data.metadata);
        self.seal_and_write(did, &record.did_hash, &data)?;

        if let Some(stored) = registry.find_mut(did) {
            stored.display_name = data.metadata.display_name.clone();
        }
        self.save_registry(&registry)?;

        let signing = decode_key(&record.signing_public_key)?;
        data.metadata
            .to_identity_profile(&signing)
            .build_root()
            .map_err(|e| ProfileError::Identity(e.to_string()))
    }

    /// Seals `data` under `did`'s DEK and writes it to the profile's own directory, creating the
    /// directory (owner-restricted) if needed.
    fn seal_and_write(&self, did: &str, hash: &str, data: &ProfileData) -> Result<()> {
        let dir = self.profile_dir(hash);
        std::fs::create_dir_all(&dir)?;
        crate::storage::restrict_to_owner(&dir)?;

        let plaintext = serde_json::to_vec(data)?;
        let ciphertext = self.sealer.seal(did, &plaintext)?;
        let path = dir.join(SEAL_FILE);
        let temp_path = path.with_extension("tmp");
        crate::storage::write_durably(&path, &temp_path, &ciphertext)?;
        crate::storage::restrict_to_owner(&path)?;
        Ok(())
    }

    /// Loads the plaintext registry; a missing file yields an empty registry (a fresh install).
    fn load_registry(&self) -> Result<ProfileRegistry> {
        let path = self.registry_path();
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProfileRegistry::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persists the plaintext registry durably and atomically, creating the profiles directory if
    /// needed.
    ///
    /// The registry is the ONLY pointer to every profile's DID + directory. A torn write — a crash
    /// or power loss partway through overwriting it — would otherwise strand every sealed blob (the
    /// data survives, but the app can no longer find or list it). [`crate::storage::write_durably`]
    /// writes a temp file, fsyncs it, then renames it over the registry, so a reader (or a
    /// recovering process) only ever sees the complete old registry or the complete new one —
    /// never a half-written one.
    fn save_registry(&self, registry: &ProfileRegistry) -> Result<()> {
        let path = self.registry_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp_path = path.with_extension("tmp");
        crate::storage::write_durably(&path, &temp_path, &serde_json::to_vec_pretty(registry)?)?;
        Ok(())
    }

    fn registry_path(&self) -> PathBuf {
        self.brand_dir.join(PROFILES_SUBDIR).join(REGISTRY_FILE)
    }

    fn profile_dir(&self, hash: &str) -> PathBuf {
        self.brand_dir.join(PROFILES_SUBDIR).join(hash)
    }

    fn seal_path(&self, hash: &str) -> PathBuf {
        self.profile_dir(hash).join(SEAL_FILE)
    }
}

/// Decodes a stored lowercase-hex 48-byte BLS12-381 G1 identity public key.
fn decode_key(hex_key: &str) -> Result<[u8; 48]> {
    let bytes =
        hex::decode(hex_key).map_err(|e| ProfileError::Identity(format!("bad key hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ProfileError::Identity("public key is not 48 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    /// The registry save path routes through the shared [`crate::storage::write_durably`] helper;
    /// this asserts the manager's usage still gets the atomic-replace / no-temp-left contract the
    /// helper's own test suite (`storage::tests`) covers in full.
    #[test]
    fn registry_save_path_replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let temp_path = path.with_extension("tmp");

        crate::storage::write_durably(&path, &temp_path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(
            !temp_path.exists(),
            "the temp file must be renamed away, not left behind"
        );

        // Overwriting fully replaces the previous content (no torn append / stale tail) and again
        // leaves no temp file — the property that keeps a crash mid-save from stranding profiles.
        crate::storage::write_durably(&path, &temp_path, b"second-longer-then-shorter").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-longer-then-shorter");
        crate::storage::write_durably(&path, &temp_path, b"third").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        assert!(!temp_path.exists());
    }
}
