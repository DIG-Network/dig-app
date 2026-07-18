//! The profile manager — create / select / list / edit multi-DID profiles, persisting each
//! profile's secret-bearing state sealed at rest under its own DEK.
//!
//! [`ProfileManager`] is the security-critical heart of U5. It owns the on-disk layout (the
//! plaintext registry + the per-profile sealed blobs) and delegates all crypto to the
//! [`ProfileSealer`] seam (U4) and all identity minting to the [`ProfileProvisioner`] seam
//! (U4 + wallet/engine). It never holds a private key and never seals with a shared key — every
//! per-profile blob is sealed under that profile's own DEK, so profiles are cryptographically
//! isolated from one another on disk (SPEC §3.1, §10 tests 2–3).

use std::path::{Path, PathBuf};

use dig_identity::Did;

use crate::profiles::data::{did_hash, ProfileData, ProfileRecord, ProfileRegistry};
use crate::profiles::error::{ProfileError, Result};
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
/// interchangeable without reshaping the manager.
pub struct ProfileManager<S: ProfileSealer> {
    brand_dir: PathBuf,
    sealer: S,
}

impl<S: ProfileSealer> ProfileManager<S> {
    /// Builds a manager over `brand_dir` (the per-user AppData root, [`crate::storage`]) using
    /// `sealer` for all at-rest sealing.
    pub fn new(brand_dir: impl Into<PathBuf>, sealer: S) -> Self {
        Self {
            brand_dir: brand_dir.into(),
            sealer,
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

    /// Creates a new profile: provisions an identity (mint DID + generate keys via the seam),
    /// records it, seals its initial [`ProfileData`] under the new profile's DEK, and — when it is
    /// the first profile — makes it active.
    ///
    /// Fails if the provisioner returns a non-canonical DID or a DID that already has a profile, so
    /// creation can never clobber an existing profile's sealed data.
    pub fn create_profile(
        &self,
        provisioner: &dyn ProfileProvisioner,
        metadata: ProfileMetadata,
    ) -> Result<ProfileRecord> {
        let identity = provisioner
            .provision()
            .map_err(|e| ProfileError::Provision(e.to_string()))?;

        if Did::parse(&identity.did).is_none() {
            return Err(ProfileError::InvalidDid(identity.did));
        }

        let mut registry = self.load_registry()?;
        if registry.find(&identity.did).is_some() {
            return Err(ProfileError::AlreadyExists(identity.did));
        }

        let hash = did_hash(&identity.did);
        let data = ProfileData {
            metadata,
            ..ProfileData::default()
        };
        self.seal_and_write(&identity.did, &hash, &data)?;

        let record = ProfileRecord {
            did: identity.did.clone(),
            did_hash: hash,
            signing_public_key: hex::encode(identity.signing_public_key),
            encryption_public_key: hex::encode(identity.encryption_public_key),
            paired_store_id: identity.paired_store_id,
            display_name: data.metadata.display_name.clone(),
        };

        if registry.active.is_none() {
            registry.active = Some(identity.did);
        }
        registry.profiles.push(record.clone());
        self.save_registry(&registry)?;
        Ok(record)
    }

    /// Selects `did` as the active profile and loads its sealed data into memory.
    ///
    /// The blob is opened *before* the active pointer is persisted, so a profile whose DEK cannot
    /// open its data never becomes the active profile.
    pub fn select_profile(&self, did: &str) -> Result<ProfileData> {
        let mut registry = self.load_registry()?;
        if registry.find(did).is_none() {
            return Err(ProfileError::NotFound(did.to_string()));
        }
        let data = self.load_profile_data(did)?;
        registry.active = Some(did.to_string());
        self.save_registry(&registry)?;
        Ok(data)
    }

    /// Opens and deserializes a profile's sealed data. Requires the profile's DEK (via the sealer);
    /// opening under any other profile's DEK fails with [`ProfileError::Seal`] — the cross-profile
    /// isolation boundary.
    pub fn load_profile_data(&self, did: &str) -> Result<ProfileData> {
        let path = self.seal_path(&did_hash(did));
        let ciphertext = std::fs::read(&path)?;
        let plaintext = self.sealer.open(did, &ciphertext)?;
        Ok(serde_json::from_slice(&plaintext)?)
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
        let encryption = decode_key(&record.encryption_public_key)?;
        data.metadata
            .to_identity_profile(&signing, &encryption)
            .build_root()
            .map_err(|e| ProfileError::Identity(e.to_string()))
    }

    /// Seals `data` under `did`'s DEK and writes it to the profile's own directory, creating the
    /// directory (owner-restricted) if needed.
    fn seal_and_write(&self, did: &str, hash: &str, data: &ProfileData) -> Result<()> {
        let dir = self.profile_dir(hash);
        std::fs::create_dir_all(&dir)?;
        restrict_to_owner(&dir)?;

        let plaintext = serde_json::to_vec(data)?;
        let ciphertext = self.sealer.seal(did, &plaintext)?;
        let path = dir.join(SEAL_FILE);
        write_durably(&path, &ciphertext)?;
        restrict_to_owner(&path)?;
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
    /// data survives, but the app can no longer find or list it). [`write_durably`] writes a temp
    /// file, fsyncs it, then renames it over the registry, so a reader (or a recovering process)
    /// only ever sees the complete old registry or the complete new one — never a half-written one.
    fn save_registry(&self, registry: &ProfileRegistry) -> Result<()> {
        let path = self.registry_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_durably(&path, &serde_json::to_vec_pretty(registry)?)?;
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

/// Writes `bytes` to `path` durably and atomically: write a sibling temp file, fsync it, rename it
/// over `path`, then fsync the parent directory so the rename itself is durable.
///
/// The rename gives atomicity — a concurrent reader or a process recovering after a crash sees
/// either the whole previous file or the whole new one, never a truncated mix. The fsyncs give
/// durability so the bytes survive a power loss immediately after the call. This mirrors the
/// keystore vault's sealed-file write, so every security-critical file in dig-app is written the
/// same crash-safe way.
fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let temp_path = path.with_extension("tmp");
    let mut temp = std::fs::File::create(&temp_path)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.sync_all()?;
    drop(temp);

    std::fs::rename(&temp_path, path)?;

    // fsync the parent directory so the rename (the directory entry) is itself durable. Only
    // meaningful — and only permitted — on Unix; Windows handles rename-metadata durability itself.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Decodes a stored lowercase-hex 32-byte public key.
fn decode_key(hex_key: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_key).map_err(|e| ProfileError::Identity(format!("bad key hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ProfileError::Identity("public key is not 32 bytes".to_string()))
}

/// Restricts a profile path to the owning user (mode `0700`/`0600` on Unix).
///
/// On Windows the per-user ACL is applied by the OS-integration layer (U4/installer); the
/// `%LOCALAPPDATA%` root is already per-user, so this is a no-op there.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_durably_replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let temp_path = path.with_extension("tmp");

        write_durably(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(
            !temp_path.exists(),
            "the temp file must be renamed away, not left behind"
        );

        // Overwriting fully replaces the previous content (no torn append / stale tail) and again
        // leaves no temp file — the property that keeps a crash mid-save from stranding profiles.
        write_durably(&path, b"second-longer-then-shorter").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-longer-then-shorter");
        write_durably(&path, b"third").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        assert!(!temp_path.exists());
    }
}
