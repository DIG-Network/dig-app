//! Per-user AppData layout (NC-2 / NC-3).
//!
//! All user-facing data lives in the interactive user's per-OS application-data directory, in a
//! per-profile subdirectory keyed by the profile's DID, and is **sealed at rest** to the user key
//! (dig-keystore DIGOP1 — see [`crate::keystore`]). This satisfies **NC-3** (data in the user's
//! AppData) and **NC-2** (encrypted at rest to the user key) — see the `normative-contract` skill.
//!
//! The brand directory per OS:
//! - Windows — `%LOCALAPPDATA%\DigNetwork`
//! - macOS   — `~/Library/Application Support/DigNetwork`
//! - Linux   — `$XDG_DATA_HOME/dignetwork`
//!
//! **`.dig` content-cache exemption (§5.1):** the on-chain-anchored public content cache is NOT
//! sealed and does NOT live here — the identity-agnostic engine owns it in an explicit machine
//! cache directory (plaintext, SYSTEM-write-restricted). Only identity / wallet / subscriptions /
//! config / profile-metadata are sealed under this layout.

use crate::{Error, Os, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Derives the per-profile AppData directory key from a profile's DID: lowercase-hex `sha256(did)`.
/// Stable and filesystem-safe, so `<brand>/profiles/<did-hash>/` isolates each profile's blobs on
/// disk regardless of how exotic the DID string is.
pub fn did_hash(did: &str) -> String {
    hex::encode(Sha256::digest(did.as_bytes()))
}

/// The canonical brand directory segment shared across every OS (never drift this literal — it is
/// the on-disk namespace every DIG user-app install shares).
pub const BRAND_DIR: &str = "DigNetwork";

/// The Linux brand directory segment (lowercased per XDG convention).
pub const BRAND_DIR_XDG: &str = "dignetwork";

/// Resolve the per-user brand data directory for `os`, given the relevant environment root:
/// `%LOCALAPPDATA%` on Windows, `$HOME` on macOS, `$XDG_DATA_HOME` on Linux.
///
/// The environment root is supplied by the caller (resolved from the real environment at the app
/// edge) so this function stays pure. An empty root yields [`Error::MissingEnv`], because a
/// user-app with nowhere to put the user's sealed data must fail loudly rather than write to a
/// surprising location.
pub fn brand_data_dir(os: Os, env_root: &str) -> Result<PathBuf> {
    if env_root.is_empty() {
        return Err(Error::MissingEnv {
            what: "the user AppData directory",
            var: match os {
                Os::Windows => "LOCALAPPDATA",
                Os::MacOs => "HOME",
                Os::Linux => "XDG_DATA_HOME",
            },
        });
    }
    let base = PathBuf::from(env_root);
    Ok(match os {
        Os::Windows => base.join(BRAND_DIR),
        Os::MacOs => base
            .join("Library")
            .join("Application Support")
            .join(BRAND_DIR),
        Os::Linux => base.join(BRAND_DIR_XDG),
    })
}

/// The per-profile subdirectory under the brand data directory, keyed by the profile's DID hash.
///
/// Profiles never share a directory (nor a data-encryption key — see [`crate::keystore`]), so a
/// per-profile subdir keyed by the DID hash keeps each profile's sealed blobs isolated on disk.
pub fn profile_dir(brand_dir: &std::path::Path, did_hash: &str) -> PathBuf {
    brand_dir.join("profiles").join(did_hash)
}

/// Writes `bytes` to `final_path` durably and atomically: create `temp_path` (a sibling temp file
/// the caller names), write + flush + `fsync` it, rename it over `final_path`, then `fsync` the
/// parent directory so the rename itself is durable.
///
/// This is the ONE crash-safe write idiom for every security-critical file dig-app persists (the
/// keystore's sealed identity blob, the profile registry, a sealed profile data blob) — the two
/// call sites used to duplicate it byte-for-byte before this extraction. The contract:
///
/// - **Atomicity** — the rename means a concurrent reader, or a process recovering after a crash,
///   only ever observes the complete previous file or the complete new one, never a half-written
///   or truncated mix.
/// - **Durability** — the two `fsync`s put the bytes (and, via the parent-dir fsync, the rename's
///   directory-entry update) on stable storage before the call returns, so the write survives a
///   crash/power-loss immediately after.
/// - **Confidentiality of the write-in-progress** — on Unix the temp file is created with mode
///   `0600` (owner-only) from the moment it exists, so the window between "temp file created" and
///   "renamed into place" never exposes a world/group-readable copy of security-critical bytes
///   (identity keys, sealed profile data). `final_path`'s own permissions are unaffected by the
///   rename and remain the caller's responsibility to set/assert.
///
/// Parent-directory `fsync` is skipped on Windows: it cannot open a directory handle for `fsync`,
/// and rename-metadata durability there is handled by the filesystem itself.
pub fn write_durably(final_path: &Path, temp_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    let mut temp = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(temp_path)?
    };
    #[cfg(not(unix))]
    let mut temp = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp_path)?;

    temp.write_all(bytes)?;
    temp.flush()?;
    temp.sync_all()?;
    drop(temp);

    std::fs::rename(temp_path, final_path)?;

    #[cfg(unix)]
    if let Some(parent) = final_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Restrict `path` to the owning user: `0700` for a directory, `0600` for a file, on Unix. This is
/// the ONE place the per-user restriction policy lives, shared by every security-critical directory
/// or file dig-app creates (the sealed profile blobs, the APP-SIGN persistence dirs).
///
/// On Windows it is a no-op: the `%LOCALAPPDATA%` root is already per-user ACL'd, and the per-user
/// ACL is applied by the OS-integration layer (installer) rather than by a mode bit.
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// No-op owner restriction on non-Unix targets — see the Unix variant's docs.
#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_uses_localappdata_brand() {
        let dir = brand_data_dir(Os::Windows, r"C:\Users\alice\AppData\Local").unwrap();
        assert!(dir.ends_with("DigNetwork"));
        assert!(dir.to_string_lossy().contains("AppData"));
    }

    #[test]
    fn macos_uses_application_support() {
        let dir = brand_data_dir(Os::MacOs, "/Users/alice").unwrap();
        assert_eq!(
            dir,
            PathBuf::from("/Users/alice/Library/Application Support/DigNetwork")
        );
    }

    #[test]
    fn linux_uses_xdg_data_home_lowercase() {
        let dir = brand_data_dir(Os::Linux, "/home/alice/.local/share").unwrap();
        assert_eq!(dir, PathBuf::from("/home/alice/.local/share/dignetwork"));
    }

    #[test]
    fn empty_root_is_missing_env_error() {
        let err = brand_data_dir(Os::Linux, "").unwrap_err();
        assert!(matches!(
            err,
            Error::MissingEnv {
                var: "XDG_DATA_HOME",
                ..
            }
        ));
        // The error renders a useful message rather than a bare debug string.
        assert!(err.to_string().contains("XDG_DATA_HOME"));
    }

    #[test]
    fn did_hash_is_stable_and_distinct_per_did() {
        assert_eq!(did_hash("did:chia:aaa"), did_hash("did:chia:aaa"));
        assert_ne!(did_hash("did:chia:aaa"), did_hash("did:chia:bbb"));
        // Lowercase-hex sha256 is 64 chars.
        assert_eq!(did_hash("did:chia:aaa").len(), 64);
    }

    #[test]
    fn profiles_are_isolated_by_did_hash() {
        let brand = brand_data_dir(Os::Linux, "/home/alice/.local/share").unwrap();
        let a = profile_dir(&brand, "did-aaa");
        let b = profile_dir(&brand, "did-bbb");
        assert_ne!(a, b);
        assert!(a.ends_with("did-aaa"));
        assert!(a.starts_with(&brand));
    }

    /// The shared crash-safe write: atomic replace, no temp file left behind, and (on Unix) the
    /// temp file is owner-only for its entire lifetime — never briefly world/group-readable while
    /// security-critical bytes are in flight.
    #[test]
    fn write_durably_replaces_atomically_with_no_temp_left_and_owner_only_temp_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.blob");
        let temp_path = path.with_extension("tmp");

        write_durably(&path, &temp_path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(
            !temp_path.exists(),
            "the temp file must be renamed away, not left behind"
        );

        // Overwriting fully replaces the previous content (no torn append / stale tail) and again
        // leaves no temp file — the property that keeps a crash mid-save from stranding a profile
        // or the sealed identity blob.
        write_durably(&path, &temp_path, b"second-longer-then-shorter").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-longer-then-shorter");
        write_durably(&path, &temp_path, b"third").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        assert!(!temp_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the temp file's owner-only mode must carry through the rename"
            );
        }
    }
}
