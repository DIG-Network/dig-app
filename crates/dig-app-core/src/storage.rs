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

use crate::sealer::{ProfileSealer, SealError};
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
                // `HOME` FIRST, because it is the variable that is actually missing here.
                // `environment::linux_data_root` falls back to `$HOME/.local/share` whenever
                // `XDG_DATA_HOME` is unset OR empty (the XDG default), so an empty root can only
                // mean `HOME` is unset. Naming `XDG_DATA_HOME` alone sent a systemd operator to
                // export the one variable that changes nothing -- measured on dig-app#303/#310,
                // where a unit crash-looped 35 times and `Environment=HOME=/root` ALONE fixed it.
                // It is still named, as the optional override it is, so a reader who deliberately
                // relocated their data directory knows which knob they touched.
                Os::Linux => {
                    "HOME (systemd units do not inherit it; XDG_DATA_HOME is an optional override)"
                }
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

/// A failure from [`seal_and_write`]: the plaintext could not be sealed (normally because the account
/// is locked) or the durable write to disk failed. Each vault maps this onto its own `VaultError`, so
/// the two callers keep their existing error surfaces unchanged.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealWriteError {
    /// The plaintext could not be sealed under the profile's DEK.
    #[error(transparent)]
    Seal(#[from] SealError),

    /// The ciphertext could not be written to disk.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// THE at-rest write discipline for every sealed per-profile blob — the single source of truth so the
/// recovery-phrase vault and the second-factor vault cannot drift in how they persist a secret.
///
/// Seals `plaintext` under the DEK of the profile named by `did`, then persists the ciphertext to
/// `path` exactly as every security-critical file in this crate is persisted: create the parent
/// directory if absent, write durably and atomically through a sibling `*.seal.tmp` temp file
/// ([`write_durably`] — temp + fsync + rename), then restrict the final file to its owner
/// ([`restrict_to_owner`], `0600` on Unix). On success the bytes on disk are the AEAD ciphertext and
/// nothing else; a locked account fails closed at the seal step, before any file is touched.
pub(crate) fn seal_and_write(
    sealer: &impl ProfileSealer,
    did: &str,
    path: &Path,
    plaintext: &[u8],
) -> std::result::Result<(), SealWriteError> {
    let sealed = sealer.seal(did, plaintext)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("seal.tmp");
    write_durably(path, &temp, &sealed)?;
    restrict_to_owner(path)?;
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

    /// An empty root on Linux means NEITHER `XDG_DATA_HOME` nor `HOME` was set, because
    /// `environment::app_data_root` falls back from the first to the second. The message must name
    /// both -- a reader who sets only the one named is told to set the variable that matters least
    /// under systemd (dig-app#303).
    ///
    /// Windows is the control: its resolver has no fallback, so its message must still name exactly
    /// one variable. Without it, an implementation that appended every variable name to every
    /// message would pass.
    #[test]
    fn empty_root_names_every_variable_that_would_have_worked() {
        let linux = brand_data_dir(Os::Linux, "").unwrap_err().to_string();
        assert!(linux.contains("XDG_DATA_HOME"), "{linux}");
        // `HOME` must be named IN ITS OWN RIGHT. Asserting `linux.contains("HOME")` directly is
        // vacuous -- "XDG_DATA_HOME" ends in those four characters, so that assertion passes on the
        // unfixed message naming only `XDG_DATA_HOME`. Measured: it did, and this test went green
        // against the very defect it exists to catch. Removing every `XDG_DATA_HOME` occurrence
        // first is what makes the second variable's absence observable.
        let without_xdg = linux.replace("XDG_DATA_HOME", "");
        assert!(without_xdg.contains("HOME"), "{linux}");

        let windows = brand_data_dir(Os::Windows, "").unwrap_err().to_string();
        assert!(windows.contains("LOCALAPPDATA"), "{windows}");
        assert!(!windows.contains("HOME"), "{windows}");

        // Still the typed variant, not a stringly-typed error.
        assert!(matches!(
            brand_data_dir(Os::Linux, "").unwrap_err(),
            Error::MissingEnv { .. }
        ));
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

    /// A keyed-prefix [`ProfileSealer`] double: reversible but DID-bound, so `seal_and_write` can be
    /// round-tripped without pulling in the real DIGOP1 crypto. It stands in for the shape every
    /// production sealer satisfies — the bytes on disk are the sealed form, never the plaintext.
    struct KeyedSealer;

    impl ProfileSealer for KeyedSealer {
        fn seal(&self, did: &str, plaintext: &[u8]) -> std::result::Result<Vec<u8>, SealError> {
            let mut out = format!("{did}|").into_bytes();
            out.extend_from_slice(plaintext);
            Ok(out)
        }

        fn open(
            &self,
            did: &str,
            ciphertext: &[u8],
        ) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, SealError> {
            let prefix = format!("{did}|").into_bytes();
            ciphertext
                .strip_prefix(&prefix[..])
                .map(|rest| zeroize::Zeroizing::new(rest.to_vec()))
                .ok_or(SealError::Open)
        }
    }

    /// The shared at-rest write: `seal_and_write` seals the plaintext (so the raw words never reach
    /// the file), lands the ciphertext atomically, and leaves the file owner-only (`0600` on Unix).
    /// This is what lets both vaults route through one copy of the discipline.
    #[test]
    fn seal_and_write_seals_then_lands_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("blob.seal");
        let did = "did:chia:profile-a";
        let plaintext = b"the secret bytes";

        seal_and_write(&KeyedSealer, did, &path, plaintext).unwrap();

        // The on-disk bytes are the sealed form, and open back to exactly the plaintext.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            raw.starts_with(did.as_bytes()) && raw != plaintext,
            "the file must hold sealed bytes, not the plaintext"
        );
        let opened = KeyedSealer.open(did, &raw).unwrap();
        assert_eq!(&*opened, plaintext, "the sealed blob must round-trip");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the sealed file must end owner-only");
        }
    }
}
