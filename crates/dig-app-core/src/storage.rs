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
use std::path::PathBuf;

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
    fn profiles_are_isolated_by_did_hash() {
        let brand = brand_data_dir(Os::Linux, "/home/alice/.local/share").unwrap();
        let a = profile_dir(&brand, "did-aaa");
        let b = profile_dir(&brand, "did-bbb");
        assert_ne!(a, b);
        assert!(a.ends_with("did-aaa"));
        assert!(a.starts_with(&brand));
    }
}
