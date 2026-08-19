//! The per-user session token: the second of the two independent boundaries in front of the CLI lane.
//!
//! # Why a token at all, when the endpoint is already per-user
//!
//! The pipe/socket ACL ([`super::transport`]) is the primary boundary and is an OS guarantee. The
//! token is a SECOND, independent one, and it exists because the two fail differently: an ACL
//! mistake is silent and total, while a token mismatch is a refusal the app can log. A local process
//! running as another user must clear BOTH — reach the endpoint AND read a file only this user can
//! read — so neither one being wrong on its own opens the lane.
//!
//! The token is minted fresh on every app start. It is a session credential, not a stored secret: an
//! app that is not running has no session to authorize, and a token that outlived the app it belonged
//! to would be a credential lying around for nothing.

use std::io;
use std::path::{Path, PathBuf};

use crate::secret_file::write_owner_only;

/// The token file's name under the per-user brand data directory.
const TOKEN_FILE: &str = "cli-session.token";

/// The token length in bytes. 32 bytes of CSPRNG output — the same width as the session nonces in
/// `dig-ipc-protocol`, and far beyond anything a local process could search before the app restarts.
const TOKEN_BYTES: usize = 32;

/// Where the session token lives for the app rooted at `brand_dir`.
///
/// One resolution for both halves: the app writes here and `dign` reads here, so the two can never
/// address different files.
pub fn token_path(brand_dir: &Path) -> PathBuf {
    brand_dir.join(TOKEN_FILE)
}

/// A minted per-user session token, held in memory by the server and on disk for the CLI to read.
#[derive(Clone)]
pub struct SessionToken(String);

impl SessionToken {
    /// Mint a fresh token from the OS CSPRNG.
    pub fn mint() -> Self {
        use rand_core::RngCore;

        let mut bytes = [0u8; TOKEN_BYTES];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Build a token from an already-known hex string (the CLI side, and tests).
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// The lowercase-hex form that travels on the wire.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Publish this token to the owner-only file under `brand_dir`, creating the directory if needed.
    ///
    /// The write goes through [`write_owner_only`], so the restriction is applied AT CREATION rather
    /// than tightened afterwards — there is no window in which the token sits on disk readable by
    /// anyone else.
    pub fn publish(&self, brand_dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(brand_dir)?;
        let path = token_path(brand_dir);
        write_owner_only(&path, self.0.as_bytes())?;
        Ok(path)
    }

    /// Read the published token from `brand_dir`.
    ///
    /// Surrounding whitespace is trimmed so a file a person has looked at with an editor still works;
    /// nothing else about the contents is interpreted.
    pub fn read_published(brand_dir: &Path) -> io::Result<Self> {
        let raw = std::fs::read_to_string(token_path(brand_dir))?;
        Ok(Self(raw.trim().to_string()))
    }
}

impl std::fmt::Debug for SessionToken {
    /// Never prints the token. A credential that reaches a log through a derived `Debug` is a
    /// credential in every crash report and every issue attachment.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_is_full_width_hex_and_never_repeats() {
        let (a, b) = (SessionToken::mint(), SessionToken::mint());
        assert_eq!(a.as_hex().len(), TOKEN_BYTES * 2);
        assert!(a.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.as_hex(), b.as_hex(), "two mints must not collide");
    }

    /// A published token reads back byte-identical, so the CLI and the app compare the same secret.
    ///
    /// The comparison itself is no longer here: the token never travels, and the only credential
    /// comparison on this lane is the constant-time MAC check in
    /// [`super::handshake::verify`], which its own tests pin against a nearest-wrong forgery.
    #[test]
    fn a_published_token_round_trips_byte_identically() {
        let dir = tempfile::tempdir().unwrap();
        let token = SessionToken::mint();
        token.publish(dir.path()).unwrap();

        let read = SessionToken::read_published(dir.path()).unwrap();
        assert_eq!(read.as_hex(), token.as_hex());
    }

    /// On Unix the published file is mode 0600 — the token is not readable by another local user.
    #[cfg(unix)]
    #[test]
    fn the_published_token_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = SessionToken::mint().publish(dir.path()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the session token must be owner-only");
    }

    #[test]
    fn debug_never_prints_the_token() {
        let token = SessionToken::from_hex("deadbeef");
        assert!(!format!("{token:?}").contains("deadbeef"));
    }
}
