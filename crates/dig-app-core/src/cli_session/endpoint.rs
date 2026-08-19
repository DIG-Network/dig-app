//! Where the CLI lane lives on each OS — one resolution, used by both halves.
//!
//! This is deliberately separate from [`crate::ipc`], which names the app-to-ENGINE channel. They are
//! different hops with different peers, and a shared name would let a `dign` client reach the engine
//! lane (or the reverse) simply by dialling the address it already knew.

use std::path::{Path, PathBuf};

use crate::Os;

/// The Windows named-pipe prefix. The pipe namespace carries the user, so the login name is the
/// per-user part of the address.
const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\dignetwork-cli-";

/// The Unix socket's name inside the per-user brand data directory.
const UNIX_SOCKET_NAME: &str = "cli-session.sock";

/// The address `dign` dials and dig-app listens on.
///
/// - **Windows** — a named pipe `\\.\pipe\dignetwork-cli-<user>`.
/// - **macOS / Linux** — a Unix domain socket inside `brand_dir`, the SAME per-user directory that
///   holds the session token. Putting both in one directory means one `0700` directory protects
///   both, rather than a socket in a shared runtime directory and a token somewhere else.
pub fn cli_endpoint(os: Os, user: &str, brand_dir: &Path) -> String {
    match os {
        Os::Windows => format!("{WINDOWS_PIPE_PREFIX}{user}"),
        Os::MacOs | Os::Linux => socket_path(brand_dir).to_string_lossy().into_owned(),
    }
}

/// The Unix socket path inside `brand_dir`.
pub fn socket_path(brand_dir: &Path) -> PathBuf {
    brand_dir.join(UNIX_SOCKET_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single backslash, spelled so no editor or shell can silently eat it.
    const NAMESPACE_SLASH: char = '\\';

    #[test]
    fn windows_gets_a_per_user_pipe_distinct_from_the_engine_lane() {
        let alice = cli_endpoint(Os::Windows, "alice", Path::new(""));
        assert_eq!(alice, r"\\.\pipe\dignetwork-cli-alice");
        assert_ne!(alice, cli_endpoint(Os::Windows, "bob", Path::new("")));
        // The engine lane must not be reachable at the CLI address, or a client that knows one hop
        // can dial the other.
        assert_ne!(
            alice,
            crate::ipc::channel_endpoint(Os::Windows, "alice", "")
        );
    }

    /// The pipe address must be a real UNC pipe name, not a rooted path that merely looks like one.
    ///
    /// `\.\pipe\x` is a valid FILE path on the current drive, so `CreateNamedPipeW` rejects it with
    /// `ERROR_INVALID_NAME` while every string-shaped assertion still passes. The engine lane in
    /// [`crate::ipc`] is a working pipe address on this machine, so its namespace prefix is the
    /// reference: sharing it is what makes this endpoint openable rather than merely well-formed.
    #[test]
    fn the_pipe_address_shares_the_working_engine_lane_namespace() {
        let namespace = crate::ipc::channel_endpoint(Os::Windows, "alice", "")
            .split_once("dignetwork-")
            .expect("the engine lane is a dignetwork pipe")
            .0
            .to_string();
        assert_eq!(
            namespace,
            format!(
                "{}{}.{}pipe{}",
                NAMESPACE_SLASH, NAMESPACE_SLASH, NAMESPACE_SLASH, NAMESPACE_SLASH
            )
        );
        assert!(
            cli_endpoint(Os::Windows, "alice", Path::new("")).starts_with(&namespace),
            "the CLI pipe must live in the same pipe namespace as the working engine lane"
        );
    }

    #[test]
    fn unix_puts_the_socket_beside_the_token_in_the_brand_directory() {
        let dir = Path::new("/home/alice/.local/share/DigNetwork");
        let ep = cli_endpoint(Os::Linux, "alice", dir);
        assert_eq!(ep, dir.join("cli-session.sock").to_string_lossy());
        assert_eq!(
            socket_path(dir).parent(),
            super::super::auth::token_path(dir).parent(),
            "the socket and the token must share one protected directory"
        );
    }
}
