//! The user-app ↔ engine IPC endpoint (identity-authenticated session).
//!
//! The user app and the engine talk over a **per-user OS-native local channel** — a Windows named
//! pipe or a macOS/Linux Unix domain socket — with the pipe/socket ACL scoped to the owning user
//! (tighter than loopback TCP; the OS peer credential also binds the connecting identity). The
//! existing engine `control.*` JSON-RPC *dispatch* is reused over this channel; only the transport
//! changes. Session authentication (proving possession of the active profile's identity key), the
//! `control.session.attach`/`detach` methods, and the service→user-app `sign` callback are
//! specified in `SPEC.md` and implemented by U6.
//!
//! This module resolves the endpoint address; it is pure so the per-OS naming is unit-testable.

use crate::Os;

/// The endpoint prefixes are canonical — a second implementation (the engine side, the `dign`
/// client) must resolve the SAME address for a given user.
const WINDOWS_PIPE_PREFIX: &str = r"\.\pipe\dignetwork-";
const UNIX_SOCKET_NAME: &str = "dignetwork.sock";

/// Resolve the per-user IPC endpoint address for `os` and the current `user` identifier.
///
/// - Windows — a named pipe `\.\pipe\dignetwork-<user>`.
/// - macOS / Linux — a Unix domain socket `<runtime_dir>/dignetwork.sock`, where `runtime_dir` is
///   the caller-supplied per-user runtime directory (`$XDG_RUNTIME_DIR` on Linux, a per-user path
///   on macOS). On Windows `runtime_dir` is ignored (the pipe namespace carries the user).
pub fn channel_endpoint(os: Os, user: &str, runtime_dir: &str) -> String {
    match os {
        Os::Windows => format!("{WINDOWS_PIPE_PREFIX}{user}"),
        Os::MacOs | Os::Linux => {
            let dir = runtime_dir.trim_end_matches('/');
            format!("{dir}/{UNIX_SOCKET_NAME}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_endpoint_is_a_per_user_named_pipe() {
        let ep = channel_endpoint(Os::Windows, "alice", "");
        assert_eq!(ep, r"\.\pipe\dignetwork-alice");
    }

    #[test]
    fn unix_endpoint_is_a_socket_under_the_runtime_dir() {
        assert_eq!(
            channel_endpoint(Os::Linux, "alice", "/run/user/1000"),
            "/run/user/1000/dignetwork.sock"
        );
        // A trailing slash on the runtime dir does not double up.
        assert_eq!(
            channel_endpoint(Os::MacOs, "alice", "/var/run/alice/"),
            "/var/run/alice/dignetwork.sock"
        );
    }

    #[test]
    fn distinct_users_get_distinct_windows_pipes() {
        assert_ne!(
            channel_endpoint(Os::Windows, "alice", ""),
            channel_endpoint(Os::Windows, "bob", "")
        );
    }
}
