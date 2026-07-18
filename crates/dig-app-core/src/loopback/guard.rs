//! Per-connection transport guards for the APP-SIGN loopback channel (SIGN-1, `SPEC.md` §5.6.2,
//! **security-critical**).
//!
//! These guards run during the WebSocket upgrade, BEFORE any frame is honoured, and narrow *who may
//! talk on the channel*: the `Host` header must be a loopback authority (anti-DNS-rebinding) and the
//! `Origin` must be the pinned DIG extension. They are explicitly NOT authorization to act — the
//! terminal native confirm (§5.6.1) is. A loopback bind alone is reachable by any local process, so
//! these header checks + the per-frame pairing MAC (§5.6.3) are what restrict the surface to the one
//! paired extension.

/// The canonical dig-app identity loopback port (`SPEC.md` §5.6.2; recorded in the `canonical`
/// skill). Distinct from the dig-node content/control ports (9778 / 9257) and the dig-wallet API
/// (9777) — this port carries identity/signing only.
pub const LOOPBACK_PORT: u16 = 9779;

/// The pinned DIG browser-extension ids the `Origin` guard accepts (`SPEC.md` §5.6.2; the source of
/// truth is the `canonical` skill). Two ids exist by design — the self-hosted nightly `.crx` and the
/// Chrome Web Store stable build — so BOTH are pinned. A page cannot forge another extension's id in
/// the WS handshake `Origin`, so pinning these closes the "loopback cannot authenticate the caller"
/// gap at the transport layer.
pub const PINNED_EXTENSION_IDS: &[&str] = &[
    "mlibddmbhlgogepnjdienclhnkfpkfah", // self-hosted nightly .crx (force-install pinned)
    "gdhhcalepnbdboogpajmfmhijnmdckih", // Chrome Web Store stable
];

/// Why a WebSocket upgrade was rejected by [`ConnectionGuard`]. The server maps either to a `403`
/// and closes the connection — an unpinned caller never reaches the frame loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardRejection {
    /// The `Host` header was missing or not a loopback authority on the identity port.
    BadHost,
    /// The `Origin` header was missing or not a pinned DIG extension.
    BadOrigin,
}

/// The loopback connection guard: the `Host` allowlist and `Origin` pin checked on every WS upgrade.
///
/// Built once and shared (cheap to clone the string sets) across connections. The allowlists are
/// derived from the identity port + the pinned extension ids, so the guard has no hidden state and is
/// fully unit-testable without a socket.
#[derive(Debug, Clone)]
pub struct ConnectionGuard {
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
}

impl ConnectionGuard {
    /// Build the guard for the canonical identity port and the pinned DIG extension ids.
    pub fn pinned() -> Self {
        Self::new(LOOPBACK_PORT, PINNED_EXTENSION_IDS)
    }

    /// Build the guard for an explicit `port` and extension-id allowlist. Production uses
    /// [`ConnectionGuard::pinned`]; tests use this to pin a specific port/id.
    pub fn new(port: u16, extension_ids: &[&str]) -> Self {
        let allowed_hosts = vec![
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
            format!("localhost:{port}"),
        ];
        let allowed_origins = extension_ids
            .iter()
            .map(|id| format!("chrome-extension://{id}"))
            .collect();
        Self {
            allowed_hosts,
            allowed_origins,
        }
    }

    /// Whether `host` (the WS upgrade `Host` header) is an accepted loopback authority.
    pub fn host_allowed(&self, host: Option<&str>) -> bool {
        host.is_some_and(|h| self.allowed_hosts.iter().any(|allowed| allowed == h))
    }

    /// Whether `origin` (the WS upgrade `Origin` header) is a pinned DIG extension.
    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        origin.is_some_and(|o| self.allowed_origins.iter().any(|allowed| allowed == o))
    }

    /// Check both headers, returning the first [`GuardRejection`] or `Ok(())` when both pass. `Host`
    /// is checked first (the DNS-rebinding guard), then `Origin` (the extension pin).
    pub fn check(&self, host: Option<&str>, origin: Option<&str>) -> Result<(), GuardRejection> {
        if !self.host_allowed(host) {
            return Err(GuardRejection::BadHost);
        }
        if !self.origin_allowed(origin) {
            return Err(GuardRejection::BadOrigin);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ConnectionGuard {
        ConnectionGuard::pinned()
    }

    #[test]
    fn accepts_the_three_loopback_authorities() {
        let g = guard();
        assert!(g.host_allowed(Some("127.0.0.1:9779")));
        assert!(g.host_allowed(Some("[::1]:9779")));
        assert!(g.host_allowed(Some("localhost:9779")));
    }

    #[test]
    fn rejects_a_non_loopback_or_wrong_port_host() {
        let g = guard();
        assert!(!g.host_allowed(Some("evil.example.com")));
        assert!(!g.host_allowed(Some("127.0.0.1:9778"))); // the node control port, not identity
        assert!(!g.host_allowed(Some("0.0.0.0:9779")));
        assert!(!g.host_allowed(None));
    }

    #[test]
    fn accepts_both_pinned_extension_origins() {
        let g = guard();
        assert!(g.origin_allowed(Some("chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah")));
        assert!(g.origin_allowed(Some("chrome-extension://gdhhcalepnbdboogpajmfmhijnmdckih")));
    }

    #[test]
    fn rejects_a_foreign_or_missing_origin() {
        let g = guard();
        assert!(!g.origin_allowed(Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        assert!(!g.origin_allowed(Some("https://evil.example")));
        assert!(!g.origin_allowed(None));
    }

    #[test]
    fn check_reports_host_before_origin() {
        let g = guard();
        assert_eq!(
            g.check(Some("evil.example"), Some("https://evil.example")),
            Err(GuardRejection::BadHost)
        );
        assert_eq!(
            g.check(Some("localhost:9779"), Some("https://evil.example")),
            Err(GuardRejection::BadOrigin)
        );
        assert_eq!(
            g.check(
                Some("localhost:9779"),
                Some("chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah")
            ),
            Ok(())
        );
    }
}
