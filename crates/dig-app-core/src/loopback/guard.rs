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

    /// Whether `origin` (the WS upgrade `Origin` header) may open the channel AT ALL.
    ///
    /// # What this guard is, and is not
    ///
    /// It is the anti-**web-page** boundary, and only that. A page on `https://evil.example` can reach
    /// a loopback port, but it cannot choose the `Origin` the browser attaches — so refusing every
    /// `http(s)` origin that is not pinned keeps every website off this channel, which is the attack
    /// this guard was built for. It has never been an authorization to act: pairing, and then the
    /// per-frame MAC, are.
    ///
    /// Three kinds of caller are admitted (dig_ecosystem#1848):
    ///
    /// 1. **A pinned DIG extension.** As before, and unchanged.
    /// 2. **Any browser-extension origin** (`chrome-extension://`, `moz-extension://`,
    ///    `safari-web-extension://`). A page cannot forge one of these — the browser derives it from
    ///    the installed extension — so admitting them lets a THIRD-PARTY extension reach the pairing
    ///    handshake without letting any website near it. What it can do once admitted is decided by the
    ///    pairing code and the scope, not here.
    /// 3. **No `Origin` header at all** — a native local client. Browsers ALWAYS attach `Origin` to a
    ///    WebSocket handshake, so its absence means the caller is not a page. That is the entire
    ///    inference, and it is why absence is admitted while a *foreign* `https` origin is not.
    ///
    /// The literal string `null` is refused explicitly: browsers send `Origin: null` for sandboxed
    /// and `file://` documents, so treating it as "no origin" would hand exactly those pages the
    /// native-client door.
    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        match origin {
            // A native client — not a browser page. See the doc comment for why absence is decisive.
            None => true,
            Some("null") => false,
            Some(origin) => {
                self.allowed_origins.iter().any(|allowed| allowed == origin)
                    || is_browser_extension_origin(origin)
            }
        }
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

/// The URL schemes a browser gives an INSTALLED extension. A web page can never be served from one of
/// these, so an origin carrying one identifies an extension rather than a site — which is the only
/// claim this function makes. WHICH extension, and whether it may do anything, is settled by the
/// pairing code and the per-frame MAC.
const EXTENSION_ORIGIN_SCHEMES: &[&str] = &[
    "chrome-extension://",
    "moz-extension://",
    "safari-web-extension://",
    "ms-browser-extension://",
];

/// Whether `origin` is a browser-extension origin with a non-empty id.
///
/// The id must be non-empty: `chrome-extension://` alone is not an origin any browser produces, and
/// admitting it would put a caller on the channel under an identity nothing can distinguish from
/// another such caller.
fn is_browser_extension_origin(origin: &str) -> bool {
    EXTENSION_ORIGIN_SCHEMES
        .iter()
        .any(|scheme| origin.len() > scheme.len() && origin.starts_with(scheme))
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
    fn rejects_every_web_page_origin() {
        // THE boundary this guard exists for, and the one dig_ecosystem#1848 did not move: a website
        // cannot choose the Origin its browser sends, so no site reaches this channel — with or
        // without a pairing code.
        let g = guard();
        assert!(!g.origin_allowed(Some("https://evil.example")));
        assert!(!g.origin_allowed(Some("http://localhost:3000")));
        assert!(!g.origin_allowed(Some("https://dig.net")));
    }

    #[test]
    fn rejects_the_null_origin_a_sandboxed_or_file_page_sends() {
        // `Origin: null` is what a browser sends for a sandboxed iframe or a `file://` document. It is
        // a PAGE, and reading it as "no origin, therefore a native client" would hand exactly those
        // pages the native-client door.
        let g = guard();
        assert!(!g.origin_allowed(Some("null")));
    }

    #[test]
    fn admits_a_third_party_browser_extension() {
        // A third-party extension is the motivating caller of #1848. It gets ONTO the channel; what it
        // may do there is decided by the pairing code and the scope, not by this guard.
        let g = guard();
        assert!(g.origin_allowed(Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        assert!(g.origin_allowed(Some("moz-extension://a-firefox-uuid")));
        assert!(g.origin_allowed(Some("safari-web-extension://an-id")));
    }

    #[test]
    fn rejects_a_scheme_that_only_looks_like_an_extension_origin() {
        let g = guard();
        // No id at all — no browser produces this, and it would be an identity nothing can tell apart.
        assert!(!g.origin_allowed(Some("chrome-extension://")));
        // A site whose HOST merely contains the scheme text, and a scheme that is a near-miss.
        assert!(!g.origin_allowed(Some("https://chrome-extension://evil")));
        assert!(!g.origin_allowed(Some("chrome-extensions://abc")));
        assert!(!g.origin_allowed(Some("chrome-extension:/abc")));
    }

    #[test]
    fn admits_a_native_client_that_sends_no_origin_at_all() {
        // Browsers ALWAYS attach Origin to a WebSocket handshake, so its absence means the caller is
        // not a page. This is what lets a desktop tool pair; it still needs a code, and a Host header
        // on the loopback authority.
        let g = guard();
        assert!(g.origin_allowed(None));
        assert_eq!(g.check(Some("localhost:9779"), None), Ok(()));
        // …but the Host guard is unaffected: an origin-less caller off the loopback authority is still
        // refused, so "no Origin" is not a way around the anti-DNS-rebinding check.
        assert_eq!(
            g.check(Some("evil.example.com"), None),
            Err(GuardRejection::BadHost)
        );
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
