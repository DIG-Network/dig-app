//! The loopback CONTROL client — how dig-app actually reaches a running dig-node.
//!
//! # What the node really answers
//!
//! dig-node serves its management/query plane as **JSON-RPC 2.0 over loopback HTTP**: a `POST /`
//! whose body names a `control.*` method, gated by the `X-Dig-Control-Token` header.
//! `dig-node-service`'s `serve_with_shutdown` binds up to three loopback listeners for that one
//! surface — the always-on `127.0.0.1:9778`, its best-effort IPv6 twin `[::1]:9778`, and the
//! best-effort bare `http://dig.local` on `127.0.0.2:80` (the address dig-installer registers in
//! the hosts file).
//!
//! It does **not** listen on an OS named pipe or a Unix domain socket. [`crate::ipc`] describes such
//! a per-user channel and the engine half of it was never built, so a connector that dialled a pipe
//! would report "no node" against a perfectly healthy node. This module speaks the transport that
//! exists.
//!
//! # What travels over it
//!
//! The method names, request/response envelope, typed results and error taxonomy all come from the
//! published [`dig_node_control_interface`] contract crate, which both sides of the boundary read.
//! This module owns only the *transport* — endpoint resolution, token discovery, and one small
//! blocking HTTP/1.1 exchange — because that crate is deliberately transport-agnostic.
//!
//! # The endpoint ladder (§5.3)
//!
//! [`endpoint_ladder`] yields the candidates to try in order, first responder wins:
//!
//! 1. an explicitly-configured endpoint, which wins outright and is tried alone;
//! 2. `http://dig.local` — the installer-registered local node;
//! 3. `http://localhost:9778` — the node's always-on loopback listener.
//!
//! The public `rpc.dig.net` gateway is deliberately **not** a tier. It is the anonymous public
//! *read* tier; it neither dispatches `control.*` nor could hold this machine's local control token,
//! so probing it could only ever produce a misleading answer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use dig_node_control_interface::envelope::{JsonRpcResponse, RequestId};
use dig_node_control_interface::params::StatusParams;
use dig_node_control_interface::results::StatusResult;
use dig_node_control_interface::traits::{build_request, parse_response};

/// The header dig-node gates every `control.*` method on. Byte-identical to `dig-node-service`'s
/// `control::CONTROL_TOKEN_HEADER`; a mismatch means every call is refused.
///
/// Declared here because the contract crate is transport-agnostic and does not carry it.
pub const CONTROL_TOKEN_HEADER: &str = "X-Dig-Control-Token";

/// The file dig-node writes its master control token into, inside its state directory.
/// Byte-identical to `dig-node-service`'s `control::CONTROL_TOKEN_FILE`.
const CONTROL_TOKEN_FILE: &str = "control-token";

/// Overrides dig-node's state-directory resolution, and therefore where its control token lives.
/// Byte-identical to `dig-node-service`'s `state::STATE_DIR_ENV` — honouring it is what lets a test
/// rig (and a non-default install) find the same token the node minted.
const STATE_DIR_ENV: &str = "DIG_NODE_STATE_DIR";

/// The machine-wide state folder name dig-node uses on Windows and macOS
/// (`state::MACHINE_FOLDER`), and the legacy per-user folder name on every OS.
const MACHINE_FOLDER: &str = "DigNode";

/// How long one tier of the ladder may take to answer before we fall through to the next.
///
/// The agent re-probes on every run-loop tick, so a stalled tier must never hold the loop: short
/// enough to stay responsive, long enough for a busy local node to reply.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Why a control call did not produce a result. Each variant is a distinct thing a person can act
/// on, which is what the "no node found" surface renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCallError {
    /// The endpoint could not be parsed into a host and port.
    BadEndpoint(String),
    /// Nothing answered at the endpoint — the usual "no node is running" case.
    Unreachable(String),
    /// Something answered, but not with a JSON-RPC response we could read.
    BadResponse(String),
    /// The node answered with a refusal — most often an absent or unrecognized control token.
    Refused(String),
}

impl std::fmt::Display for ControlCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlCallError::BadEndpoint(m) => write!(f, "unusable node endpoint: {m}"),
            ControlCallError::Unreachable(m) => write!(f, "{m}"),
            ControlCallError::BadResponse(m) => write!(f, "unreadable reply from the node: {m}"),
            ControlCallError::Refused(m) => write!(f, "the node refused the request: {m}"),
        }
    }
}

impl std::error::Error for ControlCallError {}

/// The §5.3 endpoint candidates to try, in order.
///
/// A non-empty `configured` endpoint wins outright — it is returned **alone**, because a user who
/// named a node meant that node, and silently falling through to a different one would be a lie.
/// Otherwise the two local tiers are returned in preference order.
pub fn endpoint_ladder(configured: Option<&str>) -> Vec<String> {
    if let Some(url) = configured.map(str::trim).filter(|u| !u.is_empty()) {
        return vec![normalize_endpoint(url)];
    }
    vec![
        format!("http://{}", dig_constants::DIG_LOCAL_HOST),
        format!("http://localhost:{}", dig_constants::DIG_NODE_PORT),
    ]
}

/// Give a bare `host` / `host:port` endpoint an explicit `http://` scheme, so the rest of this
/// module can assume one. A user typing `localhost:9778` into settings means the same thing as
/// `http://localhost:9778`.
fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

/// The paths dig-node may have written its control token to, in the order dig-node itself resolves
/// its state directory: an explicit `DIG_NODE_STATE_DIR` override first, then this OS's machine-wide
/// state directory, then the legacy per-user directory a non-service `dig-node run` still uses.
///
/// dig-app reads whichever exists; it never mints a token, because a token the node does not know
/// would authorize nothing.
pub fn control_token_candidates() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var(STATE_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        dirs.push(PathBuf::from(dir));
    }
    dirs.extend(machine_state_dirs());
    dirs.extend(legacy_state_dir());
    dirs.into_iter()
        .map(|d| d.join(CONTROL_TOKEN_FILE))
        .collect()
}

/// This OS's machine-wide dig-node state directories, mirroring `state::machine_state_dirs`.
fn machine_state_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var("PROGRAMDATA")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| r"C:\ProgramData".to_string());
        vec![PathBuf::from(base).join(MACHINE_FOLDER)]
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/Library/Application Support").join(MACHINE_FOLDER)]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        vec![
            PathBuf::from("/var/lib/dig-node"),
            PathBuf::from("/etc/dig-node"),
        ]
    }
}

/// The legacy per-user state directory a plain `dig-node run` writes its token into
/// (`%LOCALAPPDATA%\DigNode` / `$HOME/DigNode`), mirroring `state::legacy_state_dir`.
fn legacy_state_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var("LOCALAPPDATA").ok();
    #[cfg(not(windows))]
    let base = std::env::var("HOME").ok();
    base.filter(|b| !b.trim().is_empty())
        .map(|b| PathBuf::from(b).join(MACHINE_FOLDER))
}

/// Read the node's control token from the first candidate path that holds one.
///
/// `None` covers both "no node has ever run here" and "the node runs as a service whose token this
/// user may not read". Both are honest reasons a call will be refused, and the caller reports them
/// as such rather than pretending to be connected.
pub fn load_control_token() -> Option<String> {
    load_control_token_from(&control_token_candidates())
}

/// [`load_control_token`] over an explicit candidate list.
///
/// A **present-but-blank** file counts as absent and the search continues — the same rule dig-node
/// applies when reading its own token. Treating a blank file as a token would send an empty header
/// and turn a legible "no token here" into an opaque refusal.
fn load_control_token_from(candidates: &[PathBuf]) -> Option<String> {
    candidates
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

/// Ask one endpoint for `control.status` — the node's own at-a-glance snapshot.
///
/// This is the single real request/response the agent's status surface is built from. Success means
/// a dig-node is genuinely running, answered, and authorized us.
pub fn fetch_status(
    endpoint: &str,
    token: Option<&str>,
    timeout: Duration,
) -> Result<StatusResult, ControlCallError> {
    let request = build_request(RequestId::from(1), &StatusParams {});
    let body = serde_json::to_vec(&request)
        .map_err(|e| ControlCallError::BadResponse(format!("could not encode the request: {e}")))?;
    let raw = post_json(endpoint, &body, token, timeout)?;
    let response: JsonRpcResponse = serde_json::from_slice(&raw)
        .map_err(|e| ControlCallError::BadResponse(format!("not a JSON-RPC response: {e}")))?;
    parse_response::<StatusParams>(response).map_err(|e| ControlCallError::Refused(e.message))
}

/// Walk `ladder` and return the first tier that answers, along with the endpoint that did.
///
/// Every tier's failure is kept so the "no node found" surface can say what was actually tried,
/// rather than only that nothing worked.
pub fn resolve_status(
    ladder: &[String],
    token: Option<&str>,
    timeout: Duration,
) -> Result<(String, StatusResult), Vec<(String, ControlCallError)>> {
    let mut failures = Vec::new();
    for endpoint in ladder {
        match fetch_status(endpoint, token, timeout) {
            Ok(status) => return Ok((endpoint.clone(), status)),
            Err(e) => failures.push((endpoint.clone(), e)),
        }
    }
    Err(failures)
}

/// POST `body` as JSON to `endpoint`'s root and return the response body bytes.
///
/// A deliberately minimal blocking HTTP/1.1 exchange: one request, `Connection: close`, read to EOF.
/// The control plane is a loopback JSON-RPC endpoint reached from the agent's *synchronous* run
/// loop, so a full HTTP client stack would buy nothing here — and staying blocking keeps the
/// connector usable from that loop without dragging in an async runtime.
fn post_json(
    endpoint: &str,
    body: &[u8],
    token: Option<&str>,
    timeout: Duration,
) -> Result<Vec<u8>, ControlCallError> {
    let (host, port) = split_host_port(endpoint)?;
    let stream = connect(&host, port, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| ControlCallError::Unreachable(format!("could not arm the timeout: {e}")))?;

    let mut head = format!(
        "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str(CONTROL_TOKEN_HEADER);
        head.push_str(": ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    let mut writer = &stream;
    writer
        .write_all(head.as_bytes())
        .and_then(|()| writer.write_all(body))
        .and_then(|()| writer.flush())
        .map_err(|e| ControlCallError::Unreachable(format!("could not send the request: {e}")))?;

    read_http_body(stream)
}

/// Dial `host:port`, preferring IPv6 (§5.2) among the resolved addresses.
///
/// `localhost` resolves to both loopback families and the node's IPv6 listener is best-effort — so
/// we try each resolved address in IPv6-first order and take the first that connects, rather than
/// betting the whole probe on whichever address the resolver happened to list first.
fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, ControlCallError> {
    let mut addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| ControlCallError::Unreachable(format!("cannot resolve {host}: {e}")))?
        .collect();
    addrs.sort_by_key(|a| !a.is_ipv6());
    if addrs.is_empty() {
        return Err(ControlCallError::BadEndpoint(format!(
            "{host} resolved to no address"
        )));
    }
    let mut last = String::from("connection refused");
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(ControlCallError::Unreachable(format!(
        "no DIG node answered at {host}:{port} ({last})"
    )))
}

/// Read an HTTP/1.1 response and return its body, mapping a non-2xx status to a refusal.
///
/// The node closes the connection after replying (`Connection: close`), so reading to EOF is the
/// framing — this one endpoint never needs chunked-transfer handling.
fn read_http_body(stream: TcpStream) -> Result<Vec<u8>, ControlCallError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| ControlCallError::Unreachable(format!("no reply from the node: {e}")))?;
    let code = http_status_code(&status_line)?;

    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| ControlCallError::BadResponse(format!("truncated headers: {e}")))?;
        if read == 0 || line.trim().is_empty() {
            break;
        }
    }

    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|e| ControlCallError::BadResponse(format!("truncated body: {e}")))?;

    if !(200..300).contains(&code) {
        let detail = String::from_utf8_lossy(&body).trim().to_string();
        return Err(ControlCallError::Refused(format!("HTTP {code} {detail}")));
    }
    Ok(body)
}

/// Pull the numeric status code out of an HTTP status line (`HTTP/1.1 200 OK`).
fn http_status_code(status_line: &str) -> Result<u16, ControlCallError> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            ControlCallError::BadResponse(format!(
                "not an HTTP status line: {:?}",
                status_line.trim()
            ))
        })
}

/// Split an `http://host[:port]` endpoint into its host and port, defaulting the port from the
/// scheme (`http` → 80, `https` → 443) exactly as a browser would.
///
/// The bare `http://dig.local` tier depends on this: dig-node serves that name on port **80**, not
/// on [`dig_constants::DIG_NODE_PORT`], so defaulting to the node's high port would make the tier
/// fail against a node that is answering.
fn split_host_port(endpoint: &str) -> Result<(String, u16), ControlCallError> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| ControlCallError::BadEndpoint(format!("{endpoint} has no scheme")))?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => {
            return Err(ControlCallError::BadEndpoint(format!(
                "unsupported scheme {other:?} (expected http or https)"
            )))
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(ControlCallError::BadEndpoint(format!(
            "{endpoint} has no host"
        )));
    }
    match authority.rsplit_once(':') {
        // A colon inside `[::1]` is part of an IPv6 literal, not a port separator.
        Some((host, port)) if !port.contains(']') && !host.is_empty() => {
            let port = port.parse().map_err(|_| {
                ControlCallError::BadEndpoint(format!("{port:?} is not a port number"))
            })?;
            Ok((strip_brackets(host), port))
        }
        _ => Ok((strip_brackets(authority), default_port)),
    }
}

/// Unwrap an IPv6 literal's `[...]` brackets, which are URL syntax rather than part of the address.
fn strip_brackets(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node::{Behaviour, FakeNode};

    /// An endpoint on loopback that nothing is listening on, for the "no node running" path. Bind an
    /// ephemeral port, learn its number, then drop the listener — so the port is real, held by
    /// nobody, and reliably refuses.
    fn dead_endpoint() -> String {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = l.local_addr().expect("addr");
        drop(l);
        format!("http://{addr}")
    }

    fn quick() -> Duration {
        Duration::from_secs(2)
    }

    #[test]
    fn fetch_status_reads_a_real_reply_from_a_real_socket() {
        let node = FakeNode::serving_status();
        let status = fetch_status(&node.endpoint(), Some(node.token()), quick())
            .expect("a node that answers control.status must yield a status");
        assert_eq!(status.version, FakeNode::VERSION);
        assert_eq!(status.hosted_store_count, 3);
        assert_eq!(status.cached_capsule_count, 9);
        assert!(status.running);
        assert!(status.sync.available);
        // The method name must have gone out on the wire — asserted from the SERVER's copy of the
        // request, not from the client's own idea of what it sent.
        assert!(node.received().contains("control.status"));
    }

    #[test]
    fn fetch_status_sends_the_control_token_header() {
        let node = FakeNode::serving_status();
        fetch_status(&node.endpoint(), Some(node.token()), quick()).expect("status");
        let request = node.received();
        assert!(
            request.contains(&format!("{CONTROL_TOKEN_HEADER}: {}", FakeNode::TOKEN)),
            "the control token must travel as its own header; got:\n{request}"
        );
    }

    #[test]
    fn a_missing_token_is_refused_not_reported_connected() {
        // The fake gates on the token exactly as the node does, so omitting it must surface as a
        // refusal — never as a success, and never as "unreachable" (the node IS there).
        let node = FakeNode::serving_status();
        let err = fetch_status(&node.endpoint(), None, quick()).expect_err("must be refused");
        assert!(
            matches!(err, ControlCallError::Refused(_)),
            "expected a refusal, got {err:?}"
        );
    }

    #[test]
    fn nothing_listening_is_unreachable_and_names_the_endpoint() {
        let endpoint = dead_endpoint();
        let err = fetch_status(&endpoint, Some("t"), quick()).expect_err("must not connect");
        match err {
            ControlCallError::Unreachable(m) => assert!(
                m.contains("no DIG node answered"),
                "the reason must be legible to a person; got {m:?}"
            ),
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn a_json_rpc_error_from_the_node_is_a_refusal_carrying_its_message() {
        let node = FakeNode::with_behaviour(Behaviour::JsonRpcError("token rejected".into()));
        let err = fetch_status(&node.endpoint(), Some(node.token()), quick())
            .expect_err("a JSON-RPC error is not a status");
        assert_eq!(err, ControlCallError::Refused("token rejected".to_string()));
    }

    #[test]
    fn a_non_json_body_is_a_bad_response_not_a_silent_default() {
        let node = FakeNode::with_behaviour(Behaviour::Http(200, "<html>nope</html>".into()));
        let err = fetch_status(&node.endpoint(), Some(node.token()), quick())
            .expect_err("HTML is not a JSON-RPC response");
        assert!(
            matches!(err, ControlCallError::BadResponse(_)),
            "expected BadResponse, got {err:?}"
        );
    }

    #[test]
    fn a_node_that_accepts_then_says_nothing_fails_rather_than_hanging() {
        let node = FakeNode::with_behaviour(Behaviour::Silent);
        let err = fetch_status(
            &node.endpoint(),
            Some(node.token()),
            Duration::from_millis(300),
        )
        .expect_err("a mute node must not look connected");
        assert!(
            matches!(
                err,
                ControlCallError::Unreachable(_) | ControlCallError::BadResponse(_)
            ),
            "expected a failure, got {err:?}"
        );
    }

    #[test]
    fn the_ladder_is_dig_local_then_localhost_when_nothing_is_configured() {
        let ladder = endpoint_ladder(None);
        assert_eq!(
            ladder,
            vec![
                "http://dig.local".to_string(),
                format!("http://localhost:{}", dig_constants::DIG_NODE_PORT),
            ]
        );
    }

    #[test]
    fn a_configured_endpoint_wins_outright_and_is_tried_alone() {
        // §5.3: an explicit endpoint overrides the ladder entirely — falling through to a DIFFERENT
        // node would silently answer about a machine the user did not ask about.
        assert_eq!(
            endpoint_ladder(Some("http://10.0.0.5:9778")),
            vec!["http://10.0.0.5:9778".to_string()]
        );
        // A blank setting is "unset", not "an endpoint called empty string".
        assert_eq!(endpoint_ladder(Some("   ")), endpoint_ladder(None));
    }

    #[test]
    fn a_configured_endpoint_without_a_scheme_is_still_dialable() {
        assert_eq!(
            endpoint_ladder(Some("localhost:9778/")),
            vec!["http://localhost:9778".to_string()]
        );
    }

    #[test]
    fn resolve_status_falls_through_a_dead_tier_to_a_live_one() {
        // The fixture must contain BOTH a dead tier and a LIVE one: a ladder of only dead tiers
        // cannot distinguish "falls through" from "gives up on the first failure".
        let node = FakeNode::serving_status();
        let ladder = vec![dead_endpoint(), node.endpoint()];
        let (endpoint, status) = resolve_status(&ladder, Some(node.token()), quick())
            .expect("the live tier must answer");
        assert_eq!(endpoint, node.endpoint());
        assert_eq!(status.version, FakeNode::VERSION);
    }

    #[test]
    fn resolve_status_stops_at_the_first_tier_that_answers() {
        // Ordering is load-bearing: put the LIVE node first and a dead tier second. If the walk
        // ignored order (or kept going), the returned endpoint would not be the first one.
        let node = FakeNode::serving_status();
        let ladder = vec![node.endpoint(), dead_endpoint()];
        let (endpoint, _) = resolve_status(&ladder, Some(node.token()), quick()).expect("answered");
        assert_eq!(endpoint, node.endpoint());
    }

    #[test]
    fn resolve_status_reports_every_tier_it_tried_when_none_answer() {
        let ladder = vec![dead_endpoint(), dead_endpoint()];
        let failures = resolve_status(&ladder, Some("t"), quick()).expect_err("none can answer");
        assert_eq!(failures.len(), 2, "each tier's reason must be reported");
        for (endpoint, error) in failures {
            assert!(ladder.contains(&endpoint));
            assert!(matches!(error, ControlCallError::Unreachable(_)));
        }
    }

    #[test]
    fn split_host_port_defaults_the_port_from_the_scheme() {
        // `http://dig.local` MUST resolve to port 80 — the port dig-node actually binds for the
        // bare dig.local listener. Defaulting to 9778 here would break the whole first tier.
        assert_eq!(
            split_host_port("http://dig.local").unwrap(),
            ("dig.local".to_string(), 80)
        );
        assert_eq!(
            split_host_port("https://rpc.dig.net").unwrap(),
            ("rpc.dig.net".to_string(), 443)
        );
        assert_eq!(
            split_host_port("http://localhost:9778").unwrap(),
            ("localhost".to_string(), 9778)
        );
    }

    #[test]
    fn split_host_port_reads_an_ipv6_literal_without_eating_its_colons() {
        assert_eq!(
            split_host_port("http://[::1]:9778").unwrap(),
            ("::1".to_string(), 9778)
        );
        assert_eq!(
            split_host_port("http://[::1]").unwrap(),
            ("::1".to_string(), 80)
        );
    }

    #[test]
    fn split_host_port_rejects_endpoints_it_cannot_dial() {
        for bad in [
            "dig.local:9778",
            "ftp://dig.local",
            "http://",
            "http://localhost:not-a-port",
        ] {
            assert!(
                split_host_port(bad).is_err(),
                "{bad:?} must not be accepted as an endpoint"
            );
        }
    }

    #[test]
    fn split_host_port_ignores_a_path_query_or_fragment() {
        assert_eq!(
            split_host_port("http://localhost:9778/some/path?q=1#f").unwrap(),
            ("localhost".to_string(), 9778)
        );
    }

    #[test]
    fn the_token_is_looked_for_where_dig_node_writes_it() {
        // The env override is dig-node's OWN state-dir override, so honouring it is what makes the
        // app and the node agree on one token file.
        let dir = tempfile::tempdir().expect("tempdir");
        let candidates = {
            let _guard = EnvGuard::set(STATE_DIR_ENV, dir.path().to_str().unwrap());
            control_token_candidates()
        };
        assert_eq!(
            candidates.first().expect("at least one candidate"),
            &dir.path().join(CONTROL_TOKEN_FILE),
            "the DIG_NODE_STATE_DIR override must be tried FIRST"
        );
        assert!(
            candidates.len() > 1,
            "the default install locations must still be tried after the override"
        );
    }

    #[test]
    fn a_token_file_is_read_and_trimmed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(CONTROL_TOKEN_FILE);
        std::fs::write(&path, "  abc123\n").expect("write");
        assert_eq!(
            load_control_token_from(&[path]).as_deref(),
            Some("abc123"),
            "the token must be trimmed — a trailing newline is not part of it"
        );
    }

    #[test]
    fn a_blank_token_file_is_skipped_in_favour_of_a_later_real_one() {
        // The fixture needs BOTH a blank candidate and a real one AFTER it: a list of only blank
        // files could not tell "skips blanks and keeps looking" apart from "gives up at the first
        // unusable file".
        let dir = tempfile::tempdir().expect("tempdir");
        let blank = dir.path().join("blank-token");
        let real = dir.path().join("real-token");
        std::fs::write(&blank, "   \n").expect("write");
        std::fs::write(&real, "realtoken").expect("write");
        assert_eq!(
            load_control_token_from(&[blank.clone(), real]).as_deref(),
            Some("realtoken")
        );
        // And a blank file ALONE yields nothing, rather than an empty-string "token".
        assert_eq!(load_control_token_from(&[blank]), None);
    }

    #[test]
    fn a_missing_token_file_is_no_token_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            load_control_token_from(&[dir.path().join("does-not-exist")]),
            None
        );
    }

    /// Sets an environment variable for the life of the guard, restoring the previous value on drop.
    /// Env is process-global, so these tests hold a mutex rather than racing each other.
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key,
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
