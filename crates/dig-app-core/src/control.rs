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
use std::path::{Path, PathBuf};
use std::time::Duration;

use dig_node_control_interface::envelope::{JsonRpcResponse, RequestId};
use dig_node_control_interface::error::ControlError;
use dig_node_control_interface::params::StatusParams;
use dig_node_control_interface::results::StatusResult;
use dig_node_control_interface::traits::{build_request, parse_response, ControlCall};

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

/// Relocates dig-node's cache directory, and with it the LEGACY state dir a plain `dig-node run`
/// writes its control token into. Byte-identical to the variable `dig-node-core`'s
/// `canonical_cache_dir` reads.
const CACHE_DIR_ENV: &str = "DIG_NODE_CACHE";

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
    ///
    /// Strictly *nothing accepted the connection*. A node that accepted and then took too long is
    /// [`TimedOut`](Self::TimedOut), never this: only a refused connection is evidence about
    /// whether a node exists (dig_ecosystem#2325).
    Unreachable(String),
    /// A node accepted the connection and did not finish answering inside the caller's budget.
    ///
    /// The node is demonstrably THERE — the socket connected — so nothing downstream may conclude
    /// anything about whether one is running. The only honest statement is that this call did not
    /// finish, which is why the budget belongs to the CALLER: a liveness probe and a chain read
    /// wait for very different things.
    TimedOut(String),
    /// Something answered, but not with a JSON-RPC response we could read.
    BadResponse(String),
    /// The node understood the call and answered a JSON-RPC **error** — it declined the request.
    ///
    /// The string is the node's OWN message, which is explicitly not contract-stable. Nothing may
    /// branch on its words; a caller that must know *which* refusal this was needs a typed fact,
    /// which is what [`HttpRefused`](Self::HttpRefused) is.
    Refused(String),
    /// The node refused at the HTTP layer, before any JSON-RPC error could exist — most often a
    /// `401` for an absent or unrecognized control token.
    ///
    /// # Why this is its own variant and not a formatted [`Refused`](Self::Refused)
    ///
    /// It began as one: `Refused(format!("HTTP {code} …"))`, with the status recovered by parsing
    /// that string back out. But the same variant also carries the node's own JSON-RPC message, so a
    /// node answering the message `"HTTP 401 …"` would be read as an authorization refusal it never
    /// made — a fact derived from prose the node controls rather than from anything this module
    /// observed (dig_ecosystem#2330). The status is a fact, so it is carried as one.
    HttpRefused {
        /// The HTTP status. `401` and `403` mean this app holds no usable control token, which is a
        /// permission fault with a real remedy — never an absent or incapable node.
        code: u16,
        /// The response body, for a diagnosis.
        detail: String,
    },
}

impl std::fmt::Display for ControlCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlCallError::BadEndpoint(m) => write!(f, "unusable node endpoint: {m}"),
            ControlCallError::Unreachable(m) => write!(f, "{m}"),
            ControlCallError::TimedOut(m) => write!(f, "the node did not answer in time: {m}"),
            ControlCallError::BadResponse(m) => write!(f, "unreadable reply from the node: {m}"),
            ControlCallError::Refused(m) => write!(f, "the node refused the request: {m}"),
            // The same sentence a formatted `Refused` produced before the split, so no surface's
            // copy changed when the variant did.
            ControlCallError::HttpRefused { code, detail } => {
                write!(f, "the node refused the request: HTTP {code} {detail}")
            }
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
    control_token_candidates_from(
        non_empty_env(STATE_DIR_ENV).as_deref(),
        non_empty_env(CACHE_DIR_ENV).as_deref(),
    )
}

/// [`control_token_candidates`] over explicit override values, so the ordering and the
/// cache-dir-relative derivation are testable without mutating process-global environment.
fn control_token_candidates_from(state_dir: Option<&str>, cache_dir: Option<&str>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = state_dir.map(str::trim).filter(|d| !d.is_empty()) {
        dirs.push(PathBuf::from(dir));
    }
    dirs.extend(machine_state_dirs());
    dirs.extend(legacy_state_dir(cache_dir));
    dirs.into_iter()
        .map(|d| d.join(CONTROL_TOKEN_FILE))
        .collect()
}

/// An environment variable's value, treating unset and blank alike.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
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

/// The legacy per-user state directory a plain (non-service) `dig-node run` writes its token into,
/// mirroring `state::legacy_state_dir`.
///
/// dig-node derives it as `config_path().parent()`, and `config_path()` is `cache_dir().parent()`
/// joined with `config.json` — so this directory is **the PARENT of dig-node's cache directory**, not
/// the cache directory itself. `cache_dir()` honours `DIG_NODE_CACHE` (which the installer sets), so
/// an override there MOVES the token: `cache_override.parent()`. Hardcoding the default root would
/// make dig-app report "no control token" against a correctly-paired node.
///
/// With no override the default is `%LOCALAPPDATA%\DigNode` / `$HOME/DigNode` — which is exactly
/// `<...>/DigNode/cache`'s parent, so both branches express the same rule.
///
/// NOT covered: when the canonical cache dir is unwritable, dig-node falls back to a PID-keyed
/// private directory, whose name is unknowable from outside that process. A node in that degraded
/// mode cannot be located by any external client until it publishes its state dir.
fn legacy_state_dir(cache_dir: Option<&str>) -> Option<PathBuf> {
    if let Some(cache) = cache_dir.map(str::trim).filter(|c| !c.is_empty()) {
        return PathBuf::from(cache)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf);
    }
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

/// Send one typed control call to `endpoint` and return its typed result.
///
/// The write-side twin of [`fetch_status`]: the same one-shot blocking JSON-RPC exchange, but generic
/// over any [`ControlCall`] in the contract crate — so `control.cache.setCap` (and any future control
/// mutation the tray needs) goes through the SAME transport, token header and response parsing rather
/// than a hand-rolled request. The cap is persisted by the NODE this reaches (which holds the config
/// lock, §2002); dig-app never writes the node's config itself.
pub fn call_control<C>(
    endpoint: &str,
    call: &C,
    token: Option<&str>,
    timeout: Duration,
) -> Result<C::Output, ControlCallError>
where
    C: ControlCall,
{
    call_control_result(endpoint, call, token, timeout).map_err(|failure| match failure {
        ControlFailure::Transport(e) => e,
        ControlFailure::Rejected(e) => ControlCallError::Refused(e.message),
    })
}

/// Why a control call did not produce a result, **keeping the node's typed refusal intact**.
///
/// [`call_control`] flattens a rejection to its human message, which is all its callers need. A
/// caller that must BRANCH on what the node said — "you are running a build without this method"
/// reads differently to "the read failed" — needs the stable `data.code` symbol and the numeric wire
/// code, and neither survives that flattening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFailure {
    /// The call never reached a node, or its reply was unreadable.
    Transport(ControlCallError),
    /// A node answered with a JSON-RPC error, carried whole so the caller can key off
    /// [`ControlError::data`]'s stable symbol rather than the human message.
    Rejected(ControlError),
}

impl std::fmt::Display for ControlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlFailure::Transport(e) => write!(f, "{e}"),
            ControlFailure::Rejected(e) => write!(f, "{}", e.message),
        }
    }
}

impl std::error::Error for ControlFailure {}

/// [`call_control`], but surfacing the node's typed [`ControlError`] instead of only its message.
///
/// The transport is identical; only the error shape differs. `call_control` is written in terms of
/// this, so there is exactly one request/response path and the two can never drift.
pub fn call_control_result<C>(
    endpoint: &str,
    call: &C,
    token: Option<&str>,
    timeout: Duration,
) -> Result<C::Output, ControlFailure>
where
    C: ControlCall,
{
    let request = build_request(RequestId::from(1), call);
    let body = serde_json::to_vec(&request).map_err(|e| {
        ControlFailure::Transport(ControlCallError::BadResponse(format!(
            "could not encode the request: {e}"
        )))
    })?;
    let raw = post_json(endpoint, &body, token, timeout).map_err(ControlFailure::Transport)?;
    let response: JsonRpcResponse = serde_json::from_slice(&raw).map_err(|e| {
        ControlFailure::Transport(ControlCallError::BadResponse(format!(
            "not a JSON-RPC response: {e}"
        )))
    })?;
    parse_response::<C>(response).map_err(ControlFailure::Rejected)
}

/// Set the node's content-cache size cap, returning the cap the node now holds.
///
/// A thin, named wrapper over [`call_control`] for `control.cache.setCap`, so the tray shell applies a
/// cap without depending on the contract crate directly. The node ECHOES the cap it applied (which may
/// differ from the request — it floors sub-64-MiB values), and this returns that echoed value so the
/// caller reports the truth rather than the request.
pub fn set_cache_cap(
    endpoint: &str,
    cap_bytes: u64,
    token: Option<&str>,
    timeout: Duration,
) -> Result<u64, ControlCallError> {
    use dig_node_control_interface::params::SetCapParams;
    call_control(endpoint, &SetCapParams { cap_bytes }, token, timeout).map(|r| r.cap_bytes)
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
    let trust = trust_for(&host);
    post_json_to(&host, port, body, token, timeout, trust)
}

/// [`post_json`] with the endpoint already split and its [`EndpointTrust`] stated outright.
///
/// The trust is a parameter rather than something re-derived down here so that the one rule that
/// decides whether this machine's control token may leave the machine — [`trust_for`] — lives in
/// exactly one place and is directly exercisable by a test.
fn post_json_to(
    host: &str,
    port: u16,
    body: &[u8],
    token: Option<&str>,
    timeout: Duration,
    trust: EndpointTrust,
) -> Result<Vec<u8>, ControlCallError> {
    let stream = connect(host, port, timeout, trust)?;
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
        .map_err(|e| stalled_or(&e, format!("could not send the request: {e}")))?;

    read_http_body(stream)
}

/// Classify a socket error on an ALREADY-CONNECTED stream.
///
/// The connection succeeded, so a node is demonstrably there and the only thing in doubt is whether
/// it answered in time. An expired socket timeout is therefore
/// [`TimedOut`](ControlCallError::TimedOut); anything else (a reset, a broken pipe) genuinely lost
/// the link and stays [`Unreachable`](ControlCallError::Unreachable).
///
/// Windows reports an expired read timeout as `TimedOut` and Unix as `WouldBlock`, so both kinds
/// mean the same thing here (dig_ecosystem#2325).
fn stalled_or(error: &std::io::Error, detail: String) -> ControlCallError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            ControlCallError::TimedOut(detail)
        }
        _ => ControlCallError::Unreachable(detail),
    }
}

/// Who chose an endpoint, which decides whether this machine's control token may travel to it.
///
/// The distinction is not cosmetic: the token authorizes every `control.*` mutation on the local
/// node, so it may only ever be handed to a peer the *user* named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointTrust {
    /// A host dig-app guessed at on the user's behalf — the `dig.local` / `localhost` ladder tiers.
    /// Nobody vouched for whoever answers to that name, so the address it resolves to MUST be
    /// loopback (dig_ecosystem#2471).
    AutoDiscovered,
    /// A host the user typed into settings. It may legitimately be a node on another machine, and
    /// §5.3 says a configured node always wins — so no address filter applies.
    UserConfigured,
}

/// Classify a host by whether dig-app guessed it or the user named it.
///
/// The two ladder names are the whole auto-discovered set ([`endpoint_ladder`]), and neither is
/// authoritatively owned on a stock machine: `dig.local` is answered by mDNS/LLMNR when the
/// installer's hosts entry is absent, so any same-LAN responder can claim it. A user who types one
/// of those two names by hand is pointing at their own machine anyway, so requiring loopback of them
/// costs a correctly-installed user nothing while closing the impersonation entirely.
fn trust_for(host: &str) -> EndpointTrust {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == dig_constants::DIG_LOCAL_HOST || host == "localhost" {
        EndpointTrust::AutoDiscovered
    } else {
        EndpointTrust::UserConfigured
    }
}

/// Dial `host:port`, preferring IPv6 (§5.2) among the resolved addresses.
///
/// `localhost` resolves to both loopback families and the node's IPv6 listener is best-effort — so
/// we try each resolved address in IPv6-first order and take the first that connects, rather than
/// betting the whole probe on whichever address the resolver happened to list first.
///
/// An [`EndpointTrust::AutoDiscovered`] host is additionally held to resolving *only* to loopback,
/// and the filter is applied HERE — before any socket is opened — so that a name hijacked on the
/// LAN never receives so much as a connection, let alone the control token
/// (dig_ecosystem#2471).
fn connect(
    host: &str,
    port: u16,
    timeout: Duration,
    trust: EndpointTrust,
) -> Result<TcpStream, ControlCallError> {
    let mut addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| ControlCallError::Unreachable(format!("cannot resolve {host}: {e}")))?
        .collect();
    if trust == EndpointTrust::AutoDiscovered {
        addrs.retain(|a| a.ip().is_loopback());
        if addrs.is_empty() {
            return Err(ControlCallError::Unreachable(format!(
                "{host} did not resolve to this machine, so it is not the local node; \
                 set an explicit node address in settings to reach a node elsewhere"
            )));
        }
    }
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
        .map_err(|e| stalled_or(&e, format!("no reply from the node: {e}")))?;
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
        return Err(ControlCallError::HttpRefused { code, detail });
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
        //
        // The refusal happens at the HTTP layer, before a JSON-RPC error could exist, so the honest
        // shape is `HttpRefused` carrying the status as a fact rather than `Refused` carrying prose
        // (dig_ecosystem#2330). Asserting the code and not merely the variant is what distinguishes
        // "this app holds no usable token" — which has a remedy — from any other HTTP failure.
        let node = FakeNode::serving_status();
        let err = fetch_status(&node.endpoint(), None, quick()).expect_err("must be refused");
        assert!(
            matches!(err, ControlCallError::HttpRefused { code: 401, .. }),
            "expected a 401 refusal, got {err:?}"
        );
    }

    /// **An HTTP refusal carries its status as a FACT, and a node's prose cannot forge one**
    /// (dig_ecosystem#2330).
    ///
    /// A caller telling "this app holds no usable control token" apart from "the node fell over"
    /// branches on this status, so where it comes from is the whole property. The second half is the
    /// load-bearing one: the earlier shape formatted the status into `Refused`'s string and parsed
    /// it back, and this fixture — a node whose JSON-RPC *message* is literally `HTTP 401 …` — is
    /// the only one that can see the difference, because both shapes agree on every other input.
    #[test]
    fn an_http_refusal_carries_its_status_and_a_node_message_cannot_forge_one() {
        for status in [401u16, 403, 500] {
            let node = FakeNode::with_behaviour(Behaviour::Http(status, "refused".into()));
            let err = fetch_status(&node.endpoint(), Some(node.token()), quick())
                .expect_err("a non-2xx is not a status");
            assert!(
                matches!(err, ControlCallError::HttpRefused { code, .. } if code == status),
                "the status must survive the trip as a typed fact; got {err:?}"
            );
        }

        let node = FakeNode::with_behaviour(Behaviour::JsonRpcError("HTTP 401 nice try".into()));
        let err = fetch_status(&node.endpoint(), Some(node.token()), quick())
            .expect_err("a JSON-RPC error is not a status");
        assert_eq!(
            err,
            ControlCallError::Refused("HTTP 401 nice try".to_string()),
            "a message the NODE wrote must not become an authorization refusal it never made"
        );
        // ...and the sentence a person reads did not change when the variant split.
        assert_eq!(
            ControlCallError::HttpRefused {
                code: 401,
                detail: "no".to_string()
            }
            .to_string(),
            "the node refused the request: HTTP 401 no"
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

    /// **A node that connects and answers LATE is not a node that is absent** (dig_ecosystem#2325).
    ///
    /// Two actors vary by exactly one thing — whether anything is listening — and the transport must
    /// report them differently, because only one of them says anything at all about whether a node
    /// exists. Before this, both produced [`ControlCallError::Unreachable`], and a chain read that
    /// merely overran its budget reached the user as "no DIG node is running".
    ///
    /// The dead-port control is what makes this a placement test rather than an outcome test: an
    /// implementation that renamed every failure to `TimedOut` would pass the first half and fail
    /// the second.
    #[test]
    fn a_late_answer_is_a_timeout_while_a_dead_port_stays_unreachable() {
        let slow = FakeNode::with_behaviour(Behaviour::SlowWallet {
            reply: crate::test_support::node::WalletReply::Balance {
                xch: 1,
                dig: 1,
                synced: true, source: Some("db"), peak_height: Some(6_000_000),},
            // Comfortably past the budget below, so the outcome cannot depend on scheduling noise.
            delay: Duration::from_secs(3),
        });
        let late = fetch_status(
            &slow.endpoint(),
            Some(slow.token()),
            Duration::from_millis(200),
        )
        .expect_err("the reply arrives after the budget");
        assert!(
            matches!(late, ControlCallError::TimedOut(_)),
            "a node that answered late must not be reported as absent; got {late:?}"
        );

        let dead = fetch_status(&dead_endpoint(), Some("t"), Duration::from_millis(200))
            .expect_err("nothing is listening");
        assert!(
            matches!(dead, ControlCallError::Unreachable(_)),
            "a dead port is genuinely unreachable; got {dead:?}"
        );
    }

    /// The timeout's own words describe OUR call, never the node's existence — the wording defect
    /// behind dig_ecosystem#2325 was as damaging as the budget that triggered it.
    #[test]
    fn a_timeout_describes_the_call_not_the_node() {
        let message = ControlCallError::TimedOut("after 200ms".to_string()).to_string();
        assert!(
            !message.contains("no DIG node"),
            "a timeout cannot know whether a node is running: {message}"
        );
        assert!(message.contains("did not answer"), "{message}");
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
    fn the_cache_dir_override_moves_the_legacy_token_location() {
        // dig-node's legacy state dir is `config_path().parent()` = `cache_dir().PARENT()`, and
        // `cache_dir()` honours DIG_NODE_CACHE. With that var set (the installer sets it), a token
        // written by a plain `dig-node run` is NOT under the default %LOCALAPPDATA%/$HOME root, so a
        // hardcoded default reports "no control token" against a correctly-paired node.
        //
        // Built from a tempdir rather than a literal so the fixture is a real path on EVERY OS: a
        // `D:\...` literal has no parent on Linux, where the coverage gate runs, and would have
        // passed there for the wrong reason.
        let root = tempfile::tempdir().expect("tempdir");
        let cache = root.path().join("cache");
        let candidates = control_token_candidates_from(None, cache.to_str());

        // The cache dir's PARENT, not the cache dir itself. A fix that joined the cache dir would
        // look in `<cache>/control-token` — the nearest wrong implementation — so this asserts the
        // exact expected path AND the absence of the wrong one.
        assert!(
            candidates.contains(&root.path().join(CONTROL_TOKEN_FILE)),
            "expected the cache dir's PARENT ({:?}); got {candidates:?}",
            root.path().join(CONTROL_TOKEN_FILE)
        );
        assert!(
            !candidates.contains(&cache.join(CONTROL_TOKEN_FILE)),
            "the cache dir itself is not the state dir; got {candidates:?}"
        );
    }

    #[test]
    fn the_state_dir_override_still_outranks_the_cache_dir_override() {
        // Both overrides set: DIG_NODE_STATE_DIR is dig-node's own direct state-dir override and
        // MUST win, so the fixture sets BOTH — with only one set, either order would pass.
        let root = tempfile::tempdir().expect("tempdir");
        let state = root.path().join("state");
        let cache = root.path().join("cache");
        let candidates = control_token_candidates_from(state.to_str(), cache.to_str());
        assert_eq!(
            candidates.first(),
            Some(&state.join(CONTROL_TOKEN_FILE)),
            "the explicit state-dir override must be tried FIRST; got {candidates:?}"
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

    /// The control token authorizes every `control.*` mutation on this machine's node, so an
    /// auto-discovered ladder name that resolves OFF loopback must receive **no bytes at all** —
    /// not a refused call, not an empty request, nothing (dig_ecosystem#2471).
    ///
    /// `dig.local` is answered by mDNS/LLMNR when the installer's hosts entry is missing, so a
    /// same-LAN responder can hold that name. The fixture is a listener on a NON-loopback local
    /// address, which is the property under test; asserting from the SERVER's accept queue (rather
    /// than from an internal predicate) is what makes the test blind to no path — a guard placed
    /// after the dial, or a second code path that still sent the header, would both be caught here.
    #[test]
    fn an_auto_discovered_host_off_loopback_receives_nothing() {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        assert!(
            !std::net::Ipv4Addr::UNSPECIFIED.is_loopback(),
            "the fixture is only meaningful if its address is genuinely not loopback"
        );

        let err = post_json_to(
            "0.0.0.0",
            port,
            b"{}",
            Some("super-secret-control-token"),
            quick(),
            EndpointTrust::AutoDiscovered,
        )
        .expect_err("a non-loopback answer to an auto-discovered name is not the local node");

        assert!(
            matches!(err, ControlCallError::Unreachable(ref m) if m.contains("not the local node")),
            "the person must be told this is not their node, and how to reach one elsewhere; got {err:?}"
        );
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((stream, peer)) => panic!(
                "a connection reached {peer} — the token may already be in its buffer: {stream:?}"
            ),
            Err(e) => panic!("unexpected accept error: {e}"),
        }
    }

    /// The same fixture with exactly ONE field varied — the trust — still reaches a non-loopback
    /// address and still carries the token.
    ///
    /// This is the direction that would make an over-strict fix a worse regression than the bug:
    /// §5.3 says an explicitly configured node always wins, so a user pointing dig-app at their own
    /// node on another machine must keep working. Its control is the test above.
    ///
    /// **Ignored on Windows (dig_ecosystem#2705), because it hangs there rather than failing.**
    /// `accept()` and `read_to_end()` below are both untimed, and `read_to_end` returns only at EOF
    /// — i.e. only once the client end is fully closed. The 300ms budget passed to `post_json_to`
    /// bounds the CLIENT's wait, not this side's. Dialling the wildcard `0.0.0.0` is also
    /// platform-dependent: Linux routes it to localhost, Windows does not. The result is not a red
    /// test but a wedged harness — no `test result:` line at all — which is indistinguishable from
    /// a dead agent, and which ran the `Native confirmer (windows-latest)` job into GitHub's
    /// six-hour ceiling on every merge to `main` after it landed.
    ///
    /// `ignore` rather than `cfg(not(windows))` on purpose: the test still COMPILES on Windows, so
    /// it cannot rot behind a cfg while the code it covers changes, and it can still be run there
    /// deliberately with `-- --ignored` once the fix lands. It still runs normally on Linux and
    /// macOS, so the guarantee keeps a real guard on two of three platforms.
    ///
    /// Un-skip by bounding THIS side — `set_read_timeout` on the accepted stream, and read the
    /// request head rather than to EOF, since only headers are asserted — and dialling `127.0.0.1`.
    #[test]
    #[cfg_attr(
        windows,
        ignore = "hangs on Windows: untimed accept()/read_to_end() on a 0.0.0.0 dial (dig_ecosystem#2705)"
    )]
    fn a_user_configured_host_off_loopback_still_receives_the_token() {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let _ = post_json_to(
            "0.0.0.0",
            port,
            b"{}",
            Some("super-secret-control-token"),
            Duration::from_millis(300),
            EndpointTrust::UserConfigured,
        );

        let (mut stream, _) = listener
            .accept()
            .expect("the configured node must be dialled");
        let mut request = Vec::new();
        stream.read_to_end(&mut request).expect("read the request");
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.contains(&format!(
                "{CONTROL_TOKEN_HEADER}: super-secret-control-token"
            )),
            "a node the user named must still be authorized; got:
{request}"
        );
    }

    /// The refusal happens on the RESOLVED address, before any dial — so an auto-discovered name
    /// pointing at an unroutable LAN address costs no connect timeout.
    ///
    /// The elapsed bound is the assertion that matters: a filter applied after `connect_timeout`
    /// would satisfy the error check and blow this budget.
    #[test]
    fn an_auto_discovered_host_off_loopback_is_refused_without_dialling() {
        let started = std::time::Instant::now();
        let err = connect(
            "10.255.255.1",
            9778,
            Duration::from_secs(20),
            EndpointTrust::AutoDiscovered,
        )
        .expect_err("an unroutable LAN address is not the local node");
        assert!(
            matches!(err, ControlCallError::Unreachable(_)),
            "got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "no dial may be attempted; took {:?}",
            started.elapsed()
        );
    }

    /// Only the two names dig-app guesses at are held to loopback; everything else is the user's
    /// choice. Case and a trailing root dot are the same name to a resolver, so they must be the
    /// same name here too.
    #[test]
    fn only_the_guessed_ladder_names_are_auto_discovered() {
        for guessed in [
            "dig.local",
            "DIG.Local",
            "dig.local.",
            "localhost",
            "LOCALHOST",
        ] {
            assert_eq!(
                trust_for(guessed),
                EndpointTrust::AutoDiscovered,
                "{guessed} is a name dig-app guessed at"
            );
        }
        for named in ["10.0.0.5", "my-node.lan", "node.example.com", "127.0.0.1"] {
            assert_eq!(
                trust_for(named),
                EndpointTrust::UserConfigured,
                "{named} can only have come from the user"
            );
        }
    }

    /// Both loopback families answer to `localhost`, and the ladder must keep reaching them — the
    /// filter is about non-loopback answers, never about narrowing the local node to IPv4.
    #[test]
    fn the_localhost_tier_still_reaches_a_real_loopback_node() {
        let node = FakeNode::serving_status();
        let (host, port) = split_host_port(&node.endpoint()).expect("split");
        let body = post_json_to(
            &host,
            port,
            br#"{"jsonrpc":"2.0","id":1,"method":"control.status","params":{}}"#,
            Some(node.token()),
            quick(),
            EndpointTrust::AutoDiscovered,
        )
        .expect("a loopback node must still be reachable from an auto-discovered tier");
        assert!(!body.is_empty());
    }
}
