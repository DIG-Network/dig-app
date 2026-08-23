//! The `dign` half of the CLI lane: dial the running dig-app, attach, ask one question.
//!
//! This is the whole implementation behind `dign`'s `send_to_app`. It lives here, in the library,
//! rather than in the binary, for the reason every other piece of `dign` does: a binary is a
//! test-free zone, and the attach-then-dispatch sequence is exactly the part that must be proven.

use std::path::Path;
use std::time::Duration;

use crate::gateway::{Command, ErrorCode, GatewayError, Outcome};
use crate::Os;

use super::auth::SessionToken;
use super::deadline::FrameBudget;
use super::endpoint::cli_endpoint;
use super::handshake::{self, Nonce};
use super::transport;
use super::wire::{ChallengeAnswer, Request, Response};

use dig_ipc_protocol::FrameTransport;

/// The request ids of the three frames one `dign` invocation sends, in order.
const CHALLENGE_ID: u64 = 1;
const ATTACH_ID: u64 = 2;
const COMMAND_ID: u64 = 3;

/// How long the peer may take to answer a HANDSHAKE frame before this process gives up on it.
///
/// Both handshake legs are answered out of the app's own memory -- mint a nonce, compute one MAC,
/// compare one MAC -- and reach neither disk nor network. Ten seconds is enormous for that work, and
/// deliberately so: this bound exists to end a silence, not to police latency on a loaded machine.
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

/// How long the peer may take to answer the COMMAND frame.
///
/// Longer than [`HANDSHAKE_BUDGET`] because different work bounds it: the app may consult the node,
/// and through it the chain, before it can answer. One budget across both legs would have to be this
/// one, which would let a peer that never speaks at all hold the terminal for a minute rather than
/// the ten seconds its silence deserves.
const COMMAND_BUDGET: Duration = Duration::from_secs(60);

/// What this process was waiting for when the peer stopped answering, in the words a person reads.
const HANDSHAKE_LEG: &str = "for it to prove it is dig-app";
const COMMAND_LEG: &str = "for its answer to the command";

/// Send `command` to the running dig-app for this user and return what it answered.
///
/// Resolves the host's own per-user endpoint and token directory, so the CLI and the app can never
/// address different ones.
pub fn send(command: &Command) -> Result<Outcome, GatewayError> {
    let env = crate::environment::AppEnvironment::from_host();
    let brand_dir = env
        .brand_dir()
        .map_err(|e| GatewayError::new(ErrorCode::IoError, e.to_string()))?;
    send_via(
        &cli_endpoint(env.os, &env.user, &brand_dir),
        &brand_dir,
        command,
    )
}

/// [`send`], with the endpoint and token directory named explicitly — the seam an integration test
/// drives against a server it started itself.
pub fn send_via(
    endpoint: &str,
    brand_dir: &Path,
    command: &Command,
) -> Result<Outcome, GatewayError> {
    let token = SessionToken::read_published(brand_dir).map_err(not_running)?;
    // The connect leg is bounded on Unix, and needs no bound on Windows: the listener there always
    // holds an unconnected instance, so the open finds one waiting or fails at once. The same
    // exemption does NOT hold on Unix -- see `transport::unix::connect` for the Linux kernel path
    // that makes a blocking connect to a listening-but-deaf holder wait forever -- so that socket is
    // armed with `SO_SNDTIMEO` before it dials. Everything AFTER this point is a wait on bytes the
    // peer chooses to send, and every one of those legs is bounded below.
    let stream = transport::connect(endpoint).map_err(connect_failed)?;
    let budget = FrameBudget::of(HANDSHAKE_BUDGET);
    let mut frames = transport::frames(stream, budget.clone()).map_err(io_failed)?;

    // The server proves itself FIRST, and nothing but a nonce has left this process until it has.
    let client_nonce = Nonce::mint();
    let challenged = challenge_the_peer(&mut frames, client_nonce.as_hex())?;
    let server_nonce = authenticate_server(&token, &client_nonce, &challenged)?;

    let client_proof = handshake::proof(
        &token,
        handshake::CLIENT_PROOF_CONTEXT,
        &client_nonce,
        &server_nonce,
    );
    ask(
        &mut frames,
        Request::attach(ATTACH_ID, client_proof),
        HANDSHAKE_LEG,
    )?;

    budget.set(COMMAND_BUDGET);
    ask(
        &mut frames,
        Request::dispatch(COMMAND_ID, command.clone()),
        COMMAND_LEG,
    )
}

/// Ask the peer to prove itself, taking NOTHING it wrote except the two handshake values.
///
/// # Why this is not [`ask`]
///
/// [`ask`] hands the caller the peer's own [`Outcome`] or its own [`GatewayError`], and `dign` renders
/// both: the error's `message` and `hint` are printed verbatim and its `code` becomes the process exit
/// status. That is safe for every frame AFTER [`authenticate_server`] has succeeded, and unsafe for the
/// one frame before it. Three rounds of review closed that hole one channel at a time -- the transport,
/// then the `result` channel, then the `error` channel of this same frame -- so it is closed by TYPE
/// here instead: [`ChallengeAnswer`] has no field a peer's prose or exit status could travel in, and
/// every refusal below is authored in this function.
fn challenge_the_peer(
    frames: &mut impl FrameTransport,
    client_nonce_hex: &str,
) -> Result<ChallengeAnswer, GatewayError> {
    let request = Request::challenge(CHALLENGE_ID, client_nonce_hex);
    let line = serde_json::to_string(&request).map_err(encoding_failed)?;
    frames
        .send_frame(&line)
        .map_err(|e| lane_failed(e, HANDSHAKE_LEG))?;
    let reply = frames
        .recv_frame()
        .map_err(|e| lane_failed(e, HANDSHAKE_LEG))?;
    // The parse error is DISCARDED rather than interpolated: a serde message quotes the bytes it
    // choked on, which on this frame are bytes the unproven peer chose.
    let response: Response = serde_json::from_str(&reply)
        .map_err(|_| impostor("its answer to the challenge was not a frame this build can read"))?;
    response
        .into_challenge_answer()
        .map_err(|refusal| impostor(&refusal.to_string()))
}

/// Verify that whatever answered the challenge holds this app's session secret.
///
/// # Why this is the load-bearing line of the whole lane
///
/// The endpoint name is derived from the login name and needs no privilege to create, so the peer on
/// the other end of a successful `connect` is NOT necessarily dig-app. Before this check existed the
/// client sent the session token as its first frame, which handed the secret to any local principal
/// that had claimed the name first and let it answer with a fabricated wallet address. Everything
/// after this function assumes the peer is the real app; nothing before it may assume anything.
///
/// Returns the server nonce, so the transcript the client proves over can only be the one it verified.
fn authenticate_server(
    token: &SessionToken,
    client_nonce: &Nonce,
    challenged: &ChallengeAnswer,
) -> Result<Nonce, GatewayError> {
    let server_nonce =
        Nonce::from_peer_hex(&challenged.server_nonce_hex).map_err(|e| impostor(&e.to_string()))?;
    handshake::verify(
        token,
        handshake::SERVER_PROOF_CONTEXT,
        client_nonce,
        &server_nonce,
        &challenged.server_proof_hex,
    )
    .map_err(|e| impostor(&e.to_string()))?;
    Ok(server_nonce)
}

/// The refusal when the peer on the lane is not the app that published the session secret.
///
/// Loud on purpose. Every other failure on this lane is ordinary (the app is not running, the pipe
/// broke); this one means something is ANSWERING for dig-app, and the person needs to know that
/// rather than see a shrug.
fn impostor(detail: &str) -> GatewayError {
    tracing::error!(
        detail,
        "the process answering the dign CLI lane is not this dig-app"
    );
    GatewayError::new(
        ErrorCode::Denied,
        format!("refusing this lane: the process answering it is not dig-app ({detail})"),
    )
    .with_hint(
        "another program on this machine is holding the DIG command-line endpoint. Nothing it \
         printed can be trusted. Close it, restart the DIG app, then run this command again.",
    )
}

/// Send one request and read its answer, giving up if the peer stops answering.
///
/// `leg` names what this process was waiting for, so a timeout can say which silence it hit.
fn ask(
    frames: &mut impl FrameTransport,
    request: Request,
    leg: &str,
) -> Result<Outcome, GatewayError> {
    let line = serde_json::to_string(&request).map_err(encoding_failed)?;
    frames.send_frame(&line).map_err(|e| lane_failed(e, leg))?;
    let reply = frames.recv_frame().map_err(|e| lane_failed(e, leg))?;
    let response: Response = serde_json::from_str(&reply).map_err(|e| {
        GatewayError::new(
            ErrorCode::IoError,
            format!("dig-app sent a reply this build cannot read: {e}"),
        )
    })?;
    response.into_result()
}

/// A request this build could not even encode. Never peer-influenced: the request is ours.
fn encoding_failed(error: serde_json::Error) -> GatewayError {
    GatewayError::new(
        ErrorCode::IoError,
        format!("could not encode the request: {error}"),
    )
}

/// The failure a person actually has when the socket or the token file is not there: dig-app is not
/// running. Reported as `NOT_CONNECTED` with the remedy, never as a raw OS error.
fn not_running(error: std::io::Error) -> GatewayError {
    tracing::debug!(error = %error, "the dig-app CLI lane could not be reached");
    GatewayError::new(ErrorCode::NotConnected, "dig-app is not running")
        .with_hint("start the DIG app, then run this command again")
}

/// A failure once the lane WAS reachable: an I/O error, not a missing app.
fn io_failed(error: std::io::Error) -> GatewayError {
    GatewayError::new(
        ErrorCode::IoError,
        format!("the dig-app session failed mid-request: {error}"),
    )
}

/// A failure on one leg of an established lane, told apart by whether the peer went SILENT.
///
/// # Why the silence gets its own sentence
///
/// A peer that accepted the connection and then never wrote is a different diagnosis from one that
/// could not be reached, and the remedy differs with it: nothing is wrong with the endpoint, so
/// "start the DIG app" is the wrong advice and "could not connect" is the wrong description. What the
/// person needs to know is that something IS holding the command-line endpoint and has stopped
/// answering -- which, since the address needs no privilege to claim, may not be dig-app at all.
///
/// The code stays `NOT_CONNECTED`: a peer that will not speak is, for every purpose a caller has,
/// indistinguishable from an app that is not there, and minting a new exit status for it would change
/// what every existing script does with this lane.
fn lane_failed(error: std::io::Error, leg: &str) -> GatewayError {
    if !expired(&error) {
        return io_failed(error);
    }
    tracing::warn!(
        leg,
        "the process holding the dign CLI endpoint accepted the connection and stopped answering"
    );
    held_endpoint(&format!(
        "the process holding the DIG command-line endpoint accepted this connection and then \
         stopped answering; gave up waiting {leg}"
    ))
}

/// Whether `error` is one of this lane's own bounds expiring rather than a real I/O failure.
///
/// Two kinds, because the two mechanisms report differently: a READ deadline surfaces as
/// [`std::io::ErrorKind::TimedOut`], while an expired `SO_SNDTIMEO` on a write or on the connect
/// surfaces as `EAGAIN` -- [`std::io::ErrorKind::WouldBlock`]. Matching only the first would leave
/// the 30s write bound and the connect bound reporting a raw OS message in place of the authored
/// remedy, which is the whole point of having them.
fn expired(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// The failure of the CONNECT leg, told apart by whether the endpoint is HELD or simply absent.
///
/// A refused connect really does mean the app is not running, and "start the DIG app" is the right
/// remedy for it -- so that case is deliberately left reported exactly as it was. A connect that
/// EXPIRED is the opposite diagnosis: something bound the name, called `listen`, and is not
/// accepting, which no restart of a stopped app addresses.
fn connect_failed(error: std::io::Error) -> GatewayError {
    if !expired(&error) {
        return not_running(error);
    }
    tracing::warn!("the process holding the dign CLI endpoint is not accepting connections");
    held_endpoint(
        "the process holding the DIG command-line endpoint is not accepting connections; gave up \
         waiting for it to answer the dial",
    )
}

/// The one refusal every held-endpoint diagnosis shares: what happened, and the remedy that fits it.
///
/// The code stays `NOT_CONNECTED` -- see [`lane_failed`] for why a new exit status would change what
/// every existing script does with this lane.
fn held_endpoint(what: &str) -> GatewayError {
    GatewayError::new(ErrorCode::NotConnected, what.to_owned()).with_hint(
        "the endpoint is being held, so this is not simply a stopped app: something on this machine \
         claimed it and is not answering. Quit the DIG app if it is running, close whatever else may \
         be holding the endpoint, then start the DIG app and run this command again.",
    )
}

/// The endpoint this host's `dign` dials, for the `--json` diagnostics and the docs.
pub fn host_endpoint(os: Os, user: &str, brand_dir: &Path) -> String {
    cli_endpoint(os, user, brand_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_session::server::CliSessionServer;
    use crate::cli_session::test_support::{ApprovingConfirmer, StubIdentity, UnusedOpener};
    use crate::gateway::ProfilesAction;

    /// The FULL round trip over a real OS channel: a server bound on this host's native transport,
    /// a client that resolves the endpoint and token from disk exactly as `dign` does, and the two
    /// acceptance verbs answered across it.
    ///
    /// An in-memory duplex cannot prove this. The per-OS transport, the `try_clone` of the duplex
    /// halves, the token file's location, and the framing across a kernel buffer are precisely the
    /// parts a fake replaces — and precisely the parts that have to work on the user's machine.
    #[test]
    fn a_real_client_reaches_a_real_server_over_the_per_user_channel() {
        let dir = tempfile::tempdir().unwrap();
        let brand_dir = dir.path().to_path_buf();
        let endpoint = cli_endpoint(
            crate::environment::current_os(),
            &format!("digtest-{}", std::process::id()),
            &brand_dir,
        );

        let serving_endpoint = endpoint.clone();
        let serving_dir = brand_dir.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (identity, opener, confirmer) =
                (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
            let server = CliSessionServer::bind(
                &serving_endpoint,
                &serving_dir,
                &identity,
                &opener,
                &confirmer,
            )
            .expect("the lane binds");
            ready_tx.send(()).unwrap();
            // Two conversations: one per verb, because `dign` is a one-shot process.
            for _ in 0..2 {
                let stream = server.accept_one().expect("a client connects");
                server
                    .serve_one(stream)
                    .expect("the conversation completes");
            }
        });
        ready_rx.recv().expect("the server publishes its token");

        let listed = send_via(
            &endpoint,
            &brand_dir,
            &Command::Profiles(ProfilesAction::List),
        )
        .expect("profiles list crosses the channel");
        assert_eq!(listed.result["profiles"][0]["did"], "did:chia:one");

        let balance = send_via(
            &endpoint,
            &brand_dir,
            &Command::Wallet(crate::gateway::WalletAction::Balance),
        )
        .expect("wallet balance crosses the channel");
        assert_eq!(balance.result["balance_mojos"], 4_200);

        server.join().expect("the server thread ends cleanly");
    }

    /// With no app running there is no token file, and the person is told the actionable thing —
    /// not an `ENOENT`.
    #[test]
    fn a_missing_app_reports_not_connected_with_the_remedy() {
        let dir = tempfile::tempdir().unwrap();
        let err = send_via(
            &cli_endpoint(crate::environment::current_os(), "nobody", dir.path()),
            dir.path(),
            &Command::Profiles(ProfilesAction::List),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotConnected);
        assert_eq!(
            err.hint.as_deref(),
            Some("start the DIG app, then run this command again")
        );
    }

    /// A token file that does NOT match the running app's is refused by the server, and the client
    /// surfaces that refusal rather than proceeding.
    ///
    /// This is the client-side half of the server's wrong-token guard: it proves the refusal
    /// survives the wire and stops the command, not merely that the server said no.
    #[test]
    fn a_stale_token_is_refused_across_the_channel() {
        let dir = tempfile::tempdir().unwrap();
        let brand_dir = dir.path().to_path_buf();
        let endpoint = cli_endpoint(
            crate::environment::current_os(),
            &format!("digstale-{}", std::process::id()),
            &brand_dir,
        );

        let serving_endpoint = endpoint.clone();
        let serving_dir = brand_dir.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (identity, opener, confirmer) =
                (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
            let server = CliSessionServer::bind(
                &serving_endpoint,
                &serving_dir,
                &identity,
                &opener,
                &confirmer,
            )
            .expect("the lane binds");
            ready_tx.send(()).unwrap();
            let stream = server.accept_one().expect("a client connects");
            let _ = server.serve_one(stream);
        });
        ready_rx.recv().unwrap();

        // Overwrite the published token with another well-formed one, exactly as a token left over
        // from a previous app run would be.
        SessionToken::mint().publish(&brand_dir).unwrap();

        let err = send_via(
            &endpoint,
            &brand_dir,
            &Command::Profiles(ProfilesAction::List),
        )
        .expect_err("a stale token must not be served");
        assert_eq!(err.code, ErrorCode::Denied);
        server.join().unwrap();
    }
}
