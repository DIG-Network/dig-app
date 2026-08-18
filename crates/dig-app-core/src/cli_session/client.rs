//! The `dign` half of the CLI lane: dial the running dig-app, attach, ask one question.
//!
//! This is the whole implementation behind `dign`'s `send_to_app`. It lives here, in the library,
//! rather than in the binary, for the reason every other piece of `dign` does: a binary is a
//! test-free zone, and the attach-then-dispatch sequence is exactly the part that must be proven.

use std::path::Path;

use crate::gateway::{Command, ErrorCode, GatewayError, Outcome};
use crate::Os;

use super::auth::SessionToken;
use super::endpoint::cli_endpoint;
use super::transport;
use super::wire::{Request, Response};

use dig_ipc_protocol::FrameTransport;

/// The request id of the attach, and of the single command that follows it.
const ATTACH_ID: u64 = 1;
const COMMAND_ID: u64 = 2;

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
    let stream = transport::connect(endpoint).map_err(not_running)?;
    let mut frames = transport::frames(stream).map_err(io_failed)?;

    ask(&mut frames, Request::attach(ATTACH_ID, token.as_hex()))?;
    ask(&mut frames, Request::dispatch(COMMAND_ID, command.clone()))
}

/// Send one request and read its answer.
fn ask(frames: &mut impl FrameTransport, request: Request) -> Result<Outcome, GatewayError> {
    let line = serde_json::to_string(&request).map_err(|e| {
        GatewayError::new(
            ErrorCode::IoError,
            format!("could not encode the request: {e}"),
        )
    })?;
    frames.send_frame(&line).map_err(io_failed)?;
    let reply = frames.recv_frame().map_err(io_failed)?;
    let response: Response = serde_json::from_str(&reply).map_err(|e| {
        GatewayError::new(
            ErrorCode::IoError,
            format!("dig-app sent a reply this build cannot read: {e}"),
        )
    })?;
    response.into_result()
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
