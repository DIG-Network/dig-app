//! Both remaining silent-peer legs of the CLI lane are bounded AT THEIR CALL SITES
//! (dig_ecosystem#908, dig-app#218).
//!
//! # Why these two, and why here
//!
//! `cli_session_stall` proves the client's HANDSHAKE leg is bounded, and
//! `cli_session_connect_backlog` proves the CONNECT leg is. Two legs were left with a bound whose
//! mechanism is well unit-tested in `deadline.rs` and whose INSTALLATION nothing observed:
//!
//! * the SERVER's per-frame bound, applied in
//!   [`CliSessionServer::serve_one`](dig_app_core::cli_session::CliSessionServer::serve_one). This
//!   lane serves one conversation at a time, so a client that connects and then never speaks holds
//!   the only accept slot for the life of the app and every other `diga` on the machine reports that
//!   dig-app is not running -- the #218 hang from the other side.
//! * the CLIENT's DISPATCH bound, raised from the handshake budget once the peer is proven, so an
//!   app that authenticates and then never answers the command cannot hang the terminal either.
//!
//! Measured before these tests existed: with BOTH budgets substituted to one hour, all 56 tests of
//! the lane stayed green. The server's unit tests reach `CliSession::converse` with a mock duplex and
//! therefore never traverse `serve_one`, which is the only place the server budget appears.
//!
//! # Why every bound is asserted from BOTH sides
//!
//! A test that only asserts "it returned quickly" passes against a bound of zero and against a peer
//! that hung up, so each measurement below carries a lower bound too: the wait must be long enough
//! that only the budget under test could have ended it, and short enough that a budget exists at all.
//! The lower bound is what makes the DISPATCH test see its own placement -- with the raise deleted
//! the client would give up at the 10s handshake budget, which is green against an upper bound alone.
//!
//! # Why every measurement runs on its own thread
//!
//! Against an unbounded leg the call under test does not fail, it HANGS. A test that hangs takes the
//! runner down with it instead of reporting, so each call is made on a worker thread and the
//! assertions wait on a channel.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use dig_app_core::cli_session::{
    cli_endpoint, send_via, transport, CliSessionServer, HostIdentity, UnavailableConfirmer,
    UnopenedLinks,
};
use dig_app_core::gateway::{
    Command, EngineProxy, ErrorCode, GatewayError, LocalIdentity, PendingProfileCreation,
    ProfileSeedRequest, ProfileSummary, ProfilesAction,
};

/// An engine seam that refuses everything, because neither budget under test routes an engine verb.
///
/// A real proxy would dial a node, and a fixture that reached the network would measure the
/// network's patience rather than this lane's — which is the one thing these two tests must not do.
struct NoEngine;

impl EngineProxy for NoEngine {
    fn call(
        &self,
        _method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::NotConnected,
            "this fixture routes no engine verb",
        ))
    }
}

/// Distinguishes concurrent lanes: the Windows pipe namespace is machine-global.
static NEXT_LANE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// The host OS the endpoint is addressed for -- this one, so the fixture uses the real transport.
fn host_os() -> dig_app_core::Os {
    if cfg!(windows) {
        dig_app_core::Os::Windows
    } else if cfg!(target_os = "macos") {
        dig_app_core::Os::MacOs
    } else {
        dig_app_core::Os::Linux
    }
}

/// A per-user endpoint nothing else in this process is using.
fn a_private_endpoint(tag: &str, brand_dir: &std::path::Path) -> String {
    cli_endpoint(
        host_os(),
        &format!(
            "{tag}-{}-{}",
            std::process::id(),
            NEXT_LANE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        brand_dir,
    )
}

/// The headline for the server leg: a client that connects and says nothing releases the lane.
///
/// The bound under test is the SERVER's, so the measurement is `serve_one` itself rather than
/// anything the client observes: the client here never learns whether it was dropped.
#[test]
fn a_client_that_connects_and_never_speaks_cannot_hold_the_lane() {
    // Comfortably above the server's own 30s per-frame budget and far below any CI step timeout, so
    // an unbounded server FAILS this test rather than killing the runner.
    const PATIENCE: Duration = Duration::from_secs(90);

    let brand_dir = tempfile::tempdir().expect("a brand directory");
    let dir = brand_dir.path().to_path_buf();
    let endpoint = a_private_endpoint("digmute", &dir);

    // The server is built INSIDE its thread because it borrows its seams; the thread signals once
    // the endpoint is bound, so the mute client below cannot dial a name that does not exist yet.
    let (bound_tx, bound_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let serve_at = endpoint.clone();
    let serve_in = dir.clone();
    std::thread::spawn(move || {
        let identity = HostIdentity::under(&serve_in);
        let (opener, confirmer) = (UnopenedLinks, UnavailableConfirmer);
        let server = CliSessionServer::bind(
            &serve_at, &serve_in, &NoEngine, &identity, &opener, &confirmer,
        )
        .expect("the lane binds its own private endpoint");
        let _ = bound_tx.send(());
        let stream = server.accept_one().expect("the mute client connects");
        let began = Instant::now();
        let outcome = server.serve_one(stream);
        let _ = done_tx.send((outcome, began.elapsed()));
    });
    bound_rx
        .recv_timeout(PATIENCE)
        .expect("the lane binds within the test's patience");

    // Connected, and silent for the whole measurement. The stream is held rather than dropped: a
    // dropped stream is an EOF, which ends `converse` cleanly with no deadline anywhere in the code.
    let _mute = transport::connect(&endpoint).expect("a client reaches the bound lane");

    let (outcome, took) = done_rx.recv_timeout(PATIENCE).unwrap_or_else(|_| {
        panic!(
            "the lane is still serving a client that has said nothing for {PATIENCE:?}: the server \
             installs no per-frame bound, so one silent client holds the only accept slot"
        )
    });

    let error = match outcome {
        Ok(()) => panic!(
            "a silent client must not end the conversation cleanly: a clean end is what an EOF \
             produces, and this client never hung up"
        ),
        Err(error) => error,
    };
    // NOT merely "an error": a refused connection or a broken pipe would fail too, and neither
    // proves a deadline exists.
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::TimedOut,
        "the lane must give up on a DEADLINE, not on some other fault: {error}"
    );

    // Both directions. Without the lower bound this passes against a budget of zero.
    assert!(
        took >= Duration::from_secs(25),
        "the lane dropped the client after {took:?}, well inside its 30s per-frame budget, so \
         something other than the deadline ended the conversation"
    );
    assert!(
        took < Duration::from_secs(60),
        "the client frame budget is 30s; holding the lane for {took:?} means the deadline is not \
         the thing that ended it"
    );
}

/// The headline for the dispatch leg: an app that proves itself and then never answers the command
/// still cannot hang the terminal.
///
/// The peer here is the REAL server, authenticating honestly, with one seam that never returns -- so
/// the client passes its handshake and is left waiting on exactly the leg under test.
#[test]
fn a_proven_app_that_never_answers_the_command_cannot_hang_the_cli() {
    // Comfortably above the client's own 60s command budget and far below any CI step timeout.
    const PATIENCE: Duration = Duration::from_secs(120);

    let brand_dir = tempfile::tempdir().expect("a brand directory");
    let dir = brand_dir.path().to_path_buf();
    let endpoint = a_private_endpoint("digdumb", &dir);

    let (bound_tx, bound_rx) = mpsc::channel();
    let serve_at = endpoint.clone();
    let serve_in = dir.clone();
    std::thread::spawn(move || {
        let (identity, opener, confirmer) = (StalledIdentity, UnopenedLinks, UnavailableConfirmer);
        let server = CliSessionServer::bind(
            &serve_at, &serve_in, &NoEngine, &identity, &opener, &confirmer,
        )
        .expect("the lane binds its own private endpoint");
        let _ = bound_tx.send(());
        let stream = server.accept_one().expect("the client connects");
        let _ = server.serve_one(stream);
    });
    bound_rx
        .recv_timeout(PATIENCE)
        .expect("the lane binds within the test's patience");

    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        let answer = send_via(&endpoint, &dir, &Command::Profiles(ProfilesAction::List));
        let _ = done_tx.send((answer, began.elapsed()));
    });

    let (answer, took) = done_rx.recv_timeout(PATIENCE).unwrap_or_else(|_| {
        panic!(
            "the CLI is still waiting after {PATIENCE:?} for a command answer from an app that \
             proved itself and then went quiet: the dispatch leg has no bound"
        )
    });

    let error = match answer {
        Ok(outcome) => panic!(
            "an unanswered command must not produce an answer: {:?}",
            outcome.result
        ),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::NotConnected);
    // The refusal must name the leg it gave up on, so a handshake timeout cannot be mistaken for
    // this one.
    assert!(
        error.message.contains("for its answer to the command"),
        "the refusal must name the DISPATCH leg, not the handshake: {}",
        error.message
    );

    // The lower bound is the placement proof: the dispatch budget is raised from the 10s handshake
    // budget once the peer is proven, so a client that gave up near 10s never installed the raise.
    assert!(
        took >= Duration::from_secs(50),
        "the CLI gave up after {took:?}, which is the HANDSHAKE budget rather than the command \
         budget: the dispatch leg never had its own bound installed"
    );
    assert!(
        took < Duration::from_secs(100),
        "the command budget is 60s; waiting {took:?} means the deadline is not the thing that \
         ended it"
    );
}

/// Long enough to outlast any bound this lane could reasonably choose, so the seam is still stalled
/// when the measurement ends.
const FOREVER: Duration = Duration::from_secs(600);

/// An identity whose served seam is reached and never returns -- an app that authenticated and then
/// wedged, which is indistinguishable, from the CLI's side, from one that chose not to answer.
struct StalledIdentity;

impl LocalIdentity for StalledIdentity {
    fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
        std::thread::sleep(FOREVER);
        unreachable!("the measurement ends long before this seam returns")
    }
    fn begin_profile_creation(
        &self,
        _seed: ProfileSeedRequest,
    ) -> Result<PendingProfileCreation, GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn select_profile(&self, _did: &str) -> Result<(), GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn default_profile(&self) -> Result<Option<String>, GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn set_default_profile(&self, _did: &str) -> Result<(), GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn wallet_address(&self) -> Result<String, GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn wallet_balance(&self) -> Result<u64, GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, GatewayError> {
        unreachable!("this fixture dispatches `profiles list` and nothing else")
    }
}
