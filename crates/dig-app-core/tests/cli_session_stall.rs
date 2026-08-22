//! A holder of the CLI endpoint that accepts the connection and then never answers must not be able
//! to stop `dign` from ever returning (dig_ecosystem#908, dig-app#218).
//!
//! # Why the fixture STALLS instead of closing
//!
//! The obvious fixture — accept, then drop the stream — proves nothing at all: a closed stream returns
//! EOF on the first read, so the client returns promptly with **no deadline anywhere in the code**.
//! That test is green against the defect it claims to catch. The holder below therefore completes the
//! accept and then parks the connection alive, in a thread that outlives the measurement, so the only
//! thing that can end the client's wait is a deadline.
//!
//! # Why the whole measurement runs on its own thread
//!
//! Against an unfixed build the call under test does not fail, it HANGS. A test that hangs takes the
//! CI runner down with it rather than reporting a failure, so the call is made on a worker thread and
//! the assertions wait on a channel: an unfixed build fails this test with a legible message, in
//! bounded time, and the harness stays alive to report it.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use dig_app_core::cli_session::{cli_endpoint, send_via, transport, SessionToken};
use dig_app_core::gateway::{Command, ErrorCode, ProfilesAction};

/// Distinguishes concurrent holders: the Windows pipe namespace is machine-global.
static NEXT_HOLDER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// The longest this test will wait for the client to return before declaring the lane hung.
///
/// Comfortably above the client's own handshake budget and far below any CI step timeout, so an
/// unfixed build reports a FAILURE here rather than a killed runner.
const PATIENCE: Duration = Duration::from_secs(90);

/// A process that holds the per-user CLI endpoint, accepts, and then says nothing at all — a squatter,
/// or an app that wedged after binding. Either way the bytes never come.
struct SilentHolder {
    endpoint: String,
    brand_dir: tempfile::TempDir,
    /// The accepted connection, parked here so it stays OPEN for the whole measurement. Dropping it
    /// would close the stream and hand the client an EOF, which is the failure mode this fixture
    /// exists to avoid.
    _parked: mpsc::Receiver<()>,
}

impl SilentHolder {
    fn claim_the_endpoint() -> Self {
        let brand_dir = tempfile::tempdir().expect("a brand directory");
        let os = if cfg!(windows) {
            dig_app_core::Os::Windows
        } else if cfg!(target_os = "macos") {
            dig_app_core::Os::MacOs
        } else {
            dig_app_core::Os::Linux
        };
        let endpoint = cli_endpoint(
            os,
            &format!(
                "digstall-{}-{}",
                std::process::id(),
                NEXT_HOLDER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            brand_dir.path(),
        );
        let listener = transport::bind(&endpoint, brand_dir.path())
            .expect("the silent holder claims the predictable name first");
        // The client reads the published token before it dials, so a lane with no token file would
        // refuse before ever reaching the silence under test.
        SessionToken::mint()
            .publish(brand_dir.path())
            .expect("a published session token");

        // The accepted stream is moved into a thread that parks forever. The thread is deliberately
        // never joined: joining it would mean waiting for a peer defined by never finishing.
        let (parked_tx, parked_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let accepted = listener.accept().expect("the client connects");
            // Accepted, and answered with nothing. Holding both the stream and the listener keeps the
            // endpoint claimed and the connection open for as long as this process lives.
            let _held = (accepted, listener);
            let _ = parked_tx.send(());
            std::thread::sleep(Duration::from_secs(600));
        });

        Self {
            endpoint,
            brand_dir,
            _parked: parked_rx,
        }
    }
}

/// The headline: a person gets a refusal, not a dead terminal.
#[test]
fn a_holder_that_accepts_and_never_answers_cannot_hang_the_cli() {
    let holder = SilentHolder::claim_the_endpoint();
    let endpoint = holder.endpoint.clone();
    let brand_dir = holder.brand_dir.path().to_path_buf();

    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        let answer = send_via(
            &endpoint,
            &brand_dir,
            &Command::Profiles(ProfilesAction::List),
        );
        let _ = done_tx.send((answer, began.elapsed()));
    });

    let (answer, took) = done_rx.recv_timeout(PATIENCE).unwrap_or_else(|_| {
        panic!(
            "the CLI lane is still waiting after {PATIENCE:?} on a peer that accepted and never \
             answered: there is no read deadline on this lane"
        )
    });

    let error = match answer {
        Ok(outcome) => panic!(
            "a silent peer must not produce an answer: {:?}",
            outcome.result
        ),
        Err(error) => error,
    };

    // NOT merely "an error": a connection refused, a bad token, or a closed stream all fail too, and
    // none of them would prove a deadline exists. The refusal has to be the one authored for silence.
    assert_eq!(error.code, ErrorCode::NotConnected);
    assert!(
        error.message.contains("stopped answering"),
        "the person must learn the endpoint answered nothing, not merely that something failed: {}",
        error.message
    );
    assert!(
        error.message.contains("prove it is dig-app"),
        "the refusal must name the leg it gave up on: {}",
        error.message
    );
    assert!(
        error
            .hint
            .as_deref()
            .is_some_and(|hint| hint.contains("holding the endpoint")),
        "the remedy must address a HELD endpoint, not a stopped app: {:?}",
        error.hint
    );

    // The bound is real in both directions. Under the deadline the wait is the handshake budget;
    // without one it is unbounded, and a bound tested only from below can only confirm itself.
    assert!(
        took >= Duration::from_secs(9),
        "the client gave up before its handshake budget, so something other than the deadline ended \
         the wait: {took:?}"
    );
    assert!(
        took < Duration::from_secs(30),
        "the handshake budget is 10s; a wait of {took:?} means the deadline is not the thing that \
         ended it"
    );
}
