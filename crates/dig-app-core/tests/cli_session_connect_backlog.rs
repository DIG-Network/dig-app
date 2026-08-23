//! The CONNECT leg of the `diga` lane must be bounded too, on every platform it builds for
//! (dig_ecosystem#908, dig-app#218).
//!
//! # The claim under test
//!
//! The lane exempts its connect leg from a deadline on the grounds that neither transport can block
//! on the peer. That is true of a Windows named pipe and of a Darwin Unix socket, both of which
//! refuse at once when no instance or no queue slot is free. It is NOT obviously true of Linux:
//! `unix_stream_connect` checks `unix_recvq_full` and, for a BLOCKING socket, waits in
//! `unix_wait_for_peer` bounded by `sk_sndtimeo` — which defaults to `MAX_SCHEDULE_TIMEOUT`.
//! `EAGAIN` is returned only for a non-blocking socket, and `UnixStream::connect` is blocking.
//!
//! So a holder that binds, listens, and then never ACCEPTS is a second silent-holder shape, reached
//! one leg earlier than the one `cli_session_stall` covers: the client never gets far enough to have
//! a read deadline applied to it at all.
//!
//! # Why the fixture never accepts, and why it shrinks its own queue
//!
//! Filling a listener's accept queue is the only way to make `connect(2)` itself wait. The holder
//! below binds the per-user endpoint, publishes a token so the client gets past its pre-dial check,
//! and then drops every incoming connection on the floor by never calling `accept`.
//!
//! It re-`listen`s with a backlog of zero first. Rust's `UnixListener::bind` uses `SOMAXCONN`, so a
//! fixture that filled the default queue would need thousands of descriptors on BOTH ends inside one
//! test process — measured at 4,097 dials against a 4,096 `somaxconn`, which is a descriptor-limit
//! coin flip rather than a test. A squatter picks its own backlog anyway, so shrinking it changes the
//! fixture's cost and nothing about the client behaviour under measurement.
//!
//! # Why the whole measurement runs on its own thread
//!
//! Against an unbounded connect the call under test does not fail, it HANGS. The call is therefore
//! made on a worker thread and the assertion waits on a channel, so an unfixed build reports a
//! legible failure in bounded time instead of taking the runner down with it.
#![cfg(unix)]

use std::sync::mpsc;
use std::time::{Duration, Instant};

use dig_app_core::cli_session::{cli_endpoint, send_via, SessionToken};
use dig_app_core::gateway::{Command, ErrorCode, ProfilesAction};

/// The longest this test waits for the client to return before declaring the connect leg unbounded.
///
/// Far above any bound the lane could reasonably choose and far below any CI step timeout.
const PATIENCE: Duration = Duration::from_secs(90);

/// The longest a BOUNDED connect leg may take. Generous: the property under test is that a bound
/// exists at all, not what it is.
const BOUND: Duration = Duration::from_secs(45);

/// How long the filler must go without completing a dial before the queue counts as full.
const QUIESCE: Duration = Duration::from_secs(2);

/// A process that claims the endpoint, listens, and then never accepts anything.
struct DeafHolder {
    endpoint: String,
    brand_dir: tempfile::TempDir,
    /// The listener, parked so the endpoint stays claimed and its queue stays unaccepted for the
    /// whole measurement. Dropping it would close the socket and turn every dial into a refusal —
    /// which is the false green this fixture exists to avoid.
    _listener: std::os::unix::net::UnixListener,
    /// The filler dials, held open so the kernel keeps them queued.
    _filled: Vec<std::os::unix::net::UnixStream>,
}

impl DeafHolder {
    fn claim_and_fill() -> Self {
        use std::os::unix::io::AsRawFd;

        let brand_dir = tempfile::tempdir().expect("a brand directory");
        let host_os = if cfg!(target_os = "macos") {
            dig_app_core::Os::MacOs
        } else {
            dig_app_core::Os::Linux
        };
        let endpoint = cli_endpoint(
            host_os,
            &format!("digdeaf-{}", std::process::id()),
            brand_dir.path(),
        );
        let listener = std::os::unix::net::UnixListener::bind(&endpoint)
            .expect("the deaf holder claims the predictable name first");
        // Shrink the accept queue to nothing. See the module docs: the default is `SOMAXCONN`.
        // SAFETY: `listener` owns this descriptor and outlives the call.
        assert_eq!(
            unsafe { libc::listen(listener.as_raw_fd(), 0) },
            0,
            "the fixture could not shrink its own accept queue: {}",
            std::io::Error::last_os_error()
        );
        // The client reads the published token before it dials, so a lane with no token file would
        // refuse before ever reaching the connect under test.
        SessionToken::mint()
            .publish(brand_dir.path())
            .expect("a published session token");

        Self {
            _filled: fill_the_accept_queue(&endpoint),
            endpoint,
            brand_dir,
            _listener: listener,
        }
    }
}

/// Dial `endpoint` until a dial stops completing, and return every dial that did.
///
/// The filler runs on its own thread precisely BECAUSE the dial that fills the queue is the one that
/// blocks: that thread is abandoned mid-connect, which is the very behaviour under test.
fn fill_the_accept_queue(endpoint: &str) -> Vec<std::os::unix::net::UnixStream> {
    let (tx, rx) = mpsc::channel();
    let dial_at = endpoint.to_owned();
    std::thread::spawn(move || {
        // Bounded so a platform that never blocks cannot spin here forever burning descriptors.
        for _ in 0..64 {
            match std::os::unix::net::UnixStream::connect(&dial_at) {
                Ok(stream) => {
                    if tx.send(stream).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let mut filled = Vec::new();
    while let Ok(stream) = rx.recv_timeout(QUIESCE) {
        filled.push(stream);
    }
    filled
}

/// The headline: a holder that listens and never accepts cannot hang the CLI at the connect leg.
#[test]
fn a_holder_that_never_accepts_cannot_hang_the_cli_at_connect() {
    let holder = DeafHolder::claim_and_fill();
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
            "the CLI lane is still waiting after {PATIENCE:?} to CONNECT to a holder that listens \
             and never accepts: the connect leg has no bound on this platform"
        )
    });

    match answer {
        Ok(outcome) => panic!(
            "a holder that never accepts must not produce an answer: {:?}",
            outcome.result
        ),
        // The lane must fail as an unreachable app, not as a raw OS error the person cannot act on.
        Err(error) => assert_eq!(
            error.code,
            ErrorCode::NotConnected,
            "an unreachable holder must be reported as a connection failure: {error:?}"
        ),
    }

    assert!(
        took < BOUND,
        "the connect leg took {took:?}; a bound that loose is indistinguishable from none"
    );
}
