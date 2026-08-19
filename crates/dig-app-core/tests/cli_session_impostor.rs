//! The CLI lane must not believe a process that merely got to the endpoint name first.
//!
//! # The defect this file exists for
//!
//! The endpoint address is derived from the login name (`\\.\pipe\dignetwork-cli-<user>` on Windows,
//! a socket in the per-user brand directory on Unix), and creating either needs no privilege. So a
//! local principal that claims the name BEFORE dig-app does — a second unprivileged account, or a
//! low-integrity same-user sandbox — is the process `dign` connects to. An earlier version of the
//! client sent the session token as its very first frame and then printed whatever came back, so that
//! principal both harvested the secret and chose the wallet address the person saw.
//!
//! # Why the impostor here speaks no protocol
//!
//! It answers EVERY frame with the same fabricated success, built as raw JSON rather than through the
//! crate's own wire types. That is deliberate: the test then compiles and runs against the vulnerable
//! revision as well as the fixed one, so its red run is a real reproduction of the exploit rather than
//! a test of the fix against itself.

use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use dig_app_core::cli_session::{cli_endpoint, send_via, transport, SessionToken};
use dig_app_core::gateway::{Command, WalletAction};

/// Distinguishes concurrent impostors from one another.
static NEXT_IMPOSTOR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// The address the impostor wants the person to see. Sending funds here sends them to the attacker.
const IMPOSTOR_ADDRESS: &str = "xch1IMPOSTORADDRESS";

/// How convincing the impostor tries to be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Impersonation {
    /// Answers the challenge with a WELL-FORMED reply carrying a full-width nonce and a full-width
    /// proof that is simply not the right MAC.
    ///
    /// This is the nearest wrong impostor, and it is the one that makes the MAC comparison
    /// load-bearing. An impostor whose reply merely lacks the expected fields is refused by the field
    /// lookup, so a test using only that fixture stays green even with the comparison forced true --
    /// measured, on this very change.
    WellFormedButUnprovable,
    /// Ignores the protocol entirely and answers everything with the fabricated address, which is
    /// what the ORIGINAL exploit did before the challenge method existed.
    ProtocolIgnorant,
}

/// Serve one connection as the impostor, recording every byte received, and answer with a fabricated
/// wallet address it has no right to know.
fn serve_as_impostor(
    stream: transport::CliStream,
    transcript: Arc<Mutex<Vec<String>>>,
    style: Impersonation,
) {
    let mut writer = stream.try_clone().expect("the impostor can write back");
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        transcript.lock().unwrap().push(line.clone());
        let frame: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        // The id is echoed so a client that correlates by id is satisfied; every other field is a
        // fabrication, which is exactly the freedom the attacker has.
        let id = frame["id"].as_u64().unwrap_or(1);
        let is_challenge = frame["method"] == "control.session.challenge";
        let reply = if style == Impersonation::WellFormedButUnprovable && is_challenge {
            // 32 bytes of hex in each field, so nothing but the MAC itself can reject this.
            let nonce = "11".repeat(32);
            let forged = "22".repeat(32);
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"summary":"dig-app proved this session","result":{{"server_nonce_hex":"{nonce}","server_proof_hex":"{forged}"}}}}}}"#
            )
        } else {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"summary":"{IMPOSTOR_ADDRESS}","result":{{"address":"{IMPOSTOR_ADDRESS}"}}}}}}"#
            )
        };
        if writeln!(writer, "{reply}").is_err() || writer.flush().is_err() {
            return;
        }
    }
}

/// A running impostor: the endpoint it holds, the published secret it never read, and what it heard.
struct Impostor {
    endpoint: String,
    brand_dir: tempfile::TempDir,
    secret: String,
    transcript: Arc<Mutex<Vec<String>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Impostor {
    /// Publish a real session secret, then let an impostor claim the endpoint before the app can.
    fn holding_the_endpoint(style: Impersonation) -> Self {
        let brand_dir = tempfile::tempdir().unwrap();
        // The app published its secret to its owner-only file, as it does on every start. The
        // impostor cannot read it — and must not need to.
        let token = SessionToken::mint();
        token.publish(brand_dir.path()).unwrap();

        // The host's own OS, so the endpoint is the real per-user address on whichever platform
        // this runs: a named pipe on Windows, a socket in the brand directory elsewhere.
        let os = if cfg!(windows) {
            dig_app_core::Os::Windows
        } else if cfg!(target_os = "macos") {
            dig_app_core::Os::MacOs
        } else {
            dig_app_core::Os::Linux
        };
        let endpoint = cli_endpoint(
            os,
            // Unique per impostor: the pipe namespace is machine-global, so two tests in this file
            // running concurrently would otherwise fight over one name.
            &format!(
                "digimpostor-{}-{}",
                std::process::id(),
                NEXT_IMPOSTOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            brand_dir.path(),
        );
        let listener = transport::bind(&endpoint, brand_dir.path())
            .expect("the impostor claims the predictable name first");

        let transcript = Arc::new(Mutex::new(Vec::new()));
        let heard = Arc::clone(&transcript);
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            if let Ok(stream) = listener.accept() {
                serve_as_impostor(stream, heard, style);
            }
        });
        ready_rx.recv().unwrap();

        Self {
            endpoint,
            secret: token.as_hex().to_string(),
            brand_dir,
            transcript,
            thread: Some(thread),
        }
    }

    /// Everything the impostor received, concatenated.
    fn heard(&self) -> String {
        self.transcript.lock().unwrap().concat()
    }
}

impl Drop for Impostor {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The headline: a genuine client must REFUSE an endpoint held by something that cannot prove it is
/// dig-app, rather than print the address that thing chose.
///
/// This is the money-lie: `dign wallet address` is the verb a person copies a receive address out of.
#[test]
fn a_client_refuses_an_impostor_that_holds_the_endpoint() {
    let impostor = Impostor::holding_the_endpoint(Impersonation::WellFormedButUnprovable);

    let answer = send_via(
        &impostor.endpoint,
        impostor.brand_dir.path(),
        &Command::Wallet(WalletAction::Address),
    );

    let error = match answer {
        Ok(outcome) => panic!(
            "the client believed an impostor: summary {:?}, result {}",
            outcome.summary, outcome.result
        ),
        Err(error) => error,
    };
    assert!(
        !format!("{error:?}").contains(IMPOSTOR_ADDRESS),
        "the refusal must not carry the fabricated address forward: {error:?}"
    );
    // The refusal has to be about the peer, not a generic I/O shrug: a person reading it needs to
    // know something is answering for dig-app.
    assert_eq!(error.code, dig_app_core::gateway::ErrorCode::Denied);
    assert!(
        error.message.contains("not dig-app"),
        "the refusal must name what is wrong: {}",
        error.message
    );
}

/// The refusal is not the whole claim. The secret must never have LEFT the client, because a secret
/// already on the wire is lost whatever the client does next.
///
/// Asserting only that the client errored would stay green against a client that sent the token
/// first and then refused the answer — which is the previous behaviour with a check bolted on after
/// the damage.
#[test]
fn an_impostor_never_receives_the_session_secret() {
    let impostor = Impostor::holding_the_endpoint(Impersonation::WellFormedButUnprovable);

    let _ = send_via(
        &impostor.endpoint,
        impostor.brand_dir.path(),
        &Command::Wallet(WalletAction::Address),
    );

    let heard = impostor.heard();
    assert!(
        !heard.is_empty(),
        "the fixture is void unless the client actually spoke to the impostor"
    );
    assert!(
        !heard.contains(&impostor.secret),
        "the client transmitted the session secret to an unauthenticated peer: {heard}"
    );
    // A fragment is as fatal as the whole, so the halves are checked separately: a client that split
    // the secret across frames would pass the whole-string check above.
    let (first_half, second_half) = impostor.secret.split_at(impostor.secret.len() / 2);
    for fragment in [first_half, second_half] {
        assert!(
            !heard.contains(fragment),
            "a fragment of the session secret reached the impostor: {heard}"
        );
    }
    // And the client must not have gone on to ask its question: a command sent to an impostor is a
    // command an attacker learns.
    assert!(
        !heard.contains("gateway.dispatch"),
        "the client dispatched its command to an unauthenticated peer: {heard}"
    );
}

/// The protocol-ignorant impostor -- the exact shape of the original exploit, which answered every
/// frame with the fabricated address -- must be refused too, and must also learn nothing.
///
/// Kept alongside the well-formed one because the two are rejected by DIFFERENT code: this one fails
/// the field lookup, that one fails the MAC comparison. Either check alone would leave the other path
/// unproven.
#[test]
fn a_protocol_ignorant_impostor_is_refused_and_learns_nothing() {
    let impostor = Impostor::holding_the_endpoint(Impersonation::ProtocolIgnorant);

    let error = send_via(
        &impostor.endpoint,
        impostor.brand_dir.path(),
        &Command::Wallet(WalletAction::Address),
    )
    .expect_err("an impostor that answers nonsense must not be believed");

    assert_eq!(error.code, dig_app_core::gateway::ErrorCode::Denied);
    let heard = impostor.heard();
    assert!(!heard.is_empty(), "the client must have spoken to it");
    assert!(
        !heard.contains(&impostor.secret),
        "the session secret reached the impostor: {heard}"
    );
}
