//! Shared test doubles for the master-HD custody path (test-only).
//!
//! The custody path is the master-HD
//! [`AccountResidency`](crate::account::residency::AccountResidency), so these helpers give every test
//! module ONE way to build the two seams the loopback/pairing/whitelist/wallet stores depend on:
//!
//! - [`test_sealer`] — a cheap-KDF [`AccountSealer`] at a deterministic per-label DEK. Two sealers
//!   built from the SAME label share a DEK (so a "restart" round-trips a sealed blob); DISTINCT labels
//!   derive DISTINCT DEKs, which is exactly the model's cross-profile isolation (isolation rests on the
//!   DEK, not on the advisory DID argument — see [`crate::account::sealer`]).
//! - [`test_residency`] — a freshly-enrolled, unlocked residency; call `.signer(ProfileIx::ROOT)` for
//!   its live-view [`SessionSigner`], which fails closed the instant the residency is locked
//!   ([`lock_all`](crate::session_lock::SessionKeys::lock_all)).

use std::sync::Arc;

use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
use dig_keystore::{KdfParams, MemoryBackend};
use dig_session::{Password, SEED_LEN};
use sha2::{Digest, Sha256};

use crate::account::residency::AccountResidency;
use crate::account::sealer::AccountSealer;

/// A cheap-KDF [`AccountSealer`] bound to a DEK deterministically derived from `label`. Same label →
/// same DEK (a persisted blob re-opens across a simulated restart); different label → different DEK
/// (cross-profile isolation, cryptographically enforced by the AEAD tag).
pub fn test_sealer(label: &str) -> AccountSealer {
    let dek: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    AccountSealer::with_kdf(dek, KdfParams::FAST_TEST)
}

/// A freshly-enrolled, unlocked master-HD residency over a random seed. Cheap (an in-memory keystore
/// backend); each call is an independent account with its own key material.
pub fn test_residency() -> AccountResidency {
    use rand_core::RngCore;
    let mut seed = [0u8; SEED_LEN];
    rand_core::OsRng.fill_bytes(&mut seed);
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("test-account"),
        Password::new("pw"),
        &seed,
        ProfileIx::ROOT,
    )
    .expect("enrol a fresh test account");
    AccountResidency::new(unlocked)
}

/// One [`InputPrompt`](crate::confirm::InputPrompt) as a [`ScriptedInput`] recorded it — owned, because
/// the real prompt borrows its strings from the caller's frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPrompt {
    /// The primary line the window asked.
    pub heading: String,
    /// The explanatory body.
    pub body: String,
    /// The submit button's label.
    pub submit: String,
    /// Whether the field started masked.
    pub masked: bool,
    /// The reveal control's label, or `None` when the window offered none.
    ///
    /// The LABEL and not a `bool`: a double that recorded only "there was a reveal control" could not
    /// express a wrong label, and a wrong label is exactly the defect this recorded — the password window
    /// inherited the recovery-phrase copy "Show the words while I type" and shipped it
    /// (dig_ecosystem#1817). A double that can only vary one field cannot catch a multi-field lie.
    pub reveal_label: Option<String>,
}

/// A [`NativeConfirmer`](crate::confirm::NativeConfirmer) whose input window returns a SCRIPT of
/// answers in order, recording every prompt it was shown.
///
/// # Why a script and not a fixed answer
///
/// A double that can only ever return ONE string cannot express a multi-answer lie — it cannot say
/// "the user typed X, then Y", which is precisely the case a type-it-twice ceremony exists to catch.
/// Every test that turns on a mismatch, a re-ask, or a bound would silently degenerate into a test of
/// the happy path. So the answers are a queue, and the prompts are recorded, so a test can assert BOTH
/// what came out and how many questions it took.
///
/// Running past the end of the script yields [`InputOutcome::Cancelled`] — a script that runs out is a
/// user who walked away, which is a legitimate outcome rather than a panic that would mask a real
/// off-by-one in the ceremony's loop.
pub struct ScriptedInput {
    answers: std::sync::Mutex<std::collections::VecDeque<Answer>>,
    prompts: std::sync::Mutex<Vec<RecordedPrompt>>,
}

/// What the scripted window does for one prompt.
enum Answer {
    /// The user typed this and submitted it.
    Typed(String),
    /// The user cancelled.
    Cancelled,
    /// No window could be drawn.
    Unavailable,
}

impl ScriptedInput {
    /// A window that answers each prompt with the next string in `answers`.
    pub fn of<I: IntoIterator<Item = String>>(answers: I) -> Arc<Self> {
        Self::scripted(answers.into_iter().map(Answer::Typed).collect())
    }

    /// A window the user always cancels.
    pub fn cancelling() -> Arc<Self> {
        Self::scripted(vec![Answer::Cancelled])
    }

    /// A host on which no input window can be drawn at all.
    pub fn unavailable() -> Arc<Self> {
        Self::scripted(vec![Answer::Unavailable])
    }

    /// A window that answers `a`, `b`, `a`, `b`, … forever — a user who never manages to type the
    /// same thing twice, which is what proves a re-ask loop is BOUNDED rather than testing that it
    /// eventually succeeds.
    pub fn alternating(a: String, b: String) -> Arc<Self> {
        // Long enough that the ceremony's own bound, not the script's length, is what stops the loop:
        // a script that ran out first would prove the bound exists when it does not.
        let answers = (0..64)
            .map(|i| Answer::Typed(if i % 2 == 0 { a.clone() } else { b.clone() }))
            .collect();
        Self::scripted(answers)
    }

    fn scripted(answers: Vec<Answer>) -> Arc<Self> {
        Arc::new(Self {
            answers: std::sync::Mutex::new(answers.into()),
            prompts: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// This window as the `Arc<dyn NativeConfirmer>` a ceremony holds.
    ///
    /// A plain `Arc::clone` infers `Arc<ScriptedInput>` and will not coerce at an argument position, so
    /// this spells the coercion once rather than at every call site.
    pub fn confirmer(self: &Arc<Self>) -> Arc<dyn crate::confirm::NativeConfirmer> {
        Arc::clone(self) as Arc<dyn crate::confirm::NativeConfirmer>
    }

    /// Every prompt this window was shown, in order.
    pub fn prompts(&self) -> Vec<RecordedPrompt> {
        self.prompts.lock().expect("scripted prompts").clone()
    }
}

impl crate::confirm::NativeConfirmer for ScriptedInput {
    fn confirm_pair(
        &self,
        _prompt: &crate::confirm::PairPrompt<'_>,
    ) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }

    fn confirm_connect(
        &self,
        _prompt: &crate::confirm::ConnectPrompt<'_>,
    ) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }

    fn confirm_sign(
        &self,
        _prompt: &crate::confirm::SignPrompt<'_>,
    ) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }

    fn request_input(
        &self,
        prompt: &crate::confirm::InputPrompt<'_>,
    ) -> crate::confirm::InputOutcome {
        self.prompts
            .lock()
            .expect("scripted prompts")
            .push(RecordedPrompt {
                heading: prompt.heading.to_string(),
                body: prompt.body.to_string(),
                submit: prompt.submit.to_string(),
                masked: prompt.masked,
                reveal_label: prompt.reveal_label.map(str::to_string),
            });
        match self.answers.lock().expect("scripted answers").pop_front() {
            Some(Answer::Typed(text)) => {
                crate::confirm::InputOutcome::Provided(zeroize::Zeroizing::new(text))
            }
            Some(Answer::Unavailable) => crate::confirm::InputOutcome::Unavailable,
            Some(Answer::Cancelled) | None => crate::confirm::InputOutcome::Cancelled,
        }
    }
}

/// A FAKE dig-node control plane, served over a real loopback TCP socket.
///
/// The connector under test is a transport, so its tests must exercise a transport: this stands up
/// an actual [`TcpListener`](std::net::TcpListener), speaks real HTTP/1.1 back, and replies with the
/// real JSON shape `dig-node`'s `control.rs::status` emits. A double that shared a helper with the
/// client — or wrote into a discarding sink — could pass while the bytes on the wire were wrong.
pub mod node {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    use crate::control::CONTROL_TOKEN_HEADER;

    /// How a [`FakeNode`] should answer the one request it accepts.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Behaviour {
        /// Reply `200` with a `control.status` result — a healthy, authorized node.
        Status,
        /// Reply `200` with a JSON-RPC `error` — what an unauthorized/refused call looks like.
        JsonRpcError(String),
        /// Reply with an HTTP status and body — e.g. the `401` an unknown token draws.
        Http(u16, String),
        /// Accept the connection and close it without replying — a node that is up but mute.
        Silent,
    }

    /// A one-shot fake control plane on loopback. Dropping it joins the server thread.
    pub struct FakeNode {
        addr: SocketAddr,
        token: String,
        requests: mpsc::Receiver<String>,
        server: Option<JoinHandle<()>>,
    }

    impl FakeNode {
        /// The node version this fake reports, so a test can assert the value travelled rather than
        /// that *some* string arrived.
        pub const VERSION: &'static str = "0.64.0";

        /// The token this fake accepts. A request without it draws the `401` a real node would send.
        pub const TOKEN: &'static str = "f00dcafe";

        /// A fake that answers `control.status` like a healthy node.
        pub fn serving_status() -> Self {
            Self::with_behaviour(Behaviour::Status)
        }

        /// A fake with an explicit [`Behaviour`], bound to an ephemeral loopback port.
        pub fn with_behaviour(behaviour: Behaviour) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            let (tx, requests) = mpsc::channel();
            let server = std::thread::spawn(move || serve_once(listener, behaviour, tx));
            Self {
                addr,
                token: Self::TOKEN.to_string(),
                requests,
                server: Some(server),
            }
        }

        /// The `http://…` endpoint a client should dial.
        pub fn endpoint(&self) -> String {
            format!("http://{}", self.addr)
        }

        /// The token this fake authorizes.
        pub fn token(&self) -> &str {
            &self.token
        }

        /// The raw request text the fake received, so a test can assert what actually went out on
        /// the wire (the method name, the token header) rather than trusting the client's own view.
        pub fn received(&self) -> String {
            self.requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the fake node received no request")
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            if let Some(server) = self.server.take() {
                // The server thread is parked in a BLOCKING `accept`, so a fake that no test ever
                // dialled would never return and the join would hang the test run forever — a hang
                // is a far worse failure than an assertion, because it reports nothing. Poke the
                // listener with a throwaway connection so `accept` returns and the thread finishes.
                let _ = std::net::TcpStream::connect(self.addr);
                let _ = server.join();
            }
        }
    }

    /// Accept exactly one connection, report the request text, and answer per `behaviour`.
    fn serve_once(listener: TcpListener, behaviour: Behaviour, tx: mpsc::Sender<String>) {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let request = read_request(&mut stream);
        let authorized = request
            .to_lowercase()
            .contains(&format!("{}: {}", CONTROL_TOKEN_HEADER, FakeNode::TOKEN).to_lowercase());
        let _ = tx.send(request);

        let (code, body) = match &behaviour {
            Behaviour::Silent => return,
            // A real node gates `control.*` on the token, so the fake must too — otherwise a client
            // that forgot the header would still see a green test.
            _ if !authorized => (401, "401: unauthorized control request".to_string()),
            Behaviour::Status => (200, status_result()),
            Behaviour::JsonRpcError(message) => (200, json_rpc_error(message)),
            Behaviour::Http(code, body) => (*code, body.clone()),
        };
        let _ = write!(
            stream,
            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
    }

    /// Read the request head plus its declared `Content-Length` body.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        // Read to the end of the headers first: the body length is only knowable from them.
        while !buf.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return String::from_utf8_lossy(&buf).to_string(),
                Ok(_) => buf.push(byte[0]),
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let len = head
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_ok() {
            buf.extend_from_slice(&body);
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// The `control.status` reply, field-for-field as `dig-node-service`'s `control::status` emits it.
    fn status_result() -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "running": true,
                "service": "dig-node",
                "version": FakeNode::VERSION,
                "commit": "deadbee",
                "protocol": "1",
                "uptime_secs": 4242,
                "addr": "127.0.0.1:9778",
                "upstream": "https://rpc.dig.net",
                "cache": { "cap_bytes": 1024, "used_bytes": 512, "dir": "/tmp/cache", "shared": false },
                "hosted_store_count": 3,
                "cached_capsule_count": 9,
                "pinned_store_count": 1,
                "sync": { "available": true }
            }
        })
        .to_string()
    }

    /// A JSON-RPC error reply carrying `message`.
    fn json_rpc_error(message: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": message,
                "data": { "code": "UNAUTHORIZED", "origin": "shell" }
            }
        })
        .to_string()
    }
}
