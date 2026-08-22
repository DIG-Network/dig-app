//! The dig-app half of the CLI lane: authenticate a `dign` client, then serve its commands.
//!
//! The server owns NO policy of its own. It authenticates the session and hands every command to the
//! [`crate::gateway::Gateway`], which is the one place that decides where a command is
//! served — so the CLI reaches exactly the surface the tray reaches, through the same seams,
//! including the native confirm ceremony in front of a signature (dig_ecosystem#908: the app signs
//! nothing without the user's own confirmation, and a CLI session is not a way around it).
//!
//! The two halves are split on purpose. [`CliSession`] is the CONVERSATION — pure over a frame
//! transport, so every authentication and routing rule below is unit-tested without a socket.
//! [`CliSessionServer`] adds the bound endpoint and the accept loop.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::confirm::NativeConfirmer;
use crate::gateway::{
    Command, EngineProxy, ErrorCode, Gateway, GatewayError, LinkOpener, LocalIdentity, Outcome,
};

use super::auth::SessionToken;
use super::deadline::FrameBudget;
use super::handshake::{self, Nonce};
use super::transport::{self, CliListener, CliStream};
use super::wire::{
    Request, RequestParams, Response, FIELD_SERVER_NONCE, FIELD_SERVER_PROOF, METHOD_ATTACH,
    METHOD_CHALLENGE, METHOD_DISPATCH,
};

use dig_ipc_protocol::FrameTransport;

/// A conversation's authentication state. A command frame is only ever served in [`Self::Attached`].
///
/// The state is a three-step ladder rather than a flag because the handshake is MUTUAL: the client
/// cannot prove anything until it has a server nonce to prove it over, and the server cannot check a
/// client proof without remembering the transcript it issued.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attachment {
    /// Nothing has been exchanged yet: only a challenge is accepted.
    Pending,
    /// A challenge was answered; the transcript is pinned and an attach may be checked against it.
    Challenged {
        /// The nonce the client contributed.
        client: Nonce,
        /// The nonce this server contributed.
        server: Nonce,
    },
    /// The client proved it holds the session secret; commands are served.
    Attached,
}

/// One `dign` conversation's rules: authenticate, then route through the gateway.
pub struct CliSession<'a> {
    token: SessionToken,
    identity: &'a dyn LocalIdentity,
    opener: &'a dyn LinkOpener,
    confirmer: &'a dyn NativeConfirmer,
}

impl<'a> CliSession<'a> {
    /// Build the conversation rules over the gateway seams and the session `token`.
    pub fn new(
        token: SessionToken,
        identity: &'a dyn LocalIdentity,
        opener: &'a dyn LinkOpener,
        confirmer: &'a dyn NativeConfirmer,
    ) -> Self {
        Self {
            token,
            identity,
            opener,
            confirmer,
        }
    }

    /// Serve one client to the end of its conversation.
    ///
    /// Returns `Ok(())` when the client hangs up, which is how every successful conversation ends.
    pub fn converse(&self, frames: &mut impl FrameTransport) -> std::io::Result<()> {
        let mut attachment = Attachment::Pending;
        loop {
            let line = match frames.recv_frame() {
                Ok(line) => line,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let response = self.answer(&line, &mut attachment);
            frames.send_frame(&serde_json::to_string(&response).map_err(std::io::Error::other)?)?;
        }
    }

    /// Answer one request line, advancing `attachment` if it was a successful attach.
    fn answer(&self, line: &str, attachment: &mut Attachment) -> Response {
        let request: Request = match serde_json::from_str(line) {
            Ok(request) => request,
            // The id is unknowable for an unparseable frame, so the response carries 0; the client
            // is the only speaker in this conversation, so it correlates by order.
            Err(e) => {
                return Response::failed(
                    0,
                    GatewayError::new(ErrorCode::Usage, format!("unreadable request frame: {e}")),
                )
            }
        };
        let id = request.id;
        match (request.method.as_str(), request.params) {
            (METHOD_CHALLENGE, RequestParams::Challenge { client_nonce_hex }) => {
                self.challenge(id, &client_nonce_hex, attachment)
            }
            (METHOD_ATTACH, RequestParams::Attach { client_proof_hex }) => {
                self.attach(id, &client_proof_hex, attachment)
            }
            (METHOD_DISPATCH, RequestParams::Dispatch { command }) => {
                self.dispatch(id, command, attachment)
            }
            (method, _) => Response::failed(
                id,
                GatewayError::new(
                    ErrorCode::Usage,
                    format!("`{method}` is not a method of the dig-app CLI session"),
                ),
            ),
        }
    }

    /// Answer the client challenge by PROVING this app holds the session secret.
    ///
    /// This is the half that makes the lane mutually authenticated. Only a holder of the secret can
    /// compute the MAC, so a client that verifies it before attaching cannot be fooled by an impostor
    /// that squatted the endpoint name (see [`handshake`]).
    fn challenge(&self, id: u64, client_nonce_hex: &str, attachment: &mut Attachment) -> Response {
        let client = match Nonce::from_peer_hex(client_nonce_hex) {
            Ok(nonce) => nonce,
            Err(e) => {
                return Response::failed(id, GatewayError::new(ErrorCode::Usage, e.to_string()))
            }
        };
        let server = Nonce::mint();
        let server_proof = handshake::proof(
            &self.token,
            handshake::SERVER_PROOF_CONTEXT,
            &client,
            &server,
        );
        // Pinned BEFORE the answer goes out, so the transcript the client will prove over is the one
        // this server issued rather than one a later frame could redefine.
        *attachment = Attachment::Challenged {
            client,
            server: server.clone(),
        };
        Response::ok(
            id,
            Outcome::new(
                "dig-app proved this session",
                serde_json::json!({
                    FIELD_SERVER_NONCE: server.as_hex(),
                    FIELD_SERVER_PROOF: server_proof,
                }),
            ),
        )
    }

    /// Check the client half of the mutual proof and open the session.
    ///
    /// An attach with no preceding challenge is refused: there is no transcript to verify against,
    /// and accepting one would be a way to reach the session without the server ever proving itself.
    fn attach(&self, id: u64, presented: &str, attachment: &mut Attachment) -> Response {
        let Attachment::Challenged { client, server } = attachment else {
            return Response::failed(
                id,
                GatewayError::new(
                    ErrorCode::Denied,
                    "this session must be challenged before it can be attached",
                ),
            );
        };
        if let Err(e) = handshake::verify(
            &self.token,
            handshake::CLIENT_PROOF_CONTEXT,
            client,
            server,
            presented,
        ) {
            tracing::warn!("a dign client failed the session proof");
            return Response::failed(
                id,
                GatewayError::new(ErrorCode::Denied, e.to_string()).with_hint(
                    "re-run `dign` — dig-app mints a new session secret each time it starts",
                ),
            );
        }
        *attachment = Attachment::Attached;
        Response::ok(
            id,
            Outcome::new(
                "attached to dig-app",
                serde_json::json!({ "app_version": env!("CARGO_PKG_VERSION") }),
            ),
        )
    }

    /// Route one command through the gateway, refusing an unattached client.
    fn dispatch(&self, id: u64, command: Command, attachment: &Attachment) -> Response {
        if *attachment != Attachment::Attached {
            return Response::failed(
                id,
                GatewayError::new(
                    ErrorCode::Denied,
                    "this session has not attached, so no command can be served on it",
                ),
            );
        }
        let gateway = Gateway::new(&UnproxiedEngine, self.identity, self.opener, self.confirmer);
        match gateway.dispatch(&command) {
            Ok(outcome) => Response::ok(id, outcome),
            Err(error) => Response::failed(id, error),
        }
    }
}

/// How many consecutive `accept` failures the lane absorbs before giving up.
///
/// Bounded so a permanently broken listener stops rather than spinning forever, and large enough
/// that an ordinary transient fault -- a momentary `CreateNamedPipeW` failure on Windows -- never
/// reaches the ceiling.
const MAX_CONSECUTIVE_ACCEPT_FAULTS: u32 = 8;

/// The pause between accept retries. Short enough to be invisible to a waiting `dign`, long enough
/// that eight attempts cannot become a hot loop.
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(50);

/// The retry policy for [`CliSessionServer::serve_blocking`]'s accept loop.
///
/// Split out from the loop because the loop itself cannot be tested -- it never returns on a
/// healthy listener, and `CliListener` has no seam for injecting an OS fault. The DECISION is the
/// part with edges, so the decision is what carries the tests.
///
/// This policy is only half the guarantee, and on its own it is worth nothing: retrying an accept
/// is pointless if the listener cannot accept any more. The other half -- that a faulted listener
/// still holds, or re-claims, an instance -- lives in
/// `transport`'s `the_lane_still_accepts_after_a_fault_emptied_its_pending_instance` and
/// `a_squatted_name_is_refused_rather_than_joined_when_reclaiming`. Read the two together; the
/// tests below deliberately assert nothing about the listener.
#[derive(Default)]
struct AcceptFaults {
    /// Consecutive failures since the last accepted client. Reset by [`Self::succeeded`].
    consecutive: u32,
}

impl AcceptFaults {
    /// Record a failure, returning how long to wait before retrying, or `None` once the lane has
    /// failed [`MAX_CONSECUTIVE_ACCEPT_FAULTS`] times in a row and should give up.
    fn tolerate(&mut self) -> Option<Duration> {
        self.consecutive += 1;
        match self.consecutive < MAX_CONSECUTIVE_ACCEPT_FAULTS {
            true => Some(ACCEPT_RETRY_BACKOFF),
            false => None,
        }
    }

    /// A client was accepted, so the run of failures is over. Without this a lane that faulted
    /// occasionally over days would eventually reach the ceiling and quit on a healthy listener.
    fn succeeded(&mut self) {
        self.consecutive = 0;
    }
}

/// The CLI lane server: a bound per-user endpoint plus the conversation rules it serves with.
/// How long a connected client may take to send its next frame before the lane drops it.
///
/// A whole `dign` invocation is three frames sent back to back by a one-shot process, so a client
/// still silent after thirty seconds is not slow -- it is stalled, or it is not a client. The bound is
/// per FRAME rather than per conversation so that a server-side answer which legitimately takes time
/// never counts against the client that is waiting for it.
const CLIENT_FRAME_BUDGET: Duration = Duration::from_secs(30);

pub struct CliSessionServer<'a> {
    listener: CliListener,
    session: CliSession<'a>,
}

impl<'a> CliSessionServer<'a> {
    /// Bind the lane at `endpoint` under `brand_dir`, mint the session token, and publish it where
    /// `dign` looks for it.
    ///
    /// The token is published only AFTER the bind succeeds, so a failed start never leaves a
    /// credential on disk for a lane nothing is serving. That ordering is a real guarantee on BOTH
    /// platforms because both claim the endpoint here: Unix binds the socket, and Windows creates
    /// the pipe's first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`. An earlier Windows transport
    /// only encoded the name at bind and created the instance at the first accept, which made this
    /// paragraph Unix-only -- a squatted name then failed AFTER the token was already on disk.
    pub fn bind(
        endpoint: &str,
        brand_dir: &Path,
        identity: &'a dyn LocalIdentity,
        opener: &'a dyn LinkOpener,
        confirmer: &'a dyn NativeConfirmer,
    ) -> std::io::Result<Self> {
        let listener = transport::bind(endpoint, brand_dir)?;
        let token = SessionToken::mint();
        token.publish(brand_dir)?;
        Ok(Self {
            listener,
            session: CliSession::new(token, identity, opener, confirmer),
        })
    }

    /// Serve clients one conversation at a time, tolerating transient accept failures.
    ///
    /// Serial service is deliberate: `dign` attaches, asks one question and exits, and the seams
    /// behind the gateway (the account residency, the native confirmer) are single-ceremony
    /// surfaces. Two concurrent confirm prompts would be a worse answer than a client waiting.
    ///
    /// # Why an accept failure does not end the lane
    ///
    /// Returning on the first `accept` error made a single transient fault indistinguishable, from
    /// the user's side, from an app that had exited: the serving thread ended, the session token
    /// stayed published on disk, and every later `dign` reported "dig-app is not running" for the
    /// remaining life of a running, visible app. Nothing restarted it and nothing surfaced it
    /// beyond one log line. A per-conversation error was already treated as ordinary; an accept
    /// error is no more fatal, so it is logged and retried under this module's `AcceptFaults` policy.
    ///
    /// The ceiling matters as much as the tolerance: a permanently broken listener must give up
    /// loudly rather than spin, which is why this returns the last error once
    /// `MAX_CONSECUTIVE_ACCEPT_FAULTS` consecutive attempts have failed.
    pub fn serve_blocking(&self) -> std::io::Result<()> {
        let mut faults = AcceptFaults::default();
        loop {
            match self.listener.accept() {
                Ok(stream) => {
                    faults.succeeded();
                    if let Err(e) = self.serve_one(stream) {
                        // A client that hung up mid-conversation is ordinary; it must not end the
                        // lane.
                        tracing::debug!(error = %e, "a dign client conversation ended");
                    }
                }
                Err(e) => match faults.tolerate() {
                    Some(backoff) => {
                        tracing::warn!(
                            error = %e,
                            consecutive = faults.consecutive,
                            "the dign lane could not accept a client; retrying"
                        );
                        std::thread::sleep(backoff);
                    }
                    None => {
                        tracing::error!(
                            error = %e,
                            consecutive = faults.consecutive,
                            "the dign lane gave up accepting clients"
                        );
                        return Err(e);
                    }
                },
            }
        }
    }

    /// Block until one client connects, returning its stream. The seam an integration test uses to
    /// serve a bounded number of conversations instead of looping forever.
    pub fn accept_one(&self) -> std::io::Result<CliStream> {
        self.listener.accept()
    }

    /// Serve one accepted client.
    ///
    /// Every frame the client sends is bounded by `CLIENT_FRAME_BUDGET`, because this lane serves
    /// one conversation at a time: a client that connects and then never speaks would otherwise hold
    /// the only accept slot for the life of the app, and every other `dign` on the machine would
    /// report that dig-app is not running.
    pub fn serve_one(&self, stream: CliStream) -> std::io::Result<()> {
        let mut frames = transport::frames(stream, FrameBudget::of(CLIENT_FRAME_BUDGET))?;
        self.session.converse(&mut frames)
    }
}

/// The engine proxy the CLI lane serves with today: an honest refusal naming the method.
///
/// dig-app reaches the node over its own loopback control channel with TYPED calls
/// ([`crate::control`]), which is not the untyped `(method, params)` shape an [`EngineProxy`]
/// forwards. Rather than invent a second, untyped path to the node for the CLI's sake, engine-routed
/// verbs report `NOT_CONNECTED` and say so — a person sees why, instead of a hang or an empty result.
/// What a person can actually run right now, named verb by verb.
///
/// Every entry is a VERB, never a family, because a family includes its refusing members. Two
/// earlier versions of this constant named a family and were false in the one direction that
/// matters -- a hint is the remedy the error promises, so naming something that refuses makes the
/// remedy the bug:
///
/// * `dign wallet` wholesale -- `wallet balance` refuses on purpose (a `0` there is
///   indistinguishable from an empty wallet, see
///   [`super::host_identity::HostIdentity::wallet_balance`]).
/// * `dign profiles` wholesale -- three of the four `profiles` verbs refuse:
///   [`super::host_identity::HostIdentity::begin_profile_creation`] is `DENIED` (minting spends
///   XCH and is confirmed in the app), while `profiles select` and the argument form of
///   `profiles default` are `LOCKED` registry writes. Only `profiles list` and the no-argument
///   `profiles default` answer.
const SERVED_NOW_HINT: &str = "`dign profiles list`, `dign profiles default` (no argument) and \
     `dign account status` are served now; `dign wallet address` needs an unlocked account";

struct UnproxiedEngine;

impl EngineProxy for UnproxiedEngine {
    fn call(&self, method: &str, _params: Value) -> Result<Value, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::NotConnected,
            format!("dig-app does not yet proxy `{method}` to the node on behalf of the CLI"),
        )
        .with_hint(SERVED_NOW_HINT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_session::test_support::{
        ApprovingConfirmer, ScriptedDuplex, StubIdentity, UnusedOpener,
    };
    use crate::gateway::{ProfilesAction, WalletAction};

    /// Drive one conversation over a scripted client and collect its responses.
    fn conversation(token: &SessionToken, requests: &[Request]) -> Vec<Response> {
        let (identity, opener, confirmer) =
            (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
        let session = CliSession::new(token.clone(), &identity, &opener, &confirmer);
        let mut duplex = ScriptedDuplex::of(requests);
        session
            .converse(&mut duplex)
            .expect("the conversation ends cleanly");
        duplex.responses()
    }

    /// Drive a conversation that FIRST completes the mutual handshake, then sends `requests`.
    ///
    /// The client proof cannot be scripted in advance, because it is a MAC over a nonce the server
    /// mints during the conversation -- which is precisely the property that stops a captured attach
    /// frame being replayed. So this helper plays the client the way [`super::super::client`] does:
    /// challenge, read the answer, prove over the nonce that came back.
    ///
    /// Returns the attach response first, then one response per entry in `requests`.
    fn attached_conversation(token: &SessionToken, requests: &[Request]) -> Vec<Response> {
        let (identity, opener, confirmer) =
            (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
        let session = CliSession::new(token.clone(), &identity, &opener, &confirmer);
        let mut attachment = Attachment::Pending;
        let answer = |request: &Request, attachment: &mut Attachment| {
            session.answer(&serde_json::to_string(request).unwrap(), attachment)
        };

        let client_nonce = Nonce::mint();
        let challenged = answer(
            &Request::challenge(1, client_nonce.as_hex()),
            &mut attachment,
        )
        .into_result()
        .expect("the server proves itself");
        let server_nonce =
            Nonce::from_peer_hex(challenged.result[FIELD_SERVER_NONCE].as_str().unwrap()).unwrap();
        let proof = handshake::proof(
            token,
            handshake::CLIENT_PROOF_CONTEXT,
            &client_nonce,
            &server_nonce,
        );

        let mut out = vec![answer(&Request::attach(2, proof), &mut attachment)];
        for request in requests {
            out.push(answer(request, &mut attachment));
        }
        out
    }

    /// The first acceptance verb, end to end through the server: attach, then `profiles list`.
    #[test]
    fn an_attached_client_gets_its_profiles_listed() {
        let token = SessionToken::mint();
        let out = attached_conversation(
            &token,
            &[Request::dispatch(
                3,
                Command::Profiles(ProfilesAction::List),
            )],
        );
        assert!(out[0].error.is_none(), "the attach must succeed");
        let listed = out[1]
            .clone()
            .into_result()
            .expect("profiles list is served");
        assert_eq!(listed.result["profiles"][0]["did"], "did:chia:one");
    }

    /// The SECOND acceptance verb, so a fixture that only ever exercises one local route cannot pass.
    #[test]
    fn an_attached_client_gets_its_wallet_balance() {
        let token = SessionToken::mint();
        let out = attached_conversation(
            &token,
            &[Request::dispatch(3, Command::Wallet(WalletAction::Balance))],
        );
        let balance = out[1]
            .clone()
            .into_result()
            .expect("wallet balance is served");
        assert_eq!(balance.result["balance_mojos"], 4_200);
    }

    /// A command sent with NO attach is refused. This is what the token exists for, and it is
    /// asserted on the SAME command the attached test proves works — so the only difference between
    /// the two runs is the attach.
    #[test]
    fn a_command_without_an_attach_is_denied() {
        let token = SessionToken::mint();
        let out = conversation(
            &token,
            &[Request::dispatch(
                1,
                Command::Profiles(ProfilesAction::List),
            )],
        );
        assert_eq!(
            out[0].clone().into_result().unwrap_err().code,
            ErrorCode::Denied
        );
    }

    /// An attach with NO preceding challenge is refused by the state ladder — and the command that
    /// follows it is still refused.
    ///
    /// Renamed from `a_wrong_token_neither_attaches_nor_leaves_the_session_usable`, which is what it
    /// checked before the lane became mutually authenticated. It now sends a frame the ladder rejects
    /// one layer BEFORE the proof comparison, so it never reaches that comparison and must not claim
    /// to cover it; `a_wrong_client_proof_after_a_real_challenge_is_refused` is that test.
    ///
    /// Asserting only that the attach failed would pass against a server that marked the session
    /// attached BEFORE checking the ladder, because both produce a failed attach frame. The second
    /// hop is what distinguishes a rejection from a rejection that let the session through anyway.
    #[test]
    fn an_attach_without_a_challenge_neither_attaches_nor_leaves_the_session_usable() {
        let token = SessionToken::mint();
        let out = conversation(
            &token,
            &[
                Request::attach(1, SessionToken::mint().as_hex()),
                Request::dispatch(2, Command::Profiles(ProfilesAction::List)),
            ],
        );
        assert_eq!(
            out[0].clone().into_result().unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            out[1].clone().into_result().unwrap_err().code,
            ErrorCode::Denied,
            "a rejected attach must not leave the session usable"
        );
    }

    /// The SERVER-direction proof comparison: a client that completes a real challenge and then
    /// presents a well-formed proof it could not have computed is refused, and the session stays shut.
    ///
    /// # Why the fixture has to go all the way to `Challenged` first
    ///
    /// The state ladder refuses an attach that had no challenge, so a wrong-proof frame sent cold is
    /// rejected a layer before the MAC and pins nothing about it — that is exactly how the previous
    /// test came to keep its name while covering a different check. This one plays the whole client
    /// half honestly and substitutes ONE thing: the proof, computed over the true transcript under a
    /// DIFFERENT session secret. Full width, right shape, right transcript, wrong key, so the
    /// comparison in `attach` is the only thing left that can reject it.
    #[test]
    fn a_wrong_client_proof_after_a_real_challenge_is_refused() {
        let token = SessionToken::mint();
        let (identity, opener, confirmer) =
            (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
        let session = CliSession::new(token.clone(), &identity, &opener, &confirmer);
        let mut attachment = Attachment::Pending;
        let answer = |request: &Request, attachment: &mut Attachment| {
            session.answer(&serde_json::to_string(request).unwrap(), attachment)
        };

        let client_nonce = Nonce::mint();
        let challenged = answer(
            &Request::challenge(1, client_nonce.as_hex()),
            &mut attachment,
        )
        .into_result()
        .expect("the server proves itself");
        assert_eq!(
            attachment,
            Attachment::Challenged {
                client: client_nonce.clone(),
                server: Nonce::from_peer_hex(
                    challenged.result[FIELD_SERVER_NONCE].as_str().unwrap()
                )
                .unwrap(),
            },
            "the fixture is void unless the ladder really reached Challenged"
        );
        let server_nonce =
            Nonce::from_peer_hex(challenged.result[FIELD_SERVER_NONCE].as_str().unwrap()).unwrap();

        // The one substitution: the right MAC construction over the right transcript, under a secret
        // this client was never given.
        let forged = handshake::proof(
            &SessionToken::mint(),
            handshake::CLIENT_PROOF_CONTEXT,
            &client_nonce,
            &server_nonce,
        );
        let refused = answer(&Request::attach(2, forged), &mut attachment)
            .into_result()
            .expect_err("a proof computed under another secret must not attach");
        assert_eq!(refused.code, ErrorCode::Denied);

        // And the session is not usable afterwards: a refusal that still opened the session would be
        // the whole exploit, and the refusal frame alone cannot tell the two apart.
        assert_eq!(
            attachment,
            Attachment::Challenged {
                client: client_nonce,
                server: server_nonce
            }
        );
        let after = answer(
            &Request::dispatch(3, Command::Profiles(ProfilesAction::List)),
            &mut attachment,
        )
        .into_result()
        .expect_err("a rejected proof must not leave the session usable");
        assert_eq!(after.code, ErrorCode::Denied);
    }

    /// An unknown method is a catalogued refusal naming the method, not a dropped frame.
    #[test]
    fn an_unknown_method_is_refused_by_name() {
        let token = SessionToken::mint();
        let mut request = Request::challenge(1, Nonce::mint().as_hex());
        request.method = "control.session.detach".into();
        let out = conversation(&token, &[request]);
        let err = out[0].clone().into_result().unwrap_err();
        assert_eq!(err.code, ErrorCode::Usage);
        assert!(err.message.contains("control.session.detach"));
    }

    /// An engine-routed verb says WHY it cannot be served rather than hanging or returning nothing.
    #[test]
    fn an_engine_routed_verb_reports_that_it_is_not_proxied_yet() {
        let token = SessionToken::mint();
        let out = attached_conversation(&token, &[Request::dispatch(3, Command::Info)]);
        let err = out[1].clone().into_result().unwrap_err();
        assert_eq!(err.code, ErrorCode::NotConnected);
        assert!(err.message.contains("control.status"));
    }

    /// A run of transient accept failures is absorbed, and the ceiling is where it stops.
    ///
    /// Pinned from BOTH sides: one attempt below the ceiling must still be tolerated, and the
    /// ceiling attempt itself must give up. A bound checked only from below confirms nothing but
    /// itself.
    #[test]
    fn the_accept_loop_tolerates_faults_up_to_its_ceiling_and_then_gives_up() {
        let mut faults = AcceptFaults::default();

        for attempt in 1..MAX_CONSECUTIVE_ACCEPT_FAULTS {
            assert_eq!(
                faults.tolerate(),
                Some(ACCEPT_RETRY_BACKOFF),
                "attempt {attempt} is below the ceiling and must be retried"
            );
        }

        assert_eq!(
            faults.tolerate(),
            None,
            "the {MAX_CONSECUTIVE_ACCEPT_FAULTS}th consecutive failure must end the lane"
        );
    }

    /// An accepted client ends the run, so occasional faults over a long uptime never accumulate
    /// into a give-up on a healthy listener.
    ///
    /// This is the assertion a counter that only ever increments would fail: it drives the count to
    /// one below the ceiling, succeeds once, and then requires a FULL fresh run of tolerance --
    /// which a non-resetting counter answers with `None` on its first call.
    #[test]
    fn an_accepted_client_clears_the_fault_run() {
        let mut faults = AcceptFaults::default();
        for _ in 1..MAX_CONSECUTIVE_ACCEPT_FAULTS {
            faults.tolerate();
        }

        faults.succeeded();

        for attempt in 1..MAX_CONSECUTIVE_ACCEPT_FAULTS {
            assert_eq!(
                faults.tolerate(),
                Some(ACCEPT_RETRY_BACKOFF),
                "after a success, attempt {attempt} must be tolerated again"
            );
        }
    }

    /// The backoff is a real pause, because a zero would turn tolerance into a hot loop.
    #[test]
    fn the_accept_backoff_is_not_instant() {
        assert!(ACCEPT_RETRY_BACKOFF > Duration::ZERO);
    }

    /// The remedy an engine refusal offers must be a verb that actually answers.
    ///
    /// `dign info` refusing is by design; sending the person to `dign wallet` was not, because
    /// `dign wallet balance` refuses too. `host_identity`'s
    /// `seed_bound_verbs_refuse_with_a_remedy_and_never_substitute_a_value` pins that refusal. Chaining
    /// one refusal to another is how a surface ends up lying about money without any single message
    /// being wrong. If a later lane serves the balance, that host_identity test fails first and
    /// leads back here.
    #[test]
    fn the_refusal_hint_only_names_verbs_that_answer() {
        let token = SessionToken::mint();
        let out = attached_conversation(&token, &[Request::dispatch(3, Command::Info)]);
        let hint = out[1]
            .clone()
            .into_result()
            .unwrap_err()
            .hint
            .expect("an engine refusal carries its remedy");

        assert!(
            hint.contains("dign profiles list"),
            "the remedy must name a verb that answers: {hint}"
        );

        // The property is that no FAMILY name appears, because a family includes its refusing
        // members. Asserting the outcome ("the hint is short", "the hint mentions profiles") would
        // stay green for a hint that named `dign profiles` wholesale -- which is the exact defect
        // this test was written for and, in its first form, pinned.
        for family in ["`dign profiles`", "`dign wallet`", "`dign account`"] {
            assert!(
                !hint.contains(family),
                "{family} as a family includes verbs that refuse: {hint}"
            );
        }
    }

    /// A refused command must also not have RUN.
    ///
    /// The two refusal tests above both dispatch `Profiles(List)`, a READ. They prove the refusal
    /// was reported; nothing about them could notice a gateway that ran the command anyway and then
    /// reported a refusal on top. `StubIdentity::selected` was added to close exactly that gap and
    /// no test read it, so the gap stayed open.
    ///
    /// `Profiles(Select)` is the mutation, so this asserts both halves on both ways in: no attach at
    /// all, and an attach with the wrong token. Verified red by deleting the `Attachment::Attached`
    /// guard in `dispatch` — the response then carries no error and `selected` holds the DID.
    #[test]
    fn a_refused_command_never_reaches_the_gateway() {
        let token = SessionToken::mint();
        let wrong = SessionToken::mint();
        for preamble in [Vec::new(), vec![Request::attach(1, wrong.as_hex())]] {
            let (identity, opener, confirmer) =
                (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
            let session = CliSession::new(token.clone(), &identity, &opener, &confirmer);

            let mut requests = preamble;
            requests.push(Request::dispatch(
                9,
                Command::Profiles(ProfilesAction::Select {
                    did: "did:chia:two".into(),
                }),
            ));
            let mut duplex = ScriptedDuplex::of(&requests);
            session
                .converse(&mut duplex)
                .expect("the conversation ends");

            let refusal = duplex
                .responses()
                .last()
                .expect("the select was answered")
                .clone()
                .into_result()
                .unwrap_err();
            assert_eq!(refusal.code, ErrorCode::Denied);
            assert!(
                identity.selected.borrow().is_empty(),
                "a refused select must not have reached the identity: {:?}",
                identity.selected.borrow()
            );
        }
    }

    /// An unreadable frame is answered, not ignored — a silent drop would hang the client on a read
    /// that never returns.
    #[test]
    fn an_unreadable_frame_is_answered_with_a_usage_error() {
        let (identity, opener, confirmer) =
            (StubIdentity::default(), UnusedOpener, ApprovingConfirmer);
        let session = CliSession::new(SessionToken::mint(), &identity, &opener, &confirmer);
        let mut duplex = ScriptedDuplex::of_lines(&["{not json"]);
        session.converse(&mut duplex).unwrap();
        assert_eq!(
            duplex.responses()[0]
                .clone()
                .into_result()
                .unwrap_err()
                .code,
            ErrorCode::Usage
        );
    }
}
