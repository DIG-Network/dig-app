//! The dig-app half of the CLI lane: authenticate a `dign` client, then serve its commands.
//!
//! The server owns NO policy of its own. It authenticates the session and hands every command to the
//! [`Gateway`](crate::gateway::Gateway), which is the one place that decides where a command is
//! served — so the CLI reaches exactly the surface the tray reaches, through the same seams,
//! including the native confirm ceremony in front of a signature (dig_ecosystem#908: the app signs
//! nothing without the user's own confirmation, and a CLI session is not a way around it).
//!
//! The two halves are split on purpose. [`CliSession`] is the CONVERSATION — pure over a frame
//! transport, so every authentication and routing rule below is unit-tested without a socket.
//! [`CliSessionServer`] adds the bound endpoint and the accept loop.

use std::path::Path;

use serde_json::Value;

use crate::confirm::NativeConfirmer;
use crate::gateway::{
    Command, EngineProxy, ErrorCode, Gateway, GatewayError, LinkOpener, LocalIdentity, Outcome,
};

use super::auth::SessionToken;
use super::transport::{self, CliListener, CliStream};
use super::wire::{Request, RequestParams, Response, METHOD_ATTACH, METHOD_DISPATCH};

use dig_ipc_protocol::FrameTransport;

/// A conversation's authentication state. A command frame is only ever served in [`Self::Attached`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attachment {
    /// Nothing has been proven yet: only an attach is accepted.
    Pending,
    /// The client presented the session token; commands are served.
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
            (METHOD_ATTACH, RequestParams::Attach { token_hex }) => {
                self.attach(id, &token_hex, attachment)
            }
            (METHOD_DISPATCH, RequestParams::Dispatch { command }) => {
                self.dispatch(id, command, *attachment)
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

    /// Check the presented token and open the session.
    fn attach(&self, id: u64, presented: &str, attachment: &mut Attachment) -> Response {
        if !self.token.matches(presented) {
            tracing::warn!("a dign client presented the wrong session token");
            return Response::failed(
                id,
                GatewayError::new(
                    ErrorCode::Denied,
                    "this session token does not belong to the running dig-app",
                )
                .with_hint("re-run `dign` — dig-app mints a new token each time it starts"),
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
    fn dispatch(&self, id: u64, command: Command, attachment: Attachment) -> Response {
        if attachment != Attachment::Attached {
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

/// The CLI lane server: a bound per-user endpoint plus the conversation rules it serves with.
pub struct CliSessionServer<'a> {
    listener: CliListener,
    session: CliSession<'a>,
}

impl<'a> CliSessionServer<'a> {
    /// Bind the lane at `endpoint` under `brand_dir`, mint the session token, and publish it where
    /// `dign` looks for it.
    ///
    /// The token is published only AFTER the bind succeeds, so a failed start never leaves a
    /// credential on disk for a lane nothing is serving.
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

    /// Serve clients until the listener fails, one conversation at a time.
    ///
    /// Serial service is deliberate: `dign` attaches, asks one question and exits, and the seams
    /// behind the gateway (the account residency, the native confirmer) are single-ceremony
    /// surfaces. Two concurrent confirm prompts would be a worse answer than a client waiting.
    pub fn serve_blocking(&self) -> std::io::Result<()> {
        loop {
            let stream = self.listener.accept()?;
            if let Err(e) = self.serve_one(stream) {
                // A client that hung up mid-conversation is ordinary; it must not end the lane.
                tracing::debug!(error = %e, "a dign client conversation ended");
            }
        }
    }

    /// Block until one client connects, returning its stream. The seam an integration test uses to
    /// serve a bounded number of conversations instead of looping forever.
    pub fn accept_one(&self) -> std::io::Result<CliStream> {
        self.listener.accept()
    }

    /// Serve one accepted client.
    pub fn serve_one(&self, stream: CliStream) -> std::io::Result<()> {
        let mut frames = transport::frames(stream)?;
        self.session.converse(&mut frames)
    }
}

/// The engine proxy the CLI lane serves with today: an honest refusal naming the method.
///
/// dig-app reaches the node over its own loopback control channel with TYPED calls
/// ([`crate::control`]), which is not the untyped `(method, params)` shape an [`EngineProxy`]
/// forwards. Rather than invent a second, untyped path to the node for the CLI's sake, engine-routed
/// verbs report `NOT_CONNECTED` and say so — a person sees why, instead of a hang or an empty result.
struct UnproxiedEngine;

impl EngineProxy for UnproxiedEngine {
    fn call(&self, method: &str, _params: Value) -> Result<Value, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::NotConnected,
            format!("dig-app does not yet proxy `{method}` to the node on behalf of the CLI"),
        )
        .with_hint("the local verbs — `dign profiles` and `dign wallet` — are served now"))
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

    /// The first acceptance verb, end to end through the server: attach, then `profiles list`.
    #[test]
    fn an_attached_client_gets_its_profiles_listed() {
        let token = SessionToken::mint();
        let out = conversation(
            &token,
            &[
                Request::attach(1, token.as_hex()),
                Request::dispatch(2, Command::Profiles(ProfilesAction::List)),
            ],
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
        let out = conversation(
            &token,
            &[
                Request::attach(1, token.as_hex()),
                Request::dispatch(2, Command::Wallet(WalletAction::Balance)),
            ],
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

    /// A WRONG token does not attach — and the command that follows it is still refused.
    ///
    /// Asserting only that the attach failed would pass against a server that marked the session
    /// attached BEFORE checking the token, because both produce a failed attach frame. The second
    /// hop is what distinguishes a rejection from a rejection that let the session through anyway.
    #[test]
    fn a_wrong_token_neither_attaches_nor_leaves_the_session_usable() {
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

    /// An unknown method is a catalogued refusal naming the method, not a dropped frame.
    #[test]
    fn an_unknown_method_is_refused_by_name() {
        let token = SessionToken::mint();
        let mut request = Request::attach(1, token.as_hex());
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
        let out = conversation(
            &token,
            &[
                Request::attach(1, token.as_hex()),
                Request::dispatch(2, Command::Info),
            ],
        );
        let err = out[1].clone().into_result().unwrap_err();
        assert_eq!(err.code, ErrorCode::NotConnected);
        assert!(err.message.contains("control.status"));
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
