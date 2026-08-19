//! The `dign` <-> dig-app frame contract: what travels over the per-user pipe/socket.
//!
//! One frame is one line of JSON, so the transport is the newline-delimited
//! [`LineTransport`](dig_ipc_protocol::LineTransport) both halves of the IPC protocol crate already
//! use. The shapes here are JSON-RPC 2.0 envelopes: the field names ARE the contract, and both
//! binaries ship from this workspace so they can never be built from two different definitions.

use serde::{Deserialize, Serialize};

use crate::gateway::{Command, ErrorCode, GatewayError, Outcome};

/// The JSON-RPC version string every frame carries.
pub const JSONRPC_VERSION: &str = "2.0";

/// `control.session.challenge` — the CLI asks the app to prove it holds the session secret, BEFORE
/// the CLI proves anything of its own.
///
/// This frame is what makes the lane mutually authenticated. It carries a nonce, never a secret, so a
/// frame delivered to an impostor that squatted the endpoint name teaches that impostor nothing. See
/// [`super::handshake`] for the construction and for why the order of the two proofs matters.
pub const METHOD_CHALLENGE: &str = "control.session.challenge";

/// `control.session.attach` — the CLI proves it may use this session before it may ask for anything.
///
/// The name matches the app-to-engine handshake method (`dig_ipc_protocol`) deliberately: this is the
/// same idea one hop earlier in the chain, and a reader tracing a session across the two hops should
/// meet one vocabulary rather than two.
pub const METHOD_ATTACH: &str = "control.session.attach";

/// The field carrying the server nonce in a [`METHOD_CHALLENGE`] answer.
pub const FIELD_SERVER_NONCE: &str = "server_nonce_hex";

/// The field carrying the server proof in a [`METHOD_CHALLENGE`] answer.
pub const FIELD_SERVER_PROOF: &str = "server_proof_hex";

/// `gateway.dispatch` — one parsed [`Command`] for the gateway to route and serve.
pub const METHOD_DISPATCH: &str = "gateway.dispatch";

/// A request frame: an attach, or a command to dispatch.
///
/// `method` is matched exhaustively by the server, so an unknown method is a catalogued refusal
/// rather than a frame that is quietly ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// The correlation id, echoed on the response.
    pub id: u64,
    /// [`METHOD_ATTACH`] or [`METHOD_DISPATCH`].
    pub method: String,
    /// The parameters for `method`.
    pub params: RequestParams,
}

/// The parameter union, tagged by which method carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestParams {
    /// [`METHOD_CHALLENGE`] — the client nonce the server proof is computed over.
    Challenge {
        /// 32 bytes of CSPRNG output, lowercase hex. Not a secret.
        client_nonce_hex: String,
    },
    /// [`METHOD_ATTACH`] — the client half of the mutual proof, lowercase hex.
    ///
    /// The session token itself NEVER travels in this frame. The client proves knowledge of it with a
    /// MAC over the two handshake nonces, so an impostor holding the endpoint learns nothing it could
    /// present to the real app later.
    Attach {
        /// The [`super::handshake::CLIENT_PROOF_CONTEXT`] MAC over both nonces.
        client_proof_hex: String,
    },
    /// [`METHOD_DISPATCH`] — the command to route.
    Dispatch {
        /// The parsed `dign` invocation.
        command: Command,
    },
}

/// A response frame: exactly one of `result` / `error` is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// The id of the request being answered.
    pub id: u64,
    /// The outcome, when the call succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Outcome>,
    /// The catalogued failure, when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<GatewayError>,
}

impl Request {
    /// A challenge request contributing `client_nonce_hex` to the handshake transcript.
    pub fn challenge(id: u64, client_nonce_hex: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: METHOD_CHALLENGE.to_string(),
            params: RequestParams::Challenge {
                client_nonce_hex: client_nonce_hex.into(),
            },
        }
    }

    /// An attach request presenting the client half of the mutual proof.
    pub fn attach(id: u64, client_proof_hex: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: METHOD_ATTACH.to_string(),
            params: RequestParams::Attach {
                client_proof_hex: client_proof_hex.into(),
            },
        }
    }

    /// A dispatch request carrying `command`.
    pub fn dispatch(id: u64, command: Command) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: METHOD_DISPATCH.to_string(),
            params: RequestParams::Dispatch { command },
        }
    }
}

impl Response {
    /// A successful answer to request `id`.
    pub fn ok(id: u64, outcome: Outcome) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(outcome),
            error: None,
        }
    }

    /// A failed answer to request `id`.
    pub fn failed(id: u64, error: GatewayError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Read the frame as the `Result` the caller wanted.
    ///
    /// A frame carrying NEITHER half is a protocol violation, not a success: answering it with an
    /// empty outcome would let a malformed or truncated reply read as "the command worked".
    pub fn into_result(self) -> Result<Outcome, GatewayError> {
        match (self.result, self.error) {
            (Some(outcome), None) => Ok(outcome),
            (_, Some(error)) => Err(error),
            (None, None) => Err(GatewayError::new(
                ErrorCode::IoError,
                "the dig-app session returned a frame with neither a result nor an error",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{ProfilesAction, WalletAction};

    /// The two acceptance commands survive the wire byte-for-byte. A command that round-trips into a
    /// DIFFERENT command is the failure this guards: the server acts on what it decoded, so a lossy
    /// encoding would run a verb the person never typed.
    #[test]
    fn a_command_round_trips_through_a_dispatch_frame() {
        for command in [
            Command::Profiles(ProfilesAction::List),
            Command::Wallet(WalletAction::Balance),
            Command::Profiles(ProfilesAction::Select {
                did: "did:chia:abc".into(),
            }),
        ] {
            let line = serde_json::to_string(&Request::dispatch(7, command.clone())).unwrap();
            let back: Request = serde_json::from_str(&line).unwrap();
            assert_eq!(back.id, 7);
            assert_eq!(back.method, METHOD_DISPATCH);
            let RequestParams::Dispatch { command: decoded } = back.params else {
                panic!("a dispatch frame decoded as an attach");
            };
            assert_eq!(decoded, command);
        }
    }

    #[test]
    fn an_attach_frame_carries_the_client_proof() {
        let line = serde_json::to_string(&Request::attach(1, "ab12")).unwrap();
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(back.method, METHOD_ATTACH);
        let RequestParams::Attach { client_proof_hex } = back.params else {
            panic!("an attach frame decoded as another method");
        };
        assert_eq!(client_proof_hex, "ab12");
    }

    #[test]
    fn a_challenge_frame_carries_the_client_nonce() {
        let line = serde_json::to_string(&Request::challenge(1, "cd34")).unwrap();
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(back.method, METHOD_CHALLENGE);
        let RequestParams::Challenge { client_nonce_hex } = back.params else {
            panic!("a challenge frame decoded as another method");
        };
        assert_eq!(client_nonce_hex, "cd34");
    }

    /// The untagged parameter union must never let one method decode as another: the server matches
    /// the method AND the params together, so a challenge that could parse as an attach would be a
    /// way to reach the attach arm with no nonce ever exchanged.
    #[test]
    fn the_three_parameter_shapes_are_mutually_exclusive() {
        let frames = [
            Request::challenge(1, "cd34"),
            Request::attach(1, "ab12"),
            Request::dispatch(1, Command::Profiles(ProfilesAction::List)),
        ];
        for frame in frames {
            let expected = std::mem::discriminant(&frame.params);
            let line = serde_json::to_string(&frame).unwrap();
            let back: Request = serde_json::from_str(&line).unwrap();
            assert_eq!(
                std::mem::discriminant(&back.params),
                expected,
                "{} decoded as a different parameter shape",
                frame.method
            );
        }
    }

    #[test]
    fn an_error_response_keeps_its_catalogued_code() {
        let frame = Response::failed(3, GatewayError::new(ErrorCode::Locked, "locked"));
        let line = serde_json::to_string(&frame).unwrap();
        let back: Response = serde_json::from_str(&line).unwrap();
        let err = back.into_result().unwrap_err();
        assert_eq!(err.code, ErrorCode::Locked);
    }

    /// A frame with neither half must not read as success.
    #[test]
    fn an_empty_response_is_an_io_error_not_an_empty_success() {
        let frame = Response {
            jsonrpc: JSONRPC_VERSION.into(),
            id: 1,
            result: None,
            error: None,
        };
        assert_eq!(frame.into_result().unwrap_err().code, ErrorCode::IoError);
    }
}
