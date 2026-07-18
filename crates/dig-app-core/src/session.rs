//! The identity-authenticated engine session — the app side of the IPC channel (U6, epic #908,
//! **security-critical / custody**).
//!
//! dig-app proves possession of the active profile's identity to the identity-agnostic engine, then
//! keeps a live session over which the engine may ask the app to sign engine-initiated operations.
//! The private key never crosses this boundary: the app signs *in process* and returns only the
//! signature. This module implements the app half of the `control.session.*` handshake and the
//! engine→app `sign` callback, exactly as specified in `SPEC.md` §5.3.
//!
//! ## Handshake (app → engine)
//!
//! 1. `control.session.begin { profile_did, signing_pubkey_hex }` → `{ nonce_b64, session_candidate }`.
//! 2. The app signs the domain-separated challenge [`SESSION_CHALLENGE_DOMAIN`] ‖ `nonce` ‖
//!    `profile_did` with the in-memory Ed25519 identity key (slot `0x0010`).
//! 3. `control.session.attach { session_candidate, signature_b64, profile }` → `{ session_id,
//!    engine_capabilities }`. The engine verifies the signature against the pubkey from step 1 and
//!    opens an in-memory session bound to the profile.
//! 4. `control.session.detach { session_id }` on logout / profile switch / exit.
//!
//! ## `sign` callback (engine → app, same connection)
//!
//! The engine cannot sign (it holds no user key). For an engine-initiated operation it sends
//! `sign { session_id, op_id, payload_type, payload_b64, context }`; the app runs a [`SignPolicy`]
//! gate, signs the payload with the in-memory key, and returns `{ signature_b64, pubkey_hex }`. A
//! denied or un-signable request returns a JSON-RPC error correlated by the same request id.
//!
//! ## Boundary invariants
//!
//! - The identity private key is resolved through the [`SessionSigner`] seam (the U4/U5 unlocked
//!   identity), never held raw in this module and never serialized onto the wire.
//! - Blind-signing is the custody risk: the engine chooses the callback payload. [`SignPolicy`] is
//!   the mandatory gate — there is no default-allow — so an operator can require confirmation or
//!   scope which `payload_type`s an attached session may sign.
//! - The local per-user pipe/socket frames are NOT end-to-end sealed: the OS per-user ACL is the
//!   confidentiality boundary here (ecosystem §5.4). Recipient-directed content the engine later
//!   relays onward is sealed to the recipient's `0x0011` key upstream of this channel — out of scope
//!   for this module, which must simply not undermine that boundary (it never does: it moves only
//!   session-control frames and detached signatures).

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::keystore::{IdentitySecrets, SIGNATURE_LEN};

/// The domain separator prepended to every session-attach challenge, so a signature minted for the
/// session handshake can never be replayed as a signature over a spend, an SMT write, or any other
/// message the identity key signs. Canonical — the engine builds the identical challenge to verify.
///
/// This is one instance of the crate-wide invariant: **every signature the slot-`0x0010` identity
/// key produces MUST carry a unique per-purpose domain-separation tag.** Two purposes never share a
/// tag, and no purpose signs un-prefixed caller bytes — otherwise a signature minted for one purpose
/// could be replayed as a valid signature for another (a cross-protocol signing oracle).
pub const SESSION_CHALLENGE_DOMAIN: &[u8] = b"DIGNET-SESSION-v1";

/// The domain separator for the engine→app `sign` callback (§ [`SessionClient::handle_next_sign_callback`]).
/// Distinct from [`SESSION_CHALLENGE_DOMAIN`], so a callback signature can NEVER equal an attach
/// challenge signature — nor any other message the identity key signs — even when the engine chooses
/// the callback payload to be byte-for-byte a valid attach challenge. Canonical: the engine
/// reconstructs the identical byte string to verify.
pub const SIGN_CALLBACK_DOMAIN: &[u8] = b"DIGNET-SIGN-v1";

/// The largest single IPC frame [`LineTransport`] will read (1 MiB). Session-control frames and a
/// detached signature are tiny; even a spend/SMT payload in a `sign` callback is far under this. The
/// cap bounds a compromised local engine's ability to OOM the app with a newline-less giant frame.
const MAX_FRAME_BYTES: u64 = 1024 * 1024;

/// The most engine `sign` callbacks the client will service while awaiting a single handshake
/// response before giving up. Bounds a compromised engine that would otherwise wedge the app in an
/// endless callback stream instead of answering the request.
const MAX_INTERLEAVED_CALLBACKS: usize = 64;

/// JSON-RPC error code returned to the engine when a [`SignPolicy`] denies a `sign` callback.
const SIGN_DENIED_CODE: i64 = -32001;
/// JSON-RPC error code returned to the engine when a `sign` callback payload is not valid base64.
const SIGN_BAD_PAYLOAD_CODE: i64 = -32602;

// The `control.*` methods this module speaks, kept as constants so the strings live in one place.
const METHOD_BEGIN: &str = "control.session.begin";
const METHOD_ATTACH: &str = "control.session.attach";
const METHOD_DETACH: &str = "control.session.detach";
const METHOD_SIGN: &str = "sign";

/// Builds the exact bytes the identity key signs to attach a session: the domain separator, then the
/// engine's nonce, then the profile DID. Pure and canonical — the engine reconstructs the identical
/// message to verify, so app and engine MUST agree on this construction byte-for-byte.
pub fn challenge_message(nonce: &[u8], profile_did: &str) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SESSION_CHALLENGE_DOMAIN.len() + nonce.len() + profile_did.len());
    message.extend_from_slice(SESSION_CHALLENGE_DOMAIN);
    message.extend_from_slice(nonce);
    message.extend_from_slice(profile_did.as_bytes());
    message
}

/// Builds the exact bytes the identity key signs for an engine `sign` callback:
///
/// ```text
/// SIGN_CALLBACK_DOMAIN ‖ len16(payload_type) ‖ payload_type ‖ payload
/// ```
///
/// where `len16` is the big-endian `u16` byte length of `payload_type`. The length prefix makes the
/// `payload_type ‖ payload` boundary unambiguous, so `(type="a", payload="bc")` cannot collide with
/// `(type="ab", payload="c")`. The [`SIGN_CALLBACK_DOMAIN`] tag — distinct from
/// [`SESSION_CHALLENGE_DOMAIN`] — guarantees a callback signature can never equal an attach-challenge
/// signature (or any other identity-key signature), closing the cross-protocol signing oracle a
/// malicious engine would otherwise exploit by submitting a crafted `payload`.
///
/// Pure and canonical — the engine reconstructs the identical byte string to verify, so app and
/// engine MUST agree on this construction byte-for-byte.
///
/// `payload_type` is bounded to [`u16::MAX`] bytes (labels are short); a longer label is a protocol
/// error the caller rejects before signing.
pub fn sign_callback_message(payload_type: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let type_len = u16::try_from(payload_type.len()).ok()?;
    let mut message =
        Vec::with_capacity(SIGN_CALLBACK_DOMAIN.len() + 2 + payload_type.len() + payload.len());
    message.extend_from_slice(SIGN_CALLBACK_DOMAIN);
    message.extend_from_slice(&type_len.to_be_bytes());
    message.extend_from_slice(payload_type.as_bytes());
    message.extend_from_slice(payload);
    Some(message)
}

/// The signing capability the session client needs from the unlocked identity, without holding the
/// raw key. The production implementation is the U4/U5 in-memory [`IdentitySecrets`]; tests inject a
/// fake. Keeping this a narrow seam is what enforces the custody boundary: this module can sign and
/// name the public key, but can never read, copy, or transmit the private key.
pub trait SessionSigner {
    /// The Ed25519 signing public key (`dig-identity` slot `0x0010`).
    fn signing_public_key(&self) -> [u8; 32];

    /// Sign `message` with the in-memory identity key, returning only the detached signature.
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN];

    /// The signing public key as lowercase hex — the form carried on the wire (`signing_pubkey_hex`,
    /// `pubkey_hex`).
    fn signing_public_key_hex(&self) -> String {
        hex::encode(self.signing_public_key())
    }
}

/// The unlocked profile identity signs session challenges and engine callbacks directly. The key
/// itself stays owned by [`IdentitySecrets`]; this impl only borrows its signing primitive.
impl SessionSigner for IdentitySecrets {
    fn signing_public_key(&self) -> [u8; 32] {
        IdentitySecrets::signing_public_key(self)
    }

    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        IdentitySecrets::sign(self, message)
    }
}

/// A decoded engine `sign` callback presented to a [`SignPolicy`] for authorization. Borrows the
/// request so a policy can inspect it without the payload being copied out of the channel.
pub struct SignRequest<'a> {
    /// The session the engine is signing on behalf of.
    pub session_id: &'a str,
    /// The engine-assigned operation id, for correlation and audit.
    pub op_id: &'a str,
    /// The engine's label for what kind of payload this is (a spend bundle, an SMT write, …).
    pub payload_type: &'a str,
    /// The raw bytes the engine wants signed (already base64-decoded).
    pub payload: &'a [u8],
    /// Optional engine-supplied context (human-readable description, amounts, recipient) a policy or
    /// a confirmation prompt can surface. Absent when the engine sends none.
    pub context: Option<&'a serde_json::Value>,
}

/// A [`SignPolicy`]'s ruling on one engine `sign` callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignDecision {
    /// Sign the payload and return the signature to the engine.
    Allow,
    /// Refuse; the reason is returned to the engine as a JSON-RPC error (never signed).
    Deny(String),
}

/// The custody gate for engine-initiated signing. The engine chooses the callback payload, so a
/// blanket "sign anything the engine asks" would let a compromised engine mint arbitrary signatures
/// with the user's key. Every session client MUST supply a policy; there is deliberately no
/// default-allow. Production policies range from user-confirmation prompts to a `payload_type`
/// allowlist; tests use [`AllowAllSignPolicy`] / [`DenyAllSignPolicy`].
pub trait SignPolicy {
    /// Rule on whether the in-memory identity key may sign `request`.
    fn authorize(&self, request: &SignRequest<'_>) -> SignDecision;
}

/// A newline-delimited JSON-RPC frame transport — the per-user named pipe / Unix domain socket
/// abstracted so the protocol logic is transport-agnostic and unit-testable. Each frame is one line
/// of JSON; the newline is the framing.
pub trait FrameTransport {
    /// Send one JSON frame (the implementation appends the newline and flushes).
    fn send_frame(&mut self, frame: &str) -> io::Result<()>;

    /// Receive one JSON frame (a single line, newline stripped). A closed channel surfaces as
    /// [`io::ErrorKind::UnexpectedEof`] — the signal the session client treats as a dropped pipe.
    fn recv_frame(&mut self) -> io::Result<String>;
}

/// A [`FrameTransport`] over any byte-stream reader/writer pair — a `UnixStream` (with a
/// `try_clone`d half), a Windows named-pipe handle, or an in-memory duplex in tests. The read half
/// is buffered so `read_line` frames cheaply; the write half is flushed after every frame so the
/// engine sees requests promptly.
pub struct LineTransport<R: Read, W: Write> {
    reader: BufReader<R>,
    writer: W,
}

impl<R: Read, W: Write> LineTransport<R, W> {
    /// Build a transport from an already-connected reader and writer (typically the two halves of one
    /// duplex stream).
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }
}

impl<R: Read, W: Write> FrameTransport for LineTransport<R, W> {
    fn send_frame(&mut self, frame: &str) -> io::Result<()> {
        self.writer.write_all(frame.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    fn recv_frame(&mut self) -> io::Result<String> {
        // Read one newline-delimited frame, but NEVER more than MAX_FRAME_BYTES: the engine is a
        // local peer, but a compromised or buggy one could otherwise stream a newline-less multi-GB
        // "frame" and OOM the user's app. Cap the read and reject an over-long frame instead.
        let mut buf = Vec::new();
        let read = (&mut self.reader)
            .take(MAX_FRAME_BYTES)
            .read_until(b'\n', &mut buf)?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if buf.last() != Some(&b'\n') && buf.len() as u64 >= MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine frame exceeds the maximum size",
            ));
        }
        let text = String::from_utf8(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "engine frame is not UTF-8"))?;
        Ok(text.trim_end_matches(['\n', '\r']).to_string())
    }
}

/// A live, attached engine session. One exists per active profile (the app is multi-session aware;
/// see [`SessionRegistry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The engine-assigned session identifier, echoed on `detach` and correlated in `sign` callbacks.
    pub session_id: String,
    /// The capabilities the engine advertised for this session.
    pub engine_capabilities: Vec<String>,
    /// The DID whose identity attached this session.
    pub profile_did: String,
}

/// The active profile's attachment payload — the `{ did, subscriptions, config_digest }` the app
/// pushes to the engine on attach (`SPEC.md` §5.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileAttachment {
    /// The profile DID being attached.
    pub did: String,
    /// The subscriptions the engine should serve for this session.
    pub subscriptions: Vec<String>,
    /// A digest of the profile's config, so the engine can detect config drift without seeing the
    /// (sealed) config itself.
    pub config_digest: String,
}

/// Errors from driving a session over the IPC channel.
///
/// A denied or malformed engine `sign` callback is NOT one of these — it is answered to the engine as
/// a JSON-RPC error and does not fail the local caller. These variants are for failures that break
/// the app's own handshake or read loop.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The transport failed — most importantly [`io::ErrorKind::UnexpectedEof`], the dropped-pipe
    /// signal that triggers a re-attach.
    #[error("session transport I/O error: {0}")]
    Io(#[from] io::Error),

    /// A frame was not well-formed JSON-RPC.
    #[error("malformed session frame: {0}")]
    Frame(#[from] serde_json::Error),

    /// The engine answered a handshake request with a JSON-RPC error.
    #[error("engine rejected the request: [{code}] {message}")]
    Engine {
        /// The JSON-RPC error code the engine returned.
        code: i64,
        /// The human-readable message the engine returned.
        message: String,
    },

    /// A handshake response arrived for a request id the app was not awaiting — a desynchronized
    /// channel.
    #[error("engine reply id did not match the pending request")]
    IdMismatch,

    /// A frame the app expected to be a response carried neither a result nor an error.
    #[error("engine frame was neither a valid response nor a known callback")]
    MalformedResponse,

    /// [`SessionClient::handle_next_sign_callback`] read a frame that was not a `sign` callback.
    #[error("expected an engine sign callback but received a different frame")]
    NotASignCallback,

    /// The engine streamed more than [`MAX_INTERLEAVED_CALLBACKS`] `sign` callbacks without answering
    /// the pending handshake request — a wedged or hostile engine. The app gives up rather than loop
    /// forever.
    #[error("engine sent too many interleaved callbacks without a response")]
    TooManyCallbacks,
}

/// The app-side session client: owns the transport to one engine connection, the [`SessionSigner`]
/// (the unlocked identity), and the [`SignPolicy`] custody gate. Drives the begin→attach handshake,
/// services engine `sign` callbacks, detaches, and re-attaches after a dropped pipe.
///
/// One client drives one connection (hence one profile's session). The app runs several — one per
/// active profile — and tracks their [`Session`] handles in a [`SessionRegistry`].
pub struct SessionClient<T: FrameTransport, S: SessionSigner, P: SignPolicy> {
    transport: T,
    signer: S,
    policy: P,
    next_id: u64,
}

impl<T: FrameTransport, S: SessionSigner, P: SignPolicy> SessionClient<T, S, P> {
    /// Build a client over an already-connected `transport`, signing with `signer` and gating engine
    /// `sign` callbacks through `policy`.
    pub fn new(transport: T, signer: S, policy: P) -> Self {
        Self {
            transport,
            signer,
            policy,
            next_id: 1,
        }
    }

    /// Run the full identity-authenticated handshake for `profile` and return the opened [`Session`]:
    /// `begin` to obtain the nonce + candidate, sign the domain-separated challenge with the
    /// in-memory key, then `attach`. The private key never leaves the process — only the signature
    /// and the public key cross the wire.
    ///
    /// # Errors
    ///
    /// [`SessionError::Io`] if the pipe drops (the re-attach trigger), [`SessionError::Engine`] if the
    /// engine rejects begin or attach, or a frame/parse error on a malformed reply.
    pub fn begin_and_attach(
        &mut self,
        profile: ProfileAttachment,
    ) -> Result<Session, SessionError> {
        let begin_pubkey_hex = self.signer.signing_public_key_hex();
        let begin: BeginResult = self.call(
            METHOD_BEGIN,
            BeginParams {
                profile_did: &profile.did,
                signing_pubkey_hex: begin_pubkey_hex.clone(),
            },
        )?;

        let nonce = BASE64
            .decode(begin.nonce_b64.as_bytes())
            .map_err(|_| SessionError::MalformedResponse)?;

        // We advertised `signer`'s public key in `begin`, and we attach `profile.did`; the engine
        // backstops that this DID's published slot-0x0010 key IS this key (it verifies the challenge
        // signature against the begin pubkey and binds the session to the DID). Locally assert the
        // key we sign with is the one we advertised, so a future refactor that let them diverge trips
        // in debug builds rather than silently attaching a mismatched identity.
        debug_assert_eq!(
            self.signer.signing_public_key_hex(),
            begin_pubkey_hex,
            "the attach signature must use the same identity key advertised in begin"
        );
        let signature = self.signer.sign(&challenge_message(&nonce, &profile.did));

        let attach: AttachResult = self.call(
            METHOD_ATTACH,
            AttachParams {
                session_candidate: &begin.session_candidate,
                signature_b64: BASE64.encode(signature),
                profile: &profile,
            },
        )?;

        Ok(Session {
            session_id: attach.session_id,
            engine_capabilities: attach.engine_capabilities,
            profile_did: profile.did,
        })
    }

    /// Detach `session` (logout / profile switch / exit): tell the engine to drop its in-memory
    /// context for this session.
    ///
    /// # Errors
    ///
    /// [`SessionError::Io`] if the pipe is already gone (which effectively achieves the same end —
    /// the engine drops the session when the connection closes), or [`SessionError::Engine`] if the
    /// engine reports a problem.
    pub fn detach(&mut self, session: &Session) -> Result<(), SessionError> {
        let _: DetachResult = self.call(
            METHOD_DETACH,
            DetachParams {
                session_id: &session.session_id,
            },
        )?;
        Ok(())
    }

    /// Re-establish a session after an engine restart or a dropped pipe: swap in a freshly-connected
    /// `transport` and re-run the handshake. The caller reconnects the OS channel (a new pipe/socket)
    /// and passes it here.
    ///
    /// # Errors
    ///
    /// As [`begin_and_attach`](Self::begin_and_attach).
    pub fn reattach(
        &mut self,
        transport: T,
        profile: ProfileAttachment,
    ) -> Result<Session, SessionError> {
        self.transport = transport;
        self.next_id = 1;
        self.begin_and_attach(profile)
    }

    /// Read one frame and, if it is an engine `sign` callback, service it: decode the payload, gate it
    /// through the [`SignPolicy`], sign with the in-memory key on approval, and answer the engine with
    /// `{ signature_b64, pubkey_hex }` (or a JSON-RPC error on denial / bad payload). The private key
    /// is never returned — only the signature. Returns the [`SignDecision`] taken, for the caller's
    /// audit log.
    ///
    /// Callbacks only arrive after attach, so the app pumps this once a session is live.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotASignCallback`] if the frame was not a `sign` request, or a transport/parse
    /// error.
    pub fn handle_next_sign_callback(&mut self) -> Result<SignDecision, SessionError> {
        let raw = self.transport.recv_frame()?;
        let frame: IncomingFrame = serde_json::from_str(&raw)?;
        match frame.method.as_deref() {
            Some(METHOD_SIGN) => self.service_sign_callback(frame),
            _ => Err(SessionError::NotASignCallback),
        }
    }

    /// Service a parsed `sign` callback frame: policy-gate, sign, and reply. Factored out so the read
    /// loop can also service callbacks that interleave with a pending handshake response.
    fn service_sign_callback(
        &mut self,
        frame: IncomingFrame,
    ) -> Result<SignDecision, SessionError> {
        let id = frame.id.clone().unwrap_or(serde_json::Value::Null);
        let params: SignCallbackParams =
            serde_json::from_value(frame.params.unwrap_or(serde_json::Value::Null))?;

        let payload = match BASE64.decode(params.payload_b64.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_error(
                    &id,
                    SIGN_BAD_PAYLOAD_CODE,
                    "sign payload is not valid base64",
                )?;
                return Ok(SignDecision::Deny("invalid base64 payload".to_string()));
            }
        };

        let decision = self.policy.authorize(&SignRequest {
            session_id: &params.session_id,
            op_id: &params.op_id,
            payload_type: &params.payload_type,
            payload: &payload,
            context: params.context.as_ref(),
        });

        match &decision {
            SignDecision::Allow => {
                // Sign the DOMAIN-SEPARATED, length-prefixed message — never the engine's raw bytes.
                // This is what closes the cross-protocol signing oracle: a malicious engine cannot
                // choose a `payload` that makes this signature verify as an attach challenge (or any
                // other identity-key signature), because the `DIGNET-SIGN-v1` tag can never equal the
                // `DIGNET-SESSION-v1` (or any other) tag those messages carry.
                match sign_callback_message(&params.payload_type, &payload) {
                    Some(message) => {
                        let signature = self.signer.sign(&message);
                        self.send_result(
                            &id,
                            SignCallbackResult {
                                signature_b64: BASE64.encode(signature),
                                pubkey_hex: self.signer.signing_public_key_hex(),
                            },
                        )?;
                    }
                    None => {
                        // A `payload_type` longer than u16::MAX cannot be length-prefixed
                        // unambiguously — reject rather than sign an ambiguous message.
                        self.send_error(
                            &id,
                            SIGN_BAD_PAYLOAD_CODE,
                            "sign payload_type exceeds the maximum length",
                        )?;
                        return Ok(SignDecision::Deny("payload_type too long".to_string()));
                    }
                }
            }
            SignDecision::Deny(reason) => {
                self.send_error(&id, SIGN_DENIED_CODE, reason)?;
            }
        }
        Ok(decision)
    }

    /// Send a JSON-RPC request and read its response, servicing any engine `sign` callback that
    /// interleaves before the response arrives (the connection is full-duplex). Returns the typed
    /// result, or [`SessionError::Engine`] if the engine answered with an error.
    fn call<Q: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: Q,
    ) -> Result<R, SessionError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = serde_json::to_string(&RpcRequest {
            jsonrpc: JSONRPC_VERSION,
            id,
            method,
            params,
        })?;
        self.transport.send_frame(&request)?;
        self.read_response(id)
    }

    /// Read frames until the response for `awaited_id` arrives, servicing interleaved `sign`
    /// callbacks along the way.
    fn read_response<R: for<'de> Deserialize<'de>>(
        &mut self,
        awaited_id: u64,
    ) -> Result<R, SessionError> {
        let mut callbacks_serviced = 0usize;
        loop {
            let raw = self.transport.recv_frame()?;
            let frame: IncomingFrame = serde_json::from_str(&raw)?;

            if frame.method.as_deref() == Some(METHOD_SIGN) {
                callbacks_serviced += 1;
                if callbacks_serviced > MAX_INTERLEAVED_CALLBACKS {
                    return Err(SessionError::TooManyCallbacks);
                }
                self.service_sign_callback(frame)?;
                continue;
            }

            if frame.id.as_ref().and_then(serde_json::Value::as_u64) != Some(awaited_id) {
                return Err(SessionError::IdMismatch);
            }
            if let Some(error) = frame.error {
                return Err(SessionError::Engine {
                    code: error.code,
                    message: error.message,
                });
            }
            let result = frame.result.ok_or(SessionError::MalformedResponse)?;
            return Ok(serde_json::from_value(result)?);
        }
    }

    /// Write a JSON-RPC success reply to an engine-initiated request.
    fn send_result<V: Serialize>(
        &mut self,
        id: &serde_json::Value,
        result: V,
    ) -> Result<(), SessionError> {
        let frame = serde_json::to_string(&RpcResult {
            jsonrpc: JSONRPC_VERSION,
            id,
            result,
        })?;
        self.transport.send_frame(&frame).map_err(SessionError::Io)
    }

    /// Write a JSON-RPC error reply to an engine-initiated request.
    fn send_error(
        &mut self,
        id: &serde_json::Value,
        code: i64,
        message: &str,
    ) -> Result<(), SessionError> {
        let frame = serde_json::to_string(&RpcErrorReply {
            jsonrpc: JSONRPC_VERSION,
            id,
            error: RpcError {
                code,
                message: message.to_string(),
            },
        })?;
        self.transport.send_frame(&frame).map_err(SessionError::Io)
    }
}

/// The app's map of live sessions, one per active profile — the multi-session awareness `SPEC.md`
/// §5 requires (fast-user-switching and concurrent profiles). Keyed by profile DID.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    by_did: HashMap<String, Session>,
}

impl SessionRegistry {
    /// A registry with no sessions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the live session for its profile DID.
    pub fn insert(&mut self, session: Session) {
        self.by_did.insert(session.profile_did.clone(), session);
    }

    /// The live session for `profile_did`, if one is attached.
    pub fn get(&self, profile_did: &str) -> Option<&Session> {
        self.by_did.get(profile_did)
    }

    /// Drop and return the session for `profile_did` (on detach / logout).
    pub fn remove(&mut self, profile_did: &str) -> Option<Session> {
        self.by_did.remove(profile_did)
    }

    /// How many sessions are currently attached.
    pub fn len(&self) -> usize {
        self.by_did.len()
    }

    /// Whether no session is attached.
    pub fn is_empty(&self) -> bool {
        self.by_did.is_empty()
    }
}

/// A trivially-permissive [`SignPolicy`] for tests and non-signing contexts. Production code MUST use
/// a real policy (confirmation / allowlist) — signing whatever the engine asks defeats the custody
/// gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllSignPolicy;

impl SignPolicy for AllowAllSignPolicy {
    fn authorize(&self, _request: &SignRequest<'_>) -> SignDecision {
        SignDecision::Allow
    }
}

/// A [`SignPolicy`] that refuses every engine `sign` callback — the safe default and a test double.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllSignPolicy;

impl SignPolicy for DenyAllSignPolicy {
    fn authorize(&self, _request: &SignRequest<'_>) -> SignDecision {
        SignDecision::Deny("signing is disabled by policy".to_string())
    }
}

const JSONRPC_VERSION: &str = "2.0";

// --- Wire shapes (JSON-RPC 2.0). Kept private: they are the on-wire encoding, not the public API. ---

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Serialize)]
struct RpcResult<'a, V: Serialize> {
    jsonrpc: &'static str,
    id: &'a serde_json::Value,
    result: V,
}

#[derive(Serialize)]
struct RpcErrorReply<'a> {
    jsonrpc: &'static str,
    id: &'a serde_json::Value,
    error: RpcError,
}

/// A frame arriving from the engine — either a response to an app request (`result`/`error` set) or
/// an engine-initiated request such as the `sign` callback (`method`/`params` set). Every field is
/// optional so one type parses both.
#[derive(Deserialize)]
struct IncomingFrame {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Serialize, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Serialize)]
struct BeginParams<'a> {
    profile_did: &'a str,
    signing_pubkey_hex: String,
}

#[derive(Deserialize)]
struct BeginResult {
    nonce_b64: String,
    session_candidate: String,
}

#[derive(Serialize)]
struct AttachParams<'a> {
    session_candidate: &'a str,
    signature_b64: String,
    profile: &'a ProfileAttachment,
}

#[derive(Deserialize)]
struct AttachResult {
    session_id: String,
    #[serde(default)]
    engine_capabilities: Vec<String>,
}

#[derive(Serialize)]
struct DetachParams<'a> {
    session_id: &'a str,
}

#[derive(Deserialize)]
struct DetachResult {}

#[derive(Deserialize)]
struct SignCallbackParams {
    session_id: String,
    op_id: String,
    payload_type: String,
    payload_b64: String,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct SignCallbackResult {
    signature_b64: String,
    pubkey_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::verify_signature;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;

    /// A scripted in-memory transport: `incoming` frames are what the engine "sends" (popped in
    /// order); `outgoing` records every frame the client sent, so tests can assert on the wire bytes.
    #[derive(Default)]
    struct FakeTransport {
        incoming: VecDeque<String>,
        outgoing: Vec<String>,
    }

    impl FakeTransport {
        fn scripted(frames: impl IntoIterator<Item = String>) -> Self {
            Self {
                incoming: frames.into_iter().collect(),
                outgoing: Vec::new(),
            }
        }
    }

    impl FrameTransport for FakeTransport {
        fn send_frame(&mut self, frame: &str) -> io::Result<()> {
            self.outgoing.push(frame.to_string());
            Ok(())
        }

        fn recv_frame(&mut self) -> io::Result<String> {
            self.incoming
                .pop_front()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    const DID: &str = "did:chia:testprofile";

    /// The scripted engine reply's nonce. Derived (not a literal) so it is unmistakably a test
    /// fixture — the production nonce is generated by the engine, never hard-coded.
    fn nonce() -> Vec<u8> {
        Sha256::digest(b"dig-app u6 session test nonce fixture").to_vec()
    }

    fn signer() -> IdentitySecrets {
        IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(42))
    }

    fn profile() -> ProfileAttachment {
        ProfileAttachment {
            did: DID.to_string(),
            subscriptions: vec!["store-a".to_string()],
            config_digest: "cfg-digest".to_string(),
        }
    }

    fn begin_frame(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"nonce_b64":"{}","session_candidate":"cand-1"}}}}"#,
            BASE64.encode(nonce())
        )
    }

    fn attach_frame(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"session_id":"sess-1","engine_capabilities":["content.serve","sync"]}}}}"#
        )
    }

    /// Reads the attach frame the client sent and returns the (challenge-verifying) outcome the engine
    /// would compute for `expected_pubkey`.
    fn attach_signature_verifies(outgoing: &str, expected_pubkey: &[u8; 32]) -> bool {
        let sent: serde_json::Value = serde_json::from_str(outgoing).unwrap();
        let sig_b64 = sent["params"]["signature_b64"].as_str().unwrap();
        let signature: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        verify_signature(
            expected_pubkey,
            &challenge_message(&nonce(), DID),
            &signature,
        )
    }

    #[test]
    fn challenge_is_domain_separated_and_deterministic() {
        let m = challenge_message(&nonce(), DID);
        assert!(m.starts_with(SESSION_CHALLENGE_DOMAIN));
        assert_eq!(m, challenge_message(&nonce(), DID));
        // A different nonce or DID yields a different challenge.
        assert_ne!(m, challenge_message(b"other-nonce", DID));
        assert_ne!(m, challenge_message(&nonce(), "did:chia:someoneelse"));
    }

    #[test]
    fn begin_then_attach_happy_path_opens_a_session() {
        let id = signer();
        let pubkey = id.signing_public_key();
        let transport = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, id, AllowAllSignPolicy);

        let session = client.begin_and_attach(profile()).unwrap();

        assert_eq!(session.session_id, "sess-1");
        assert_eq!(session.profile_did, DID);
        assert_eq!(session.engine_capabilities, ["content.serve", "sync"]);
        // The attach carried a signature over the domain-separated challenge, valid for our key.
        assert!(attach_signature_verifies(
            &client.transport.outgoing[1],
            &pubkey
        ));
    }

    #[test]
    fn attach_signature_is_rejected_for_a_foreign_key() {
        let id = signer();
        let stranger = IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(999));
        let transport = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, id, AllowAllSignPolicy);

        client.begin_and_attach(profile()).unwrap();

        // An engine verifying against the WRONG pubkey (a foreign identity) rejects the attach — the
        // signature binds the session to exactly the attaching key.
        assert!(!attach_signature_verifies(
            &client.transport.outgoing[1],
            &stranger.signing_public_key()
        ));
    }

    #[test]
    fn begin_propagates_an_engine_error() {
        let err = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown profile"}}"#;
        let transport = FakeTransport::scripted([err.to_string()]);
        let mut client = SessionClient::new(transport, signer(), AllowAllSignPolicy);

        match client.begin_and_attach(profile()) {
            Err(SessionError::Engine { code, message }) => {
                assert_eq!(code, -32000);
                assert_eq!(message, "unknown profile");
            }
            other => panic!("expected an engine error, got {other:?}"),
        }
    }

    #[test]
    fn sign_callback_returns_a_signature_without_exposing_the_key() {
        let id = signer();
        let pubkey = id.signing_public_key();
        let payload = b"spend-bundle-bytes";
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":77,"method":"sign","params":{{"session_id":"sess-1","op_id":"op-9","payload_type":"spend","payload_b64":"{}","context":{{"amount":5}}}}}}"#,
            BASE64.encode(payload)
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, id, AllowAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert_eq!(decision, SignDecision::Allow);

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["id"], 77);
        // The reply carries ONLY a signature + the public key — never the private key.
        let sig_b64 = reply["result"]["signature_b64"].as_str().unwrap();
        let signature: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        // The signature is over the DOMAIN-SEPARATED callback message, not the raw payload.
        let signed = sign_callback_message("spend", payload).unwrap();
        assert!(verify_signature(&pubkey, &signed, &signature));
        assert!(
            !verify_signature(&pubkey, payload, &signature),
            "the signature must NOT verify over the raw payload — it is domain-separated"
        );
        assert_eq!(reply["result"]["pubkey_hex"], hex::encode(pubkey));
        assert!(reply["result"].get("signing").is_none());
        assert!(reply["result"].get("private_key").is_none());
    }

    #[test]
    fn sign_callback_cannot_be_used_as_an_attach_signing_oracle() {
        // A malicious engine crafts a `sign` callback whose payload is BYTE-FOR-BYTE a valid attach
        // challenge (`DIGNET-SESSION-v1 ‖ nonce ‖ did`), hoping the returned signature can be replayed
        // to attach as this identity. Domain separation must defeat it: the produced signature must
        // NOT verify as an attach signature for (nonce, did).
        let id = signer();
        let pubkey = id.signing_public_key();
        let forged_payload = challenge_message(&nonce(), DID);
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":13,"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"spend","payload_b64":"{}"}}}}"#,
            BASE64.encode(&forged_payload)
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, id, AllowAllSignPolicy);

        client.handle_next_sign_callback().unwrap();

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        let sig_b64 = reply["result"]["signature_b64"].as_str().unwrap();
        let signature: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();

        // The oracle is closed: the callback signature is NOT a valid attach challenge signature.
        assert!(
            !verify_signature(&pubkey, &forged_payload, &signature),
            "cross-protocol signing oracle: a callback signature verified as an attach challenge"
        );
        // It IS a valid signature over the domain-separated callback message (proves it really signed).
        let signed = sign_callback_message("spend", &forged_payload).unwrap();
        assert!(verify_signature(&pubkey, &signed, &signature));
    }

    #[test]
    fn sign_callback_message_disambiguates_the_type_payload_boundary() {
        // Length-prefixing `payload_type` means (type="a", payload="bc") and (type="ab", payload="c")
        // hash to distinct messages, so their signatures can never be confused.
        let a = sign_callback_message("a", b"bc").unwrap();
        let b = sign_callback_message("ab", b"c").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(SIGN_CALLBACK_DOMAIN));
        // A callback message can never equal an attach challenge (different domain tags).
        assert!(!a.starts_with(SESSION_CHALLENGE_DOMAIN));
    }

    #[test]
    fn sign_callback_denied_by_policy_returns_an_error_and_no_signature() {
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":88,"method":"sign","params":{{"session_id":"sess-1","op_id":"op-1","payload_type":"spend","payload_b64":"{}"}}}}"#,
            BASE64.encode(b"anything")
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, signer(), DenyAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert!(matches!(decision, SignDecision::Deny(_)));

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["id"], 88);
        assert_eq!(reply["error"]["code"], SIGN_DENIED_CODE);
        assert!(reply.get("result").is_none());
    }

    #[test]
    fn sign_callback_with_a_bad_payload_returns_an_error() {
        let callback = r#"{"jsonrpc":"2.0","id":5,"method":"sign","params":{"session_id":"s","op_id":"o","payload_type":"spend","payload_b64":"not!!base64"}}"#;
        let transport = FakeTransport::scripted([callback.to_string()]);
        let mut client = SessionClient::new(transport, signer(), AllowAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert!(matches!(decision, SignDecision::Deny(_)));
        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["error"]["code"], SIGN_BAD_PAYLOAD_CODE);
    }

    #[test]
    fn handle_next_sign_callback_rejects_a_non_callback_frame() {
        let transport = FakeTransport::scripted([attach_frame(1)]);
        let mut client = SessionClient::new(transport, signer(), AllowAllSignPolicy);
        assert!(matches!(
            client.handle_next_sign_callback(),
            Err(SessionError::NotASignCallback)
        ));
    }

    #[test]
    fn a_sign_callback_interleaved_before_a_response_is_serviced() {
        // The engine sends a sign callback (id 500) before answering begin (id 1). The client must
        // service the callback and still resolve the begin response.
        let id = signer();
        let interleaved = format!(
            r#"{{"jsonrpc":"2.0","id":500,"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"t","payload_b64":"{}"}}}}"#,
            BASE64.encode(b"x")
        );
        let transport = FakeTransport::scripted([interleaved, begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, id, AllowAllSignPolicy);

        let session = client.begin_and_attach(profile()).unwrap();
        assert_eq!(session.session_id, "sess-1");
        // The interleaved callback was answered (a reply frame carrying id 500 was sent), even though
        // it arrived between the begin request and its response.
        let serviced_the_callback = client.transport.outgoing.iter().any(|frame| {
            serde_json::from_str::<serde_json::Value>(frame)
                .map(|v| v["id"] == 500 && v.get("result").is_some())
                .unwrap_or(false)
        });
        assert!(serviced_the_callback);
    }

    #[test]
    fn a_dropped_pipe_surfaces_as_an_io_error_then_reattach_recovers() {
        // First connection drops immediately (no frames → EOF on the first recv).
        let dropped = FakeTransport::default();
        let mut client = SessionClient::new(dropped, signer(), AllowAllSignPolicy);
        match client.begin_and_attach(profile()) {
            Err(SessionError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected an EOF I/O error, got {other:?}"),
        }

        // Reconnect with a fresh transport and re-run the handshake successfully.
        let fresh = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let session = client.reattach(fresh, profile()).unwrap();
        assert_eq!(session.session_id, "sess-1");
    }

    #[test]
    fn detach_sends_the_session_id() {
        let ack = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let transport = FakeTransport::scripted([ack.to_string()]);
        let mut client = SessionClient::new(transport, signer(), AllowAllSignPolicy);
        let session = Session {
            session_id: "sess-42".to_string(),
            engine_capabilities: vec![],
            profile_did: DID.to_string(),
        };

        client.detach(&session).unwrap();

        let sent: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(sent["method"], METHOD_DETACH);
        assert_eq!(sent["params"]["session_id"], "sess-42");
    }

    #[test]
    fn registry_tracks_one_session_per_profile() {
        let mut registry = SessionRegistry::new();
        assert!(registry.is_empty());

        let alice = Session {
            session_id: "a".to_string(),
            engine_capabilities: vec![],
            profile_did: "did:chia:alice".to_string(),
        };
        let bob = Session {
            session_id: "b".to_string(),
            engine_capabilities: vec![],
            profile_did: "did:chia:bob".to_string(),
        };
        registry.insert(alice.clone());
        registry.insert(bob);

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get("did:chia:alice"), Some(&alice));

        let removed = registry.remove("did:chia:bob").unwrap();
        assert_eq!(removed.session_id, "b");
        assert_eq!(registry.len(), 1);
        assert!(registry.get("did:chia:bob").is_none());
    }

    #[test]
    fn line_transport_round_trips_frames_over_a_byte_stream() {
        // Write two frames into an in-memory reader; assert framing splits them and the writer emits
        // newline-terminated frames.
        let reader = io::Cursor::new(b"{\"a\":1}\n{\"b\":2}\n".to_vec());
        let writer: Vec<u8> = Vec::new();
        let mut transport = LineTransport::new(reader, writer);

        assert_eq!(transport.recv_frame().unwrap(), r#"{"a":1}"#);
        assert_eq!(transport.recv_frame().unwrap(), r#"{"b":2}"#);
        assert_eq!(
            transport.recv_frame().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        transport.send_frame(r#"{"c":3}"#).unwrap();
        assert_eq!(transport.writer, b"{\"c\":3}\n");
    }

    #[test]
    fn line_transport_rejects_an_oversized_frame_instead_of_oom() {
        // A newline-less "frame" larger than the cap is rejected as InvalidData — the reader never
        // buffers unbounded bytes (we allocate the input, but recv_frame stops at the cap).
        let giant = vec![b'x'; (MAX_FRAME_BYTES + 16) as usize];
        let mut transport = LineTransport::new(io::Cursor::new(giant), Vec::<u8>::new());
        let err = transport.recv_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_response_gives_up_after_too_many_interleaved_callbacks() {
        // The engine floods sign callbacks and never answers begin. The client services up to the
        // cap, then bails with TooManyCallbacks rather than looping forever.
        let flood = (0..MAX_INTERLEAVED_CALLBACKS + 1).map(|i| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{i},"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"t","payload_b64":"{}"}}}}"#,
                BASE64.encode(b"x")
            )
        });
        let transport = FakeTransport::scripted(flood);
        let mut client = SessionClient::new(transport, signer(), AllowAllSignPolicy);
        assert!(matches!(
            client.begin_and_attach(profile()),
            Err(SessionError::TooManyCallbacks)
        ));
    }
}
