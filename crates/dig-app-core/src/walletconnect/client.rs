//! The live WalletConnect client: a websocket to the relay, wrapped in the synchronous
//! [`WalletConnectSurface`] the tray journeys call.
//!
//! The tray is a synchronous OS event loop and the relay is an async websocket, so something has to
//! bridge them. That something is here, on the same shape [`crate::sign_service::serve_blocking`]
//! already uses for the loopback listener: a dedicated current-thread tokio runtime, owned by this
//! client, driven with `block_on` from whichever thread the tray menu handler is on.
//!
//! # The shape of a connection, and why it is a state machine rather than one call
//!
//! WalletConnect pairing is two exchanges separated by a HUMAN, and the human is slow:
//!
//! 1. subscribe to the pairing topic from the `wc:` link, and wait for the dapp's
//!    `wc_sessionPropose`;
//! 2. *the person reads the proposal and decides*;
//! 3. answer the proposal on the pairing topic — sealed as a type-1 envelope, because the dapp
//!    cannot derive the session key without this wallet's X25519 public key — then publish
//!    `wc_sessionSettle` on the derived session topic and subscribe to it.
//!
//! So the websocket and the half-finished exchange have to survive across step 2, which is why this
//! client holds a [`Pending`] rather than doing the whole thing in one function. A design that
//! re-dialled at step 3 would lose the pairing subscription and, with it, the dapp's ability to hear
//! the answer.
//!
//! # What this module is NOT allowed to do
//!
//! It never touches the identity key. Signing is reached only through the
//! [`WcSigner`](super::request::WcSigner) seam, from [`super::request::handle_request`], and nothing
//! here calls dig-node. See the [module docs](super) for the whole custody boundary.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use x25519_dalek::StaticSecret;

use super::crypto;
use super::journey::{ProposalError, SessionProposal, WalletConnectSurface};
use super::relay::{
    self, RelayConfig, TAG_SESSION_DELETE, TAG_SESSION_PROPOSE_RESPONSE, TAG_SESSION_SETTLE,
    TTL_SESSION_MESSAGE, TTL_SESSION_RESPONSE,
};
use super::request::{CHIA_NAMESPACE, SUPPORTED_EVENTS};
use super::session::{DappMetadata, DisconnectOutcome, WcSession, SESSION_TTL_SECS};
use super::uri::WcUri;

/// How long the wallet waits for a dapp to send its proposal after the link is pasted.
///
/// Thirty seconds. The dapp has usually already sent it — the relay holds messages, so the proposal
/// is typically waiting the instant the subscription lands — and the wait exists for the case where
/// the person pasted the link before the dapp finished publishing. Much longer would leave the tray
/// menu handler blocked on a link that was stale before it was pasted.
pub const PROPOSAL_WAIT: Duration = Duration::from_secs(30);

/// How long any single relay round trip may take.
const RELAY_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest relay frame this client will read.
///
/// WalletConnect frames are small — a proposal with metadata and icon URLs is a few kilobytes — and
/// the relay is an untrusted intermediary that can send whatever it likes. Without a bound, a
/// hostile or broken relay can grow the tray process's memory without limit by streaming one frame.
/// A megabyte is far above any legitimate frame and far below anything that matters.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A proposal that has been read and not yet answered, plus everything needed to answer it.
struct Pending {
    proposal: SessionProposal,
    /// The pairing key the response is sealed under. The proposal arrived under it, and the
    /// response must go back under it — the session key does not exist for the dapp yet.
    pairing_key: [u8; crypto::KEY_LEN],
    /// The dapp's X25519 public key, taken from the proposal.
    peer_public_key: [u8; crypto::KEY_LEN],
}

/// The live client.
///
/// Generic over nothing: the session store, confirmer and signer are reached through the surface's
/// caller rather than held here, which keeps this type about the TRANSPORT and leaves custody in
/// [`super::request`].
pub struct WcClient {
    config: RelayConfig,
    runtime: tokio::runtime::Runtime,
    /// The open websocket, if one is up. Re-dialled on demand rather than held open indefinitely:
    /// the tray spends almost all its life with no pairing in flight, and an idle socket to a public
    /// relay is a standing statement that this wallet exists.
    socket: Mutex<Option<Socket>>,
    pending: Mutex<Option<Pending>>,
    /// Monotonic relay request ids. WalletConnect ids are conventionally microsecond-ish integers;
    /// a counter is sufficient because they only need to be unique within this connection.
    next_id: Mutex<u64>,
    /// The sessions this client believes are live, so [`list`](WalletConnectSurface::list) can
    /// answer without a round trip. Shared with the caller's store through an `Arc`.
    sessions: Arc<Mutex<Vec<WcSession>>>,
}

impl WcClient {
    /// Build a client over `config`.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if a tokio runtime cannot be built.
    pub fn new(config: RelayConfig) -> std::io::Result<Self> {
        Ok(Self {
            config,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            socket: Mutex::new(None),
            pending: Mutex::new(None),
            next_id: Mutex::new(1),
            sessions: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Seed the client with sessions restored from disk at start-up.
    pub fn restore(&self, sessions: Vec<WcSession>) {
        *self.sessions.lock().unwrap_or_else(|e| e.into_inner()) = sessions;
    }

    fn id(&self) -> u64 {
        let mut next = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        *next
    }

    /// Dial the relay, replacing any existing socket.
    async fn dial(&self) -> Result<Socket, RelayFault> {
        let jwt = relay::mint_auth_jwt(
            &relay::new_auth_key(),
            &self.config.url,
            &hex::encode(rand_topic()),
            relay::now_secs(),
        );
        let url = self
            .config
            .dial_url(&jwt)
            .map_err(|_| RelayFault::NotConfigured)?;
        let (socket, _) = tokio::time::timeout(RELAY_TIMEOUT, tokio_tungstenite::connect_async(url))
            .await
            .map_err(|_| RelayFault::Unreachable("the relay did not answer in time".into()))?
            .map_err(|e| RelayFault::Unreachable(e.to_string()))?;
        Ok(socket)
    }
}

/// A transport-level failure, mapped to [`ProposalError`] at the surface boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayFault {
    NotConfigured,
    Unreachable(String),
    NoProposal,
    Protocol(String),
}

impl From<RelayFault> for ProposalError {
    fn from(fault: RelayFault) -> Self {
        match fault {
            RelayFault::NotConfigured => Self::NotConfigured,
            RelayFault::Unreachable(why) => Self::Unreachable(why),
            RelayFault::NoProposal => Self::NoProposal,
            // A relay speaking something this client cannot parse is, from the person's side, a
            // relay that could not be used. The detail goes in the message rather than into a
            // variant nothing would render differently.
            RelayFault::Protocol(why) => Self::Unreachable(why),
        }
    }
}

/// Send one frame.
async fn send(socket: &mut Socket, frame: &Value) -> Result<(), RelayFault> {
    socket
        .send(Message::Text(frame.to_string()))
        .await
        .map_err(|e| RelayFault::Unreachable(e.to_string()))
}

/// Read frames until one satisfies `want`, or `deadline` passes.
///
/// Frames that are not wanted are ACKNOWLEDGED and dropped rather than treated as errors: the relay
/// interleaves its own acknowledgements with deliveries, and a reader that stopped at the first
/// unexpected frame would never see past them.
async fn read_until<T>(
    socket: &mut Socket,
    deadline: Duration,
    mut want: impl FnMut(&Value) -> Option<T>,
) -> Result<T, RelayFault> {
    let deadline = tokio::time::Instant::now() + deadline;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(RelayFault::NoProposal);
        }
        let message = tokio::time::timeout(remaining, socket.next())
            .await
            .map_err(|_| RelayFault::NoProposal)?
            .ok_or_else(|| RelayFault::Unreachable("the relay closed the connection".into()))?
            .map_err(|e| RelayFault::Unreachable(e.to_string()))?;

        let text = match message {
            Message::Text(text) => text,
            // Binary, ping and close frames are not relay JSON-RPC. Ping/pong is handled by the
            // library; anything else is ignored rather than fatal.
            Message::Close(_) => {
                return Err(RelayFault::Unreachable("the relay closed the connection".into()))
            }
            _ => continue,
        };
        if text.len() > MAX_FRAME_BYTES {
            return Err(RelayFault::Protocol(
                "the relay sent an implausibly large frame".into(),
            ));
        }
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            // A relay that sends non-JSON is broken, but one bad frame is not a reason to abandon a
            // connection that may still deliver the proposal.
            continue;
        };
        if let Some(found) = want(&frame) {
            return Ok(found);
        }
        if let Some(delivery) = relay::read_delivery(&frame) {
            let _ = send(socket, &relay::ack_frame(delivery.id)).await;
        }
    }
}

/// Read a `wc_sessionPropose` out of an opened envelope.
///
/// Every field is taken defensively: this is a stranger's JSON, arriving before any human has
/// approved anything.
fn parse_propose(plaintext: &str) -> Option<(u64, [u8; crypto::KEY_LEN], SessionProposal)> {
    let frame: Value = serde_json::from_str(plaintext).ok()?;
    if frame.get("method")?.as_str()? != "wc_sessionPropose" {
        return None;
    }
    let request_id = frame.get("id")?.as_u64()?;
    let params = frame.get("params")?;

    let mut peer_public_key = [0u8; crypto::KEY_LEN];
    let proposer_key = params.get("proposer")?.get("publicKey")?.as_str()?;
    hex::decode_to_slice(proposer_key, &mut peer_public_key).ok()?;

    let metadata = params.get("proposer")?.get("metadata");
    let peer = DappMetadata {
        name: string_at(metadata, "name"),
        description: string_at(metadata, "description"),
        url: string_at(metadata, "url"),
        icons: metadata
            .and_then(|m| m.get("icons"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
    };

    // Both `requiredNamespaces` and `optionalNamespaces` are read, because a dapp may put the Chia
    // methods in either and a wallet that read only one would settle an empty session against a
    // perfectly ordinary proposal.
    let mut chains = Vec::new();
    let mut requested_methods = Vec::new();
    for key in ["requiredNamespaces", "optionalNamespaces"] {
        let Some(namespace) = params.get(key).and_then(|n| n.get(CHIA_NAMESPACE)) else {
            continue;
        };
        collect_strings(namespace.get("chains"), &mut chains);
        collect_strings(namespace.get("methods"), &mut requested_methods);
    }
    requested_methods.sort();
    requested_methods.dedup();
    chains.sort();
    chains.dedup();

    Some((
        request_id,
        peer_public_key,
        SessionProposal {
            request_id,
            pairing_topic: String::new(),
            peer,
            chains,
            requested_methods,
        },
    ))
}

fn string_at(value: Option<&Value>, key: &str) -> String {
    value
        .and_then(|v| v.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn collect_strings(value: Option<&Value>, into: &mut Vec<String>) {
    let Some(array) = value.and_then(Value::as_array) else {
        return;
    };
    into.extend(array.iter().filter_map(|v| v.as_str().map(str::to_string)));
}

/// Build the `wc_sessionSettle` params for an approved proposal.
///
/// Split out from the async flow so the shape a dapp actually receives — the namespace, the methods,
/// the accounts, the expiry — is checkable without a relay.
pub fn settle_params(
    session: &WcSession,
    wallet_public_key: &[u8; crypto::KEY_LEN],
    metadata: &DappMetadata,
) -> Value {
    json!({
        "relay": { "protocol": "irn" },
        "controller": {
            "publicKey": hex::encode(wallet_public_key),
            "metadata": {
                "name": metadata.name,
                "description": metadata.description,
                "url": metadata.url,
                "icons": metadata.icons,
            },
        },
        "namespaces": {
            CHIA_NAMESPACE: {
                "chains": session.chains,
                "accounts": session.accounts,
                "methods": session.methods,
                "events": SUPPORTED_EVENTS,
            },
        },
        "expiry": session.expires_at,
    })
}

/// This wallet's own metadata, as a dapp sees it in the settle.
pub fn wallet_metadata() -> DappMetadata {
    DappMetadata {
        name: "DIG".to_string(),
        description: "The DIG Network identity app".to_string(),
        url: "https://dig.net".to_string(),
        icons: Vec::new(),
    }
}

/// A random 32-byte value, hex-encoded by the caller. Used for the JWT subject, which the relay
/// treats as an opaque per-connection nonce.
fn rand_topic() -> [u8; 32] {
    use rand_core::RngCore;
    let mut out = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut out);
    out
}

impl WalletConnectSurface for WcClient {
    fn is_configured(&self) -> bool {
        self.config.is_usable()
    }

    fn propose(&self, uri: &WcUri) -> Result<SessionProposal, ProposalError> {
        if !self.is_configured() {
            return Err(ProposalError::NotConfigured);
        }
        let outcome: Result<(SessionProposal, Pending, Socket), RelayFault> =
            self.runtime.block_on(async {
                let mut socket = self.dial().await?;
                send(&mut socket, &relay::subscribe_frame(self.id(), &uri.topic)).await?;

                let key = uri.sym_key;
                let topic = uri.topic.clone();
                let (request_id, peer_public_key, mut proposal) =
                    read_until(&mut socket, PROPOSAL_WAIT, |frame| {
                        let delivery = relay::read_delivery(frame)?;
                        if delivery.topic != topic {
                            return None;
                        }
                        let opened = crypto::open(&key, &delivery.message).ok()?;
                        parse_propose(&opened.plaintext)
                    })
                    .await?;
                proposal.pairing_topic = uri.topic.clone();
                let _ = request_id;
                Ok((
                    proposal.clone(),
                    Pending {
                        proposal,
                        pairing_key: uri.sym_key,
                        peer_public_key,
                    },
                    socket,
                ))
            });

        let (proposal, pending, socket) = outcome?;
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
        *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(socket);
        Ok(proposal)
    }

    fn approve(&self, proposal: SessionProposal) -> Result<WcSession, ProposalError> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(ProposalError::NoProposal)?;
        let mut socket = self
            .socket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(ProposalError::NoProposal)?;

        let (secret, wallet_public) = crypto::new_keypair();
        let session_key = crypto::derive_session_key(&secret, &pending.peer_public_key);
        let session_topic = crypto::topic_of(&session_key);
        let now = relay::now_secs();

        let session = WcSession {
            topic: session_topic.clone(),
            sym_key_hex: hex::encode(session_key),
            // Stamped by the store on settle; this value is a placeholder the store overwrites.
            profile_did: String::new(),
            peer: proposal.peer.clone(),
            chains: proposal.chains.clone(),
            methods: proposal.settled_methods(),
            accounts: Vec::new(),
            connected_at: now,
            expires_at: now + SESSION_TTL_SECS,
        };

        let result: Result<(), RelayFault> = self.runtime.block_on(async {
            // 1. Answer the proposal on the PAIRING topic, as a type-1 envelope so the dapp learns
            //    this wallet's public key and can derive the same session key.
            let response = json!({
                "id": pending.proposal.request_id,
                "jsonrpc": "2.0",
                "result": {
                    "relay": { "protocol": "irn" },
                    "responderPublicKey": hex::encode(wallet_public),
                },
            });
            let sealed = crypto::seal_type1(
                &pending.pairing_key,
                &wallet_public,
                &response.to_string(),
            );
            send(
                &mut socket,
                &relay::publish_frame(
                    self.id(),
                    &pending.proposal.pairing_topic,
                    &sealed,
                    TAG_SESSION_PROPOSE_RESPONSE,
                    TTL_SESSION_RESPONSE,
                ),
            )
            .await?;

            // 2. Subscribe to the session topic BEFORE settling on it, so a dapp that answers
            //    instantly is not answering into a topic nothing is listening to.
            send(
                &mut socket,
                &relay::subscribe_frame(self.id(), &session_topic),
            )
            .await?;

            // 3. Settle.
            let settle = json!({
                "id": self.id(),
                "jsonrpc": "2.0",
                "method": "wc_sessionSettle",
                "params": settle_params(&session, &wallet_public, &wallet_metadata()),
            });
            let sealed = crypto::seal_type0(&session_key, &settle.to_string());
            send(
                &mut socket,
                &relay::publish_frame(
                    self.id(),
                    &session_topic,
                    &sealed,
                    TAG_SESSION_SETTLE,
                    TTL_SESSION_MESSAGE,
                ),
            )
            .await?;
            Ok(())
        });
        result?;

        *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(socket);
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(session.clone());
        Ok(session)
    }

    fn reject(&self, proposal: SessionProposal) {
        let Some(pending) = self.pending.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        let Some(mut socket) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        // Best effort, and deliberately so: the person has already declined, and the local decision
        // stands whether or not the dapp hears about it. Failing to tell them is a worse experience,
        // never a weaker one.
        let _ = self.runtime.block_on(async {
            let response = json!({
                "id": proposal.request_id,
                "jsonrpc": "2.0",
                "error": { "code": 5000, "message": "the connection was declined" },
            });
            let sealed = crypto::seal_type0(&pending.pairing_key, &response.to_string());
            send(
                &mut socket,
                &relay::publish_frame(
                    self.id(),
                    &proposal.pairing_topic,
                    &sealed,
                    TAG_SESSION_PROPOSE_RESPONSE,
                    TTL_SESSION_RESPONSE,
                ),
            )
            .await
        });
    }

    fn list(&self) -> Vec<WcSession> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn disconnect(&self, topic: &str) -> DisconnectOutcome {
        let session = {
            let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let Some(index) = all.iter().position(|s| s.topic == topic) else {
                return DisconnectOutcome::NotFound;
            };
            all.remove(index)
        };

        // Telling the dapp is best effort for the same reason rejecting is: the person asked to
        // disconnect, and that has happened locally regardless of whether the relay was reachable.
        // Reporting failure here would invite them to retry an action that already took effect.
        let mut key = [0u8; crypto::KEY_LEN];
        if hex::decode_to_slice(&session.sym_key_hex, &mut key).is_ok() {
            if let Some(mut socket) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = self.runtime.block_on(async {
                    let delete = json!({
                        "id": self.id(),
                        "jsonrpc": "2.0",
                        "method": "wc_sessionDelete",
                        "params": { "code": 6000, "message": "disconnected by the user" },
                    });
                    let sealed = crypto::seal_type0(&key, &delete.to_string());
                    send(
                        &mut socket,
                        &relay::publish_frame(
                            self.id(),
                            topic,
                            &sealed,
                            TAG_SESSION_DELETE,
                            TTL_SESSION_MESSAGE,
                        ),
                    )
                    .await
                });
            }
        }
        DisconnectOutcome::Disconnected
    }
}
