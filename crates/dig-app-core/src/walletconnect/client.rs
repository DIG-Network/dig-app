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
/// the relay is an untrusted intermediary that can send whatever it likes. A megabyte is far above
/// any legitimate frame and far below anything that matters.
///
/// # Where this is enforced, and why the obvious place is the wrong one
///
/// It is given to the websocket library through [`socket_config`], so tungstenite refuses an
/// oversized message while READING it. Checking `text.len()` after `next()` returns — which is the
/// natural-looking place — is too late by construction: the message has already been assembled in
/// memory, so the check reports the allocation it was meant to prevent. tungstenite's own default
/// ceiling is 64 MiB, so the post-hoc form would have let a hostile relay force a 64 MiB allocation
/// in the tray process on demand. The length check below the read is kept as defence in depth,
/// where it costs nothing.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The websocket limits this client dials with.
///
/// Both ceilings are set: `max_message_size` bounds a whole message and `max_frame_size` bounds one
/// websocket frame, and a message can be split across many frames — so bounding only the message
/// still permits a stream of frames the library must buffer to reassemble it.
fn socket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..Default::default()
    }
}

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
        let (socket, _) = tokio::time::timeout(
            RELAY_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(url, Some(socket_config()), false),
        )
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
                return Err(RelayFault::Unreachable(
                    "the relay closed the connection".into(),
                ))
            }
            _ => continue,
        };
        // Defence in depth: `socket_config` already made an oversized message a read ERROR above,
        // so reaching this is either a library change or a frame that arrived by another path.
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
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
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
            let sealed =
                crypto::seal_type1(&pending.pairing_key, &wallet_public, &response.to_string());
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
        let Some(pending) = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::request::SUPPORTED_METHODS;

    const NOW: u64 = 1_800_000_000;

    /// A proposal shaped as `@walletconnect/sign-client` emits one.
    fn propose_json(namespace_key: &str) -> String {
        json!({
            "id": 1_699_999_999_000_001u64,
            "jsonrpc": "2.0",
            "method": "wc_sessionPropose",
            "params": {
                "requiredNamespaces": {},
                namespace_key: {
                    CHIA_NAMESPACE: {
                        "chains": ["chia:mainnet"],
                        "methods": ["chip0002_connect", "chip0002_signMessage"],
                        "events": ["accountsChanged"],
                    },
                },
                "relays": [{ "protocol": "irn" }],
                "proposer": {
                    "publicKey": "cd".repeat(32),
                    "metadata": {
                        "name": "Example Dapp",
                        "description": "An example",
                        "url": "https://dapp.example",
                        "icons": ["https://dapp.example/icon.png"],
                    },
                },
            },
        })
        .to_string()
    }

    #[test]
    fn a_well_formed_proposal_is_read_in_full() {
        let (id, peer_key, proposal) =
            parse_propose(&propose_json("optionalNamespaces")).expect("parses");
        assert_eq!(id, 1_699_999_999_000_001);
        assert_eq!(peer_key, [0xcdu8; 32]);
        assert_eq!(proposal.peer.name, "Example Dapp");
        assert_eq!(proposal.peer.url, "https://dapp.example");
        assert_eq!(proposal.peer.icons, vec!["https://dapp.example/icon.png"]);
        assert_eq!(proposal.chains, vec!["chia:mainnet"]);
        assert_eq!(
            proposal.requested_methods,
            vec!["chip0002_connect", "chip0002_signMessage"]
        );
    }

    /// A dapp may put the Chia methods in EITHER namespace map. A wallet reading only one settles an
    /// empty session against a perfectly ordinary proposal, and the person then sees a connection
    /// granting nothing with no explanation — so both are asserted, not just the common one.
    #[test]
    fn a_proposal_is_read_from_either_namespace_map() {
        for key in ["requiredNamespaces", "optionalNamespaces"] {
            let (_, _, proposal) = parse_propose(&propose_json(key)).expect(key);
            assert!(
                proposal
                    .requested_methods
                    .contains(&"chip0002_signMessage".to_string()),
                "methods were not read from {key}"
            );
        }
    }

    /// Methods present in BOTH maps are listed once, or the consent window shows the same capability
    /// twice and reads as a rendering fault.
    #[test]
    fn methods_present_in_both_maps_are_listed_once() {
        let both = json!({
            "id": 1u64,
            "method": "wc_sessionPropose",
            "params": {
                "requiredNamespaces": { CHIA_NAMESPACE: {
                    "chains": ["chia:mainnet"], "methods": ["chip0002_connect"] } },
                "optionalNamespaces": { CHIA_NAMESPACE: {
                    "chains": ["chia:mainnet"], "methods": ["chip0002_connect"] } },
                "proposer": { "publicKey": "cd".repeat(32) },
            },
        })
        .to_string();
        let (_, _, proposal) = parse_propose(&both).unwrap();
        assert_eq!(proposal.requested_methods, vec!["chip0002_connect"]);
        assert_eq!(proposal.chains, vec!["chia:mainnet"]);
    }

    /// Every case below is a stranger's JSON arriving BEFORE any human has approved anything, so
    /// each must be refused rather than panicking the tray process. The proposer key is the sharp
    /// one: it is decoded into a fixed 32-byte buffer, where a length assumption is a crash.
    #[test]
    fn every_malformed_proposal_is_refused_without_panicking() {
        let short_key =
            json!({ "id": 1, "method": "wc_sessionPropose", "params": { "proposer": { "publicKey": "cd" } } })
                .to_string();
        let long_key = json!({ "id": 1, "method": "wc_sessionPropose", "params": { "proposer": { "publicKey": "cd".repeat(64) } } })
            .to_string();
        let non_hex = json!({ "id": 1, "method": "wc_sessionPropose", "params": { "proposer": { "publicKey": "zz".repeat(32) } } })
            .to_string();
        let wrong_type = json!({ "id": 1, "method": "wc_sessionPropose", "params": { "proposer": { "publicKey": 7 } } })
            .to_string();
        let other_method =
            json!({ "id": 1, "method": "wc_sessionSettle", "params": {} }).to_string();
        let no_method = json!({ "id": 1, "params": {} }).to_string();
        let no_id = json!({ "method": "wc_sessionPropose", "params": { "proposer": { "publicKey": "cd".repeat(32) } } })
            .to_string();
        let no_proposer =
            json!({ "id": 1, "method": "wc_sessionPropose", "params": {} }).to_string();

        for (what, raw) in [
            ("not json at all", "garbage"),
            ("an empty string", ""),
            ("a different method", other_method.as_str()),
            ("no method", no_method.as_str()),
            ("no id", no_id.as_str()),
            ("no proposer", no_proposer.as_str()),
            ("a short proposer key", short_key.as_str()),
            ("an over-long proposer key", long_key.as_str()),
            ("a non-hex proposer key", non_hex.as_str()),
            ("a numeric proposer key", wrong_type.as_str()),
        ] {
            assert!(parse_propose(raw).is_none(), "accepted {what}");
        }
    }

    /// A proposal with NO metadata is legal and must still parse — the dapp simply said nothing
    /// about itself, and the consent window has its own words for that. Refusing here would make an
    /// anonymous dapp indistinguishable from a malformed one.
    #[test]
    fn a_proposal_without_metadata_still_parses() {
        let bare = json!({
            "id": 5u64,
            "method": "wc_sessionPropose",
            "params": { "proposer": { "publicKey": "cd".repeat(32) } },
        })
        .to_string();
        let (_, _, proposal) = parse_propose(&bare).expect("an anonymous dapp is not a broken one");
        assert!(proposal.peer.name.is_empty());
        assert!(proposal.peer.url.is_empty());
        assert!(proposal.requested_methods.is_empty());
    }

    /// Metadata of the WRONG TYPE degrades rather than failing: it is the dapp describing itself,
    /// and a number where a name belongs is odd, not hostile.
    #[test]
    fn metadata_of_the_wrong_type_degrades_to_empty() {
        let odd = json!({
            "id": 5u64,
            "method": "wc_sessionPropose",
            "params": {
                "proposer": {
                    "publicKey": "cd".repeat(32),
                    "metadata": { "name": 42, "url": ["a"], "icons": "not-an-array" },
                },
            },
        })
        .to_string();
        let (_, _, proposal) = parse_propose(&odd).expect("parses");
        assert!(proposal.peer.name.is_empty());
        assert!(proposal.peer.url.is_empty());
        assert!(proposal.peer.icons.is_empty());
    }

    fn settled_session() -> WcSession {
        WcSession {
            topic: "aa".repeat(32),
            sym_key_hex: "bb".repeat(32),
            profile_did: "did:chia:me".into(),
            peer: DappMetadata::default(),
            chains: vec!["chia:mainnet".into()],
            methods: vec!["chip0002_connect".into(), "chip0002_signMessage".into()],
            accounts: vec!["chia:mainnet:xch1abc".into()],
            connected_at: NOW,
            expires_at: NOW + SESSION_TTL_SECS,
        }
    }

    /// The settle is the moment the wallet states ON THE WIRE what it will honour, and a dapp reads
    /// each field. Asserted field by field, because a wrong namespace key or a missing expiry is
    /// invisible until a real dapp silently refuses the session.
    #[test]
    fn the_settle_states_the_namespace_the_methods_and_the_expiry() {
        let session = settled_session();
        let params = settle_params(&session, &[0x11u8; 32], &wallet_metadata());

        assert_eq!(params["relay"]["protocol"], "irn");
        assert_eq!(params["controller"]["publicKey"], "11".repeat(32));
        assert_eq!(params["controller"]["metadata"]["name"], "DIG");

        let namespace = &params["namespaces"][CHIA_NAMESPACE];
        assert_eq!(namespace["chains"], json!(["chia:mainnet"]));
        assert_eq!(namespace["accounts"], json!(["chia:mainnet:xch1abc"]));
        assert_eq!(
            namespace["methods"],
            json!(["chip0002_connect", "chip0002_signMessage"]),
            "the settle must advertise the SESSION methods, not the whole catalogue"
        );
        assert_eq!(namespace["events"], json!(SUPPORTED_EVENTS));
        assert_eq!(params["expiry"], NOW + SESSION_TTL_SECS);
    }

    /// A wallet advertising its full catalogue would widen the session past the proposal the person
    /// approved. The fixture is a session holding strictly FEWER methods than the wallet supports —
    /// the only shape that can tell the two apart.
    #[test]
    fn the_settle_never_advertises_more_than_the_session_settled() {
        let narrow = WcSession {
            methods: vec!["chip0002_connect".into()],
            ..settled_session()
        };
        assert!(
            SUPPORTED_METHODS.len() > narrow.methods.len(),
            "the fixture is meaningful only while the wallet supports more than this session did"
        );
        let params = settle_params(&narrow, &[0u8; 32], &wallet_metadata());
        assert_eq!(
            params["namespaces"][CHIA_NAMESPACE]["methods"],
            json!(["chip0002_connect"])
        );
    }

    #[test]
    fn a_client_without_a_project_id_reports_itself_unconfigured() {
        let client = WcClient::new(RelayConfig::default()).expect("builds");
        assert!(!client.is_configured());
        let uri = WcUri::parse(&format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .unwrap();
        assert_eq!(client.propose(&uri), Err(ProposalError::NotConfigured));
    }

    /// Approving with nothing pending must refuse rather than fabricate a session. Reachable in
    /// practice: a proposal that timed out, or a second approval of one already settled.
    #[test]
    fn approving_without_a_pending_proposal_settles_nothing() {
        let client = WcClient::new(RelayConfig::default()).expect("builds");
        let proposal = SessionProposal {
            request_id: 1,
            pairing_topic: "a".repeat(64),
            peer: DappMetadata::default(),
            chains: Vec::new(),
            requested_methods: Vec::new(),
        };
        assert_eq!(client.approve(proposal), Err(ProposalError::NoProposal));
        assert!(client.list().is_empty());
    }

    #[test]
    fn disconnecting_a_session_the_client_does_not_hold_reports_not_found() {
        let client = WcClient::new(RelayConfig::default()).expect("builds");
        assert_eq!(client.disconnect("nope"), DisconnectOutcome::NotFound);
    }

    /// Two sessions, so a removal that cleared the whole list is distinguishable from one that
    /// removed the named row.
    #[test]
    fn restored_sessions_are_listed_and_disconnect_removes_only_the_named_one() {
        let client = WcClient::new(RelayConfig::default()).expect("builds");
        let a = settled_session();
        let b = WcSession {
            topic: "cc".repeat(32),
            ..settled_session()
        };
        client.restore(vec![a.clone(), b.clone()]);
        assert_eq!(client.list().len(), 2);
        assert_eq!(client.disconnect(&a.topic), DisconnectOutcome::Disconnected);
        let left: Vec<String> = client.list().into_iter().map(|s| s.topic).collect();
        assert_eq!(left, vec![b.topic]);
    }

    /// The frame bound exists because the relay is untrusted and can stream without limit. Pinned as
    /// a value, and sanity-checked against a real frame, so a change to either side is visible.
    #[test]
    fn the_frame_bound_is_far_above_a_real_frame() {
        assert_eq!(MAX_FRAME_BYTES, 1024 * 1024);
        assert!(propose_json("optionalNamespaces").len() < MAX_FRAME_BYTES / 100);
    }

    /// The bound has to reach the WEBSOCKET, not merely exist as a constant the reader checks after
    /// the fact.
    ///
    /// This is the assertion that distinguishes the two placements. A `text.len()` check after
    /// `next()` returns satisfies every outcome-shaped test identically — an oversized frame is
    /// refused either way — while having already allocated the message it refused. Only the config
    /// can show WHERE the refusal happens, so the config is what is asserted.
    ///
    /// Both ceilings are checked: a message can be split across frames, so bounding the message
    /// alone still lets the library buffer a stream of frames to reassemble it.
    #[test]
    fn the_frame_bound_is_given_to_the_websocket_rather_than_checked_afterwards() {
        let config = socket_config();
        assert_eq!(
            config.max_message_size,
            Some(MAX_FRAME_BYTES),
            "an unset message ceiling leaves tungstenite's 64 MiB default in force"
        );
        assert_eq!(
            config.max_frame_size,
            Some(MAX_FRAME_BYTES),
            "bounding the message but not the frame still permits a reassembly buffer"
        );
    }

    /// The relay subject is a per-connection nonce. Two connections presenting the same one would
    /// let a relay operator link them.
    #[test]
    fn each_connection_presents_a_different_relay_subject() {
        assert_ne!(rand_topic(), rand_topic());
    }
}

/// Tests that put a REAL websocket under the reader, rather than a hand-shaped double.
///
/// The relay is an untrusted intermediary, and every property here is about how this client behaves
/// when the thing on the other end misbehaves. A double built from the same assumptions as the code
/// cannot see a wrong assumption; a genuine socket can, because the websocket library sits in
/// between and enforces limits a double would simply agree to.
#[cfg(test)]
mod relay_socket_tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Start a websocket server on loopback running `serve` against the accepted connection, and
    /// return the URL to dial.
    ///
    /// IPv4 loopback specifically. This is a test fixture rather than peer networking, so the
    /// ecosystem IPv6-first rule does not apply, and some CI hosts have no loopback IPv6.
    async fn serve_one<F, Fut>(serve: F) -> String
    where
        F: FnOnce(WebSocketStream<tokio::net::TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accepts");
            let socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("upgrades");
            serve(socket).await;
        });
        format!("ws://127.0.0.1:{port}")
    }

    /// Dial with the SAME config production dials with, so these tests exercise the real limits
    /// rather than a permissive test-only socket.
    async fn dial(url: &str) -> Socket {
        let (socket, _) =
            tokio_tungstenite::connect_async_with_config(url, Some(socket_config()), false)
                .await
                .expect("connects");
        socket
    }

    fn delivery_frame(id: u64, topic: &str, message: &str) -> String {
        json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": topic, "message": message } },
        })
        .to_string()
    }

    /// The control for every test below: an ordinary delivery is read off a real socket.
    ///
    /// Without it, a reader that never returned anything at all would satisfy each negative test
    /// just as well as a correct one does.
    #[tokio::test]
    async fn a_delivery_is_read_from_a_real_socket() {
        let url = serve_one(|mut server| async move {
            server
                .send(Message::Text(delivery_frame(1, "topic-a", "SEALED")))
                .await
                .expect("sends");
            // Held open, so the client is not racing a close.
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let found = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery)
            .await
            .expect("reads the delivery");
        assert_eq!(found.topic, "topic-a");
        assert_eq!(found.message, "SEALED");
    }

    /// Relay acknowledgements and unknown methods are interleaved with deliveries, so the wanted one
    /// is placed BEHIND two frames the reader must skip. A reader that stopped at the first
    /// unexpected frame never sees past them.
    #[tokio::test]
    async fn frames_that_are_not_the_wanted_one_are_skipped_rather_than_ending_the_read() {
        let url = serve_one(|mut server| async move {
            for frame in [
                json!({ "id": 1, "jsonrpc": "2.0", "result": true }).to_string(),
                json!({ "id": 2, "jsonrpc": "2.0", "method": "irn_somethingNew", "params": {} })
                    .to_string(),
                delivery_frame(3, "topic-b", "WANTED"),
            ] {
                server.send(Message::Text(frame)).await.expect("sends");
            }
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let found = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery)
            .await
            .expect("reads past the noise");
        assert_eq!(found.message, "WANTED");
    }

    /// A relay sending non-JSON must not abandon a connection that may still deliver the proposal.
    /// The garbage is placed BEFORE the real delivery, so a reader that gave up on it fails here.
    #[tokio::test]
    async fn a_malformed_frame_does_not_abandon_the_connection() {
        let url = serve_one(|mut server| async move {
            server
                .send(Message::Text("this is not json".to_string()))
                .await
                .expect("sends");
            server
                .send(Message::Text(delivery_frame(2, "topic-c", "STILL-HERE")))
                .await
                .expect("sends");
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let found = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery)
            .await
            .expect("survives the garbage");
        assert_eq!(found.message, "STILL-HERE");
    }

    /// **The bound, observed rather than asserted about.**
    ///
    /// `the_frame_bound_is_given_to_the_websocket_rather_than_checked_afterwards` pins the config;
    /// this pins what the config DOES. The server sends a frame over [`MAX_FRAME_BYTES`] and the
    /// read must fail — which it can only do if the ceiling reached the websocket, because the
    /// post-read length check sits downstream of the very allocation this frame would otherwise
    /// have forced.
    ///
    /// The size is drawn FROM the limit rather than picked: a fixture at some round number below the
    /// real ceiling would prove nothing about the ceiling.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_by_the_websocket_itself() {
        let oversized = "z".repeat(MAX_FRAME_BYTES + 1024);
        let url = serve_one(move |mut server| async move {
            // The server is deliberately NOT bound by the client config, which is the point: a
            // hostile relay does not honour the wallet limits.
            let _ = server.send(Message::Text(oversized)).await;
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let outcome = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery).await;

        // The variant is the PLACEMENT, and asserting merely `is_err()` here would not have been a
        // placement test at all: with the ceiling removed from the config, tungstenite still accepts
        // a one-megabyte frame (its own default is 64 MiB), the reader assembles it, and the
        // post-read length check refuses it as `Protocol` — so `is_err()` holds under BOTH
        // arrangements and could not tell them apart.
        //
        // A refusal raised while READING surfaces as a websocket error, which maps to `Unreachable`.
        // That variant is reachable only when the limit reached the socket.
        assert!(
            matches!(outcome, Err(RelayFault::Unreachable(_))),
            "expected the websocket itself to refuse the frame; got {outcome:?}, which means the              frame was fully read and only then rejected"
        );
    }

    /// The other side of the bound. Without it, the test above passes for a ceiling of one byte, and
    /// a limit that refuses everything large is indistinguishable from one set correctly.
    #[tokio::test]
    async fn a_large_but_permitted_frame_is_still_accepted() {
        // Half the ceiling: far larger than any realistic proposal, and comfortably inside the limit
        // once the JSON envelope is wrapped around it.
        let padding = "y".repeat(MAX_FRAME_BYTES / 2);
        let url = serve_one(move |mut server| async move {
            let _ = server
                .send(Message::Text(delivery_frame(1, "topic-d", &padding)))
                .await;
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let found = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery)
            .await
            .expect("a frame under the ceiling must be read");
        assert!(found.message.len() > MAX_FRAME_BYTES / 4);
    }

    /// A relay that closes mid-wait is reported as unreachable, not as a proposal that never came.
    /// The two have different remedies on the consent window, so they must not collapse into one.
    #[tokio::test]
    async fn a_relay_that_closes_is_reported_as_unreachable() {
        let url = serve_one(|mut server| async move {
            let _ = server.close(None).await;
        })
        .await;

        let mut socket = dial(&url).await;
        let outcome = read_until(&mut socket, Duration::from_secs(5), relay::read_delivery).await;
        assert!(
            matches!(outcome, Err(RelayFault::Unreachable(_))),
            "expected an unreachable relay, got {outcome:?}"
        );
    }

    /// A relay that says nothing times out as "no proposal" — the case whose advice tells the person
    /// to go back and fetch a fresh link.
    #[tokio::test]
    async fn a_silent_relay_times_out_as_no_proposal() {
        let url = serve_one(|mut server| async move {
            // Never sends. Held open so the client waits rather than seeing a close.
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        let outcome = read_until(
            &mut socket,
            Duration::from_millis(250),
            relay::read_delivery,
        )
        .await;
        assert_eq!(outcome.err(), Some(RelayFault::NoProposal));
    }

    /// Every delivery the reader SKIPS must be acknowledged, or the relay redelivers it forever. The
    /// server captures what it received, so the ack is observed on the wire rather than inferred
    /// from the reader having moved on.
    #[tokio::test]
    async fn a_skipped_delivery_is_acknowledged_so_the_relay_stops_resending_it() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let url = serve_one(|mut server| async move {
            server
                .send(Message::Text(delivery_frame(77, "topic-skip", "IGNORED")))
                .await
                .expect("sends");
            if let Some(Ok(Message::Text(reply))) = server.next().await {
                let _ = tx.send(reply);
            }
            let _ = server.next().await;
        })
        .await;

        let mut socket = dial(&url).await;
        // Wanting something that never arrives is what makes the delivery above SKIPPED rather than
        // returned, which is the state the acknowledgement belongs to.
        let _ = read_until(&mut socket, Duration::from_millis(400), |frame| {
            frame.get("method").filter(|m| *m == "never").map(|_| ())
        })
        .await;

        let acked = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("the ack must arrive")
            .expect("the server captured it");
        let acked: Value = serde_json::from_str(&acked).expect("the ack is JSON");
        assert_eq!(acked, relay::ack_frame(77));
    }

    /// `send` puts a frame on a real socket and the peer receives it byte-for-byte. Small, but it is
    /// the only proof that the publish path works at all — every publish in `approve`, `reject` and
    /// `disconnect` goes through this one function.
    #[tokio::test]
    async fn a_sent_frame_arrives_at_the_peer_unchanged() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let url = serve_one(|mut server| async move {
            if let Some(Ok(Message::Text(got))) = server.next().await {
                let _ = tx.send(got);
            }
        })
        .await;

        let mut socket = dial(&url).await;
        let frame = relay::publish_frame(9, "topic-e", "SEALED", relay::TAG_SESSION_SETTLE, 300);
        send(&mut socket, &frame).await.expect("sends");

        let got = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("arrives")
            .expect("captured");
        assert_eq!(serde_json::from_str::<Value>(&got).unwrap(), frame);
    }
}
