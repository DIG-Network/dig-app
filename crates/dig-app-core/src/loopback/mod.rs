//! The APP-SIGN loopback identity server — the browser-reachable front door dig-app exposes for the
//! extension↔dig-app signing channel (SIGN-1, `SPEC.md` §5.6, **security-critical**).
//!
//! A web dapp reaches dig-app *through* the paired DIG browser extension, which relays over this
//! loopback WebSocket. The server:
//!
//! 1. binds loopback-only — `[::1]:9779` (IPv6-first, ecosystem §5.2) AND `127.0.0.1:9779` — never a
//!    routable address;
//! 2. runs the [`ConnectionGuard`] on every WS upgrade (`Host` allowlist + `Origin` pin, §5.6.2),
//!    rejecting an unpinned caller with `403` before any frame is read;
//! 3. feeds each JSON-RPC frame to the [`FrameRouter`], which authenticates it against the sealed
//!    [`crate::pairing::PairingStore`] (§5.6.3) and dispatches it.
//!
//! The transport is deliberately thin: all security-critical logic (the auth gate, the pairing
//! handshake, the error taxonomy) lives in the synchronous [`dispatch`] + [`crate::pairing`] cores,
//! so it is unit-testable without a socket. This module only moves bytes and applies the upgrade
//! guard.

pub mod dispatch;
pub mod guard;
pub mod persist;

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;

use crate::profiles::sealer::ProfileSealer;

pub use dispatch::{FrameRouter, ProfileConnectInfo, RequestFrame, SignErrorCode};
pub use guard::{ConnectionGuard, GuardRejection, LOOPBACK_PORT, PINNED_EXTENSION_IDS};
pub use persist::{FileSealedStore, NullSealedStore, PersistedSignState, SealedRecordStore};

/// The loopback identity server. Owns the shared [`FrameRouter`] (behind an `Arc`, one per active
/// profile's endpoint) and the connection [`ConnectionGuard`], and serves the two loopback listeners.
pub struct LoopbackServer<S: ProfileSealer + Send + Sync + 'static> {
    router: Arc<FrameRouter<S>>,
    guard: Arc<ConnectionGuard>,
}

impl<S: ProfileSealer + Send + Sync + 'static> LoopbackServer<S> {
    /// Build a server over `router`, admitting connections that pass `guard`.
    pub fn new(router: FrameRouter<S>, guard: ConnectionGuard) -> Self {
        Self {
            router: Arc::new(router),
            guard: Arc::new(guard),
        }
    }

    /// Bind both loopback listeners (`[::1]:9779` first, then `127.0.0.1:9779`) and serve
    /// connections until the process exits. Binding IPv6 first honours the ecosystem IPv6-first rule
    /// (§5.2); the IPv4 listener is the fallback for hosts without loopback IPv6.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if neither loopback address can be bound (e.g. the port is already in use).
    /// A single-family bind failure is tolerated as long as the other family binds.
    pub async fn serve(self) -> std::io::Result<()> {
        let v6 = TcpListener::bind(("::1", LOOPBACK_PORT)).await;
        let v4 = TcpListener::bind(("127.0.0.1", LOOPBACK_PORT)).await;
        // Tolerate a single-family bind failure, but if NEITHER loopback family binds there is no
        // endpoint to serve — surface the IPv4 error (the more universally expected family).
        let bound: Vec<TcpListener> = [v6, v4].into_iter().filter_map(Result::ok).collect();
        if bound.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "neither loopback address could be bound on the identity port",
            ));
        }

        let mut tasks = Vec::new();
        for listener in bound {
            let router = Arc::clone(&self.router);
            let guard = Arc::clone(&self.guard);
            tasks.push(tokio::spawn(accept_loop(listener, router, guard)));
        }
        for task in tasks {
            let _ = task.await;
        }
        Ok(())
    }

    /// Serve ONE already-connected stream: run the guarded WS upgrade, then the frame loop. Exposed so
    /// the accept loop and the tests share exactly one code path (tests drive it over an in-memory
    /// duplex, so the full handshake + guard + routing is exercised without binding a port).
    pub async fn serve_connection<IO>(
        router: Arc<FrameRouter<S>>,
        guard: Arc<ConnectionGuard>,
        io: IO,
    ) -> Result<(), LoopbackError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let ws = accept_guarded(io, &guard).await?;
        run_frame_loop(ws, &router).await
    }
}

/// Accept connections from one loopback listener forever, serving each on its own task.
async fn accept_loop<S: ProfileSealer + Send + Sync + 'static>(
    listener: TcpListener,
    router: Arc<FrameRouter<S>>,
    guard: Arc<ConnectionGuard>,
) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let router = Arc::clone(&router);
        let guard = Arc::clone(&guard);
        tokio::spawn(async move {
            // A rejected upgrade or a dropped connection is not fatal — log and move on.
            if let Err(err) = LoopbackServer::serve_connection(router, guard, stream).await {
                tracing::debug!(error = %err, "loopback connection ended");
            }
        });
    }
}

/// Run the WebSocket upgrade, applying the [`ConnectionGuard`] to the handshake headers. A rejected
/// upgrade returns `403` to the caller and surfaces as [`LoopbackError::Rejected`].
///
// The header callback's `Result<Response, ErrorResponse>` is tungstenite's mandated signature; the
// large `Err` variant (an `http::Response`) is not ours to box, so the lint is allowed here.
#[allow(clippy::result_large_err)]
async fn accept_guarded<IO>(
    io: IO,
    guard: &ConnectionGuard,
) -> Result<tokio_tungstenite::WebSocketStream<IO>, LoopbackError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let guard = guard.clone();
    let callback = move |req: &HandshakeRequest,
                         response: HandshakeResponse|
          -> Result<HandshakeResponse, ErrorResponse> {
        let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
        match guard.check(header("host"), header("origin")) {
            Ok(()) => Ok(response),
            Err(_) => Err(forbidden()),
        }
    };
    tokio_tungstenite::accept_hdr_async(io, callback)
        .await
        .map_err(|_| LoopbackError::Rejected)
}

/// The frame loop: read text frames, route each through the [`FrameRouter`], and write the response.
/// Non-text frames are ignored; a close or transport error ends the loop.
async fn run_frame_loop<S, IO>(
    mut ws: tokio_tungstenite::WebSocketStream<IO>,
    router: &FrameRouter<S>,
) -> Result<(), LoopbackError>
where
    S: ProfileSealer + Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(message) = ws.next().await {
        let text = match message.map_err(|_| LoopbackError::Transport)? {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue,
        };
        let response = route_text(&text, router);
        ws.send(Message::Text(response.to_string()))
            .await
            .map_err(|_| LoopbackError::Transport)?;
    }
    Ok(())
}

/// Parse one text frame and route it, or return a JSON-RPC parse error for a malformed frame. A
/// malformed frame never aborts the connection — it is answered and the loop continues.
fn route_text<S: ProfileSealer>(text: &str, router: &FrameRouter<S>) -> serde_json::Value {
    match serde_json::from_str::<RequestFrame>(text) {
        Ok(frame) => router.handle(&frame),
        Err(_) => json!({
            "jsonrpc": "2.0",
            "id": serde_json::Value::Null,
            "error": { "code": -32700, "message": "parse error" },
        }),
    }
}

/// The `403` returned when the [`ConnectionGuard`] rejects a WS upgrade.
fn forbidden() -> ErrorResponse {
    ErrorResponse::new(Some("origin or host not permitted".to_string()))
        .map_status(StatusCode::FORBIDDEN)
}

/// Small helper: set the status on an [`ErrorResponse`] fluently.
trait WithStatus {
    fn map_status(self, status: StatusCode) -> Self;
}

impl WithStatus for ErrorResponse {
    fn map_status(mut self, status: StatusCode) -> Self {
        *self.status_mut() = status;
        self
    }
}

/// A failure serving one loopback connection. None are fatal to the server — a connection ends and
/// the listener keeps accepting.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackError {
    /// The WS upgrade was rejected (guard failure) or failed to negotiate.
    #[error("websocket upgrade rejected")]
    Rejected,
    /// A transport error reading or writing a frame (including a dropped connection).
    #[error("loopback transport error")]
    Transport,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConfirmDecision, ConnectPrompt, NativeConfirmer, PairPrompt, SignPrompt};
    use crate::keystore::IdentitySecrets;
    use crate::pairing::PairingStore;
    use crate::profiles::keystore_sealer::{KeystoreSealer, UnlockedIdentities};
    use dig_keystore::KdfParams;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::{HeaderValue, ORIGIN};

    const DID: &str = "did:chia:server-test";
    const EXT: &str = "mlibddmbhlgogepnjdienclhnkfpkfah";

    struct Approver;
    impl NativeConfirmer for Approver {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_connect(&self, _: &ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_sign(&self, _: &SignPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
    }

    fn router() -> FrameRouter<KeystoreSealer> {
        use crate::loopback::dispatch::ProfileConnectInfo;
        use crate::session::SessionSigner;
        use crate::whitelist::WhitelistStore;
        use std::sync::Arc;

        let identities = UnlockedIdentities::new();
        identities.unlock(DID, IdentitySecrets::generate());
        let pairings = PairingStore::new(
            KeystoreSealer::with_kdf(identities.clone(), KdfParams::FAST_TEST),
            DID,
        );
        let whitelist = WhitelistStore::new(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            DID,
        );
        let signer = IdentitySecrets::generate();
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec!["xch1testaddress".to_string()],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(Approver),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        )
    }

    /// Build a WS client handshake request with a chosen `Host` (via the URI authority) and `Origin`.
    fn client_request(host: &str, origin: &str) -> HandshakeRequest {
        let mut request = format!("ws://{host}/").into_client_request().unwrap();
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        request
    }

    /// Spawn the server on one side of an in-memory duplex, connect a WS client on the other with the
    /// given handshake headers, and return the connected client stream (or the handshake error).
    async fn connect(
        host: &str,
        origin: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::tungstenite::Error,
    > {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let router = Arc::new(router());
        let guard = Arc::new(ConnectionGuard::pinned());
        tokio::spawn(async move {
            let _ = LoopbackServer::serve_connection(router, guard, server_io).await;
        });
        let (client, _resp) =
            tokio_tungstenite::client_async(client_request(host, origin), client_io).await?;
        Ok(client)
    }

    /// Send a JSON-RPC frame and read the next text response as a `Value`.
    async fn round_trip(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        frame: serde_json::Value,
    ) -> serde_json::Value {
        ws.send(Message::Text(frame.to_string())).await.unwrap();
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Text(text) => return serde_json::from_str(&text).unwrap(),
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn a_pinned_client_completes_the_handshake_and_pairs() {
        let mut ws = connect(
            "localhost:9779",
            "chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah",
        )
        .await
        .expect("pinned client handshake succeeds");

        let resp = round_trip(
            &mut ws,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "pair.begin",
                    "params": { "ext_id": EXT, "requested_at": 1 } }),
        )
        .await;
        assert!(resp["result"]["pairing_id"].is_string());
        let token = resp["result"]["channel_token_b64"].as_str().unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token).unwrap();
        assert_eq!(decoded.len(), 32, "the channel token is 32 CSPRNG bytes");
    }

    #[tokio::test]
    async fn a_foreign_origin_is_rejected_at_the_handshake() {
        let result = connect("localhost:9779", "https://evil.example").await;
        assert!(result.is_err(), "an unpinned origin must fail the upgrade");
    }

    #[tokio::test]
    async fn a_bad_host_is_rejected_at_the_handshake() {
        let result = connect(
            "evil.example.com",
            "chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah",
        )
        .await;
        assert!(result.is_err(), "a non-loopback Host must fail the upgrade");
    }

    #[tokio::test]
    async fn a_malformed_frame_gets_a_parse_error_not_a_disconnect() {
        let mut ws = connect(
            "127.0.0.1:9779",
            "chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah",
        )
        .await
        .unwrap();
        ws.send(Message::Text("not json".to_string()))
            .await
            .unwrap();
        let resp = loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Text(t) => break serde_json::from_str::<serde_json::Value>(&t).unwrap(),
                _ => continue,
            }
        };
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn an_unauthenticated_frame_is_rejected_over_the_wire() {
        let mut ws = connect(
            "127.0.0.1:9779",
            "chrome-extension://mlibddmbhlgogepnjdienclhnkfpkfah",
        )
        .await
        .unwrap();
        let resp = round_trip(
            &mut ws,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "sign.request", "params": {} }),
        )
        .await;
        assert_eq!(resp["error"]["message"], "AUTH_REQUIRED");
    }
}
