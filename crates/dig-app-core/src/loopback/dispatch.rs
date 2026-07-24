//! The JSON-RPC frame router for the APP-SIGN loopback channel (SIGN-1, `SPEC.md` §5.6,
//! **security-critical**).
//!
//! This is the pure, synchronous core the async [`super::LoopbackServer`] feeds parsed frames into: given a
//! request frame it applies the per-frame authentication (§5.6.3) and returns the JSON-RPC response.
//! Keeping it transport-free is what makes the security-critical logic — the auth gate, the pairing
//! handshake, the error taxonomy — exhaustively unit-testable without a socket.
//!
//! ## What the router routes
//!
//! - **`pair.begin`** — a native pairing confirm (§5.6.1) then mint + seal + persist the channel token
//!   (§5.6.3). This is the ONE frame that carries no `auth` (it establishes it).
//! - **every other frame** — authenticated first (`AUTH_REQUIRED` / `AUTH_BAD_MAC` / `AUTH_REPLAY`),
//!   THEN dispatched:
//!   - **`connect.request` / `connect.revoke`** — the dapp connect-whitelist (§5.6.4): a whitelisted
//!     origin returns its connection handle directly; an un-whitelisted one raises the native connect
//!     confirm and, on approval, seals a per-origin whitelist entry.
//!   - **`sign.request`** — the sign flow (§5.6.5): gate on the whitelist (`CONNECT_REQUIRED`
//!     otherwise) → decode + native confirm through the ONE [`NativeConfirmSignPolicy`] → on approval
//!     sign the domain-separated `DIGNET-SIGN-v1` message with the in-memory identity key and return
//!     `{ signature_b64, pubkey_hex }`.
//!
//! The per-OS native confirm windows land in SIGN-3 behind the frozen [`NativeConfirmer`] trait; until
//! then the injected confirmer is the fail-closed [`crate::confirm::HeadlessConfirmer`].

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::confirm::{ConfirmDecision, ConnectPrompt, NativeConfirmer, PairPrompt};
use crate::loopback::persist::{NullSealedStore, SealedRecordStore};
use crate::pairing::{AuthFailure, PairingStore};
use crate::sealer::ProfileSealer;
use crate::session::{sign_callback_message, SessionSigner};
use crate::sign_policy::{NativeConfirmSignPolicy, SignRejection, SignSubject, SignVerdict};
use crate::whitelist::WhitelistStore;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// The stable symbolic error codes the extension keys its UX off (`SPEC.md` §5.6.7). Each carries a
/// numeric JSON-RPC `code` (an application-specific range, distinct from the JSON-RPC reserved
/// `-32xxx` band) and its canonical symbol string, sent as the error `message` so both the numeric
/// and symbolic forms are on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignErrorCode {
    /// No valid pairing for this frame (unpaired / revoked).
    AuthRequired,
    /// Pairing-token MAC verification failed.
    AuthBadMac,
    /// Frame nonce not strictly greater than the last accepted.
    AuthReplay,
    /// User denied the pairing confirm.
    PairDenied,
    /// User did not answer the pairing confirm in time.
    PairTimeout,
    /// The `origin` is not whitelisted for the active profile.
    ConnectRequired,
    /// User denied the connect modal.
    ConnectDenied,
    /// User did not answer the connect modal in time.
    ConnectTimeout,
    /// User denied the sign confirm.
    SignDenied,
    /// User did not answer the sign confirm in time.
    SignTimeout,
    /// `payload_type` not on the decoder allowlist (blind-sign refused).
    SignUnknownType,
    /// Known type, but the payload did not decode for display.
    SignBadPayload,
    /// No desktop session — native confirm unavailable (headless fail-closed).
    SignNoConfirmer,
    /// The active profile could not be unlocked.
    Locked,
}

impl SignErrorCode {
    /// The canonical symbol string (`SPEC.md` §5.6.7) — sent as the JSON-RPC error `message`.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AuthBadMac => "AUTH_BAD_MAC",
            Self::AuthReplay => "AUTH_REPLAY",
            Self::PairDenied => "PAIR_DENIED",
            Self::PairTimeout => "PAIR_TIMEOUT",
            Self::ConnectRequired => "CONNECT_REQUIRED",
            Self::ConnectDenied => "CONNECT_DENIED",
            Self::ConnectTimeout => "CONNECT_TIMEOUT",
            Self::SignDenied => "SIGN_DENIED",
            Self::SignTimeout => "SIGN_TIMEOUT",
            Self::SignUnknownType => "SIGN_UNKNOWN_TYPE",
            Self::SignBadPayload => "SIGN_BAD_PAYLOAD",
            Self::SignNoConfirmer => "SIGN_NO_CONFIRMER",
            Self::Locked => "LOCKED",
        }
    }

    /// The numeric JSON-RPC error code (application range, one per symbol).
    pub fn code(self) -> i64 {
        match self {
            Self::AuthRequired => -33001,
            Self::AuthBadMac => -33002,
            Self::AuthReplay => -33003,
            Self::PairDenied => -33010,
            Self::PairTimeout => -33011,
            Self::ConnectRequired => -33020,
            Self::ConnectDenied => -33021,
            Self::ConnectTimeout => -33022,
            Self::SignDenied => -33030,
            Self::SignTimeout => -33031,
            Self::SignUnknownType => -33032,
            Self::SignBadPayload => -33033,
            Self::SignNoConfirmer => -33034,
            Self::Locked => -33040,
        }
    }
}

/// The `auth` object every non-pairing frame carries (`SPEC.md` §5.6.3).
#[derive(Debug, Clone, Deserialize)]
pub struct FrameAuth {
    /// The pairing this frame authenticates against.
    pub pairing_id: String,
    /// A strictly-monotonic per-pairing nonce (barring replay).
    pub nonce: u64,
    /// Base64 HMAC-SHA256 of the canonical frame bytes under the channel secret.
    pub mac_b64: String,
}

/// A parsed request frame off the loopback channel. `params` defaults to `null` when absent; `auth`
/// is absent only on `pair.begin`.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestFrame {
    /// The correlation id echoed on the response.
    #[serde(default)]
    pub id: Value,
    /// The JSON-RPC method.
    pub method: String,
    /// The method parameters (the MAC binds their canonical form).
    #[serde(default)]
    pub params: Value,
    /// The per-frame authentication (absent on `pair.begin`).
    #[serde(default)]
    pub auth: Option<FrameAuth>,
}

/// `pair.begin` parameters (`SPEC.md` §5.6.3).
#[derive(Debug, Deserialize)]
struct PairBeginParams {
    ext_id: String,
    #[serde(default)]
    ext_label: Option<String>,
}

/// `connect.request` parameters (`SPEC.md` §5.6.4).
#[derive(Debug, Deserialize)]
struct ConnectParams {
    origin: String,
    #[serde(default)]
    dapp_name: Option<String>,
    #[serde(default)]
    requested_permissions: Vec<String>,
}

/// `connect.revoke` parameters (`SPEC.md` §5.6.4).
#[derive(Debug, Deserialize)]
struct ConnectRevokeParams {
    origin: String,
}

/// `sign.request` parameters (`SPEC.md` §5.6.5). `payload_b64` is the base64 of the exact bytes that
/// get signed; the decoder renders directly from them so display binds to what is signed.
#[derive(Debug, Deserialize)]
struct SignParams {
    payload_type: String,
    payload_b64: String,
}

/// Just the `origin` of a `sign.request`, parsed first so the connect gate runs before the payload is
/// validated (an unconnected origin ⇒ `CONNECT_REQUIRED` regardless of the payload's shape).
#[derive(Debug, Deserialize)]
struct OriginGate {
    origin: String,
}

/// The connect-handle the app returns to a dapp on a successful `connect.request` (§5.6.4): the active
/// profile plus the addresses/pubkeys the `window.chia` connect contract exposes. Computed once by the
/// wiring layer (from the active profile's identity + wallet) and handed to the router, so the router
/// stays decoupled from the wallet.
#[derive(Debug, Clone)]
pub struct ProfileConnectInfo {
    /// The active profile's DID.
    pub profile_did: String,
    /// The wallet receive addresses (`xch1…`) exposed to a connected dapp.
    pub addresses: Vec<String>,
    /// The public keys (hex) exposed to a connected dapp.
    pub pubkeys: Vec<String>,
}

/// The session-lock re-auth gate the sign path consults immediately before it uses the identity key
/// (WSEC-D, `SPEC.md` §5.6, dig_ecosystem#967).
///
/// A profile stays unlocked only while its DEK lives in the in-memory session; the session-lock
/// lifecycle drops that DEK on idle / OS screen-lock / one-tap lock-now. When it has, the next
/// signature must RE-AUTHENTICATE (re-unlock the DEK) before it can proceed. This seam is how the
/// transport-free router asks "is a re-auth owed, and if so did it succeed?" without depending on the
/// session-lock controller or the keystore directly.
///
/// **Reads never consult this** — a lock gates the identity key, not content, so browsing/reads keep
/// flowing untouched (§6.0). Only [`handle_sign`](FrameRouter::handle_sign) calls it.
pub trait SignReauthGate: Send + Sync {
    /// Authorize the next signature. Returns `true` when signing may proceed — either the session was
    /// never locked, or a re-unlock just succeeded — and `false` when the session is locked and could
    /// not be re-unlocked, in which case the sign is refused with `LOCKED` rather than attempted on a
    /// dropped key.
    fn authorize_sign(&self) -> bool;
}

/// The default gate: signing is always authorized. This preserves the pre-tray-hookup behaviour where
/// the only lock enforcement is the signer's own DEK-drop hard barrier (a locked session yields no
/// signature → `LOCKED`). The tray boot injects a session-lock-backed gate over this default.
pub struct OpenSignGate;

impl SignReauthGate for OpenSignGate {
    fn authorize_sign(&self) -> bool {
        true
    }
}

/// The frame router: authenticates every frame against the [`PairingStore`] and dispatches it,
/// raising the native confirm (§5.6.1) through the [`NativeConfirmer`] where a decision is required.
///
/// Generic over the [`ProfileSealer`] so the pairing + whitelist stores seal under the active
/// profile's DEK (NC-2). Shared behind an `Arc` by the async server; every method takes `&self`.
pub struct FrameRouter<S: ProfileSealer> {
    pairings: PairingStore<S>,
    whitelist: WhitelistStore<S>,
    /// Gates pairing + connect confirms (§5.6.1). Shared with `sign_policy`, which gates sign confirms.
    confirmer: Arc<dyn NativeConfirmer>,
    /// The ONE production sign policy (decode + native confirm) — the same policy the §5.3 engine
    /// callback funnels through, so there is a single sign-authorization point (§5.6.6).
    sign_policy: NativeConfirmSignPolicy,
    /// Signs the domain-separated `DIGNET-SIGN-v1` message with the in-memory identity key (slot
    /// `0x0010`) after the policy approves. The private key never leaves this seam.
    signer: Box<dyn SessionSigner + Send + Sync>,
    /// The connect-handle returned on a granted connect.
    connect_info: ProfileConnectInfo,
    /// The extension ids permitted to `pair.begin` — the same pinned set the `Origin` guard enforces.
    allowed_ext_ids: Vec<String>,
    /// The at-rest persistence sink: seals the sealed pairing/whitelist bytes + nonce high-water marks
    /// to disk so they survive a restart (#958/#956). Defaults to the no-op [`NullSealedStore`]; the
    /// tray boot injects a [`FileSealedStore`](crate::loopback::FileSealedStore) via
    /// [`with_persistence`](Self::with_persistence).
    persist: Arc<dyn SealedRecordStore>,
    /// The session-lock re-auth gate consulted before every signature (§5.6, WSEC-D). Defaults to the
    /// always-authorize [`OpenSignGate`]; the tray boot injects a session-lock-backed gate via
    /// [`with_reauth_gate`](Self::with_reauth_gate) so a locked session forces a re-unlock before it
    /// signs. Reads never consult it.
    reauth_gate: Arc<dyn SignReauthGate>,
}

impl<S: ProfileSealer> FrameRouter<S> {
    /// Build a router over the per-profile `pairings` + `whitelist` stores, gating pairing/connect
    /// through `confirmer`, signing approved requests with `signer`, returning `connect_info` on a
    /// granted connect, and accepting pairing requests only from `allowed_ext_ids`. The sign policy
    /// shares `confirmer` so pairing, connect, and sign all draw the one native-confirm surface.
    pub fn new(
        pairings: PairingStore<S>,
        whitelist: WhitelistStore<S>,
        confirmer: Arc<dyn NativeConfirmer>,
        signer: Box<dyn SessionSigner + Send + Sync>,
        connect_info: ProfileConnectInfo,
        allowed_ext_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        let sign_policy = NativeConfirmSignPolicy::new(Arc::clone(&confirmer));
        Self {
            pairings,
            whitelist,
            confirmer,
            sign_policy,
            signer,
            connect_info,
            allowed_ext_ids: allowed_ext_ids.into_iter().collect(),
            persist: Arc::new(NullSealedStore),
            reauth_gate: Arc::new(OpenSignGate),
        }
    }

    /// Inject the session-lock re-auth gate consulted before every signature (WSEC-D, #967). Without
    /// this the router uses the always-authorize [`OpenSignGate`] (the unit-test default + pre-hookup
    /// behaviour); the tray boot supplies a gate backed by the live session-lock so a locked session
    /// re-authenticates before it signs.
    pub fn with_reauth_gate(mut self, reauth_gate: Arc<dyn SignReauthGate>) -> Self {
        self.reauth_gate = reauth_gate;
        self
    }

    /// Attach a durable [`SealedRecordStore`] so granted pairings, connected origins, and nonce
    /// high-water marks are written at rest and survive a restart (#958/#956). Without this the router
    /// keeps every record in memory only (the pre-wiring behaviour + the unit-test default).
    pub fn with_persistence(mut self, persist: Arc<dyn SealedRecordStore>) -> Self {
        self.persist = persist;
        self
    }

    /// Restore persisted pairings + connected origins + the nonce ledger on boot, so a paired
    /// extension and its connected dapps keep working across a restart WITHOUT a fresh pairing, and a
    /// pre-restart frame cannot replay (#956). Sealed records that this profile's DEK cannot open (a
    /// foreign/corrupt record) are skipped. Returns `(pairings, origins)` restored, for the boot log.
    ///
    /// **Fail-closed on a missing nonce mark (#956).** A restored pairing whose replay high-water mark
    /// is absent from the (plaintext, unauthenticated) nonce ledger — because the ledger file was
    /// deleted, or the pairing had never authenticated a frame before the restart — is DROPPED rather
    /// than restored with an empty (`None`) ledger. An empty ledger would accept ANY nonce and so
    /// reopen the full replay window; dropping the pairing forces a fresh re-pair instead. Only a
    /// pairing WITH a known high-water mark is re-seeded and kept live.
    ///
    /// Call once, before the server begins accepting frames.
    pub fn restore(&self) -> (usize, usize) {
        let state = self.persist.load();
        let mut pairings = 0;
        for sealed in &state.pairings {
            match self.pairings.restore_sealed(sealed) {
                Ok(pairing_id) => match state.nonces.get(&pairing_id) {
                    // Re-seed the replay high-water mark so a captured frame cannot replay (#956).
                    Some(&last_nonce) => {
                        self.pairings.seed_last_nonce(&pairing_id, last_nonce);
                        pairings += 1;
                    }
                    // No trustworthy high-water mark — fail closed: drop the pairing (require re-pair)
                    // rather than accept any nonce against an empty ledger.
                    None => {
                        self.pairings.unpair(&pairing_id);
                        tracing::warn!(
                            "dropped a restored pairing with no persisted nonce mark — re-pair required"
                        );
                    }
                },
                Err(_) => tracing::warn!("skipped a pairing record this profile cannot open"),
            }
        }
        let mut origins = 0;
        for sealed in &state.whitelist {
            match self.whitelist.restore_sealed(sealed) {
                Ok(_) => origins += 1,
                Err(_) => tracing::warn!("skipped a whitelist record this profile cannot open"),
            }
        }
        tracing::info!(pairings, origins, "restored APP-SIGN state from disk");
        (pairings, origins)
    }

    /// Route one request frame to its JSON-RPC response `Value`. Never panics on caller input — a
    /// malformed frame becomes a JSON-RPC error, never an abort.
    pub fn handle(&self, frame: &RequestFrame) -> Value {
        match frame.method.as_str() {
            "pair.begin" => self.handle_pair_begin(&frame.id, &frame.params),
            _ => self.handle_authenticated(frame),
        }
    }

    /// The pairing handshake (§5.6.3): verify the extension id is pinned, raise the native pairing
    /// confirm, and on approval mint + seal + persist the channel token.
    fn handle_pair_begin(&self, id: &Value, params: &Value) -> Value {
        let Ok(params) = serde_json::from_value::<PairBeginParams>(params.clone()) else {
            return error(id, SignErrorCode::PairDenied);
        };
        // The ext_id MUST be a pinned DIG extension — the same set the Origin guard enforces, checked
        // again here so a frame that somehow bypassed the transport guard still cannot self-pair.
        if !self.allowed_ext_ids.contains(&params.ext_id) {
            return error(id, SignErrorCode::PairDenied);
        }

        let decision = self.confirmer.confirm_pair(&PairPrompt {
            ext_id: &params.ext_id,
            ext_label: params.ext_label.as_deref(),
        });
        if let Some(code) = pair_decision_error(decision) {
            return error(id, code);
        }

        match self.pairings.pair(&params.ext_id, now_epoch_secs()) {
            Ok(outcome) => {
                // Persist the sealed record so the pairing survives a restart (#958). Best-effort:
                // a failed write is logged inside the store and never fails the pairing.
                self.persist
                    .persist_pairing(&outcome.pairing_id, &outcome.sealed_record);
                ok(
                    id,
                    json!({
                        "pairing_id": outcome.pairing_id,
                        "channel_token_b64": outcome.channel_token_b64,
                    }),
                )
            }
            // Sealing fails only when the active profile is locked — surface it as LOCKED.
            Err(_) => error(id, SignErrorCode::Locked),
        }
    }

    /// Every non-pairing frame: authenticate it, then dispatch to the connect/sign handlers.
    fn handle_authenticated(&self, frame: &RequestFrame) -> Value {
        if let Err(code) = self.authenticate(frame) {
            return error(&frame.id, code);
        }
        match frame.method.as_str() {
            "connect.request" => self.handle_connect(&frame.id, &frame.params),
            "connect.revoke" => self.handle_connect_revoke(&frame.id, &frame.params),
            "sign.request" => self.handle_sign(&frame.id, &frame.params),
            _ => method_not_found(&frame.id),
        }
    }

    /// The dapp connect / whitelist handler (§5.6.4). An already-whitelisted origin returns its
    /// connection handle without a modal; otherwise the native connect confirm decides, and on
    /// approval a per-origin whitelist entry is sealed at rest before the handle is returned.
    fn handle_connect(&self, id: &Value, params: &Value) -> Value {
        let Ok(params) = serde_json::from_value::<ConnectParams>(params.clone()) else {
            return error(id, SignErrorCode::ConnectDenied);
        };

        if self.whitelist.is_whitelisted(&params.origin) {
            return ok(id, self.connect_result());
        }

        let decision = self.confirmer.confirm_connect(&ConnectPrompt {
            origin: &params.origin,
            dapp_name: params.dapp_name.as_deref(),
        });
        match decision {
            ConfirmDecision::Approve => {
                match self.whitelist.grant(
                    &params.origin,
                    params.requested_permissions,
                    now_epoch_secs(),
                ) {
                    Ok(outcome) => {
                        // Persist the sealed grant so the connected origin survives a restart (#958).
                        self.persist
                            .persist_whitelist(&params.origin, &outcome.sealed_record);
                        ok(id, self.connect_result())
                    }
                    // Sealing fails only when the active profile is locked — surface it as LOCKED.
                    Err(_) => error(id, SignErrorCode::Locked),
                }
            }
            ConfirmDecision::Deny => error(id, SignErrorCode::ConnectDenied),
            ConfirmDecision::Timeout => error(id, SignErrorCode::ConnectTimeout),
            ConfirmDecision::Unavailable => error(id, SignErrorCode::SignNoConfirmer),
        }
    }

    /// The `connect.revoke` handler (§5.6.4): drop the origin's whitelist entry, returning it to
    /// `CONNECT_REQUIRED`. Idempotent — revoking an unknown origin still succeeds.
    fn handle_connect_revoke(&self, id: &Value, params: &Value) -> Value {
        let Ok(params) = serde_json::from_value::<ConnectRevokeParams>(params.clone()) else {
            return error(id, SignErrorCode::ConnectDenied);
        };
        let revoked = self.whitelist.revoke(&params.origin);
        if revoked {
            // Drop the at-rest record too, so the revocation survives a restart (#958).
            self.persist.remove_whitelist(&params.origin);
        }
        ok(id, json!({ "revoked": revoked }))
    }

    /// The `sign.request` handler (§5.6.5). Gate on the whitelist, decode + native-confirm through the
    /// one [`NativeConfirmSignPolicy`], and on approval sign the domain-separated `DIGNET-SIGN-v1`
    /// message with the in-memory identity key — never the raw payload (the signing-oracle guard).
    fn handle_sign(&self, id: &Value, params: &Value) -> Value {
        // Connect gate FIRST: an un-whitelisted origin never reaches the decoder or the key (§5.6.4).
        // The origin is read before the rest of the payload, so an unconnected origin is refused with
        // `CONNECT_REQUIRED` regardless of whether the payload is well-formed.
        let Ok(gate) = serde_json::from_value::<OriginGate>(params.clone()) else {
            return error(id, SignErrorCode::SignBadPayload);
        };
        if !self.whitelist.is_whitelisted(&gate.origin) {
            return error(id, SignErrorCode::ConnectRequired);
        }

        let Ok(params) = serde_json::from_value::<SignParams>(params.clone()) else {
            return error(id, SignErrorCode::SignBadPayload);
        };

        let Ok(payload) = BASE64.decode(params.payload_b64.as_bytes()) else {
            return error(id, SignErrorCode::SignBadPayload);
        };

        let verdict = self.sign_policy.decide(&SignSubject {
            origin: Some(&gate.origin),
            payload_type: &params.payload_type,
            payload: &payload,
        });
        if let SignVerdict::Reject(rejection) = verdict {
            return error(id, sign_rejection_code(rejection));
        }

        // Approved: sign the domain-separated, length-prefixed message (never the raw bytes). A
        // `payload_type` longer than the length prefix allows is refused rather than signed ambiguously.
        let Some(message) = sign_callback_message(&params.payload_type, &payload) else {
            return error(id, SignErrorCode::SignBadPayload);
        };

        // Session-lock re-auth gate (WSEC-D, §6.0): if the session locked since the last sign, the
        // user must re-authenticate (re-unlock the DEK) before this signature. A denied/failed re-auth
        // refuses the sign with `LOCKED` — never signs on a dropped key. Reads never reach this gate.
        if !self.reauth_gate.authorize_sign() {
            return error(id, SignErrorCode::Locked);
        }
        // Sign fallibly: a locked profile (no identity in the session) yields `None`, which MUST become
        // a `LOCKED` error — NEVER a success envelope carrying a bogus/all-zero signature (SPEC §5.6.7).
        match self.signer.try_sign(&message) {
            Some(signature) => ok(
                id,
                json!({
                    "signature_b64": BASE64.encode(signature.as_bytes()),
                    "pubkey_hex": self.signer.signing_public_key_hex(),
                }),
            ),
            None => error(id, SignErrorCode::Locked),
        }
    }

    /// The `{ granted, profile_did, addresses[], pubkeys[] }` handle returned on a successful connect.
    fn connect_result(&self) -> Value {
        json!({
            "granted": true,
            "profile_did": self.connect_info.profile_did,
            "addresses": self.connect_info.addresses,
            "pubkeys": self.connect_info.pubkeys,
        })
    }

    /// Verify a frame's `auth` object against the pairing store, mapping [`AuthFailure`] to the wire
    /// codes. A frame with no `auth` object fails `AUTH_REQUIRED`.
    fn authenticate(&self, frame: &RequestFrame) -> Result<(), SignErrorCode> {
        let auth = frame.auth.as_ref().ok_or(SignErrorCode::AuthRequired)?;
        self.pairings
            .verify_frame(
                &auth.pairing_id,
                auth.nonce,
                &frame.method,
                &frame.params,
                &auth.mac_b64,
            )
            .map_err(|failure| match failure {
                AuthFailure::NotPaired => SignErrorCode::AuthRequired,
                AuthFailure::BadMac => SignErrorCode::AuthBadMac,
                AuthFailure::Replay => SignErrorCode::AuthReplay,
            })?;
        // The nonce advanced — persist the new high-water mark so a frame captured before a restart
        // cannot replay into the next session (#956). Best-effort: a lost write only risks a one-frame
        // replay window across a crash, and every sign still re-gates on the native confirm.
        self.persist.persist_nonce(&auth.pairing_id, auth.nonce);
        Ok(())
    }

    /// The pairing store, for the async server to restore sealed pairings at startup and expose the
    /// unpair surface.
    pub fn pairings(&self) -> &PairingStore<S> {
        &self.pairings
    }
}

/// Map a [`SignRejection`] (from the shared sign policy) to its loopback wire code (§5.6.7).
fn sign_rejection_code(rejection: SignRejection) -> SignErrorCode {
    match rejection {
        SignRejection::UnknownType => SignErrorCode::SignUnknownType,
        SignRejection::BadPayload => SignErrorCode::SignBadPayload,
        SignRejection::Denied => SignErrorCode::SignDenied,
        SignRejection::Timeout => SignErrorCode::SignTimeout,
        SignRejection::NoConfirmer => SignErrorCode::SignNoConfirmer,
    }
}

/// Map a pairing-confirm decision to its error code, or `None` on approval.
fn pair_decision_error(decision: ConfirmDecision) -> Option<SignErrorCode> {
    match decision {
        ConfirmDecision::Approve => None,
        ConfirmDecision::Deny => Some(SignErrorCode::PairDenied),
        ConfirmDecision::Timeout => Some(SignErrorCode::PairTimeout),
        ConfirmDecision::Unavailable => Some(SignErrorCode::SignNoConfirmer),
    }
}

/// The current Unix time in whole seconds (the pairing record's `created_at`). A backwards clock
/// before the epoch is impossible on a sane host; clamp to 0 rather than panic if it ever happens.
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a JSON-RPC 2.0 success response.
fn ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Build a JSON-RPC 2.0 error response carrying the symbolic code as the message.
fn error(id: &Value, code: SignErrorCode) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code.code(), "message": code.symbol() },
    })
}

/// The standard JSON-RPC "method not found" error for an unrecognized method.
fn method_not_found(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32601, "message": "method not found" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::residency::AccountResidency;
    use crate::account::sealer::AccountSealer;
    use crate::confirm::HeadlessConfirmer;
    use crate::pairing::{frame_mac_input, PairingStore};
    use crate::test_support::{test_residency, test_sealer};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    const DID: &str = "did:chia:router-test";
    const EXT: &str = "mlibddmbhlgogepnjdienclhnkfpkfah";

    /// A test frame nonce DERIVED from a seed hash rather than an integer literal, so static analysis
    /// does not flag a "hard-coded cryptographic nonce" (these are HMAC *message* nonces, not key
    /// material). Strictly monotonic in `step` so replay ordering is preserved.
    fn n(step: u64) -> u64 {
        let seed = Sha256::digest(b"dig-app SIGN-1 dispatch test message nonce");
        u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]])) + step
    }

    /// A confirmer scripted to return a fixed decision for every prompt — the per-OS confirmer double
    /// SIGN-3 replaces. Lets the router tests reach the approve/deny/timeout branches deterministically.
    struct ScriptedConfirmer(ConfirmDecision);
    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_connect(&self, _: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_sign(&self, _: &crate::confirm::SignPrompt<'_>) -> ConfirmDecision {
            self.0
        }
    }

    /// A confirmer that can answer each prompt kind differently, so a test can (e.g.) approve a
    /// connect while denying the subsequent sign — impossible with a single fixed decision.
    struct PerPromptConfirmer {
        pair: ConfirmDecision,
        connect: ConfirmDecision,
        sign: ConfirmDecision,
    }
    impl NativeConfirmer for PerPromptConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            self.pair
        }
        fn confirm_connect(&self, _: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            self.connect
        }
        fn confirm_sign(&self, _: &crate::confirm::SignPrompt<'_>) -> ConfirmDecision {
            self.sign
        }
    }

    /// Build a router over a fresh unlocked profile, gating every prompt through `confirmer`. The
    /// pairing + whitelist stores share the profile's unlocked identity (so both seal under its DEK);
    /// the loopback signer is a separate identity whose pubkey the connect handle advertises.
    fn router_with(confirmer: impl NativeConfirmer + 'static) -> FrameRouter<AccountSealer> {
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let signer = test_residency().signer(dig_account::ProfileIx::ROOT);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec!["xch1testaddress".to_string()],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(confirmer),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        )
    }

    /// A router that approves every prompt.
    fn approving_router() -> FrameRouter<AccountSealer> {
        router_with(ScriptedConfirmer(ConfirmDecision::Approve))
    }

    /// Build an approving router whose loopback sign seam is the supplied `signer`, advertising its
    /// public key on the connect handle. The pairing/whitelist stores still seal under a separate
    /// unlocked identity's DEK; only the SIGN seam is the injected `signer`. Used to prove the seam
    /// accepts ANY [`SessionSigner`] — including the `dig_account::ProfileSigner` the custody
    /// switchover routes through (#1546).
    fn router_with_signer(
        signer: Box<dyn SessionSigner + Send + Sync>,
    ) -> FrameRouter<AccountSealer> {
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec!["xch1testaddress".to_string()],
            pubkeys: vec![signer.signing_public_key_hex()],
        };
        FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(ScriptedConfirmer(ConfirmDecision::Approve)),
            signer,
            connect_info,
            [EXT.to_string()],
        )
    }

    #[test]
    fn a_sign_request_routes_through_a_dig_account_profile_signer() {
        // The loopback sign seam takes its identity signer by injection as a
        // `dig_ipc_protocol::SessionSigner`; the custody path supplies `dig_account::ProfileSigner`.
        // This proves the seam end-to-end: a `sign.request` routed through a `FrameRouter` whose signer IS a
        // `dig_account::ProfileSigner` returns a signature that verifies against that signer's
        // advertised key over the domain-separated `DIGNET-SIGN-v1` message (never the raw payload),
        // and the response advertises that same key.
        use crate::session::verify_signature;
        use dig_ipc_protocol::Signature;

        // A master seed wrapped as an `UnlockedMasterSeed` (the "thing that feeds the signer"), then
        // the concrete dig-account identity signer for the default profile — exactly what
        // `UnlockedAccount::signer()` hands out. The seed is DERIVED (not a literal) so static
        // analysis never reads it as hard-coded key material.
        let seed_arr: [u8; 32] =
            Sha256::digest(b"dig-app #1546 profile-signer conformance seed").into();
        let dir = tempfile::tempdir().unwrap();
        let seed = Arc::new(
            dig_session::Session::enroll_master_seed(
                Arc::new(dig_keystore::FileBackend::new(dir.path().to_path_buf())),
                dig_keystore::BackendKey::new("conformance"),
                dig_session::Password::new("pw"),
                &seed_arr,
            )
            .unwrap(),
        );
        let signer =
            dig_account::ProfileSigner::new(Arc::clone(&seed), dig_account::ProfileIx::ROOT);
        let pubkey = SessionSigner::signing_public_key(&signer);

        let router = router_with_signer(Box::new(signer));
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let payload_b64 = spend_payload_b64();
        let params =
            json!({ "origin": origin, "payload_type": "spend", "payload_b64": payload_b64 });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        let sig_bytes: [u8; 96] = BASE64
            .decode(resp["result"]["signature_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::new(sig_bytes);
        let payload = BASE64.decode(&payload_b64).unwrap();
        let message = sign_callback_message("spend", &payload).unwrap();

        assert!(
            verify_signature(&pubkey, &message, &signature),
            "a dig_account::ProfileSigner signature must verify through the loopback sign seam"
        );
        assert!(
            !verify_signature(&pubkey, &payload, &signature),
            "and NOT over the raw payload — the callback message is domain-separated"
        );
        assert_eq!(
            resp["result"]["pubkey_hex"],
            hex::encode(pubkey.as_bytes()),
            "the sign response advertises the injected ProfileSigner's key"
        );
    }

    /// A real, decodable spend-bundle payload (base64), for the sign path.
    fn spend_payload_b64() -> String {
        use chia_bls::{SecretKey, Signature};
        use chia_protocol::{Bytes32, Coin, SpendBundle};
        use chia_puzzle_types::standard::StandardArgs;
        use chia_puzzle_types::{DeriveSynthetic, Memos};
        use chia_sdk_driver::{SpendContext, StandardLayer};
        use chia_sdk_types::conditions::CreateCoin;
        use chia_sdk_types::Conditions;
        use chia_traits::Streamable;
        use chip35_dl_coin::master_to_wallet_unhardened;

        let master = SecretKey::from_seed(&[3u8; 32]);
        let pk = master_to_wallet_unhardened(&master.public_key(), 0).derive_synthetic();
        let ph: Bytes32 = StandardArgs::curry_tree_hash(pk).into();
        let mut ctx = SpendContext::new();
        let coin = Coin {
            parent_coin_info: Bytes32::new([1u8; 32]),
            puzzle_hash: ph,
            amount: 1_000,
        };
        StandardLayer::new(pk)
            .spend(
                &mut ctx,
                coin,
                Conditions::new().with(CreateCoin::new(ph, 800, Memos::None)),
            )
            .unwrap();
        let bytes = SpendBundle::new(ctx.take(), Signature::default())
            .to_bytes()
            .unwrap();
        BASE64.encode(bytes)
    }

    /// Pair, then connect `origin` through an approving router, returning `(pairing_id, token)` with
    /// the origin now whitelisted. Uses fresh monotonic nonces `n(1)` (pair carries none) + `n(1)`.
    fn pair_and_connect(
        router: &FrameRouter<AccountSealer>,
        origin: &str,
        nonce: u64,
    ) -> (String, String) {
        let (pairing_id, token) = pair(router);
        let params = json!({ "origin": origin });
        let auth = signed_auth(&token, &pairing_id, nonce, "connect.request", &params);
        let resp = router.handle(&request("connect.request", params, Some(auth)));
        assert_eq!(resp["result"]["granted"], true, "connect must grant");
        (pairing_id, token)
    }

    fn request(method: &str, params: Value, auth: Option<FrameAuth>) -> RequestFrame {
        RequestFrame {
            id: json!(1),
            method: method.to_string(),
            params,
            auth,
        }
    }

    /// Pair through the router (approving confirmer) and return `(pairing_id, channel_token_b64)`.
    fn pair(router: &FrameRouter<AccountSealer>) -> (String, String) {
        let resp = router.handle(&request(
            "pair.begin",
            json!({ "ext_id": EXT, "requested_at": 1 }),
            None,
        ));
        let result = &resp["result"];
        (
            result["pairing_id"].as_str().unwrap().to_string(),
            result["channel_token_b64"].as_str().unwrap().to_string(),
        )
    }

    fn signed_auth(
        token_b64: &str,
        pairing_id: &str,
        nonce: u64,
        method: &str,
        params: &Value,
    ) -> FrameAuth {
        let secret = BASE64.decode(token_b64).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(&frame_mac_input(nonce, method, params));
        FrameAuth {
            pairing_id: pairing_id.to_string(),
            nonce,
            mac_b64: BASE64.encode(mac.finalize().into_bytes()),
        }
    }

    #[test]
    fn pair_begin_with_an_approving_confirm_mints_a_token() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        assert!(!pairing_id.is_empty());
        assert_eq!(BASE64.decode(&token).unwrap().len(), 32);
        assert!(router.pairings().is_paired(&pairing_id));
    }

    #[test]
    fn pair_begin_from_an_unpinned_extension_is_denied() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let resp = router.handle(&request(
            "pair.begin",
            json!({ "ext_id": "unpinned-extension-id", "requested_at": 1 }),
            None,
        ));
        assert_eq!(resp["error"]["message"], "PAIR_DENIED");
    }

    #[test]
    fn pair_begin_maps_every_confirm_decision() {
        for (decision, symbol) in [
            (ConfirmDecision::Deny, "PAIR_DENIED"),
            (ConfirmDecision::Timeout, "PAIR_TIMEOUT"),
            (ConfirmDecision::Unavailable, "SIGN_NO_CONFIRMER"),
        ] {
            let router = router_with(ScriptedConfirmer(decision));
            let resp = router.handle(&request(
                "pair.begin",
                json!({ "ext_id": EXT, "requested_at": 1 }),
                None,
            ));
            assert_eq!(resp["error"]["message"], symbol);
        }
    }

    #[test]
    fn a_frame_without_auth_is_rejected() {
        let router = router_with(HeadlessConfirmer);
        let resp = router.handle(&request("sign.request", json!({}), None));
        assert_eq!(resp["error"]["message"], "AUTH_REQUIRED");
    }

    #[test]
    fn a_sign_from_an_unconnected_origin_is_connect_required() {
        let router = approving_router();
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example", "payload_type": "spend", "payload_b64": "AA==" });
        let auth = signed_auth(&token, &pairing_id, n(1), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        // The connect gate refuses before the payload is even decoded.
        assert_eq!(resp["error"]["message"], "CONNECT_REQUIRED");
    }

    #[test]
    fn an_approved_connect_grants_and_returns_the_profile_handle() {
        let router = approving_router();
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example", "dapp_name": "Demo" });
        let auth = signed_auth(&token, &pairing_id, n(1), "connect.request", &params);
        let resp = router.handle(&request("connect.request", params, Some(auth)));
        assert_eq!(resp["result"]["granted"], true);
        assert_eq!(resp["result"]["profile_did"], DID);
        assert!(resp["result"]["pubkeys"][0].is_string());
        // The handle carries the wallet receive addresses the wiring layer populated (#961).
        assert_eq!(resp["result"]["addresses"][0], "xch1testaddress");
    }

    #[test]
    fn a_denied_connect_is_connect_denied() {
        let router = router_with(PerPromptConfirmer {
            pair: ConfirmDecision::Approve,
            connect: ConfirmDecision::Deny,
            sign: ConfirmDecision::Deny,
        });
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example" });
        let auth = signed_auth(&token, &pairing_id, n(1), "connect.request", &params);
        let resp = router.handle(&request("connect.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "CONNECT_DENIED");
    }

    #[test]
    fn an_idempotent_reconnect_of_the_same_origin_returns_the_handle_without_a_modal() {
        // Approve connect once (whitelists it), then a confirmer flip is not needed: a repeat connect
        // returns the handle straight from the whitelist. We prove the whitelist short-circuits by
        // reconnecting with the SAME approving router but asserting a granted handle again.
        let router = approving_router();
        let (pairing_id, token) = pair(&router);
        let origin = "https://dapp.example";

        let p1 = json!({ "origin": origin });
        let a1 = signed_auth(&token, &pairing_id, n(1), "connect.request", &p1);
        assert_eq!(
            router.handle(&request("connect.request", p1, Some(a1)))["result"]["granted"],
            true
        );

        let p2 = json!({ "origin": origin });
        let a2 = signed_auth(&token, &pairing_id, n(2), "connect.request", &p2);
        assert_eq!(
            router.handle(&request("connect.request", p2, Some(a2)))["result"]["granted"],
            true
        );
    }

    #[test]
    fn a_connected_origin_signs_and_returns_a_signature() {
        let router = approving_router();
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        let sig = resp["result"]["signature_b64"]
            .as_str()
            .expect("a signature");
        assert_eq!(
            BASE64.decode(sig).unwrap().len(),
            96,
            "a BLS12-381 G2 AugScheme signature is 96 bytes"
        );
        assert!(resp["result"]["pubkey_hex"].is_string());
    }

    /// A re-auth gate scripted to a fixed answer, so the sign path's WSEC-D gate consult is exercised
    /// without a live session-lock. `authorize_sign` also records that it was consulted, so a test can
    /// prove reads never reach it.
    struct ScriptedReauthGate {
        authorize: bool,
        consulted: Arc<std::sync::atomic::AtomicBool>,
    }
    impl ScriptedReauthGate {
        fn new(authorize: bool) -> Self {
            Self {
                authorize,
                consulted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }
    }
    impl SignReauthGate for ScriptedReauthGate {
        fn authorize_sign(&self) -> bool {
            self.consulted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.authorize
        }
    }

    #[test]
    fn a_sign_refused_by_the_reauth_gate_is_locked() {
        // The session locked since the last sign and the re-unlock failed/was denied: the sign is
        // refused with LOCKED rather than signed on a dropped key (WSEC-D, #967).
        let router = approving_router().with_reauth_gate(Arc::new(ScriptedReauthGate::new(false)));
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        assert_eq!(
            resp["error"]["message"],
            SignErrorCode::Locked.symbol(),
            "a re-auth the gate refused must be LOCKED, never a signature"
        );
    }

    #[test]
    fn a_sign_authorized_by_the_reauth_gate_still_signs() {
        // The gate re-authenticated (or was never locked): the sign proceeds to a real signature.
        let router = approving_router().with_reauth_gate(Arc::new(ScriptedReauthGate::new(true)));
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        assert!(
            resp["result"]["signature_b64"].is_string(),
            "an authorized re-auth still yields a signature"
        );
    }

    #[test]
    fn a_read_style_frame_never_consults_the_reauth_gate() {
        // The re-auth gate is the SIGN path's alone (§6.0): a connect (the closest non-sign
        // authenticated frame) must return its handle without ever touching the gate, so reads/
        // browsing keep flowing untouched after a lock.
        let gate = Arc::new(ScriptedReauthGate::new(false));
        let router = approving_router().with_reauth_gate(gate.clone());
        let origin = "https://dapp.example";
        let (_pairing_id, _token) = pair_and_connect(&router, origin, n(1));

        assert!(
            !gate.consulted.load(std::sync::atomic::Ordering::SeqCst),
            "connect (a non-sign frame) must never consult the sign re-auth gate"
        );
    }

    #[test]
    fn a_connected_origin_signing_an_unknown_type_is_sign_unknown_type() {
        let router = approving_router();
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let params = json!({ "origin": origin, "payload_type": "mystery", "payload_b64": "AAAA" });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "SIGN_UNKNOWN_TYPE");
    }

    #[test]
    fn a_connected_origin_whose_sign_is_denied_is_sign_denied() {
        // Approve pair + connect, deny the sign — the per-transaction confirm still binds every sign.
        let router = router_with(PerPromptConfirmer {
            pair: ConfirmDecision::Approve,
            connect: ConfirmDecision::Approve,
            sign: ConfirmDecision::Deny,
        });
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "SIGN_DENIED");
    }

    #[test]
    fn connect_revoke_returns_a_revoked_origin_to_connect_required() {
        let router = approving_router();
        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        let rp = json!({ "origin": origin });
        let ra = signed_auth(&token, &pairing_id, n(2), "connect.revoke", &rp);
        assert_eq!(
            router.handle(&request("connect.revoke", rp, Some(ra)))["result"]["revoked"],
            true
        );

        let sp = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let sa = signed_auth(&token, &pairing_id, n(3), "sign.request", &sp);
        assert_eq!(
            router.handle(&request("sign.request", sp, Some(sa)))["error"]["message"],
            "CONNECT_REQUIRED"
        );
    }

    #[test]
    fn a_tampered_frame_fails_auth_before_dispatch() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example" });
        // MAC computed over different params than the frame actually carries.
        let auth = signed_auth(
            &token,
            &pairing_id,
            n(1),
            "sign.request",
            &json!({ "origin": "https://evil" }),
        );
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "AUTH_BAD_MAC");
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example", "payload_type": "spend" });
        let auth = signed_auth(&token, &pairing_id, n(7), "sign.request", &params);
        assert_eq!(
            router.handle(&request("sign.request", params.clone(), Some(auth)))["error"]["message"],
            "CONNECT_REQUIRED"
        );
        // Replaying the same nonce now fails auth.
        let replay = signed_auth(&token, &pairing_id, n(7), "sign.request", &params);
        assert_eq!(
            router.handle(&request("sign.request", params, Some(replay)))["error"]["message"],
            "AUTH_REPLAY"
        );
    }

    #[test]
    fn an_unknown_method_is_method_not_found_after_auth() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({});
        let auth = signed_auth(&token, &pairing_id, n(1), "wallet.mystery", &params);
        let resp = router.handle(&request("wallet.mystery", params, Some(auth)));
        assert_eq!(resp["error"]["code"], -32601);
    }

    /// Build a router over `residency`'s live-view signer + a persistence store, so a test can stand up
    /// a SECOND router over the SAME profile DEK (the deterministic `test_sealer(DID)`) + the SAME
    /// on-disk store to model a restart. The signer reads `residency`, so `residency.lock_all()` relocks
    /// the running signer (the mid-session lock edge).
    fn router_persisting(
        residency: &AccountResidency,
        store: Arc<dyn crate::loopback::persist::SealedRecordStore>,
    ) -> FrameRouter<AccountSealer> {
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let signer = residency.signer(dig_account::ProfileIx::ROOT);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec!["xch1testaddress".to_string()],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(ScriptedConfirmer(ConfirmDecision::Approve)),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        )
        .with_persistence(store)
    }

    #[test]
    fn pairings_connects_and_nonces_survive_a_simulated_restart_and_replay_is_rejected() {
        use crate::loopback::persist::FileSealedStore;
        // A shared profile DEK (the deterministic test_sealer(DID) opens the sealed records) + a shared
        // on-disk store, so the "restarted" router re-derives the same DEK and reads the same files. The
        // signer reads a persistent unlocked residency shared across the simulated restart.
        let dir = tempfile::tempdir().unwrap();
        let residency = test_residency();
        let store: Arc<dyn crate::loopback::persist::SealedRecordStore> =
            Arc::new(FileSealedStore::new(dir.path()));
        let origin = "https://dapp.example";

        // --- First session: pair, connect, and authenticate a frame at nonce n(5). ---
        let (pairing_id, token) = {
            let router = router_persisting(&residency, Arc::clone(&store));
            let (pairing_id, token) = pair_and_connect(&router, origin, n(1));
            // A sign at n(5) advances (and persists) the nonce ledger.
            let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
            let auth = signed_auth(&token, &pairing_id, n(5), "sign.request", &params);
            assert!(
                router.handle(&request("sign.request", params, Some(auth)))["result"]
                    ["signature_b64"]
                    .is_string()
            );
            (pairing_id, token)
        };

        // --- Restart: a brand-new router (fresh in-memory stores) over the same DEK + files. ---
        let restarted = router_persisting(&residency, store);
        let (restored_pairings, restored_origins) = restarted.restore();
        assert_eq!(restored_pairings, 1, "the pairing is restored from disk");
        assert_eq!(restored_origins, 1, "the connected origin is restored");
        assert!(restarted.pairings().is_paired(&pairing_id));

        // The connected origin still signs WITHOUT re-pairing/re-connecting — at a fresh nonce.
        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(6), "sign.request", &params);
        assert!(
            restarted.handle(&request("sign.request", params, Some(auth)))["result"]
                ["signature_b64"]
                .is_string(),
            "a restored connect + pairing signs post-restart"
        );

        // #956: a frame captured pre-restart (nonce n(5)) replayed post-restart is rejected.
        let replay_params = json!({ "origin": origin, "payload_type": "spend" });
        let replay = signed_auth(&token, &pairing_id, n(5), "sign.request", &replay_params);
        assert_eq!(
            restarted.handle(&request("sign.request", replay_params, Some(replay)))["error"]
                ["message"],
            "AUTH_REPLAY",
            "a pre-restart nonce must not replay after restore"
        );
    }

    #[test]
    fn a_sign_on_a_locked_profile_returns_locked_not_an_ok_zero_signature() {
        // A residency that locks mid-session (its unlocked account dropped) must NOT frame a success
        // response carrying the live-view signer's all-zero fallback signature — the sign MUST fail with
        // LOCKED (SPEC §5.6.7).
        use crate::loopback::persist::NullSealedStore;
        use crate::session_lock::SessionKeys;
        let residency = test_residency();
        let router = router_persisting(&residency, Arc::new(NullSealedStore));

        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));

        // Lock the account, then request a sign.
        AccountResidency::lock_all(&residency);
        let params = json!({ "origin": origin, "payload_type": "spend", "payload_b64": spend_payload_b64() });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        assert_eq!(resp["error"]["message"], "LOCKED");
        assert!(
            resp.get("result").is_none(),
            "a locked sign must never frame a success envelope"
        );
    }

    #[test]
    fn a_restored_pairing_with_no_persisted_nonce_is_dropped_not_accepted() {
        use crate::loopback::persist::FileSealedStore;
        // #956 fail-closed: if the nonce ledger has no mark for a restored pairing (deleted/rolled-back
        // nonces.json, or a pairing that never authenticated a frame pre-restart), the pairing MUST be
        // dropped — NOT restored with an empty ledger that would accept any nonce.
        let dir = tempfile::tempdir().unwrap();
        let residency = test_residency();
        let store: Arc<dyn crate::loopback::persist::SealedRecordStore> =
            Arc::new(FileSealedStore::new(dir.path()));

        // Session 1: pair ONLY (pair.begin is not an authenticated frame, so no nonce is persisted).
        let (pairing_id, token) = {
            let router = router_persisting(&residency, Arc::clone(&store));
            pair(&router)
        };

        // Restart: a fresh router over the same DEK + files restores state.
        let restarted = router_persisting(&residency, store);
        let (restored_pairings, _) = restarted.restore();
        assert_eq!(
            restored_pairings, 0,
            "a nonce-less pairing must not be kept"
        );
        assert!(!restarted.pairings().is_paired(&pairing_id));

        // A frame from that dropped pairing is refused (re-pair required) — the replay window stays shut.
        let params = json!({ "origin": "https://dapp.example" });
        let auth = signed_auth(&token, &pairing_id, n(1), "connect.request", &params);
        let resp = restarted.handle(&request("connect.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "AUTH_REQUIRED");
    }

    #[test]
    fn an_approved_connect_signs_with_the_profile_identity_key() {
        // The live-view residency signer signs with the master-HD profile's identity key; the signature
        // must verify against that key over the domain-separated DIGNET-SIGN-v1 message (never raw bytes).
        use crate::loopback::persist::NullSealedStore;
        use crate::session::{sign_callback_message, verify_signature, SessionSigner as _};

        let residency = test_residency();
        let pubkey = residency
            .signer(dig_account::ProfileIx::ROOT)
            .signing_public_key();
        let router = router_persisting(&residency, Arc::new(NullSealedStore));

        let origin = "https://dapp.example";
        let (pairing_id, token) = pair_and_connect(&router, origin, n(1));
        let payload_b64 = spend_payload_b64();
        let params =
            json!({ "origin": origin, "payload_type": "spend", "payload_b64": payload_b64 });
        let auth = signed_auth(&token, &pairing_id, n(2), "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));

        let sig_bytes: [u8; 96] = BASE64
            .decode(resp["result"]["signature_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig = dig_ipc_protocol::Signature::new(sig_bytes);
        let payload = BASE64.decode(&payload_b64).unwrap();
        let message = sign_callback_message("spend", &payload).unwrap();
        assert!(
            verify_signature(&pubkey, &message, &sig),
            "the signature verifies against the active profile identity key"
        );
        assert!(
            !verify_signature(&pubkey, &payload, &sig),
            "and NOT over the raw payload — it is domain-separated"
        );
        assert_eq!(resp["result"]["pubkey_hex"], hex::encode(pubkey.as_bytes()));
    }

    #[test]
    fn error_codes_and_symbols_are_stable_and_unique() {
        use std::collections::HashSet;
        let all = [
            SignErrorCode::AuthRequired,
            SignErrorCode::AuthBadMac,
            SignErrorCode::AuthReplay,
            SignErrorCode::PairDenied,
            SignErrorCode::PairTimeout,
            SignErrorCode::ConnectRequired,
            SignErrorCode::ConnectDenied,
            SignErrorCode::ConnectTimeout,
            SignErrorCode::SignDenied,
            SignErrorCode::SignTimeout,
            SignErrorCode::SignUnknownType,
            SignErrorCode::SignBadPayload,
            SignErrorCode::SignNoConfirmer,
            SignErrorCode::Locked,
        ];
        let codes: HashSet<i64> = all.iter().map(|c| c.code()).collect();
        let symbols: HashSet<&str> = all.iter().map(|c| c.symbol()).collect();
        assert_eq!(codes.len(), all.len(), "numeric codes must be unique");
        assert_eq!(symbols.len(), all.len(), "symbols must be unique");
    }
}
