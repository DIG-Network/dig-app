//! The JSON-RPC frame router for the APP-SIGN loopback channel (SIGN-1, `SPEC.md` §5.6,
//! **security-critical**).
//!
//! This is the pure, synchronous core the async [`super::server`] feeds parsed frames into: given a
//! request frame it applies the per-frame authentication (§5.6.3) and returns the JSON-RPC response.
//! Keeping it transport-free is what makes the security-critical logic — the auth gate, the pairing
//! handshake, the error taxonomy — exhaustively unit-testable without a socket.
//!
//! ## What SIGN-1 routes
//!
//! - **`pair.begin`** — fully implemented: a native pairing confirm (§5.6.1) then mint + seal + persist
//!   the channel token (§5.6.3). This is the ONE frame that carries no `auth` (it establishes it).
//! - **every other frame** — authenticated first (`AUTH_REQUIRED` / `AUTH_BAD_MAC` / `AUTH_REPLAY`),
//!   THEN dispatched. `connect.request` and `sign.request` are SIGN-1 stubs: they prove the
//!   authenticated transport works and return the honest §5.6.7 code for a transport-only build — the
//!   dapp whitelist (SIGN-2) and the per-OS sign confirm (SIGN-3) fill in the real behaviour against
//!   this same seam.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::confirm::{ConfirmDecision, NativeConfirmer, PairPrompt};
use crate::pairing::{AuthFailure, PairingStore};
use crate::profiles::sealer::ProfileSealer;

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

/// The frame router: authenticates every frame against the [`PairingStore`] and dispatches it,
/// raising the native confirm (§5.6.1) through the [`NativeConfirmer`] where a decision is required.
///
/// Generic over the [`ProfileSealer`] so the pairing store seals under the active profile's DEK
/// (NC-2). Shared behind an `Arc` by the async server; every method takes `&self`.
pub struct FrameRouter<S: ProfileSealer> {
    pairings: PairingStore<S>,
    confirmer: Box<dyn NativeConfirmer>,
    /// The extension ids permitted to `pair.begin` — the same pinned set the `Origin` guard enforces.
    allowed_ext_ids: Vec<String>,
}

impl<S: ProfileSealer> FrameRouter<S> {
    /// Build a router over `pairings`, gating privileged actions through `confirmer` and accepting
    /// pairing requests only from `allowed_ext_ids`.
    pub fn new(
        pairings: PairingStore<S>,
        confirmer: Box<dyn NativeConfirmer>,
        allowed_ext_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            pairings,
            confirmer,
            allowed_ext_ids: allowed_ext_ids.into_iter().collect(),
        }
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
            Ok(outcome) => ok(
                id,
                json!({
                    "pairing_id": outcome.pairing_id,
                    "channel_token_b64": outcome.channel_token_b64,
                }),
            ),
            // Sealing fails only when the active profile is locked — surface it as LOCKED.
            Err(_) => error(id, SignErrorCode::Locked),
        }
    }

    /// Every non-pairing frame: authenticate it, then dispatch. SIGN-1 answers the `connect`/`sign`
    /// frames with the honest transport-only code (the real whitelist + sign land in SIGN-2/3).
    fn handle_authenticated(&self, frame: &RequestFrame) -> Value {
        if let Err(code) = self.authenticate(frame) {
            return error(&frame.id, code);
        }
        match frame.method.as_str() {
            // A sign needs a whitelisted origin first; SIGN-1 holds no whitelist, so every origin is
            // un-connected. SIGN-2 adds the whitelist check + the decode/confirm/sign path.
            "sign.request" => error(&frame.id, SignErrorCode::ConnectRequired),
            // The connect modal is a native confirm; SIGN-1 ships only the headless (fail-closed)
            // confirmer, so connect cannot be granted yet. SIGN-3 wires the per-OS modal.
            "connect.request" => error(&frame.id, SignErrorCode::SignNoConfirmer),
            _ => method_not_found(&frame.id),
        }
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
            })
    }

    /// The pairing store, for the async server to restore sealed pairings at startup and expose the
    /// unpair surface.
    pub fn pairings(&self) -> &PairingStore<S> {
        &self.pairings
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
    use crate::confirm::HeadlessConfirmer;
    use crate::keystore::IdentitySecrets;
    use crate::pairing::{frame_mac_input, PairingStore};
    use crate::profiles::keystore_sealer::{KeystoreSealer, UnlockedIdentities};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use dig_keystore::KdfParams;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    const DID: &str = "did:chia:router-test";
    const EXT: &str = "mlibddmbhlgogepnjdienclhnkfpkfah";

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

    fn pairing_store() -> PairingStore<KeystoreSealer> {
        let identities = UnlockedIdentities::new();
        identities.unlock(DID, IdentitySecrets::generate());
        PairingStore::new(KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST), DID)
    }

    fn router_with(confirmer: impl NativeConfirmer + 'static) -> FrameRouter<KeystoreSealer> {
        FrameRouter::new(
            pairing_store(),
            Box::new(confirmer),
            [EXT.to_string()],
        )
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
    fn pair(router: &FrameRouter<KeystoreSealer>) -> (String, String) {
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

    fn signed_auth(token_b64: &str, pairing_id: &str, nonce: u64, method: &str, params: &Value) -> FrameAuth {
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
    fn a_frame_with_a_valid_mac_authenticates_and_reaches_the_stub() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example", "payload_type": "spend" });
        let auth = signed_auth(&token, &pairing_id, 1, "sign.request", &params);
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        // Authenticated, then the SIGN-1 sign stub: a sign needs a connected origin first.
        assert_eq!(resp["error"]["message"], "CONNECT_REQUIRED");
    }

    #[test]
    fn connect_request_authenticates_then_reports_no_confirmer() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example" });
        let auth = signed_auth(&token, &pairing_id, 1, "connect.request", &params);
        let resp = router.handle(&request("connect.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "SIGN_NO_CONFIRMER");
    }

    #[test]
    fn a_tampered_frame_fails_auth_before_dispatch() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example" });
        // MAC computed over different params than the frame actually carries.
        let auth = signed_auth(&token, &pairing_id, 1, "sign.request", &json!({ "origin": "https://evil" }));
        let resp = router.handle(&request("sign.request", params, Some(auth)));
        assert_eq!(resp["error"]["message"], "AUTH_BAD_MAC");
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let router = router_with(ScriptedConfirmer(ConfirmDecision::Approve));
        let (pairing_id, token) = pair(&router);
        let params = json!({ "origin": "https://dapp.example", "payload_type": "spend" });
        let auth = signed_auth(&token, &pairing_id, 7, "sign.request", &params);
        assert_eq!(
            router.handle(&request("sign.request", params.clone(), Some(auth)))["error"]["message"],
            "CONNECT_REQUIRED"
        );
        // Replaying nonce 7 now fails auth.
        let replay = signed_auth(&token, &pairing_id, 7, "sign.request", &params);
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
        let auth = signed_auth(&token, &pairing_id, 1, "wallet.mystery", &params);
        let resp = router.handle(&request("wallet.mystery", params, Some(auth)));
        assert_eq!(resp["error"]["code"], -32601);
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
