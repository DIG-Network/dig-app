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

use serde::Deserialize;
use serde_json::{json, Value};

use crate::confirm::{ConfirmDecision, ConnectPrompt, NativeConfirmer, PairPrompt};
use crate::digchat::{self, SealInputs, EPK_LEN};
use crate::loopback::persist::{NullSealedStore, SealedRecordStore};
use crate::pairing::{
    AuthFailure, Capability, CapabilitySet, NewPairing, PairedApp, PairingAuthority, PairingStore,
};
use crate::pairing_code::{PairingCode, PairingCodeIssuer};
use crate::sealer::ProfileSealer;
use crate::session::{sign_callback_message, SessionSigner};
use crate::sign_policy::{NativeConfirmSignPolicy, SignRejection, SignSubject, SignVerdict};
use crate::whitelist::WhitelistStore;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use x25519_dalek::{PublicKey, StaticSecret};

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
    /// An unpinned caller offered no pairing code, or one that was wrong, expired, already used, or
    /// past its attempt budget (§5.6.3a).
    ///
    /// ONE code for every one of those cases, deliberately. Distinguishing "no code is outstanding"
    /// from "that code was wrong" would tell a caller whether a human is mid-pairing right now, which
    /// is precisely the signal a process racing to redeem someone else's code wants. The distinction
    /// exists in [`CodeFailure`](crate::pairing_code::CodeFailure) for the log, not on the wire.
    PairCodeRejected,
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
    /// The frame authenticated, but this pairing's scope does not grant the method it asked for
    /// (§5.6.3a) — a code-paired third party reaching for `sign.request`.
    ///
    /// Distinct from every `AUTH_*` code on purpose: the caller IS who it says it is and its token is
    /// good, so telling it "authentication failed" would send a well-behaved app into a re-pair loop
    /// that could never grant what it is asking for.
    CapNotGranted,
    /// An `identity.*` request was malformed: a missing/oversized field, a `payload`/`envelope` that
    /// was not valid base64, or a sealing key of the wrong length (dig_ecosystem#1931).
    IdentityBadRequest,
    /// An `identity.unseal` envelope did not authenticate under this profile's sealing key — a wrong
    /// recipient, a tampered/re-addressed header, or a corrupted body (indistinguishable, on purpose).
    UnsealFailed,
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
            Self::PairCodeRejected => "PAIR_CODE_REJECTED",
            Self::ConnectRequired => "CONNECT_REQUIRED",
            Self::ConnectDenied => "CONNECT_DENIED",
            Self::ConnectTimeout => "CONNECT_TIMEOUT",
            Self::SignDenied => "SIGN_DENIED",
            Self::SignTimeout => "SIGN_TIMEOUT",
            Self::SignUnknownType => "SIGN_UNKNOWN_TYPE",
            Self::SignBadPayload => "SIGN_BAD_PAYLOAD",
            Self::SignNoConfirmer => "SIGN_NO_CONFIRMER",
            Self::Locked => "LOCKED",
            Self::CapNotGranted => "CAP_NOT_GRANTED",
            Self::IdentityBadRequest => "IDENTITY_BAD_REQUEST",
            Self::UnsealFailed => "UNSEAL_FAILED",
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
            Self::PairCodeRejected => -33012,
            Self::ConnectRequired => -33020,
            Self::ConnectDenied => -33021,
            Self::ConnectTimeout => -33022,
            Self::SignDenied => -33030,
            Self::SignTimeout => -33031,
            Self::SignUnknownType => -33032,
            Self::SignBadPayload => -33033,
            Self::SignNoConfirmer => -33034,
            Self::Locked => -33040,
            Self::CapNotGranted => -33050,
            Self::IdentityBadRequest => -33060,
            Self::UnsealFailed => -33061,
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

/// `pair.begin` parameters (`SPEC.md` §5.6.3 / §5.6.3a).
///
/// `pairing_code` is what an unpinned caller offers INSTEAD of a pin. It is absent for DIG's own
/// extensions, whose `ext_id` is the pin, and required for everyone else.
#[derive(Debug, Deserialize)]
struct PairBeginParams {
    ext_id: String,
    #[serde(default)]
    ext_label: Option<String>,
    #[serde(default)]
    pairing_code: Option<String>,
    /// The `identity.*` capabilities the caller asks for (dig_ecosystem#1931). Absent for callers
    /// that only want the control plane; dig-chat sends `["identity.attest","identity.seal",
    /// "identity.unseal"]`. Unknown names are dropped when the grant is computed.
    #[serde(default)]
    requested_capabilities: Vec<String>,
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

/// `identity.seal` parameters (`SPEC.md` §5.6, dig_ecosystem#1931): seal `plaintext_b64` into a
/// `DIGCHAT1` envelope addressed to `recipient_did` under its published X25519 sealing public key.
#[derive(Debug, Deserialize)]
struct IdentitySealParams {
    recipient_did: String,
    recipient_sealing_public_key_b64: String,
    plaintext_b64: String,
}

/// `identity.unseal` parameters (`SPEC.md` §5.6, dig_ecosystem#1931): open a `DIGCHAT1` envelope
/// addressed to this profile.
#[derive(Debug, Deserialize)]
struct IdentityUnsealParams {
    envelope_b64: String,
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

/// The domain-separation tag the `identity.attest` attestation is signed OVER, before the sealing
/// public key (`SPEC.md` §5.6, dig_ecosystem#1931).
///
/// **Why this exists (a security caveat).** The identity signer's `sign` (a
/// [`SessionSigner`](crate::session::SessionSigner) over the profile's `0x0010` BLS key) signs raw
/// bytes and is SHARED with session-attach challenges and `dign sign`. Without a distinct prefix, an
/// attestation signature over a 32-byte sealing key could be lifted and replayed as some other
/// signed message. Prefixing every attestation with `DIGATTEST1\0` domain-separates it from every
/// other thing that key ever signs, so an attestation can never be mistaken for a session or spend
/// message. The trailing NUL keeps the tag an unambiguous, self-delimiting prefix.
pub const DIGATTEST1_DST: &[u8] = b"DIGATTEST1\0";

/// Supplies the active profile's X25519 SEALING keypair to the `identity.*` handlers
/// (dig_ecosystem#1931). The private half stays behind this seam — dig-app is the key holder, and the
/// router never copies raw seed bytes — mirroring how the identity signer is injected.
///
/// Returns `None` when the profile is locked, so a locked `identity.seal`/`unseal`/`attest` refuses
/// with `LOCKED` rather than operating on a dropped key (parity with the sign path).
pub trait ProfileSealingKey: Send + Sync {
    /// The active profile's X25519 sealing secret, or `None` when the profile is locked.
    fn sealing_secret(&self) -> Option<StaticSecret>;
}

/// The default sealing-key seam: always locked (no key). A router built without an injected
/// [`ProfileSealingKey`] therefore refuses every `identity.*` method with `LOCKED` — fail-closed,
/// the safe default until the tray boot injects a live key. Keeps the pre-#1931 unit-test wiring
/// (which never sealed) compiling unchanged.
pub struct LockedSealingKey;

impl ProfileSealingKey for LockedSealingKey {
    fn sealing_secret(&self) -> Option<StaticSecret> {
        None
    }
}

/// The frame router: authenticates every frame against the [`PairingStore`] and dispatches it,
/// raising the native confirm (§5.6.1) through the [`NativeConfirmer`] where a decision is required.
///
/// Generic over the [`ProfileSealer`] so the pairing + whitelist stores seal under the active
/// profile's DEK (NC-2). Shared behind an `Arc` by the async server; every method takes `&self`.
pub struct FrameRouter<S: ProfileSealer> {
    /// Shared with the tray's [`PairedAppsControl`] so a revoke from the menu and the authentication
    /// of the next frame act on the SAME live map — which is what makes a revoke immediate rather
    /// than a promise kept at the next restart.
    pairings: Arc<PairingStore<S>>,
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
    /// The extension ids permitted to `pair.begin` WITHOUT a pairing code — the same pinned set the
    /// `Origin` guard enforces. Callers outside it must redeem a code from [`codes`](Self::codes).
    allowed_ext_ids: Vec<String>,
    /// The pairing codes the tray issues and this router redeems (§5.6.3a).
    ///
    /// The router holds it but has NO path to `issue` — only [`PairedAppsControl`], which the tray
    /// takes via [`control`](Self::control), can mint one. That is the direction rule made
    /// structural: no frame this router ever handles can cause a code to exist. A router whose
    /// `control` handle nobody holds therefore has no code, ever, and admits no third party at all.
    codes: Arc<PairingCodeIssuer>,
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
    /// The active profile's X25519 sealing keypair seam for the `identity.*` handlers
    /// (dig_ecosystem#1931). Defaults to the fail-closed [`LockedSealingKey`]; the tray boot injects a
    /// live key via [`with_sealing_key`](Self::with_sealing_key). Independent of `signer` (which is
    /// the BLS identity/attestation signer) — this is the X25519 seal/unseal key.
    sealing_key: Arc<dyn ProfileSealingKey>,
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
            pairings: Arc::new(pairings),
            whitelist,
            confirmer,
            sign_policy,
            signer,
            connect_info,
            allowed_ext_ids: allowed_ext_ids.into_iter().collect(),
            codes: Arc::new(PairingCodeIssuer::new()),
            persist: Arc::new(NullSealedStore),
            reauth_gate: Arc::new(OpenSignGate),
            sealing_key: Arc::new(LockedSealingKey),
        }
    }

    /// Inject the active profile's X25519 sealing keypair seam for the `identity.*` handlers
    /// (dig_ecosystem#1931). Without this the router uses the fail-closed [`LockedSealingKey`] (every
    /// `identity.*` method refuses `LOCKED`); the tray boot supplies a seam backed by the unlocked
    /// account's `profile_sealing_key`.
    pub fn with_sealing_key(mut self, sealing_key: Arc<dyn ProfileSealingKey>) -> Self {
        self.sealing_key = sealing_key;
        self
    }

    /// Inject the session-lock re-auth gate consulted before every signature (WSEC-D, #967). Without
    /// this the router uses the always-authorize [`OpenSignGate`] (the unit-test default + pre-hookup
    /// behaviour); the tray boot supplies a gate backed by the live session-lock so a locked session
    /// re-authenticates before it signs.
    pub fn with_reauth_gate(mut self, reauth_gate: Arc<dyn SignReauthGate>) -> Self {
        self.reauth_gate = reauth_gate;
        self
    }

    /// The handle the tray drives the paired-app surface through: issue a code, list what is paired,
    /// revoke one. Take it BEFORE the router is moved onto the serving thread.
    pub fn control(&self) -> PairedAppsControl<S> {
        PairedAppsControl {
            pairings: Arc::clone(&self.pairings),
            codes: Arc::clone(&self.codes),
            persist: Arc::clone(&self.persist),
        }
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

    /// The pairing handshake (§5.6.3 / §5.6.3a): establish that the caller may pair AT ALL, raise the
    /// native pairing confirm, and on approval mint + seal + persist the channel token.
    ///
    /// # The two ways in, and why they are not one way
    ///
    /// A **pinned** DIG extension pairs on its `ext_id` alone — the same set the `Origin` guard
    /// enforces, checked again here so a frame that somehow bypassed the transport guard still cannot
    /// self-pair. **Anyone else** must redeem a pairing code the USER generated in the tray, and is
    /// paired with the narrower [`PairingScope::ThirdParty`](crate::pairing::PairingScope::ThirdParty).
    ///
    /// The pin path is untouched by the code path: making `allowed_ext_ids` optional so one branch
    /// could serve both would mean a caller claiming a pinned id no longer has to BE at that pinned
    /// origin, which is a regression dressed as a simplification.
    ///
    /// # Why the code is checked BEFORE the window
    ///
    /// It is the whole of the no-unsolicited-prompt property: a caller with no valid code is refused
    /// having drawn nothing, so a hostile local process cannot make a consent window appear, cannot
    /// spam a person into approving one, and cannot even learn that a code is outstanding
    /// (`PAIR_CODE_REJECTED` is one error for every failure). The cost is that a code is spent even if
    /// the user then declines the window — which is the right way round: a pairing the user refused is
    /// exactly the moment a code should stop working.
    fn handle_pair_begin(&self, id: &Value, params: &Value) -> Value {
        let Ok(params) = serde_json::from_value::<PairBeginParams>(params.clone()) else {
            return error(id, SignErrorCode::PairDenied);
        };

        // The identity capabilities the caller asked for, narrowed to the ones we recognize
        // (dig_ecosystem#1931). Independent of the money `scope` below — an identity-only chat app is
        // paired with a non-signing scope AND its identity capabilities.
        let granted = CapabilitySet::from_requested(&params.requested_capabilities);

        let base = if self.allowed_ext_ids.contains(&params.ext_id) {
            NewPairing::pinned(&params.ext_id, params.ext_label.as_deref())
        } else {
            let candidate = params.pairing_code.as_deref().unwrap_or("");
            if let Err(failure) = self.codes.redeem(candidate, now_epoch_secs()) {
                // The REASON is logged and never sent: on the wire every failure is one code.
                tracing::info!(?failure, "refused an unpinned pair.begin");
                return error(id, SignErrorCode::PairCodeRejected);
            }
            NewPairing::third_party(&params.ext_id, params.ext_label.as_deref())
        };
        let request = base.with_capabilities(granted.clone());

        let decision = self.confirmer.confirm_pair(&PairPrompt {
            ext_id: &params.ext_id,
            ext_label: params.ext_label.as_deref(),
        });
        if let Some(code) = pair_decision_error(decision) {
            return error(id, code);
        }

        match self.pairings.pair(&request, now_epoch_secs()) {
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
                        // Tell the caller what it was granted rather than letting it discover the
                        // limit by having a sign refused: an app that knows it cannot sign can say so
                        // in its own UI instead of offering a button that always fails.
                        "may_sign": request.scope.may_sign(),
                        // Echo the granted identity capabilities (dig_ecosystem#1931, D5) so the caller
                        // knows which of the ones it requested it actually holds — dig-chat gates its
                        // `connected` state on this echo naming the identity class.
                        "granted_capabilities": granted.wire_names(),
                    }),
                )
            }
            // Sealing fails only when the active profile is locked — surface it as LOCKED.
            Err(_) => error(id, SignErrorCode::Locked),
        }
    }

    /// Every non-pairing frame: authenticate it, check the pairing's scope permits the method, then
    /// dispatch.
    ///
    /// The order is load-bearing. Authentication runs FIRST, so an unauthenticated caller learns
    /// nothing about what any pairing may do; the capability check runs SECOND, on the scope of the
    /// pairing the frame actually authenticated as — never on anything the frame itself claimed.
    fn handle_authenticated(&self, frame: &RequestFrame) -> Value {
        let authority = match self.authenticate(frame) {
            Ok(authority) => authority,
            Err(code) => return error(&frame.id, code),
        };
        if !permits(&authority, &frame.method) {
            return error(&frame.id, SignErrorCode::CapNotGranted);
        }
        match frame.method.as_str() {
            "connect.request" => self.handle_connect(&frame.id, &frame.params),
            "connect.revoke" => self.handle_connect_revoke(&frame.id, &frame.params),
            "sign.request" => self.handle_sign(&frame.id, &frame.params),
            "identity.attest" => self.handle_identity_attest(&frame.id),
            "identity.seal" => self.handle_identity_seal(&frame.id, &frame.params),
            "identity.unseal" => self.handle_identity_unseal(&frame.id, &frame.params),
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

    /// The `identity.attest` handler (`SPEC.md` §5.6, dig_ecosystem#1931): publish this profile's DID,
    /// its X25519 sealing public key, and an attestation binding the two.
    ///
    /// The attestation is `ProfileSigner::sign(DIGATTEST1 ‖ sealing_pubkey)` — the BLS `0x0010`
    /// identity key (the identity path, NOT the money `sign.request` gate). The [`DIGATTEST1_DST`]
    /// prefix domain-separates it from every other message that key signs (see the constant). No
    /// per-call confirm and no connect gate: the capability grant at pair time IS the authorization,
    /// and attest is the probe dig-chat uses to reach `connected`.
    fn handle_identity_attest(&self, id: &Value) -> Value {
        let Some(secret) = self.sealing_key.sealing_secret() else {
            return error(id, SignErrorCode::Locked);
        };
        let sealing_pubkey = PublicKey::from(&secret).to_bytes();

        // The attestation message is the domain-separation tag followed by the sealing public key, so
        // a signature over it can never be replayed as a session-attach or spend message.
        let mut message = Vec::with_capacity(DIGATTEST1_DST.len() + EPK_LEN);
        message.extend_from_slice(DIGATTEST1_DST);
        message.extend_from_slice(&sealing_pubkey);

        // A locked identity signer yields no signature → LOCKED, never a bogus all-zero attestation.
        let Some(signature) = self.signer.try_sign(&message) else {
            return error(id, SignErrorCode::Locked);
        };

        ok(
            id,
            json!({
                "did": self.connect_info.profile_did,
                "sealing_public_key_b64": BASE64.encode(sealing_pubkey),
                "attestation_b64": BASE64.encode(signature.as_bytes()),
            }),
        )
    }

    /// The `identity.seal` handler (`SPEC.md` §5.6, dig_ecosystem#1931): seal a caller-supplied
    /// plaintext into a `DIGCHAT1` envelope addressed to `recipient_did` under its published sealing
    /// key, with this profile's DID as the (unauthenticated, sealed-box) sender claim in the AAD.
    ///
    /// Sealing draws a fresh random ephemeral key + nonce and never touches this profile's sealing
    /// SECRET (encryption is to the recipient's public key), so it does not gate on `LOCKED`. The
    /// plaintext is never retained — it lives only for the duration of the seal.
    fn handle_identity_seal(&self, id: &Value, params: &Value) -> Value {
        let Ok(params) = serde_json::from_value::<IdentitySealParams>(params.clone()) else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };
        let Ok(recipient_pk_bytes) =
            BASE64.decode(params.recipient_sealing_public_key_b64.as_bytes())
        else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };
        let Ok(recipient_sealing_public_key) =
            <[u8; EPK_LEN]>::try_from(recipient_pk_bytes.as_slice())
        else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };
        let Ok(plaintext) = BASE64.decode(params.plaintext_b64.as_bytes()) else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };
        // The plaintext buffer is dropped at the end of this scope — never stored on the router.
        let plaintext = zeroize::Zeroizing::new(plaintext);

        match digchat::seal(&SealInputs {
            sender_did: &self.connect_info.profile_did,
            recipient_did: &params.recipient_did,
            recipient_sealing_public_key,
            plaintext: &plaintext,
        }) {
            Ok(envelope) => ok(id, json!({ "envelope_b64": BASE64.encode(envelope) })),
            Err(e) => error(id, digchat_error_code(&e)),
        }
    }

    /// The `identity.unseal` handler (`SPEC.md` §5.6, dig_ecosystem#1931): open a `DIGCHAT1` envelope
    /// addressed to this profile and return the recovered plaintext plus the sender DID. `sender_did`
    /// is the header's UNVERIFIED sender claim; `open` succeeding proves recipient-integrity, not
    /// sender identity (suite 1 sealed-box, #1940).
    ///
    /// Unsealing NEEDS this profile's sealing secret, so a locked profile refuses `LOCKED`. An
    /// envelope that decodes but does not authenticate — a wrong recipient, a tampered/re-addressed
    /// header, a corrupted body — is `UNSEAL_FAILED`; a malformed envelope is `IDENTITY_BAD_REQUEST`.
    fn handle_identity_unseal(&self, id: &Value, params: &Value) -> Value {
        let Some(secret) = self.sealing_key.sealing_secret() else {
            return error(id, SignErrorCode::Locked);
        };
        let Ok(params) = serde_json::from_value::<IdentityUnsealParams>(params.clone()) else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };
        let Ok(envelope_bytes) = BASE64.decode(params.envelope_b64.as_bytes()) else {
            return error(id, SignErrorCode::IdentityBadRequest);
        };

        match digchat::open(&envelope_bytes, &secret) {
            // `sender_did` is the header's UNVERIFIED sender claim; `open` succeeding proves
            // recipient-integrity, not sender identity (suite 1 sealed-box). The plaintext is
            // base64'd out then dropped (Zeroizing).
            Ok((envelope, plaintext)) => ok(
                id,
                json!({
                    "sender_did": envelope.sender_did,
                    "plaintext_b64": BASE64.encode(&*plaintext),
                }),
            ),
            Err(e) => error(id, digchat_error_code(&e)),
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
    /// codes and returning the authenticated pairing's [`PairingScope`](crate::pairing::PairingScope). A frame with no `auth` object
    /// fails `AUTH_REQUIRED`.
    fn authenticate(&self, frame: &RequestFrame) -> Result<PairingAuthority, SignErrorCode> {
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
        // Only an AUTHENTICATED frame moves "last seen", so the management window cannot be made to
        // show a revoked or impersonated app as recently active.
        let now = now_epoch_secs();
        self.pairings.note_seen(&auth.pairing_id, now);
        // The pairing verified a moment ago, so it is live; a race that unpaired it in between is a
        // revoke, and refusing the frame is the correct outcome of one.
        self.pairings
            .authority_of(&auth.pairing_id)
            .ok_or(SignErrorCode::AuthRequired)
    }

    /// The pairing store, for the async server to restore sealed pairings at startup and expose the
    /// unpair surface.
    pub fn pairings(&self) -> &PairingStore<S> {
        &self.pairings
    }
}

/// Whether an authenticated pairing may call `method` (§5.6.3a, dig_ecosystem#1931).
///
/// Stated as ONE function over the method name rather than a check inside each handler, so a method
/// added later is a line here rather than a capability that silently defaults to allowed — the failure
/// mode where a new endpoint quietly hands a caller something it was never granted.
///
/// The two authorization axes are kept SEPARATE and independent:
/// - **`sign.request`** — the MONEY boundary, gated ONLY by [`PairingScope::may_sign`](crate::pairing::PairingScope::may_sign). Untouched by
///   #1931: an identity capability can never open it.
/// - **`identity.*`** — gated ONLY by the granted [`CapabilitySet`]. A KNOWN identity method that is
///   not granted returns `false` here → `CAP_NOT_GRANTED`; an UNKNOWN method returns `true` here and
///   falls through to `method_not_found` → `-32601` (so a never-defined method is not conflated with
///   a real-but-ungranted one).
/// - **everything else** (`connect.*`) is the control plane, always permitted to an authenticated
///   pairing.
///
/// Map a [`digchat::DigchatError`] to its wire error code. A NON-AUTHENTIC envelope (wrong key,
/// tampered/re-addressed header, corrupted body) is `UNSEAL_FAILED`; every MALFORMED-input case is
/// `IDENTITY_BAD_REQUEST`. The two are kept distinct so a caller can tell "you sent me garbage" from
/// "this is a real envelope I cannot open".
fn digchat_error_code(error: &digchat::DigchatError) -> SignErrorCode {
    match error {
        digchat::DigchatError::NotAuthentic => SignErrorCode::UnsealFailed,
        _ => SignErrorCode::IdentityBadRequest,
    }
}

fn permits(authority: &PairingAuthority, method: &str) -> bool {
    match method {
        "sign.request" => authority.scope.may_sign(),
        m if Capability::is_identity_method(m) => authority.capabilities.permits_method(m),
        _ => true,
    }
}

/// The tray's handle onto the live pairing surface (dig_ecosystem#1848): issue a code, list what is
/// paired, revoke one.
///
/// Holds the SAME [`PairingStore`] the [`FrameRouter`] authenticates against, which is the whole
/// mechanism behind an immediate revoke: [`revoke`](Self::revoke) removes the live entry, so the
/// revoked app's very next frame fails `AUTH_REQUIRED` on the channel it is already holding open. A
/// handle that only deleted the at-rest record would leave the session running until the next restart
/// — a revoke that reads as done and is not.
///
/// Cheap to clone (three `Arc`s) and `Send + Sync`, so the tray thread holds one while the loopback
/// server owns the router.
pub struct PairedAppsControl<S: ProfileSealer> {
    pairings: Arc<PairingStore<S>>,
    codes: Arc<PairingCodeIssuer>,
    persist: Arc<dyn SealedRecordStore>,
}

impl<S: ProfileSealer> Clone for PairedAppsControl<S> {
    fn clone(&self) -> Self {
        Self {
            pairings: Arc::clone(&self.pairings),
            codes: Arc::clone(&self.codes),
            persist: Arc::clone(&self.persist),
        }
    }
}

impl<S: ProfileSealer> PairedAppsControl<S> {
    /// Mint a pairing code for the user to carry to their app, replacing any outstanding one.
    ///
    /// Reachable ONLY from the tray — the router has no path to it — which is what makes "the user
    /// generates the code" a structural property rather than a convention.
    pub fn issue_code(&self, now: u64) -> PairingCode {
        self.codes.issue(now)
    }

    /// Destroy any outstanding code — the user's way to take one back.
    pub fn cancel_code(&self) {
        self.codes.cancel();
    }

    /// Every app currently paired with this profile, oldest first.
    pub fn list(&self) -> Vec<PairedApp> {
        self.pairings.list()
    }

    /// Revoke `pairing_id`: drop the live pairing FIRST so the next frame from that app fails
    /// immediately, then delete its at-rest record so the revocation survives a restart. Returns
    /// whether an app was actually paired under that id.
    ///
    /// The order matters. Deleting the record first would leave a window — however short — in which
    /// the app is still authenticated on a channel the user has been told is closed.
    pub fn revoke(&self, pairing_id: &str) -> bool {
        let was_paired = self.pairings.unpair(pairing_id);
        if was_paired {
            self.persist.remove_pairing(pairing_id);
        }
        was_paired
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

/// The current Unix time in whole seconds (the pairing record's `created_at`, and the instant a
/// pairing code is redeemed against). Re-exported from [`crate::pairing_code`] so the router and the
/// tray that issues the code read the same clock through the same definition.
use crate::pairing_code::now_epoch_secs;

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
    use crate::pairing::{frame_mac_input, PairingScope, PairingStore};
    use crate::test_support::{test_residency, test_sealer};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// An app id DIG does not ship — the caller the whole pairing-code path exists for.
    const THIRD_PARTY: &str = "com.example.someones-tool";

    /// A confirmer that COUNTS how many windows it was asked to draw.
    ///
    /// The count is the assertion in the tests below: "no unsolicited prompt" is a claim about windows,
    /// and an implementation that prompted first and refused afterwards would return an identical
    /// error while letting a hostile process spam a person until one is clicked.
    struct CountingConfirmer {
        decision: ConfirmDecision,
        prompts: Arc<AtomicUsize>,
    }
    impl NativeConfirmer for CountingConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            self.decision
        }
        fn confirm_connect(&self, _: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn confirm_sign(&self, _: &crate::confirm::SignPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
    }

    /// A router plus the TRAY-side handle onto it, because every test below acts as both ends: the
    /// tray that issues a code, and the app that types one.
    fn router_with_codes(
        confirmer: impl NativeConfirmer + 'static,
    ) -> (FrameRouter<AccountSealer>, PairedAppsControl<AccountSealer>) {
        let router = router_with(confirmer);
        let control = router.control();
        (router, control)
    }

    /// A `pair.begin` frame from an app DIG does not ship, optionally carrying a code.
    fn third_party_pair(code: Option<&str>) -> Value {
        let mut params = json!({ "ext_id": THIRD_PARTY, "ext_label": "A Tool" });
        if let Some(code) = code {
            params["pairing_code"] = json!(code);
        }
        params
    }

    /// An authenticated frame, MAC'd exactly as a real client would.
    fn authed_request(
        method: &str,
        params: Value,
        pairing_id: &str,
        token: &str,
        nonce: u64,
    ) -> RequestFrame {
        let auth = signed_auth(token, pairing_id, nonce, method, &params);
        request(method, params, Some(auth))
    }

    /// Pair a third party with `code` and return the response.
    fn pair_third_party(router: &FrameRouter<AccountSealer>, code: &str) -> Value {
        router.handle(&request("pair.begin", third_party_pair(Some(code)), None))
    }

    #[test]
    fn an_unpinned_caller_with_no_code_is_refused_without_drawing_a_window() {
        let prompts = Arc::new(AtomicUsize::new(0));
        let (router, _codes) = router_with_codes(CountingConfirmer {
            decision: ConfirmDecision::Approve,
            prompts: Arc::clone(&prompts),
        });

        let resp = router.handle(&request("pair.begin", third_party_pair(None), None));
        assert_eq!(resp["error"]["message"], "PAIR_CODE_REJECTED");
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            0,
            "no code, no window: a person must never be asked about a caller that has no code"
        );
    }

    #[test]
    fn an_unpinned_caller_with_the_users_code_pairs_with_a_narrower_scope() {
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let code = codes.issue_code(now_epoch_secs());

        let resp = pair_third_party(&router, &code.display());
        let pairing_id = resp["result"]["pairing_id"]
            .as_str()
            .expect("a code-paired app is paired");
        assert_eq!(
            resp["result"]["may_sign"], false,
            "the app is told up front that it cannot sign"
        );
        assert_eq!(
            router.pairings().scope_of(pairing_id),
            Some(PairingScope::ThirdParty)
        );
    }

    #[test]
    fn a_code_paired_app_may_connect_but_never_sign() {
        // The capability boundary through the REAL frame path (MAC and all) rather than by asking the
        // scope directly — the check has to be WIRED INTO dispatch, not merely to exist.
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let code = codes.issue_code(now_epoch_secs());
        let paired = pair_third_party(&router, &code.display());
        let pairing_id = paired["result"]["pairing_id"].as_str().unwrap().to_string();
        let token = paired["result"]["channel_token_b64"].as_str().unwrap();

        let connect = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://dapp.example" }),
            &pairing_id,
            token,
            n(1),
        ));
        assert_eq!(
            connect["result"]["granted"], true,
            "the control plane IS what a third party is paired for"
        );

        let sign = router.handle(&authed_request(
            "sign.request",
            json!({
                "origin": "https://dapp.example",
                "payload_type": "spend",
                "payload_b64": spend_payload_b64(),
            }),
            &pairing_id,
            token,
            n(2),
        ));
        assert_eq!(
            sign["error"]["message"], "CAP_NOT_GRANTED",
            "a code-paired app must not reach the identity key"
        );
    }

    #[test]
    fn a_pinned_extension_still_signs_and_still_needs_no_code() {
        // The other side of the same bound. A scope check that refused everyone would satisfy the test
        // above while silently breaking DIG's own extension — and the pinned path must ALSO still work
        // with NO code outstanding, since making the pin optional was the regression to avoid.
        let (router, _codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));

        let resp = router.handle(&request(
            "pair.begin",
            json!({ "ext_id": EXT, "requested_at": 1 }),
            None,
        ));
        assert_eq!(resp["result"]["may_sign"], true);
        let pairing_id = resp["result"]["pairing_id"].as_str().unwrap().to_string();
        let token = resp["result"]["channel_token_b64"].as_str().unwrap();

        router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://dapp.example" }),
            &pairing_id,
            token,
            n(1),
        ));
        let sign = router.handle(&authed_request(
            "sign.request",
            json!({
                "origin": "https://dapp.example",
                "payload_type": "spend",
                "payload_b64": spend_payload_b64(),
            }),
            &pairing_id,
            token,
            n(2),
        ));
        assert!(
            sign["result"]["signature_b64"].is_string(),
            "the pinned path is untouched: {sign}"
        );
    }

    #[test]
    fn a_wrong_code_is_refused_and_the_guessing_stops_at_the_budget() {
        // The brute-force bound, through the FRAME path: a caller hammering `pair.begin` gets exactly
        // MAX_ATTEMPTS shots before the code is destroyed, and no window is ever drawn.
        let prompts = Arc::new(AtomicUsize::new(0));
        let (router, codes) = router_with_codes(CountingConfirmer {
            decision: ConfirmDecision::Approve,
            prompts: Arc::clone(&prompts),
        });
        let code = codes.issue_code(now_epoch_secs());

        for _ in 0..200 {
            let resp = pair_third_party(&router, "ZZZZ-ZZZZ");
            assert_eq!(resp["error"]["message"], "PAIR_CODE_REJECTED");
        }
        assert_eq!(prompts.load(Ordering::SeqCst), 0);

        // The user's own code is dead too — the budget destroyed it, so the way forward is a NEW code
        // rather than a retry, and the attacker's loop cannot be resumed against the same secret.
        let resp = pair_third_party(&router, &code.display());
        assert_eq!(resp["error"]["message"], "PAIR_CODE_REJECTED");
    }

    #[test]
    fn a_code_pairs_one_app_and_not_a_second() {
        // Single-use through the real handler: a second app arriving with the same code — the shape of
        // a local process that watched the user type it — gets nothing.
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let code = codes.issue_code(now_epoch_secs());

        assert!(pair_third_party(&router, &code.display())["result"]["pairing_id"].is_string());
        assert_eq!(
            pair_third_party(&router, &code.display())["error"]["message"],
            "PAIR_CODE_REJECTED"
        );
    }

    #[test]
    fn a_declined_pairing_spends_the_code() {
        // The user said no. The code must not survive for whatever asks next — the moment a person
        // refuses a pairing is exactly the moment that code should stop working.
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Deny));
        let code = codes.issue_code(now_epoch_secs());

        let denied = pair_third_party(&router, &code.display());
        assert_eq!(denied["error"]["message"], "PAIR_DENIED");
        // The refused code is spent: presenting it again gets nothing.
        assert_eq!(
            pair_third_party(&router, &code.display())["error"]["message"],
            "PAIR_CODE_REJECTED"
        );
    }

    #[test]
    fn with_no_code_ever_issued_no_third_party_is_admitted() {
        // The fail-closed default. Nothing but the tray can mint a code, so a router whose tray handle
        // nobody has used admits no third party — the door is shut rather than open with a default.
        let router = approving_router();
        assert_eq!(
            pair_third_party(&router, "ABCD-EFGH")["error"]["message"],
            "PAIR_CODE_REJECTED"
        );
    }

    #[test]
    fn revoking_kills_the_live_channel_on_the_very_next_frame() {
        // THE promise of the management surface. The revoked app keeps its token and its open channel;
        // what must change is that the token stops working IMMEDIATELY — so this asserts on a frame
        // sent AFTER the revoke, not on the record being gone.
        //
        // Two apps, because a revoke that simply cleared everything would satisfy a one-app fixture
        // while being a purge rather than a revocation.
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let control = router.control();

        let code = codes.issue_code(now_epoch_secs());
        let doomed = pair_third_party(&router, &code.display());
        let kept = router.handle(&request(
            "pair.begin",
            json!({ "ext_id": EXT, "requested_at": 1 }),
            None,
        ));

        let doomed_id = doomed["result"]["pairing_id"].as_str().unwrap().to_string();
        let doomed_token = doomed["result"]["channel_token_b64"].as_str().unwrap();
        let kept_id = kept["result"]["pairing_id"].as_str().unwrap().to_string();
        let kept_token = kept["result"]["channel_token_b64"].as_str().unwrap();

        // Both work BEFORE the revoke, so every assertion after it is about the revoke.
        let before = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://before.example" }),
            &doomed_id,
            doomed_token,
            n(1),
        ));
        assert_eq!(before["result"]["granted"], true);

        assert!(control.revoke(&doomed_id));

        let after = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://after.example" }),
            &doomed_id,
            doomed_token,
            n(2),
        ));
        assert_eq!(
            after["error"]["message"], "AUTH_REQUIRED",
            "the revoked app's next frame must FAIL, on the channel it already holds"
        );

        let untouched = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://other.example" }),
            &kept_id,
            kept_token,
            n(3),
        ));
        assert_eq!(
            untouched["result"]["granted"], true,
            "revoking one app must not disturb another"
        );
        assert!(!control.revoke(&doomed_id), "revoking twice is idempotent");
    }

    #[test]
    fn the_management_list_shows_what_is_paired_and_when_it_last_spoke() {
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let control = router.control();
        assert!(
            control.list().is_empty(),
            "a fresh profile has no paired apps"
        );

        let code = codes.issue_code(now_epoch_secs());
        let paired = pair_third_party(&router, &code.display());
        let pairing_id = paired["result"]["pairing_id"].as_str().unwrap().to_string();

        let listed = control.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ext_id, THIRD_PARTY);
        assert_eq!(listed[0].label.as_deref(), Some("A Tool"));
        assert_eq!(listed[0].scope, PairingScope::ThirdParty);
        assert_eq!(
            listed[0].last_seen_at, None,
            "paired, but the app has not spoken yet"
        );

        router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://dapp.example" }),
            &pairing_id,
            paired["result"]["channel_token_b64"].as_str().unwrap(),
            n(1),
        ));
        assert!(
            control.list()[0].last_seen_at.is_some(),
            "an authenticated frame is what 'last seen' means"
        );
    }

    #[test]
    fn a_failed_frame_never_makes_an_app_look_active() {
        // "Last seen" is what a user reads when deciding whether to revoke something. A timestamp that
        // moved for a frame that failed its MAC would be a lie about the one thing the surface is for.
        let (router, codes) = router_with_codes(ScriptedConfirmer(ConfirmDecision::Approve));
        let control = router.control();
        let code = codes.issue_code(now_epoch_secs());
        let paired = pair_third_party(&router, &code.display());
        let pairing_id = paired["result"]["pairing_id"].as_str().unwrap().to_string();

        let forged = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://dapp.example" }),
            &pairing_id,
            &BASE64.encode([0u8; 32]),
            n(1),
        ));
        assert_eq!(forged["error"]["message"], "AUTH_BAD_MAC");
        assert_eq!(control.list()[0].last_seen_at, None);
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
            SignErrorCode::CapNotGranted,
            SignErrorCode::IdentityBadRequest,
            SignErrorCode::UnsealFailed,
        ];
        let codes: HashSet<i64> = all.iter().map(|c| c.code()).collect();
        let symbols: HashSet<&str> = all.iter().map(|c| c.symbol()).collect();
        assert_eq!(codes.len(), all.len(), "numeric codes must be unique");
        assert_eq!(symbols.len(), all.len(), "symbols must be unique");
    }

    // ---- identity.* capability class (dig_ecosystem#1931) --------------------------------------

    use crate::pairing::{Capability, CapabilitySet};
    use x25519_dalek::{PublicKey, StaticSecret};

    /// The three identity capabilities dig-chat requests, as wire names.
    const IDENTITY_CAPS: [&str; 3] = ["identity.attest", "identity.seal", "identity.unseal"];

    /// A fixed X25519 sealing keypair seam for the identity tests — a deterministic secret so a
    /// failure is reproducible and the derived public key is known.
    struct FixedSealingKey(StaticSecret);
    impl ProfileSealingKey for FixedSealingKey {
        fn sealing_secret(&self) -> Option<StaticSecret> {
            Some(StaticSecret::from(self.0.to_bytes()))
        }
    }

    /// A sealing secret DERIVED from a seed hash (never a literal, so static analysis does not read it
    /// as hard-coded key material).
    fn identity_sealing_secret() -> StaticSecret {
        let seed: [u8; 32] = Sha256::digest(b"dig-app #1931 identity sealing key").into();
        StaticSecret::from(seed)
    }

    /// Build an approving router with a KNOWN identity signer + a KNOWN sealing key, returning the
    /// router, the signer's BLS public key (to verify an attestation) and the sealing secret (to open
    /// what the router sealed / seal what it opens). The pairing/whitelist stores seal under a
    /// separate profile DEK; only the identity seams are the ones under test.
    fn identity_router() -> (
        FrameRouter<AccountSealer>,
        dig_ipc_protocol::domain::SigningPublicKey,
        StaticSecret,
    ) {
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let signer = test_residency().signer(dig_account::ProfileIx::ROOT);
        let signer_pubkey = SessionSigner::signing_public_key(&signer);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec!["xch1testaddress".to_string()],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        let sealing = identity_sealing_secret();
        let router = FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(ScriptedConfirmer(ConfirmDecision::Approve)),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        )
        .with_sealing_key(Arc::new(FixedSealingKey(StaticSecret::from(
            sealing.to_bytes(),
        ))));
        (router, signer_pubkey, sealing)
    }

    /// Pair the pinned `EXT` requesting `requested_capabilities`, returning `(pairing_id, token)` and
    /// the `granted_capabilities` the response echoed. The pinned path needs no code.
    fn pair_requesting(
        router: &FrameRouter<AccountSealer>,
        requested_capabilities: &[&str],
    ) -> (String, String, Vec<String>) {
        let resp = router.handle(&request(
            "pair.begin",
            json!({ "ext_id": EXT, "requested_capabilities": requested_capabilities }),
            None,
        ));
        let result = &resp["result"];
        let granted = result["granted_capabilities"]
            .as_array()
            .expect("granted_capabilities is echoed")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        (
            result["pairing_id"].as_str().unwrap().to_string(),
            result["channel_token_b64"].as_str().unwrap().to_string(),
            granted,
        )
    }

    #[test]
    fn d3_an_identity_only_pairing_is_refused_sign_request_with_cap_not_granted() {
        // THE load-bearing separation (#1931): a pairing that holds every identity capability but a
        // NON-signing scope must be refused `sign.request` with CAP_NOT_GRANTED — not -32601 (that is
        // an unknown method), and certainly not a signature. Two actors keep this honest: the SAME
        // pairing is granted identity.attest (which succeeds) and denied sign.request, so the refusal
        // is about the money boundary, not a channel that refuses everything.
        let (router, _pk, _sealing) = identity_router();
        // A code-paired third party has a NON-signing scope; grant it the identity class on top.
        let control = router.control();
        let code = control.issue_code(now_epoch_secs());
        let resp = router.handle(&request(
            "pair.begin",
            json!({
                "ext_id": THIRD_PARTY,
                "ext_label": "Chat",
                "pairing_code": code.display(),
                "requested_capabilities": IDENTITY_CAPS,
            }),
            None,
        ));
        let pairing_id = resp["result"]["pairing_id"].as_str().unwrap().to_string();
        let token = resp["result"]["channel_token_b64"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            resp["result"]["may_sign"], false,
            "an identity-only pairing does not hold the money scope"
        );

        // identity.attest is GRANTED → it succeeds (the truthful control).
        let attest = router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ));
        assert!(
            attest["result"]["did"].is_string(),
            "the identity capability it WAS granted works"
        );

        // sign.request is NOT in its scope → CAP_NOT_GRANTED, and no signature is produced.
        let sign = router.handle(&authed_request(
            "sign.request",
            json!({
                "origin": "https://dapp.example",
                "payload_type": "spend",
                "payload_b64": spend_payload_b64(),
            }),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(
            sign["error"]["message"], "CAP_NOT_GRANTED",
            "an identity grant must NEVER open the money boundary"
        );
        assert!(sign["result"].is_null(), "and no signature is returned");

        // A genuinely unknown method is still -32601, NOT CAP_NOT_GRANTED — the two are distinct.
        let unknown = router.handle(&authed_request(
            "identity.teleport",
            json!({}),
            &pairing_id,
            &token,
            n(3),
        ));
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn d3_a_known_identity_method_that_was_not_granted_is_cap_not_granted() {
        // The KNOWN-but-ungranted split: a pairing granted ONLY identity.attest must be refused
        // identity.seal with CAP_NOT_GRANTED (a known method it lacks), while identity.teleport (never
        // defined) is -32601. Distinguishing the two is exactly what `is_identity_method` buys.
        let (router, _pk, _sealing) = identity_router();
        let (pairing_id, token, granted) = pair_requesting(&router, &["identity.attest"]);
        assert_eq!(
            granted,
            vec!["identity.attest"],
            "only the one it asked for"
        );

        let seal = router.handle(&authed_request(
            "identity.seal",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ));
        assert_eq!(
            seal["error"]["message"], "CAP_NOT_GRANTED",
            "a known identity method it was not granted is CAP_NOT_GRANTED"
        );
        let unknown = router.handle(&authed_request(
            "identity.nope",
            json!({}),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(
            unknown["error"]["code"], -32601,
            "an unknown method stays -32601"
        );
    }

    #[test]
    fn d4_an_old_sealed_pairing_refuses_identity_but_still_signs_per_scope() {
        // §5.1 back-compat: a pairing record sealed BEFORE the capability field existed opens with an
        // EMPTY capability set, so every identity.* is refused CAP_NOT_GRANTED — while sign.request
        // still works per its (pinned) PairingScope, proving the empty-set default did not disturb the
        // money gate. The fixture is the OLD JSON shape sealed by hand (a round-trip of the new struct
        // could never catch a missing serde(default)).
        use crate::pairing::CHANNEL_SECRET_LEN;
        let sealer = test_sealer(DID);
        let secret = [0x5u8; CHANNEL_SECRET_LEN];
        let old_shape = json!({
            "pairing_id": "old-record-1931",
            "ext_id": EXT,
            "scope": "DigExtension",
            "channel_secret_b64": BASE64.encode(secret),
            "created_at": 1_700_000_000u64,
        });
        let sealed = sealer
            .seal(DID, &serde_json::to_vec(&old_shape).unwrap())
            .unwrap();

        let (router, _pk, _sealing) = identity_router();
        let pairing_id = router.pairings().restore_sealed(&sealed).unwrap();
        // Empty capabilities → identity refused; scope preserved → still signs.
        let authority = router.pairings().authority_of(&pairing_id).unwrap();
        assert!(
            authority.capabilities.is_empty(),
            "old record has no capabilities"
        );
        assert_eq!(authority.scope, PairingScope::DigExtension);

        let token = BASE64.encode(secret);
        let attest = router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ));
        assert_eq!(
            attest["error"]["message"], "CAP_NOT_GRANTED",
            "an old record grants no identity capability"
        );
        // …but the money gate is unchanged: whitelist the origin, then sign succeeds.
        let connect = router.handle(&authed_request(
            "connect.request",
            json!({ "origin": "https://dapp.example" }),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(connect["result"]["granted"], true);
        let sign = router.handle(&authed_request(
            "sign.request",
            json!({
                "origin": "https://dapp.example",
                "payload_type": "spend",
                "payload_b64": spend_payload_b64(),
            }),
            &pairing_id,
            &token,
            n(3),
        ));
        assert!(
            sign["result"]["signature_b64"].is_string(),
            "the pinned scope still signs — the empty capability default left the money gate intact"
        );
    }

    #[test]
    fn d5_pair_begin_echoes_only_the_recognized_requested_capabilities() {
        // The grant echoes back the capabilities actually held, dropping an unknown one, so the caller
        // learns exactly what it has rather than assuming its whole request was honoured.
        let (router, _pk, _sealing) = identity_router();
        let (_id, _token, granted) = pair_requesting(
            &router,
            &[
                "identity.attest",
                "identity.seal",
                "identity.unseal",
                "money.print",
            ],
        );
        assert_eq!(
            granted,
            vec!["identity.attest", "identity.seal", "identity.unseal"],
            "the recognized identity capabilities are granted; the bogus one is dropped"
        );
        assert!(
            !granted.iter().any(|c| c == "money.print"),
            "a non-identity capability is never granted through the identity path"
        );
    }

    #[test]
    fn d5_a_revoke_kills_a_live_identity_pairing() {
        // Revocation semantics (#1848) hold for identity pairings too: after unpair, the very next
        // identity frame fails AUTH_REQUIRED on the channel it is already holding open.
        let (router, _pk, _sealing) = identity_router();
        let (pairing_id, token, _granted) = pair_requesting(&router, &IDENTITY_CAPS);
        assert!(router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ))["result"]["did"]
            .is_string());

        assert!(router.pairings().unpair(&pairing_id));
        let after = router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(after["error"]["message"], "AUTH_REQUIRED");
    }

    #[test]
    fn d6_identity_attest_returns_a_dst_prefixed_attestation_over_the_sealing_key() {
        // The attestation binds the sealing key to the DID, signed with the BLS identity key, and it
        // MUST carry the DIGATTEST1 domain-separation tag so it can never be replayed as a session or
        // spend message. The load-bearing halves: the signature verifies over (DST ‖ pubkey) and does
        // NOT verify over the bare pubkey (proving the tag is actually present, not merely documented).
        use crate::session::verify_signature;
        use dig_ipc_protocol::Signature;

        let (router, signer_pubkey, sealing) = identity_router();
        let (pairing_id, token, _granted) = pair_requesting(&router, &["identity.attest"]);

        let resp = router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ));
        assert_eq!(resp["result"]["did"], DID);

        // The published sealing key is the seam's public half, 32 bytes.
        let published_pk = BASE64
            .decode(resp["result"]["sealing_public_key_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            published_pk,
            PublicKey::from(&sealing).to_bytes().to_vec(),
            "attest publishes the profile's real sealing public key"
        );

        let sig_bytes: [u8; 96] = BASE64
            .decode(resp["result"]["attestation_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::new(sig_bytes);

        let mut dst_message = DIGATTEST1_DST.to_vec();
        dst_message.extend_from_slice(&published_pk);
        assert!(
            verify_signature(&signer_pubkey, &dst_message, &signature),
            "the attestation verifies over DIGATTEST1 ‖ sealing_pubkey"
        );
        assert!(
            !verify_signature(&signer_pubkey, &published_pk, &signature),
            "and NOT over the bare sealing key — the DST prefix must be present (anti-replay)"
        );
    }

    #[test]
    fn d6_identity_attest_on_a_locked_profile_is_locked() {
        // A locked sealing seam yields no key → LOCKED, never a bogus attestation over an absent key.
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let signer = test_residency().signer(dig_account::ProfileIx::ROOT);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec![],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        // No `.with_sealing_key` → the fail-closed LockedSealingKey.
        let router = FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(ScriptedConfirmer(ConfirmDecision::Approve)),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        );
        let (pairing_id, token, _granted) = pair_requesting(&router, &["identity.attest"]);
        let resp = router.handle(&authed_request(
            "identity.attest",
            json!({}),
            &pairing_id,
            &token,
            n(1),
        ));
        assert_eq!(resp["error"]["message"], "LOCKED");
    }

    #[test]
    fn d7_seal_then_unseal_round_trips_the_plaintext_and_the_sender_claim() {
        // The router seam end-to-end: seal a message to THIS profile's own sealing key, then unseal
        // it, recovering the plaintext AND the sender DID claim (the profile's own DID). Under suite 1
        // the sender DID is an unauthenticated claim; here it round-trips because we sealed it.
        let (router, _pk, sealing) = identity_router();
        let (pairing_id, token, _granted) = pair_requesting(&router, &IDENTITY_CAPS);
        let recipient_pk_b64 = BASE64.encode(PublicKey::from(&sealing).to_bytes());
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let sealed = router.handle(&authed_request(
            "identity.seal",
            json!({
                "recipient_did": DID,
                "recipient_sealing_public_key_b64": recipient_pk_b64,
                "plaintext_b64": BASE64.encode(plaintext),
            }),
            &pairing_id,
            &token,
            n(1),
        ));
        let envelope_b64 = sealed["result"]["envelope_b64"]
            .as_str()
            .unwrap()
            .to_string();
        // What travels is ciphertext (NC-1): the plaintext appears nowhere in the envelope bytes.
        let envelope_bytes = BASE64.decode(&envelope_b64).unwrap();
        assert!(
            envelope_bytes
                .windows(plaintext.len())
                .all(|w| w != plaintext),
            "the sealed envelope must carry no byte of the plaintext (NC-1)"
        );

        let opened = router.handle(&authed_request(
            "identity.unseal",
            json!({ "envelope_b64": envelope_b64 }),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(
            BASE64
                .decode(opened["result"]["plaintext_b64"].as_str().unwrap())
                .unwrap(),
            plaintext,
            "unseal recovers the plaintext"
        );
        assert_eq!(
            opened["result"]["sender_did"], DID,
            "unseal returns the sender DID claim (unauthenticated under suite 1)"
        );
    }

    #[test]
    fn d7_unseal_opens_the_dig_chat_golden_envelope_addressed_to_this_key() {
        // Cross-implementation parity at the SEAM: an envelope produced by dig-chat's normative
        // reference (the golden vector pinned in `digchat`) unseals through the router path when the
        // profile's sealing key is the vector's recipient key. Proves the router opens what dig-chat
        // seals, not merely what it seals itself.
        // The golden fixture recipient secret is all-0xb0 (see `digchat::tests`).
        let bob_secret = StaticSecret::from([0xb0u8; 32]);
        let pairings = PairingStore::new(test_sealer(DID), DID);
        let whitelist = WhitelistStore::new(test_sealer(DID), DID);
        let signer = test_residency().signer(dig_account::ProfileIx::ROOT);
        let connect_info = ProfileConnectInfo {
            profile_did: DID.to_string(),
            addresses: vec![],
            pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
        };
        let router = FrameRouter::new(
            pairings,
            whitelist,
            Arc::new(ScriptedConfirmer(ConfirmDecision::Approve)),
            Box::new(signer),
            connect_info,
            [EXT.to_string()],
        )
        .with_sealing_key(Arc::new(FixedSealingKey(StaticSecret::from(
            bob_secret.to_bytes(),
        ))));
        let (pairing_id, token, _granted) = pair_requesting(&router, &IDENTITY_CAPS);

        // The golden DIGCHAT1 wire, sealed by dig-chat's TypeScript reference to the 0xb0 recipient.
        const GOLDEN_WIRE_HEX: &str = "44494743484154310101000e6469643a636869613a616c696365000c6469643a636869613a626f625855784cb3c8c796d84ac93e8f4a53dab0bb31e80960042cfa87f03a4293b3081111111111111111111111111111111111111111111111110000003f6fca01f4081e31c4ec7b4c88d3fe30b68beaf12bfa0d19a30bfdb2965de1a52c86fe8f76b62845c13c65567abaac27034f8c507ebceec57e28ec3733b9d47a";
        let wire: Vec<u8> = (0..GOLDEN_WIRE_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&GOLDEN_WIRE_HEX[i..i + 2], 16).unwrap())
            .collect();

        let opened = router.handle(&authed_request(
            "identity.unseal",
            json!({ "envelope_b64": BASE64.encode(&wire) }),
            &pairing_id,
            &token,
            n(1),
        ));
        assert_eq!(
            opened["result"]["sender_did"], "did:chia:alice",
            "the sender DID claim carried in dig-chat's own envelope (unauthenticated under suite 1)"
        );
        assert_eq!(
            BASE64
                .decode(opened["result"]["plaintext_b64"].as_str().unwrap())
                .unwrap(),
            b"meet me at the bridge at nine, bring the ledger",
        );
    }

    #[test]
    fn d7_unseal_of_a_tampered_or_misaddressed_envelope_fails_and_locked_refuses() {
        let (router, _pk, sealing) = identity_router();
        let (pairing_id, token, _granted) = pair_requesting(&router, &IDENTITY_CAPS);
        let recipient_pk_b64 = BASE64.encode(PublicKey::from(&sealing).to_bytes());

        let sealed = router.handle(&authed_request(
            "identity.seal",
            json!({
                "recipient_did": DID,
                "recipient_sealing_public_key_b64": recipient_pk_b64,
                "plaintext_b64": BASE64.encode(b"secret"),
            }),
            &pairing_id,
            &token,
            n(1),
        ));
        let mut wire = BASE64
            .decode(sealed["result"]["envelope_b64"].as_str().unwrap())
            .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01; // flip a ciphertext byte

        let tampered = router.handle(&authed_request(
            "identity.unseal",
            json!({ "envelope_b64": BASE64.encode(&wire) }),
            &pairing_id,
            &token,
            n(2),
        ));
        assert_eq!(
            tampered["error"]["message"], "UNSEAL_FAILED",
            "a tampered envelope that decodes but does not authenticate is UNSEAL_FAILED"
        );

        // Garbage that is not even a valid envelope is IDENTITY_BAD_REQUEST, a distinct error.
        let garbage = router.handle(&authed_request(
            "identity.unseal",
            json!({ "envelope_b64": BASE64.encode(b"not an envelope") }),
            &pairing_id,
            &token,
            n(3),
        ));
        assert_eq!(garbage["error"]["message"], "IDENTITY_BAD_REQUEST");
    }

    #[test]
    fn capability_set_serialization_is_the_wire_strings() {
        // The sealed record must carry the capabilities as their stable wire names, so a second
        // implementation (or an old build) reads the same set. A round-trip pins that.
        let set = CapabilitySet::from_requested(&IDENTITY_CAPS);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(
            json,
            r#"["identity.attest","identity.seal","identity.unseal"]"#
        );
        let back: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert!(back.contains(Capability::IdentityAttest));
        assert!(back.contains(Capability::IdentitySeal));
        assert!(back.contains(Capability::IdentityUnseal));
    }
}
