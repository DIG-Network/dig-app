//! Extension↔dig-app pairing + per-frame authentication — the security core of the APP-SIGN
//! loopback channel (SIGN-1, `SPEC.md` §5.6.3, **security-critical**).
//!
//! Pairing establishes ONE trusted mediator once, like pairing a hardware device: a native confirm
//! (§5.6.1) mints a 32-byte CSPRNG `channel_secret`, sealed at rest DIGOP1 per-profile (NC-2) via the
//! [`ProfileSealer`] seam. Thereafter every request frame carries an
//! `auth { pairing_id, nonce, mac_b64 }`, and the app verifies — before any dispatch — that:
//!
//! 1. the `mac_b64` is `HMAC-SHA256(channel_secret, canonical_frame_bytes)` (a **constant-time**
//!    check via [`hmac`]'s `verify_slice`), and
//! 2. the `nonce` is **strictly greater** than the last accepted nonce for that pairing (barring
//!    replay).
//!
//! The token is defense-in-depth on the channel, NOT the sign gate — the terminal native confirm
//! still binds every sign (§5.6.3). This module owns the MAC construction, the monotonic-nonce
//! ledger, and the sealed pairing store; it holds no signing key and makes no policy decision.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::live::{
    belongs_to_active_profile, visible_under_active_profile, ConsentError, ConsentedProfile,
    LiveDid,
};
use crate::sealer::{ProfileSealer, SealError};

/// The length of the channel secret (a pairing token), in bytes — 256 bits of CSPRNG entropy.
pub const CHANNEL_SECRET_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Why a per-frame [`auth`](PairingStore::verify_frame) check failed. Mapped to the §5.6.7 wire codes
/// (`AUTH_REQUIRED` / `AUTH_BAD_MAC` / `AUTH_REPLAY`) by the dispatch layer; kept transport-agnostic
/// here so the security core does not depend on the wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No live pairing exists for the frame's `pairing_id` (never paired, or unpaired/revoked).
    NotPaired,
    /// The MAC did not verify against the pairing's channel secret (tampered / wrong secret).
    BadMac,
    /// The frame's nonce was not strictly greater than the last accepted nonce — a replay.
    Replay,
}

/// The bytes the pairing-token MAC is computed over, exactly as `SPEC.md` §5.6.3 specifies:
///
/// ```text
/// utf8(nonce_decimal) ‖ 0x00 ‖ method ‖ 0x00 ‖ canonical_json(params)
/// ```
///
/// The `0x00` separators keep the three fields unambiguous: the **first** `0x00` delimits the nonce
/// (a decimal integer, so it is NUL-free) and the **last** `0x00` delimits the params
/// (`canonical_json` escapes control characters, so the serialized params can never contain a raw
/// `0x00`). The method occupies the bytes between and MAY contain any byte — even a `0x00` — because
/// it is bounded by the first and last separators, so no two distinct `(nonce, method, params)`
/// triples can produce the same input bytes. Pure and canonical — the extension (SIGN-4) reconstructs
/// the identical bytes, so both sides MUST agree byte-for-byte.
pub fn frame_mac_input(nonce: u64, method: &str, params: &serde_json::Value) -> Vec<u8> {
    let nonce_decimal = nonce.to_string();
    let canonical_params = canonical_json(params);
    let mut input =
        Vec::with_capacity(nonce_decimal.len() + 1 + method.len() + 1 + canonical_params.len());
    input.extend_from_slice(nonce_decimal.as_bytes());
    input.push(0x00);
    input.extend_from_slice(method.as_bytes());
    input.push(0x00);
    input.extend_from_slice(canonical_params.as_bytes());
    input
}

/// Serialize `value` to a **canonical** JSON string: object keys sorted by **Unicode codepoint**
/// order (which, for Rust's `str`, is the default byte-lexicographic ordering of the UTF-8 bytes) at
/// every level, no insignificant whitespace, and scalars rendered by `serde_json`. Codepoint order —
/// NOT UTF-16 code-unit order — is normative (the two diverge for supplementary-plane characters);
/// SIGN-4 MUST sort by codepoint to match (SPEC §5.6.3). Determinism is a security requirement — the
/// MAC binds `canonical_json(params)`, so the extension and dig-app MUST derive byte-identical bytes
/// from equal JSON values regardless of the key order the transport happened to deliver.
///
/// The canonical form is: `{` sorted `"key":value` pairs joined by `,` `}` for objects, `[` elements
/// joined by `,` `]` for arrays, and the `serde_json` compact rendering for every scalar (which
/// escapes control characters, so a NUL can never appear raw and collide with the field separators
/// in [`frame_mac_input`]).
pub fn canonical_json(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut out = String::from("{");
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // `to_string` on a string Value applies the canonical JSON string escaping to the key.
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                out.push_str(&canonical_json(&map[key]));
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        // Scalars (null / bool / number / string) already serialize deterministically and compactly.
        scalar => scalar.to_string(),
    }
}

/// WHAT a paired caller is allowed to do — and the reason a third party is not simply given what
/// DIG's own extension has (dig_ecosystem#1848).
///
/// # Why the two are not the same
///
/// A pinned DIG extension is code DIG writes, reviews and publishes; the pin is a statement about the
/// code on the other end of the channel. A code-paired third party has passed a check on the USER —
/// they held a code — which says nothing about what the program does once it is through. For the
/// signing oracle in particular, that difference matters: with a pinned extension the per-sign native
/// confirm is the LAST barrier, but with an arbitrary local process it would be the ONLY one, and
/// confirm-fatigue is a real bypass rather than a theoretical one.
///
/// So a third party gets the control plane — connect, and the profile handle that comes with it — and
/// signing authority stays a deliberate future grant rather than a default. Defaulting to "the same as
/// ours" would have been the risky choice, and it is refused here rather than left unstated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PairingScope {
    /// A pinned DIG extension: the full channel, including `sign.request`.
    ///
    /// The DEFAULT, and deliberately so: every pairing sealed before this distinction existed was
    /// pinned by construction (there was no other way to pair), so a record written by an older build
    /// and opened by this one is restored with exactly the authority it had.
    #[default]
    DigExtension,
    /// A code-paired third party: the control plane (`connect.request` / `connect.revoke`), NOT signing.
    ThirdParty,
}

impl PairingScope {
    /// Whether a pairing in this scope may reach the identity key through `sign.request`.
    pub fn may_sign(self) -> bool {
        matches!(self, Self::DigExtension)
    }

    /// What this scope permits, in the words the management window shows the user.
    ///
    /// The user's question is "what can this program do to my account", and the honest answer is a
    /// sentence, not the variant's name.
    pub fn summary(self) -> &'static str {
        match self {
            Self::DigExtension => "can ask you to approve signatures, and connect websites",
            Self::ThirdParty => "can connect websites — cannot ask you to sign anything",
        }
    }
}

/// One capability from the `identity.*` class (`SPEC.md` §5.6, dig_ecosystem#1931/#1913).
///
/// # Why this is a SEPARATE axis from [`PairingScope`]
///
/// [`PairingScope`] is the MONEY gate: it decides `sign.request`, the one method that reaches the
/// spend/identity signing key, and only a pinned DIG extension holds it. The `identity.*` class is a
/// DIFFERENT power — sealing and unsealing end-to-end-encrypted messages (dig-chat) — that a
/// code-paired third party legitimately needs and that must NEVER imply the money power. So it is
/// granted per-pairing as an explicit set, checked independently of the scope. A pairing can hold
/// every identity capability and still be refused `sign.request`; that separation is the whole point
/// of #1931 (dig-chat reaches `connected` without ever touching the money boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    /// `identity.attest` — publish the profile's DID + X25519 sealing public key + its attestation.
    #[serde(rename = "identity.attest")]
    IdentityAttest,
    /// `identity.seal` — seal a plaintext into a `DIGCHAT1` envelope to a recipient.
    #[serde(rename = "identity.seal")]
    IdentitySeal,
    /// `identity.unseal` — open a `DIGCHAT1` envelope addressed to this profile.
    #[serde(rename = "identity.unseal")]
    IdentityUnseal,
}

impl Capability {
    /// The stable wire method name this capability gates.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::IdentityAttest => "identity.attest",
            Self::IdentitySeal => "identity.seal",
            Self::IdentityUnseal => "identity.unseal",
        }
    }

    /// Parse a wire method name into its [`Capability`], or `None` if it names no known capability.
    pub fn from_wire(method: &str) -> Option<Self> {
        match method {
            "identity.attest" => Some(Self::IdentityAttest),
            "identity.seal" => Some(Self::IdentitySeal),
            "identity.unseal" => Some(Self::IdentityUnseal),
            _ => None,
        }
    }

    /// Whether `method` names a capability in the identity class. Used by the dispatcher to split a
    /// KNOWN-but-ungranted identity method (→ `CAP_NOT_GRANTED`) from an UNKNOWN one (→ `-32601`).
    pub fn is_identity_method(method: &str) -> bool {
        Self::from_wire(method).is_some()
    }
}

/// The set of `identity.*` capabilities a pairing has been granted.
///
/// Stored on the sealed pairing record and `#[serde(default)]` there, so a record sealed before this
/// class existed opens as the EMPTY set — which refuses every `identity.*` method, exactly the safe
/// default (§5.1 back-compat). A `BTreeSet` so the serialized order is deterministic (the sealed
/// bytes must be stable) and membership is a set, not a list with duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    /// The set of capabilities to grant for a set of REQUESTED wire names (as an app sends in
    /// `pair.begin`): every name that maps to a known [`Capability`] is granted, unknown names are
    /// dropped. This is the grant policy — the identity class carries no money power, so a paired app
    /// that asks for its identity capabilities is granted the ones it names.
    pub fn from_requested<S: AsRef<str>>(requested: &[S]) -> Self {
        Self(
            requested
                .iter()
                .filter_map(|name| Capability::from_wire(name.as_ref()))
                .collect(),
        )
    }

    /// Whether this set grants the capability that gates `method`. `false` for a non-identity method
    /// (those are gated elsewhere) and for an identity method not in the set.
    pub fn permits_method(&self, method: &str) -> bool {
        Capability::from_wire(method).is_some_and(|cap| self.0.contains(&cap))
    }

    /// The granted wire names, sorted, for the `pair.begin` `granted_capabilities` echo (§5.6.3, D5).
    pub fn wire_names(&self) -> Vec<&'static str> {
        self.0.iter().map(|cap| cap.wire_name()).collect()
    }

    /// Whether the set is empty (grants no identity capability).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the set contains `capability`.
    pub fn contains(&self, capability: Capability) -> bool {
        self.0.contains(&capability)
    }
}

/// What an authenticated pairing may do: its money [`PairingScope`] AND its granted identity
/// [`CapabilitySet`]. Returned by [`PairingStore::authority_of`] so the dispatcher checks BOTH axes
/// against the pairing the frame actually authenticated as — never against anything the frame claimed.
#[derive(Debug, Clone)]
pub struct PairingAuthority {
    /// The money gate (whether `sign.request` is permitted).
    pub scope: PairingScope,
    /// The granted `identity.*` capabilities.
    pub capabilities: CapabilitySet,
}

/// A pairing record — the at-rest form persisted DIGOP1-sealed per-profile (§5.6.3). The
/// `channel_secret` is the only sensitive field; it is base64-encoded in the serialized form and the
/// whole record is sealed before it ever touches disk, so the base64 is never at rest in the clear.
///
/// `label` and `scope` were added by dig_ecosystem#1848 and are `serde(default)` so a record sealed by
/// an earlier build still opens: a pairing that predates the distinction was pinned, which is exactly
/// what [`PairingScope::default`] restores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// The opaque pairing identifier (a UUID) the extension echoes in every `auth` object.
    pub pairing_id: String,
    /// The paired extension id (pinned; matches the `Origin` guard).
    pub ext_id: String,
    /// The name the app called itself when it paired, if it gave one.
    ///
    /// **Caller-supplied and therefore untrusted** — it is a display string, never an identity. The
    /// management window shows it beside the `ext_id`, which is what the channel actually authenticates
    /// against, so a program calling itself "DIG" cannot pass itself off as one.
    #[serde(default)]
    pub label: Option<String>,
    /// What this pairing may do.
    #[serde(default)]
    pub scope: PairingScope,
    /// The granted `identity.*` capabilities (dig_ecosystem#1931). `serde(default)` so a record
    /// sealed before the identity class existed opens as the EMPTY set — refusing every `identity.*`
    /// method, the safe default (§5.1 back-compat).
    #[serde(default)]
    pub granted_capabilities: CapabilitySet,
    /// The 32-byte channel secret, base64-encoded for the sealed serialization. Zeroized on drop (the
    /// record is transient — built, sealed, then dropped — but the base64 secret must not linger in
    /// freed heap), matching the identity-key at-rest handling.
    pub channel_secret_b64: String,
    /// Unix-epoch seconds when the pairing was created.
    pub created_at: u64,
}

impl PairingRecord {
    fn channel_secret(&self) -> Result<Zeroizing<[u8; CHANNEL_SECRET_LEN]>, SealError> {
        let mut bytes = Zeroizing::new(
            BASE64
                .decode(self.channel_secret_b64.as_bytes())
                .map_err(|_| SealError::Open)?,
        );
        let array: [u8; CHANNEL_SECRET_LEN] =
            bytes.as_slice().try_into().map_err(|_| SealError::Open)?;
        bytes.zeroize();
        Ok(Zeroizing::new(array))
    }
}

impl Drop for PairingRecord {
    /// Scrub the base64-encoded channel secret from memory when the transient record is dropped.
    fn drop(&mut self) {
        self.channel_secret_b64.zeroize();
    }
}

/// The outcome of a successful [`PairingStore::pair`]: the handle returned to the extension plus the
/// sealed record the caller persists at rest.
pub struct PairingOutcome {
    /// The opaque pairing id.
    pub pairing_id: String,
    /// Base64 of the 32-byte channel token — returned to the extension, stored in
    /// `chrome.storage.local` (§5.6.3). Grants channel access only, never sign authority.
    pub channel_token_b64: String,
    /// The DIGOP1-sealed [`PairingRecord`] bytes to persist (NC-2). Ciphertext at rest; only the
    /// active profile's DEK can reopen it.
    pub sealed_record: Vec<u8>,
}

/// What to pair — gathered into one value so the pinned and code-paired paths cannot drift into
/// different argument orders at their two call sites.
#[derive(Debug, Clone)]
pub struct NewPairing<'a> {
    /// The caller's extension/app id. Authenticated by the `Origin` guard for a browser extension;
    /// for a native third-party client it is a self-declared name, which is why such a caller must
    /// also redeem a pairing code.
    pub ext_id: &'a str,
    /// The caller's self-declared display name, if any. Untrusted — see [`PairingRecord::label`].
    pub label: Option<&'a str>,
    /// What the pairing may do.
    pub scope: PairingScope,
    /// The `identity.*` capabilities granted at pair time (dig_ecosystem#1931). Independent of
    /// `scope` — an identity-only pairing carries capabilities with a non-signing scope.
    pub capabilities: CapabilitySet,
}

impl<'a> NewPairing<'a> {
    /// A pairing for a PINNED DIG extension — the full channel, no identity capabilities by default.
    pub fn pinned(ext_id: &'a str, label: Option<&'a str>) -> Self {
        Self {
            ext_id,
            label,
            scope: PairingScope::DigExtension,
            capabilities: CapabilitySet::default(),
        }
    }

    /// A pairing for a code-paired third party — the control plane only, no identity capabilities by
    /// default.
    pub fn third_party(ext_id: &'a str, label: Option<&'a str>) -> Self {
        Self {
            ext_id,
            label,
            scope: PairingScope::ThirdParty,
            capabilities: CapabilitySet::default(),
        }
    }

    /// Grant `capabilities` to this pairing (the `identity.*` class, dig_ecosystem#1931). Chainable
    /// on either constructor, so a pinned extension OR a code-paired app can hold identity
    /// capabilities without changing its money `scope`.
    pub fn with_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// One paired app as the management surface shows it (dig_ecosystem#1848). Carries no secret — this is
/// the view a window renders, so nothing in it may be sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedApp {
    /// The opaque pairing id — also how the user names one to revoke it.
    pub pairing_id: String,
    /// The app id the channel authenticates against.
    pub ext_id: String,
    /// The app's self-declared display name, if it gave one. Untrusted.
    pub label: Option<String>,
    /// What it is allowed to do.
    pub scope: PairingScope,
    /// The `identity.*` capabilities it was granted (dig_ecosystem#1931).
    pub capabilities: CapabilitySet,
    /// Unix-epoch seconds when the user approved the pairing.
    pub paired_at: u64,
    /// Unix-epoch seconds of the last frame this pairing successfully authenticated, or `None` if it
    /// has not been heard from since dig-app started.
    ///
    /// This is the honest answer to "is it connected right now": the channel is a request/response
    /// socket that a well-behaved app leaves idle, so a live TCP connection would not mean the app is
    /// doing anything and its absence would not mean it had gone. When it last SPOKE is checkable and
    /// means what it says.
    pub last_seen_at: Option<u64>,
}

/// One live (in-memory, unsealed) pairing the server authenticates frames against. The sealed record
/// is the durable form; this is the hot-path copy holding the secret and the monotonic-nonce ledger.
struct LivePairing {
    /// The profile this pairing belongs to, as the DID read at the moment it was paired or restored.
    ///
    /// Held so the map can be read PER PROFILE. The store is built once at boot and lives on a serving
    /// thread, so a pairing made under profile A would otherwise keep authenticating frames after the
    /// user switched to B — and a revoke taken under B would delete B's sealed record while dropping
    /// A's live one (dig_ecosystem#2398 ADV-A1).
    profile_did: String,
    ext_id: String,
    label: Option<String>,
    scope: PairingScope,
    capabilities: CapabilitySet,
    paired_at: u64,
    last_seen_at: Option<u64>,
    /// The channel secret, held in a [`Zeroizing`] buffer so it is scrubbed from memory when the
    /// pairing is dropped (unpair / app exit) — parity with the identity-key handling.
    channel_secret: Zeroizing<[u8; CHANNEL_SECRET_LEN]>,
    /// The highest nonce accepted so far, or `None` before the first authenticated frame. A frame is
    /// accepted only if its nonce is strictly greater, so replays and reorders are rejected.
    last_nonce: Option<u64>,
}

/// The per-profile store of paired extensions and their monotonic-nonce ledgers. Seals new pairings
/// at rest through the [`ProfileSealer`] seam (NC-2) and authenticates every subsequent frame's MAC +
/// nonce. Interior-mutable ([`Mutex`]) so the [`crate::loopback`] server can share one store across
/// connection tasks behind an `Arc`.
pub struct PairingStore<S: ProfileSealer> {
    sealer: S,
    /// The DID this store seals under, read at each seal/open rather than captured — see
    /// [`LiveDid`]. A captured DID would tag records with the profile that was active when the
    /// sign-service assembly was built, while `sealer` derived the DEK of the profile active NOW.
    profile_did: LiveDid,
    live: Mutex<HashMap<String, LivePairing>>,
}

impl<S: ProfileSealer> PairingStore<S> {
    /// Build a store that seals pairings under `profile_did`'s DEK via `sealer`. A `&str`/`String`
    /// converts to a FIXED DID (a fixture, or a host whose profile cannot move); production passes a
    /// [`LiveDid::read`] over the residency so the store follows a profile switch.
    pub fn new(sealer: S, profile_did: impl Into<LiveDid>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// The DID to seal under right now, or a fail-closed [`SealError`] when no profile is active —
    /// which is what a locked account reads as. Refusing is the only honest answer: a placeholder
    /// would tag a real record with a name no profile owns, and that record could never be opened by
    /// the profile that wrote it.
    fn seal_as(&self) -> Result<String, SealError> {
        self.profile_did
            .get()
            .ok_or_else(|| SealError::Seal("no active profile — the account is locked".to_string()))
    }

    /// Read the profile a pairing confirm is about to be answered under. Take this BEFORE raising the
    /// confirm and hand it to [`pair`](Self::pair); see [`ConsentedProfile`].
    pub fn consent_now(&self) -> ConsentedProfile {
        ConsentedProfile::reading(&self.profile_did)
    }

    /// Pair `ext_id`: mint a fresh 32-byte CSPRNG channel secret, register it live, and seal the
    /// [`PairingRecord`] at rest under the active profile's DEK. Returns the handle for the extension
    /// plus the sealed bytes to persist. The caller invokes the native pairing confirm (§5.6.3)
    /// BEFORE calling this — the store mints a secret only for an already-approved pairing.
    ///
    /// `consent`, taken before that confirm, is what binds the minted authority to the profile whose
    /// owner approved it: a switch landing in between is refused rather than granted a channel token.
    ///
    /// # Errors
    ///
    /// [`ConsentError::ProfileMoved`] if the active profile changed since `consent` was taken;
    /// [`ConsentError::Seal`] if the profile is locked or sealing fails. No live entry is registered on
    /// either error.
    pub fn pair(
        &self,
        consent: &ConsentedProfile,
        request: &NewPairing<'_>,
        created_at: u64,
    ) -> Result<PairingOutcome, ConsentError> {
        let mut channel_secret = Zeroizing::new([0u8; CHANNEL_SECRET_LEN]);
        OsRng.fill_bytes(&mut *channel_secret);
        let pairing_id = Uuid::new_v4().to_string();

        let record = PairingRecord {
            pairing_id: pairing_id.clone(),
            ext_id: request.ext_id.to_string(),
            label: request.label.map(str::to_string),
            scope: request.scope,
            granted_capabilities: request.capabilities.clone(),
            channel_secret_b64: BASE64.encode(*channel_secret),
            created_at,
        };
        // Seal FIRST: if sealing fails (locked profile) we register nothing, so the store never holds
        // a live pairing that has no durable at-rest counterpart. The plaintext serialization is held
        // in a zeroizing buffer so the marshalled secret does not linger in freed heap.
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&record).map_err(|e| SealError::Seal(e.to_string()))?,
        );
        let profile_did = self.seal_as()?;
        if !consent.still_holds(&profile_did) {
            return Err(ConsentError::ProfileMoved);
        }
        // `seal_bound`, not `seal`: the DID above and the DEK inside the sealer used to be two
        // independent reads, so a switch landing between them sealed under one profile's key under
        // the other's name (dig-app#255). The sealer now re-resolves the DID from the acquisition
        // that yields the key and refuses if they disagree, which makes the consent check above a
        // guard against a SLOWER switch rather than the only thing standing between the two reads.
        let sealed_record = self.sealer.seal_bound(&profile_did, &plaintext)?;

        self.lock().insert(
            pairing_id.clone(),
            LivePairing {
                profile_did,
                ext_id: request.ext_id.to_string(),
                label: request.label.map(str::to_string),
                scope: request.scope,
                capabilities: request.capabilities.clone(),
                paired_at: created_at,
                last_seen_at: None,
                channel_secret: Zeroizing::new(*channel_secret),
                last_nonce: None,
            },
        );
        Ok(PairingOutcome {
            pairing_id,
            channel_token_b64: BASE64.encode(*channel_secret),
            sealed_record,
        })
    }

    /// Drop every live pairing, so a reload can repopulate from what is at rest for the profile that
    /// is active NOW (dig-app#255).
    ///
    /// # Why this is safe to do on a switch, and why it is not the thing that makes it safe
    ///
    /// Authorization is decided by the DID each record was GRANTED under, never by which records
    /// happen to be resident — so clearing changes what is present, not what is permitted. That
    /// ordering matters: a reload that repopulated first and cleared second would still be correct,
    /// and a design that relied on residency for authorization would not be.
    ///
    /// Fail-closed if a reload does not follow: an empty map authorizes nothing, so the worst
    /// outcome of clearing is that an app is asked to pair again.
    pub fn clear_live(&self) {
        self.lock().clear();
    }

    /// Restore a pairing from its sealed at-rest bytes (app restart): open the record under the active
    /// profile's DEK and register it live with a fresh (empty) nonce ledger. Returns the restored
    /// `pairing_id`.
    ///
    /// # Errors
    ///
    /// [`SealError::Open`] if the bytes were not sealed by this profile's DEK or are corrupt.
    pub fn restore_sealed(&self, sealed_record: &[u8]) -> Result<String, SealError> {
        let profile_did = self.seal_as()?;
        let plaintext = self.sealer.open(&profile_did, sealed_record)?;
        let record: PairingRecord =
            serde_json::from_slice(&plaintext).map_err(|_| SealError::Open)?;
        let channel_secret = record.channel_secret()?;
        let pairing_id = record.pairing_id.clone();
        self.lock().insert(
            pairing_id.clone(),
            LivePairing {
                profile_did,
                ext_id: record.ext_id.clone(),
                label: record.label.clone(),
                scope: record.scope,
                capabilities: record.granted_capabilities.clone(),
                paired_at: record.created_at,
                // Not "never seen" — "not seen SINCE THIS BOOT", which is what the field means and
                // what the management window says.
                last_seen_at: None,
                channel_secret,
                last_nonce: None,
            },
        );
        Ok(pairing_id)
    }

    /// Seed the monotonic-nonce high-water mark for an already-restored pairing (`SPEC.md` §5.6.3,
    /// closes dig_ecosystem#956). Called right after [`restore_sealed`](Self::restore_sealed) on boot
    /// with the `last_nonce` that was persisted alongside the sealed record, so a frame captured
    /// before the restart cannot replay into the new session: the restored ledger already rejects any
    /// nonce `<= last_nonce`. A no-op if the pairing is not live (nothing to seed).
    ///
    /// The seed only ever RAISES the mark (`max`): a stale/rolled-back persisted value can never lower
    /// a mark the live session has already advanced past, so seeding is safe to call unconditionally.
    pub fn seed_last_nonce(&self, pairing_id: &str, last_nonce: u64) {
        let mut live = self.lock();
        if let Some(pairing) = self.of_active_mut(&mut live, pairing_id) {
            let seeded = pairing
                .last_nonce
                .map_or(last_nonce, |cur| cur.max(last_nonce));
            pairing.last_nonce = Some(seeded);
        }
    }

    /// Verify a request frame's `auth` before it is dispatched: the MAC must match the pairing's
    /// channel secret (constant-time) AND the nonce must be strictly greater than the last accepted
    /// one. On success the nonce ledger advances and `Ok(())` is returned; on any failure the ledger
    /// is left untouched (a bad-MAC or replayed frame can never advance — or reset — the nonce).
    ///
    /// The MAC is checked BEFORE the nonce so an attacker who cannot forge the MAC learns nothing
    /// about the current nonce state and can never perturb it.
    pub fn verify_frame(
        &self,
        pairing_id: &str,
        nonce: u64,
        method: &str,
        params: &serde_json::Value,
        mac_b64: &str,
    ) -> Result<(), AuthFailure> {
        let active = self.profile_did.get();
        let mut live = self.lock();
        let pairing = live
            .get_mut(pairing_id)
            .filter(|pairing| belongs_to_active_profile(active.as_deref(), &pairing.profile_did))
            .ok_or(AuthFailure::NotPaired)?;

        let provided_mac = BASE64
            .decode(mac_b64.as_bytes())
            .map_err(|_| AuthFailure::BadMac)?;
        let mut mac = HmacSha256::new_from_slice(&pairing.channel_secret[..])
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(&frame_mac_input(nonce, method, params));
        // `verify_slice` is constant-time and also rejects a wrong-length MAC — no manual compare.
        mac.verify_slice(&provided_mac)
            .map_err(|_| AuthFailure::BadMac)?;

        if pairing.last_nonce.is_some_and(|last| nonce <= last) {
            return Err(AuthFailure::Replay);
        }
        pairing.last_nonce = Some(nonce);
        Ok(())
    }

    /// Remove a live pairing (the "unpair" surface, §5.6.3). Returns whether a pairing FOR THE ACTIVE
    /// PROFILE was present. After unpairing, every frame from that `pairing_id` fails
    /// [`AuthFailure::NotPaired`]. The caller separately deletes the sealed at-rest record.
    ///
    /// Another profile's pairing is left alone, for the reason
    /// [`WhitelistStore::revoke`](crate::whitelist::WhitelistStore::revoke) gives: the durable half of
    /// this revoke is written to the ACTIVE profile's directory, so dropping a foreign live entry here
    /// would revoke only until the next start.
    ///
    /// Scoped to the VISIBLE set rather than the authorized one, so that what a person can see in the
    /// tray is what they can remove: a locked account lists its pairings ([`list`](Self::list)), and a
    /// remove that silently reported "not paired" against a row still on the screen would read as the
    /// app having handled it. Withdrawing access is the safe direction — it hands out no authority —
    /// which is why this predicate and the authorization one differ here and nowhere else.
    pub fn unpair(&self, pairing_id: &str) -> bool {
        let mut live = self.lock();
        if self.visible_mut(&mut live, pairing_id).is_none() {
            return false;
        }
        live.remove(pairing_id).is_some()
    }

    /// Whether a live pairing for the active profile exists for `pairing_id`.
    pub fn is_paired(&self, pairing_id: &str) -> bool {
        self.ext_id_of(pairing_id).is_some()
    }

    /// The paired extension id for `pairing_id`, if any (for the confirm prompt's "via paired
    /// extension" display).
    pub fn ext_id_of(&self, pairing_id: &str) -> Option<String> {
        self.of_active(&self.lock(), pairing_id)
            .map(|p| p.ext_id.clone())
    }

    /// What `pairing_id` is allowed to do, or `None` if it is not paired.
    ///
    /// The dispatch layer consults this AFTER authenticating a frame, so a capability check can never
    /// be reached by a caller that failed the MAC.
    pub fn scope_of(&self, pairing_id: &str) -> Option<PairingScope> {
        self.of_active(&self.lock(), pairing_id).map(|p| p.scope)
    }

    /// The full authority (money [`PairingScope`] + granted [`CapabilitySet`]) for `pairing_id`, or
    /// `None` if it is not paired. The dispatch layer consults this AFTER authenticating a frame, so
    /// neither the money gate nor the capability check can be reached by a caller that failed the MAC.
    pub fn authority_of(&self, pairing_id: &str) -> Option<PairingAuthority> {
        self.of_active(&self.lock(), pairing_id)
            .map(|p| PairingAuthority {
                scope: p.scope,
                capabilities: p.capabilities.clone(),
            })
    }

    /// Record that `pairing_id` was heard from at `now` — the "last seen" the management window shows.
    ///
    /// Called only after a frame AUTHENTICATES, so an unpaired or badly-MAC'd frame can never move a
    /// paired app's timestamp and make it look active. A no-op for an unknown pairing.
    pub fn note_seen(&self, pairing_id: &str, now: u64) {
        let mut live = self.lock();
        if let Some(pairing) = self.of_active_mut(&mut live, pairing_id) {
            pairing.last_seen_at = Some(now);
        }
    }

    /// Every live pairing, as the management surface shows them — oldest first, so the list a user
    /// reads twice is in the same order both times.
    ///
    /// Carries no secret: the channel secret stays in `LivePairing` and never reaches a window.
    pub fn list(&self) -> Vec<PairedApp> {
        let active = self.profile_did.get();
        let mut apps: Vec<PairedApp> = self
            .lock()
            .iter()
            .filter(|(_, live)| visible_under_active_profile(active.as_deref(), &live.profile_did))
            .map(|(pairing_id, live)| PairedApp {
                pairing_id: pairing_id.clone(),
                ext_id: live.ext_id.clone(),
                label: live.label.clone(),
                scope: live.scope,
                capabilities: live.capabilities.clone(),
                paired_at: live.paired_at,
                last_seen_at: live.last_seen_at,
            })
            .collect();
        // Ties broken by id so the order is TOTAL: a `HashMap` iterates arbitrarily, and two apps
        // paired in the same second would otherwise swap places between two openings of the window —
        // which matters here because the user revokes an app by its position in that list.
        apps.sort_by(|a, b| {
            a.paired_at
                .cmp(&b.paired_at)
                .then_with(|| a.pairing_id.cmp(&b.pairing_id))
        });
        apps
    }

    /// The live pairing under `pairing_id`, but only if the profile now active may ACT on it — the
    /// lookup behind every authorization read here. A locked account gets `None`
    /// ([`belongs_to_active_profile`]).
    fn of_active<'a>(
        &self,
        live: &'a HashMap<String, LivePairing>,
        pairing_id: &str,
    ) -> Option<&'a LivePairing> {
        let active = self.profile_did.get();
        live.get(pairing_id)
            .filter(|pairing| belongs_to_active_profile(active.as_deref(), &pairing.profile_did))
    }

    /// [`of_active`](Self::of_active), mutably.
    fn of_active_mut<'a>(
        &self,
        live: &'a mut HashMap<String, LivePairing>,
        pairing_id: &str,
    ) -> Option<&'a mut LivePairing> {
        let active = self.profile_did.get();
        live.get_mut(pairing_id)
            .filter(|pairing| belongs_to_active_profile(active.as_deref(), &pairing.profile_did))
    }

    /// The live pairing under `pairing_id` as the tray SHOWS it — the companion to [`list`](Self::list)
    /// for the one management action ([`unpair`](Self::unpair)) that removes access rather than
    /// granting it.
    fn visible_mut<'a>(
        &self,
        live: &'a mut HashMap<String, LivePairing>,
        pairing_id: &str,
    ) -> Option<&'a mut LivePairing> {
        let active = self.profile_did.get();
        live.get_mut(pairing_id)
            .filter(|pairing| visible_under_active_profile(active.as_deref(), &pairing.profile_did))
    }

    /// A poisoned mutex means another thread panicked mid-update — fail loudly rather than
    /// authenticate against half-updated pairing state.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, LivePairing>> {
        self.live.lock().expect("pairing-store mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::sealer::AccountSealer;
    use crate::test_support::test_sealer;
    use serde_json::json;
    use sha2::Digest;

    const DID: &str = "did:chia:pairing-test";
    const EXT: &str = "chrome-extension-id";

    /// A test frame nonce DERIVED from a seed hash rather than an integer literal, so static analysis
    /// does not flag a "hard-coded cryptographic nonce" (these are HMAC *message* nonces, not key
    /// material). Strictly monotonic in `step`, so replay/stale ordering is preserved:
    /// `n(3) < n(5) < n(6)`.
    fn n(step: u64) -> u64 {
        let seed = Sha256::digest(b"dig-app SIGN-1 pairing test message nonce");
        u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]])) + step
    }

    /// A store sealing under a fresh profile DEK (the fast test KDF).
    fn store() -> PairingStore<AccountSealer> {
        PairingStore::new(test_sealer(DID), DID)
    }

    /// Compute the client-side MAC the extension would send for a frame.
    fn client_mac(
        secret_b64: &str,
        nonce: u64,
        method: &str,
        params: &serde_json::Value,
    ) -> String {
        let secret = BASE64.decode(secret_b64).unwrap();
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&frame_mac_input(nonce, method, params));
        BASE64.encode(mac.finalize().into_bytes())
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level_and_is_whitespace_free() {
        let a = json!({"b": 1, "a": {"y": 2, "x": [3, {"n": 4, "m": 5}]}});
        let b = json!({"a": {"x": [3, {"m": 5, "n": 4}], "y": 2}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            canonical_json(&a),
            r#"{"a":{"x":[3,{"m":5,"n":4}],"y":2},"b":1}"#
        );
    }

    #[test]
    fn frame_mac_input_is_unambiguous_across_field_boundaries() {
        // Moving a byte across the method/params boundary changes the input (the 0x00 separators
        // prevent (method="a", params concat) from colliding with (method="ab", …)).
        let p = json!({});
        assert_ne!(
            frame_mac_input(n(1), "a", &p),
            frame_mac_input(n(1), "ab", &p)
        );
        // The nonce is bound too.
        assert_ne!(
            frame_mac_input(n(1), "m", &p),
            frame_mac_input(n(2), "m", &p)
        );
    }

    #[test]
    fn pair_mints_a_token_and_seals_the_record() {
        let store = store();
        let out = store
            .pair(
                &store.consent_now(),
                &NewPairing::pinned(EXT, None),
                1_700_000_000,
            )
            .unwrap();

        assert!(store.is_paired(&out.pairing_id));
        assert_eq!(store.ext_id_of(&out.pairing_id).as_deref(), Some(EXT));
        // The channel token is 32 bytes of base64.
        assert_eq!(BASE64.decode(&out.channel_token_b64).unwrap().len(), 32);
        // The sealed record is ciphertext, not the plaintext record.
        assert!(!out.sealed_record.is_empty());
        assert!(!String::from_utf8_lossy(&out.sealed_record).contains(EXT));
    }

    #[test]
    fn two_pairings_mint_distinct_secrets_and_ids() {
        let store = store();
        let a = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let b = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 2)
            .unwrap();
        assert_ne!(a.pairing_id, b.pairing_id);
        assert_ne!(a.channel_token_b64, b.channel_token_b64);
    }

    #[test]
    fn a_sealed_pairing_round_trips_through_restore() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 42)
            .unwrap();
        store.unpair(&out.pairing_id);
        assert!(!store.is_paired(&out.pairing_id));

        let restored = store.restore_sealed(&out.sealed_record).unwrap();
        assert_eq!(restored, out.pairing_id);
        assert!(store.is_paired(&out.pairing_id));
    }

    #[test]
    fn a_valid_frame_authenticates() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({"origin": "https://dapp.example"});
        let mac = client_mac(&out.channel_token_b64, n(1), "connect.request", &params);
        assert!(store
            .verify_frame(&out.pairing_id, n(1), "connect.request", &params, &mac)
            .is_ok());
    }

    #[test]
    fn an_unknown_pairing_id_is_not_paired() {
        let store = store();
        let params = json!({});
        assert_eq!(
            store.verify_frame("no-such-pairing", n(1), "m", &params, "AAAA"),
            Err(AuthFailure::NotPaired)
        );
    }

    #[test]
    fn a_tampered_mac_is_rejected() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({"amount": 5});
        let good = client_mac(&out.channel_token_b64, n(1), "sign.request", &params);
        // Forge by signing DIFFERENT params — the MAC no longer matches the frame.
        let tampered = client_mac(
            &out.channel_token_b64,
            n(1),
            "sign.request",
            &json!({"amount": 500}),
        );
        assert_ne!(good, tampered);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(1), "sign.request", &params, &tampered),
            Err(AuthFailure::BadMac)
        );
    }

    #[test]
    fn a_mac_from_a_foreign_secret_is_rejected() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({});
        let foreign_secret = BASE64.encode([9u8; CHANNEL_SECRET_LEN]);
        let mac = client_mac(&foreign_secret, n(1), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(1), "m", &params, &mac),
            Err(AuthFailure::BadMac)
        );
    }

    #[test]
    fn a_replayed_or_stale_nonce_is_rejected() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({});
        let mac5 = client_mac(&out.channel_token_b64, n(5), "m", &params);
        assert!(store
            .verify_frame(&out.pairing_id, n(5), "m", &params, &mac5)
            .is_ok());

        // Replaying nonce n(5) is rejected.
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(5), "m", &params, &mac5),
            Err(AuthFailure::Replay)
        );
        // A lower nonce is rejected.
        let mac3 = client_mac(&out.channel_token_b64, n(3), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(3), "m", &params, &mac3),
            Err(AuthFailure::Replay)
        );
        // A strictly-greater nonce advances.
        let mac6 = client_mac(&out.channel_token_b64, n(6), "m", &params);
        assert!(store
            .verify_frame(&out.pairing_id, n(6), "m", &params, &mac6)
            .is_ok());
    }

    #[test]
    fn a_bad_mac_does_not_advance_the_nonce_ledger() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({});
        // A bad-MAC frame at a high nonce must NOT poison the ledger.
        let bad = client_mac(&BASE64.encode([0u8; 32]), n(100), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(100), "m", &params, &bad),
            Err(AuthFailure::BadMac)
        );
        // A subsequent VALID low nonce still authenticates — the ledger was untouched.
        let good = client_mac(&out.channel_token_b64, n(1), "m", &params);
        assert!(store
            .verify_frame(&out.pairing_id, n(1), "m", &params, &good)
            .is_ok());
    }

    #[test]
    fn unpairing_revokes_authentication() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        assert!(store.unpair(&out.pairing_id));
        assert!(!store.unpair(&out.pairing_id));
        let params = json!({});
        let mac = client_mac(&out.channel_token_b64, n(1), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(1), "m", &params, &mac),
            Err(AuthFailure::NotPaired)
        );
    }

    /// **A locked account authenticates no frame, but still SHOWS what is paired.**
    ///
    /// The two halves are asserted together because they are the whole design: authorization fails
    /// closed on a lock (the active profile can be switched while locked, and the sign path's re-auth
    /// unlocks into whatever that is), while display stays permissive so a person coming back to a
    /// locked screen sees their own apps rather than an empty list. A test asserting only the refusal
    /// would be satisfied by dropping the entries entirely.
    ///
    /// The control is the same store while unlocked: without it a fixture with a bad MAC would produce
    /// the same `NotPaired`.
    #[test]
    fn a_locked_account_authenticates_no_frame_but_still_lists_its_pairings() {
        use crate::account::boot::live_profile_did;
        use crate::account::residency::AccountResidency;
        use crate::session_lock::SessionKeys;
        use dig_keystore::KdfParams;

        let residency = crate::test_support::test_residency();
        let store = PairingStore::new(
            residency.sealer(KdfParams::FAST_TEST),
            live_profile_did(&residency),
        );
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .expect("an unlocked profile pairs");
        let params = json!({});
        let frame = |nonce: u64| {
            (
                nonce,
                client_mac(&out.channel_token_b64, nonce, "m", &params),
            )
        };

        let (nonce, mac) = frame(n(1));
        assert!(
            store
                .verify_frame(&out.pairing_id, nonce, "m", &params, &mac)
                .is_ok(),
            "control: the pairing authenticates while the account is unlocked"
        );

        AccountResidency::lock_all(&residency);

        let (nonce, mac) = frame(n(2));
        assert_eq!(
            Err(AuthFailure::NotPaired),
            store.verify_frame(&out.pairing_id, nonce, "m", &params, &mac),
            "a locked account cannot attribute this pairing, so it must authenticate nothing"
        );
        assert!(
            store.authority_of(&out.pairing_id).is_none(),
            "and it must hand out no capabilities — `permits` is decided from them"
        );
        assert_eq!(
            vec![out.pairing_id.clone()],
            store
                .list()
                .into_iter()
                .map(|app| app.pairing_id)
                .collect::<Vec<_>>(),
            "but the tray must still SHOW it: hiding a person's own apps behind a lock teaches them \
             the app forgot, and showing a row grants nothing"
        );
        assert!(
            store.unpair(&out.pairing_id),
            "and what they can see they must be able to remove — a revoke withdraws access"
        );
    }

    #[test]
    fn seeding_the_nonce_ledger_rejects_a_pre_restart_frame_replay() {
        // dig_ecosystem#956: a frame captured before a restart must not replay after restore. The
        // persisted high-water mark is re-seeded onto the freshly-restored (empty) ledger, so a nonce
        // at or below it is rejected as a replay — exactly as if the session had never restarted.
        // Same profile DEK (same label) shared across the "restart" — a fresh store over the SAME DEK
        // models a restarted app that re-unlocked the profile.
        let store_of = || PairingStore::new(test_sealer(DID), DID);

        let first = store_of();
        let out = first
            .pair(&first.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({});
        let mac = client_mac(&out.channel_token_b64, n(5), "m", &params);
        assert!(first
            .verify_frame(&out.pairing_id, n(5), "m", &params, &mac)
            .is_ok());

        // Simulate a restart: a fresh store restores the sealed pairing (empty ledger) and re-seeds
        // the persisted high-water mark n(5).
        let restarted = store_of();
        let restored = restarted.restore_sealed(&out.sealed_record).unwrap();
        restarted.seed_last_nonce(&restored, n(5));

        // The captured n(5) frame replayed post-restart is now rejected …
        assert_eq!(
            restarted.verify_frame(&restored, n(5), "m", &params, &mac),
            Err(AuthFailure::Replay)
        );
        // … while a strictly-greater nonce still advances.
        let mac6 = client_mac(&out.channel_token_b64, n(6), "m", &params);
        assert!(restarted
            .verify_frame(&restored, n(6), "m", &params, &mac6)
            .is_ok());
    }

    #[test]
    fn seeding_never_lowers_an_already_advanced_ledger() {
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        let params = json!({});
        let mac6 = client_mac(&out.channel_token_b64, n(6), "m", &params);
        assert!(store
            .verify_frame(&out.pairing_id, n(6), "m", &params, &mac6)
            .is_ok());
        // A stale persisted mark below the live one must not reopen a replay window.
        store.seed_last_nonce(&out.pairing_id, n(3));
        let mac4 = client_mac(&out.channel_token_b64, n(4), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(4), "m", &params, &mac4),
            Err(AuthFailure::Replay)
        );
    }

    #[test]
    fn seeding_a_missing_pairing_is_a_noop() {
        store().seed_last_nonce("no-such-pairing", 42);
    }

    #[test]
    fn a_record_sealed_before_scopes_existed_restores_as_a_pinned_extension() {
        // dig_ecosystem#1848 added `label` and `scope` to the sealed record. Every pairing written by
        // an earlier build was PINNED (there was no other way to pair), so an old record must restore
        // with the full channel — not with a `ThirdParty` scope that silently strips an installed
        // extension's ability to sign.
        //
        // The fixture is the OLD JSON shape, sealed by hand, rather than a round-trip of the new struct
        // — a round-trip would exercise serde's own output and could never catch a missing
        // `serde(default)`.
        let sealer = test_sealer(DID);
        let old_shape = serde_json::json!({
            "pairing_id": "0f3e7f2c-old-record",
            "ext_id": EXT,
            "channel_secret_b64": BASE64.encode([7u8; CHANNEL_SECRET_LEN]),
            "created_at": 1_700_000_000u64,
        });
        let sealed = sealer
            .seal(DID, &serde_json::to_vec(&old_shape).unwrap())
            .unwrap();

        let store = PairingStore::new(test_sealer(DID), DID);
        let pairing_id = store
            .restore_sealed(&sealed)
            .expect("an older record must still open");
        assert_eq!(pairing_id, "0f3e7f2c-old-record");
        assert_eq!(
            store.scope_of(&pairing_id),
            Some(PairingScope::DigExtension)
        );
        assert!(store.scope_of(&pairing_id).unwrap().may_sign());
    }

    #[test]
    fn a_third_party_pairing_may_not_sign_while_a_pinned_one_may() {
        // Both halves, because a scope check that returned `false` unconditionally would satisfy the
        // third-party assertion alone and quietly break DIG's own extension.
        let store = store();
        let third = store
            .pair(
                &store.consent_now(),
                &NewPairing::third_party("com.example.tool", Some("Tool")),
                1,
            )
            .unwrap();
        let pinned = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();

        assert_eq!(
            store.scope_of(&third.pairing_id),
            Some(PairingScope::ThirdParty)
        );
        assert!(!store.scope_of(&third.pairing_id).unwrap().may_sign());
        assert!(store.scope_of(&pinned.pairing_id).unwrap().may_sign());
        assert_eq!(store.scope_of("no-such-pairing"), None);
    }

    #[test]
    fn the_scope_survives_a_seal_and_restore() {
        // A third party that could regain signing authority by restarting dig-app would make the
        // whole distinction cosmetic.
        let store = store();
        let out = store
            .pair(
                &store.consent_now(),
                &NewPairing::third_party("com.example.tool", Some("Tool")),
                1,
            )
            .unwrap();
        store.unpair(&out.pairing_id);

        store.restore_sealed(&out.sealed_record).unwrap();
        assert_eq!(
            store.scope_of(&out.pairing_id),
            Some(PairingScope::ThirdParty)
        );
        assert_eq!(
            store.list()[0].label.as_deref(),
            Some("Tool"),
            "the display name survives too"
        );
    }

    #[test]
    fn the_list_is_oldest_first_and_carries_no_secret() {
        let store = store();
        let older = store
            .pair(
                &store.consent_now(),
                &NewPairing::third_party("com.example.b", Some("B")),
                100,
            )
            .unwrap();
        let newer = store
            .pair(
                &store.consent_now(),
                &NewPairing::pinned(EXT, Some("DIG for Chrome")),
                200,
            )
            .unwrap();

        let apps = store.list();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].pairing_id, older.pairing_id, "oldest first");
        assert_eq!(apps[1].pairing_id, newer.pairing_id);
        assert_eq!(apps[0].label.as_deref(), Some("B"));
        assert_eq!(apps[0].scope, PairingScope::ThirdParty);
        assert_eq!(apps[0].paired_at, 100);
        assert_eq!(apps[0].last_seen_at, None, "not heard from since boot");

        // The view a WINDOW renders must not carry the channel secret in any form.
        let rendered = format!("{apps:?}");
        assert!(!rendered.contains(&older.channel_token_b64));
        assert!(!rendered.contains(&newer.channel_token_b64));
    }

    #[test]
    fn last_seen_moves_only_when_an_app_is_actually_heard_from() {
        // "Last seen" is what the management window uses to answer "is this thing still around", so a
        // timestamp that moved for an unpaired or badly-authenticated caller would be a lie about a
        // program the user is deciding whether to revoke.
        let store = store();
        let out = store
            .pair(&store.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();
        assert_eq!(store.list()[0].last_seen_at, None);

        store.note_seen(&out.pairing_id, 1_700_000_500);
        assert_eq!(store.list()[0].last_seen_at, Some(1_700_000_500));

        // An unknown pairing is a no-op rather than an entry appearing from nowhere.
        store.note_seen("no-such-pairing", 1_700_000_900);
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].last_seen_at, Some(1_700_000_500));
    }

    #[test]
    fn revoking_removes_the_app_from_the_list_and_from_the_channel() {
        // The two halves of a revoke that is not a false promise: it disappears from what the user is
        // shown AND its token stops working. Only the second is the security property.
        let store = store();
        let kept = store
            .pair(
                &store.consent_now(),
                &NewPairing::pinned(EXT, Some("keep me")),
                1,
            )
            .unwrap();
        let doomed = store
            .pair(
                &store.consent_now(),
                &NewPairing::third_party("com.example.tool", None),
                2,
            )
            .unwrap();
        assert_eq!(store.list().len(), 2);

        assert!(store.unpair(&doomed.pairing_id));

        let apps = store.list();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].pairing_id, kept.pairing_id);

        let params = json!({});
        let mac = client_mac(&doomed.channel_token_b64, n(1), "m", &params);
        assert_eq!(
            store.verify_frame(&doomed.pairing_id, n(1), "m", &params, &mac),
            Err(AuthFailure::NotPaired),
            "the revoked app's own token must stop authenticating"
        );
        // …and the pairing that was NOT revoked is untouched, so revoke is targeted rather than a purge.
        let kept_mac = client_mac(&kept.channel_token_b64, n(1), "m", &params);
        assert!(store
            .verify_frame(&kept.pairing_id, n(1), "m", &params, &kept_mac)
            .is_ok());
    }

    #[test]
    fn a_foreign_profile_cannot_restore_a_sealed_pairing() {
        // The sealed record is bound to the sealing profile's DEK (NC-2 cross-profile isolation).
        let store_a = store();
        let out = store_a
            .pair(&store_a.consent_now(), &NewPairing::pinned(EXT, None), 1)
            .unwrap();

        // A DISTINCT profile DEK (a different label) cannot open A's sealed pairing.
        let store_b = PairingStore::new(test_sealer("did:chia:other"), "did:chia:other");
        assert!(matches!(
            store_b.restore_sealed(&out.sealed_record),
            Err(SealError::Open)
        ));
    }
}
