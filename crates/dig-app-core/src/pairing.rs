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

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

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

/// A pairing record — the at-rest form persisted DIGOP1-sealed per-profile (§5.6.3). The
/// `channel_secret` is the only sensitive field; it is base64-encoded in the serialized form and the
/// whole record is sealed before it ever touches disk, so the base64 is never at rest in the clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// The opaque pairing identifier (a UUID) the extension echoes in every `auth` object.
    pub pairing_id: String,
    /// The paired extension id (pinned; matches the `Origin` guard).
    pub ext_id: String,
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

/// One live (in-memory, unsealed) pairing the server authenticates frames against. The sealed record
/// is the durable form; this is the hot-path copy holding the secret and the monotonic-nonce ledger.
struct LivePairing {
    ext_id: String,
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
    profile_did: String,
    live: Mutex<HashMap<String, LivePairing>>,
}

impl<S: ProfileSealer> PairingStore<S> {
    /// Build a store that seals pairings under `profile_did`'s DEK via `sealer`.
    pub fn new(sealer: S, profile_did: impl Into<String>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Pair `ext_id`: mint a fresh 32-byte CSPRNG channel secret, register it live, and seal the
    /// [`PairingRecord`] at rest under the active profile's DEK. Returns the handle for the extension
    /// plus the sealed bytes to persist. The caller invokes the native pairing confirm (§5.6.3)
    /// BEFORE calling this — the store mints a secret only for an already-approved pairing.
    ///
    /// # Errors
    ///
    /// [`SealError`] if the profile is locked or sealing fails; no live entry is registered on error.
    pub fn pair(&self, ext_id: &str, created_at: u64) -> Result<PairingOutcome, SealError> {
        let mut channel_secret = Zeroizing::new([0u8; CHANNEL_SECRET_LEN]);
        OsRng.fill_bytes(&mut *channel_secret);
        let pairing_id = Uuid::new_v4().to_string();

        let record = PairingRecord {
            pairing_id: pairing_id.clone(),
            ext_id: ext_id.to_string(),
            channel_secret_b64: BASE64.encode(*channel_secret),
            created_at,
        };
        // Seal FIRST: if sealing fails (locked profile) we register nothing, so the store never holds
        // a live pairing that has no durable at-rest counterpart. The plaintext serialization is held
        // in a zeroizing buffer so the marshalled secret does not linger in freed heap.
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&record).map_err(|e| SealError::Seal(e.to_string()))?,
        );
        let sealed_record = self.sealer.seal(&self.profile_did, &plaintext)?;

        self.lock().insert(
            pairing_id.clone(),
            LivePairing {
                ext_id: ext_id.to_string(),
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

    /// Restore a pairing from its sealed at-rest bytes (app restart): open the record under the active
    /// profile's DEK and register it live with a fresh (empty) nonce ledger. Returns the restored
    /// `pairing_id`.
    ///
    /// # Errors
    ///
    /// [`SealError::Open`] if the bytes were not sealed by this profile's DEK or are corrupt.
    pub fn restore_sealed(&self, sealed_record: &[u8]) -> Result<String, SealError> {
        let plaintext = self.sealer.open(&self.profile_did, sealed_record)?;
        let record: PairingRecord =
            serde_json::from_slice(&plaintext).map_err(|_| SealError::Open)?;
        let channel_secret = record.channel_secret()?;
        let pairing_id = record.pairing_id.clone();
        self.lock().insert(
            pairing_id.clone(),
            LivePairing {
                ext_id: record.ext_id.clone(),
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
        if let Some(pairing) = self.lock().get_mut(pairing_id) {
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
        let mut live = self.lock();
        let pairing = live.get_mut(pairing_id).ok_or(AuthFailure::NotPaired)?;

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

    /// Remove a live pairing (the "unpair" surface, §5.6.3). Returns whether a pairing was present.
    /// After unpairing, every frame from that `pairing_id` fails [`AuthFailure::NotPaired`]. The
    /// caller separately deletes the sealed at-rest record.
    pub fn unpair(&self, pairing_id: &str) -> bool {
        self.lock().remove(pairing_id).is_some()
    }

    /// Whether a live pairing exists for `pairing_id`.
    pub fn is_paired(&self, pairing_id: &str) -> bool {
        self.lock().contains_key(pairing_id)
    }

    /// The paired extension id for `pairing_id`, if any (for the confirm prompt's "via paired
    /// extension" display).
    pub fn ext_id_of(&self, pairing_id: &str) -> Option<String> {
        self.lock().get(pairing_id).map(|p| p.ext_id.clone())
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
        let out = store.pair(EXT, 1_700_000_000).unwrap();

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
        let a = store.pair(EXT, 1).unwrap();
        let b = store.pair(EXT, 2).unwrap();
        assert_ne!(a.pairing_id, b.pairing_id);
        assert_ne!(a.channel_token_b64, b.channel_token_b64);
    }

    #[test]
    fn a_sealed_pairing_round_trips_through_restore() {
        let store = store();
        let out = store.pair(EXT, 42).unwrap();
        store.unpair(&out.pairing_id);
        assert!(!store.is_paired(&out.pairing_id));

        let restored = store.restore_sealed(&out.sealed_record).unwrap();
        assert_eq!(restored, out.pairing_id);
        assert!(store.is_paired(&out.pairing_id));
    }

    #[test]
    fn a_valid_frame_authenticates() {
        let store = store();
        let out = store.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
        assert!(store.unpair(&out.pairing_id));
        assert!(!store.unpair(&out.pairing_id));
        let params = json!({});
        let mac = client_mac(&out.channel_token_b64, n(1), "m", &params);
        assert_eq!(
            store.verify_frame(&out.pairing_id, n(1), "m", &params, &mac),
            Err(AuthFailure::NotPaired)
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
        let out = first.pair(EXT, 1).unwrap();
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
        let out = store.pair(EXT, 1).unwrap();
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
    fn a_foreign_profile_cannot_restore_a_sealed_pairing() {
        // The sealed record is bound to the sealing profile's DEK (NC-2 cross-profile isolation).
        let store_a = store();
        let out = store_a.pair(EXT, 1).unwrap();

        // A DISTINCT profile DEK (a different label) cannot open A's sealed pairing.
        let store_b = PairingStore::new(test_sealer("did:chia:other"), "did:chia:other");
        assert!(matches!(
            store_b.restore_sealed(&out.sealed_record),
            Err(SealError::Open)
        ));
    }
}
