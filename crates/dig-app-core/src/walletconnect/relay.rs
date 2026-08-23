//! Talking to the WalletConnect relay: how it is addressed, how this wallet proves it may connect,
//! and the `irn` JSON-RPC it speaks once connected.
//!
//! The relay is a public message bus and an **untrusted intermediary**. It routes by topic and it
//! stores what it is given; it cannot read any of it, because everything it carries is a
//! [`crate::walletconnect::crypto`] envelope. Nothing in this module holds a signing key, and the
//! only secret it touches is the ephemeral ed25519 key it mints to authenticate the websocket — a
//! key that exists for one connection, signs one JWT, and can authorise nothing on any chain.
//!
//! # The project id, and why a build can honestly lack one
//!
//! Every WalletConnect relay requires a wallet to identify itself with a project id issued by
//! `cloud.walletconnect.com`. There is no anonymous mode, and no part of the pairing string supplies
//! one — so a build without a configured id genuinely cannot connect, and pretending otherwise would
//! produce a tray row that looks live and does nothing (dig_ecosystem#1800). [`RelayConfig`] makes
//! the absence explicit and typed, so the tray asks before it asks a person to paste a link.
//!
//! # What is pure here, and what is not
//!
//! The addressing, the JWT and the frame shapes are pure functions with tests. The websocket loop is
//! the thin part on top. That split is deliberate: everything that could be silently WRONG — a
//! mis-signed JWT, a mis-shaped publish, a wrong tag — is checkable without a network.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The relay every WalletConnect client reaches by default.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.org";

/// How long a settle-response envelope is held by the relay if the dapp is offline, in seconds.
///
/// Five minutes, matching `@walletconnect/sign-client`'s `wc_sessionPropose` response TTL. A dapp
/// waiting on a person to approve is measured in the seconds it takes to read a window; holding the
/// answer longer than that mostly stores replies to proposals nobody is waiting for any more.
pub const TTL_SESSION_RESPONSE: u64 = 300;

/// How long an ordinary session message is held, in seconds. Also the WalletConnect default.
pub const TTL_SESSION_MESSAGE: u64 = 300;

/// The relay `tag` for a session-propose response. Tags are how the relay routes push notifications;
/// they are protocol constants and a wrong one is invisible until a phone stops waking up.
pub const TAG_SESSION_PROPOSE_RESPONSE: u64 = 1101;
/// The relay `tag` for `wc_sessionSettle`.
pub const TAG_SESSION_SETTLE: u64 = 1102;
/// The relay `tag` for a `wc_sessionRequest` response.
pub const TAG_SESSION_REQUEST_RESPONSE: u64 = 1109;
/// The relay `tag` for `wc_sessionDelete`.
pub const TAG_SESSION_DELETE: u64 = 1112;

/// Where the relay is and who this wallet says it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// The relay websocket URL. Defaults to [`DEFAULT_RELAY_URL`].
    #[serde(default = "default_relay_url")]
    pub url: String,
    /// The WalletConnect Cloud project id. `None` means WalletConnect is not usable in this build,
    /// and the tray says so rather than offering a control that cannot work.
    #[serde(default)]
    pub project_id: Option<String>,
}

fn default_relay_url() -> String {
    DEFAULT_RELAY_URL.to_string()
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            url: default_relay_url(),
            project_id: None,
        }
    }
}

impl RelayConfig {
    /// Whether this build can reach a relay at all.
    ///
    /// A whitespace-only project id counts as absent: a half-filled settings file is a far more
    /// likely state than a deliberate empty string, and treating it as present produces a
    /// connection refused by the relay with no clue why.
    pub fn is_usable(&self) -> bool {
        self.project_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
    }

    /// The full websocket URL to dial, including the project id and the freshly-signed auth JWT.
    ///
    /// # Errors
    ///
    /// [`RelayError::NotConfigured`] when no project id is set.
    pub fn dial_url(&self, auth_jwt: &str) -> Result<String, RelayError> {
        if !self.is_usable() {
            return Err(RelayError::NotConfigured);
        }
        let project_id = self.project_id.as_deref().unwrap_or_default().trim();
        Ok(format!(
            "{}/?projectId={}&auth={}",
            self.url.trim_end_matches('/'),
            project_id,
            auth_jwt
        ))
    }
}

/// Why the relay could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// No project id is configured, so there is nowhere to connect.
    NotConfigured,
    /// The websocket could not be opened or was dropped.
    Transport(String),
    /// The relay answered, but not with anything this client understands.
    Protocol(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "no WalletConnect project id is configured"),
            Self::Transport(why) => {
                write!(f, "the WalletConnect relay could not be reached: {why}")
            }
            Self::Protocol(why) => write!(f, "the WalletConnect relay replied unexpectedly: {why}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Build the `irn_subscribe` frame for `topic`.
pub fn subscribe_frame(id: u64, topic: &str) -> Value {
    json!({
        "id": id,
        "jsonrpc": "2.0",
        "method": "irn_subscribe",
        "params": { "topic": topic },
    })
}

/// Build the `irn_publish` frame carrying an already-sealed envelope.
///
/// `message` is ciphertext by the time it reaches here — this function neither seals nor inspects
/// it, which is what keeps the relay layer incapable of leaking a plaintext by mistake.
pub fn publish_frame(id: u64, topic: &str, message: &str, tag: u64, ttl: u64) -> Value {
    json!({
        "id": id,
        "jsonrpc": "2.0",
        "method": "irn_publish",
        "params": {
            "topic": topic,
            "message": message,
            "ttl": ttl,
            "tag": tag,
            // `false` because DIG draws its own foreground window; asking the relay to push a
            // notification as well would produce two prompts for one decision.
            "prompt": false,
        },
    })
}

/// One inbound relay delivery: a sealed envelope on a topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The relay request id, which must be acknowledged or the relay redelivers.
    pub id: u64,
    /// The topic it arrived on.
    pub topic: String,
    /// The sealed envelope, still opaque.
    pub message: String,
}

/// Read an inbound relay frame, if it is a subscription delivery.
///
/// Returns `None` for everything else — acknowledgements, errors, and frames from a future relay
/// version. Ignoring the unrecognised rather than failing on it is what lets a wallet keep working
/// when the relay grows a frame type; the alternative is a client that dies on a deployment it was
/// not consulted about.
pub fn read_delivery(frame: &Value) -> Option<Delivery> {
    if frame.get("method")?.as_str()? != "irn_subscription" {
        return None;
    }
    let id = frame.get("id")?.as_u64()?;
    let data = frame.get("params")?.get("data")?;
    Some(Delivery {
        id,
        topic: data.get("topic")?.as_str()?.to_string(),
        message: data.get("message")?.as_str()?.to_string(),
    })
}

/// Acknowledge a delivery so the relay stops redelivering it.
pub fn ack_frame(id: u64) -> Value {
    json!({ "id": id, "jsonrpc": "2.0", "result": true })
}

/// How long a freshly-minted relay auth JWT is valid, in seconds.
///
/// One hour. The token authorises a websocket connection and nothing else, and the connection is
/// re-established with a fresh token, so a longer life buys nothing and a shorter one risks a clock
/// skew rejecting a legitimate wallet.
pub const AUTH_JWT_TTL_SECS: u64 = 3600;

/// Mint the relay auth JWT this wallet presents on connect.
///
/// The relay requires an `EdDSA` JWT whose issuer is a `did:key` ed25519 identity. The key is
/// EPHEMERAL and generated per connection: the relay only needs a stable-for-this-connection
/// identity, so a persistent one would create a cross-session correlator — a relay operator could
/// tell that the same wallet returned — for no benefit at all.
///
/// # Errors
///
/// [`RelayError::Protocol`] if the system clock is before the unix epoch, which is the only way the
/// timestamps can fail to build.
pub fn mint_auth_jwt(
    signing_key: &ed25519_dalek::SigningKey,
    aud: &str,
    sub: &str,
    now: u64,
) -> String {
    use ed25519_dalek::Signer as _;

    let header = json!({ "alg": "EdDSA", "typ": "JWT" });
    let payload = json!({
        "iss": did_key(&signing_key.verifying_key()),
        "sub": sub,
        "aud": aud,
        "iat": now,
        "exp": now + AUTH_JWT_TTL_SECS,
    });
    let signing_input = format!(
        "{}.{}",
        BASE64URL.encode(header.to_string()),
        BASE64URL.encode(payload.to_string())
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", BASE64URL.encode(signature.to_bytes()))
}

/// The `did:key` form of an ed25519 public key, as the relay expects the JWT issuer.
///
/// `did:key:z` followed by the base58btc encoding of the multicodec prefix `0xed 0x01` and the raw
/// key. The prefix is what tells a reader the key is ed25519; omitting it produces a DID that parses
/// and identifies the wrong key type.
pub fn did_key(public: &ed25519_dalek::VerifyingKey) -> String {
    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.extend_from_slice(&[0xed, 0x01]);
    prefixed.extend_from_slice(public.as_bytes());
    format!("did:key:z{}", bs58::encode(prefixed).into_string())
}

/// Mint a fresh ephemeral ed25519 key for one relay connection.
pub fn new_auth_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
}

/// Seconds since the unix epoch, saturating at zero on a clock before it.
///
/// Saturating rather than panicking: a misconfigured clock should produce a JWT the relay rejects
/// with a clear message, not a crash of the tray process.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> RelayConfig {
        RelayConfig {
            url: DEFAULT_RELAY_URL.to_string(),
            project_id: Some("abc123".to_string()),
        }
    }

    #[test]
    fn a_config_without_a_project_id_is_not_usable() {
        assert!(!RelayConfig::default().is_usable());
    }

    /// A whitespace-only id is the half-filled settings file, and it must read as absent — the
    /// alternative is a dial the relay refuses with nothing anywhere explaining why.
    #[test]
    fn a_blank_project_id_reads_as_absent() {
        let cfg = RelayConfig {
            project_id: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(!cfg.is_usable());
        assert_eq!(cfg.dial_url("jwt"), Err(RelayError::NotConfigured));
    }

    #[test]
    fn a_configured_relay_is_usable() {
        assert!(configured().is_usable());
    }

    #[test]
    fn the_dial_url_carries_the_project_id_and_the_token() {
        let url = configured().dial_url("thetoken").unwrap();
        assert_eq!(
            url,
            "wss://relay.walletconnect.org/?projectId=abc123&auth=thetoken"
        );
    }

    /// A trailing slash on the configured URL must not produce a double slash — the relay is exact
    /// about its path, and `//?projectId=` is a different request.
    #[test]
    fn a_trailing_slash_in_the_configured_url_does_not_double() {
        let cfg = RelayConfig {
            url: "wss://relay.example/".to_string(),
            ..configured()
        };
        assert_eq!(
            cfg.dial_url("t").unwrap(),
            "wss://relay.example/?projectId=abc123&auth=t"
        );
    }

    #[test]
    fn a_subscribe_frame_names_its_topic() {
        let frame = subscribe_frame(7, "abcd");
        assert_eq!(frame["method"], "irn_subscribe");
        assert_eq!(frame["id"], 7);
        assert_eq!(frame["params"]["topic"], "abcd");
    }

    /// The publish frame's tag and ttl are protocol constants a wrong value silently breaks, so they
    /// are asserted as VALUES rather than merely round-tripped.
    #[test]
    fn a_publish_frame_carries_the_tag_ttl_and_sealed_body() {
        let frame = publish_frame(
            9,
            "topic1",
            "SEALED",
            TAG_SESSION_SETTLE,
            TTL_SESSION_MESSAGE,
        );
        assert_eq!(frame["method"], "irn_publish");
        assert_eq!(frame["params"]["topic"], "topic1");
        assert_eq!(frame["params"]["message"], "SEALED");
        assert_eq!(frame["params"]["tag"], 1102);
        assert_eq!(frame["params"]["ttl"], 300);
        assert_eq!(
            frame["params"]["prompt"], false,
            "DIG draws its own window; a relay push would be a second prompt for one decision"
        );
    }

    #[test]
    fn a_subscription_delivery_is_read_out_of_its_frame() {
        let frame = json!({
            "id": 42,
            "jsonrpc": "2.0",
            "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": "t", "message": "m" } },
        });
        assert_eq!(
            read_delivery(&frame),
            Some(Delivery {
                id: 42,
                topic: "t".into(),
                message: "m".into()
            })
        );
    }

    /// Acknowledgements, errors and unknown methods must all be ignored rather than mistaken for a
    /// delivery — and unknown methods specifically, because a relay that grows a frame type must not
    /// break every wallet that did not know about it.
    #[test]
    fn everything_that_is_not_a_delivery_is_ignored() {
        for frame in [
            json!({ "id": 1, "jsonrpc": "2.0", "result": true }),
            json!({ "id": 1, "jsonrpc": "2.0", "error": { "code": -1, "message": "no" } }),
            json!({ "id": 1, "jsonrpc": "2.0", "method": "irn_somethingNew", "params": {} }),
            json!({ "method": "irn_subscription", "params": {} }),
            json!({ "id": 1, "method": "irn_subscription", "params": { "data": { "topic": "t" } } }),
        ] {
            assert_eq!(read_delivery(&frame), None, "frame: {frame}");
        }
    }

    #[test]
    fn an_acknowledgement_answers_the_delivery_id() {
        assert_eq!(
            ack_frame(5),
            json!({ "id": 5, "jsonrpc": "2.0", "result": true })
        );
    }

    /// The multicodec prefix is what identifies the key as ed25519. A DID built without it parses
    /// perfectly and names the wrong key type, which the relay rejects with an opaque error — so the
    /// prefix is asserted through a known-answer vector rather than through the code's own logic.
    #[test]
    fn a_did_key_carries_the_ed25519_multicodec_prefix() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
        let did = did_key(&key.verifying_key());
        assert!(did.starts_with("did:key:z6Mk"), "got {did}");
        // Decoding must recover exactly the prefix and the raw key.
        let decoded = bs58::decode(did.trim_start_matches("did:key:z"))
            .into_vec()
            .unwrap();
        assert_eq!(&decoded[..2], &[0xed, 0x01]);
        assert_eq!(&decoded[2..], key.verifying_key().as_bytes());
    }

    /// The JWT must be three base64url segments AND its signature must verify under the issuer's own
    /// key. Checking only the shape would pass for a token signed with the wrong key, which is the
    /// mistake that produces a relay rejection nobody can debug.
    #[test]
    fn the_auth_jwt_verifies_under_the_key_that_issued_it() {
        use ed25519_dalek::{Signature, Verifier as _};

        let key = new_auth_key();
        let jwt = mint_auth_jwt(&key, "wss://relay.example", "subject", 1_700_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT is three segments");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = BASE64URL.decode(parts[2]).unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        key.verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("the relay will check exactly this");
    }

    #[test]
    fn the_auth_jwt_claims_the_relay_as_its_audience_and_expires() {
        let key = new_auth_key();
        let jwt = mint_auth_jwt(&key, "wss://relay.example", "subject", 1_700_000_000);
        let payload: Value =
            serde_json::from_slice(&BASE64URL.decode(jwt.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload["aud"], "wss://relay.example");
        assert_eq!(payload["sub"], "subject");
        assert_eq!(payload["iat"], 1_700_000_000u64);
        assert_eq!(payload["exp"], 1_700_000_000u64 + AUTH_JWT_TTL_SECS);
        assert_eq!(payload["iss"], did_key(&key.verifying_key()));
    }

    /// The header must say `EdDSA`. A relay reading `HS256` here rejects the connection, and the
    /// failure surfaces as an unexplained disconnect.
    #[test]
    fn the_auth_jwt_header_declares_eddsa() {
        let key = new_auth_key();
        let jwt = mint_auth_jwt(&key, "wss://relay.example", "s", 1);
        let header: Value =
            serde_json::from_slice(&BASE64URL.decode(jwt.split('.').next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
    }

    /// Two connections must not be linkable by their auth identity. This is the ephemeral-key
    /// property stated on `mint_auth_jwt`, and it is exactly the kind of claim that rots silently if
    /// someone later "optimises" the key into a stored one.
    #[test]
    fn each_connection_authenticates_under_a_different_identity() {
        assert_ne!(
            did_key(&new_auth_key().verifying_key()),
            did_key(&new_auth_key().verifying_key())
        );
    }

    /// The JWT is not base64URL by accident: standard base64 emits `+` and `/`, which are not valid
    /// in a JWT segment and would be mangled in the query string the token is carried in.
    #[test]
    fn the_jwt_segments_are_url_safe() {
        let key = new_auth_key();
        // Many tokens, because `+` and `/` appear in only some signatures — a single sample can pass
        // for a standard-base64 implementation by luck.
        for _ in 0..64 {
            let jwt = mint_auth_jwt(&new_auth_key(), "wss://r", "s", 1);
            assert!(
                !jwt.contains('+') && !jwt.contains('/') && !jwt.contains('='),
                "not url-safe: {jwt}"
            );
        }
        let _ = key;
    }
}
