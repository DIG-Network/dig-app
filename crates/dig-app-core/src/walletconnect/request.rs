//! What a connected dapp may ask for, and what happens when it asks — the custody half of
//! WalletConnect (**security-critical**).
//!
//! WalletConnect is a signing transport, so this module is the one place in the feature where being
//! wrong costs a person their money. Three rules shape all of it, and none of them is negotiable:
//!
//! 1. **The key never leaves this process, and never reaches dig-node.** Signing goes through the
//!    same in-app [`SessionSigner`] the loopback channel uses (dig_ecosystem#908). Nothing in this
//!    module holds a private key, serialises one, or sends anything key-shaped anywhere; a request
//!    arrives as JSON and leaves as a detached signature.
//! 2. **The wallet advertises only what it can honour.** [`SUPPORTED_METHODS`] is settled into the
//!    session namespace, so a dapp learns at connect time exactly what this wallet does. A method
//!    outside it is refused with [`MethodUnsupported`](WcRequestError::MethodUnsupported) rather
//!    than accepted and quietly dropped — the failure mode that makes a surface lie about whether a
//!    privileged action took effect.
//! 3. **Every signature is a fresh human decision.** The session grant is permission to ASK, never
//!    permission to sign. Each signing method raises the same native confirm window every other
//!    signature in this app raises, and a locked account refuses rather than signing.
//!
//! # Why the signed bytes are not the bytes the dapp sent
//!
//! A wallet that signs arbitrary attacker-chosen bytes with its identity key is a signing oracle: a
//! dapp asks for a "message" that happens to be a valid spend, and the signature is valid for that
//! spend. So the payload is wrapped by
//! [`sign_callback_message`](crate::session::sign_callback_message) — the same domain-separated,
//! length-prefixed construction the loopback path uses — with a `walletconnect:` method tag inside
//! the domain. A signature produced here is therefore verifiable as a WalletConnect message
//! signature and is not valid as anything else.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::confirm::{ConfirmDecision, NativeConfirmer, SignPrompt};

use super::session::WcSession;

/// The `chip0002_connect` handshake: the dapp confirming it is talking to a wallet.
pub const METHOD_CONNECT: &str = "chip0002_connect";
/// The `chip0002_chainId` read: which chain this session speaks for.
pub const METHOD_CHAIN_ID: &str = "chip0002_chainId";
/// The `chip0002_getPublicKeys` read: the profile's identity signing key.
pub const METHOD_GET_PUBLIC_KEYS: &str = "chip0002_getPublicKeys";
/// The `chip0002_signMessage` signing method.
pub const METHOD_SIGN_MESSAGE: &str = "chip0002_signMessage";
/// The `chia_getCurrentAddress` read: the profile's receive address.
pub const METHOD_GET_CURRENT_ADDRESS: &str = "chia_getCurrentAddress";

/// Exactly what this wallet advertises in a settled session, and exactly what it implements.
///
/// **The list is the contract.** It is settled into the session namespace, stored on the
/// [`WcSession`], and checked on every request — so a dapp is told the truth once, at connect, and
/// the answer cannot drift underneath it afterwards.
///
/// Sage advertises a larger set (spends, offers, wallet enumeration). Those are deliberately ABSENT
/// rather than stubbed: each needs the coin-selection and spend-building path, and a method
/// advertised but unhonoured is worse than one a dapp can see is missing, because the dapp has
/// already told the person their transaction is on its way.
pub const SUPPORTED_METHODS: &[&str] = &[
    METHOD_CONNECT,
    METHOD_CHAIN_ID,
    METHOD_GET_PUBLIC_KEYS,
    METHOD_SIGN_MESSAGE,
    METHOD_GET_CURRENT_ADDRESS,
];

/// The session events this wallet emits. Both are CAIP-25 standard; a dapp subscribes to them to
/// learn that the person switched profile or network under it.
pub const SUPPORTED_EVENTS: &[&str] = &["accountsChanged", "chainChanged"];

/// The CAIP-2 namespace Chia sessions live in.
pub const CHIA_NAMESPACE: &str = "chia";

/// Why a request was refused.
///
/// These map onto JSON-RPC error codes on the wire. The signing refusals are deliberately distinct
/// from each other: a dapp that cannot tell "you said no" from "your wallet is locked" shows the
/// person the wrong next step, and the two have opposite remedies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WcRequestError {
    /// The method is not one this wallet advertised. Carries the name so the dapp can say which.
    MethodUnsupported(String),
    /// The session advertised this method but this particular session did not settle it.
    MethodNotPermitted(String),
    /// The request parameters did not parse.
    BadParams(&'static str),
    /// The person declined the signing confirm.
    UserRejected,
    /// The confirm window was not answered in time.
    Timeout,
    /// No confirm window could be drawn — a headless host. Fails closed: nothing is signed.
    NoConfirmer,
    /// The account is locked and could not be re-opened, so no key was available.
    Locked,
}

impl WcRequestError {
    /// The JSON-RPC error code a dapp sees.
    ///
    /// `4001` and `5000` are the CAIP-25 / WalletConnect conventional codes for user-rejection and
    /// unsupported-method respectively, which is what a dapp written against Sage already handles.
    /// The rest sit in the wallet-defined `5xxx` band.
    pub fn code(&self) -> i64 {
        match self {
            Self::UserRejected => 4001,
            Self::MethodUnsupported(_) | Self::MethodNotPermitted(_) => 5000,
            Self::BadParams(_) => 5001,
            Self::Timeout => 5002,
            Self::NoConfirmer => 5003,
            Self::Locked => 5004,
        }
    }

    /// The human-readable message carried beside the code.
    pub fn message(&self) -> String {
        match self {
            Self::MethodUnsupported(m) => format!("this wallet does not support {m}"),
            Self::MethodNotPermitted(m) => {
                format!("{m} was not granted for this session - reconnect to request it")
            }
            Self::BadParams(why) => format!("the request parameters are not usable: {why}"),
            Self::UserRejected => "the request was declined".to_string(),
            Self::Timeout => "the request was not answered in time".to_string(),
            Self::NoConfirmer => {
                "this computer has no desktop session, so nothing can be approved here".to_string()
            }
            Self::Locked => "the DIG account is locked".to_string(),
        }
    }

    /// The JSON-RPC `error` object.
    pub fn to_json(&self) -> Value {
        json!({ "code": self.code(), "message": self.message() })
    }
}

/// What the handler needs to know about the profile a session belongs to.
///
/// A snapshot taken per request rather than captured once, so a profile switch is reflected in the
/// next answer instead of the dapp being told about whoever was active when the relay task started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileFacts {
    /// The CAIP-2 chain id, e.g. `chia:mainnet`.
    pub chain_id: String,
    /// The identity signing public key, lowercase hex.
    pub signing_public_key_hex: String,
    /// The profile's receive addresses, first-preferred.
    pub addresses: Vec<String>,
}

/// The in-app signer seam.
///
/// A trait local to this module, taking and returning nothing key-shaped, so the handler can be
/// tested against a double without an unlocked account — and so it is visible at a glance that the
/// widest thing this module can do with custody is ask for a detached signature over bytes it built
/// itself. Production passes the same [`SessionSigner`](crate::session::SessionSigner) the loopback
/// router signs with.
pub trait WcSigner {
    /// Sign `message`, or `None` when the account is locked.
    ///
    /// Fallible on purpose: a signer that returned zeroes on a locked account would let a success
    /// envelope carry a signature that verifies against nothing, and the dapp would report the
    /// action as done.
    fn try_sign(&self, message: &[u8]) -> Option<Vec<u8>>;
}

/// The gate consulted immediately before the key is used, so a session that locked since the last
/// request re-authenticates. Mirrors [`SignReauthGate`](crate::loopback::SignReauthGate).
pub trait WcReauthGate {
    /// `true` when signing may proceed.
    fn authorize_sign(&self) -> bool;
}

/// A gate that always authorizes — the default where no session lock is wired.
pub struct OpenWcReauthGate;

impl WcReauthGate for OpenWcReauthGate {
    fn authorize_sign(&self) -> bool {
        true
    }
}

/// The `chip0002_signMessage` parameters.
#[derive(Debug, Deserialize)]
struct SignMessageParams {
    /// The message to sign, as the dapp supplied it. Treated as opaque bytes.
    message: String,
}

/// Handle one `wc_sessionRequest` against `session`.
///
/// The order of the guards is the security property and is not incidental:
///
/// 1. **advertised?** — an unknown method never reaches a parser;
/// 2. **permitted by THIS session?** — read from what was settled, not from today's capability list;
/// 3. **parse** — attacker-shaped input meets a parser only after both gates;
/// 4. **human confirm** — for signing methods, and it is per-request;
/// 5. **re-auth** — because step 4 can take minutes, and the account may have locked inside them;
/// 6. **permitted AGAIN** — `authorize_sign` is a state TRANSITION that unlocks into whichever
///    profile is active by the time it runs, so everything decided before it was decided about a
///    possibly different profile. The loopback path re-checks its gate here for the same reason
///    (dig_ecosystem#2398) and this one must not be the weaker sibling;
/// 7. **sign, fallibly** — a locked signer becomes [`Locked`](WcRequestError::Locked), never a
///    success envelope with an empty signature.
pub fn handle_request(
    session: &WcSession,
    method: &str,
    params: &Value,
    facts: &ProfileFacts,
    confirmer: &dyn NativeConfirmer,
    signer: &dyn WcSigner,
    reauth: &dyn WcReauthGate,
) -> Result<Value, WcRequestError> {
    if !SUPPORTED_METHODS.contains(&method) {
        return Err(WcRequestError::MethodUnsupported(method.to_string()));
    }
    if !session.permits(method) {
        return Err(WcRequestError::MethodNotPermitted(method.to_string()));
    }

    match method {
        // The handshake. `true` and nothing else: a dapp uses it to learn the wallet is answering,
        // and any payload here would be a fact the wallet has not been asked for.
        METHOD_CONNECT => Ok(json!(true)),
        METHOD_CHAIN_ID => Ok(json!(facts.chain_id)),
        // The identity signing key, which is public by construction — it is what verifies every
        // signature this wallet produces. Returned as a list because CHIP-0002 is written for
        // wallets holding many; this one answers with the active profile's single key.
        METHOD_GET_PUBLIC_KEYS => Ok(json!([facts.signing_public_key_hex])),
        // `null` rather than an error when no address has been derived yet: that is an ordinary
        // early state, and CHIP-0002 defines `null` for it. Inventing an address, or reporting a
        // failure, would each misdescribe it.
        METHOD_GET_CURRENT_ADDRESS => Ok(facts.addresses.first().map_or(Value::Null, |a| json!(a))),
        METHOD_SIGN_MESSAGE => sign_message(session, params, facts, confirmer, signer, reauth),
        // Unreachable: the advertised-method gate above is the only door in. Kept as a refusal
        // rather than an `unreachable!()` so a future method added to SUPPORTED_METHODS without a
        // handler is a clean error to its dapp instead of a panic in the tray process.
        other => Err(WcRequestError::MethodUnsupported(other.to_string())),
    }
}

/// The one signing method, and the only path in this module that touches the key.
fn sign_message(
    session: &WcSession,
    params: &Value,
    facts: &ProfileFacts,
    confirmer: &dyn NativeConfirmer,
    signer: &dyn WcSigner,
    reauth: &dyn WcReauthGate,
) -> Result<Value, WcRequestError> {
    let parsed: SignMessageParams = serde_json::from_value(params.clone())
        .map_err(|_| WcRequestError::BadParams("expected a message string"))?;

    // The identity shown on the confirm is the dapp's SELF-DECLARED url, and the window says so.
    // There is no channel in WalletConnect that could verify it — unlike the loopback path, where a
    // paired browser extension vouches for a committed tab origin — so presenting it as verified
    // would be the surface lying about who is asking.
    let subject_origin = declared_origin(session);
    let body = confirm_body(&subject_origin, &parsed.message);
    let decision = confirmer.confirm_sign(&SignPrompt {
        origin: &subject_origin,
        payload_type: SIGN_MESSAGE_PAYLOAD_TYPE,
        decoded_tx: Some(&body),
    });
    match decision {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => return Err(WcRequestError::UserRejected),
        ConfirmDecision::Timeout => return Err(WcRequestError::Timeout),
        ConfirmDecision::Unavailable => return Err(WcRequestError::NoConfirmer),
    }

    if !reauth.authorize_sign() {
        return Err(WcRequestError::Locked);
    }
    // Re-check AFTER the re-auth: see the ordering note on `handle_request`.
    if !session.permits(METHOD_SIGN_MESSAGE) {
        return Err(WcRequestError::MethodNotPermitted(
            METHOD_SIGN_MESSAGE.to_string(),
        ));
    }

    // Domain-separated and length-prefixed. NEVER the dapp's raw bytes — see the module docs on the
    // signing-oracle hazard.
    let message =
        crate::session::sign_callback_message(SIGN_MESSAGE_PAYLOAD_TYPE, parsed.message.as_bytes())
            .ok_or(WcRequestError::BadParams("the message is too large to sign"))?;

    let signature = signer.try_sign(&message).ok_or(WcRequestError::Locked)?;
    Ok(json!({
        "signature": hex::encode(signature),
        "publicKey": facts.signing_public_key_hex,
    }))
}

/// The payload-type tag that goes inside the signing domain.
///
/// It names the TRANSPORT as well as the method, so a signature produced for a WalletConnect dapp
/// cannot be replayed as one produced for the loopback extension channel even though both use the
/// same construction and the same key.
pub const SIGN_MESSAGE_PAYLOAD_TYPE: &str = "walletconnect:chip0002_signMessage";

/// The most of a dapp-supplied message that is shown on the confirm window.
///
/// The window draws its body into a bounded area, and a body that overran used to be CLIPPED IN
/// SILENCE — the defect that hid sixteen recovery words (dig_ecosystem#49). A hostile dapp chooses
/// its message freely, so without a cap it can push the wallet's own warning off the bottom and
/// leave a person approving text that is entirely the dapp's. The cap is small enough that
/// everything after the quoted message still fits.
pub const MESSAGE_PREVIEW_LIMIT: usize = 240;

/// The most of a dapp's self-declared identity that is shown. Shorter than the message cap because
/// it occupies a single line of window chrome.
pub const ORIGIN_PREVIEW_LIMIT: usize = 80;

/// Render the sign-confirm body: who is asking, that DIG cannot vouch for them, and the message.
///
/// # Why the message is flattened and quoted
///
/// The window's text pipeline draws glyphs literally, so there is no markup to escape
/// (`confirm::gui::render` proves that, and asserts nothing re-escapes it either) — but LAYOUT is
/// still forgeable. Newlines let a dapp compose a block that looks like the wallet's own chrome
/// ("Verified by DIG"), and sheer length lets it push the real text out of view. So every run of
/// whitespace collapses to a single space, the result is truncated to [`MESSAGE_PREVIEW_LIMIT`], and
/// it is wrapped in quotes with the wallet's own words on both sides. The dapp gets one line, inside
/// a frame it cannot break out of.
fn confirm_body(origin: &str, message: &str) -> String {
    let (shown, elided) = flatten_and_cap(message, MESSAGE_PREVIEW_LIMIT);
    let tail = if elided {
        "\n\nThe message is longer than this and has been shortened for display."
    } else {
        ""
    };
    format!(
        "{origin} is asking your DIG identity to sign a message.\n\n\
         DIG cannot check who that app really is — the name and address above are what the app says \
         about itself.\n\n\
         The message:\n\"{shown}\"\n\n\
         Signing proves you control this DIG identity. It does not move any money.{tail}"
    )
}

/// How a dapp is identified on a consent window: its declared URL if it gave one, else its declared
/// name, else an explicit statement that it gave neither.
///
/// Never an empty string. A confirm window whose "who is asking" line is blank reads as a rendering
/// bug, and a person dismisses rendering bugs.
///
/// Flattened and capped for the same layout reason the message is — the dapp chooses this string
/// too, and it lands on the line naming WHO is asking, which is the most valuable line to forge.
fn declared_origin(session: &WcSession) -> String {
    let candidate = if !session.peer.url.trim().is_empty() {
        &session.peer.url
    } else if !session.peer.name.trim().is_empty() {
        &session.peer.name
    } else {
        return "An app that did not identify itself".to_string();
    };
    flatten_and_cap(candidate, ORIGIN_PREVIEW_LIMIT).0
}

/// Collapse all whitespace to single spaces and cap at `limit` CHARACTERS, reporting whether
/// anything was dropped.
///
/// Characters rather than bytes: slicing a UTF-8 string at a byte index inside a multi-byte
/// character panics, and this string is chosen by the dapp — so a byte cap here would be a remotely
/// triggerable crash of the tray process.
fn flatten_and_cap(s: &str, limit: usize) -> (String, bool) {
    let flattened: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() <= limit {
        return (flattened, false);
    }
    (flattened.chars().take(limit).collect(), true)
}
