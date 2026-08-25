//! What a connected dapp may ask for, and what happens when it asks — the custody half of
//! WalletConnect (**security-critical**).
//!
//! WalletConnect is a signing transport, so this module is the one place in the feature where being
//! wrong costs a person their money. Three rules shape all of it, and none of them is negotiable:
//!
//! 1. **The key never leaves this process, and never reaches dig-node.** Signing goes through the
//!    same in-app [`SessionSigner`](crate::session::SessionSigner) the loopback channel uses (dig_ecosystem#908). Nothing in this
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

use crate::confirm::{
    neutralize_for_display, neutralize_or, ConfirmDecision, NativeConfirmer, SignPrompt,
};

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
            .ok_or(WcRequestError::BadParams(
                "the message is too large to sign",
            ))?;

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
    let preview = neutralize_for_display(message, MESSAGE_PREVIEW_LIMIT);
    let shown = &preview.text;
    let tail = if preview.elided {
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
    neutralize_or(
        candidate,
        ORIGIN_PREVIEW_LIMIT,
        "An app that did not identify itself",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{
        ClaimPrompt, ConnectPrompt, InputOutcome, InputPrompt, NoticePrompt, PairPrompt,
        RevealPrompt,
    };
    use crate::walletconnect::session::{DappMetadata, WcSession, SESSION_TTL_SECS};
    use std::sync::Mutex;

    const NOW: u64 = 1_800_000_000;

    /// A confirmer that answers with a fixed decision and RECORDS every prompt it was shown.
    ///
    /// Recording matters as much as answering: several properties here are about what the person
    /// was shown and in what ORDER, and a double that only returned a verdict could not see either.
    struct Recorder {
        decision: ConfirmDecision,
        /// Every sign-confirm body drawn, in order.
        bodies: Mutex<Vec<String>>,
        /// Every origin line drawn, in order.
        origins: Mutex<Vec<String>>,
        /// The interleaved trace of consent and signing, which is how ordering is asserted.
        trace: Mutex<Vec<&'static str>>,
    }

    impl Recorder {
        fn answering(decision: ConfirmDecision) -> Self {
            Self {
                decision,
                bodies: Mutex::new(Vec::new()),
                origins: Mutex::new(Vec::new()),
                trace: Mutex::new(Vec::new()),
            }
        }
        fn approving() -> Self {
            Self::answering(ConfirmDecision::Approve)
        }
        fn prompts(&self) -> usize {
            self.bodies.lock().unwrap().len()
        }
        fn last_body(&self) -> String {
            self.bodies
                .lock()
                .unwrap()
                .last()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl NativeConfirmer for Recorder {
        fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn confirm_sign(&self, p: &SignPrompt<'_>) -> ConfirmDecision {
            self.trace.lock().unwrap().push("confirm");
            self.bodies
                .lock()
                .unwrap()
                .push(p.decoded_tx.unwrap_or_default().to_string());
            self.origins.lock().unwrap().push(p.origin.to_string());
            self.decision
        }
        fn confirm_reveal(&self, _p: &RevealPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn confirm_claim(&self, _p: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.decision
        }
        fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
            InputOutcome::Cancelled
        }
    }

    /// A signer that records the EXACT bytes it was asked to sign.
    ///
    /// The bytes are the point. A double that only reported "I was called" could not distinguish a
    /// wallet that signs the dapp's raw message — a signing oracle — from one that signs a
    /// domain-separated wrapper, and those are the same call count.
    struct SpySigner<'a> {
        available: bool,
        seen: Mutex<Vec<Vec<u8>>>,
        trace: Option<&'a Mutex<Vec<&'static str>>>,
    }

    impl<'a> SpySigner<'a> {
        fn ready(trace: &'a Mutex<Vec<&'static str>>) -> Self {
            Self {
                available: true,
                seen: Mutex::new(Vec::new()),
                trace: Some(trace),
            }
        }
        fn locked() -> Self {
            Self {
                available: false,
                seen: Mutex::new(Vec::new()),
                trace: None,
            }
        }
        fn calls(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        fn last(&self) -> Vec<u8> {
            self.seen
                .lock()
                .unwrap()
                .last()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl WcSigner for SpySigner<'_> {
        fn try_sign(&self, message: &[u8]) -> Option<Vec<u8>> {
            if let Some(trace) = self.trace {
                trace.lock().unwrap().push("sign");
            }
            self.seen.lock().unwrap().push(message.to_vec());
            self.available.then(|| vec![0xABu8; 96])
        }
    }

    /// A re-auth gate with a fixed answer, recording whether it was consulted at all.
    struct Gate {
        allow: bool,
        consulted: Mutex<bool>,
    }

    impl Gate {
        fn open() -> Self {
            Self {
                allow: true,
                consulted: Mutex::new(false),
            }
        }
        fn refusing() -> Self {
            Self {
                allow: false,
                consulted: Mutex::new(false),
            }
        }
    }

    impl WcReauthGate for Gate {
        fn authorize_sign(&self) -> bool {
            *self.consulted.lock().unwrap() = true;
            self.allow
        }
    }

    fn facts() -> ProfileFacts {
        ProfileFacts {
            chain_id: "chia:mainnet".into(),
            signing_public_key_hex: "ab".repeat(48),
            addresses: vec!["xch1theaddress".into()],
        }
    }

    /// A session settling EVERY supported method, so a refusal in a test is never merely the
    /// session's own narrowness.
    fn session_with(methods: Vec<String>) -> WcSession {
        WcSession {
            topic: "t".repeat(64),
            sym_key_hex: "aa".repeat(32),
            profile_did: "did:chia:me".into(),
            peer: DappMetadata {
                name: "Example Dapp".into(),
                description: String::new(),
                url: "https://dapp.example".into(),
                icons: Vec::new(),
            },
            chains: vec!["chia:mainnet".into()],
            methods,
            accounts: vec!["chia:mainnet:xch1theaddress".into()],
            connected_at: NOW,
            expires_at: NOW + SESSION_TTL_SECS,
        }
    }

    fn full_session() -> WcSession {
        session_with(SUPPORTED_METHODS.iter().map(|m| (*m).to_string()).collect())
    }

    // ---- the read methods -------------------------------------------------------------------

    /// Reads must answer WITHOUT raising a window. A wallet that prompted to disclose its own public
    /// address would train people to click through prompts, which is how the signing prompt stops
    /// being read.
    #[test]
    fn every_read_method_answers_without_prompting_or_signing() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::locked();
        let gate = Gate::open();
        let session = full_session();

        for method in [
            METHOD_CONNECT,
            METHOD_CHAIN_ID,
            METHOD_GET_PUBLIC_KEYS,
            METHOD_GET_CURRENT_ADDRESS,
        ] {
            handle_request(
                &session,
                method,
                &json!({}),
                &facts(),
                &confirmer,
                &signer,
                &gate,
            )
            .unwrap_or_else(|e| panic!("{method} should answer: {e:?}"));
        }
        assert_eq!(confirmer.prompts(), 0, "a read must not raise a window");
        assert_eq!(signer.calls(), 0, "a read must not reach the key");
        assert!(!*gate.consulted.lock().unwrap());
    }

    #[test]
    fn the_read_methods_answer_with_the_profiles_own_facts() {
        let (c, s, g) = (Recorder::approving(), SpySigner::locked(), Gate::open());
        let session = full_session();
        let call = |m: &str| handle_request(&session, m, &json!({}), &facts(), &c, &s, &g).unwrap();
        assert_eq!(call(METHOD_CONNECT), json!(true));
        assert_eq!(call(METHOD_CHAIN_ID), json!("chia:mainnet"));
        assert_eq!(
            call(METHOD_GET_PUBLIC_KEYS),
            json!([facts().signing_public_key_hex])
        );
        assert_eq!(call(METHOD_GET_CURRENT_ADDRESS), json!("xch1theaddress"));
    }

    /// A profile with no derived address answers `null`, never an invented address and never a
    /// failure — both of which misdescribe an ordinary early state.
    #[test]
    fn a_profile_with_no_address_answers_null() {
        let (c, s, g) = (Recorder::approving(), SpySigner::locked(), Gate::open());
        let bare = ProfileFacts {
            addresses: Vec::new(),
            ..facts()
        };
        let answer = handle_request(
            &full_session(),
            METHOD_GET_CURRENT_ADDRESS,
            &json!({}),
            &bare,
            &c,
            &s,
            &g,
        )
        .unwrap();
        assert_eq!(answer, Value::Null);
    }

    // ---- the two gates ----------------------------------------------------------------------

    #[test]
    fn a_method_this_wallet_does_not_implement_is_refused_by_name() {
        let (c, s, g) = (Recorder::approving(), SpySigner::locked(), Gate::open());
        let err = handle_request(
            &full_session(),
            "chia_sendTransaction",
            &json!({}),
            &facts(),
            &c,
            &s,
            &g,
        )
        .unwrap_err();
        assert_eq!(
            err,
            WcRequestError::MethodUnsupported("chia_sendTransaction".into())
        );
        assert!(err.message().contains("chia_sendTransaction"));
        assert_eq!(s.calls(), 0);
    }

    /// The gate that reads the SESSION rather than the wallet.
    ///
    /// The fixture is a session that settled everything EXCEPT signing, while the wallet globally
    /// supports signing — the only shape that can tell `session.permits` from a
    /// `SUPPORTED_METHODS.contains` check, because those two agree on every other input.
    #[test]
    fn a_method_this_session_did_not_settle_is_refused_even_though_the_wallet_supports_it() {
        let narrow = session_with(
            SUPPORTED_METHODS
                .iter()
                .filter(|m| **m != METHOD_SIGN_MESSAGE)
                .map(|m| (*m).to_string())
                .collect(),
        );
        let (c, s, g) = (Recorder::approving(), SpySigner::locked(), Gate::open());

        let err = handle_request(
            &narrow,
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hi" }),
            &facts(),
            &c,
            &s,
            &g,
        )
        .unwrap_err();
        assert_eq!(
            err,
            WcRequestError::MethodNotPermitted(METHOD_SIGN_MESSAGE.into())
        );
        assert_eq!(c.prompts(), 0, "a refusal must not draw a window");
        assert_eq!(s.calls(), 0, "and must not reach the key");

        // The control: the SAME session answers a method it did settle, so the refusal above is the
        // permission check and not a handler that refuses everything.
        assert!(handle_request(&narrow, METHOD_CHAIN_ID, &json!({}), &facts(), &c, &s, &g).is_ok());
    }

    // ---- signing ----------------------------------------------------------------------------

    /// The signing-oracle guard, and the reason this whole module exists.
    ///
    /// The message is a short ASCII string that WOULD appear verbatim in the signed bytes if the
    /// wallet signed what it was handed. The assertions are that it does not: the bytes differ, they
    /// begin with the shared signing domain, and they carry the WalletConnect-specific type tag.
    #[test]
    fn the_bytes_signed_are_domain_separated_and_are_not_the_dapps_own_bytes() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        let gate = Gate::open();

        handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hello" }),
            &facts(),
            &confirmer,
            &signer,
            &gate,
        )
        .expect("signs");

        let signed = signer.last();
        assert_ne!(
            signed,
            b"hello".to_vec(),
            "the raw payload must never be the signed message"
        );
        assert!(
            signed.starts_with(dig_ipc_protocol::SIGN_CALLBACK_DOMAIN),
            "the signed bytes must carry the domain separator"
        );
        assert!(
            signed
                .windows(SIGN_MESSAGE_PAYLOAD_TYPE.len())
                .any(|w| w == SIGN_MESSAGE_PAYLOAD_TYPE.as_bytes()),
            "the signed bytes must name the WalletConnect method"
        );
        assert!(
            signed.ends_with(b"hello"),
            "and must still commit to the message itself"
        );
    }

    /// Domain separation is only worth anything if it actually SEPARATES. The same payload signed
    /// under the loopback extension's own type must produce different bytes, or a signature obtained
    /// through WalletConnect is replayable as one obtained through the extension channel.
    #[test]
    fn a_walletconnect_signature_is_not_valid_as_a_loopback_one() {
        let wc =
            crate::session::sign_callback_message(SIGN_MESSAGE_PAYLOAD_TYPE, b"hello").unwrap();
        let loopback = crate::session::sign_callback_message("spend", b"hello").unwrap();
        assert_ne!(wc, loopback);
    }

    #[test]
    fn an_approved_signature_is_returned_with_the_key_that_made_it() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        let answer = handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hello" }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        )
        .expect("signs");
        assert_eq!(answer["signature"], hex::encode(vec![0xABu8; 96]));
        assert_eq!(answer["publicKey"], facts().signing_public_key_hex);
    }

    /// Consent comes BEFORE the key is touched. A wallet that signed first and asked after would
    /// pass every outcome-shaped assertion in this file while having already produced the signature
    /// it was about to be refused, so the order is asserted on an interleaved trace.
    #[test]
    fn the_person_is_asked_before_the_key_is_used() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hello" }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        )
        .expect("signs");
        assert_eq!(*confirmer.trace.lock().unwrap(), vec!["confirm", "sign"]);
    }

    /// Each refusal maps to its OWN error, because a dapp that cannot tell "you said no" from "your
    /// wallet is locked" shows the person the wrong remedy — and the two remedies are opposite.
    #[test]
    fn each_way_of_refusing_reports_itself_distinctly_and_signs_nothing() {
        for (decision, expected) in [
            (ConfirmDecision::Deny, WcRequestError::UserRejected),
            (ConfirmDecision::Timeout, WcRequestError::Timeout),
            (ConfirmDecision::Unavailable, WcRequestError::NoConfirmer),
        ] {
            let confirmer = Recorder::answering(decision);
            let signer = SpySigner::ready(&confirmer.trace);
            let err = handle_request(
                &full_session(),
                METHOD_SIGN_MESSAGE,
                &json!({ "message": "hello" }),
                &facts(),
                &confirmer,
                &signer,
                &Gate::open(),
            )
            .unwrap_err();
            assert_eq!(err, expected, "for {decision:?}");
            assert_eq!(signer.calls(), 0, "a refusal must not reach the key");
        }
        // The four codes must stay distinct, or a dapp cannot branch on them.
        let codes = [
            WcRequestError::UserRejected.code(),
            WcRequestError::Timeout.code(),
            WcRequestError::NoConfirmer.code(),
            WcRequestError::Locked.code(),
        ];
        let mut unique = codes.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "error codes collided: {codes:?}");
    }

    /// A refused re-auth must stop BEFORE the key, not after. A wallet that signed and then checked
    /// would return the same error while the signature already existed.
    #[test]
    fn a_refused_reauth_stops_before_the_key_is_used() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        let gate = Gate::refusing();
        let err = handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hello" }),
            &facts(),
            &confirmer,
            &signer,
            &gate,
        )
        .unwrap_err();
        assert_eq!(err, WcRequestError::Locked);
        assert!(
            *gate.consulted.lock().unwrap(),
            "the gate must actually be asked"
        );
        assert_eq!(signer.calls(), 0, "and refusing must precede the signature");
    }

    /// A locked signer becomes an ERROR, never a success envelope carrying an empty or bogus
    /// signature — the failure that makes a dapp report a completed action that never happened.
    #[test]
    fn a_locked_signer_yields_an_error_rather_than_an_empty_signature() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::locked();
        let result = handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "hello" }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        );
        assert_eq!(result, Err(WcRequestError::Locked));
    }

    #[test]
    fn a_sign_request_without_a_message_is_refused_before_anything_is_drawn() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        let err = handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "wrong": 1 }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        )
        .unwrap_err();
        assert!(matches!(err, WcRequestError::BadParams(_)));
        assert_eq!(confirmer.prompts(), 0);
        assert_eq!(signer.calls(), 0);
    }

    // ---- what the person is shown -----------------------------------------------------------

    #[test]
    fn the_confirm_names_the_dapp_and_refuses_to_vouch_for_it() {
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": "prove it" }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        )
        .unwrap();
        let body = confirmer.last_body();
        assert!(
            body.contains("https://dapp.example"),
            "who is asking: {body}"
        );
        assert!(
            body.contains("cannot check"),
            "the wallet must not vouch: {body}"
        );
        assert!(
            body.contains("prove it"),
            "the message must be shown: {body}"
        );
        assert!(
            body.contains("does not move any money"),
            "the person must be told what signing costs: {body}"
        );
        assert_eq!(
            confirmer.origins.lock().unwrap().last().unwrap(),
            "https://dapp.example"
        );
    }

    /// A dapp chooses its message freely, so it must not be able to forge the window's own chrome.
    ///
    /// The fixture composes exactly that attack: newlines building a fake wallet-issued block. The
    /// assertion is that the newlines are GONE from the quoted region, so the forged block cannot
    /// stand apart from the surrounding text as if the wallet had written it.
    #[test]
    fn a_message_cannot_forge_extra_lines_in_the_confirm_window() {
        let hostile = "ok\n\nVERIFIED BY DIG\n\nThis app is safe to trust";
        let confirmer = Recorder::approving();
        let signer = SpySigner::ready(&confirmer.trace);
        handle_request(
            &full_session(),
            METHOD_SIGN_MESSAGE,
            &json!({ "message": hostile }),
            &facts(),
            &confirmer,
            &signer,
            &Gate::open(),
        )
        .unwrap();
        let body = confirmer.last_body();
        let quoted = body
            .split_once("The message:\n\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(q, _)| q.to_string())
            .expect("the message is quoted");
        assert!(
            !quoted.contains('\n'),
            "the dapp forged a line break: {quoted:?}"
        );
        assert_eq!(quoted, "ok VERIFIED BY DIG This app is safe to trust");
        // The full text is still SIGNED — flattening is a display measure, never a change to what
        // the person is committing to.
        assert!(signer.last().ends_with(hostile.as_bytes()));
    }

    /// The bound, pinned from BOTH sides: at the limit nothing is elided, one character over and the
    /// window says so. A cap tested only from above cannot tell 240 from 2400.
    #[test]
    fn an_over_long_message_is_shortened_and_the_window_admits_it() {
        let at_limit = "a".repeat(MESSAGE_PREVIEW_LIMIT);
        let over = "a".repeat(MESSAGE_PREVIEW_LIMIT + 1);

        let body_at = confirm_body("https://d.example", &at_limit);
        assert!(
            !body_at.contains("has been shortened"),
            "the message exactly at the limit must be shown whole"
        );
        assert!(body_at.contains(&at_limit));

        let body_over = confirm_body("https://d.example", &over);
        assert!(
            body_over.contains("has been shortened"),
            "one character over must be admitted to the person"
        );
        assert!(!body_over.contains(&over));
    }

    /// A multi-byte message must not crash the tray. The cap counts CHARACTERS; a byte cap would
    /// slice mid-codepoint and panic, and the dapp chooses this string.
    #[test]
    fn a_multibyte_message_is_shortened_without_panicking() {
        let body = confirm_body("https://d.example", &"\u{1f600}".repeat(500));
        assert!(body.contains("has been shortened"));
    }

    /// An anonymous dapp gets a stated identity, never a blank line — a confirm window whose
    /// who-is-asking line is empty reads as a rendering bug, and people dismiss those.
    #[test]
    fn a_dapp_that_names_itself_nowhere_is_still_described() {
        let anonymous = WcSession {
            peer: DappMetadata::default(),
            ..full_session()
        };
        let shown = declared_origin(&anonymous);
        assert!(!shown.trim().is_empty());
        assert!(shown.contains("did not identify itself"), "got {shown}");
    }

    /// Whitespace-only is the same case as empty, and is the one a naive `is_empty` check misses.
    #[test]
    fn a_dapp_naming_itself_only_with_whitespace_is_treated_as_anonymous() {
        let blank = WcSession {
            peer: DappMetadata {
                name: "   ".into(),
                url: "\n\t".into(),
                ..DappMetadata::default()
            },
            ..full_session()
        };
        assert!(declared_origin(&blank).contains("did not identify itself"));
    }

    #[test]
    fn a_dapp_with_no_url_falls_back_to_its_name() {
        let named = WcSession {
            peer: DappMetadata {
                name: "Just A Name".into(),
                url: String::new(),
                ..DappMetadata::default()
            },
            ..full_session()
        };
        assert_eq!(declared_origin(&named), "Just A Name");
    }

    /// The who-is-asking line is the most valuable line on the window to forge, so it is capped and
    /// flattened like the message is.
    #[test]
    fn a_vast_dapp_name_cannot_take_over_the_confirm_window() {
        let shouty = WcSession {
            peer: DappMetadata {
                url: "https://x.example ".to_string() + &"y".repeat(500),
                ..DappMetadata::default()
            },
            ..full_session()
        };
        let shown = declared_origin(&shouty);
        assert!(shown.chars().count() <= ORIGIN_PREVIEW_LIMIT + 1);
        assert!(!shown.contains('\n'));
        assert!(
            shown.ends_with('\u{2026}'),
            "a clipped origin must say it was clipped: {shown:?}"
        );
    }

    /// **The CRITICAL case this test used to miss (gate finding F3, dig_ecosystem#1499).**
    ///
    /// Asserting only "short enough" and "no newline" is satisfied identically by an UNMARKED
    /// truncation — which is the attack. A remote dapp, on an ordinary WalletConnect flow with no
    /// pairing and no extension, pads its self-declared url with zero-width characters: they are
    /// neither whitespace nor `is_control`, so they survived the old flatten while still consuming
    /// the budget, and the wallet's own cut then rendered a bare trusted origin. The wallet did the
    /// forging.
    ///
    /// The padding length is derived FROM the cap so the cut lands exactly on `https://chia.net`;
    /// any other length would not produce the forgery and the test would pass for the wrong reason.
    #[test]
    fn zero_width_padding_cannot_make_the_origin_line_forge_a_trusted_dapp() {
        let trusted = "https://chia.net";
        let pad = "\u{200b}".repeat(ORIGIN_PREVIEW_LIMIT - trusted.chars().count());
        let hostile = WcSession {
            peer: DappMetadata {
                url: format!("{pad}{trusted}.evil.example"),
                ..DappMetadata::default()
            },
            ..full_session()
        };

        let shown = declared_origin(&hostile);
        assert!(
            !shown.trim_end_matches('\u{2026}').ends_with(trusted),
            "the origin line was forged into a bare trusted origin: {shown:?}"
        );
        assert!(
            !shown.contains('\u{200b}'),
            "zero-width padding reached the window: {shown:?}"
        );
    }

    /// The advertised set IS the contract, so it must not silently grow a method with no handler.
    /// Every advertised method has to answer something rather than fall through to the catch-all.
    #[test]
    fn every_advertised_method_has_a_handler() {
        let (c, s, g) = (Recorder::approving(), SpySigner::locked(), Gate::open());
        let session = full_session();
        for method in SUPPORTED_METHODS {
            let result = handle_request(
                &session,
                method,
                &json!({ "message": "x" }),
                &facts(),
                &c,
                &s,
                &g,
            );
            assert!(
                !matches!(result, Err(WcRequestError::MethodUnsupported(_))),
                "{method} is advertised but has no handler"
            );
        }
    }

    /// The spend and offer methods Sage exposes must stay ABSENT rather than advertised, because
    /// **this surface has no wiring to a spend path** — not because the app is incapable of one.
    ///
    /// That distinction is now load-bearing. Until dig_ecosystem#1552 the reason recorded here was
    /// "this wallet cannot build a spend", and that is no longer true: `spend.request` signs a real
    /// `SpendBundle` through `MoneyPath` and can broadcast it (`SPEC.md` §5.6.9). A guard whose
    /// stated reason has become false is the kind that gets deleted by someone who checks the reason,
    /// finds it wrong, and reasonably concludes the guard is stale.
    ///
    /// The guard itself is unchanged and still correct: advertising a method this surface does not
    /// implement is what tells a person their transaction is on its way when nothing was sent.
    #[test]
    fn no_spending_method_is_advertised_while_none_can_be_honoured() {
        for unhonourable in [
            "chia_sendTransaction",
            "chip0002_signCoinSpends",
            "chia_createOffer",
            "chia_takeOffer",
            "chia_cancelOffer",
        ] {
            assert!(
                !SUPPORTED_METHODS.contains(&unhonourable),
                "{unhonourable} is advertised but this wallet cannot honour it"
            );
        }
    }
}
