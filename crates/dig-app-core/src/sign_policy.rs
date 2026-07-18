//! The ONE production sign-authorization policy — decode, then native-confirm (SIGN-2, `SPEC.md`
//! §5.6.5/§5.6.6, **security-critical / custody**).
//!
//! Both signing entry points funnel through this single policy so there is exactly one authorization
//! point with no divergence (§5.6.6):
//!
//! - the §5.3 engine `sign` callback ([`crate::session::SessionClient`]), via the [`SignPolicy`] trait;
//! - the §5.6.5 loopback `sign.request` handler ([`crate::loopback::dispatch`]), via [`Self::decide`].
//!
//! The policy never signs and never touches a key — it only rules. For every request it:
//!
//! 1. **decodes** the payload into human terms ([`crate::decode`]); an unknown or undecodable payload
//!    is refused (never blind-signed);
//! 2. **raises the native confirm** ([`NativeConfirmer::confirm_sign`]) showing the decoded transaction
//!    and the vouched origin — the terminal human gate (biometric/passphrase, SIGN-3).
//!
//! Only on an explicit human approval does the caller then sign the domain-separated
//! `DIGNET-SIGN-v1` message (`session.rs::sign_callback_message`). The `AllowAll`/`DenyAll` policies
//! in `session.rs` remain TEST doubles; production wires this policy.

use std::sync::Arc;

use crate::confirm::{ConfirmDecision, NativeConfirmer, SignPrompt};
use crate::decode::{decode, DecodeReject};
use crate::session::{SignDecision, SignPolicy, SignRequest};
use crate::spend_summary;

/// Why the policy refused to authorize a signature. Each maps to a stable §5.6.7 symbol so both the
/// loopback wire codes and the engine `SignDecision::Deny` reason derive from one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignRejection {
    /// `payload_type` is not on the decoder allowlist — a blind-sign request (`SIGN_UNKNOWN_TYPE`).
    UnknownType,
    /// A known type whose payload did not decode for display (`SIGN_BAD_PAYLOAD`).
    BadPayload,
    /// The user denied the sign confirm (`SIGN_DENIED`).
    Denied,
    /// The user did not answer the sign confirm in time (`SIGN_TIMEOUT`).
    Timeout,
    /// No native confirmer is available — headless, fail-closed (`SIGN_NO_CONFIRMER`).
    NoConfirmer,
}

impl SignRejection {
    /// The canonical §5.6.7 symbol string for this rejection.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::UnknownType => "SIGN_UNKNOWN_TYPE",
            Self::BadPayload => "SIGN_BAD_PAYLOAD",
            Self::Denied => "SIGN_DENIED",
            Self::Timeout => "SIGN_TIMEOUT",
            Self::NoConfirmer => "SIGN_NO_CONFIRMER",
        }
    }
}

/// The policy's ruling on one sign request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignVerdict {
    /// The human approved — the caller may sign the domain-separated message.
    Approve,
    /// Refused; nothing is signed. Carries the reason for the caller's error mapping.
    Reject(SignRejection),
}

/// What the policy needs to know to rule on a signature, independent of which entry point asked. The
/// `payload` is the exact bytes that will be signed, so the decoded display binds to what is signed
/// (§ [`crate::decode`]).
pub struct SignSubject<'a> {
    /// The vouched dapp origin (loopback path), or `None` for the engine callback path (no origin).
    pub origin: Option<&'a str>,
    /// The `payload_type` tag selecting the decoder + allowlist (§5.6.5).
    pub payload_type: &'a str,
    /// The raw bytes that will be signed.
    pub payload: &'a [u8],
}

/// The production sign policy: decode + native confirm. Holds a shared [`NativeConfirmer`] (the per-OS
/// biometric confirm in production, SIGN-3; a fail-closed [`crate::confirm::HeadlessConfirmer`] until
/// then) and no key material — the terminal human gate lives entirely in the confirmer.
pub struct NativeConfirmSignPolicy {
    confirmer: Arc<dyn NativeConfirmer>,
}

impl NativeConfirmSignPolicy {
    /// Build the policy over the shared native confirmer that draws the sign-confirm window.
    pub fn new(confirmer: Arc<dyn NativeConfirmer>) -> Self {
        Self { confirmer }
    }

    /// Rule on `subject`: decode it (fail closed on unknown/undecodable), then raise the native
    /// sign-confirm showing the decoded transaction. Returns [`SignVerdict::Approve`] only on an
    /// explicit human approval.
    pub fn decide(&self, subject: &SignSubject<'_>) -> SignVerdict {
        let decoded = match decode(subject.payload_type, subject.payload) {
            Ok(decoded) => decoded,
            Err(DecodeReject::UnknownType) => {
                return SignVerdict::Reject(SignRejection::UnknownType)
            }
            Err(DecodeReject::BadPayload) => return SignVerdict::Reject(SignRejection::BadPayload),
        };

        // The confirm shows a plain-language summary as the default view, with the precise mojo-level
        // decode kept below as details — both derived from the same decoded bytes (WSEC-B, §5.6.5).
        let body = spend_summary::confirm_body(&decoded);
        let decision = self.confirmer.confirm_sign(&SignPrompt {
            origin: subject.origin.unwrap_or_default(),
            payload_type: subject.payload_type,
            decoded_tx: Some(&body),
        });

        match decision {
            ConfirmDecision::Approve => SignVerdict::Approve,
            ConfirmDecision::Deny => SignVerdict::Reject(SignRejection::Denied),
            ConfirmDecision::Timeout => SignVerdict::Reject(SignRejection::Timeout),
            ConfirmDecision::Unavailable => SignVerdict::Reject(SignRejection::NoConfirmer),
        }
    }
}

/// The engine `sign` callback path (§5.3): the engine supplies no dapp origin, and the granular
/// rejection collapses to the callback's single `Deny(reason)` (the engine keys off the reason
/// string; the loopback path keeps the granular §5.6.7 code via [`NativeConfirmSignPolicy::decide`]).
impl SignPolicy for NativeConfirmSignPolicy {
    fn authorize(&self, request: &SignRequest<'_>) -> SignDecision {
        let subject = SignSubject {
            origin: None,
            payload_type: request.payload_type,
            payload: request.payload,
        };
        match self.decide(&subject) {
            SignVerdict::Approve => SignDecision::Allow,
            SignVerdict::Reject(rejection) => SignDecision::Deny(rejection.symbol().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConnectPrompt, PairPrompt};
    use chia_bls::{SecretKey, Signature};
    use chia_protocol::{Bytes32, Coin, SpendBundle};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::{DeriveSynthetic, Memos};
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_types::conditions::CreateCoin;
    use chia_sdk_types::Conditions;
    use chia_traits::Streamable;
    use chip35_dl_coin::master_to_wallet_unhardened;

    /// A confirmer scripted to return a fixed decision for every prompt (the SIGN-3 confirmer double).
    struct ScriptedConfirmer(ConfirmDecision);
    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_connect(&self, _: &ConnectPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_sign(&self, _: &SignPrompt<'_>) -> ConfirmDecision {
            self.0
        }
    }

    fn policy(decision: ConfirmDecision) -> NativeConfirmSignPolicy {
        NativeConfirmSignPolicy::new(Arc::new(ScriptedConfirmer(decision)))
    }

    /// A real, decodable spend-bundle payload (a standard-layer coin creating one output).
    fn spend_payload() -> Vec<u8> {
        let master = SecretKey::from_seed(&[3u8; 32]);
        let pk = master_to_wallet_unhardened(&master.public_key(), 0).derive_synthetic();
        let mut ctx = SpendContext::new();
        let coin = Coin {
            parent_coin_info: Bytes32::new([1u8; 32]),
            puzzle_hash: StandardArgs::curry_tree_hash(pk).into(),
            amount: 1_000,
        };
        let recipient: Bytes32 = StandardArgs::curry_tree_hash(pk).into();
        StandardLayer::new(pk)
            .spend(
                &mut ctx,
                coin,
                Conditions::new().with(CreateCoin::new(recipient, 800, Memos::None)),
            )
            .unwrap();
        SpendBundle::new(ctx.take(), Signature::default())
            .to_bytes()
            .unwrap()
    }

    fn subject<'a>(payload_type: &'a str, payload: &'a [u8]) -> SignSubject<'a> {
        SignSubject {
            origin: Some("https://dapp.example"),
            payload_type,
            payload,
        }
    }

    #[test]
    fn an_approving_confirm_of_a_decodable_spend_is_approved() {
        let payload = spend_payload();
        let verdict = policy(ConfirmDecision::Approve).decide(&subject("spend", &payload));
        assert_eq!(verdict, SignVerdict::Approve);
    }

    #[test]
    fn a_denied_confirm_rejects_with_sign_denied() {
        let payload = spend_payload();
        let verdict = policy(ConfirmDecision::Deny).decide(&subject("spend", &payload));
        assert_eq!(verdict, SignVerdict::Reject(SignRejection::Denied));
    }

    #[test]
    fn a_timeout_confirm_rejects_with_sign_timeout() {
        let payload = spend_payload();
        let verdict = policy(ConfirmDecision::Timeout).decide(&subject("spend", &payload));
        assert_eq!(verdict, SignVerdict::Reject(SignRejection::Timeout));
    }

    #[test]
    fn a_headless_host_rejects_with_no_confirmer() {
        let payload = spend_payload();
        let verdict = policy(ConfirmDecision::Unavailable).decide(&subject("spend", &payload));
        assert_eq!(verdict, SignVerdict::Reject(SignRejection::NoConfirmer));
    }

    #[test]
    fn an_unknown_type_is_refused_before_any_confirm() {
        // Even an approving confirmer never signs an unknown type — the decode gate fails first.
        let verdict = policy(ConfirmDecision::Approve).decide(&subject("mystery", b"bytes"));
        assert_eq!(verdict, SignVerdict::Reject(SignRejection::UnknownType));
    }

    #[test]
    fn an_undecodable_known_type_is_refused_before_any_confirm() {
        let verdict = policy(ConfirmDecision::Approve).decide(&subject("spend", b"not a bundle"));
        assert_eq!(verdict, SignVerdict::Reject(SignRejection::BadPayload));
    }

    /// A confirmer that records the `decoded_tx` body it was shown, to assert what the human sees.
    struct RecordingConfirmer(std::sync::Mutex<Option<String>>);
    impl NativeConfirmer for RecordingConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_connect(&self, _: &ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_sign(&self, prompt: &SignPrompt<'_>) -> ConfirmDecision {
            *self.0.lock().unwrap() = prompt.decoded_tx.map(str::to_string);
            ConfirmDecision::Approve
        }
    }

    #[test]
    fn the_confirm_shows_a_plain_language_summary_derived_from_the_signed_bytes() {
        // spend_payload creates one 800-mojo output from a 1_000-mojo coin (a 200-mojo fee). The
        // confirm body must lead with the human XCH summary and keep the raw mojo decode as details —
        // both from the SAME bytes handed to the decoder (display-binds).
        let payload = spend_payload();
        let recorder = Arc::new(RecordingConfirmer(std::sync::Mutex::new(None)));
        let policy = NativeConfirmSignPolicy::new(recorder.clone());

        let verdict = policy.decide(&subject("spend", &payload));
        assert_eq!(verdict, SignVerdict::Approve);

        let shown = recorder
            .0
            .lock()
            .unwrap()
            .clone()
            .expect("a body was shown");
        assert!(
            shown.contains("Send 0.0000000008 XCH to xch1"),
            "plain-language XCH summary is the default view, got: {shown}"
        );
        assert!(shown.contains("Network fee: 0.0000000002 XCH"));
        assert!(
            shown.contains("Details:") && shown.contains("800 mojos"),
            "the raw mojo decode is kept as details"
        );
        assert_eq!(
            &shown,
            &spend_summary::confirm_body(&decode("spend", &payload).unwrap()),
            "the shown body is exactly the summary of the decoded signed bytes"
        );
    }

    #[test]
    fn the_engine_sign_policy_maps_approve_to_allow() {
        let payload = spend_payload();
        let request = SignRequest {
            session_id: "s",
            op_id: "o",
            payload_type: "spend",
            payload: &payload,
            context: None,
        };
        assert_eq!(
            policy(ConfirmDecision::Approve).authorize(&request),
            SignDecision::Allow
        );
    }

    #[test]
    fn the_engine_sign_policy_maps_an_unknown_type_to_a_symbolic_deny() {
        let request = SignRequest {
            session_id: "s",
            op_id: "o",
            payload_type: "mystery",
            payload: b"x",
            context: None,
        };
        assert_eq!(
            policy(ConfirmDecision::Approve).authorize(&request),
            SignDecision::Deny("SIGN_UNKNOWN_TYPE".to_string())
        );
    }
}
