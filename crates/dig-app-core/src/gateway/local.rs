//! The local-identity seam: serve a [`Route::UserApp`] command with the held user identity.
//!
//! Local commands — profiles, wallet, sign — are served IN the user app because they need the
//! in-memory user key or the user's profile state (which never leave the app; the engine is
//! identity-agnostic, SPEC §2.3). The gateway does not itself touch the keystore or profile store;
//! it depends on the [`LocalIdentity`] seam, whose real implementation the binary wires over the
//! U4 keystore + U5 profile store. Keeping the seam here means the gateway's local dispatch is
//! unit-tested against a double, and the identity subsystems stay owned by their own modules.

use serde_json::json;

use super::command::{Command, ProfilesAction, WalletAction};
use super::outcome::{ErrorCode, GatewayError, Outcome};
use crate::confirm::{ConfirmDecision, NativeConfirmer, SignPrompt};
use crate::session::user_sign_message;

/// The `payload_type` label the local `dign sign` path presents at the native confirm. Unlike the
/// engine/dapp `sign` paths — which name a decodable transaction type (`spend`, …) — this is the
/// user signing their OWN arbitrary message, so it carries no transaction decoder; the confirm shows
/// the message text verbatim.
const USER_SIGN_PAYLOAD_TYPE: &str = "user-message";

/// A one-line view of a profile for the CLI: its DID, display name, and whether it is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    /// The profile's `did:chia:` decentralized identifier.
    pub did: String,
    /// The human display name.
    pub name: String,
    /// Whether this is the currently active profile.
    pub active: bool,
}

/// The held user identity the gateway serves local commands against.
///
/// The real implementation is backed by the U4 keystore (sign), the U5 profile store (profiles),
/// and the wallet host; it returns [`ErrorCode::Locked`] when no profile is unlocked. Every method
/// is fallible so a locked / missing-profile state surfaces as a catalogued error, never a panic.
pub trait LocalIdentity {
    /// Every profile known to the user app, active flag set on the current one.
    fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError>;
    /// Create a new profile with `name`, returning its summary (its freshly minted DID).
    fn create_profile(&self, name: &str) -> Result<ProfileSummary, GatewayError>;
    /// Make the profile identified by `did` the active one.
    fn select_profile(&self, did: &str) -> Result<(), GatewayError>;
    /// The active profile's wallet receive address.
    fn wallet_address(&self) -> Result<String, GatewayError>;
    /// The active profile's confirmed balance, in mojos.
    fn wallet_balance(&self) -> Result<u64, GatewayError>;
    /// Sign `message` with the active profile's identity key, returning the raw signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, GatewayError>;
}

/// Serve a local command against `identity`, producing the dual human/machine [`Outcome`].
///
/// # Panics
/// Never — engine-routed commands are dispatched elsewhere; passing one here is a gateway bug and
/// yields an `internal` usage error rather than a panic.
pub fn handle_local(
    command: &Command,
    identity: &dyn LocalIdentity,
    confirmer: &dyn NativeConfirmer,
) -> Result<Outcome, GatewayError> {
    tracing::debug!(action = command.action(), "routing command locally");
    let result = match command {
        Command::Profiles(action) => handle_profiles(action, identity),
        Command::Wallet(action) => handle_wallet(action, identity),
        Command::Sign { message } => handle_sign(message, identity, confirmer),
        other => Err(GatewayError::new(
            ErrorCode::Usage,
            format!("{} is not a local command", other.action()),
        )),
    };
    if let Err(e) = &result {
        tracing::warn!(action = command.action(), code = ?e.code, "local command failed");
    }
    result
}

/// Serve the profile sub-commands: list / show the active one / create / select.
fn handle_profiles(
    action: &ProfilesAction,
    identity: &dyn LocalIdentity,
) -> Result<Outcome, GatewayError> {
    match action {
        ProfilesAction::List => {
            let profiles = identity.profiles()?;
            let summary = format!("{} profile(s)", profiles.len());
            let result = json!({ "profiles": profiles_to_json(&profiles) });
            Ok(Outcome::new(summary, result))
        }
        ProfilesAction::Show => {
            let active = active_profile(identity)?;
            Ok(Outcome::new(
                format!("active profile: {} ({})", active.name, active.did),
                json!({ "profile": profile_to_json(&active) }),
            ))
        }
        ProfilesAction::Create { name } => {
            let created = identity.create_profile(name)?;
            Ok(Outcome::new(
                format!("created profile \"{}\" ({})", created.name, created.did),
                json!({ "profile": profile_to_json(&created) }),
            ))
        }
        ProfilesAction::Select { did } => {
            identity.select_profile(did)?;
            Ok(Outcome::new(
                format!("active profile is now {did}"),
                json!({ "active_did": did }),
            ))
        }
    }
}

/// Serve the wallet sub-commands: the active profile's address / balance.
fn handle_wallet(
    action: &WalletAction,
    identity: &dyn LocalIdentity,
) -> Result<Outcome, GatewayError> {
    match action {
        WalletAction::Address => {
            let address = identity.wallet_address()?;
            Ok(Outcome::new(
                format!("wallet address: {address}"),
                json!({ "address": address }),
            ))
        }
        WalletAction::Balance => {
            let mojos = identity.wallet_balance()?;
            Ok(Outcome::new(
                format!("confirmed balance: {mojos} mojos"),
                json!({ "balance_mojos": mojos }),
            ))
        }
    }
}

/// Serve `sign`: gate on the native confirm, then sign the DOMAIN-SEPARATED user-sign message with
/// the active identity key, returning a hex signature.
///
/// Two custody guards, both mandatory (SPEC §3.5, security fix #959):
///
/// 1. **Confirm gate.** The local gateway holds the custody key, so a local process could otherwise
///    obtain an identity-key signature silently. Every `dign sign` is gated on the terminal native
///    confirm ([`NativeConfirmer::confirm_sign`], the SIGN-1 seam) — the same human authorization the
///    engine (§5.3) and dapp (§5.6) sign paths require, so all three signing paths funnel through a
///    human gate with no silent-signing divergence. A declined / timed-out / headless confirm yields
///    [`ErrorCode::Denied`] and NEVER touches the key.
/// 2. **Domain separation.** On approval the key signs [`user_sign_message`] (the `DIGNET-USER-SIGN-v1`
///    tag ‖ the message) — NEVER the raw `message.as_bytes()`. This closes the cross-protocol signing
///    oracle: because the tag is distinct from every other 0x0010 purpose, a `dign sign` signature can
///    never be replayed as a session attach or a spend/callback authorization, even if the caller
///    shapes `message` to look like one of those bodies.
fn handle_sign(
    message: &str,
    identity: &dyn LocalIdentity,
    confirmer: &dyn NativeConfirmer,
) -> Result<Outcome, GatewayError> {
    // The user is signing their own message; show it verbatim at the confirm — there is no
    // transaction to decode, so `decoded_tx` carries the plaintext being signed.
    let decision = confirmer.confirm_sign(&SignPrompt {
        origin: "",
        payload_type: USER_SIGN_PAYLOAD_TYPE,
        decoded_tx: Some(message),
    });
    match decision {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => {
            return Err(GatewayError::new(
                ErrorCode::Denied,
                "signing was declined at the confirm prompt",
            ))
        }
        ConfirmDecision::Timeout => {
            return Err(GatewayError::new(
                ErrorCode::Denied,
                "the sign confirm was not answered in time",
            ))
        }
        ConfirmDecision::Unavailable => {
            return Err(GatewayError::new(
                ErrorCode::Denied,
                "no native confirmer is available to authorize signing",
            )
            .with_hint("signing requires a desktop session with the dig-app confirm prompt"))
        }
    }

    let signature = identity.sign(&user_sign_message(message.as_bytes()))?;
    let hex = hex::encode(signature);
    Ok(Outcome::new(
        format!("signature: {hex}"),
        json!({ "signature": hex }),
    ))
}

/// The active profile, or a `NOT_FOUND` error when none is selected.
fn active_profile(identity: &dyn LocalIdentity) -> Result<ProfileSummary, GatewayError> {
    identity
        .profiles()?
        .into_iter()
        .find(|profile| profile.active)
        .ok_or_else(|| {
            GatewayError::new(ErrorCode::NotFound, "no active profile")
                .with_hint("create one with `dign profiles create <name>`")
        })
}

fn profiles_to_json(profiles: &[ProfileSummary]) -> serde_json::Value {
    serde_json::Value::Array(profiles.iter().map(profile_to_json).collect())
}

fn profile_to_json(profile: &ProfileSummary) -> serde_json::Value {
    json!({ "did": profile.did, "name": profile.name, "active": profile.active })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A test double: an in-memory profile set + a canned signature, tracking the last `select`.
    #[derive(Default)]
    struct FakeIdentity {
        profiles: Vec<ProfileSummary>,
        selected: RefCell<Option<String>>,
        locked: bool,
    }

    impl LocalIdentity for FakeIdentity {
        fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
            Ok(self.profiles.clone())
        }
        fn create_profile(&self, name: &str) -> Result<ProfileSummary, GatewayError> {
            Ok(ProfileSummary {
                did: format!("did:chia:{name}"),
                name: name.into(),
                active: true,
            })
        }
        fn select_profile(&self, did: &str) -> Result<(), GatewayError> {
            *self.selected.borrow_mut() = Some(did.into());
            Ok(())
        }
        fn wallet_address(&self) -> Result<String, GatewayError> {
            Ok("xch1testaddr".into())
        }
        fn wallet_balance(&self) -> Result<u64, GatewayError> {
            Ok(1_234)
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, GatewayError> {
            if self.locked {
                return Err(GatewayError::new(ErrorCode::Locked, "no unlocked identity"));
            }
            Ok(message.to_vec())
        }
    }

    fn one_active(name: &str) -> ProfileSummary {
        ProfileSummary {
            did: format!("did:chia:{name}"),
            name: name.into(),
            active: true,
        }
    }

    /// A native-confirm double returning a fixed decision — the SIGN-3 confirmer stand-in for the
    /// gateway's local sign gate.
    struct ScriptedConfirmer(ConfirmDecision);
    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _: &crate::confirm::PairPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_connect(&self, _: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            self.0
        }
        fn confirm_sign(&self, _: &SignPrompt<'_>) -> ConfirmDecision {
            self.0
        }
    }

    /// A confirmer that approves every prompt (for the non-sign commands, which never consult it).
    fn approving() -> ScriptedConfirmer {
        ScriptedConfirmer(ConfirmDecision::Approve)
    }

    /// Serve a `dign sign` of `message` against `identity`, gated by a confirmer scripted to `decision`.
    fn sign(
        identity: &FakeIdentity,
        message: &str,
        decision: ConfirmDecision,
    ) -> Result<Outcome, GatewayError> {
        handle_local(
            &Command::Sign {
                message: message.into(),
            },
            identity,
            &ScriptedConfirmer(decision),
        )
    }

    #[test]
    fn list_reports_every_profile() {
        let identity = FakeIdentity {
            profiles: vec![one_active("alice")],
            ..Default::default()
        };
        let out = handle_local(
            &Command::Profiles(ProfilesAction::List),
            &identity,
            &approving(),
        )
        .unwrap();
        assert_eq!(out.result["profiles"].as_array().unwrap().len(), 1);
        assert_eq!(out.result["profiles"][0]["did"], json!("did:chia:alice"));
    }

    #[test]
    fn show_errors_not_found_when_no_active_profile() {
        let identity = FakeIdentity::default();
        let err = handle_local(
            &Command::Profiles(ProfilesAction::Show),
            &identity,
            &approving(),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[test]
    fn select_forwards_the_did_to_the_identity() {
        let identity = FakeIdentity::default();
        handle_local(
            &Command::Profiles(ProfilesAction::Select {
                did: "did:chia:bob".into(),
            }),
            &identity,
            &approving(),
        )
        .unwrap();
        assert_eq!(identity.selected.borrow().as_deref(), Some("did:chia:bob"));
    }

    #[test]
    fn sign_of_an_approved_message_is_domain_separated_not_the_raw_bytes() {
        let identity = FakeIdentity::default();
        let out = sign(&identity, "hi", ConfirmDecision::Approve).unwrap();
        // The fake echoes the bytes it was asked to sign, so the returned hex proves the key signed
        // the DOMAIN-SEPARATED `DIGNET-USER-SIGN-v1 ‖ "hi"` message — NEVER the raw "hi" (0x6869).
        let expected = hex::encode(user_sign_message(b"hi"));
        assert_eq!(out.result["signature"], json!(expected));
        assert_ne!(out.result["signature"], json!("6869"));
    }

    #[test]
    fn sign_is_refused_without_a_native_confirm_and_never_touches_the_key() {
        let identity = FakeIdentity::default();
        for declined in [
            ConfirmDecision::Deny,
            ConfirmDecision::Timeout,
            ConfirmDecision::Unavailable,
        ] {
            let err = sign(&identity, "hi", declined).unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::Denied,
                "a non-approved confirm ({declined:?}) must refuse signing"
            );
        }
    }

    #[test]
    fn sign_surfaces_a_locked_identity_as_locked_after_the_confirm() {
        let identity = FakeIdentity {
            locked: true,
            ..Default::default()
        };
        let err = sign(&identity, "hi", ConfirmDecision::Approve).unwrap_err();
        assert_eq!(err.code, ErrorCode::Locked);
    }

    #[test]
    fn wallet_address_and_balance_render_both_audiences() {
        let identity = FakeIdentity {
            profiles: vec![one_active("a")],
            ..Default::default()
        };
        let addr = handle_local(
            &Command::Wallet(WalletAction::Address),
            &identity,
            &approving(),
        )
        .unwrap();
        assert_eq!(addr.result["address"], json!("xch1testaddr"));
        let bal = handle_local(
            &Command::Wallet(WalletAction::Balance),
            &identity,
            &approving(),
        )
        .unwrap();
        assert_eq!(bal.result["balance_mojos"], json!(1_234));
    }

    #[test]
    fn create_mints_and_returns_the_new_profile() {
        let identity = FakeIdentity::default();
        let out = handle_local(
            &Command::Profiles(ProfilesAction::Create {
                name: "carol".into(),
            }),
            &identity,
            &approving(),
        )
        .unwrap();
        assert_eq!(out.result["profile"]["name"], json!("carol"));
    }

    #[test]
    fn an_engine_command_passed_locally_is_a_usage_bug_not_a_panic() {
        let identity = FakeIdentity::default();
        let err = handle_local(&Command::Info, &identity, &approving()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Usage);
    }
}
