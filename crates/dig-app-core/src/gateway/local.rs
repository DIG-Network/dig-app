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
) -> Result<Outcome, GatewayError> {
    match command {
        Command::Profiles(action) => handle_profiles(action, identity),
        Command::Wallet(action) => handle_wallet(action, identity),
        Command::Sign { message } => handle_sign(message, identity),
        other => Err(GatewayError::new(
            ErrorCode::Usage,
            format!("{} is not a local command", other.action()),
        )),
    }
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

/// Serve `sign`: sign the message bytes with the active identity key, returning a hex signature.
fn handle_sign(message: &str, identity: &dyn LocalIdentity) -> Result<Outcome, GatewayError> {
    let signature = identity.sign(message.as_bytes())?;
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

    #[test]
    fn list_reports_every_profile() {
        let identity = FakeIdentity {
            profiles: vec![one_active("alice")],
            ..Default::default()
        };
        let out = handle_local(&Command::Profiles(ProfilesAction::List), &identity).unwrap();
        assert_eq!(out.result["profiles"].as_array().unwrap().len(), 1);
        assert_eq!(out.result["profiles"][0]["did"], json!("did:chia:alice"));
    }

    #[test]
    fn show_errors_not_found_when_no_active_profile() {
        let identity = FakeIdentity::default();
        let err = handle_local(&Command::Profiles(ProfilesAction::Show), &identity).unwrap_err();
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
        )
        .unwrap();
        assert_eq!(identity.selected.borrow().as_deref(), Some("did:chia:bob"));
    }

    #[test]
    fn sign_returns_a_hex_signature() {
        let identity = FakeIdentity::default();
        let out = handle_local(
            &Command::Sign {
                message: "hi".into(),
            },
            &identity,
        )
        .unwrap();
        // The fake echoes the message bytes; "hi" == 0x6869.
        assert_eq!(out.result["signature"], json!("6869"));
    }

    #[test]
    fn sign_surfaces_a_locked_identity_as_locked() {
        let identity = FakeIdentity {
            locked: true,
            ..Default::default()
        };
        let err = handle_local(
            &Command::Sign {
                message: "hi".into(),
            },
            &identity,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Locked);
    }

    #[test]
    fn wallet_address_and_balance_render_both_audiences() {
        let identity = FakeIdentity {
            profiles: vec![one_active("a")],
            ..Default::default()
        };
        let addr = handle_local(&Command::Wallet(WalletAction::Address), &identity).unwrap();
        assert_eq!(addr.result["address"], json!("xch1testaddr"));
        let bal = handle_local(&Command::Wallet(WalletAction::Balance), &identity).unwrap();
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
        )
        .unwrap();
        assert_eq!(out.result["profile"]["name"], json!("carol"));
    }

    #[test]
    fn an_engine_command_passed_locally_is_a_usage_bug_not_a_panic() {
        let identity = FakeIdentity::default();
        let err = handle_local(&Command::Info, &identity).unwrap_err();
        assert_eq!(err.code, ErrorCode::Usage);
    }
}
