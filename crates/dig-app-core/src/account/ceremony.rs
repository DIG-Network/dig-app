//! The **spend-confirmation** half of the auth ceremony — the OS biometric gate every spend passes
//! through, shared by every [`AuthCeremony`](crate::account::auth::AuthCeremony) implementation.
//!
//! # Why this is a free function and not a ceremony of its own
//!
//! [`AuthCeremony`](crate::account::auth::AuthCeremony) has two halves that answer to different
//! authorities: *who are you* (a password — [`PasswordCeremony`](crate::account::passphrase::PasswordCeremony))
//! and *do you authorize this spend* (the per-OS biometric confirm). The second half is identical for
//! every implementation of the first, so it lives here once and is called, rather than copied into each.
//!
//! # What was here before (dig_ecosystem#1817)
//!
//! This module used to hold `CredentialCeremony`: an [`AuthCeremony`](crate::account::auth::AuthCeremony)
//! that GENERATED the account's seal password from the OS CSPRNG on first run, filed it in the OS
//! credential store, and handed it back on every later boot so the account unlocked with no prompt at
//! all. The sealing crypto was sound and the password was 256 bits — but it was held by the MACHINE, so
//! there was no user-known secret protecting custody anywhere, and any code running in the user's OS
//! session could read it and reach the master seed.
//!
//! **It is deleted, and there is deliberately no zero-prompt fallback of any kind** — see
//! [`passphrase`](crate::account::passphrase) for what replaced it and `SPEC.md` §3.1e for the normative
//! statement, so that re-introducing a machine-held unlock password is a visible regression rather than a
//! quiet convenience. The one place the old machine password is still read is
//! [`migrate`](crate::account::migrate), which uses it exactly once to re-seal the seed under a password
//! the user chooses, and then deletes it.
//!
//! Spend confirmation is unchanged by all of that: the money path calls
//! [`confirm_spend_natively`], which renders the independently re-derived [`SpendSummary`]
//! (recipients / fee / tier — never raw bytes) and requires the user to authorize it at the OS
//! biometric/passphrase prompt (Windows Hello / macOS Touch ID / Linux polkit). A headless host has no
//! confirmer, so a spend confirmation fails closed there (`Unavailable`).

use dig_account::{SpendDecision, SpendSummary};

use crate::account::auth::CeremonyError;
use crate::confirm::{ConfirmDecision, NativeConfirmer, SignPrompt};

/// Put `summary` to the user at the host's native biometric/passphrase gate and return their ruling.
///
/// The prompt body is the summary's OWN rendering — dig-account's independently re-derived recipients,
/// amounts and fee — so what the user reads cannot disagree with what the signature will authorize, and
/// no raw transaction bytes are ever shown.
///
/// # Errors
///
/// [`CeremonyError::Unavailable`] when the host has no confirmer (a headless host), so the spend aborts
/// with no key touched rather than silently declining as if the user had chosen to.
pub fn confirm_spend_natively(
    confirmer: &dyn NativeConfirmer,
    summary: &SpendSummary,
) -> Result<SpendDecision, CeremonyError> {
    let body = render_spend(summary);
    let prompt = SignPrompt {
        origin: SPEND_CONFIRM_ORIGIN,
        payload_type: SPEND_PAYLOAD_TYPE,
        decoded_tx: Some(&body),
    };
    Ok(match confirmer.confirm_sign(&prompt) {
        ConfirmDecision::Approve => SpendDecision::Approve,
        ConfirmDecision::Deny => {
            SpendDecision::Decline(Some("declined at the confirm prompt".to_string()))
        }
        ConfirmDecision::Timeout => {
            SpendDecision::Decline(Some("the confirm prompt timed out".to_string()))
        }
        ConfirmDecision::Unavailable => {
            return Err(CeremonyError::Unavailable(
                "no native confirmer for the spend prompt".to_string(),
            ))
        }
    })
}

/// The origin label shown on a local wallet spend confirmation — a fixed, non-dapp source (the spend
/// originates in the user's own app, not a vouched web origin).
const SPEND_CONFIRM_ORIGIN: &str = "dig-app (local wallet)";

/// The payload tag naming what the confirm prompt is authorizing (parallels the §5.6.5 dapp sign tags).
const SPEND_PAYLOAD_TYPE: &str = "wallet.spend";

/// Render a [`SpendSummary`] as the plain-text confirm body: the custody tier, each recipient +
/// amount, and the fee. Uses the summary's own [`Display`](std::fmt::Display) — the recipients + fee
/// are dig-account's independently re-derived figures, so the body cannot disagree with what is signed.
/// Plain text only (the per-OS confirmers neutralize markup), never key material.
fn render_spend(summary: &SpendSummary) -> String {
    format!("Approve this {:?}-tier spend?\n\n{}", summary.tier, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConnectPrompt, PairPrompt};
    use std::sync::Mutex;

    /// A [`NativeConfirmer`] double returning a fixed decision + recording the confirm body it was
    /// shown, so a test can assert the spend was routed through the native gate with the re-derived
    /// summary (never raw bytes).
    struct ScriptedConfirmer {
        decision: ConfirmDecision,
        last_body: Mutex<Option<String>>,
    }

    impl ScriptedConfirmer {
        fn new(decision: ConfirmDecision) -> Self {
            Self {
                decision,
                last_body: Mutex::new(None),
            }
        }
    }

    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _prompt: &PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("the spend confirm never pairs")
        }
        fn confirm_connect(&self, _prompt: &ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("the spend confirm never connects")
        }
        fn confirm_sign(&self, prompt: &SignPrompt<'_>) -> ConfirmDecision {
            *self.last_body.lock().unwrap() = prompt.decoded_tx.map(str::to_string);
            self.decision
        }
    }

    fn sample_summary() -> SpendSummary {
        use dig_account::{SpendRecipient, SpendTier};
        SpendSummary::new(
            SpendTier::Vault,
            vec![SpendRecipient {
                address: "xch1recipient".into(),
                amount_mojos: 5_000_000,
                asset_id: None,
            }],
            10,
        )
    }

    #[test]
    fn an_approved_native_confirm_approves_the_spend_and_shows_the_summary() {
        let confirmer = ScriptedConfirmer::new(ConfirmDecision::Approve);
        let decision = confirm_spend_natively(&confirmer, &sample_summary()).unwrap();
        assert_eq!(decision, SpendDecision::Approve);
        let body = confirmer.last_body.lock().unwrap().clone().unwrap();
        assert!(
            body.contains("xch1recipient") && body.contains("Vault"),
            "the native prompt shows the re-derived summary: {body}"
        );
    }

    #[test]
    fn a_denied_native_confirm_declines_the_spend() {
        let confirmer = ScriptedConfirmer::new(ConfirmDecision::Deny);
        let decision = confirm_spend_natively(&confirmer, &sample_summary()).unwrap();
        assert!(matches!(decision, SpendDecision::Decline(_)));
    }

    #[test]
    fn a_timed_out_native_confirm_declines_the_spend() {
        let confirmer = ScriptedConfirmer::new(ConfirmDecision::Timeout);
        let decision = confirm_spend_natively(&confirmer, &sample_summary()).unwrap();
        assert!(matches!(decision, SpendDecision::Decline(_)));
    }

    #[test]
    fn a_headless_host_fails_the_spend_confirm_closed() {
        // No native confirmer (Unavailable) -> a ceremony ERROR (not a silent decline), so the money
        // path aborts fail-closed with no key touched.
        let confirmer = ScriptedConfirmer::new(ConfirmDecision::Unavailable);
        let result = confirm_spend_natively(&confirmer, &sample_summary());
        assert!(matches!(result, Err(CeremonyError::Unavailable(_))));
    }
}
