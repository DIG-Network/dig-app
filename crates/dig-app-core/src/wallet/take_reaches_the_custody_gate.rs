//! **The measurement**: does dig-account's custody gate admit a take-offer spend at all?
//!
//! # Why this file exists before any offer UI does
//!
//! `PolicyAuthorizer::authorize_op` is the ONLY route from unsigned coin spends to a signature, and
//! until now it had never seen a settlement-layer spend arrive through `dig-account`. The settlement
//! arm is unit-proven one layer down in `dig-wallet-backend`, and `dig-account` mentions the
//! settlement puzzle only to NAME it in a summary and, in the vault tier, to DENY it. Neither of
//! those is evidence that a real take-offer spend survives the gate, and building a take UI on the
//! assumption that it does would put the discovery at the end of the work instead of the start.
//!
//! So these tests hand the gate the exact bytes [`dig_offers::take_build`] produces — no hand-built
//! spend, no description of a spend — and record what it rules. What they assert is the RULING, not
//! a signature: obtaining one needs an unlocked account, and the question here is whether the policy
//! layer admits the shape at all.
//!
//! # What a green here does and does not prove
//!
//! It proves the gate parses a settlement-layer spend, tiers it, and reaches a decision rather than
//! erroring out on a shape it cannot account for. It does NOT prove a take settles on a live chain —
//! nothing here touches a network, and nothing here signs.

use std::sync::Arc;

use dig_account::{
    AutoSendPolicy, CustodyPolicy, HotWallet, PolicyAuthorizer, ProfileIx, SpendOpClass,
    SpendRuling, SystemClock, Vault,
};

use crate::wallet::offer_fixture::{an_offer_of, taker_spends_for, XCH_FOR_XCH};

/// A mainnet address that is NOT the taker's, standing in for the profile's hot wallet.
///
/// The gate needs a decodable hot-wallet address to construct at all. It is deliberately a stranger
/// to the fixture's taker, so the vault rule below is exercised against a spend that genuinely pays
/// somewhere else — a hot wallet that happened to BE the taker would let a vault spend pass the
/// destination check for the wrong reason.
const A_HOT_WALLET: &str = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs0mnzk0";

/// Build the gate the way the running app does: one authorizer, fixed policy, real clock.
fn gate_on(custody: CustodyPolicy) -> PolicyAuthorizer {
    PolicyAuthorizer::new(
        ProfileIx::new(0),
        custody,
        AutoSendPolicy::default(),
        A_HOT_WALLET,
        Arc::new(SystemClock),
    )
    .expect("the fixture hot-wallet address must decode")
}

/// **A hot-wallet profile's take-offer spend REACHES a decision at the custody gate.**
///
/// This is the measurement the whole offer feature was gated on. The failure it is built to catch is
/// not a denial — a denial would be a policy answer — but an ERROR: the gate re-derives the spend
/// from its bytes, and a settlement-layer spend it could not account for would come back
/// `PolicyIndeterminate` or `Spend`, which has no route onward and would make offers structurally
/// untakeable no matter what the UI did.
///
/// The expected ruling is `RequiresConfirmation`: a take commits value to the settlement puzzle, and
/// the default hot-wallet allowance is zero, so it tiers `Confirm` and escalates to the human
/// ceremony. That is the correct answer for an irreversible swap, and it is asserted rather than
/// merely "not an error" so that a future change silently auto-approving a take fails here.
#[test]
fn a_hot_wallet_take_is_admitted_by_the_custody_gate_and_escalated_to_the_human() {
    let spends = taker_spends_for(&an_offer_of(XCH_FOR_XCH));
    let gate = gate_on(CustodyPolicy::Hot(HotWallet::default()));

    let ruling = gate
        .authorize_op(&spends, SpendOpClass::Undeclared)
        .expect("the gate must be able to account for a take-offer spend");

    assert!(
        matches!(ruling, SpendRuling::RequiresConfirmation(_)),
        "an irreversible swap must reach the confirm ceremony, never auto-approve"
    );
}

/// **The gate NAMES the settlement puzzle in what the human is shown.**
///
/// The ceremony renders the gate's own summary, so if the settlement commitment were missing from it
/// a person would be asked to approve a spend whose largest effect was invisible. Asserting the
/// ruling alone cannot see that: a summary with the settlement line dropped escalates identically.
///
/// A second, ordinary recipient is not needed here — the take's own change line supplies the control,
/// so a summary that named everything "the offer settlement puzzle" would fail too.
#[test]
fn the_summary_the_human_sees_names_the_settlement_puzzle() {
    let spends = taker_spends_for(&an_offer_of(XCH_FOR_XCH));
    let gate = gate_on(CustodyPolicy::Hot(HotWallet::default()));

    let SpendRuling::RequiresConfirmation(pending) = gate
        .authorize_op(&spends, SpendOpClass::Undeclared)
        .expect("the gate must account for a take-offer spend")
    else {
        panic!("a take must escalate, so there is a summary to inspect");
    };

    let named: Vec<&str> = pending
        .summary()
        .recipients
        .iter()
        .map(|line| line.address.as_str())
        .collect();
    assert!(
        named.iter().any(|line| line.contains("settlement")),
        "the value committed to settlement must appear in what the human approves: {named:?}"
    );
}

/// **A vault-tier profile's take is DENIED, by the rule that exists to deny it.**
///
/// This is the refusal `crate::wallet::offer::take_permitted_by` surfaces up front. It is measured
/// here against the real gate rather than assumed, because the disabled control's whole justification
/// is that the spend would be refused anyway — and a control disabled for a reason that turned out to
/// be false would be withholding a capability the user actually has.
#[test]
fn a_vault_profile_is_denied_by_the_gate_for_the_reason_the_ui_states() {
    let spends = taker_spends_for(&an_offer_of(XCH_FOR_XCH));
    let gate = gate_on(CustodyPolicy::Vault(Vault::default()));

    let err = gate
        .authorize_op(&spends, SpendOpClass::Undeclared)
        .expect_err("a vault spend may not commit value to the settlement puzzle");

    let refusal = err.to_string();
    assert!(
        refusal.contains("hot wallet"),
        "the denial must be the hot-wallet-only outflow rule, not some other failure: {refusal}"
    );
}
