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

/// An address that is NOT the fixture taker's, standing in for the profile's own hot wallet.
///
/// ENCODED rather than written as a literal, so it cannot rot into an undecodable string. It is
/// deliberately a stranger to the fixture's taker, so the vault rule below is exercised against a
/// spend that genuinely pays somewhere else — a hot wallet that happened to BE the taker would let a
/// vault spend pass the destination check for the wrong reason.
fn a_hot_wallet() -> String {
    chia_sdk_utils::Address::new(
        chia_protocol::Bytes32::new([0x11; 32]),
        dig_account::MAINNET_ADDRESS_PREFIX.to_string(),
    )
    .encode()
    .expect("a 32-byte puzzle hash always encodes")
}

/// Build the gate the way the running app does: one authorizer, fixed policy, real clock.
fn gate_on(custody: CustodyPolicy) -> PolicyAuthorizer {
    PolicyAuthorizer::new(
        ProfileIx::ROOT,
        custody,
        AutoSendPolicy::default(),
        &a_hot_wallet(),
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

/// **MEASURED, and it is a finding: the ceremony names only the side the taker PAYS.**
///
/// A swap has two sides, and the gate's summary carries one. The received leg — the maker's offered
/// coins, claimed to the taker's own change address — is dropped as change, and the settlement
/// commitment nets out because the same bundle creates and spends the settlement coin. So what a
/// person is asked to approve reads as an ordinary payment out, with nothing said about what arrives.
///
/// That is not dishonest (every figure it shows is true) but it is incomplete for an irreversible
/// swap, which is why NC-14 lands on the OFFER surface: `wallet::offer::OfferTerms` names both sides
/// from `summarize` BEFORE the ceremony is ever reached, so consent is given against the full trade.
///
/// The assertion pins the exact leg rather than merely counting lines: it must be the MAKER's payee
/// address for the requested amount. A summary that instead showed the taker's change would satisfy
/// "one recipient, 400 mojos" under a wrong implementation, and the two keys differ precisely so this
/// test can tell them apart.
#[test]
fn the_ceremony_names_the_paid_leg_of_the_swap_and_not_the_received_one() {
    let taker_change = chia_sdk_utils::Address::new(
        crate::wallet::offer_fixture::taker().puzzle_hash,
        dig_account::MAINNET_ADDRESS_PREFIX.to_string(),
    )
    .encode()
    .expect("a puzzle hash encodes");
    let payee = chia_sdk_utils::Address::new(
        crate::wallet::offer_fixture::maker().puzzle_hash,
        dig_account::MAINNET_ADDRESS_PREFIX.to_string(),
    )
    .encode()
    .expect("a puzzle hash encodes");

    let spends = taker_spends_for(&an_offer_of(XCH_FOR_XCH));
    let gate = gate_on(CustodyPolicy::Hot(HotWallet::default()));

    let SpendRuling::RequiresConfirmation(pending) = gate
        .authorize_op(&spends, SpendOpClass::Undeclared)
        .expect("the gate must account for a take-offer spend")
    else {
        panic!("a take must escalate, so there is a summary to inspect");
    };

    let paid: Vec<(&str, u64)> = pending
        .summary()
        .recipients
        .iter()
        .map(|line| (line.address.as_str(), line.amount_mojos))
        .collect();
    assert_eq!(
        paid,
        vec![(payee.as_str(), 400)],
        "the ceremony describes the requested payment to the maker, and nothing else"
    );
    assert!(
        !paid.iter().any(|(address, _)| *address == taker_change),
        "the received leg is invisible to the ceremony — that is the finding this test records"
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

    let Err(err) = gate.authorize_op(&spends, SpendOpClass::Undeclared) else {
        panic!("a vault spend may not commit value to the settlement puzzle");
    };

    let refusal = err.to_string();
    assert!(
        refusal.contains("hot wallet"),
        "the denial must be the hot-wallet-only outflow rule, not some other failure: {refusal}"
    );
}
