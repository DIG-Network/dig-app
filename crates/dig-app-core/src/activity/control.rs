//! The audit record over the loopback control plane — `control.spends.list`.
//!
//! [`super`] decides what an entry MEANS; this module is only how the question reaches dig-node and
//! how its answer comes back. The split matters because the two fail differently: a wrong model
//! renders a spend badly, while a wrong mapping here turns a node that could not be asked into one
//! that appears to have spent nothing.
//!
//! # The published contract IS the decoder
//!
//! There is no hand-written decoder here and there must never be one again. The response is
//! deserialised into [`SpendsListResult`] from `dig-node-control-interface`, and this module only
//! MAPS that typed value onto [`super`]'s model.
//!
//! That is not a tidiness preference. Until dig-app#289 this module carried a `wire` module of
//! field-name constants and three hand decoders, and they agreed with dig-node on almost nothing:
//! camelCase names against a snake_case node, an `intendedCoinId` key **the node has never sent**,
//! and an `asset` decoder written to the PARAMS encoding rather than the results one. Every one of
//! those was independently fatal, and the reason they went unnoticed for so long is that the tests
//! built their fixtures from the same constants — **the decoder was decoding its own tests.**
//!
//! Deserialising the contract type makes the COMPILER the check. A field dig-node renames is now a
//! build failure in this crate rather than an empty tab on somebody's machine, and that is the whole
//! of the fix: repairing the names one at a time would have rebuilt the same hand-written mechanism
//! that produced the drift.
//!
//! # What the node sends that this app does NOT re-derive
//!
//! * **`kind` is the producer's token** — `"mirror-coin"`, one word — and the collateralise/reclaim
//!   DIRECTION lives in `purpose`, which is contractually "one human sentence" (dig-node SPEC §23.1).
//!   So `purpose` is rendered verbatim and **never parsed**: keying a money direction off prose would
//!   be inventing a claim about which way the money went. A filterable direction would be a contract
//!   addition, not a suffix smuggled back into `kind`.
//! * **`chain_reference` carries its own observed/expected flag**, so this app never has to guess
//!   whether a coin id is evidence or an expectation. `confirmed: false` becomes
//!   [`AutomatedSpend::intended_coin_id`], which every renderer must label as expected.
//! * **Amounts are decimal STRINGS**, because a `u64` does not survive a JSON number through an f64
//!   parser. A string that is not a `u64` fails the whole read rather than being defaulted: a
//!   silently rounded or zeroed figure about somebody's money is the lie this record exists to
//!   prevent.
//!
//! # Two different incompletenesses, and the tab must not merge them
//!
//! [`SpendsListResult`] reports both `complete` (is this page the WHOLE matching set?) and
//! `unreadable_lines` (how many entries the node could not parse). They fail differently — a
//! truncated page is missing rows that exist and can be fetched, a corrupt trail is missing rows
//! nobody can recover — and both make the list shown less than the record. Both are carried across
//! and [`super::ActivityLedger::is_complete`] requires both to be clean.
//!
//! # The answer that must never collapse into an empty list
//!
//! | node says | becomes | the person is told |
//! |---|---|---|
//! | a ledger | [`Known`](super::ActivityReading::Known) | the spends, including the empty case |
//! | `METHOD_NOT_FOUND` / `NOT_SUPPORTED` | [`NotSupported`](super::ActivityUnknown::NotSupported) | this node is too old to keep the record |
//! | `UNAUTHORIZED` | [`Refused`](super::ActivityUnknown::Refused) | DIG could not authenticate locally |
//! | no node, or no answer | [`NoNode`](super::ActivityUnknown::NoNode) | start the node |
//! | an answer that will not parse | [`Unreadable`](super::ActivityUnknown::Unreadable) | the node said something DIG cannot read |
//!
//! **A node too old to keep the record and a node that has spent nothing print the same empty
//! list**, and only one of those means no money moved. That is why `METHOD_NOT_FOUND` maps to its
//! own reason rather than to an empty ledger: the second is a measurement and the first is the
//! absence of one.
//!
//! # An empty tab is the ordinary answer today, and it is not this module's bug
//!
//! Nothing in dig-node production writes the audit record yet ([`dig-node#411`]), so a correct node
//! answers `{"spends": [], "complete": true, "unreadable_lines": 0}` — which the contract defines as
//! *"this node has moved no money unattended"*. That is a measured zero and renders as one. It is
//! only honest because the four absences above are kept structurally apart from it.
//!
//! [`dig-node#411`]: https://github.com/DIG-Network/dig-node/issues/411
//!
//! # Branch on the SYMBOL, never on the numeric code
//!
//! The numbers are not stable across contract releases — `-32044` named `WALLET_COINS_RESERVED` in
//! the 0.20 contract and `WALLET_NODE_SPEND_DISABLED` in 0.21, which are opposite dispositions. Every
//! match here is on the stable UPPER_SNAKE symbol in `data.code`, the same discipline
//! [`crate::wallet::reservations_control`] documents.
//!
//! # Nothing privileged crosses here (§908)
//!
//! This is a READ of the node's own bookkeeping. A coin id and a height are public chain facts and a
//! store id is a public identifier; there is no key, seed, signature or bundle in the request or the
//! response, and there never may be — auditing a spend authorizes nothing.

use std::time::Duration;

use dig_node_control_interface::params::SpendsListParams;
use dig_node_control_interface::results::{
    AutomatedSpend as WireSpend, SpendAsset, SpendFailureStage, SpendOutcome as WireOutcome,
    SpendsListResult,
};
use dig_node_control_interface::traits::ControlCall;

use crate::control;

use super::absence::ControlAbsence;
use crate::wallet::state::{Asset, AssetId};

use super::{
    ActivityLedger, ActivityReading, ActivityUnknown, AutomatedSpend, FailureStage, SpendKind,
    SpendOutcome,
};

/// How long the audit read may take before it is abandoned.
///
/// The record is a node-local table, not a chain read, so this is nothing like the balance budget
/// that has to allow for a public HTTPS chain source. Five seconds is generous for a table read and
/// short enough that a wedged node costs a pending pane rather than a frozen window.
pub const ACTIVITY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The method that returns the audit record.
///
/// Taken from the contract's own `ControlCall` impl rather than spelled here, so the one remaining
/// string in this module is not one this app can get wrong either.
pub fn method() -> &'static str {
    <SpendsListParams as ControlCall>::METHOD.name()
}

/// Read the audit record from the node this machine is running.
///
/// Returns an [`ActivityReading`] rather than a `Result`, because every failure here is a state the
/// pane has to render honestly — and a `Result` at this seam invites a caller to
/// `unwrap_or_default()` an outage into an empty ledger, which is the one mapping this module
/// exists to prevent.
///
/// # Why the RAW call, when the contract type is right there
///
/// [`crate::control::call_control_result`] would decode the result for us, but it reports a decode
/// failure as a TRANSPORT error — which this module maps to [`ActivityUnknown::NoNode`], i.e. "start
/// your node", about a node that answered. Posting raw and deserialising here keeps "the node said
/// something DIG cannot read" distinguishable from "nobody answered", which is a difference the
/// person reading the pane has to act on differently.
pub fn read(endpoint: Option<&str>, token: Option<&str>, timeout: Duration) -> ActivityReading {
    let Some(endpoint) = endpoint else {
        return ActivityReading::Unknown(ActivityUnknown::NoNode);
    };
    // The whole page, unfiltered: this is an audit surface, and a filter applied here would decide
    // for the user which of their spends counts.
    let params = serde_json::to_value(SpendsListParams::default())
        .expect("the contract params type is plain data and always serializes");
    match control::call_control_raw(endpoint, method(), params, token, timeout) {
        Ok(value) => match serde_json::from_value::<SpendsListResult>(value) {
            Ok(result) => match ledger_from(result) {
                Some(ledger) => ActivityReading::Known(ledger),
                None => ActivityReading::Unknown(ActivityUnknown::Unreadable),
            },
            Err(_) => ActivityReading::Unknown(ActivityUnknown::Unreadable),
        },
        Err(failure) => ActivityReading::Unknown(ControlAbsence::of(&failure).into()),
    }
}

/// Map the contract's answer onto this app's model, or `None` when a value in it is unusable.
///
/// # Why an unusable ENTRY fails the whole read
///
/// The only thing that can be unusable after a typed decode is an amount string that is not a
/// `u64`. Dropping such an entry would turn it into a **silently shorter audit record** — the exact
/// failure mode an audit surface cannot have — and defaulting it to zero would put a false figure
/// against somebody's money. So it makes the whole answer
/// [`Unreadable`](ActivityUnknown::Unreadable): a pane saying "DIG could not read this" is
/// recoverable, and a pane quietly missing or mis-stating a spend is not.
fn ledger_from(result: SpendsListResult) -> Option<ActivityLedger> {
    Some(ActivityLedger {
        spends: result
            .spends
            .into_iter()
            .map(spend_from)
            .collect::<Option<Vec<_>>>()?,
        complete: result.complete,
        unreadable_lines: result.unreadable_lines,
    })
}

/// Map one contract row.
fn spend_from(spend: WireSpend) -> Option<AutomatedSpend> {
    Some(AutomatedSpend {
        // The node records milliseconds; this surface renders seconds. Converted at the boundary, in
        // one place, so no renderer has to know which unit it was handed — mixing the two is how a
        // timestamp lands in 1970 or fifty thousand years hence.
        at_unix: spend.initiated_ms / 1_000,
        kind: SpendKind::from_wire(&spend.kind),
        purpose: spend.purpose,
        asset: asset_from(spend.asset)?,
        base_units: spend.amount_mojos.parse().ok()?,
        store: spend.store_id,
        fee_mojos: spend.fee_mojos.parse().ok()?,
        // A reference the node has NOT seen on chain is an expectation, and only an expectation may
        // reach this field. The contract's own `confirmed` flag decides that, so this app never
        // re-derives the distinction the node already made — an observed coin id belongs to the
        // `Confirmed` outcome and is read from there.
        intended_coin_id: spend
            .chain_reference
            .filter(|reference| !reference.confirmed)
            .map(|reference| reference.coin_id),
        outcome: outcome_from(spend.status),
    })
}

/// Map a contract outcome.
///
/// Exhaustive on both enums, so a variant added on either side is a compile error here rather than a
/// silent default — and there is no honest default to pick, because every arm is a statement about
/// whether somebody's money moved.
fn outcome_from(status: WireOutcome) -> SpendOutcome {
    match status {
        WireOutcome::Pending => SpendOutcome::Pending,
        WireOutcome::Submitted => SpendOutcome::Submitted,
        WireOutcome::Confirmed { height, coin_id } => SpendOutcome::Confirmed { height, coin_id },
        WireOutcome::Failed { stage, reason } => SpendOutcome::Failed {
            stage: stage_from(stage),
            reason,
        },
        WireOutcome::Unresolved { reason } => SpendOutcome::Unresolved { reason },
    }
}

/// Map a failure stage.
///
/// The one mapping in this module worth reading twice: only [`FailureStage::BeforeSigning`] permits
/// a surface to say the money stayed put, and the contract's name for it is `Signing` — "it failed
/// AT the signing stage", i.e. before a bundle existed. The two spellings describe the same instant
/// from opposite sides, and this `match` is where that is stated once. The hand decoder this
/// replaced looked for the string `"before-signing"`, which the node has never sent, so every
/// signing-stage failure fell through to `Confirmation` and over-reported "may have moved money".
const fn stage_from(stage: SpendFailureStage) -> FailureStage {
    match stage {
        SpendFailureStage::Signing => FailureStage::BeforeSigning,
        SpendFailureStage::Broadcast => FailureStage::Broadcast,
        SpendFailureStage::Confirmation => FailureStage::Confirmation,
    }
}

/// Map a contract asset onto the wallet's own.
///
/// `None` only for a CAT whose asset id is not hex, which is a value no correct node produces and
/// which this app cannot render as an amount.
fn asset_from(asset: SpendAsset) -> Option<Asset> {
    match asset {
        SpendAsset::Xch => Some(Asset::Xch),
        SpendAsset::Dig => Some(Asset::DIG),
        SpendAsset::Cat { asset_id } => Some(Asset::Cat(AssetId::from_hex(&asset_id).ok()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlFailure;
    use dig_node_control_interface::error::ControlErrorCode;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};
    use serde_json::{json, Value};

    fn rejected(code: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32601,
            message: "no".to_string(),
            data: ControlErrorData {
                code: code.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    /// Decode a raw payload exactly as [`read`] does, so a test exercises the real path.
    fn decode(page: Value) -> Option<ActivityLedger> {
        ledger_from(serde_json::from_value::<SpendsListResult>(page).ok()?)
    }

    /// A page **in dig-node's own wire spelling**, transcribed from what `spends_list_wire`
    /// serialises (`dig-node-service/src/control.rs`, v0.168.0+).
    ///
    /// Written as raw JSON rather than built from the contract's Rust types on purpose: constructing
    /// `SpendsListResult` and serialising it would assert that the contract agrees with itself,
    /// which is true however far dig-app has drifted from the node. The bytes are the contract.
    fn node_page() -> Value {
        json!({
            "spends": [
                {
                    "id": "s1",
                    "revision": 1,
                    "kind": "mirror-coin",
                    "purpose": "Collateralise store-a for epoch 41",
                    "authority": { "principal": "node", "grant": "standing" },
                    "asset": { "asset": "dig" },
                    "amount_mojos": "20000",
                    "fee_mojos": "1000000",
                    "store_id": "store-a",
                    "initiated_ms": 1_787_500_000_000u64,
                    "updated_ms": 1_787_500_001_000u64,
                    "status": { "state": "confirmed", "height": 9_211_798, "coin_id": "abc" },
                    "funding_coin_ids": ["def"],
                    "chain_reference": { "coin_id": "abc", "confirmed": true }
                },
                {
                    "id": "s2",
                    "revision": 1,
                    "kind": "mirror-coin",
                    "purpose": "Reclaim collateral from store-b",
                    "authority": { "principal": "node", "grant": "standing" },
                    "asset": { "asset": "xch" },
                    "amount_mojos": "18446744073709551615",
                    "fee_mojos": "0",
                    "store_id": Value::Null,
                    "initiated_ms": 1_787_400_000_000u64,
                    "updated_ms": 1_787_400_000_000u64,
                    "status": { "state": "failed", "stage": "signing", "reason": "insufficient funds" },
                    "funding_coin_ids": [],
                    "chain_reference": { "coin_id": "expected99", "confirmed": false }
                }
            ],
            "complete": true,
            "cursor": "s2",
            "unreadable_lines": 0
        })
    }

    /// **Proves:** the page dig-node actually sends decodes through the PUBLISHED contract type with
    /// no hand-written decoder, and every field survives the crossing with its meaning intact.
    ///
    /// **Catches** the dig-app#289 drift in one shot. Under the deleted `wire` decoder this page was
    /// undecodable — snake_case names, `asset` as an object, stringified amounts, and a
    /// `chain_reference` where an `intendedCoinId` was expected — so the tab showed "the node said
    /// something DIG cannot read" against a perfectly correct node.
    ///
    /// The assertions are on CONTENT, not merely on a successful decode: a decode proves the shape,
    /// and a shape can be right while a value lands in the wrong field. Each one below is a claim
    /// about somebody's money.
    #[test]
    fn the_page_dig_node_sends_decodes_through_the_published_contract() {
        let ledger = decode(node_page()).expect("dig-node's own wire shape must decode");
        assert_eq!(ledger.spends.len(), 2);

        let confirmed = &ledger.spends[0];
        assert_eq!(confirmed.kind, SpendKind::MirrorCoin);
        assert_eq!(confirmed.purpose, "Collateralise store-a for epoch 41");
        assert_eq!(confirmed.asset, Asset::DIG);
        assert_eq!(confirmed.base_units, 20_000);
        assert_eq!(confirmed.fee_mojos, 1_000_000);
        assert_eq!(confirmed.store.as_deref(), Some("store-a"));
        // Milliseconds in, seconds out.
        assert_eq!(confirmed.at_unix, 1_787_500_000);
        assert_eq!(confirmed.chain_reference(), Some("abc"));
        assert_eq!(
            confirmed.intended_coin_id, None,
            "a reference the node marked CONFIRMED is evidence and must not become an expectation"
        );

        let failed = &ledger.spends[1];
        assert_eq!(
            failed.base_units,
            u64::MAX,
            "the full u64 range must survive the decimal string; an f64 parse would round it"
        );
        assert_eq!(failed.store, None);
        assert_eq!(
            failed.intended_coin_id.as_deref(),
            Some("expected99"),
            "a reference the node marked UNCONFIRMED is the coin to look for, never evidence"
        );
        assert_eq!(failed.chain_reference(), None);
        match &failed.outcome {
            SpendOutcome::Failed { stage, reason } => {
                assert_eq!(
                    *stage,
                    FailureStage::BeforeSigning,
                    "the node's `signing` stage is the one that means the money stayed put; \
                     reading it as anything else over-reports that money may have moved"
                );
                assert!(!stage.may_have_moved_money());
                assert_eq!(reason, "insufficient funds");
            }
            other => panic!("expected a failed row, got {other:?}"),
        }

        assert!(ledger.is_complete());
    }

    /// **Proves:** `kind` is the producer token and the direction lives in `purpose`, which is
    /// carried as prose and never parsed.
    ///
    /// The two rows differ ONLY in their purpose sentence — same kind, same asset, same amount — so
    /// an implementation that classified direction from the kind token, or that dropped `purpose`,
    /// makes the two rows indistinguishable and fails here. The nearest wrong implementation is the
    /// deleted one, which expected `"mirror-coin.collateral"` and rendered both as `Other`.
    #[test]
    fn direction_lives_in_the_purpose_sentence_and_is_carried_verbatim() {
        let mut page = node_page();
        let rows = page["spends"].as_array_mut().expect("rows");
        rows[1]["status"] = json!({ "state": "confirmed", "height": 1, "coin_id": "z" });

        let ledger = decode(page).expect("must decode");
        assert_eq!(ledger.spends[0].kind, ledger.spends[1].kind);
        assert_eq!(ledger.spends[0].kind, SpendKind::MirrorCoin);
        assert_eq!(
            ledger.spends[0].purpose,
            "Collateralise store-a for epoch 41"
        );
        assert_eq!(ledger.spends[1].purpose, "Reclaim collateral from store-b");
    }

    /// **Proves:** a TRUNCATED page is not the whole record, and says so separately from a corrupt
    /// trail.
    ///
    /// The two fixtures vary one field each against a clean control, because the nearest wrong
    /// implementation reads only `unreadable_lines` — which was the whole of the previous
    /// completeness test — and would call a truncated page complete.
    #[test]
    fn a_truncated_page_and_a_corrupt_trail_are_both_incomplete() {
        let clean = decode(node_page()).expect("must decode");
        assert!(clean.is_complete(), "the control must be complete");

        let mut truncated = node_page();
        truncated["complete"] = json!(false);
        assert!(
            !decode(truncated).expect("must decode").is_complete(),
            "a page the node said was truncated is not the whole record"
        );

        let mut corrupt = node_page();
        corrupt["unreadable_lines"] = json!(3);
        let corrupt = decode(corrupt).expect("must decode");
        assert!(!corrupt.is_complete());
        assert_eq!(corrupt.unreadable_lines, 3);
    }

    /// **Proves:** an amount that is not a `u64` fails the WHOLE read.
    ///
    /// A dropped row would shorten an audit record silently and a defaulted zero would state a false
    /// figure about money; both are worse than a pane saying it could not read the answer. The
    /// control is the same page with the amount restored, which is what makes this about the AMOUNT
    /// rather than about the fixture being malformed generally.
    #[test]
    fn an_unreadable_amount_fails_the_whole_read_rather_than_dropping_a_row() {
        let mut page = node_page();
        page["spends"][0]["amount_mojos"] = json!("not-a-number");
        assert!(
            decode(page).is_none(),
            "a row with an unusable amount must not be dropped or zeroed"
        );
        assert_eq!(
            decode(node_page())
                .expect("control must decode")
                .spends
                .len(),
            2
        );
    }

    /// **Proves:** a genuinely empty page is a MEASURED zero, and none of the four absences is.
    ///
    /// A node that does not serve the method and a node that has spent nothing produce identical
    /// panes under the obvious implementation. The empty-but-known ledger in the same test is the
    /// control that makes the distinction meaningful rather than incidental.
    #[test]
    fn an_old_node_is_unsupported_and_not_an_empty_record() {
        assert_eq!(
            ActivityUnknown::from(ControlAbsence::of(&rejected(
                ControlErrorCode::MethodNotFound.name()
            ))),
            ActivityUnknown::NotSupported
        );
        assert_eq!(
            ActivityUnknown::from(ControlAbsence::of(&rejected("NOT_SUPPORTED"))),
            ActivityUnknown::NotSupported
        );

        let genuinely_empty = decode(json!({
            "spends": [],
            "complete": true,
            "cursor": Value::Null,
            "unreadable_lines": 0
        }))
        .expect("an empty spend list is a valid answer");
        assert!(genuinely_empty.spends.is_empty());
        assert!(
            genuinely_empty.is_complete(),
            "a node that says its record is whole and empty has MEASURED that it spent nothing"
        );
        assert!(
            ActivityReading::Known(genuinely_empty).is_known_empty(),
            "a measured zero reads as a measured zero"
        );
        assert!(
            !ActivityReading::Unknown(ActivityUnknown::NotSupported).is_known_empty(),
            "an unsupported node must never read as a measured zero"
        );
    }

    /// **Proves:** a required key the node omits makes the answer UNREADABLE, never an empty ledger.
    ///
    /// `unreadable_lines` is required by the contract with no serde default, and that is what lets
    /// the model carry a plain count instead of an "it did not say" case: silence is not a number
    /// here, it is a failed decode. The control is the same page WITH the key.
    #[test]
    fn a_missing_required_key_is_unreadable_and_not_an_empty_record() {
        assert!(
            decode(json!({ "spends": [], "complete": true, "cursor": Value::Null })).is_none(),
            "a node that did not say whether its trail was whole has not reported an empty record"
        );
        assert!(decode(json!({
            "spends": [],
            "complete": true,
            "cursor": Value::Null,
            "unreadable_lines": 0
        }))
        .is_some());
    }
}
