//! The audit record over the loopback control plane — `control.spends.list`.
//!
//! [`super`] decides what an entry MEANS; this module is only how the question reaches dig-node and
//! how its answer comes back. The split matters because the two fail differently: a wrong model
//! renders a spend badly, while a wrong mapping here turns a node that could not be asked into one
//! that appears to have spent nothing.
//!
//! # THE METHOD NOW EXISTS, AND THIS DECODER DOES NOT MATCH IT
//!
//! The record itself shipped in [`dig-node#378`], along with the `dign spends` verbs that read it.
//! The **control method was deliberately left out at first**, and correctly so:
//! `dig-node-control-interface` is a published crate, so release-first (§4.1) means
//! `control.spends.list` must exist in a published version before dig-app may adopt it.
//!
//! **That release has happened.** `dig-node-control-interface` **0.24.0** declares
//! `ControlMethod::SpendsList` and a typed `SpendsListResult`, this crate already depends on
//! `0.24`, and dig-node serves the method from **v0.165.0**. The older wording here — that this
//! call returns `METHOD_NOT_FOUND` "against every node in the world" — is therefore no longer
//! true, and planning work against it would be planning against a fact that has expired.
//!
//! ## The drift this exposed, which is why [`wire`] below is now WRONG
//!
//! [`wire`]'s field names were written to a proposed shape and dig-node emits a different one.
//! Measured against the live handler (`dig-node-service/src/control.rs`, `spend_row`):
//!
//! | this module expects | dig-node actually emits |
//! |---|---|
//! | `initiatedMs` | `initiated_ms` |
//! | `amountMojos` (number) | `amount_mojos` (**decimal STRING**) |
//! | `feeMojos` | `fee_mojos` (**decimal STRING**) |
//! | `storeId` | `store_id` |
//! | `coinId` | `coin_id` |
//! | `unreadableLines` | `unreadable_lines` |
//! | `intendedCoinId` | `chain_reference: { coin_id, confirmed }` |
//!
//! So the casing is not the whole of it: two amounts changed TYPE and the chain reference changed
//! SHAPE. Fixing the spelling alone would still be wrong.
//!
//! **A page carrying spends fails CLOSED, and that part is fine**: the first missing field makes
//! [`parse_spend`] return `None`, which makes the whole answer
//! [`Unreadable`](super::ActivityUnknown::Unreadable) rather than a shorter, tidy list.
//!
//! **An EMPTY page does not, and that part is a live defect.** `spends: []` decodes cleanly, and
//! `unreadable_lines` is then missed by name and read as the absent-means-zero case — so a node
//! reporting a CORRUPTED audit trail is rendered as one with nothing to report. That is precisely
//! the claim the field exists to prevent, and it is reachable today on any node at v0.165.0 or
//! later. `a_node_shaped_page_is_decoded_or_refused_but_never_quietly_zeroed` pins it.
//!
//! # Why the method is still named at runtime rather than typed
//!
//! Every other control caller in this crate goes through [`crate::control::call_control`] and gets a
//! typed result from the published contract crate. This one does not yet: it is issued through the
//! untyped twin, [`crate::control::call_control_raw`], and decoded by [`parse_ledger`].
//!
//! **Taking the typed `SpendsListResult` is the fix, and it is now unblocked** — it deletes
//! [`parse_ledger`] and [`wire`] together, which is the only change that resolves the type and shape
//! rows above rather than just the spelling ones. It is deliberately NOT done in this diff, which
//! corrects claims that had become false and pins the drift with a test; the adoption is tracked on
//! [`dig-app#289`].
//!
//! [`dig-node#378`]: https://github.com/DIG-Network/dig-node/pull/378
//! [`dig-app#289`]: https://github.com/DIG-Network/dig-app/issues/289
//!
//! # Three shapes from the node's record that MUST survive the crossing
//!
//! Each one is a guarantee the record makes structurally, and each is lost by the obvious flattening:
//!
//! 1. **`Confirmed { height, coin_id }` keeps its evidence INSIDE the variant.** Flattening it into a
//!    nullable height beside a status word lets a confirmation height exist without a confirmation.
//! 2. **`Unresolved` is not `Failed`.** "The node signed and does not know" is not "it did not
//!    happen"; money may well have moved, and a view that shows them alike is lying about money.
//! 3. **A failure carries its STAGE.** A broadcast- or confirmation-stage failure put a signed bundle
//!    on the wire, so it must never render as money that did not move. See
//!    [`FailureStage`].
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

use dig_node_control_interface::error::ControlErrorCode;
use serde_json::Value;

use crate::control::{self, ControlFailure};
use crate::wallet::state::{Asset, AssetId};

use super::{
    ActivityLedger, ActivityReading, ActivityUnknown, AutomatedSpend, FailureStage, LockedTotal,
    SpendFailure, SpendKind, SpendOutcome,
};

/// How long the audit read may take before it is abandoned.
///
/// The record is a node-local table, not a chain read, so this is nothing like the balance budget
/// that has to allow for a public HTTPS chain source. Five seconds is generous for a table read and
/// short enough that a wedged node costs a pending pane rather than a frozen window.
pub const ACTIVITY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The wire vocabulary, in ONE place.
///
/// Listed as constants rather than spelled inline at each `get` so that the swap to the published
/// contract crate (see the module docs) is a single mechanical edit, and so a typo in a field name
/// is visible beside the others rather than buried in a decoder.
pub mod wire {
    /// The method that returns the audit record.
    ///
    /// Named to match dig-node's own `dign spends list` verb and the method declared in
    /// `dig-node-control-interface` 0.24.0, so the CLI and this tab name one thing one way.
    ///
    /// The METHOD name is the one constant here that dig-node agrees with; see the module
    /// docs for the field names that it does not.
    pub const METHOD: &str = "control.spends.list";
    /// The array of spend entries.
    pub const SPENDS: &str = "spends";
    /// A spend's unix MILLISECOND, which is the unit the node's record keeps.
    pub const INITIATED_MS: &str = "initiatedMs";
    /// A spend's producer word.
    pub const KIND: &str = "kind";
    /// A spend's asset.
    pub const ASSET: &str = "asset";
    /// A spend's amount in the asset's base units.
    pub const AMOUNT: &str = "amountMojos";
    /// The XCH fee, in mojos.
    pub const FEE: &str = "feeMojos";
    /// The store a spend was on behalf of, when there is one.
    pub const STORE: &str = "storeId";
    /// The coin the spend INTENDED to create — an expectation, never evidence.
    pub const INTENDED_COIN: &str = "intendedCoinId";
    /// The status object.
    pub const STATUS: &str = "status";
    /// The status discriminant: `pending` / `submitted` / `confirmed` / `failed` / `unresolved`.
    pub const STATE: &str = "state";
    /// A confirmed status's peak height.
    pub const HEIGHT: &str = "height";
    /// A confirmed status's coin id — the coin the chain was SEEN to hold.
    pub const COIN_ID: &str = "coinId";
    /// A failed status's STAGE — how far it got, and therefore whether money may have moved.
    pub const STAGE: &str = "stage";
    /// A failed status's reason discriminant.
    pub const REASON: &str = "reason";
    /// A failed status's human detail.
    pub const DETAIL: &str = "detail";
    /// How many lines of the node's trail could not be parsed.
    pub const UNREADABLE_LINES: &str = "unreadableLines";
    /// The locked-collateral summary.
    pub const LOCKED: &str = "locked";
    /// How many stores hold collateral.
    pub const LOCKED_STORES: &str = "stores";
    /// The total locked, in base units.
    pub const LOCKED_AMOUNT: &str = "baseUnits";
}

/// Read the audit record from the node this machine is running.
///
/// Returns an [`ActivityReading`] rather than a `Result`, because every failure here is a state the
/// pane has to render honestly — and a `Result` at this seam invites a caller to
/// `unwrap_or_default()` an outage into an empty ledger, which is the one mapping this module
/// exists to prevent.
pub fn read(endpoint: Option<&str>, token: Option<&str>, timeout: Duration) -> ActivityReading {
    let Some(endpoint) = endpoint else {
        return ActivityReading::Unknown(ActivityUnknown::NoNode);
    };
    match control::call_control_raw(endpoint, wire::METHOD, Value::Null, token, timeout) {
        Ok(value) => match parse_ledger(&value) {
            Some(ledger) => ActivityReading::Known(ledger),
            None => ActivityReading::Unknown(ActivityUnknown::Unreadable),
        },
        Err(failure) => ActivityReading::Unknown(reason_for(&failure)),
    }
}

/// Which absence a control failure is.
///
/// Split out from [`read`] so it is unit-testable without a socket: the mapping is the part that has
/// to be right, and it is the part a live test would exercise least.
pub fn reason_for(failure: &ControlFailure) -> ActivityUnknown {
    let ControlFailure::Rejected(error) = failure else {
        // Transport: the node was not reachable at all, or its reply was not a JSON-RPC response.
        // Either way nobody was asked, so the remedy is the node rather than its version.
        return ActivityUnknown::NoNode;
    };
    match error.data.code.as_str() {
        code if code == ControlErrorCode::MethodNotFound.name() => ActivityUnknown::NotSupported,
        "NOT_SUPPORTED" => ActivityUnknown::NotSupported,
        "UNAUTHORIZED" => ActivityUnknown::Refused,
        _ => ActivityUnknown::Unreadable,
    }
}

/// Decode the node's answer, or `None` when it is not one this app can read.
///
/// # Why a malformed ENTRY fails the whole read
///
/// An entry that will not parse is dropped by the obvious implementation, which turns a decoding
/// bug into a **silently shorter audit record** — the exact failure mode an audit surface cannot
/// have. So a bad entry makes the whole answer [`Unreadable`](ActivityUnknown::Unreadable): a pane
/// saying "DIG could not read this" is recoverable, and a pane quietly missing a spend is not.
fn parse_ledger(value: &Value) -> Option<ActivityLedger> {
    let spends = value
        .get(wire::SPENDS)?
        .as_array()?
        .iter()
        .map(parse_spend)
        .collect::<Option<Vec<_>>>()?;
    let locked = match value.get(wire::LOCKED) {
        // Absent is a legitimate answer from a producer that locks nothing, and it means zero.
        None | Some(Value::Null) => LockedTotal::default(),
        Some(locked) => LockedTotal {
            stores: u32::try_from(locked.get(wire::LOCKED_STORES)?.as_u64()?).ok()?,
            base_units: locked.get(wire::LOCKED_AMOUNT)?.as_u64()?,
        },
    };
    Some(ActivityLedger {
        spends,
        locked,
        // Absent means the node reported none, which is the honest reading for a node whose trail was
        // wholly readable. It is NOT defaulted on a malformed value: a non-integer here would be a
        // node saying something about its own trail that this app could not read, and answering
        // "zero unreadable lines" to that is the exact claim the field exists to prevent.
        unreadable_lines: match value.get(wire::UNREADABLE_LINES) {
            None | Some(Value::Null) => 0,
            Some(count) => count.as_u64()?,
        },
    })
}

/// Decode one entry.
fn parse_spend(value: &Value) -> Option<AutomatedSpend> {
    Some(AutomatedSpend {
        // The node records milliseconds; this surface renders seconds. Converted at the boundary, in
        // one place, so no renderer has to know which unit it was handed — mixing the two is how a
        // timestamp lands in 1970 or fifty thousand years hence.
        at_unix: value.get(wire::INITIATED_MS)?.as_u64()? / 1_000,
        kind: SpendKind::from_wire(value.get(wire::KIND)?.as_str()?),
        asset: parse_asset(value.get(wire::ASSET)?)?,
        base_units: value.get(wire::AMOUNT)?.as_u64()?,
        store: value
            .get(wire::STORE)
            .and_then(Value::as_str)
            .map(str::to_string),
        // Absent is legitimate — a producer need not name a fee — and it means zero.
        fee_mojos: value.get(wire::FEE).and_then(Value::as_u64).unwrap_or(0),
        intended_coin_id: value
            .get(wire::INTENDED_COIN)
            .and_then(Value::as_str)
            .map(str::to_string),
        outcome: parse_outcome(value.get(wire::STATUS)?)?,
    })
}

/// Decode a status.
///
/// An unrecognised `state` is `None` rather than a default arm: defaulting would have to pick one of
/// "it happened" or "it did not", and both are claims about somebody's money that nothing measured.
///
/// # `unresolved` is decoded, and it is not a failure
///
/// The node's record keeps "signed and does not know" apart from "did not happen" precisely because
/// money may well have moved. Mapping it onto `Failed` here would undo that guarantee in transit,
/// which is the one thing this decoder exists not to do.
fn parse_outcome(value: &Value) -> Option<SpendOutcome> {
    match value.get(wire::STATE)?.as_str()? {
        "pending" => Some(SpendOutcome::Pending),
        "submitted" => Some(SpendOutcome::Submitted),
        "unresolved" => Some(SpendOutcome::Unresolved),
        "confirmed" => Some(SpendOutcome::Confirmed {
            height: u32::try_from(value.get(wire::HEIGHT)?.as_u64()?).ok()?,
            // Required, not optional: a confirmation with no coin id is a confirmation nobody can
            // check, and the model has no way to represent one.
            coin_id: value.get(wire::COIN_ID)?.as_str()?.to_string(),
        }),
        "failed" => {
            let detail = value
                .get(wire::DETAIL)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Some(SpendOutcome::Failed {
                // An ABSENT stage is read as `Confirmation`, the pessimistic arm, by
                // `FailureStage::from_wire`'s fallback. A node that failed to say how far it got has
                // told us nothing about whether money moved, and the safe reading of nothing is "we
                // do not know" — never "nothing happened".
                stage: FailureStage::from_wire(
                    value
                        .get(wire::STAGE)
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                reason: match value.get(wire::REASON).and_then(Value::as_str) {
                    Some("insufficient-funds") => SpendFailure::InsufficientFunds,
                    Some("rejected") => SpendFailure::Rejected(detail),
                    _ => SpendFailure::Other(match detail.is_empty() {
                        true => "The node did not say why.".to_string(),
                        false => detail,
                    }),
                },
            })
        }
        _ => None,
    }
}

/// Decode an asset in the contract crate's own encoding, so the two cannot drift.
fn parse_asset(value: &Value) -> Option<Asset> {
    match value {
        Value::String(word) if word == "xch" => Some(Asset::Xch),
        Value::String(word) if word == "dig" => Some(Asset::DIG),
        Value::Object(_) => {
            let hex = value.get("cat")?.as_str()?;
            Some(Asset::Cat(AssetId::from_hex(hex).ok()?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};

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

    fn ledger_json(spends: Value) -> Value {
        serde_json::json!({
            "spends": spends,
            "locked": { "stores": 2, "baseUnits": 40_000 },
        })
    }

    /// One entry EXACTLY as dig-node emits it (`dig-node-service/src/control.rs`, `spend_row`).
    ///
    /// Transcribed from the node's own `json!` literal rather than from this module's [`wire`]
    /// constants: building it from `wire` would assert that this decoder agrees with itself, which
    /// is true however wrong the names are, and is the whole reason the drift went unnoticed.
    fn node_shaped_spend() -> Value {
        serde_json::json!({
            "id": "s1",
            "revision": 1,
            "kind": "mirror_coin",
            "purpose": "collateralise",
            "authority": { "principal": "node", "grant": "standing" },
            "asset": "dig",
            // The node stringifies both amounts; this decoder asks for `as_u64`.
            "amount_mojos": "40000",
            "fee_mojos": "1000",
            "store_id": "store-a",
            "initiated_ms": 1_724_000_000_000u64,
            "updated_ms": 1_724_000_000_000u64,
            "status": { "state": "confirmed", "height": 9_211_798, "coin_id": "0xabc" },
            "funding_coin_ids": ["0xdef"],
            "chain_reference": { "coin_id": "0xabc", "confirmed": true },
        })
    }

    /// dig-app's hand decoder CANNOT read the payload dig-node actually sends.
    ///
    /// Green, and load-bearing in the direction that matters: it proves the drift is real rather
    /// than a reading of two files side by side, and it fails the moment the decoder is corrected
    /// — at which point it should be DELETED along with `parse_ledger`, not adjusted.
    ///
    /// Failing CLOSED here is the correct half of the behaviour. A partial decode of a spend record
    /// would be a money lie; refusing the whole page is recoverable.
    #[test]
    fn the_hand_decoder_refuses_the_page_dig_node_actually_sends() {
        let page = serde_json::json!({
            "spends": [node_shaped_spend()],
            "complete": true,
            "cursor": "s1",
            "unreadable_lines": 0,
        });
        assert!(
            parse_ledger(&page).is_none(),
            "if this now decodes, `wire` has been corrected -- delete this test with `parse_ledger`"
        );

        // The control that makes the assertion above mean "the NAMES are wrong" rather than "some
        // entry was malformed": the same entry, respelled to what this decoder asks for, decodes.
        let respelled = serde_json::json!({
            "spends": [{
                "kind": "mirror_coin",
                "asset": "dig",
                "amountMojos": 40_000u64,
                "feeMojos": 1_000u64,
                "storeId": "store-a",
                "initiatedMs": 1_724_000_000_000u64,
                "status": { "state": "confirmed", "height": 9_211_798, "coinId": "0xabc" },
            }],
        });
        assert!(
            parse_ledger(&respelled).is_some(),
            "the control must decode, or the first assertion proves nothing about field NAMES"
        );
    }

    /// An empty page must not render a CORRUPT audit trail as a tidy one.
    ///
    /// **Ignored because it is RED, and it is red because of a live defect, not a missing feature.**
    /// dig-node emits `unreadable_lines`; this decoder reads `unreadableLines`, misses it, and takes
    /// the absent-means-zero path — so a node reporting lost audit entries is shown as having
    /// nothing to report. Reachable on any node at v0.165.0 or later.
    ///
    /// It is written as the property that MUST hold rather than the behaviour that currently does,
    /// so adopting the typed `SpendsListResult` (dig-app#289) turns it green by fixing the defect.
    /// Un-ignore it there.
    ///
    /// The fixture uses a NON-ZERO count deliberately: at `0` the assertion passes whether the
    /// field is read or ignored, which is precisely the blindness under test.
    #[test]
    #[ignore = "RED: unreadable_lines is lost to a field-name drift -- fixed by dig-app#289"]
    fn an_empty_page_still_reports_the_nodes_unreadable_line_count() {
        let empty_but_corrupt = serde_json::json!({
            "spends": [],
            "complete": true,
            "cursor": Value::Null,
            "unreadable_lines": 3,
        });
        let decoded = parse_ledger(&empty_but_corrupt)
            .expect("an empty page is a legitimate answer and must decode");
        assert_eq!(
            decoded.unreadable_lines, 3,
            "the node reported 3 unreadable entries; reporting 0 hides a corrupt audit trail"
        );
    }

    /// **A node that does not serve the method is NOT a node that has spent nothing.**
    ///
    /// The two produce identical panes under the obvious implementation, so the assertion pins the
    /// reason rather than merely that something went wrong — and it is checked against a genuinely
    /// empty KNOWN ledger in the same test, which is the control that makes the distinction
    /// meaningful rather than incidental.
    #[test]
    fn an_old_node_is_unsupported_and_not_an_empty_record() {
        assert_eq!(
            reason_for(&rejected(ControlErrorCode::MethodNotFound.name())),
            ActivityUnknown::NotSupported
        );
        assert_eq!(
            reason_for(&rejected("NOT_SUPPORTED")),
            ActivityUnknown::NotSupported
        );

        let genuinely_empty = parse_ledger(&ledger_json(serde_json::json!([])))
            .expect("an empty spend list is a valid answer");
        assert!(genuinely_empty.spends.is_empty());
        assert!(
            ActivityReading::Known(genuinely_empty).is_known_empty(),
            "a measured zero reads as a measured zero"
        );
        assert!(
            !ActivityReading::Unknown(ActivityUnknown::NotSupported).is_known_empty(),
            "an unsupported node must never read as a measured zero"
        );
    }

    /// **Every other failure lands on its own remedy.**
    #[test]
    fn each_failure_names_the_thing_that_is_missing() {
        assert_eq!(
            reason_for(&rejected("UNAUTHORIZED")),
            ActivityUnknown::Refused
        );
        assert_eq!(
            reason_for(&rejected("SOMETHING_ELSE")),
            ActivityUnknown::Unreadable
        );
        assert_eq!(
            reason_for(&ControlFailure::Transport(
                control::ControlCallError::BadEndpoint("nope".into())
            )),
            ActivityUnknown::NoNode
        );
    }

    /// **With no endpoint nothing is asked, and the answer says so** rather than reporting an empty
    /// record for a node that was never contacted.
    #[test]
    fn no_endpoint_is_no_node() {
        assert_eq!(
            read(None, None, ACTIVITY_READ_TIMEOUT),
            ActivityReading::Unknown(ActivityUnknown::NoNode)
        );
    }

    /// **A whole record decodes**, including the failure entry and the locked total.
    #[test]
    fn a_record_decodes_end_to_end() {
        let ledger = parse_ledger(&ledger_json(serde_json::json!([
            {
                "initiatedMs": 1_787_500_000_000u64,
                "kind": "mirror-coin.collateral",
                "asset": "dig",
                "amountMojos": 20_000,
                "store": "store-a",
                "status": { "state": "confirmed", "height": 9_172_077, "coinId": "ab12" },
            },
            {
                "initiatedMs": 1_787_400_000_000u64,
                "kind": "mirror-coin.collateral",
                "asset": "dig",
                "amountMojos": 20_000,
                "status": { "state": "failed", "reason": "insufficient-funds" },
            },
        ])))
        .expect("a well-formed record decodes");

        assert_eq!(ledger.spends.len(), 2);
        assert_eq!(ledger.spends[0].chain_reference(), Some("ab12"));
        assert_eq!(ledger.spends[0].asset, Asset::DIG);
        assert_eq!(
            ledger.spends[1].outcome,
            SpendOutcome::Failed {
                // The node named no stage, so the decode lands on the PESSIMISTIC arm rather than
                // assuming nothing happened — see `FailureStage::from_wire`.
                stage: FailureStage::Confirmation,
                reason: SpendFailure::InsufficientFunds,
            },
            "the failure is an entry, not an omission"
        );
        assert_eq!(ledger.spends[1].chain_reference(), None);
        assert_eq!(
            ledger.locked,
            LockedTotal {
                stores: 2,
                base_units: 40_000
            }
        );
    }

    /// **A malformed entry fails the whole read rather than shortening the record.**
    ///
    /// The fixture is two entries, one good and one whose outcome names a state this app does not
    /// know — so a drop-the-bad-one implementation returns a perfectly plausible ONE-entry ledger
    /// and the pane silently omits a spend. A single-entry fixture could not tell the two apart,
    /// because dropping the only entry looks the same as refusing the answer.
    #[test]
    fn a_bad_entry_is_never_silently_dropped() {
        let mixed = ledger_json(serde_json::json!([
            {
                "initiatedMs": 1000u64, "kind": "mirror-coin.collateral", "asset": "dig",
                "amountMojos": 20_000,
                "status": { "state": "confirmed", "height": 1, "coinId": "aa" },
            },
            {
                "initiatedMs": 2000u64, "kind": "mirror-coin.collateral", "asset": "dig",
                "amountMojos": 20_000,
                "status": { "state": "who-knows" },
            },
        ]));
        assert!(
            parse_ledger(&mixed).is_none(),
            "an audit record that is quietly one entry short is worse than one that refuses"
        );
    }

    /// **A confirmation with no coin id is refused**, because it is a claim nobody can check.
    #[test]
    fn a_confirmation_without_evidence_is_refused() {
        assert!(parse_outcome(&serde_json::json!({
            "state": "confirmed", "height": 9_172_077
        }))
        .is_none());
    }

    /// **A producer this app has never heard of survives the decode**, so a newer node cannot make
    /// an entry vanish from the audit record.
    #[test]
    fn an_unknown_producer_decodes_rather_than_failing() {
        let ledger = parse_ledger(&ledger_json(serde_json::json!([{
            "initiatedMs": 1000u64,
            "kind": "some-future-producer.topup",
            "asset": "xch",
            "amountMojos": 5_000,
            "status": { "state": "submitted" },
        }])))
        .expect("an unknown kind is still an entry");
        assert_eq!(
            ledger.spends[0].kind,
            SpendKind::Other("some-future-producer.topup".to_string())
        );
        assert_eq!(ledger.spends[0].asset, Asset::Xch);
    }

    /// **An absent locked summary is zero, not an unreadable record** — a producer that locks
    /// nothing has nothing to report.
    #[test]
    fn an_absent_locked_total_is_zero() {
        let ledger = parse_ledger(&serde_json::json!({ "spends": [] }))
            .expect("a record with no locked summary is readable");
        assert_eq!(ledger.locked, LockedTotal::default());
    }

    /// **A response with no `spends` key at all is unreadable**, never an empty record.
    #[test]
    fn a_response_missing_the_spend_list_is_unreadable() {
        assert!(parse_ledger(&serde_json::json!({ "locked": null })).is_none());
    }
}
