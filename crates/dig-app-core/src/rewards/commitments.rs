//! The read path for `dig.listRewardDistributorCommitments` (dig_ecosystem#3452, #3451).
//!
//! Same door as [`super::node_status`]: [`crate::control::call_control_raw`] speaks the loopback
//! control surface with a method named at runtime, and `dig-app-core` does not depend on
//! `dig-rpc-protocol`, so the reply is decoded here from JSON into private mirror structs. The wire
//! this decodes is dig-rpc-protocol **0.15.0** (SPEC §4.6), locked by dig-node v0.262.0.
//!
//! # Why the decode is strict
//!
//! `recoverable_base_units` is a money figure whose ABSENCE means "the chain refuses this
//! clawback". It is therefore a plain `Option<u64>` with no `#[serde(default)]`, no `unwrap_or`
//! and no coercing deserializer: `null` and an omitted key are `None`, `0` is a real `Some(0)`, and
//! anything that is not a non-negative integer is an error, never a zero. Every other field is
//! required. A decode error is an error, never an empty list (SPEC §4.6 clause 5).
//!
//! # The clock
//!
//! Presence of a figure is judged against the REPLY's `chain_peak_timestamp`, inside
//! `RewardDistributorCommitment::parse_from_rpc`. This module never reads the local clock; that
//! belongs to `ProvenClawback::open` alone.

use std::time::Duration;

use serde_json::{json, Value};

use crate::control::{self, ControlFailure};

use super::client::DistributorCommitments;

/// The one method this module calls, spelled once so no caller can drift from it.
pub const COMMITMENTS_METHOD: &str = "dig.listRewardDistributorCommitments";

/// The call never reached a node. Not a claim about any distributor.
pub const REASON_TRANSPORT: &str = "this app could not reach the node to ask";

/// This node does not serve the method. Carries the numeric code so callers can route it to the
/// neutral "cannot be asked" note rather than a fault banner.
pub const REASON_METHOD_NOT_FOUND: &str =
    "this node does not serve dig.listRewardDistributorCommitments (-32601)";

/// The node answered with a JSON-RPC error that is not `-32601`.
pub const REASON_REFUSED: &str = "the node refused the reward commitments read";

/// Why a reply could not become a [`DistributorCommitments`]. Every variant is a refusal to render
/// anything; none of them degrades to an empty list or a zero figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentsDecodeError {
    /// The JSON does not have the 0.15.0 shape (missing field, wrong type, negative, fractional or
    /// out-of-range number, string where a number belongs).
    Malformed,
    /// A `launcher_id` or `clawback_puzzle_hash` is not exactly 64 hex characters.
    BadHex,
    /// `withdrawal_share_bps` exceeds 10 000 -- a responder MUST NOT emit that.
    ShareOutOfRange,
    /// `chain_peak_height` or `chain_peak_timestamp` is `0`: SPEC makes both required, never 0,
    /// and a zero clock would mark every slot "not started".
    MissingAnchor,
    /// The reply is about a different distributor than the one asked for.
    WrongDistributor,
}

/// How a read failed: the call did not produce a reply, or the reply could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentsReadError {
    /// A static `REASON_*` from [`fetch`].
    Fetch(&'static str),
    /// The reply arrived and was refused by [`decode`].
    Decode(CommitmentsDecodeError),
}

/// Ask one node for a distributor's commitments, or say why that could not be done.
pub fn fetch(
    endpoint: &str,
    launcher_id: &[u8; 32],
    token: Option<&str>,
    timeout: Duration,
) -> Result<Value, &'static str> {
    let params = json!({ "launcher_id": hex_lower(launcher_id) });
    match control::call_control_raw(endpoint, COMMITMENTS_METHOD, params, token, timeout) {
        Ok(value) => Ok(value),
        Err(ControlFailure::Transport(_)) => Err(REASON_TRANSPORT),
        Err(ControlFailure::Rejected(error)) if error.code == -32601 => {
            Err(REASON_METHOD_NOT_FOUND)
        }
        Err(ControlFailure::Rejected(_)) => Err(REASON_REFUSED),
    }
}

/// [`fetch`] then [`decode`] against the same launcher id.
pub fn read(
    endpoint: &str,
    launcher_id: &[u8; 32],
    token: Option<&str>,
    timeout: Duration,
) -> Result<DistributorCommitments, CommitmentsReadError> {
    let raw = fetch(endpoint, launcher_id, token, timeout).map_err(CommitmentsReadError::Fetch)?;
    decode(&raw, launcher_id).map_err(CommitmentsReadError::Decode)
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decode a reply. STUB: red-test scaffold, replaced by the real decode in the next commit.
pub fn decode(
    _raw: &Value,
    _requested: &[u8; 32],
) -> Result<DistributorCommitments, CommitmentsDecodeError> {
    Err(CommitmentsDecodeError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::client::{FakeRewardsClient, RewardsClient, RewardsClientError};

    const LAUNCHER: [u8; 32] = [0xab; 32];
    const PEAK: u64 = 1_695_000_000;

    fn row(epoch_start: u64, recoverable: Value) -> Value {
        json!({
            "epoch_start": epoch_start,
            "clawback_puzzle_hash": "cd".repeat(32),
            "rewards_base_units": 1_000_000u64,
            "recoverable_base_units": recoverable,
        })
    }

    /// A reply with the given rows, everything else SPEC-literal.
    fn reply(rows: Vec<Value>) -> Value {
        json!({
            "launcher_id": "ab".repeat(32),
            "withdrawal_share_bps": 9000,
            "epoch_seconds": 604_800u64,
            "commitments": rows,
            "observed_at": PEAK + 5,
            "chain_peak_height": 12_345u64,
            "chain_peak_timestamp": PEAK,
        })
    }

    /// The SPEC-literal 0.15 fixture: 900000, a real zero, and a started slot carrying null.
    fn spec_fixture() -> Value {
        reply(vec![
            row(1_700_000_000, json!(900_000)),
            row(1_700_604_800, json!(0)),
            row(1_690_000_000, Value::Null),
        ])
    }

    fn figure_of(rows: Vec<Value>) -> Option<u64> {
        let decoded = decode(&reply(rows), &LAUNCHER).expect("decodes");
        assert_eq!(decoded.commitments.len(), 1, "the row must be kept");
        decoded.commitments[0].recoverable_base_units()
    }

    // ---- a: null / omitted / 0 / figure ----------------------------------------------------

    #[test]
    fn null_figure_decodes_to_none_not_zero() {
        assert_eq!(figure_of(vec![row(1_700_000_000, Value::Null)]), None);
    }

    #[test]
    fn omitted_figure_decodes_to_none_not_zero() {
        let mut omitted = row(1_700_000_000, Value::Null);
        omitted
            .as_object_mut()
            .unwrap()
            .remove("recoverable_base_units");
        assert_eq!(figure_of(vec![omitted]), None);
    }

    #[test]
    fn zero_figure_decodes_to_a_real_some_zero() {
        assert_eq!(figure_of(vec![row(1_700_000_000, json!(0))]), Some(0));
    }

    #[test]
    fn a_figure_decodes_exactly() {
        assert_eq!(
            figure_of(vec![row(1_700_000_000, json!(900_000))]),
            Some(900_000)
        );
        assert_eq!(
            figure_of(vec![row(1_700_000_000, json!(u64::MAX))]),
            Some(u64::MAX)
        );
    }

    // ---- b: a started slot keeps its row, figure None -------------------------------------

    #[test]
    fn a_started_slot_keeps_its_row_with_no_figure_even_when_the_wire_carries_one() {
        for epoch_start in [PEAK - 1, PEAK] {
            let rows = vec![row(epoch_start, json!(900_000))];
            assert_eq!(figure_of(rows), None, "epoch_start={epoch_start}");
        }
        let decoded = decode(&reply(vec![row(PEAK, json!(900_000))]), &LAUNCHER).unwrap();
        assert_eq!(decoded.commitments[0].epoch_start(), PEAK);
        assert_eq!(decoded.commitments[0].rewards_base_units(), 1_000_000);
    }

    // ---- c: errors, never None or 0 ---------------------------------------------------------

    fn assert_figure_refused(value: Value) {
        let result = decode(&reply(vec![row(1_700_000_000, value.clone())]), &LAUNCHER);
        assert_eq!(result, Err(CommitmentsDecodeError::Malformed), "{value}");
    }

    #[test]
    fn a_garbage_figure_is_an_error_never_none_or_zero() {
        assert_figure_refused(json!(-1));
        assert_figure_refused(json!(1.5));
        assert_figure_refused(json!("5"));
        assert_figure_refused(json!(true));
        // 2^64: one past u64::MAX
        let too_big: Value = serde_json::from_str("18446744073709551616").unwrap();
        assert_figure_refused(too_big);
    }

    fn without(field: &str) -> Value {
        let mut value = spec_fixture();
        value
            .as_object_mut()
            .unwrap()
            .remove(field)
            .expect("field exists");
        value
    }

    #[test]
    fn every_required_field_missing_is_an_error() {
        for field in [
            "launcher_id",
            "withdrawal_share_bps",
            "epoch_seconds",
            "commitments",
            "observed_at",
            "chain_peak_height",
            "chain_peak_timestamp",
        ] {
            assert_eq!(
                decode(&without(field), &LAUNCHER),
                Err(CommitmentsDecodeError::Malformed),
                "missing {field}"
            );
        }
    }

    #[test]
    fn a_missing_row_field_is_an_error() {
        for field in ["epoch_start", "clawback_puzzle_hash", "rewards_base_units"] {
            let mut value = spec_fixture();
            value["commitments"][0]
                .as_object_mut()
                .unwrap()
                .remove(field)
                .expect("field exists");
            assert_eq!(
                decode(&value, &LAUNCHER),
                Err(CommitmentsDecodeError::Malformed),
                "missing {field}"
            );
        }
    }

    #[test]
    fn a_share_above_ten_thousand_bps_is_refused() {
        let mut value = spec_fixture();
        value["withdrawal_share_bps"] = json!(10_001);
        assert_eq!(
            decode(&value, &LAUNCHER),
            Err(CommitmentsDecodeError::ShareOutOfRange)
        );
        value["withdrawal_share_bps"] = json!(10_000);
        assert!(
            decode(&value, &LAUNCHER).is_ok(),
            "the bound itself is legal"
        );
    }

    #[test]
    fn a_zero_chain_peak_is_refused() {
        for field in ["chain_peak_timestamp", "chain_peak_height"] {
            let mut value = spec_fixture();
            value[field] = json!(0);
            assert_eq!(
                decode(&value, &LAUNCHER),
                Err(CommitmentsDecodeError::MissingAnchor),
                "{field}"
            );
        }
    }

    #[test]
    fn a_malformed_hex_id_is_refused() {
        for bad in [
            "ab".repeat(31),
            "ab".repeat(33),
            "zz".repeat(32),
            String::new(),
        ] {
            let mut value = spec_fixture();
            value["launcher_id"] = json!(bad);
            assert_eq!(
                decode(&value, &LAUNCHER),
                Err(CommitmentsDecodeError::BadHex),
                "launcher_id {bad:?}"
            );
            let mut value = spec_fixture();
            value["commitments"][0]["clawback_puzzle_hash"] = json!(bad);
            assert_eq!(
                decode(&value, &LAUNCHER),
                Err(CommitmentsDecodeError::BadHex),
                "clawback_puzzle_hash {bad:?}"
            );
        }
    }

    #[test]
    fn a_reply_about_another_distributor_is_refused() {
        assert_eq!(
            decode(&spec_fixture(), &[0xee; 32]),
            Err(CommitmentsDecodeError::WrongDistributor)
        );
    }

    #[test]
    fn unknown_extra_keys_are_tolerated() {
        let mut value = spec_fixture();
        value["added_in_0_15_1"] = json!({"x": 1});
        value["commitments"][0]["extra"] = json!(true);
        assert!(decode(&value, &LAUNCHER).is_ok());
    }

    #[test]
    fn the_whole_result_is_kept_and_an_empty_list_is_legitimate() {
        let decoded = decode(&spec_fixture(), &LAUNCHER).unwrap();
        assert_eq!(decoded.launcher_id, LAUNCHER);
        assert_eq!(decoded.withdrawal_share_bps, 9000);
        assert_eq!(decoded.epoch_seconds, 604_800);
        assert_eq!(decoded.commitments.len(), 3);
        assert_eq!(decoded.observed_at, PEAK + 5);
        assert_eq!(decoded.chain_peak_height, 12_345);
        assert_eq!(decoded.chain_peak_timestamp, PEAK);

        let empty = decode(&reply(vec![]), &LAUNCHER).unwrap();
        assert!(empty.commitments.is_empty());
    }

    #[test]
    fn the_request_names_the_launcher_as_64_lowercase_hex() {
        assert_eq!(hex_lower(&LAUNCHER), "ab".repeat(32));
        assert_eq!(hex_lower(&[0x0f; 32]), "0f".repeat(32));
        assert_eq!(COMMITMENTS_METHOD, "dig.listRewardDistributorCommitments");
    }

    // ---- d: the trait seam ----------------------------------------------------------------

    #[test]
    fn a_fake_loaded_from_the_spec_fixture_answers_through_the_trait() {
        let decoded = decode(&spec_fixture(), &LAUNCHER).expect("decodes");
        let mut fake = FakeRewardsClient::default();
        fake.commitments.insert(LAUNCHER, decoded.clone());

        assert_eq!(
            fake.list_reward_distributor_commitments(LAUNCHER),
            Ok(Some(decoded))
        );
        assert_eq!(fake.list_reward_distributor_commitments([7; 32]), Ok(None));

        fake.fail_with = Some(RewardsClientError("no node".to_string()));
        assert!(fake.list_reward_distributor_commitments(LAUNCHER).is_err());
    }
}
