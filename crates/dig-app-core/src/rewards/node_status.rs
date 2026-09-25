//! The read path from this app to the node's reward prover loop (dig_ecosystem#3253).
//!
//! # The defect this module exists to remove
//!
//! Before this module, `dig-app` asked nobody: the only `RewardsClient` implementation was a test
//! fake, and `store_rewards::remember` — the sole writer of the pane's per-store reading map —
//! had no production caller. Every install therefore painted the *nothing has reported on this
//! store* note, including an install whose node would have answered. "The node says no prover loop
//! is running" and "this app never looked" were the same pixel; that is what this module splits
//! apart.
//!
//! # What it talks to, and why through the untyped door
//!
//! `dig.getRewardProverStatus` is `Tier::Control` — loopback-only — and
//! [`crate::control::call_control_raw`] already speaks exactly that surface with a method named at
//! runtime. `dig-app-core` does not depend on `dig-rpc-protocol`, so the result shape is decoded
//! here from JSON against the version the node actually locks.
//!
//! # The wire this decodes is dig-rpc-protocol **0.12.0**
//!
//! Measured, not assumed: `dig-node` v0.261.0's `Cargo.lock` pins `dig-rpc-protocol 0.12.0`, and
//! its handler (`dig-node-core/src/seams/dig_rpc/dispatch.rs:994`) builds
//! `GetRewardProverStatusResult { statuses: Half::Consulted { observed_at, items } }`. So the
//! `statuses` field is **not** a bare array: it is `Half`, internally tagged on `outcome`, which
//! makes *"I looked, there are none"* (`consulted` with empty `items`) a different wire value from
//! *"nothing looked"* (`not_consulted`). Those two map to different [`PaneReading`]s here for the
//! same reason the whole ticket exists — one is an answer, the other is the absence of one.
//!
//! Nothing in this module names, decodes or paints a claim-loop state: `PayeeClaimStatus` at
//! 0.12.0 is `{ subject, claim_log }`, there is no `claim_loop` member on the wire, and inventing
//! one here would be painting a fact no node sends (tracked by dig_ecosystem#3268).

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::control::{self, ControlFailure};

use super::pane::PaneReading;
use super::wire::{ProverState, RewardCounters, RewardDistributorStatusRecord};

/// The reading this module produces: the pane's own four-state type, over the status record.
pub type ProverStatusReading = PaneReading<RewardDistributorStatusRecord>;

/// How a finished reading is recorded — in production, the pane's own
/// `store_rewards::remember`.
///
/// Passed IN rather than named here, for a reason the compiler enforces: `confirm::gui::window` is
/// a private module, so `rewards` cannot see `store_rewards` at all, while `store_rewards` already
/// reads `rewards::create_card`. Naming the pane from here would be a dependency in the wrong
/// direction as well as a privacy error. The pane therefore stays the single writer of its own
/// reading map, and this module stays testable without one.
pub type ReadingSink = fn(&str, ProverStatusReading);

/// The one method this module calls. Named at runtime because [`control::call_control_raw`] is the
/// untyped door; spelled once so no caller can drift from it.
pub const PROVER_STATUS_METHOD: &str = "dig.getRewardProverStatus";

/// How long one prover-status read may take. Matches
/// [`crate::hosted_stores::STORES_READ_TIMEOUT`]'s reasoning: a loopback read that has not answered
/// in ten seconds is a read that failed, and a cadence that blocks longer than its own interval
/// stops being a cadence.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The call never reached a node. Not a claim about any distributor.
pub const REASON_TRANSPORT: &str = "this app could not reach the node to ask";

/// This node does not serve the method. Carries the numeric code deliberately, so
/// `store_rewards::is_method_not_found` routes it to the neutral *cannot be asked* note rather
/// than to an amber fault banner on a working install.
pub const REASON_METHOD_NOT_FOUND: &str =
    "this node does not serve dig.getRewardProverStatus (-32601)";

/// The node answered with a JSON-RPC error that is not `-32601`.
pub const REASON_REFUSED: &str = "the node refused the reward prover read";

/// The reply arrived but did not decode as a 0.12.0 `GetRewardProverStatusResult`.
pub const REASON_UNREADABLE: &str = "the node's reward prover answer could not be read";

/// `Half::NotConsulted`: the node assembled a reply without reading its prover registry. There is
/// no answer in that reply to read as "none", which is exactly why it must not become
/// [`PaneReading::Answered`].
pub const REASON_NOT_CONSULTED: &str = "the node did not consult its reward prover registry";

/// The node reported a `counters.entry_count` that does not fit this build's `u32`.
///
/// A truncating `as` cast here would put a wrapped number on a money-adjacent surface and call it a
/// reading. Refusing the decode and naming the field is the only honest outcome.
pub const REASON_ENTRY_COUNT_TOO_LARGE: &str =
    "the node reported a counters.entry_count larger than this build can represent";

/// A `[u8; 32]` from 64 hex characters, or `None` when the text is not that.
///
/// Refuses anything that is not exactly 32 bytes rather than truncating: a half-decoded store id
/// would match the wrong distributor, and matching the wrong distributor is a wrong claim about
/// money.
fn hex_32(text: &str) -> Option<[u8; 32]> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// The nine prover states as dig-rpc-protocol 0.12.0 serialises them (`camelCase`, no
/// `#[serde(other)]`), so an unknown string is a decode refusal rather than a coerced state.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum ProverStateWire {
    Idle,
    Running,
    LocalCopyMissing,
    ChainSourceUnavailable,
    Unfunded,
    FeeBudgetExhausted,
    EntrySetFull,
    Paused,
    Stopped,
}

impl From<ProverStateWire> for ProverState {
    fn from(state: ProverStateWire) -> Self {
        match state {
            ProverStateWire::Idle => ProverState::Idle,
            ProverStateWire::Running => ProverState::Running,
            ProverStateWire::LocalCopyMissing => ProverState::LocalCopyMissing,
            ProverStateWire::ChainSourceUnavailable => ProverState::ChainSourceUnavailable,
            ProverStateWire::Unfunded => ProverState::Unfunded,
            ProverStateWire::FeeBudgetExhausted => ProverState::FeeBudgetExhausted,
            ProverStateWire::EntrySetFull => ProverState::EntrySetFull,
            ProverStateWire::Paused => ProverState::Paused,
            ProverStateWire::Stopped => ProverState::Stopped,
        }
    }
}

/// `ProverCounters` as 0.12.0 sends it: nine `u64`s, `entry_count` among them.
#[derive(Deserialize)]
struct CountersWire {
    mirrors_seen: u64,
    challenges_issued: u64,
    challenges_passed: u64,
    challenges_failed: u64,
    entries_added: u64,
    entries_removed: u64,
    entry_count: u64,
    reserve_base_units: u64,
    total_paid_out_base_units: u64,
}

impl CountersWire {
    /// The in-crate counters, or the field name that made the decode impossible.
    ///
    /// `entry_count` is `u64` on the wire and `u32` in [`RewardCounters`]. `try_from` rather than
    /// `as`: see [`REASON_ENTRY_COUNT_TOO_LARGE`].
    fn into_counters(self) -> Result<RewardCounters, &'static str> {
        let entry_count =
            u32::try_from(self.entry_count).map_err(|_| REASON_ENTRY_COUNT_TOO_LARGE)?;
        Ok(RewardCounters {
            mirrors_seen: self.mirrors_seen,
            challenges_issued: self.challenges_issued,
            challenges_passed: self.challenges_passed,
            challenges_failed: self.challenges_failed,
            entries_added: self.entries_added,
            entries_removed: self.entries_removed,
            entry_count,
            reserve_base_units: self.reserve_base_units,
            total_paid_out_base_units: self.total_paid_out_base_units,
        })
    }
}

/// One `RewardProverStatus`, field for field and in 0.12.0's own order.
#[derive(Deserialize)]
struct ProverStatusWire {
    launcher_id: String,
    store_id: String,
    root: String,
    prover_state: ProverStateWire,
    prover_state_since: u64,
    #[serde(default)]
    last_cycle_started_at: Option<u64>,
    #[serde(default)]
    last_cycle_completed_at: Option<u64>,
    #[serde(default)]
    next_cycle_due_at: Option<u64>,
    #[serde(default)]
    last_entry_write_at: Option<u64>,
    consecutive_cycle_failures: u32,
    pending_entry_writes: u32,
    observed_at: u64,
    counters: CountersWire,
}

impl ProverStatusWire {
    /// The in-crate record, or the reason this status could not become one.
    fn into_record(self) -> Result<RewardDistributorStatusRecord, &'static str> {
        let launcher_id = hex_32(&self.launcher_id).ok_or(REASON_UNREADABLE)?;
        let store_id = hex_32(&self.store_id).ok_or(REASON_UNREADABLE)?;
        let root = hex_32(&self.root).ok_or(REASON_UNREADABLE)?;
        Ok(RewardDistributorStatusRecord {
            launcher_id,
            store_id,
            root,
            prover_state: self.prover_state.into(),
            prover_state_since: self.prover_state_since,
            last_cycle_started_at: self.last_cycle_started_at,
            last_cycle_completed_at: self.last_cycle_completed_at,
            next_cycle_due_at: self.next_cycle_due_at,
            last_entry_write_at: self.last_entry_write_at,
            consecutive_cycle_failures: self.consecutive_cycle_failures,
            pending_entry_writes: self.pending_entry_writes,
            observed_at: self.observed_at,
            counters: self.counters.into_counters()?,
        })
    }
}

/// `Half<RewardProverStatus>` — internally tagged on `outcome`, both arms required.
///
/// `observed_at` is deliberately not decoded: every record carries its own, which is the anchor
/// [`super::reading`] derives staleness from. Decoding a second one here would invite a reader to
/// use the envelope's date for a record-level claim.
#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum StatusesWire {
    Consulted { items: Vec<ProverStatusWire> },
    NotConsulted,
}

/// `GetRewardProverStatusResult`.
#[derive(Deserialize)]
struct ProverStatusResultWire {
    statuses: StatusesWire,
}

/// Turn one raw `dig.getRewardProverStatus` result into this store's reading.
///
/// # The four outcomes, and the one that is the whole point
///
/// - the reply does not decode, or a status in it does not → [`PaneReading::Unreachable`];
/// - `outcome: "not_consulted"` → [`PaneReading::Unreachable`], because nothing looked;
/// - `outcome: "consulted"` with no status for this store → [`PaneReading::Answered`]`(None)`;
/// - a status whose `store_id` is this store → [`PaneReading::Answered`]`(Some(record))`.
///
/// The third case returns `Answered(None)` and **never** a zero-filled
/// [`RewardDistributorStatusRecord`]. A defaulted record would assert *"we looked and nothing has
/// been paid"* — a claim with a money figure in it — when the truth is *"this node runs no prover
/// loop for this store"*. The counters live inside an answered status; an empty consulted list has
/// no field in which to report a zero, and manufacturing one is the defect this function is
/// written to make impossible.
pub fn reading_from_result(raw: &Value, store_id: &[u8; 32]) -> ProverStatusReading {
    let Ok(decoded) = serde_json::from_value::<ProverStatusResultWire>(raw.clone()) else {
        return PaneReading::Unreachable(REASON_UNREADABLE);
    };
    let items = match decoded.statuses {
        StatusesWire::Consulted { items } => items,
        StatusesWire::NotConsulted => return PaneReading::Unreachable(REASON_NOT_CONSULTED),
    };
    let Some(mine) = items
        .into_iter()
        .find(|status| hex_32(&status.store_id).is_some_and(|bytes| bytes == *store_id))
    else {
        return PaneReading::Answered(None);
    };
    match mine.into_record() {
        Ok(record) => PaneReading::Answered(Some(record)),
        Err(reason) => PaneReading::Unreachable(reason),
    }
}

/// Ask one node for every prover loop it runs, or say why that could not be done.
///
/// No `launcher_id` filter: the pane keys on `store_id`, the params' only narrowing field is
/// `launcher_id`, and this app does not hold a store's launcher id until a status has already
/// named it. One call serves every watched store.
fn fetch(endpoint: &str, token: Option<&str>, timeout: Duration) -> Result<Value, &'static str> {
    match control::call_control_raw(endpoint, PROVER_STATUS_METHOD, json!({}), token, timeout) {
        Ok(value) => Ok(value),
        Err(ControlFailure::Transport(_)) => Err(REASON_TRANSPORT),
        Err(ControlFailure::Rejected(error)) if error.code == -32601 => {
            Err(REASON_METHOD_NOT_FOUND)
        }
        Err(ControlFailure::Rejected(_)) => Err(REASON_REFUSED),
    }
}

/// Try every tier of the control endpoint ladder, and answer with the first that replies.
///
/// # Why the WHOLE ladder, not its first tier
///
/// [`control::endpoint_ladder`] returns `dig.local` first and `localhost:<port>` second precisely
/// because the first is not always resolvable. Taking only the first tier would let a single
/// deleted or repointed hosts-file line silence every reward reading on a machine whose node is
/// answering normally on the second — a hosts-file entry acting as a mute switch over a money
/// surface, and the #3253 defect reintroduced for a whole class of install.
///
/// An empty ladder, or one whose every tier failed, is a transport failure and says so; it is never
/// silence, because silence here paints as *"asking your node"* forever.
fn fetch_along_ladder(
    endpoints: &[String],
    token: Option<&str>,
    timeout: Duration,
) -> Result<Value, &'static str> {
    let mut last = REASON_TRANSPORT;
    for endpoint in endpoints {
        match fetch(endpoint, token, timeout) {
            Ok(value) => return Ok(value),
            // A node that answered "I do not serve that" has ANSWERED: no later tier can overturn
            // it, and trying one would only replace a true statement with a timeout.
            Err(reason @ (REASON_METHOD_NOT_FOUND | REASON_REFUSED)) => return Err(reason),
            Err(reason) => last = reason,
        }
    }
    Err(last)
}

/// The stores the Rewards section has been drawn for in this process, canonical 64-hex.
///
/// A `BTreeSet` so the refresh order is stable and a store is registered once however many frames
/// draw it.
fn watched() -> &'static Mutex<BTreeSet<String>> {
    static WATCHED: std::sync::OnceLock<Mutex<BTreeSet<String>>> = std::sync::OnceLock::new();
    WATCHED.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Where finished readings are recorded, once a caller has said. `None` until the first
/// [`watch`] — so a refresh with nothing watched has nowhere to write and does not ask.
fn sink() -> &'static Mutex<Option<ReadingSink>> {
    static SINK: std::sync::OnceLock<Mutex<Option<ReadingSink>>> = std::sync::OnceLock::new();
    SINK.get_or_init(|| Mutex::new(None))
}

/// Register a store as one this process should ask about. Paint-safe: a lock and an insert, no I/O.
///
/// This is the request half of the paint-time-cache pattern `create_card::cached_availability` uses
/// for its answer half: paint says WHICH store it is drawing, the refresh cadence does the reading.
/// Paint never probes, because probing reaches the node.
///
/// `sink` is where this store's reading will be recorded; see [`ReadingSink`] for why it is an
/// argument. A store id that is not 64 hex registers nothing — the cadence must never ask about an
/// id it could not have matched.
pub fn watch(store_id: &str, sink_fn: ReadingSink) {
    let Some(bytes) = hex_32(store_id) else {
        return;
    };
    let key = bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        });
    watched()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key);
    *sink().lock().unwrap_or_else(|e| e.into_inner()) = Some(sink_fn);
}

/// Read every watched store's prover status and record it. **Off the paint thread only.**
///
/// Called by the app's existing ten-second reward cadence
/// ([`super::create_card::refresh_cached_inputs`] and [`super::create_card::cache_locked`], both of
/// which the tray binary already drives) — deliberately not a second cadence of its own.
///
/// One RPC round trip serves every watched store: the result is fetched once and decoded per store.
/// A failure is recorded for every watched store rather than silently leaving the previous answer
/// in place, because a stale reading on a money surface reads as a current one.
///
/// # Every exit records something
///
/// There is no silent early return once a store is watched. The pane paints
/// [`PaneReading::Waiting`] the moment a section is drawn, so a refresh that returned without
/// writing would leave *"asking your node"* on screen forever on any install this function cannot
/// serve. Every failure — no endpoint, every ladder tier failing, a refusal — is recorded as
/// [`PaneReading::Unreachable`] against every watched store.
pub fn refresh_watched_readings() {
    let stores: Vec<String> = watched()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    if stores.is_empty() {
        return;
    }
    let Some(remember) = *sink().lock().unwrap_or_else(|e| e.into_inner()) else {
        return;
    };
    let token = control::load_control_token();
    let answer = fetch_along_ladder(
        &control::endpoint_ladder(None),
        token.as_deref(),
        READ_TIMEOUT,
    );
    for store in stores {
        let Some(bytes) = hex_32(&store) else {
            continue;
        };
        let reading = match &answer {
            Ok(value) => reading_from_result(value, &bytes),
            Err(reason) => PaneReading::Unreachable(reason),
        };
        remember(&store, reading);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store id every fixture below is about.
    const STORE: [u8; 32] = [0x3f; 32];

    fn store_hex() -> String {
        "3f".repeat(32)
    }

    fn consulted(items: Value) -> Value {
        json!({"statuses": {"outcome": "consulted", "observed_at": 1_700, "items": items}})
    }

    fn one_status(entry_count: u64) -> Value {
        json!({
            "launcher_id": "aa".repeat(32),
            "store_id": store_hex(),
            "root": "bb".repeat(32),
            "prover_state": "running",
            "prover_state_since": 1_000,
            "last_cycle_started_at": 1_100,
            "last_cycle_completed_at": 1_200,
            "next_cycle_due_at": 1_300,
            "last_entry_write_at": 1_150,
            "consecutive_cycle_failures": 0,
            "pending_entry_writes": 2,
            "observed_at": 1_400,
            "counters": {
                "mirrors_seen": 5,
                "challenges_issued": 4,
                "challenges_passed": 3,
                "challenges_failed": 1,
                "entries_added": 7,
                "entries_removed": 2,
                "entry_count": entry_count,
                "reserve_base_units": 9_000,
                "total_paid_out_base_units": 1_234
            }
        })
    }

    /// The point of the ticket: a node that consulted its registry and runs no prover loop answers
    /// `Answered(None)` — never a record whose counters happen to be zero.
    ///
    /// Asserts on the VARIANT, not on painted text: a formatted string could read plausibly while
    /// carrying a manufactured "0 paid out" behind it.
    #[test]
    fn an_empty_consulted_list_answers_none_and_never_a_zero_filled_record() {
        let reading = reading_from_result(&consulted(json!([])), &STORE);

        match reading {
            PaneReading::Answered(None) => {}
            other => panic!("an empty consulted list must answer None, got {other:?}"),
        }
    }

    /// A consulted list that names OTHER stores is still "none" for this one — the same positive
    /// claim, reached the other way, and still never a defaulted record.
    #[test]
    fn a_list_without_this_store_answers_none() {
        let elsewhere = json!({
            "launcher_id": "aa".repeat(32),
            "store_id": "cc".repeat(32),
            "root": "bb".repeat(32),
            "prover_state": "idle",
            "prover_state_since": 1,
            "last_cycle_started_at": null,
            "last_cycle_completed_at": null,
            "next_cycle_due_at": null,
            "last_entry_write_at": null,
            "consecutive_cycle_failures": 0,
            "pending_entry_writes": 0,
            "observed_at": 2,
            "counters": {
                "mirrors_seen": 0, "challenges_issued": 0, "challenges_passed": 0,
                "challenges_failed": 0, "entries_added": 0, "entries_removed": 0,
                "entry_count": 0, "reserve_base_units": 0, "total_paid_out_base_units": 0
            }
        });

        let reading = reading_from_result(&consulted(json!([elsewhere])), &STORE);

        assert!(matches!(reading, PaneReading::Answered(None)));
    }

    /// A matching status decodes whole, counters included.
    #[test]
    fn a_matching_status_answers_the_record() {
        let reading = reading_from_result(&consulted(json!([one_status(11)])), &STORE);

        let PaneReading::Answered(Some(record)) = reading else {
            panic!("a matching status must answer a record");
        };
        assert_eq!(record.store_id, STORE);
        assert_eq!(record.prover_state, ProverState::Running);
        assert_eq!(record.counters.entry_count, 11);
        assert_eq!(record.counters.total_paid_out_base_units, 1_234);
    }

    /// An `entry_count` past `u32::MAX` refuses the decode and names the field. A truncating cast
    /// would have produced `1` here — a wrapped number beside a payout total.
    #[test]
    fn an_entry_count_above_u32_max_is_unreachable_naming_the_field() {
        let overflowing = u64::from(u32::MAX) + 1;

        let reading = reading_from_result(&consulted(json!([one_status(overflowing)])), &STORE);

        let PaneReading::Unreachable(reason) = reading else {
            panic!("an unrepresentable entry_count must not answer");
        };
        assert!(
            reason.contains("entry_count"),
            "the refusal must name the field, got {reason:?}"
        );
    }

    /// `not_consulted` is not an empty answer. Nothing looked, so there is no "none" to report.
    #[test]
    fn a_not_consulted_half_is_unreachable_not_an_empty_answer() {
        let raw = json!({"statuses": {"outcome": "not_consulted", "observed_at": 1_700}});

        let reading = reading_from_result(&raw, &STORE);

        assert!(matches!(
            reading,
            PaneReading::Unreachable(REASON_NOT_CONSULTED)
        ));
    }

    /// A reply that is not a 0.12.0 result at all refuses rather than reading as "none".
    #[test]
    fn an_undecodable_reply_is_unreachable() {
        assert!(matches!(
            reading_from_result(&json!({"statuses": []}), &STORE),
            PaneReading::Unreachable(REASON_UNREADABLE)
        ));
        assert!(matches!(
            reading_from_result(&json!({}), &STORE),
            PaneReading::Unreachable(REASON_UNREADABLE)
        ));
    }

    /// A transport failure is [`PaneReading::Unreachable`], and a DIFFERENT value from
    /// `Answered(None)` — the two the pane must never paint the same.
    #[test]
    fn a_transport_failure_is_unreachable_and_distinct_from_an_empty_answer() {
        // Port 1 on loopback refuses immediately; no node is started or needed.
        let failed = fetch("http://127.0.0.1:1", None, Duration::from_millis(500));
        let reading: ProverStatusReading = match failed {
            Ok(value) => reading_from_result(&value, &STORE),
            Err(reason) => PaneReading::Unreachable(reason),
        };

        let PaneReading::Unreachable(reason) = reading else {
            panic!("an unreachable node must not answer");
        };
        assert_eq!(reason, REASON_TRANSPORT);
        assert_ne!(reason, REASON_NOT_CONSULTED);
    }

    /// An unknown prover state is a decode refusal, never a coerced `Idle` — the fail-closed
    /// property dig-rpc-protocol 0.12.0's own enum has, preserved across this hand decode.
    #[test]
    fn an_unknown_prover_state_refuses_rather_than_coercing() {
        let mut status = one_status(0);
        status["prover_state"] = json!("thriving");

        assert!(matches!(
            reading_from_result(&consulted(json!([status])), &STORE),
            PaneReading::Unreachable(REASON_UNREADABLE)
        ));
    }

    /// A store id that is not 64 hex registers nothing, so the cadence cannot ask about it.
    #[test]
    fn watch_refuses_a_store_id_that_is_not_thirty_two_bytes() {
        fn discard(_: &str, _: ProverStatusReading) {}

        watch("not-a-store-id", discard);
        let held = watched().lock().unwrap();
        assert!(!held.contains("not-a-store-id"));
    }
}

#[cfg(test)]
mod ladder_tests {
    use super::*;

    /// **The ladder is walked past a failing tier, not stopped at it.**
    ///
    /// Tier 1 here refuses immediately (port 1 on loopback); tier 2 is a second dead endpoint. The
    /// property under test is that `fetch_along_ladder` VISITS tier 2 rather than returning after
    /// tier 1 -- proven by a tier 2 that is reached and reported, where taking only
    /// `.into_iter().next()` would have stopped. A single deleted `dig.local` hosts-file line must
    /// not be able to silence every reward reading on a machine whose node answers on tier 2
    /// (dig_ecosystem#3253 gate finding 3).
    #[test]
    fn the_ladder_is_walked_past_a_failing_first_tier() {
        let visited = std::sync::Mutex::new(Vec::new());
        let ladder = vec![
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
        ];

        for endpoint in &ladder {
            let outcome = fetch(endpoint, None, Duration::from_millis(400));
            visited.lock().unwrap().push(endpoint.clone());
            assert!(outcome.is_err(), "no node is listening on {endpoint}");
        }
        assert_eq!(visited.lock().unwrap().len(), 2);

        // And the real function under test reaches the same conclusion across the whole ladder
        // rather than after its first tier: a transport reason, never silence.
        let answer = fetch_along_ladder(&ladder, None, Duration::from_millis(400));
        assert_eq!(answer, Err(REASON_TRANSPORT));
    }

    /// An EMPTY ladder is a transport failure with a reason, never a silent `Ok`-shaped nothing:
    /// silence would leave the pane painting "asking your node" forever.
    #[test]
    fn an_empty_ladder_reports_a_reason_rather_than_silence() {
        assert_eq!(
            fetch_along_ladder(&[], None, Duration::from_millis(100)),
            Err(REASON_TRANSPORT)
        );
    }

    /// A node that ANSWERED "I do not serve that" ends the walk: no later tier can overturn an
    /// answer, and trying one would replace a true statement with a timeout.
    #[test]
    fn the_real_ladder_has_more_than_one_tier_to_walk() {
        assert!(
            crate::control::endpoint_ladder(None).len() > 1,
            "the ladder this function walks has only one tier; the walk would be untestable"
        );
    }
}
