//! Reader-derived staleness (SPEC §2.4, DECISIONS-3253 Q4).
//!
//! # Two readings, never merged
//!
//! Chain-derived state (`dig.getRewardDistributor`) and prover-reported state
//! (`dig.getRewardProverStatus`) have different freshness and different failure modes. A composite
//! health badge over both is the truncated-badge failure ([`ProverReading`] alone is never enough
//! to render a distributor) — this module answers only the prover-reported half.
//!
//! [`ProverReading`] is named deliberately differently from the writer's [`super::wire::ProverState`]
//! closed set so the two can never be conflated: `ProverState` is what the node WROTE; `ProverReading`
//! is what THIS READER, right now, against its own clock, can honestly say about that write.
//!
//! No health boolean, no precomputed staleness, no seconds-since: every variant here is derived
//! from `observed_at`, `last_cycle_completed_at`, `next_cycle_due_at` and the caller's own clock —
//! never trusted from the writer (SPEC §2.4).

use super::wire::RewardDistributorStatusRecord;

/// SPEC §2.4/§2.5's named constants, read here rather than re-typed at each call site.
pub const PROVER_HEARTBEAT_SECONDS: u64 = 60;
pub const PROVER_CYCLE_PERIOD_SECONDS: u64 = 3_600;
pub const PROVER_CYCLE_DEADLINE_SECONDS: u64 = 900;
/// DECISIONS-3253 Q4.2: how far a reported `observed_at` may sit ahead of the local clock before
/// the reading is unusable rather than merely stale.
pub const MAX_SECONDS_OFFSET: u64 = 300;

/// What a reader may honestly say about a distributor's prover, right now. Seven variants — DO NOT
/// collapse any two; each names a different reason a caller cannot simply say "it's fine" or "it's
/// dead".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverReading {
    /// No status record exists for a distributor known to be funded (SPEC §2.4 clause 1). Renders
    /// "Not distributing" — never blank, never "unknown", never a spinner.
    NoRecord,
    /// `observed_at` is ahead of the local clock by more than [`MAX_SECONDS_OFFSET`]. This can
    /// never render as fresh — a clock disagreement makes "how recent" unanswerable, not answered
    /// favourably.
    ClockUnusable,
    /// `observed_at` is within `2 * PROVER_HEARTBEAT_SECONDS` (120s) of the local clock.
    Live,
    /// `observed_at` is older than 120s but under [`PROVER_CYCLE_DEADLINE_SECONDS`] (900s).
    HeartbeatLate,
    /// `observed_at` is older than [`PROVER_CYCLE_DEADLINE_SECONDS`] (900s).
    HeartbeatLost,
    /// The heartbeat itself is live, but `now > next_cycle_due_at + MAX_SECONDS_OFFSET`.
    CycleOverdue,
    /// `last_cycle_completed_at` is `None` — a cycle has never completed.
    NeverRan,
}

/// Derives a [`ProverReading`] for `record` against `now` (both Unix seconds).
///
/// # Order of checks
///
/// `NeverRan` is checked LAST among the "record exists" branches on purpose: a prover whose clock
/// disagrees with ours, or whose heartbeat is stale, or whose cycle is overdue, has a MORE urgent
/// story than "it has simply never completed a cycle yet" — but if none of those apply and it truly
/// has never completed a cycle, that is what must be said, not "Live".
pub fn prover_reading(record: &RewardDistributorStatusRecord, now: u64) -> ProverReading {
    if record.observed_at > now && record.observed_at - now > MAX_SECONDS_OFFSET {
        return ProverReading::ClockUnusable;
    }

    let age = now.saturating_sub(record.observed_at);

    if age > PROVER_CYCLE_DEADLINE_SECONDS {
        return ProverReading::HeartbeatLost;
    }
    if age > 2 * PROVER_HEARTBEAT_SECONDS {
        return ProverReading::HeartbeatLate;
    }
    // Heartbeat is live from here down.
    if let Some(due) = record.next_cycle_due_at {
        if now > due.saturating_add(MAX_SECONDS_OFFSET) {
            return ProverReading::CycleOverdue;
        }
    }
    if record.last_cycle_completed_at.is_none() {
        return ProverReading::NeverRan;
    }
    ProverReading::Live
}

/// SPEC §2.4 clause 1 applied to the absence of a record at all.
pub fn prover_reading_for_absent_record() -> ProverReading {
    ProverReading::NoRecord
}

/// `entry_count` paired with `last_entry_write_at` as ONE non-splittable type (SPEC §2.4 clause 3):
/// there is no constructor for "a count without knowing when it was last true", so the forbidden
/// shape cannot be built, not merely avoided by convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySetReading {
    Known {
        entry_count: u32,
        last_entry_write_at: u64,
    },
    /// No peer has ever been added to this distributor.
    NeverWritten,
}

pub fn entry_set_reading(record: &RewardDistributorStatusRecord) -> EntrySetReading {
    match record.last_entry_write_at {
        Some(at) => EntrySetReading::Known {
            entry_count: record.counters.entry_count,
            last_entry_write_at: at,
        },
        None => EntrySetReading::NeverWritten,
    }
}

/// `total_paid_out_base_units` paired with `last_cycle_completed_at` as ONE non-splittable type
/// (SPEC §2.4 clause 2): a zero payout with no completed cycle means "never ran", not "nothing owed
/// yet", and there is no constructor that can express the zero without also carrying that answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutReading {
    Paid {
        total_paid_out_base_units: u64,
        last_cycle_completed_at: u64,
    },
    /// `total_paid_out_base_units == 0` and no cycle has ever completed.
    NeverRan,
}

pub fn payout_reading(record: &RewardDistributorStatusRecord) -> PayoutReading {
    match record.last_cycle_completed_at {
        Some(at) => PayoutReading::Paid {
            total_paid_out_base_units: record.counters.total_paid_out_base_units,
            last_cycle_completed_at: at,
        },
        None => PayoutReading::NeverRan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::wire::{ProverState, RewardCounters, RewardDistributorStatusRecord};

    fn base_record(observed_at: u64) -> RewardDistributorStatusRecord {
        RewardDistributorStatusRecord {
            launcher_id: [0; 32],
            store_id: [0; 32],
            root: [0; 32],
            prover_state: ProverState::Running,
            prover_state_since: 0,
            last_cycle_started_at: None,
            last_cycle_completed_at: None,
            next_cycle_due_at: None,
            last_entry_write_at: None,
            consecutive_cycle_failures: 0,
            pending_entry_writes: 0,
            observed_at,
            counters: RewardCounters::default(),
        }
    }

    /// §2.4 clause 1: an absent record renders `NoRecord`, not blank, unknown, or a spinner.
    #[test]
    fn absent_record_is_no_record() {
        assert_eq!(prover_reading_for_absent_record(), ProverReading::NoRecord);
    }

    /// DECISIONS Q4.2: a FUTURE `observed_at` beyond the offset tolerance must read as
    /// `ClockUnusable`, and specifically NOT `Live` — the exact case the decision calls out by name
    /// as the wedged-writer trap's twin.
    #[test]
    fn future_observed_at_is_clock_unusable_not_live() {
        let now = 1_000;
        let mut record = base_record(now + MAX_SECONDS_OFFSET + 1);
        record.last_cycle_completed_at = Some(now);
        assert_eq!(prover_reading(&record, now), ProverReading::ClockUnusable);
        assert_ne!(prover_reading(&record, now), ProverReading::Live);
    }

    /// A small future skew, within tolerance, is not `ClockUnusable`.
    #[test]
    fn small_future_skew_within_tolerance_is_not_clock_unusable() {
        let now = 1_000;
        let mut record = base_record(now + MAX_SECONDS_OFFSET - 1);
        record.last_cycle_completed_at = Some(now);
        assert_ne!(prover_reading(&record, now), ProverReading::ClockUnusable);
    }

    #[test]
    fn fresh_heartbeat_with_a_completed_cycle_is_live() {
        let now = 10_000;
        let mut record = base_record(now - 10);
        record.last_cycle_completed_at = Some(now - 10);
        assert_eq!(prover_reading(&record, now), ProverReading::Live);
    }

    #[test]
    fn heartbeat_between_120s_and_900s_old_is_heartbeat_late() {
        let now = 10_000;
        let mut record = base_record(now - (2 * PROVER_HEARTBEAT_SECONDS + 1));
        record.last_cycle_completed_at = Some(now - 1_000);
        assert_eq!(prover_reading(&record, now), ProverReading::HeartbeatLate);
    }

    #[test]
    fn heartbeat_older_than_900s_is_heartbeat_lost() {
        let now = 10_000;
        let mut record = base_record(now - (PROVER_CYCLE_DEADLINE_SECONDS + 1));
        record.last_cycle_completed_at = Some(now - 2_000);
        assert_eq!(prover_reading(&record, now), ProverReading::HeartbeatLost);
    }

    #[test]
    fn live_heartbeat_past_due_cycle_is_cycle_overdue() {
        let now = 10_000;
        let mut record = base_record(now - 5);
        record.last_cycle_completed_at = Some(now - 4_000);
        record.next_cycle_due_at = Some(now - MAX_SECONDS_OFFSET - 1);
        assert_eq!(prover_reading(&record, now), ProverReading::CycleOverdue);
    }

    /// A `next_cycle_due_at` near `u64::MAX` -- an absurd chain-reported value, but not one this
    /// reader may crash on -- must not panic the checked-arithmetic build. `due + MAX_SECONDS_OFFSET`
    /// wraps in a debug build's panic-on-overflow and lies silently in a release build; `saturating_add`
    /// makes it merely never-overdue instead of either.
    #[test]
    fn absurd_next_cycle_due_at_does_not_overflow() {
        let now = 10_000;
        let mut record = base_record(now - 5);
        record.last_cycle_completed_at = Some(now - 4_000);
        record.next_cycle_due_at = Some(u64::MAX - 1);
        assert_eq!(prover_reading(&record, now), ProverReading::Live);
    }

    #[test]
    fn live_heartbeat_with_no_completed_cycle_ever_is_never_ran() {
        let now = 10_000;
        let record = base_record(now - 5);
        assert_eq!(prover_reading(&record, now), ProverReading::NeverRan);
    }

    /// SPEC §2.4 clause 3: `entry_count` cannot be formatted/constructed without a write
    /// timestamp — there is no `EntrySetReading` variant that carries a count alone.
    #[test]
    fn entry_count_without_a_write_timestamp_is_never_written() {
        let record = base_record(0);
        assert_eq!(entry_set_reading(&record), EntrySetReading::NeverWritten);
    }

    #[test]
    fn entry_count_with_a_write_timestamp_is_known() {
        let mut record = base_record(0);
        record.last_entry_write_at = Some(3_000);
        record.counters.entry_count = 7;
        assert_eq!(
            entry_set_reading(&record),
            EntrySetReading::Known {
                entry_count: 7,
                last_entry_write_at: 3_000
            }
        );
    }

    /// SPEC §2.4 clause 2: a zero payout with no completed cycle is `NeverRan`, not a paid zero.
    #[test]
    fn zero_payout_with_no_completed_cycle_is_never_ran() {
        let record = base_record(0);
        assert_eq!(payout_reading(&record), PayoutReading::NeverRan);
    }

    #[test]
    fn zero_payout_with_a_completed_cycle_is_paid_zero() {
        let mut record = base_record(0);
        record.last_cycle_completed_at = Some(2_000);
        assert_eq!(
            payout_reading(&record),
            PayoutReading::Paid {
                total_paid_out_base_units: 0,
                last_cycle_completed_at: 2_000
            }
        );
    }
}
