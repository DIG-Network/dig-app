//! Turns a [`RewardDistributorStatusRecord`] (or its absence) into what a person reads (SPEC §2.4).
//!
//! # No health boolean, ever
//!
//! SPEC §2.4 forbids a `healthy`/`ok`/`up`/`running` boolean and forbids consuming a pre-computed
//! staleness or "seconds since last run": a wedged loop's last write reads true forever after the
//! failure it exists to reveal. So this module takes `observed_at` and the READER's own clock and
//! derives staleness itself — it is the ONLY function in this crate permitted to make that call for
//! the rewards pane, and every other module reads its output rather than the raw record.

use super::types::RewardDistributorStatusRecord;

/// What the pane renders for one distributor's liveness, derived — never trusted from the writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayState {
    /// SPEC §2.4 clause 1: no status record exists for a distributor known to be funded. This is
    /// the ONLY correct rendering of absence — never blank, never "unknown", never a spinner that
    /// never resolves.
    NotDistributing,
    /// SPEC §2.4 clause 2: `total_paid_out_base_units == 0` with no `last_cycle_completed_at`.
    /// Zero beside no timestamp means never ran, not "nothing owed yet".
    NeverRan,
    /// A cycle has completed at least once; the record is live enough to read normally.
    Live {
        prover_state: super::types::ProverState,
        /// `entry_count` is carried only when [`entry_count_display`] can also be answered
        /// `Known` for it (§2.4 clause 3) — this variant does not duplicate that gate.
    },
}

/// SPEC §2.4 clause 1: an absent record for a funded distributor.
pub fn display_state_for_absent_record() -> DisplayState {
    DisplayState::NotDistributing
}

/// SPEC §2.4 clauses 2 and 3, applied to a present record.
pub fn display_state_for(record: &RewardDistributorStatusRecord) -> DisplayState {
    if record.counters.total_paid_out_base_units == 0 && record.last_cycle_completed_at.is_none() {
        return DisplayState::NeverRan;
    }
    DisplayState::Live {
        prover_state: record.prover_state,
    }
}

/// What may be shown for `entry_count` (SPEC §2.4 clause 3): an entry count with no write
/// timestamp is a claim about the past presented as the present, so it is refused, not rendered as
/// a plain number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryCountDisplay {
    Known { entry_count: u32, last_entry_write_at: u64 },
    Unknown,
}

pub fn entry_count_display(record: &RewardDistributorStatusRecord) -> EntryCountDisplay {
    match record.last_entry_write_at {
        Some(at) => EntryCountDisplay::Known {
            entry_count: record.counters.entry_count,
            last_entry_write_at: at,
        },
        None => EntryCountDisplay::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::types::{ProverState, RewardCounters, RewardDistributorStatusRecord};

    fn base_record() -> RewardDistributorStatusRecord {
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
            observed_at: 1_000,
            counters: RewardCounters::default(),
        }
    }

    /// §2.4 sub-clause (a): an ABSENT status record for a funded distributor renders "not
    /// distributing" — never blank, never "unknown", never a spinner that never resolves.
    #[test]
    fn absent_record_renders_not_distributing() {
        assert_eq!(
            display_state_for_absent_record(),
            DisplayState::NotDistributing
        );
    }

    /// §2.4 sub-clause (b): `total_paid_out_base_units = 0` MUST NOT render without
    /// `last_cycle_completed_at` — zero plus no timestamp means NEVER RAN.
    #[test]
    fn zero_payout_with_no_completed_cycle_renders_never_ran() {
        let record = base_record();
        assert_eq!(display_state_for(&record), DisplayState::NeverRan);
    }

    /// The inverse of (b): a zero payout WITH a completed-cycle timestamp is a real (if quiet)
    /// live distributor, not "never ran" — the timestamp is what makes the difference legible.
    #[test]
    fn zero_payout_with_a_completed_cycle_is_not_never_ran() {
        let mut record = base_record();
        record.last_cycle_completed_at = Some(2_000);
        assert_eq!(
            display_state_for(&record),
            DisplayState::Live {
                prover_state: ProverState::Running
            }
        );
    }

    /// §2.4 sub-clause (c): `entry_count` MUST NOT render without `last_entry_write_at` — an entry
    /// count with no write timestamp is a claim about the past presented as the present.
    #[test]
    fn entry_count_without_a_write_timestamp_is_refused() {
        let record = base_record();
        assert_eq!(entry_count_display(&record), EntryCountDisplay::Unknown);
    }

    /// The inverse of (c): a write timestamp makes the entry count showable.
    #[test]
    fn entry_count_with_a_write_timestamp_is_shown() {
        let mut record = base_record();
        record.last_entry_write_at = Some(3_000);
        record.counters.entry_count = 7;
        assert_eq!(
            entry_count_display(&record),
            EntryCountDisplay::Known {
                entry_count: 7,
                last_entry_write_at: 3_000
            }
        );
    }
}
