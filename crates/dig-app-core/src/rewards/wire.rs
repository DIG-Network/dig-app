//! Typed shapes mirroring dig-rewards-coin SPEC §2.3 and §2.6 verbatim.
//!
//! Nothing here is invented: every field name and every state traces to a SPEC clause named in its
//! doc comment. `dig-rpc-protocol#17` does not exist in code yet (see [`crate::rewards`]'s module
//! doc), so these are dig-app's own types until the real RPC methods land; [`crate::rewards::client::RewardsClient`]
//! (sibling module) is the seam that will be re-pointed at them without reshaping this module.

/// The closed set of prover states (SPEC §2.3). An implementation MUST use exactly this set, MUST
/// NOT add a state without adding it here, and MUST NOT collapse two into one message —
/// `LocalCopyMissing` and `Stopped` especially, because only one names the operator's own mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProverState {
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

/// One distributor's counters (SPEC §2.3 `counters`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewardCounters {
    pub mirrors_seen: u64,
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    pub challenges_failed: u64,
    pub entries_added: u64,
    pub entries_removed: u64,
    pub entry_count: u32,
    pub reserve_base_units: u64,
    pub total_paid_out_base_units: u64,
}

/// The per-distributor status record (SPEC §2.3), field for field. Every `Option<Unix seconds>`
/// field here is `None` for exactly the reason the spec names, never a stand-in zero — see
/// [`crate::rewards::reading`], which is the ONLY place this record is turned into what a person
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardDistributorStatusRecord {
    pub launcher_id: [u8; 32],
    pub store_id: [u8; 32],
    pub root: [u8; 32],
    pub prover_state: ProverState,
    pub prover_state_since: u64,
    pub last_cycle_started_at: Option<u64>,
    pub last_cycle_completed_at: Option<u64>,
    pub next_cycle_due_at: Option<u64>,
    pub last_entry_write_at: Option<u64>,
    pub consecutive_cycle_failures: u32,
    pub pending_entry_writes: u32,
    /// The chain view this record reflects — NOT "now". Staleness (§2.4) is derived by the reader
    /// from this against its own clock; it is never precomputed by the writer.
    pub observed_at: u64,
    pub counters: RewardCounters,
}

/// The ONE legal source of a reward distributor's reserve asset id (SPEC §9.1): every distributor
/// reserves `$DIG` and nothing else, so this MUST never be a typed hex literal, a runtime
/// parameter, or re-exported under a new name — it is always exactly
/// [`dig_constants::DIG_ASSET_ID`], read through this function so a caller never has to know that.
pub fn reserve_asset_id() -> chia_protocol::Bytes32 {
    dig_constants::DIG_ASSET_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC §9.1: the reserve asset id is always `dig_constants::DIG_ASSET_ID` — never a second
    /// source that could quietly drift from it.
    #[test]
    fn reserve_asset_id_is_the_dig_constants_source() {
        assert_eq!(reserve_asset_id(), dig_constants::DIG_ASSET_ID);
    }

    /// Compile-level proof that [`RewardDistributorStatusRecord`] carries exactly these fields —
    /// no more, no less. A `let Struct { a, b, .. } = x` pattern with `..` would still compile if a
    /// `healthy`/`ok`/`up`/`running` boolean were added later (SPEC §2.4's forbidden shape); this
    /// pattern has NO `..`, so it fails to compile the moment any field is added, renamed or
    /// removed, and a reviewer sees exactly which one broke it.
    #[test]
    fn status_record_has_no_extra_field_and_therefore_no_health_boolean() {
        let record = RewardDistributorStatusRecord {
            launcher_id: [0; 32],
            store_id: [0; 32],
            root: [0; 32],
            prover_state: ProverState::Idle,
            prover_state_since: 0,
            last_cycle_started_at: None,
            last_cycle_completed_at: None,
            next_cycle_due_at: None,
            last_entry_write_at: None,
            consecutive_cycle_failures: 0,
            pending_entry_writes: 0,
            observed_at: 0,
            counters: RewardCounters::default(),
        };
        let RewardDistributorStatusRecord {
            launcher_id: _,
            store_id: _,
            root: _,
            prover_state: _,
            prover_state_since: _,
            last_cycle_started_at: _,
            last_cycle_completed_at: _,
            next_cycle_due_at: _,
            last_entry_write_at: _,
            consecutive_cycle_failures: _,
            pending_entry_writes: _,
            observed_at: _,
            counters: _,
        } = record;
    }
}
