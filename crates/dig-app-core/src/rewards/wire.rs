//! Typed shapes mirroring dig-rewards-coin SPEC §2.3 and §2.6 verbatim.
//!
//! Nothing here is invented: every field name and every state traces to a SPEC clause named in its
//! doc comment. The four `Tier::Control` reward methods shipped in dig-rpc-protocol v0.11.0;
//! these types mirror SPEC §2.3 and §2.6 until dig-app's transport is wired. [`crate::rewards::client::RewardsClient`]
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
///
/// # Fields are `pub(crate)`, not `pub`
///
/// A money figure reaches a person only through `amount::format_asset_amount`, and
/// `entry_count`/`total_paid_out_base_units` reach a person only through
/// [`super::reading::entry_set_reading`]/[`super::reading::payout_reading`] — both rules that a
/// `pub` field lets any caller bypass by convention rather than by the compiler. Narrowed to
/// `pub(crate)` rather than given a constructor: a constructor over nine positional fields would
/// only re-expose the same fields as call-site arguments, and the real transport that will decode
/// `dig.getRewardProverStatus` into this type is not wired yet (see [`crate::rewards`]'s module
/// doc) — a constructor with no caller is dead code today. `pub(crate)` still closes the gap that
/// matters now: no crate OUTSIDE dig-app-core can read a raw counter and bypass `reading`'s typed
/// wrappers, and the struct-literal route stays open for this crate's own fixtures and the future
/// transport code, which is where the derive-through-`reading` contract is documented for the
/// next reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewardCounters {
    pub(crate) mirrors_seen: u64,
    pub(crate) challenges_issued: u64,
    pub(crate) challenges_passed: u64,
    pub(crate) challenges_failed: u64,
    pub(crate) entries_added: u64,
    pub(crate) entries_removed: u64,
    pub(crate) entry_count: u32,
    pub(crate) reserve_base_units: u64,
    pub(crate) total_paid_out_base_units: u64,
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

/// One committed-incentive slot (SPEC §2.6 `dig.listRewardDistributorCommitments`), mirroring
/// dig-rpc-protocol v0.11.0's `RewardDistributorCommitment` shape verbatim: all four fields, or
/// none.
///
/// # Why `recoverable_base_units` is a wire field, never a computed one
///
/// SPEC §2.6 clause 2 forbids BY NAME recomputing a share from a compiled-in constant —
/// `committed * 9000 / 10_000` or `committed * withdrawal_share_bps / 10_000` run in this crate is
/// exactly the banned defect, because the real split is decided on-chain and can differ from
/// whatever bps this crate happens to have compiled in. This type carries the chain's own already-
/// computed answer instead, so there is nothing here to recompute.
///
/// This type is no longer inert: [`super::clawback::ClawbackAuthority::prove`] (dig_ecosystem#3281)
/// constructs it into the witness it proves against, and [`super::clawback::ProvenClawback::open`]
/// reads `rewards_base_units`, `recoverable_base_units` and their difference through
/// `amount_with_unit` and paints all three as `$DIG`. The next reader must not assume no custody
/// gate reads this type — the clawback authority gate does, today. What is still true: no
/// constructor here takes a `dig.listRewardDistributorCommitments` RPC response —
/// [`super::client::RewardsClient`] does not adopt that method (deleted per the dig_ecosystem#3253
/// adversarial gate's finding 2 — the trait method wrapped only this type's `Vec`, dropping three
/// of the SPEC §2.6 result's five fields), and no constructor of this type anywhere in this crate
/// sits outside `#[cfg(test)]` code. So this type has no production value at this head, only
/// test fixtures — see dig_ecosystem#3294 for why that gap matters to [`super::clawback`]'s proof,
/// and where closing it lands once the transport is wired.
///
/// # Fields are `pub(crate)`, not `pub`
///
/// Same reasoning as [`RewardCounters`] above, applied consistently: nothing outside this crate
/// has a legitimate reason to read a commitment field directly while the type is unreachable from
/// any client method, and a `pub` field would be a hatch nobody is using yet but that a caller
/// could bypass the eventual typed reader through. Narrowed rather than left `pub` because the
/// two types sit in the same file and the same rule applies to both for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDistributorCommitment {
    pub(crate) epoch_start: u64,
    pub(crate) clawback_puzzle_hash: [u8; 32],
    pub(crate) rewards_base_units: u64,
    pub(crate) recoverable_base_units: u64,
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

    /// Compile-level proof [`RewardDistributorCommitment`] carries exactly these four fields --
    /// all four or none, per SPEC §2.6 clause 2. A `..` pattern would still compile if a fifth
    /// field silently reintroduced a pre-computed share; this pattern has no `..`.
    #[test]
    fn commitment_has_exactly_the_four_spec_fields_and_no_more() {
        let commitment = RewardDistributorCommitment {
            epoch_start: 0,
            clawback_puzzle_hash: [0; 32],
            rewards_base_units: 0,
            recoverable_base_units: 0,
        };
        let RewardDistributorCommitment {
            epoch_start: _,
            clawback_puzzle_hash: _,
            rewards_base_units: _,
            recoverable_base_units: _,
        } = commitment;
    }
}
