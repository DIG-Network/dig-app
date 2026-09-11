//! The typed client seam for three of the SPEC §2.6 RPC methods.
//!
//! `dig.listRewardDistributors`, `dig.getRewardProverStatus` and `dig.getRewardDistributor` ship
//! in dig-rpc-protocol v0.11.0 (all `Tier::Control`, loopback-only) and are adopted here in full.
//! This trait's method shapes mirror the spec's table verbatim so that re-pointing dig-app at the
//! real transport is a body swap on this trait and not a reshape of anything that calls it.
//! dig-rpc-protocol and dig-rewards-coin are read-only to this lane; nothing here edits either.
//!
//! # Why the fourth method, `dig.listRewardDistributorCommitments`, is NOT here
//!
//! An earlier revision of this branch adopted it as `Result<Vec<RewardDistributorCommitment>, _>`
//! — one field of the SPEC §2.6 result's five. §2.6 says so in bold: "five fields, not one." The
//! wrapper's three dropped fields are exactly the load-bearing ones: `withdrawal_share_bps` (clause
//! 2 bans a compiled-in constant instead), `epoch_seconds` (clause 2 again bans hardcoding
//! `604_800`), and `observed_at` (clause 3 / §12.5 clause 6's dated-absence rule). Adopting one
//! field of five gave the next implementer two banned roads and no compliant one — the same
//! CommitmentSlot-shaped hole the SPEC v0.1.2 rewrite deleted once already, one layer up. Deleted
//! per the dig_ecosystem#3253 adversarial gate (finding 2); nothing in this pane calls it, and
//! nothing in dig-node serves it yet (PRs #593/#594 open, unmerged) — the full five-field
//! `ListRewardDistributorCommitmentsResult` is adopted in the PR that actually wires clawback.

use super::wire::RewardDistributorStatusRecord;

/// A distributor this node either funds or has a claim to as a mirror (SPEC §2.6
/// `dig.listRewardDistributors`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorSummary {
    pub launcher_id: [u8; 32],
    pub store_id: [u8; 32],
    pub root: [u8; 32],
    pub funded_by_this_node: bool,
}

/// Chain-derived state of one distributor (SPEC §2.6 `dig.getRewardDistributor`): constants,
/// reserve, entry count, current distributor epoch, last entry-write time. No liveness claim lives
/// here — that is [`RewardsClient::prover_status`]'s job, per §2.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorChainState {
    pub launcher_id: [u8; 32],
    pub reserve_asset_id: [u8; 32],
    pub reserve_base_units: u64,
    pub entry_count: u32,
    pub current_distributor_epoch_start: u64,
    pub last_entry_write_at: Option<u64>,
    /// The chain-observed instant this whole snapshot is true as of (a `ChainObservation`'s
    /// `peak_timestamp`, per SPEC §12.5 clause 3/6) — every figure this pane renders from this
    /// struct must carry this alongside it; never a "now" the reader assumes.
    pub observed_at: u64,
}

/// Maps a [`dig_rewards_coin::state::DistributorSnapshot`] — the sanctioned chain-read recipe's
/// result — into the pane-facing [`DistributorChainState`].
///
/// `current_distributor_epoch_start` is derived from the OBSERVED, curried
/// `constants.epoch_seconds` and the observed `round_time_info.epoch_end` — never a literal
/// `604_800` (SPEC.md §7.4 clause 2 bans hardcoding it): the running epoch's start is the previous
/// epoch's end, i.e. `epoch_end.saturating_sub(epoch_seconds)` (confirmed by the `NewEpoch` action's
/// own invariant that `epoch_end` before a roll equals the next epoch's `epoch_start`).
pub fn distributor_chain_state_from_snapshot(
    snapshot: &dig_rewards_coin::state::DistributorSnapshot,
) -> DistributorChainState {
    let distributor = snapshot.distributor();
    let constants = &distributor.info.constants;
    let state = &distributor.info.state;
    let current_distributor_epoch_start =
        current_distributor_epoch_start(state.round_time_info.epoch_end, constants.epoch_seconds);

    DistributorChainState {
        launcher_id: constants.launcher_id.to_bytes(),
        reserve_asset_id: constants.reserve_asset_id.to_bytes(),
        reserve_base_units: snapshot.reserve_base_units(),
        entry_count: snapshot.entry_count() as u32,
        current_distributor_epoch_start,
        last_entry_write_at: snapshot.observed().last_entry_write_unix(),
        observed_at: snapshot.observed().peak_timestamp(),
    }
}

/// The running epoch's start, from two OBSERVED chain values only.
///
/// `epoch_end` (before the next `NewEpoch` roll) is the boundary instant shared with the next
/// epoch's start — the `NewEpoch` action's own invariant is `my_state.round_time_info.epoch_end ==
/// reward_slot.info.value.epoch_start`. Subtracting the curried `epoch_seconds` therefore recovers
/// the CURRENT epoch's start without a separately-stored `first_epoch_start` (which does not
/// persist past launch) and without ever assuming the library default of `604_800` seconds — a
/// distributor curried with a different `epoch_seconds` must still compute correctly here.
fn current_distributor_epoch_start(epoch_end: u64, epoch_seconds: u64) -> u64 {
    epoch_end.saturating_sub(epoch_seconds)
}

#[cfg(test)]
mod epoch_start_tests {
    use super::current_distributor_epoch_start;

    /// The subject test for step 4: a distributor curried with an `epoch_seconds` that is NOT the
    /// library default of `604_800` must still produce an epoch boundary derived from ITS curried
    /// value, not the default baked into `dig-rewards-coin`.
    #[test]
    fn epoch_start_is_derived_from_the_curried_epoch_seconds_not_a_library_default() {
        let non_default_epoch_seconds: u64 = 3_600; // one hour -- deliberately not 604_800
        let observed_epoch_end: u64 = 100_000;

        let start = current_distributor_epoch_start(observed_epoch_end, non_default_epoch_seconds);

        assert_eq!(start, 100_000 - 3_600);
        assert_ne!(
            start,
            observed_epoch_end.saturating_sub(604_800),
            "must not fall back to the DEFAULT_DISTRIBUTOR_EPOCH_SECONDS literal"
        );
    }

    /// A distributor observed before its first epoch has elapsed (adversarial: `epoch_end <
    /// epoch_seconds`, which a malformed or very-early read could produce) must saturate to zero
    /// rather than underflow/panic.
    #[test]
    fn epoch_start_saturates_rather_than_underflowing() {
        assert_eq!(current_distributor_epoch_start(10, 604_800), 0);
    }
}

/// A client's own error, deliberately opaque here: the concrete transport (when dig-app's transport
/// is wired) owns its own error shape, and this pane only ever needs to know whether an answer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardsClientError(pub String);

/// The seam this pane calls instead of talking to the node directly.
pub trait RewardsClient {
    fn list_distributors(&self) -> Result<Vec<DistributorSummary>, RewardsClientError>;
    fn prover_status(
        &self,
        launcher_id: [u8; 32],
    ) -> Result<Option<RewardDistributorStatusRecord>, RewardsClientError>;
    fn distributor(
        &self,
        launcher_id: [u8; 32],
    ) -> Result<Option<DistributorChainState>, RewardsClientError>;
}

/// An in-crate fake standing in for the real transport until dig-app's transport is wired. Every
/// four async states the pane must demonstrate (loading, empty, error, loaded) are constructible
/// from this fixture without a live node.
#[derive(Debug, Clone, Default)]
pub struct FakeRewardsClient {
    pub distributors: Vec<DistributorSummary>,
    pub statuses: std::collections::HashMap<[u8; 32], RewardDistributorStatusRecord>,
    pub chain_states: std::collections::HashMap<[u8; 32], DistributorChainState>,
    /// When set, every call fails with this error instead of answering — the pane's error state.
    pub fail_with: Option<RewardsClientError>,
}

impl RewardsClient for FakeRewardsClient {
    fn list_distributors(&self) -> Result<Vec<DistributorSummary>, RewardsClientError> {
        if let Some(err) = &self.fail_with {
            return Err(err.clone());
        }
        Ok(self.distributors.clone())
    }

    fn prover_status(
        &self,
        launcher_id: [u8; 32],
    ) -> Result<Option<RewardDistributorStatusRecord>, RewardsClientError> {
        if let Some(err) = &self.fail_with {
            return Err(err.clone());
        }
        Ok(self.statuses.get(&launcher_id).cloned())
    }

    fn distributor(
        &self,
        launcher_id: [u8; 32],
    ) -> Result<Option<DistributorChainState>, RewardsClientError> {
        if let Some(err) = &self.fail_with {
            return Err(err.clone());
        }
        Ok(self.chain_states.get(&launcher_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty-state fixture: a fake with nothing loaded answers an empty list, not an error —
    /// distinguishing "no distributors" from "could not ask".
    #[test]
    fn an_empty_fake_answers_an_empty_list_not_an_error() {
        let fake = FakeRewardsClient::default();
        assert_eq!(fake.list_distributors(), Ok(vec![]));
    }

    /// The error-state fixture: `fail_with` makes every method answer the same error, so the pane's
    /// error state can be exercised without threading failure through three fixtures separately.
    #[test]
    fn fail_with_fails_every_method() {
        let fake = FakeRewardsClient {
            fail_with: Some(RewardsClientError("no node".to_string())),
            ..Default::default()
        };
        assert!(fake.list_distributors().is_err());
        assert!(fake.prover_status([0; 32]).is_err());
        assert!(fake.distributor([0; 32]).is_err());
    }

    /// The absent-record fixture that backs §2.4 clause 1: a launcher id with no entry in
    /// `statuses` answers `Ok(None)`, not an error and not a default record.
    #[test]
    fn an_unknown_launcher_id_answers_none_not_a_default_record() {
        let fake = FakeRewardsClient::default();
        assert_eq!(fake.prover_status([7; 32]), Ok(None));
    }
}
