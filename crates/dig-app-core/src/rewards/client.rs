//! The typed client seam for the SPEC §2.6 RPC methods.
//!
//! The reward RPC methods (`dig.listRewardDistributors`, `dig.getRewardProverStatus`,
//! `dig.getRewardDistributor`, `dig.listRewardDistributorCommitments`) ship in dig-rpc-protocol
//! v0.11.0 (all `Tier::Control`, loopback-only). This trait's method shapes mirror the spec's table
//! verbatim so that re-pointing dig-app at the real transport is a body swap on this trait and not a
//! reshape of anything that calls it. dig-rpc-protocol and dig-rewards-coin are read-only to this
//! lane; nothing here edits either.

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
}

/// A client's own error, deliberately opaque here: the concrete transport (once #17 lands) owns
/// its own error shape, and this pane only ever needs to know whether an answer exists.
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

/// An in-crate fake standing in for the real transport until #17 lands. Every four async states
/// the pane must demonstrate (loading, empty, error, loaded) are constructible from this fixture
/// without a live node.
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
