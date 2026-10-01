//! [`ChainReadRewardsClient`] — an interim [`RewardsClient`] backed directly by a [`ChainSource`],
//! for the one read this pass adds: a distributor's current chain state.
//!
//! This is NOT a second seam. It implements the existing [`RewardsClient`] trait exactly like
//! [`super::client::FakeRewardsClient`] does for tests — a caller that swaps one for the other sees
//! no shape change. It exists because dig-app has no RPC transport wired for any of the three
//! methods yet; this type answers `distributor` for real, off the chain, via the ONE sanctioned
//! recipe (`dig_rewards_coin::state::read_distributor`, SPEC.md §12.1 clause 1) while
//! `list_distributors` and `prover_status` stay honestly unanswerable until their own transports
//! exist.
//!
//! The eventual replacement for this reader is the real `dig.getRewardDistributor` RPC method
//! (dig-rpc-protocol v0.11.0, `Tier::Control`) called over dig-app's node transport — not any
//! ticket number, which can be renumbered or reassigned; the method name is the stable target.

use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::state::read_distributor;
use dig_rewards_coin::RewardsError;

use super::client::{distributor_chain_state_from_snapshot, DistributorChainState};
use super::client::{DistributorSummary, RewardsClient, RewardsClientError};
use super::wire::{
    commitments_reading_from_slots, CommitmentsReading, RewardDistributorStatusRecord,
};

/// A [`RewardsClient`] whose `distributor` method reads live chain state through a [`ChainSource`],
/// via `dig_rewards_coin::state::read_distributor`. `list_distributors` and `prover_status` are
/// deliberately never answered — see their doc comments.
pub struct ChainReadRewardsClient<C: ChainSource> {
    source: C,
}

impl<C: ChainSource> ChainReadRewardsClient<C> {
    /// Wraps `source` as a [`RewardsClient`] backed by real chain reads.
    pub fn new(source: C) -> Self {
        Self { source }
    }
}

impl<C: ChainSource> RewardsClient for ChainReadRewardsClient<C> {
    /// Always `Err`: dig-app has no enumeration wire for distributors at all (`dig.
    /// listRewardDistributors` is not called from anywhere in this crate yet). This must never
    /// degrade to `Ok(vec![])` — an empty list reads as "no distributors exist," which is a claim
    /// this reader has no way to make.
    fn list_distributors(&self) -> Result<Vec<DistributorSummary>, RewardsClientError> {
        Err(RewardsClientError(
            "dig-app has no transport for listing reward distributors yet -- \
             dig.listRewardDistributors is not called from anywhere in this build"
                .to_string(),
        ))
    }

    /// Always `Err`: dig-app has no prover-status transport wired at all. dig-node v0.257.0 DOES
    /// serve `dig.getRewardProverStatus` — this is not a node-reachability problem, and upgrading
    /// the node does not fix it. dig-app simply does not call that method anywhere yet; this
    /// message must never be read as "the node could not be reached."
    fn prover_status(
        &self,
        _launcher_id: [u8; 32],
    ) -> Result<Option<RewardDistributorStatusRecord>, RewardsClientError> {
        Err(RewardsClientError(
            "dig-app does not call dig.getRewardProverStatus anywhere in this build -- \
             the node already serves it (dig-node v0.257.0); this is a missing call, and it \
             says nothing about whether the node could be reached"
                .to_string(),
        ))
    }

    /// Reads a distributor's live chain state via `dig_rewards_coin::state::read_distributor`.
    ///
    /// - The distributor genuinely does not exist on chain -> `Ok(None)`.
    /// - The chain source could not answer (transport, timeout, malformed) -> `Err`.
    ///
    /// These two outcomes are never collapsed into each other.
    fn distributor(
        &self,
        launcher_id: [u8; 32],
    ) -> Result<Option<DistributorChainState>, RewardsClientError> {
        let launcher_id = Bytes32::from(launcher_id);
        match read_distributor(&self.source, launcher_id) {
            Ok(Some(snapshot)) => Ok(Some(distributor_chain_state_from_snapshot(&snapshot))),
            Ok(None) => Ok(None),
            Err(err) => Err(RewardsClientError(err.to_string())),
        }
    }
}

/// Reads a distributor's committed-incentive slots (SPEC §2.6, dig_ecosystem#3290) via the same
/// sanctioned recipe `distributor()` uses (`dig_rewards_coin::state::read_distributor`), split into
/// [`CommitmentsReading`]'s three states rather than folded into [`RewardsClient::distributor`]:
/// that trait answers what dig-app can call `Ok`/`Err`/`None` on today (see its own doc comment for
/// why a fifth field was never added there); this is a free function precisely so it never has to
/// widen that trait to add one read.
///
/// - Chain source could not answer -> [`CommitmentsReading::Unreadable`], never a bare zero
///   (dig_ecosystem#3427).
/// - `Ok(None)` (no distributor found) -> [`CommitmentsReading::Unreadable`] too: absence is
///   unconfirmable. The only production source, `ControlChainSource::coin_record`
///   (`chain/source.rs`), answers `coinById` from the fallback tier with `synced: false` on every
///   reply, so `Ok(None)` carries no warrant that the distributor does not exist.
/// - Read succeeded, zero outstanding commitment slots -> [`CommitmentsReading::NothingCommitted`].
/// - Read succeeded, one or more slots -> [`CommitmentsReading::Committed`].
pub fn commitments_reading<C: ChainSource>(
    source: &C,
    launcher_id: [u8; 32],
) -> CommitmentsReading {
    let launcher_id = Bytes32::from(launcher_id);
    match read_distributor(source, launcher_id) {
        Ok(Some(snapshot)) => {
            let observed_at = snapshot.observed().peak_timestamp();
            let epoch_seconds = snapshot.distributor().info.constants.epoch_seconds;
            commitments_reading_from_slots(
                &snapshot.slots().commitments,
                observed_at,
                epoch_seconds,
            )
        }
        Ok(None) => CommitmentsReading::Unreadable(UNCONFIRMED_ABSENCE_REASON),
        Err(err) => CommitmentsReading::Unreadable(unreadable_reason(&err)),
    }
}

/// The reason for an unwarranted `Ok(None)`; a member of the same CLOSED static set as
/// [`unreadable_reason`]'s answers (never a peer's words).
const UNCONFIRMED_ABSENCE_REASON: &str =
    "the chain source could not confirm the distributor exists";

/// Maps a read failure to a CLOSED set of static reasons.
///
/// The error's own text is the chain source's (a peer's) words, carried verbatim; rendering it
/// would let a hostile peer put arbitrary Unicode into a sentence on the clawback money surface.
/// So only the variant class is consulted -- never `Display`, never the payload.
fn unreadable_reason(err: &RewardsError) -> &'static str {
    match err {
        RewardsError::ChainUnavailable(_) => "the chain source could not be reached",
        RewardsError::Malformed(_) => "the chain source returned a malformed answer",
        // `RewardsError` is `#[non_exhaustive]`; any other failure is still "could not read".
        _ => "the chain source could not answer",
    }
}

#[cfg(test)]
mod tests {
    use dig_chainsource_interface::{ChainSourceError, MockChainSource};

    use super::*;

    /// (a) A chain source that fails on `coin_record` must surface as `Err`, never collapse into
    /// `Ok(None)` — an unanswerable read is not the same claim as a genuine absence.
    #[test]
    fn a_chain_source_error_on_coin_record_is_err_not_ok_none() {
        let source =
            MockChainSource::new().fail_with(ChainSourceError::Transport("no peer".to_string()));
        let client = ChainReadRewardsClient::new(source);

        let result = client.distributor([9; 32]);

        assert!(
            result.is_err(),
            "a chain source failure must not read as `the distributor does not exist`"
        );
    }

    /// (b) A launcher id the chain source has never heard of answers `Ok(None)` — the distributor
    /// genuinely does not exist per this source, which is a real, actionable answer.
    #[test]
    fn an_absent_launcher_id_answers_ok_none() {
        let source = MockChainSource::new();
        let client = ChainReadRewardsClient::new(source);

        assert_eq!(client.distributor([9; 32]), Ok(None));
    }

    /// (c) `list_distributors` always fails, by name, naming the absent enumeration wire — asserted
    /// by name so a future refactor cannot quietly turn this into `Ok(vec![])`.
    #[test]
    fn list_distributors_always_names_the_absent_enumeration_wire() {
        let client = ChainReadRewardsClient::new(MockChainSource::new());

        let err = client
            .list_distributors()
            .expect_err("list_distributors must always fail: no enumeration wire exists");

        assert!(
            err.0
                .contains("no transport for listing reward distributors"),
            "unexpected message: {}",
            err.0
        );
    }

    /// (d) `prover_status` always fails, by name, naming the missing dig-app-side call rather than
    /// implying the node is unreachable or needs an upgrade.
    #[test]
    fn prover_status_always_names_the_missing_call_not_the_node() {
        let client = ChainReadRewardsClient::new(MockChainSource::new());

        let err = client
            .prover_status([1; 32])
            .expect_err("prover_status must always fail: no transport is wired");

        assert!(
            err.0.contains("does not call dig.getRewardProverStatus"),
            "unexpected message: {}",
            err.0
        );
        assert!(
            !err.0.to_lowercase().contains("unreachable"),
            "must not imply the node is unreachable: {}",
            err.0
        );
    }

    /// (e) dig_ecosystem#3290: a chain source that fails must render `commitments_reading` as
    /// `Unreadable`, never as `NothingCommitted` — a failed read is not the same claim as a
    /// distributor with nothing committed.
    #[test]
    fn a_chain_source_error_makes_commitments_reading_unreadable() {
        let source =
            MockChainSource::new().fail_with(ChainSourceError::Transport("no peer".to_string()));

        let reading = commitments_reading(&source, [9; 32]);

        assert!(
            matches!(reading, CommitmentsReading::Unreadable(_)),
            "expected Unreadable, got {reading:?}"
        );
    }

    /// (f) dig_ecosystem#3290: an `Ok(None)` for the launcher carries no warrant (the production
    /// source never reports a synced absence), so it reads `Unreadable` -- the same sentence class
    /// as any other unreadable, and never the `NothingCommitted` sentence.
    #[test]
    fn an_unwarranted_absent_launcher_reads_unreadable_not_no_distributor() {
        let source = MockChainSource::new();

        let reading = commitments_reading(&source, [9; 32]);

        assert!(
            matches!(reading, CommitmentsReading::Unreadable(_)),
            "expected Unreadable, got {reading:?}"
        );
        let sentence = super::super::clawback::commitments_reading_sentence(&reading, 0);
        let other_unreadable = super::super::clawback::commitments_reading_sentence(
            &CommitmentsReading::Unreadable("the chain source could not be reached"),
            0,
        );
        let nothing_committed = super::super::clawback::commitments_reading_sentence(
            &CommitmentsReading::NothingCommitted { observed_at: 0 },
            0,
        );
        let reason_free = |s: &str| s.replace(UNCONFIRMED_ABSENCE_REASON, "");
        assert_eq!(
            reason_free(&sentence),
            reason_free(&other_unreadable).replace("the chain source could not be reached", ""),
            "must render the same sentence class as any other unreadable"
        );
        assert_ne!(sentence, nothing_committed);
    }

    /// dig_ecosystem#3290 (loop-security finding): the chain source's own error text is hostile
    /// input. It must never reach the rendered sentence on the clawback money surface -- the
    /// reading carries a closed, static reason instead. Decision level: reading, THEN sentence.
    #[test]
    fn a_hostile_chain_source_error_text_never_reaches_the_rendered_sentence() {
        let hostile = "FUNDS-SAFE-\u{202E}\u{200B}drain";
        let failures = [
            ChainSourceError::Transport(hostile.to_string()),
            ChainSourceError::Malformed(hostile.to_string()),
        ];

        for failure in failures {
            let source = MockChainSource::new().fail_with(failure);

            let reading = commitments_reading(&source, [9; 32]);
            let sentence = super::super::clawback::commitments_reading_sentence(&reading, 0);

            assert!(
                matches!(reading, CommitmentsReading::Unreadable(_)),
                "expected Unreadable, got {reading:?}"
            );
            for forbidden in ["FUNDS-SAFE", "\u{202E}", "\u{200B}"] {
                assert!(
                    !sentence.contains(forbidden),
                    "chain-source text leaked into the sentence: {sentence:?}"
                );
            }
            assert!(
                sentence.starts_with("The commitments could not be read:"),
                "must still be the unreadable copy: {sentence:?}"
            );
        }
    }
}
