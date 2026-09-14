//! Reward distributor management pane (dig_ecosystem#3253, epic #3246).
//!
//! Binding contract: dig-rewards-coin SPEC.md (v0.1.2, ratified) §2.1-2.6, §6.5.1, §7.4-7.5, §9.1.
//! This module is a CONSUMER of that spec's record shapes; it owns none of the on-chain mechanism.
//!
//! Four `Tier::Control` reward RPC methods shipped in dig-rpc-protocol v0.11.0:
//! `dig.listRewardDistributors`, `dig.getRewardProverStatus`, `dig.getRewardDistributor` and
//! `dig.listRewardDistributorCommitments`. This module's typed client trait
//! ([`client::RewardsClient`]) adopts the first THREE verbatim, backed by an in-crate fake for
//! tests ([`client::FakeRewardsClient`]); the real transport is not wired yet. The fourth is
//! deliberately NOT adopted here — an earlier revision wrapped only one of its SPEC §2.6 result's
//! five fields, which the dig_ecosystem#3253 adversarial gate found gave the next implementer two
//! banned roads and no compliant one (finding 2). It lands in full in the PR that wires clawback.
//!
//! Placement (DECISIONS-3253 Q2): Content -> store row -> store detail -> a Rewards section. NO
//! new tab; [`crate::window_model::TabId`] stays the fixed six. Being PAID as a mirror is a
//! separate, read-only, verb-free record in Automatic spends (Activity) — see [`tab_placement`].
//!
//! # What has NOT landed in this pass
//!
//! Refill and clawback stay out for a distinct, still-open reason each. Create now has a Wallet-tab
//! card ([`create`], mounted from `confirm::gui::window::pane::wallet::creation_card`) behind the
//! two-witness gate ([`pane::WarningsShown`] + [`create::ManagerChoiceMade`], both required by
//! [`pane::CreationGate::acknowledge`]/[`create::Acknowledged::with_manager_choice`]) — but it is
//! built-but-unsubmitted: pressing Sign reaches
//! [`create::Launchable::into_manager_inner_puzzle`] and stops there, because assembling the actual
//! launch spend needs an `Offer`, a `SpendContext` and a chain submission path
//! (`dig_rewards_coin::launch::launch_dig_distributor`'s other inputs) that do not exist anywhere in
//! `dig-app-core` yet. Its puzzle-hash arm (SPEC.md §7.2 clause 1a / §15 clause 9a's compliant
//! choice, named by provenance only) is reachable; its single-key arm is drawn but permanently
//! refused at Sign, because no key-generation wiring for a key this app would create and hold
//! exists in this crate.
//! - **Refill** is blocked by SPEC.md §7.4 clause 4, tracked in dig_ecosystem#3303: the incentive
//!   commit path this clause requires is not yet safe to wrap (the interim reader
//!   [`chain_read::ChainReadRewardsClient`] only reads `reserve_base_units`; it calls no
//!   fund-moving function).
//! - **Clawback** is blocked by the absent per-slot wire dig_ecosystem#3303 is landing: there is no
//!   RPC that names a single committed slot to withdraw, so the clawback UI has nothing to target.
//!
//! This pass adds only a read path: [`chain_read::ChainReadRewardsClient`] backed by
//! `dig_rewards_coin::state::read_distributor`. Its reserve figure does NOT feed
//! [`pane::rewards_sections`] -- that wiring was the dead-code hatch dig_ecosystem#3253's
//! adversarial gate found (finding 3 of the follow-up pass): the builder that would have painted
//! it was `#[allow(dead_code)]` and never called, so it was removed rather than mounted. No
//! create, refill or clawback control is built here.

pub mod cadence;
pub mod chain_read;
pub mod clawback;
pub mod client;
pub mod copy;
pub mod create;
pub mod pane;
pub mod reading;
pub mod tab_placement;
#[cfg(test)]
pub(crate) mod test_scan;
pub mod wire;

#[cfg(test)]
mod stale_doc_cause_tests {
    /// Regression for the expired cause this doc block used to cite: the Q1 warning flow (create's
    /// acknowledgment gate, [`super::pane::WarningsShown`]/[`super::pane::CreationGate`]) shipped
    /// in an earlier PR. A module doc that still blamed it would be a stale doc claim (see
    /// dig_ecosystem knowledge base: "a TRUE clause goes false the moment its subject ships") —
    /// create is blocked by the manager-singleton inner-puzzle choice (§7.2 clause 1a / §15 clause
    /// 9a) now, not by an unshipped warning flow.
    #[test]
    fn the_not_landed_block_no_longer_cites_the_shipped_q1_warning_flow() {
        // Scan only the `//!` module-doc lines, never the whole file -- this test's own source
        // legitimately names the retired phrase in its doc comment and assertion message above,
        // and `include_str!`-ing the whole file would make the assertion self-match on its own
        // text every time, failing unconditionally regardless of what the module doc says.
        let doc_comment: String = include_str!("mod.rs")
            .lines()
            .filter(|line| line.trim_start().starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !doc_comment.contains("blocked by the full Q1 warning flow"),
            "mod.rs's module doc still blames the Q1 warning flow for a gap it no longer causes; \
             the warning flow shipped (see WarningsShown/CreationGate) — restate the real, current \
             blocker instead"
        );
    }
}
