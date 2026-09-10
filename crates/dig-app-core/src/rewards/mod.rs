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
//! Per an explicit hard constraint from the parent lane: no create/mint affordance and no clawback
//! control — not even disabled — may exist until each is fed by its real gate (the full Q1 warning
//! flow for create; the not-yet-existing per-slot RPC for clawback). Neither `pane.rs`, the
//! creation flow, nor the clawback UI are built in this commit; see the PR body for exactly what
//! is attempted vs. not.

pub mod cadence;
pub mod clawback;
pub mod client;
pub mod copy;
pub mod pane;
pub mod reading;
pub mod tab_placement;
#[cfg(test)]
pub(crate) mod test_scan;
pub mod wire;
