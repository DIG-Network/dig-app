//! Reward distributor management pane (dig_ecosystem#3253, epic #3246).
//!
//! Binding contract: dig-rewards-coin SPEC.md (v0.1.2, ratified) §2.1-2.6, §6.5.1, §7.4-7.5, §9.1.
//! This module is a CONSUMER of that spec's record shapes; it owns none of the on-chain mechanism.
//!
//! The four `Tier::Control` reward RPC methods this pane needs — `dig.listRewardDistributors`,
//! `dig.getRewardProverStatus`, `dig.getRewardDistributor`, `dig.listRewardDistributorCommitments`
//! — shipped in dig-rpc-protocol v0.11.0. This module currently defines its OWN typed client trait
//! ([`client::RewardsClient`]) whose method shapes mirror the SPEC §2.3 record and §2.6 methods
//! verbatim, backed by an in-crate fake for tests ([`client::FakeRewardsClient`]); the real transport
//! is not wired yet.
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
pub mod client;
pub mod copy;
pub mod reading;
pub mod tab_placement;
pub mod wire;
