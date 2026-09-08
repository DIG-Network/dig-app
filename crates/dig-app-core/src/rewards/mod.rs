//! Reward distributor management pane (dig_ecosystem#3253, epic #3246).
//!
//! Binding contract: dig-rewards-coin SPEC.md (v0.1.1, ratified) §2.1-2.6, §6.5.1, §7.4-7.5, §9.1.
//! This module is a CONSUMER of that spec's record shapes; it owns none of the on-chain mechanism.
//!
//! `dig-rpc-protocol#17` (the three `Tier::Control` methods this pane needs —
//! `dig.listRewardDistributors`, `dig.getRewardProverStatus`, `dig.getRewardDistributor`) is an
//! open draft with zero files: those methods do not exist in code yet. This module therefore
//! defines its OWN typed client trait ([`client::RewardsClient`]) whose method shapes mirror the
//! SPEC §2.3 record and §2.6 methods verbatim, backed by an in-crate fake for tests
//! ([`client::FakeRewardsClient`]). Wiring the real transport, and placing this pane in dig-app's
//! fixed six-tab set, are blocked on decisions relayed by the parent lane (tab placement: Q2; the
//! three copy strings: Q1/Q3/Q4) and are NOT done in this commit.

pub mod cadence;
pub mod client;
pub mod copy;
pub mod status;
pub mod types;
