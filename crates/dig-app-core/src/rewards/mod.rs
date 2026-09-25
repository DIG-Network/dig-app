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
//! Create, refill and clawback each stay out for a distinct, still-open reason — none of them is
//! the Q1 warning flow, which shipped (see [`pane::WarningsShown`]/[`pane::CreationGate`]):
//!
//! - **Create**'s two-witness GATE is compile-enforced and landed: [`create::ManagerChoice`] named
//!   by provenance only, [`create::ManagerChoiceMade`] as the binding witness (a per-value
//!   fingerprint, not merely per-variant), [`pane::Acknowledged::with_manager_choice`] (an
//!   unforgeable [`pane::Acknowledged`] consumed by value — the linear consumption is the guard,
//!   not the unrelated `may_create(&self)` predicate), and
//!   [`create::Launchable::into_manager_inner_puzzle`] as the only producer of a real
//!   `ManagerInnerPuzzle`, and the create control is now BUILT on top of it: [`create_card`]
//!   holds the card's state machine and [`create_sink`] its one worker, painted by
//!   `confirm::gui::window::pane::store_rewards`, signing and pushing through
//!   [`mint::DistributorMintDoor::begin`]. An earlier revision of this pass mounted a card whose
//!   Sign button reached `into_manager_inner_puzzle` and then discarded the result — an
//!   irreversible-looking control that created nothing — and it was removed rather than shipped
//!   disabled-in-spirit; the standing rule it left behind is that no create affordance may exist
//!   until the launch is actually wired behind it, which is the bar this pass meets.
//! - **Refill** is blocked by the absent SIGNER door, not by the on-chain primitive. The primitive
//!   exists and is public: `dig-rewards-coin` `src/fund.rs:132`
//!   `commit_incentives_for_distributor_epoch`. What does not exist is any way for this app to
//!   AUTHORISE it: `dig-account 0.30.1` — the crate that holds this app's keys — exposes exactly
//!   one reward entry point, `reward_distributor_mint.rs` `RewardDistributorMinter::begin`, beside
//!   the three reads `public_key`, `puzzle_hash` and `dig_cat_coins`. There is no refill door to
//!   call, so no refill control ships here — not even a disabled one, which would name an effect
//!   this build cannot produce.
//! - **Clawback** is blocked twice over, and BOTH have to close. There is no clawback-authorising
//!   RPC: `dig-rpc-protocol` 0.12.0's `Method` enum carries exactly five reward members —
//!   `ListRewardDistributors`, `GetRewardProverStatus`, `GetRewardDistributor`,
//!   `ListRewardDistributorCommitments` and `GetPayeeRewardClaimStatus` — every one a `list`/`get`
//!   read, and none of them authorises moving a coin. And there is no signer door either — the
//!   same `dig-account 0.30.1` surface above has no clawback entry point. (An earlier revision of
//!   this doc put a TOTAL method count here; it was wrong and is deleted rather than corrected,
//!   because a number nothing in this crate depends on is a claim that can only rot.
//!   The earlier text also blamed dig_ecosystem#3303; that issue is
//!   CLOSED and was about a `u64` overflow in `withdraw_committed_incentives`, so citing it
//!   manufactured a defect report against a fixed bug.)
//! - **The seven `ClaimLoopState` members are absent from the wire**, so nothing here decodes,
//!   names in a type, or paints one. `dig-node` v0.261.0 locks `dig-rpc-protocol` **0.12.0**
//!   (its `Cargo.lock`), where `PayeeClaimStatus` is `{ subject, claim_log }` — two fields, no
//!   `claim_loop`, no `distributors_known`, no `distributors_claimable`, no `ClaimLoopState`.
//!   Rendering a claim-loop state would be painting a fact no released node sends. Tracked by
//!   dig_ecosystem#3268 (OPEN), which wires the peer claim loop into node startup.
//!
//! # What the read path DOES ship (dig_ecosystem#3253)
//!
//! [`node_status`] is the first production transport in this module: it calls
//! `dig.getRewardProverStatus` through [`crate::control::call_control_raw`], decodes 0.12.0's
//! `GetRewardProverStatusResult` and records the result through the pane's own writer. Its whole
//! purpose is to make *"the node consulted its registry and runs no prover loop"* a different
//! painted state from *"this app never looked"* — before it, `store_rewards::remember` had no
//! production caller at all, so every install painted the second while the first was the truth.
//!
//! This pass adds only a read path: [`chain_read::ChainReadRewardsClient`] backed by
//! `dig_rewards_coin::state::read_distributor`. Its reserve figure does NOT feed
//! [`pane::rewards_sections`] -- that wiring was the dead-code hatch dig_ecosystem#3253's
//! adversarial gate found (finding 3 of the follow-up pass): the builder that would have painted
//! it was `#[allow(dead_code)]` and never called, so it was removed rather than mounted. The
//! CREATE control is built here ([`create_card`] + [`create_sink`], painted by `store_rewards`);
//! refill and clawback are not, for the two reasons above.

pub mod cadence;
pub mod chain_read;
pub mod clawback;
pub mod client;
pub mod copy;
pub mod create;
pub mod create_card;
pub mod create_sink;
pub mod humanize;
pub mod mint;
pub mod node_status;
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
