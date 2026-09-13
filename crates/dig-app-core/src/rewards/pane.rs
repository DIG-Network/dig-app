//! The Rewards section painted inside a store's detail view (dig_ecosystem#3253).
//!
//! # Why this takes the WHOLE reading, never an `Option`
//!
//! `PaneNote` names four states -- [`crate::window_model::PaneNote::Waiting`],
//! [`crate::window_model::PaneNote::Unreachable`], [`crate::window_model::PaneNote::Empty`],
//! [`crate::window_model::PaneNote::Ready`] -- and an `Option` anywhere on this path collapses
//! "still reading" and "read failed" into the same `None`, which SPEC 2.3 forbids collapsing
//! (see [`crate::rewards::wire`]'s doc comment on the same point). This module's job is to map a
//! reading to exactly one of the four without ever going through that narrower type.
//!
//! This commit lands the match itself and nothing else: the first pushed unit per the parent
//! lane's push-first instruction. The store-detail wiring, the creation flow's warning display,
//! refill and the donation disclosure are built on top of this in later commits on the same
//! branch. The Activity mirror-claim record proposed in an earlier revision of this branch was
//! deleted (dig_ecosystem#3253 adversarial gate, finding 3): its only source,
//! [`super::wire::RewardDistributorStatusRecord::counters`]'s `total_paid_out_base_units`, is the
//! FUNDER's distributor-wide total paid to every mirror, not this peer's own earnings, and a peer
//! mirroring someone else's store does not even hold that record. The honest source -- this peer's
//! own past `InitiatePayout` spends (SPEC §12.5 clause 7) -- has no shipped method yet; tracked
//! separately.

use crate::amount::{amount_with_unit, format_asset_amount};
use crate::i18n::Args;
use crate::wallet::state::Asset;
use crate::window_model::{PaneNote, Section};

use super::cadence::{days_between_claims, CadenceReading};
use super::client::DistributorChainState;
use super::copy::{
    CADENCE_FAR_END, CADENCE_NO_FUNDING_RATE, CADENCE_NO_MIRRORS_YET, CADENCE_SUB_DAY_FLOOR,
    COMMITMENT_DEPTH_BOUND, ENTRY_SET_KNOWN, ENTRY_SET_NEVER_WRITTEN, PAID_OUT_NOTHING_YET,
    PAID_OUT_TOTAL, REFILL_CADENCE, RESERVE_KNOWN_DIG, RESERVE_NOT_DIG, STATUS_CLOCK_UNUSABLE,
    STATUS_CYCLE_OVERDUE, STATUS_ENTRY_COUNT_UNKNOWN, STATUS_HEARTBEAT_LATE, STATUS_HEARTBEAT_LOST,
    STATUS_LIVE, STATUS_NEVER_RAN, STATUS_NOT_DISTRIBUTING,
};
use super::reading::{
    entry_set_reading, payout_reading, prover_reading, EntrySetReading, PayoutReading,
    ProverReading,
};
use super::wire::RewardDistributorStatusRecord;

/// The three-case reading this pane starts from, before anything is painted.
///
/// Named distinctly from [`super::client::RewardsClientError`] deliberately: a caller one level up
/// decides "still asking" vs "asked and failed" vs "answered", and this enum is what it hands down
/// -- never a `Result<Option<_>, _>`, which is the same collapsing failure with extra steps.
#[derive(Debug, Clone)]
pub enum PaneReading<T> {
    /// The call is in flight; nothing is known yet.
    Waiting,
    /// The call was made and failed. Carries the reason for [`PaneNote::Unreachable`].
    Unreachable(&'static str),
    /// The call answered. `None` here means "answered with nothing" (an empty list), which is a
    /// real, different fact from either of the other two variants -- never a stand-in for them.
    Answered(Option<T>),
}

/// Map a [`PaneReading`] to the [`PaneNote`] the tab-level shell paints.
///
/// Exhaustive over all three [`PaneReading`] cases and both halves of `Answered`, so a fifth state
/// cannot be introduced without this failing to compile.
pub fn note_for<T>(reading: &PaneReading<T>) -> PaneNote {
    match reading {
        PaneReading::Waiting => PaneNote::Waiting("the reward distributor"),
        PaneReading::Unreachable(reason) => PaneNote::Unreachable(reason),
        PaneReading::Answered(None) => {
            PaneNote::Empty("no reward distributor exists for this store yet")
        }
        PaneReading::Answered(Some(_)) => PaneNote::Ready,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One case per state, asserting the painted note differs across all four -- the style
    /// `pane/mod.rs::painted_with_note` uses for every other tab's exhaustiveness check.
    #[test]
    fn all_four_states_paint_a_different_note() {
        let waiting = note_for(&PaneReading::<()>::Waiting);
        let unreachable = note_for(&PaneReading::<()>::Unreachable("no node"));
        let empty = note_for(&PaneReading::Answered::<()>(None));
        let ready = note_for(&PaneReading::Answered(Some(())));

        assert_eq!(waiting, PaneNote::Waiting("the reward distributor"));
        assert_eq!(unreachable, PaneNote::Unreachable("no node"));
        assert_eq!(
            empty,
            PaneNote::Empty("no reward distributor exists for this store yet")
        );
        assert_eq!(ready, PaneNote::Ready);

        let notes = [waiting, unreachable, empty, ready];
        for (i, a) in notes.iter().enumerate() {
            for (j, b) in notes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "states {i} and {j} painted the same note");
                }
            }
        }
    }
}

/// One fact sentence per [`ProverReading`] variant, routed through [`super::copy`]'s catalog
/// keys -- never a Rust string literal, so every one of the 14 locales carries it (dig_ecosystem
/// #3253 correctness-gate fix: this function shipped hardcoded English in the same PR that added
/// the keys it now uses). Never a health boolean rendered as a word — each sentence names the
/// SPECIFIC reason, per §2.4's rule that no two of these may collapse.
///
/// Takes `record`/`now` (not just `reading`) because three variants' catalog keys carry
/// placeables ([`STATUS_HEARTBEAT_LATE`]'s `minutes`, [`STATUS_HEARTBEAT_LOST`]'s `duration`/
/// `observed_at_date`, [`STATUS_CYCLE_OVERDUE`]'s `since_date`/`due_date`) that only the raw
/// record and clock can fill; [`ProverReading`] itself is deliberately data-less (see its own doc
/// comment) so it can never be conflated with the writer's `ProverState`.
fn prover_status_sentence(
    reading: ProverReading,
    record: &RewardDistributorStatusRecord,
    now: u64,
) -> String {
    match reading {
        ProverReading::NoRecord => STATUS_NOT_DISTRIBUTING.text(),
        ProverReading::ClockUnusable => STATUS_CLOCK_UNUSABLE.text(),
        ProverReading::Live => STATUS_LIVE.text(),
        ProverReading::HeartbeatLate => {
            let minutes = now.saturating_sub(record.observed_at) / 60;
            STATUS_HEARTBEAT_LATE.with(&Args::new().text("minutes", minutes.to_string()))
        }
        ProverReading::HeartbeatLost => {
            // Plain unix-second values, not a humanized duration/date string: dig-app-core has no
            // date-formatting helper yet (tracked separately). These are numbers, never English
            // prose, so routing them as `Args::text` rather than a Rust literal is still correct.
            let duration_seconds = now.saturating_sub(record.observed_at);
            STATUS_HEARTBEAT_LOST.with(
                &Args::new()
                    .text("duration", duration_seconds.to_string())
                    .text("observed_at_date", record.observed_at.to_string()),
            )
        }
        ProverReading::CycleOverdue => {
            // `since_date` falls back to `prover_state_since` (always present) when no cycle has
            // ever completed yet -- CycleOverdue is reachable with `last_cycle_completed_at ==
            // None` (checked before `NeverRan` in `reading::prover_reading`).
            let since = record
                .last_cycle_completed_at
                .unwrap_or(record.prover_state_since);
            let due = record.next_cycle_due_at.unwrap_or(now);
            STATUS_CYCLE_OVERDUE.with(
                &Args::new()
                    .text("since_date", since.to_string())
                    .text("due_date", due.to_string()),
            )
        }
        ProverReading::NeverRan => STATUS_NEVER_RAN.text(),
    }
}

/// One fact sentence for the entry set (SPEC §2.4 clause 3): a count is never said without the
/// write time that makes it current, per [`EntrySetReading`]'s non-splittable shape. Routed
/// through [`super::copy`], same fix as [`prover_status_sentence`].
fn entry_set_sentence(reading: EntrySetReading) -> String {
    match reading {
        EntrySetReading::NeverWritten => ENTRY_SET_NEVER_WRITTEN.text(),
        EntrySetReading::Known {
            entry_count,
            last_entry_write_at,
        } => ENTRY_SET_KNOWN.with(
            &Args::new()
                .text("entry_count", entry_count.to_string())
                .text("last_entry_write_at", last_entry_write_at.to_string()),
        ),
    }
}

/// One fact sentence for the payout total (SPEC §2.4 clause 2), money rendered ONLY through
/// [`amount_with_unit`] -- never a raw base-unit integer, never a hand-written `"$DIG"` re-deriving
/// the ticker [`amount_with_unit`] already carries (finding 7: the two must never disagree). Routed
/// through [`super::copy`], same fix as [`prover_status_sentence`].
fn payout_sentence(reading: PayoutReading) -> String {
    match reading {
        PayoutReading::NeverRan => PAID_OUT_NOTHING_YET.text(),
        PayoutReading::Paid {
            total_paid_out_base_units,
            last_cycle_completed_at,
        } => {
            let amount = amount_with_unit(Asset::DIG, total_paid_out_base_units);
            PAID_OUT_TOTAL.with(&Args::new().text("amount", amount).text(
                "last_cycle_completed_at",
                last_cycle_completed_at.to_string(),
            ))
        }
    }
}

/// The distributor's reserve fact (SPEC §2.4 clause 3, §2.6, §12.5 clause 3/6) -- the ONLY money
/// figure this pass renders, about the DISTRIBUTOR's own reserve and never this operator's
/// earnings (§12.5 clause 7's never-admitted-vs-evicted distinction stays unexpressed). Money is
/// routed ONLY through [`format_asset_amount`], never a raw base-unit integer or a hand `/
/// 1_000`, and `observed_at` always rides alongside the figure per §2.4 clause 3 -- a figure with
/// no timestamp is a claim about the past presented as the present. When `reserve_asset_id` is
/// not `dig_constants::DIG_ASSET_ID`, states that fact instead of ever printing a $DIG number for
/// a non-$DIG reserve.
// Not yet reachable from production: `reserve_sentence` reads `DistributorChainState`
// (chain-read plumbing), but `rewards_sections`'s only production caller (`store_rewards.rs`,
// read-only to this lane) drives `RewardDistributorStatusRecord` and has no chain-read state to
// pass in. Wiring it in would mean either changing `rewards_sections`'s signature (breaks the
// read-only caller's fixed-arity call) or adding a second, parallel entry point (a shape fork) --
// both need a parent decision, flagged as a STOP condition rather than guessed. Exercised directly
// by this module's tests in the meantime so the money-rule logic (asset-identity gate,
// `observed_at` requirement) is proven, just not yet mounted.
#[allow(dead_code)]
pub(crate) fn reserve_sentence(state: &DistributorChainState) -> String {
    if state.reserve_asset_id == dig_constants::DIG_ASSET_ID.to_bytes() {
        let amount = format_asset_amount(Asset::DIG, state.reserve_base_units)
            .unwrap_or_else(|| state.reserve_base_units.to_string());
        RESERVE_KNOWN_DIG.with(
            &Args::new()
                .text("amount", amount)
                .text("observed_at", state.observed_at.to_string()),
        )
    } else {
        RESERVE_NOT_DIG.with(&Args::new().text("observed_at", state.observed_at.to_string()))
    }
}

/// SPEC §7.4 clause 1's commitment-depth bound, read from the library's own
/// `CommitmentDepth::default_depth()` -- never a literal `2` (money rule: no hardcoded commitment
/// depth may drift from what the library actually enforces).
///
/// Not yet reachable from production for the same reason as [`reserve_sentence`]:
/// `rewards_sections`'s only production caller (`store_rewards.rs`, read-only to this lane) pins
/// the Vec at exactly 4 sections both by a direct-count test and by its `.take(3)` mount logic --
/// appending a 5th broke that read-only file's own test (`answers_exactly_four_sections_with_no_rows`
/// / `the_dropped_section_is_the_cadence_one_and_nothing_here_renders_it`), proving this needs a
/// parent decision (new call site or a widened mount), not a guessed shape fork. Exercised
/// directly by this module's tests in the meantime.
#[allow(dead_code)]
pub(crate) fn commitment_depth_sentence() -> String {
    let epochs = dig_rewards_coin::fund::CommitmentDepth::default_depth().epochs();
    COMMITMENT_DEPTH_BOUND.with(&Args::new().text("epochs", epochs.to_string()))
}

/// The far end of the SPEC §6.5.1 curve, past which a day count stops being a legible number and
/// becomes noise (`250_000.0` days told nobody anything they could act on). NOT a SPEC-defined
/// bound -- SPEC §6.5.1 says only that the far end "deserves a plain statement" without fixing a
/// number -- so this is a rendering clamp only, chosen at one year as comfortably past any cadence
/// a person would plan around.
const FAR_END_DAYS_THRESHOLD: f64 = 365.0;

/// SPEC §8.6's claim-attempt cadence expressed in days: a mirror cannot claim more often than once
/// per [`super::cadence::CLAIM_CADENCE_SECONDS`] regardless of accrual rate, so a computed cadence
/// below this is unachievable, not merely fast (finding 4).
const CLAIM_CADENCE_DAYS: f64 = super::cadence::CLAIM_CADENCE_SECONDS as f64 / 86_400.0;

/// One fact sentence for claim cadence (SPEC §6.5.1) -- a claim FREQUENCY, never a funding floor
/// (see this module's sibling [`super::cadence`] doc comment for why no minimum exists). Routed
/// through [`super::copy`], same fix as [`prover_status_sentence`]: [`CadenceReading::EntryCountUnknown`]
/// reuses [`STATUS_ENTRY_COUNT_UNKNOWN`] (same root fact -- both trace back to
/// `EntrySetReading::NeverWritten`) and the ordinary [`CadenceReading::Days`] case reuses
/// [`REFILL_CADENCE`], SPEC §6.5.1's own literal-required sentence; the other three variants had
/// no existing key and got a new one.
///
/// # Two clamps, neither a floor
///
/// SPEC §6.5.1 forbids presenting a funding level as a floor or a gate, and that rule is unchanged
/// here: nothing below blocks, warns on, or refuses a rate. What IS clamped is the RENDERED NUMBER
/// -- `days` below one is unachievable (SPEC §8.6 fixes the peer's own claim-attempt cadence at
/// once a day) and printing it anyway reopens the "claims arrive at no interval" reassuring-zero
/// reading the [`CadenceReading`] enum exists to close (finding 4). `days` above
/// [`FAR_END_DAYS_THRESHOLD`] is SPEC §6.5.1's "far end" case, worded rather than printed literally.
fn cadence_sentence(reading: CadenceReading) -> String {
    match reading {
        CadenceReading::EntryCountUnknown => STATUS_ENTRY_COUNT_UNKNOWN.text(),
        CadenceReading::NoMirrorsYet => CADENCE_NO_MIRRORS_YET.text(),
        CadenceReading::NoFundingRateChosen => CADENCE_NO_FUNDING_RATE.text(),
        CadenceReading::Days(days) if days < CLAIM_CADENCE_DAYS => CADENCE_SUB_DAY_FLOOR.text(),
        CadenceReading::Days(days) if days > FAR_END_DAYS_THRESHOLD => CADENCE_FAR_END
            .with(&Args::new().text("days_threshold", format!("{FAR_END_DAYS_THRESHOLD:.0}"))),
        CadenceReading::Days(days) => {
            REFILL_CADENCE.with(&Args::new().text("days", format!("{days:.1}")))
        }
    }
}

/// Builds the Rewards section's facts from an answered record (SPEC §2.3/§2.4/§6.5.1), against the
/// caller's own clock and a chosen daily funding rate in $DIG base units.
///
/// # Why every [`Section`] here has empty `rows`
///
/// No create/mint, refill or clawback affordance ships in this pass (see this module's parent
/// [`crate::rewards`] doc comment for exactly why) -- so there is nothing yet for a row to DO. A
/// `Section` may carry its fact in the heading alone with empty rows, which is the same shape
/// [`crate::rewards::tab_placement`]'s `activity_tab_emits_zero_action_rows` guard checks for the
/// mirror-claim record; this function is deliberately built to the same shape from day one so wiring
/// it in later cannot regress that guard.
pub fn rewards_sections(
    record: &RewardDistributorStatusRecord,
    now: u64,
    daily_funding_base_units: u64,
) -> Vec<Section> {
    let prover = prover_status_sentence(prover_reading(record, now), record, now);
    let entries = entry_set_sentence(entry_set_reading(record));
    let payout = payout_sentence(payout_reading(record));
    // `NeverWritten` means "no write time is known" (SPEC §2.4 clause 3) -- it must map to
    // `None`, not a synthetic `0`, or the honest `CadenceReading::EntryCountUnknown` variant
    // becomes unreachable from this, its only production producer (finding 1).
    let entry_count_for_cadence = match entry_set_reading(record) {
        EntrySetReading::NeverWritten => None,
        EntrySetReading::Known { entry_count, .. } => Some(entry_count),
    };
    let cadence = cadence_sentence(days_between_claims(
        entry_count_for_cadence,
        daily_funding_base_units,
    ));

    [prover, entries, payout, cadence]
        .into_iter()
        .map(|heading| Section {
            heading: Some(heading),
            rows: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod rewards_sections_tests {
    use super::*;
    use crate::rewards::test_scan::{function_body, string_literals};
    use crate::rewards::wire::{ProverState, RewardCounters};

    fn base_record() -> RewardDistributorStatusRecord {
        RewardDistributorStatusRecord {
            launcher_id: [0; 32],
            store_id: [0; 32],
            root: [0; 32],
            prover_state: ProverState::Running,
            prover_state_since: 0,
            last_cycle_started_at: None,
            last_cycle_completed_at: None,
            next_cycle_due_at: None,
            last_entry_write_at: None,
            consecutive_cycle_failures: 0,
            pending_entry_writes: 0,
            observed_at: 0,
            counters: RewardCounters::default(),
        }
    }

    /// Four facts, four sections, every heading carrying its own sentence and no rows -- the shape
    /// [`tab_placement`](crate::rewards::tab_placement)'s zero-action-row guard checks for.
    #[test]
    fn answers_exactly_four_sections_with_no_rows() {
        let record = base_record();
        let sections = rewards_sections(&record, 0, 0);
        assert_eq!(sections.len(), 4, "expected one section per fact");
        for section in &sections {
            assert!(
                section.heading.is_some(),
                "every section states its fact in the heading"
            );
            assert!(section.rows.is_empty(), "no affordance ships in this pass");
        }
    }

    /// A record whose prover has never completed a cycle says so in plain language, never a
    /// health boolean rendered as a word -- rendered through [`STATUS_NEVER_RAN`], never a Rust
    /// string literal, so this asserts the catalog resolution, not a copy of it.
    #[test]
    fn never_ran_prover_names_itself_in_the_first_section() {
        let record = base_record();
        let sections = rewards_sections(&record, 0, 0);
        assert_eq!(
            sections[0].heading.as_deref(),
            Some(STATUS_NEVER_RAN.text().as_str())
        );
    }

    /// A completed payout renders through `format_asset_amount`, never a raw base-unit integer:
    /// 1_500 base units of $DIG is "1.5", not "1500".
    #[test]
    fn a_completed_payout_is_money_formatted_not_a_raw_integer() {
        let mut record = base_record();
        record.last_cycle_completed_at = Some(42);
        record.counters.total_paid_out_base_units = 1_500;
        let sections = rewards_sections(&record, 0, 0);
        let payout_heading = sections[2].heading.as_deref().unwrap();
        assert!(
            payout_heading.contains("1.5 $DIG"),
            "expected money-formatted amount, got: {payout_heading}"
        );
        assert!(!payout_heading.contains("1500"));
    }

    /// A never-written entry set (`last_entry_write_at: None`) has NO known count -- the cadence
    /// sentence must say the mirror set is unknown, never "no mirror is claiming", because the
    /// wire never asserted that (SPEC §2.4 clause 3, §12.5 clause 6). This is the rewrite of the
    /// test that encoded the adversarial gate's finding 1: `base_record()` has
    /// `last_entry_write_at: None`, so a correct fix makes the ORIGINAL assertion here fail.
    #[test]
    fn never_written_entry_set_cadence_is_entry_count_unknown_not_a_reassuring_zero() {
        let record = base_record();
        let sections = rewards_sections(&record, 0, 1_000);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert_eq!(cadence_heading, STATUS_ENTRY_COUNT_UNKNOWN.text());
    }

    /// A GENUINELY known zero entry count (post-eviction, or never admitted, but with a real
    /// write timestamp) is a different fact from an unknown entry set, and gets its own sentence:
    /// "no mirror is claiming." SPEC §2.4 clause 3's non-splittable shape, carried all the way to
    /// the pane. The sentence carries no claim about HOW the set became empty -- see the next test.
    #[test]
    fn known_zero_entry_count_cadence_is_no_mirrors_yet() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 0;
        let sections = rewards_sections(&record, 0, 1_000);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert_eq!(cadence_heading, CADENCE_NO_MIRRORS_YET.text());
    }

    /// F1 (dig_ecosystem#3253 adversarial gate, third pass): SPEC §12.5 clause 7 forbids
    /// displaying the never-admitted-vs-evicted-after-settlement distinction -- `RemoveEntry`
    /// leaves no marker to derive it from, so a guess presented as fact must never be built or
    /// shown. `CadenceReading::NoMirrorsYet` is produced identically for both histories (see
    /// [`super::cadence::CadenceReading::NoMirrorsYet`]'s doc comment), so the rendered sentence
    /// must be equally TRUE of both -- not merely which variant/key was chosen, which every other
    /// test in this file checks and which is why two earlier legs of this same gate both missed
    /// the sentence still claiming "yet". A sentence is untrue of an evicted-after-settlement state
    /// if it contains a word implying the emptiness is pending, novel, or reversible ("yet",
    /// "still", "never") or that names the excluded mechanism directly ("evict", "admit",
    /// "remove"); asserting their absence catches a reintroduction mechanically, in the string
    /// itself, not by re-reading the review comment.
    #[test]
    fn no_mirrors_yet_sentence_carries_no_never_admitted_vs_evicted_distinction() {
        let text = CADENCE_NO_MIRRORS_YET.text().to_lowercase();
        for banned in ["yet", "still", "never", "evict", "admit", "remov"] {
            assert!(
                !text.contains(banned),
                "rewards-cadence-no-mirrors-yet ({text:?}) contains {banned:?}, which claims \
                 something about HOW the mirror set became empty -- SPEC §12.5 clause 7 forbids \
                 that distinction"
            );
        }
    }

    /// A zero CHOSEN funding rate with mirrors present is a third, different sentence again
    /// (finding 5): it must not collapse into "no mirror is claiming yet", which asserts something
    /// false about a set that may well have admitted mirrors.
    #[test]
    fn zero_funding_rate_with_mirrors_present_says_choose_a_rate_not_no_mirrors_yet() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 5;
        let sections = rewards_sections(&record, 0, 0);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert_eq!(cadence_heading, CADENCE_NO_FUNDING_RATE.text());
    }

    /// The sub-day boundary (finding 4): a funding rate rich enough to compute a cadence under one
    /// day must not print a sub-`1.0` figure -- SPEC §8.6 fixes the peer's own claim-attempt
    /// cadence at once a day, so a smaller number is a promise the mechanism cannot keep. Pinned
    /// exactly at the boundary from both sides so the clamp is neither off-by-one nor missing.
    #[test]
    fn sub_day_cadence_clamps_to_the_claim_cycle_floor_not_a_sub_one_figure() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 1;
        // One mirror at 100_000 base units/day computes to 0.01 days -- deep under the floor.
        let sections = rewards_sections(&record, 0, 100_000);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert!(
            !cadence_heading.contains("0.0"),
            "sub-day cadence printed a reassuring 0.0: {cadence_heading}"
        );
        assert_eq!(cadence_heading, CADENCE_SUB_DAY_FLOOR.text());

        // Exactly at the one-day boundary (1_000 base units/day, one mirror) is NOT clamped --
        // it renders the ordinary numeric sentence, through `REFILL_CADENCE`.
        let at_boundary = rewards_sections(&record, 0, 1_000);
        let boundary_heading = at_boundary[3].heading.as_deref().unwrap();
        assert_eq!(
            boundary_heading,
            REFILL_CADENCE.with(&Args::new().text("days", "1.0"))
        );
    }

    /// The far end of the SPEC §6.5.1 curve (finding 4): an extremely thin funding rate must not
    /// print a literal, illegible day count like `250000.0`.
    #[test]
    fn far_end_cadence_is_worded_not_printed_literally() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 250;
        // 250 mirrors at 1 base unit/day computes to 250_000 days.
        let sections = rewards_sections(&record, 0, 1);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert!(
            !cadence_heading.contains("250000"),
            "far-end cadence printed the literal day count: {cadence_heading}"
        );
        assert_eq!(
            cadence_heading,
            CADENCE_FAR_END.with(&Args::new().text("days_threshold", "365"))
        );
    }

    /// Every reachable [`ProverReading`] variant renders through its catalog key, not a Rust
    /// string literal -- the direct regression test for dig_ecosystem#3253's correctness-gate
    /// finding (this pane shipped hardcoded English in the same PR that added the keys).
    #[test]
    fn every_prover_reading_resolves_through_the_catalog() {
        let record = base_record();
        assert_eq!(
            prover_status_sentence(ProverReading::NoRecord, &record, 0),
            STATUS_NOT_DISTRIBUTING.text()
        );
        assert_eq!(
            prover_status_sentence(ProverReading::ClockUnusable, &record, 0),
            STATUS_CLOCK_UNUSABLE.text()
        );
        assert_eq!(
            prover_status_sentence(ProverReading::Live, &record, 0),
            STATUS_LIVE.text()
        );
        assert_eq!(
            prover_status_sentence(ProverReading::NeverRan, &record, 0),
            STATUS_NEVER_RAN.text()
        );
        assert_eq!(
            prover_status_sentence(ProverReading::HeartbeatLate, &record, 120),
            STATUS_HEARTBEAT_LATE.with(&Args::new().text("minutes", "2"))
        );
        assert_eq!(
            prover_status_sentence(ProverReading::HeartbeatLost, &record, 900),
            STATUS_HEARTBEAT_LOST.with(
                &Args::new()
                    .text("duration", "900")
                    .text("observed_at_date", "0")
            )
        );
        assert_eq!(
            prover_status_sentence(ProverReading::CycleOverdue, &record, 1_000),
            STATUS_CYCLE_OVERDUE
                .with(&Args::new().text("since_date", "0").text("due_date", "1000"))
        );
    }

    /// Every [`EntrySetReading`] variant renders through its catalog key.
    #[test]
    fn every_entry_set_reading_resolves_through_the_catalog() {
        assert_eq!(
            entry_set_sentence(EntrySetReading::NeverWritten),
            ENTRY_SET_NEVER_WRITTEN.text()
        );
        assert_eq!(
            entry_set_sentence(EntrySetReading::Known {
                entry_count: 3,
                last_entry_write_at: 500,
            }),
            ENTRY_SET_KNOWN.with(
                &Args::new()
                    .text("entry_count", "3")
                    .text("last_entry_write_at", "500")
            )
        );
    }

    /// Every [`PayoutReading`] variant renders through its catalog key.
    #[test]
    fn every_payout_reading_resolves_through_the_catalog() {
        assert_eq!(
            payout_sentence(PayoutReading::NeverRan),
            PAID_OUT_NOTHING_YET.text()
        );
        assert_eq!(
            payout_sentence(PayoutReading::Paid {
                total_paid_out_base_units: 1_500,
                last_cycle_completed_at: 42,
            }),
            PAID_OUT_TOTAL.with(
                &Args::new()
                    .text("amount", amount_with_unit(Asset::DIG, 1_500))
                    .text("last_cycle_completed_at", "42")
            )
        );
    }

    /// Every [`CadenceReading`] variant renders through its catalog key -- the direct regression
    /// test for the same finding, over the fourth sentence builder.
    #[test]
    fn every_cadence_reading_resolves_through_the_catalog() {
        assert_eq!(
            cadence_sentence(CadenceReading::EntryCountUnknown),
            STATUS_ENTRY_COUNT_UNKNOWN.text()
        );
        assert_eq!(
            cadence_sentence(CadenceReading::NoMirrorsYet),
            CADENCE_NO_MIRRORS_YET.text()
        );
        assert_eq!(
            cadence_sentence(CadenceReading::NoFundingRateChosen),
            CADENCE_NO_FUNDING_RATE.text()
        );
        assert_eq!(
            cadence_sentence(CadenceReading::Days(0.5)),
            CADENCE_SUB_DAY_FLOOR.text()
        );
        assert_eq!(
            cadence_sentence(CadenceReading::Days(400.0)),
            CADENCE_FAR_END.with(&Args::new().text("days_threshold", "365"))
        );
        assert_eq!(
            cadence_sentence(CadenceReading::Days(10.0)),
            REFILL_CADENCE.with(&Args::new().text("days", "10.0"))
        );
    }

    /// A guard against the exact regression this test module exists to close: every one of the
    /// four sentence-builder functions' SOURCE must contain no bare English-prose string literal
    /// -- only catalog keys (kebab-case, no spaces) and plain data (arg names, format specs, also
    /// no spaces). A hardcoded English sentence always contains a space; a catalog key or arg name
    /// never does, so a `"..."` literal containing a space inside one of these four functions is
    /// exactly the defect dig_ecosystem#3253's correctness gate found.
    #[test]
    fn sentence_builders_carry_no_hardcoded_english_literal() {
        let src = include_str!("pane.rs");
        // (start marker, end marker) per builder -- explicit boundaries, not a generic "next fn"
        // scan, so the guard cannot accidentally swallow a later function or this test module's
        // own literals (which legitimately contain spaces, e.g. assertion messages).
        let bounds: [(&str, &str); 4] = [
            ("fn prover_status_sentence", "fn entry_set_sentence"),
            ("fn entry_set_sentence", "fn payout_sentence"),
            ("fn payout_sentence", "fn cadence_sentence"),
            ("fn cadence_sentence", "pub fn rewards_sections"),
        ];
        for (start_marker, end_marker) in bounds {
            let body = function_body(src, start_marker, end_marker);
            for literal in string_literals(body) {
                assert!(
                    !literal.contains(' '),
                    "{start_marker} contains a bare string literal with a space -- likely \
                     hardcoded English, not a catalog key: {literal:?}"
                );
            }
        }
    }

    // `function_body`/`string_literals` moved to `super::super::test_scan` (dig_ecosystem#3281):
    // `clawback`'s key-isolation guard needs the same string-literal extractor, and the plan calls
    // for reusing it rather than writing a second one. Imported at the top of this module.

    /// dig_ecosystem#3253's defect (1): the funder's distributor-wide TOTAL rendered as THIS
    /// operator's own earnings, up to 250x -- shipped through 11/11 green CI and security review,
    /// because no test in the repo asserted WHO a number was about. This is that test: the
    /// reserve sentence's subject must be the distributor's reserve, and it must be distinct from
    /// [`PAID_OUT_TOTAL`]'s distributor-paid-to-mirrors framing -- with the identical `N` under
    /// either subject, the two sentences must never read the same.
    #[test]
    fn the_reserve_row_is_about_the_distributor_not_this_operator() {
        let state = DistributorChainState {
            launcher_id: [0; 32],
            reserve_asset_id: dig_constants::DIG_ASSET_ID.to_bytes(),
            reserve_base_units: 1_500,
            entry_count: 0,
            current_distributor_epoch_start: 0,
            last_entry_write_at: None,
            observed_at: 99,
        };
        let reserve_text = reserve_sentence(&state);
        assert!(
            reserve_text.contains("distributor's reserve"),
            "reserve sentence must name the distributor as the subject: {reserve_text:?}"
        );
        assert!(
            reserve_text.contains("1.5"),
            "must carry the formatted amount: {reserve_text:?}"
        );

        // The identical base-unit amount, rendered through the distributor-paid-to-mirrors
        // sentence instead, MUST read differently -- proving the two subjects are not
        // interchangeable and a caller cannot silently swap one in for the other.
        let earnings_text = PAID_OUT_TOTAL.with(
            &Args::new()
                .text(
                    "amount",
                    amount_with_unit(Asset::DIG, state.reserve_base_units),
                )
                .text("last_cycle_completed_at", "99"),
        );
        assert_ne!(
            reserve_text, earnings_text,
            "the reserve figure and the paid-to-mirrors total must never render as the same \
             sentence for the same amount -- they are about different subjects"
        );
    }

    /// dig_ecosystem#3253 money rule: the reserve's `reserve_asset_id` is read from the chain, not
    /// assumed $DIG. A non-$DIG reserve must never print a $DIG figure -- the value can be exactly
    /// right and the asset subject exactly wrong, which this asserts against.
    #[test]
    fn a_non_dig_reserve_never_renders_a_dig_amount() {
        let mut not_dig_id = dig_constants::DIG_ASSET_ID.to_bytes();
        not_dig_id[0] ^= 0xFF; // flip off DIG_ASSET_ID -- same shape, different asset
        let state = DistributorChainState {
            launcher_id: [0; 32],
            reserve_asset_id: not_dig_id,
            reserve_base_units: 1_500,
            entry_count: 0,
            current_distributor_epoch_start: 0,
            last_entry_write_at: None,
            observed_at: 99,
        };
        let text = reserve_sentence(&state);
        assert!(
            !text.contains("1.5"),
            "a non-$DIG reserve must never print a $DIG figure: {text:?}"
        );
        assert!(
            text.contains("not $DIG") || text.contains("but it is not"),
            "must state the reserve is not $DIG, never stay silent about the mismatch: {text:?}"
        );
    }

    /// Finds the section whose heading is the cadence sentence, by IDENTITY rather than a
    /// fixed index: `expected` is reproduced through the same production path
    /// (`cadence_sentence` over `days_between_claims`) the caller used to build it. If a future
    /// section is inserted above cadence, this still finds the right one; if the cadence section
    /// is ever dropped or its wording changes underneath this test, it fails loudly instead of
    /// silently asserting about whatever heading happens to sit at a stale index
    /// (dig_ecosystem#3253 adversarial finding 3 — the original test read `low_rate[3]`, which is
    /// exactly the section index the production mount in `store_rewards.rs` drops).
    fn find_section_heading(sections: &[Section], expected: &str) -> String {
        sections
            .iter()
            .find_map(|section| {
                section
                    .heading
                    .clone()
                    .filter(|heading| heading == expected)
            })
            .unwrap_or_else(|| {
                panic!(
                    "no section heading matched the cadence sentence built by `cadence_sentence` \
                     (expected {expected:?}) -- the cadence section may have been dropped, \
                     reordered in a way that changed its content, or its wording changed"
                )
            })
    }

    /// dig_ecosystem#3253 defect (3)'s shape: a funding rate rendered at a mirror operator who is
    /// a PAYEE, not the funder who chose it. [`store_rewards.rs`]'s mount (read-only to this
    /// lane) correctly DROPS this section for exactly that reason -- this test pins that the
    /// cadence sentence itself is driven by the funder-supplied `daily_funding_base_units`
    /// argument, not by anything the viewer/mirror controls, so a caller that DOES address a
    /// funder (unlike the mirror-summary mount) renders a true, subject-correct sentence.
    #[test]
    fn the_funding_rate_sentence_is_about_the_funder_not_the_viewer() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 1;

        let low_rate = rewards_sections(&record, 0, 1_000);
        let high_rate = rewards_sections(&record, 0, 2_000);

        let expected_low = cadence_sentence(days_between_claims(Some(1), 1_000));
        let expected_high = cadence_sentence(days_between_claims(Some(1), 2_000));
        let low_heading = find_section_heading(&low_rate, &expected_low);
        let high_heading = find_section_heading(&high_rate, &expected_high);

        assert_ne!(
            low_heading, high_heading,
            "the cadence sentence must track the funder-supplied `daily_funding_base_units` \
             argument, not a fixed or viewer-derived value"
        );

        // English-only negative, scoped explicitly rather than routed through a copy constant:
        // `Msg`/`Args` render whatever prose a locale's catalog entry contains, and "does this
        // wording address the reader as the payee" is a property of the `en` catalog entry's
        // TEXT, not a structural property every locale can be checked for from Rust. These tests
        // render in the ambient default language (never set here), which is `en` -- the same
        // assumption `never_ran_prover_names_itself_in_the_first_section` above already makes
        // against `STATUS_NEVER_RAN.text()`. A per-locale sweep for this phrase is a copy-review
        // concern, tracked separately, not this test's job.
        for heading in [&low_heading, &high_heading] {
            assert!(
                !heading.to_lowercase().contains("you earn") && !heading.contains("your earnings"),
                "cadence sentence must never address the reader as though they are the payee \
                 earning the rate (en): {heading:?}"
            );
        }
    }
}

/// Evidence that a caller supplied exactly the five required warning-block keys to
/// [`Self::having_displayed`] -- the only function that can hand one out. Zero-sized and privately
/// constructed everywhere else.
///
/// # What this does NOT prove (finding 4)
///
/// [`REQUIRED_WARNING_KEYS`] is `pub`, so `WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS)`
/// is callable from anywhere with no paint step behind it -- an earlier revision of this doc
/// comment claimed "only the paint code that actually rendered them can produce a witness", which
/// is false as written: nothing here inspects what was actually displayed on screen. What this
/// type DOES prove is narrower but still real: the caller named the exact five required keys, no
/// fewer and no extra (see [`Self::having_displayed`]) -- so [`CreationGate::acknowledge`] cannot
/// be reached by a bare no-argument call or a partial/wrong-named list, which is the one-line forge
/// the removed `Copy` derive allowed (this type is no longer `Copy`, so a caller cannot mint a
/// second witness from a first without calling [`Self::having_displayed`] again). Wiring this to
/// genuine display provenance is deferred to the commit that paints the five blocks; see this
/// module's parent [`crate::rewards`] doc comment for why no creation-flow paint code ships yet.
#[derive(Debug, PartialEq, Eq)]
pub struct WarningsShown(());

/// The five warning-block copy keys DECISIONS-3253 Q1 requires shown before acknowledgement
/// (`super::copy::WARNING_BLOCK_1` through `_5`), spelled out as their fluent keys so this module
/// does not have to depend on `copy` for five string literals. Ratified; unchanged by this fix —
/// no `.ftl` file or warning-block string is touched.
pub const REQUIRED_WARNING_KEYS: [&str; 5] = [
    "rewards-warning-block-1",
    "rewards-warning-block-2",
    "rewards-warning-block-3",
    "rewards-warning-block-4",
    "rewards-warning-block-5",
];

impl WarningsShown {
    /// The ONLY constructor. Answers the witness when `displayed_keys` is exactly the five
    /// required keys — any order, no fewer, no extra — never for a caller merely asserting intent.
    pub fn having_displayed(displayed_keys: &[&str]) -> Option<Self> {
        let required: std::collections::HashSet<&str> = REQUIRED_WARNING_KEYS.into_iter().collect();
        let displayed: std::collections::HashSet<&str> = displayed_keys.iter().copied().collect();
        (required == displayed).then_some(Self(()))
    }
}

/// The creation flow's gate (DECISIONS-3253 Q1): the five warning blocks plus heading and closing
/// line MUST be shown, and a person must explicitly acknowledge them, before a create affordance
/// is reachable. This type exists so that invariant is enforced by the compiler rather than by a
/// paint-order convention: there is no constructor that hands out an already-acknowledged gate, and
/// [`Acknowledged::may_create`] is the ONLY function that can say yes.
///
/// # Why this is not `Copy`/`Clone`
///
/// A gate that could be copied would let a caller hold a `CreationGate` value AND its acknowledged
/// result from the same call — `let a = g.acknowledge(); g.may_create()` — which falsifies the
/// "consumes `self`" invariant this doc comment states, in the very commit that writes it (finding
/// 6). `acknowledge` therefore takes `self` by value with no `Copy` escape hatch, and returns a
/// DIFFERENT type, [`Acknowledged`], so a caller can never hold both handles to one flow.
///
/// This does not decide WHERE the warning is painted or wire a create RPC — no create/mint
/// affordance ships in this pass (see this module's parent [`crate::rewards`] doc comment). It is
/// the state machine the eventual creation-flow paint code must hold, written now so that code has
/// nowhere honest to skip the gate when it lands.
#[derive(Debug, PartialEq, Eq)]
pub struct CreationGate {
    acknowledged: bool,
}

/// The result of [`CreationGate::acknowledge`] — a value that could only have been produced by
/// consuming an unacknowledged gate together with a [`WarningsShown`] witness. `may_create` lives
/// ONLY here, never on [`CreationGate`], so there is no path to "may create" that skipped both.
#[derive(Debug, PartialEq, Eq)]
pub struct Acknowledged;

impl CreationGate {
    /// A freshly opened creation flow. The warning has not yet been acknowledged.
    pub fn unacknowledged() -> Self {
        Self {
            acknowledged: false,
        }
    }

    /// The person clicked past every warning block, evidenced by `shown`. Consumes `self` and
    /// returns [`Acknowledged`] — a caller cannot hold both an acknowledged and an unacknowledged
    /// handle to the same flow from one value, because there is no way to get `self` back.
    pub fn acknowledge(self, _shown: WarningsShown) -> Acknowledged {
        Acknowledged
    }
}

impl Acknowledged {
    /// Whether a create affordance may be shown. Always `true` — the only way to construct this
    /// type at all is through [`CreationGate::acknowledge`], which demands a [`WarningsShown`]
    /// witness.
    pub fn may_create(&self) -> bool {
        true
    }
}

impl Default for CreationGate {
    /// Same as [`Self::unacknowledged`] — the only state a creation flow may start in.
    fn default() -> Self {
        Self::unacknowledged()
    }
}

#[cfg(test)]
mod creation_gate_tests {
    use super::*;

    /// A freshly opened flow has no `may_create` at all -- the method exists only on
    /// [`Acknowledged`], which an unacknowledged [`CreationGate`] cannot produce.
    #[test]
    fn fresh_gate_has_no_create_affordance() {
        let gate = CreationGate::unacknowledged();
        assert!(!gate.acknowledged);
        let default_gate = CreationGate::default();
        assert!(!default_gate.acknowledged);
    }

    /// Acknowledging with all five required keys is the ONLY way to reach `may_create() == true`.
    #[test]
    fn acknowledging_with_all_five_keys_unlocks_create() {
        let shown = WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS)
            .expect("all five required keys shown");
        let acknowledged = CreationGate::unacknowledged().acknowledge(shown);
        assert!(acknowledged.may_create());
    }

    /// Fewer than five shown keys, or an unrelated key, never produces a witness -- there is no
    /// forge path via a partial or wrong-named list.
    #[test]
    fn a_partial_or_wrong_key_list_produces_no_witness() {
        assert!(WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS[..4]).is_none());
        assert!(WarningsShown::having_displayed(&[
            "rewards-warning-block-1",
            "rewards-warning-block-2",
            "rewards-warning-block-3",
            "rewards-warning-block-4",
            "rewards-warning-heading", // wrong fifth key
        ])
        .is_none());
    }

    /// One chained expression can no longer satisfy the gate: `acknowledge` now requires a
    /// [`WarningsShown`] argument that only [`WarningsShown::having_displayed`] can produce, so a
    /// caller has to first name the five keys it painted -- the exact forge the removed `Copy`
    /// derive allowed in one line.
    #[test]
    fn acknowledge_requires_a_warnings_shown_argument_not_a_bare_call() {
        let shown = WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS).unwrap();
        let _acknowledged: Acknowledged = CreationGate::unacknowledged().acknowledge(shown);
        // `CreationGate::unacknowledged().acknowledge()` -- zero arguments -- does not compile;
        // that is the property this test exists to hold, checked at compile time rather than by
        // an assertion this comment records instead.
    }
}
