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

use crate::amount::amount_with_unit;
use crate::i18n::Args;
use crate::wallet::state::Asset;
use crate::window_model::{PaneNote, Section};

use super::cadence::{days_between_claims, CadenceReading};
use super::copy::{
    CADENCE_FAR_END, CADENCE_NO_FUNDING_RATE, CADENCE_NO_MIRRORS_YET, CADENCE_SUB_DAY_FLOOR,
    ENTRY_SET_EMPTY, ENTRY_SET_KNOWN, PAID_OUT_NOTHING_YET, PAID_OUT_TOTAL, REFILL_CADENCE,
    STATUS_CLOCK_UNUSABLE, STATUS_CYCLE_OVERDUE, STATUS_ENTRY_COUNT_UNKNOWN, STATUS_HEARTBEAT_LATE,
    STATUS_HEARTBEAT_LOST, STATUS_LIVE, STATUS_NEVER_RAN, STATUS_NOT_DISTRIBUTING,
};
use super::humanize;
use super::mint::DistributorMintAvailability;
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
            // Routed through `super::humanize` (dig_ecosystem#3297): a raw unix-second integer
            // here read as an epoch dump, not a fact a viewer could act on. `duration` is a bare
            // span (the sentence supplies its own "for"); `observed_at_date` is a past instant.
            let duration_seconds = now.saturating_sub(record.observed_at);
            STATUS_HEARTBEAT_LOST.with(
                &Args::new()
                    .text("duration", humanize::span(duration_seconds))
                    .text("observed_at_date", humanize::ago(now, record.observed_at)),
            )
        }
        ProverReading::CycleOverdue => {
            // `since_date` falls back to `prover_state_since` (always present) when no cycle has
            // ever completed yet -- CycleOverdue is reachable with `last_cycle_completed_at ==
            // None` (checked before `NeverRan` in `reading::prover_reading`). Both placeables are
            // past instants, routed through `super::humanize::ago` (dig_ecosystem#3297).
            let since = record
                .last_cycle_completed_at
                .unwrap_or(record.prover_state_since);
            let due = record.next_cycle_due_at.unwrap_or(now);
            STATUS_CYCLE_OVERDUE.with(
                &Args::new()
                    .text("since_date", humanize::ago(now, since))
                    .text("due_date", humanize::ago(now, due)),
            )
        }
        ProverReading::NeverRan => STATUS_NEVER_RAN.text(),
    }
}

/// One fact sentence for the entry set (SPEC §2.4 clause 3): a count is never said without the
/// write time that makes it current, per [`EntrySetReading`]'s non-splittable shape. Routed
/// through [`super::copy`], same fix as [`prover_status_sentence`]. Takes `now` so
/// `last_entry_write_at` renders as a relative phrase (`super::humanize::ago`,
/// dig_ecosystem#3297) instead of a raw unix-second integer.
fn entry_set_sentence(reading: EntrySetReading, now: u64) -> String {
    match reading {
        EntrySetReading::Empty => ENTRY_SET_EMPTY.text(),
        EntrySetReading::Known {
            entry_count,
            last_entry_write_at,
        } => ENTRY_SET_KNOWN.with(
            &Args::new()
                .text("entry_count", entry_count.to_string())
                .text(
                    "last_entry_write_at",
                    humanize::ago(now, last_entry_write_at),
                ),
        ),
    }
}

/// One fact sentence for the payout total (SPEC §2.4 clause 2), money rendered ONLY through
/// [`amount_with_unit`] -- never a raw base-unit integer, never a hand-written `"$DIG"` re-deriving
/// the ticker [`amount_with_unit`] already carries (finding 7: the two must never disagree). Routed
/// through [`super::copy`], same fix as [`prover_status_sentence`]. Takes `now` so
/// `last_cycle_completed_at` renders relatively (`super::humanize::ago`, dig_ecosystem#3297).
fn payout_sentence(reading: PayoutReading, now: u64) -> String {
    match reading {
        PayoutReading::NeverRan => PAID_OUT_NOTHING_YET.text(),
        PayoutReading::Paid {
            total_paid_out_base_units,
            last_cycle_completed_at,
        } => {
            let amount = amount_with_unit(Asset::DIG, total_paid_out_base_units);
            PAID_OUT_TOTAL.with(&Args::new().text("amount", amount).text(
                "last_cycle_completed_at",
                humanize::ago(now, last_cycle_completed_at),
            ))
        }
    }
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
/// `EntrySetReading::Empty`) and the ordinary [`CadenceReading::Days`] case reuses
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

/// Builds the Rewards section's facts from an answered record (SPEC §2.3/§2.4), against the
/// caller's own clock. Two or three sections -- prover status and entry set always, payout total
/// only when [`EntrySetReading::Empty`] is not the entry-set reading -- and NEVER a funding rate:
/// this function cannot invent a number a caller has not chosen (dig_ecosystem#3301), so it takes
/// none. A caller who DOES have a chosen funding rate to show beside a cadence fact adds
/// [`cadence_section`] itself; seeing that call site is how a reviewer tells the two facts'
/// preconditions apart.
///
/// # The payout section is DROPPED, not fabricated, when the entry set is empty
///
/// A distributor only ever pays entry holders. `total_paid_out_base_units` and
/// `last_cycle_completed_at` are read from a DIFFERENT part of the record than
/// [`entry_set_reading`] collapses (dig_ecosystem#3300's fix lives in `reading.rs`, not here) --
/// so a record with `EntrySetReading::Empty` can still carry a nonzero historical payout total
/// from before every entry was evicted. Rendering "paid out N $DIG" beside "no mirror is currently
/// earning" is producible ONLY by that evicted history, which is the exact forbidden inference
/// #3300 closes for the entry-set sentence itself, reopened one section later through the payout
/// sentence instead (loop-security adversarial finding on PR #410, `ba3238cf`). The fix is
/// subtractive, the same law this epic keeps proving: when the entry set is empty, the payout
/// section is not rendered at all, regardless of what `counters.total_paid_out_base_units` or
/// `last_cycle_completed_at` say -- there is no wording of that section that does not leak the
/// history, so it is dropped rather than reworded.
///
/// # Why every [`Section`] here has empty `rows`
///
/// The create affordance this crate ships is painted by `store_rewards`'s own create card, not by
/// a row of these sections, and no refill or clawback affordance ships at all (see this module's
/// parent [`crate::rewards`] doc comment for exactly why) -- so there is nothing for a row to DO. A
/// `Section` may carry its fact in the heading alone with empty rows, which is the same shape
/// [`crate::rewards::tab_placement`]'s `activity_tab_emits_zero_action_rows` guard checks for the
/// mirror-claim record; this function is deliberately built to the same shape from day one so wiring
/// it in later cannot regress that guard.
pub fn rewards_sections(record: &RewardDistributorStatusRecord, now: u64) -> Vec<Section> {
    let prover = prover_status_sentence(prover_reading(record, now), record, now);
    let entry_set_reading_value = entry_set_reading(record);
    let entries = entry_set_sentence(entry_set_reading_value, now);

    let mut headings = vec![prover, entries];
    if entry_set_reading_value != EntrySetReading::Empty {
        headings.push(payout_sentence(payout_reading(record), now));
    }

    headings
        .into_iter()
        .map(|heading| Section {
            heading: Some(heading),
            rows: Vec::new(),
        })
        .collect()
}

/// The entry count a cadence fact may honestly be computed from, derived from the SAME
/// [`EntrySetReading`] the entry-set sentence itself renders (dig_ecosystem#3300) -- never
/// `record.counters.entry_count` read a second time independently. That is not a style
/// preference: [`EntrySetReading::Empty`] now covers both "never written" and "known,
/// genuinely zero, after a real write" (see that variant's doc), and a cadence input that
/// re-derived the zero straight from the counters would re-open exactly the pair #3300 closes,
/// on any surface that renders both this and the entry-set sentence together. So `Empty` maps to
/// `None` (unknown) here unconditionally -- the same answer for both histories -- and `Known`
/// carries its count through unchanged.
pub fn entry_count_for_cadence(reading: EntrySetReading) -> Option<u32> {
    match reading {
        EntrySetReading::Empty => None,
        EntrySetReading::Known { entry_count, .. } => Some(entry_count),
    }
}

/// One `Section` for the claim cadence at a chosen funding rate (SPEC §6.5.1) -- separated from
/// [`rewards_sections`] because this fact's precondition is different from the other three: it
/// needs a funding rate a caller CHOSE, and [`rewards_sections`] itself never receives one
/// (dig_ecosystem#3301). `entry_count` should come from [`entry_count_for_cadence`] over the same
/// [`EntrySetReading`] the caller's entry-set sentence used, for the reason that function's own
/// doc names.
///
/// # Currently unmounted
///
/// No caller wires this into a screen yet, the same way [`super::pane::WarningsShown`] and
/// [`CreationGate`] below ship ahead of their paint code: no funding-rate-setting affordance
/// exists anywhere in this app today (see
/// `crate::confirm::gui::window::pane::store_rewards`'s module doc, which mounts the OTHER
/// three sections instead, for exactly the mirror-operator's-eye-view reason this fact does not
/// belong there). `pub fn` so it is not itself flagged unreachable-from-production by the
/// compiler's dead-code lint; every catalog key its body names is exercised by this crate's own
/// `sentence_builders_carry_no_hardcoded_english_literal`/reachability guards regardless of
/// whether a screen calls it yet.
pub fn cadence_section(entry_count: Option<u32>, daily_funding_base_units: u64) -> Section {
    let cadence = cadence_sentence(days_between_claims(entry_count, daily_funding_base_units));
    Section {
        heading: Some(cadence),
        rows: Vec::new(),
    }
}

#[cfg(test)]
mod rewards_sections_tests {
    use super::*;
    use crate::rewards::test_scan::{function_body, longest_ascii_digit_run, string_literals};
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

    /// dig_ecosystem#3300, proof 2 (the SET-level one): the FULL rendered `Vec<Section>` -- every
    /// heading, not just the entry-set one -- is byte-identical between a record that never wrote
    /// an entry and one that wrote entries and was evicted back to zero. Proof 1
    /// ([`super::reading`]'s `never_written_and_evicted_to_zero_are_the_same_reading`) shows the
    /// two `EntrySetReading`s are equal; this shows that equality actually reaches every sentence
    /// a viewer would see, over the real render path, not merely the one field.
    ///
    /// # A MATRIX of `counters`, not one default pair (loop-security adversarial finding, PR #410)
    ///
    /// An earlier version of this test left `counters` at `RewardCounters::default()` on both
    /// records, which cannot reach the state where dig_ecosystem#3300's leak actually lived:
    /// `total_paid_out_base_units` and `last_cycle_completed_at` are read by [`payout_sentence`]
    /// from a part of the record [`entry_set_reading`] never touches, so a record with an empty
    /// entry set can still carry a nonzero historical payout. Rendering that payout beside "no
    /// mirror is currently earning" would reopen the exact never-admitted-vs-evicted inference
    /// this test exists to close, one section later than the entry-set sentence itself. Asserted
    /// here over every combination of a zero/nonzero payout total and a `None`/`Some` completed-
    /// cycle time, and -- the part that actually exercises the fix -- the two histories are given
    /// DIFFERENT payout states from each other in every pairing, not the same one copied onto
    /// both. Two records with equal payout counters would render identically whether or not the
    /// leak is closed, which is why an earlier version of this test could pass while blind: it
    /// never gave the two histories anything to disagree about.
    #[test]
    fn never_written_and_evicted_to_zero_render_the_identical_section_set() {
        let payout_states: [(u64, Option<u64>); 4] =
            [(0, None), (0, Some(50)), (12_500, None), (12_500, Some(50))];

        for never_written_payout in payout_states {
            for evicted_payout in payout_states {
                let (nw_total, nw_completed_at) = never_written_payout;
                let mut never_written = base_record();
                never_written.counters.total_paid_out_base_units = nw_total;
                never_written.last_cycle_completed_at = nw_completed_at;

                let (ev_total, ev_completed_at) = evicted_payout;
                let mut evicted_to_zero = base_record();
                evicted_to_zero.last_entry_write_at = Some(500);
                evicted_to_zero.counters.entry_count = 0;
                evicted_to_zero.counters.total_paid_out_base_units = ev_total;
                evicted_to_zero.last_cycle_completed_at = ev_completed_at;

                assert_eq!(
                    rewards_sections(&never_written, 1_000),
                    rewards_sections(&evicted_to_zero, 1_000),
                    "never-written payout state {never_written_payout:?} and evicted-to-zero \
                     payout state {evicted_payout:?} must render byte-identical section sets -- \
                     any difference would let a viewer infer which history occurred, which SPEC \
                     §12.5 clause 7 forbids"
                );
            }
        }
    }

    /// dig_ecosystem#3297's acceptance bar, proved over the REAL render path rather than over
    /// [`humanize`]'s own output.
    ///
    /// `humanize::tests::no_output_contains_an_epoch_shaped_digit_run` only calls `ago`/`until`
    /// directly and checks what they themselves return -- it cannot catch a call site that forgot
    /// to route through `humanize` at all. This test closes that gap for [`rewards_sections`]
    /// SPECIFICALLY (an earlier revision of this doc comment claimed it covered "anything
    /// `pane.rs` or `clawback.rs` actually renders", which was false the moment it was written --
    /// this test never calls anything in `clawback.rs`; that module's own rendered sentences are
    /// covered by `clawback::tests::no_rendered_clawback_sentence_contains_an_undocumented_epoch_shaped_digit_run`
    /// instead, so the two guards together, not either alone, are the complete enumeration). It
    /// builds two records with epoch-shaped (10-digit) timestamps on every placeable
    /// dig_ecosystem#3297 named -- `observed_at` (stale enough for `HeartbeatLost`),
    /// `last_entry_write_at`, `last_cycle_completed_at` on the first; `observed_at` (heartbeat
    /// LIVE), `last_cycle_completed_at`, `next_cycle_due_at` (overdue) on the second, so
    /// `prover_reading` classifies it `CycleOverdue` and `STATUS_CYCLE_OVERDUE`'s `since_date`/
    /// `due_date` placeables actually get scanned -- neither the `HeartbeatLost` record above nor
    /// `humanize::tests::no_output_contains_an_epoch_shaped_digit_run` reaches that branch (see
    /// `cycle_overdue_reads_the_real_fields_when_present_not_only_the_fallback`'s doc for the
    /// fixture bug this closes). Both records call the real [`rewards_sections`] entry point and
    /// scan the RESULTING STRINGS for a 9-11 digit run. Building the record is the only place this
    /// test touches a raw integer; the assertion never constructs its own expectation through
    /// `humanize`, so a future call site that reverted to `.to_string()` on a raw timestamp would
    /// be caught here even if `humanize` itself stayed perfectly correct.
    #[test]
    fn no_rendered_reward_sentence_contains_an_epoch_shaped_digit_run() {
        const NOW: u64 = 1_700_000_000; // 10 digits -- itself epoch-shaped, never rendered raw

        let assert_no_epoch_shaped_heading = |sections: &[Section]| {
            for section in sections {
                let heading = section.heading.as_deref().unwrap_or_default();
                if let Some(run) = longest_ascii_digit_run(heading) {
                    assert!(
                        !(9..=11).contains(&run),
                        "heading contains a {run}-digit run, which reads as a raw epoch second: \
                         {heading:?}"
                    );
                }
            }
        };

        let mut heartbeat_lost = base_record();
        heartbeat_lost.observed_at = NOW - 1_000; // stale past PROVER_CYCLE_DEADLINE_SECONDS -> HeartbeatLost
        heartbeat_lost.last_entry_write_at = Some(NOW - 500);
        heartbeat_lost.counters.entry_count = 5;
        heartbeat_lost.last_cycle_completed_at = Some(NOW - 200);
        heartbeat_lost.counters.total_paid_out_base_units = 12_500;
        assert_no_epoch_shaped_heading(&rewards_sections(&heartbeat_lost, NOW));

        let mut cycle_overdue = base_record();
        cycle_overdue.observed_at = NOW - 50; // heartbeat live
        cycle_overdue.last_entry_write_at = Some(NOW - 500);
        cycle_overdue.counters.entry_count = 5;
        cycle_overdue.last_cycle_completed_at = Some(NOW - 200);
        cycle_overdue.next_cycle_due_at = Some(NOW - 1_000); // overdue -> CycleOverdue
        cycle_overdue.counters.total_paid_out_base_units = 12_500;
        assert_eq!(
            prover_reading(&cycle_overdue, NOW),
            ProverReading::CycleOverdue,
            "fixture must actually reach CycleOverdue for this scan to cover since_date/due_date"
        );
        assert_no_epoch_shaped_heading(&rewards_sections(&cycle_overdue, NOW));
    }

    /// Three facts -- prover, entry set, payout -- every heading carrying its own sentence and no
    /// rows (dig_ecosystem#3301: cadence is no longer one of them; it moved to
    /// [`cadence_section`], which takes its funding rate honestly instead of `rewards_sections`
    /// inventing one). The zero-action-row half of the old four-section guard survives unchanged.
    #[test]
    fn answers_exactly_three_sections_with_no_rows() {
        // A nonempty entry set is required for the payout section to render at all (this
        // module's own "payout section is DROPPED, not fabricated, when the entry set is empty"
        // rule) -- `base_record()` alone would now answer only two sections.
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 1;
        let sections = rewards_sections(&record, 0);
        assert_eq!(
            sections.len(),
            3,
            "expected prover, entry set, payout -- no cadence"
        );
        for section in &sections {
            assert!(
                section.heading.is_some(),
                "every section states its fact in the heading"
            );
            assert!(section.rows.is_empty(), "no affordance ships in this pass");
        }
    }

    /// The subtractive half of the payout-leak fix (loop-security adversarial finding, PR #410):
    /// an empty entry set renders only prover status and entry set, never a payout section, even
    /// when `counters.total_paid_out_base_units` is nonzero -- there is no wording of "paid out N
    /// $DIG" beside "no mirror is currently earning" that does not leak the evicted history, so
    /// the section is dropped rather than reworded.
    #[test]
    fn empty_entry_set_answers_only_two_sections_even_with_a_nonzero_historical_payout() {
        let mut record = base_record();
        record.counters.total_paid_out_base_units = 12_500;
        record.last_cycle_completed_at = Some(50);
        let sections = rewards_sections(&record, 1_000);
        assert_eq!(
            sections.len(),
            2,
            "expected prover and entry set only -- payout must be dropped, not rendered, when \
             the entry set is empty"
        );
    }

    /// A record whose prover has never completed a cycle says so in plain language, never a
    /// health boolean rendered as a word -- rendered through [`STATUS_NEVER_RAN`], never a Rust
    /// string literal, so this asserts the catalog resolution, not a copy of it.
    #[test]
    fn never_ran_prover_names_itself_in_the_first_section() {
        let record = base_record();
        let sections = rewards_sections(&record, 0);
        assert_eq!(
            sections[0].heading.as_deref(),
            Some(STATUS_NEVER_RAN.text().as_str())
        );
    }

    /// A completed payout renders through `format_asset_amount`, never a raw base-unit integer:
    /// 1_500 base units of $DIG is "1.5", not "1500".
    #[test]
    fn a_completed_payout_is_money_formatted_not_a_raw_integer() {
        // A nonempty entry set is required for the payout section to render at all -- see
        // `empty_entry_set_answers_only_two_sections_even_with_a_nonzero_historical_payout`.
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 1;
        record.last_cycle_completed_at = Some(42);
        record.counters.total_paid_out_base_units = 1_500;
        let sections = rewards_sections(&record, 0);
        let payout_heading = sections[2].heading.as_deref().unwrap();
        assert!(
            payout_heading.contains("1.5 $DIG"),
            "expected money-formatted amount, got: {payout_heading}"
        );
        assert!(!payout_heading.contains("1500"));
    }

    /// A never-written entry set (`last_entry_write_at: None`) has NO known count -- the cadence
    /// sentence must say the mirror set is unknown, never "no mirror is claiming", because the
    /// wire never asserted that (SPEC §2.4 clause 3, §12.5 clause 6). Routed through
    /// [`entry_set_reading`]/[`entry_count_for_cadence`]/[`cadence_section`] directly, now that
    /// `rewards_sections` no longer carries a funding rate at all (dig_ecosystem#3301).
    #[test]
    fn never_written_entry_set_cadence_is_entry_count_unknown_not_a_reassuring_zero() {
        let record = base_record();
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));
        let cadence_heading = cadence_section(entry_count, 1_000).heading.unwrap();
        assert_eq!(cadence_heading, STATUS_ENTRY_COUNT_UNKNOWN.text());
    }

    /// dig_ecosystem#3300: a GENUINELY known zero entry count (post-eviction, or never admitted,
    /// but with a real write timestamp) is now the SAME reading as never-written --
    /// [`EntrySetReading::Empty`] carries no count and no time for either history, so it feeds
    /// [`entry_count_for_cadence`] the identical `None` and produces the identical cadence
    /// sentence as the never-written case above. This replaces the old test that asserted these
    /// two histories rendered DIFFERENT sentences (`CADENCE_NO_MIRRORS_YET`), which is exactly
    /// the forbidden never-admitted-vs-evicted inference SPEC §12.5 clause 7 bans.
    #[test]
    fn known_zero_entry_count_cadence_collapses_into_entry_count_unknown() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 0;
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));
        let cadence_heading = cadence_section(entry_count, 1_000).heading.unwrap();
        assert_eq!(cadence_heading, STATUS_ENTRY_COUNT_UNKNOWN.text());
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
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));
        let cadence_heading = cadence_section(entry_count, 0).heading.unwrap();
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
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));

        // One mirror at 100_000 base units/day computes to 0.01 days -- deep under the floor.
        let cadence_heading = cadence_section(entry_count, 100_000).heading.unwrap();
        assert!(
            !cadence_heading.contains("0.0"),
            "sub-day cadence printed a reassuring 0.0: {cadence_heading}"
        );
        assert_eq!(cadence_heading, CADENCE_SUB_DAY_FLOOR.text());

        // Exactly at the one-day boundary (1_000 base units/day, one mirror) is NOT clamped --
        // it renders the ordinary numeric sentence, through `REFILL_CADENCE`.
        let boundary_heading = cadence_section(entry_count, 1_000).heading.unwrap();
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
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));
        let cadence_heading = cadence_section(entry_count, 1).heading.unwrap();
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
                    .text("duration", humanize::span(900))
                    .text("observed_at_date", humanize::ago(900, record.observed_at))
            )
        );
        assert_eq!(
            prover_status_sentence(ProverReading::CycleOverdue, &record, 1_000),
            STATUS_CYCLE_OVERDUE.with(
                &Args::new()
                    .text("since_date", humanize::ago(1_000, 0))
                    .text("due_date", humanize::ago(1_000, 1_000))
            )
        );
    }

    /// dig_ecosystem#3297: the CycleOverdue case above never exercises the branch
    /// `prover_status_sentence`'s own doc comment names -- `base_record()` leaves
    /// `last_cycle_completed_at` and `next_cycle_due_at` both `None`, so `since_date` and
    /// `due_date` there are ALWAYS the fallback values (`prover_state_since` and `now`), never the
    /// real fields the comment says they read when a cycle HAS completed and a due time IS set.
    /// This fixture sets both, so `since_date` must read `last_cycle_completed_at` (not
    /// `prover_state_since`) and `due_date` must read the actual overdue `next_cycle_due_at` (not
    /// `now`) -- proving the non-fallback path, not just the fallback one.
    ///
    /// An earlier revision of this fixture hand-supplied `ProverReading::CycleOverdue` to
    /// `prover_status_sentence` while leaving `record.observed_at` at `base_record()`'s default of
    /// `0` -- with `now = 1_000`, `age = 1_000 > PROVER_CYCLE_DEADLINE_SECONDS` (900), so
    /// `reading::prover_reading` would actually classify that record `HeartbeatLost`, never
    /// `CycleOverdue`. The hand-supplied reading made the assertion pass without ever proving a
    /// real record reaches this branch. Setting `observed_at = now - 50` (heartbeat live) and
    /// deriving the reading through `prover_reading` closes that gap -- the `assert_eq!` right
    /// below is not decorative, it is the proof this fixture is reachable at all.
    #[test]
    fn cycle_overdue_reads_the_real_fields_when_present_not_only_the_fallback() {
        let mut record = base_record();
        record.prover_state_since = 0;
        record.observed_at = 950;
        record.last_cycle_completed_at = Some(200);
        record.next_cycle_due_at = Some(400);
        let now = 1_000;
        assert_eq!(
            prover_reading(&record, now),
            ProverReading::CycleOverdue,
            "fixture must actually reach CycleOverdue, not merely assert rendering for it"
        );
        assert_eq!(
            prover_status_sentence(prover_reading(&record, now), &record, now),
            STATUS_CYCLE_OVERDUE.with(
                &Args::new()
                    .text("since_date", humanize::ago(now, 200))
                    .text("due_date", humanize::ago(now, 400))
            )
        );
    }

    /// Every [`EntrySetReading`] variant renders through its catalog key.
    #[test]
    fn every_entry_set_reading_resolves_through_the_catalog() {
        assert_eq!(
            entry_set_sentence(EntrySetReading::Empty, 0),
            ENTRY_SET_EMPTY.text()
        );
        assert_eq!(
            entry_set_sentence(
                EntrySetReading::Known {
                    entry_count: 3,
                    last_entry_write_at: 500,
                },
                1_000,
            ),
            ENTRY_SET_KNOWN.with(
                &Args::new()
                    .text("entry_count", "3")
                    .text("last_entry_write_at", humanize::ago(1_000, 500))
            )
        );
    }

    /// Every [`PayoutReading`] variant renders through its catalog key.
    #[test]
    fn every_payout_reading_resolves_through_the_catalog() {
        assert_eq!(
            payout_sentence(PayoutReading::NeverRan, 0),
            PAID_OUT_NOTHING_YET.text()
        );
        assert_eq!(
            payout_sentence(
                PayoutReading::Paid {
                    total_paid_out_base_units: 1_500,
                    last_cycle_completed_at: 42,
                },
                1_000,
            ),
            PAID_OUT_TOTAL.with(
                &Args::new()
                    .text("amount", amount_with_unit(Asset::DIG, 1_500))
                    .text("last_cycle_completed_at", humanize::ago(1_000, 42))
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

    /// dig_ecosystem#3253 defect (3)'s shape: a funding rate rendered at a mirror operator who is
    /// a PAYEE, not the funder who chose it. [`store_rewards.rs`]'s mount (read-only to this
    /// lane) correctly never calls [`cadence_section`] at all for exactly that reason
    /// (dig_ecosystem#3301: `rewards_sections` itself now structurally cannot produce this
    /// section) -- this test pins that the cadence sentence itself is driven by the
    /// funder-supplied `daily_funding_base_units` argument, not by anything the viewer/mirror
    /// controls, so a caller that DOES address a funder renders a true, subject-correct sentence.
    #[test]
    fn the_funding_rate_sentence_is_about_the_funder_not_the_viewer() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 1;
        let entry_count = entry_count_for_cadence(entry_set_reading(&record));

        let low_heading = cadence_section(entry_count, 1_000).heading.unwrap();
        let high_heading = cadence_section(entry_count, 2_000).heading.unwrap();

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
/// second witness from a first without calling [`Self::having_displayed`] again).
///
/// Display provenance is now supplied by the CALLER rather than by this type: the create card's
/// warnings step collects its key slice AS each block is placed and hands the witness it gets
/// straight to `create_card::record_acknowledgement`, which stores it by value. No production
/// code calls `having_displayed(&REQUIRED_WARNING_KEYS)` -- asserted by
/// `create_card`'s `the_warning_witness_is_never_minted_from_the_constant`.
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
/// This type does not decide WHERE the warning is painted. The paint that walks it is
/// `store_rewards`'s create card, which holds the resulting [`Acknowledged`] by value in
/// `create_card`'s per-store witness slot until the submit consumes it — so the card has nowhere
/// honest to skip the gate.
#[derive(Debug, PartialEq, Eq)]
pub struct CreationGate {
    acknowledged: bool,
}

/// The result of [`CreationGate::acknowledge`] — a value that could only have been produced by
/// consuming an unacknowledged gate together with a [`WarningsShown`] witness. `may_create` lives
/// ONLY here, never on [`CreationGate`], so there is no path to "may create" that skipped both.
///
/// The field is private for the same reason [`WarningsShown`]'s is: a public unit struct with no
/// field (`pub struct Acknowledged;`) is constructible from ANY module, including outside this
/// crate, since `Self { }`/the bare path expression typechecks with no witness at all -- that
/// defect shipped in an earlier revision of this pass and was caught by adversarial review of
/// `create.rs`'s "untypeable without both witnesses" claim before it reached `main`. With a
/// private field, [`CreationGate::acknowledge`] is the only constructor this crate has.
#[derive(Debug, PartialEq, Eq)]
pub struct Acknowledged(());

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
        Acknowledged(())
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

/// The sentences the create card paints when a reward distributor cannot be minted right now.
///
/// Each one names the half that is actually missing, promises no date and offers no control, the
/// way [`crate::account::journey`]'s DID explainer writes the same shape of refusal
/// (`EXPLAINER_NO_CONTROL_YET`): a refusal that hints at an upgrade is a dead end, and a refusal
/// that calls anything safe or recoverable is the provenance lie `super::create`'s copy rules
/// forbid.
///
/// Plain `&'static str`s rather than [`crate::i18n::Msg`] keys, as the previous single sentence
/// was: these are the CREATE card's refusals, and the card's own user-facing copy -- warnings,
/// manager choice, coin picker, terms, submitted state -- is what ships as localized keys with the
/// wiring that makes it reachable.
pub mod create_unavailable {
    /// The account is locked, so no minter exists. Says what to do without claiming what will
    /// happen after: unlocking produces a minter, not necessarily a possible mint -- the money
    /// gates still run at the door.
    pub const LOCKED: &str = concat!(
        "This account is locked, so nothing here can sign a launch. Unlock it to see whether a ",
        "reward distributor can be created.",
    );
    /// The chain answers, and cannot walk a singleton lineage.
    pub const NO_LINEAGE_WALK: &str = concat!(
        "This node answers ordinary reads but cannot follow a singleton's history, so a launch ",
        "signed here could not be confirmed. Nothing has been signed and nothing will be spent.",
    );
    /// The chain could not be reached at all -- never rendered as an eligibility answer.
    pub const NO_CHAIN_TRANSPORT: &str = concat!(
        "The chain could not be reached, so whether a reward distributor can be created here is ",
        "unknown. Nothing has been signed and nothing will be spent.",
    );
    /// Nothing has asked yet. A sentence rather than silence, because an empty space where a
    /// refusal or a control belongs reads as *there is nothing to create here*, which is a claim
    /// no read has made.
    pub const NOT_YET_ASKED: &str =
        "Whether a reward distributor can be created here has not been checked yet.";
}

/// The availability reason the create card shows, or `None` when there is no reason to show
/// because a mint is actually possible.
///
/// Takes an `Option` because the answer comes from
/// [`super::mint::DistributorMintAvailability::probe`], which READS THE CHAIN and therefore cannot
/// run on a paint path -- the card paints the last answer the refresh cadence recorded, and `None`
/// is the honest state before the first one arrives. That is the same split
/// `ProfileMintSeams::from_readiness` already makes for the profile mint, and the reason the
/// availability stopped being a `const fn` at all: a value that moves cannot be a constant.
///
/// The production caller is `confirm::gui::window::pane::store_rewards::create_note` (a code span,
/// not a link: it is `pub(crate)`, and rustdoc refuses a public doc that links a private item),
/// which paints the returned sentence as a plain label under every Rewards section (dig-app#411).
///
/// `Some(Possible)` yields `None` -- no sentence -- and that arm is now genuinely reachable: an
/// unlocked account over a walking chain probes as `Possible`. That is the arm the create card is
/// painted under: no refusal sentence, and the card itself instead. Every other arm paints its
/// refusal and no control, which is the rule this function exists to keep -- a control that
/// reached [`super::create::Launchable::into_manager_inner_puzzle`] with nowhere to hand the
/// result is the irreversible-looking affordance that creates nothing, removed once already
/// here.
pub fn create_availability_sentence(
    availability: Option<DistributorMintAvailability>,
) -> Option<&'static str> {
    match availability {
        None => Some(create_unavailable::NOT_YET_ASKED),
        Some(DistributorMintAvailability::Possible) => None,
        Some(DistributorMintAvailability::Locked) => Some(create_unavailable::LOCKED),
        Some(DistributorMintAvailability::NoLineageWalk) => {
            Some(create_unavailable::NO_LINEAGE_WALK)
        }
        Some(DistributorMintAvailability::NoChainTransport) => {
            Some(create_unavailable::NO_CHAIN_TRANSPORT)
        }
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
#[cfg(test)]
mod create_availability_tests {
    use super::*;

    /// Every arm maps to a DISTINCT sentence, and only `Possible` maps to none.
    ///
    /// Distinctness is the property under test, not merely that each arm answers something: three
    /// refusals sharing one sentence would send somebody to unlock an account whose node is down.
    #[test]
    fn each_availability_paints_its_own_reason() {
        let sentences = [
            create_availability_sentence(None),
            create_availability_sentence(Some(DistributorMintAvailability::Locked)),
            create_availability_sentence(Some(DistributorMintAvailability::NoLineageWalk)),
            create_availability_sentence(Some(DistributorMintAvailability::NoChainTransport)),
        ];
        for (index, sentence) in sentences.iter().enumerate() {
            assert!(sentence.is_some(), "arm {index} must paint a reason");
            for other in &sentences[index + 1..] {
                assert_ne!(sentence, other, "two arms must not share one sentence");
            }
        }

        assert_eq!(
            create_availability_sentence(Some(DistributorMintAvailability::Possible)),
            None,
            "a possible mint must paint no refusal"
        );
    }

    /// No refusal promises anything. A refusal that hints at an upgrade is the dead end
    /// dig_ecosystem#1800 removed; a refusal that calls anything "safe", "secure" or
    /// "recoverable" is the provenance lie `super::super::create`'s copy rules forbid.
    #[test]
    fn no_reason_promises_anything_or_claims_safety() {
        for sentence in [
            create_unavailable::NOT_YET_ASKED,
            create_unavailable::LOCKED,
            create_unavailable::NO_LINEAGE_WALK,
            create_unavailable::NO_CHAIN_TRANSPORT,
        ] {
            let lowercased = sentence.to_lowercase();
            for forbidden in [
                "coming soon",
                "soon",
                "upgrade",
                "next version",
                "recovery",
                "recoverable",
                "safe",
                "secure",
            ] {
                assert!(
                    !lowercased.contains(forbidden),
                    "a create refusal must not contain {forbidden:?}: {sentence:?}"
                );
            }
        }
    }

    /// There is no submit control in this module to paint: the reason sentence is the whole of
    /// the create card's output, and the only other thing this module hands a caller about
    /// creation is the acknowledgement gate, which produces no affordance of its own.
    #[test]
    fn the_create_card_renders_a_sentence_and_no_control() {
        // Comment lines are stripped and the needles are ASSEMBLED, for the same reason
        // `super::super::test_scan::string_literals` strips them: a scan for a bare submit-control
        // name over this file matches this test's own source -- as the first two revisions of this
        // test did, once in a string literal and once in the comment explaining the first.
        let code_only: String = include_str!("pane.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for name in ["submit", "on_submit", "create_button", "submit_button"] {
            let needle = format!("fn {name}");
            assert!(
                !code_only.contains(&needle),
                "no submit control may exist while the minter facade does not: {needle:?}"
            );
        }
    }
}
