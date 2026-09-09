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
use crate::wallet::state::Asset;
use crate::window_model::{PaneNote, Section};

use super::cadence::{days_between_claims, CadenceReading};
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

/// One fact sentence per [`ProverReading`] variant. Never a health boolean rendered as a word —
/// each sentence names the SPECIFIC reason, per §2.4's rule that no two of these may collapse.
fn prover_status_sentence(reading: ProverReading) -> String {
    match reading {
        ProverReading::NoRecord => "Not distributing.".to_string(),
        ProverReading::ClockUnusable => {
            "This computer's clock disagrees with the prover's -- staleness cannot be judged."
                .to_string()
        }
        ProverReading::Live => "The prover is running and reporting on schedule.".to_string(),
        ProverReading::HeartbeatLate => "The prover's last report is running late.".to_string(),
        ProverReading::HeartbeatLost => "The prover has stopped reporting.".to_string(),
        ProverReading::CycleOverdue => {
            "The prover is reporting, but its cycle is overdue.".to_string()
        }
        ProverReading::NeverRan => {
            "The prover is reporting, but has never completed a cycle.".to_string()
        }
    }
}

/// One fact sentence for the entry set (SPEC §2.4 clause 3): a count is never said without the
/// write time that makes it current, per [`EntrySetReading`]'s non-splittable shape.
fn entry_set_sentence(reading: EntrySetReading) -> String {
    match reading {
        EntrySetReading::NeverWritten => "No mirror has ever been added.".to_string(),
        EntrySetReading::Known {
            entry_count,
            last_entry_write_at,
        } => format!(
            "{entry_count} mirror(s) as of the last entry write at unix time {last_entry_write_at}."
        ),
    }
}

/// One fact sentence for the payout total (SPEC §2.4 clause 2), money rendered ONLY through
/// [`amount_with_unit`] -- never a raw base-unit integer, never a hand-written `"$DIG"` re-deriving
/// the ticker [`amount_with_unit`] already carries (finding 7: the two must never disagree).
fn payout_sentence(reading: PayoutReading) -> String {
    match reading {
        PayoutReading::NeverRan => "No payout cycle has ever completed.".to_string(),
        PayoutReading::Paid {
            total_paid_out_base_units,
            last_cycle_completed_at,
        } => {
            let amount = amount_with_unit(Asset::DIG, total_paid_out_base_units);
            format!(
                "{amount} paid out in total, as of the last completed cycle at unix time \
                 {last_cycle_completed_at}."
            )
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
/// (see this module's sibling [`super::cadence`] doc comment for why no minimum exists).
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
        CadenceReading::EntryCountUnknown => {
            "The mirror set is not yet known, so a claim cadence cannot be stated.".to_string()
        }
        CadenceReading::NoMirrorsYet => {
            "No mirror is claiming yet, so there is no cadence to state.".to_string()
        }
        CadenceReading::NoFundingRateChosen => {
            "Choose a funding rate to see how often a mirror would claim.".to_string()
        }
        CadenceReading::Days(days) if days < CLAIM_CADENCE_DAYS => "At this funding rate, a \
            mirror accrues enough to claim on every claim cycle, roughly once a day."
            .to_string(),
        CadenceReading::Days(days) if days > FAR_END_DAYS_THRESHOLD => format!(
            "At this funding rate, a mirror clears the claim threshold far more than \
             {FAR_END_DAYS_THRESHOLD:.0} days apart -- it is still accruing, just not practically \
             paid."
        ),
        CadenceReading::Days(days) => {
            format!("At this funding rate, a mirror claims roughly every {days:.1} day(s).")
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
    let prover = prover_status_sentence(prover_reading(record, now));
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
    /// health boolean rendered as a word.
    #[test]
    fn never_ran_prover_names_itself_in_the_first_section() {
        let record = base_record();
        let sections = rewards_sections(&record, 0, 0);
        assert_eq!(
            sections[0].heading.as_deref(),
            Some("The prover is reporting, but has never completed a cycle.")
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
        assert_eq!(
            cadence_heading,
            "The mirror set is not yet known, so a claim cadence cannot be stated."
        );
    }

    /// A GENUINELY known zero entry count (post-eviction, or never admitted, but with a real
    /// write timestamp) is a different fact from an unknown entry set, and gets its own sentence:
    /// "no mirror is claiming yet." SPEC §2.4 clause 3's non-splittable shape, carried all the way
    /// to the pane.
    #[test]
    fn known_zero_entry_count_cadence_is_no_mirrors_yet() {
        let mut record = base_record();
        record.last_entry_write_at = Some(500);
        record.counters.entry_count = 0;
        let sections = rewards_sections(&record, 0, 1_000);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert_eq!(
            cadence_heading,
            "No mirror is claiming yet, so there is no cadence to state."
        );
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
        assert_eq!(
            cadence_heading,
            "Choose a funding rate to see how often a mirror would claim."
        );
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
        assert_eq!(
            cadence_heading,
            "At this funding rate, a mirror accrues enough to claim on every claim cycle, \
             roughly once a day."
        );

        // Exactly at the one-day boundary (1_000 base units/day, one mirror) is NOT clamped --
        // it renders the ordinary numeric sentence.
        let at_boundary = rewards_sections(&record, 0, 1_000);
        let boundary_heading = at_boundary[3].heading.as_deref().unwrap();
        assert_eq!(
            boundary_heading,
            "At this funding rate, a mirror claims roughly every 1.0 day(s)."
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
        assert!(cadence_heading.contains("far more than"));
    }
}

/// Proof that every one of the five warning blocks (DECISIONS-3253 Q1) was displayed, never merely
/// that acknowledgement was called (finding 6). Zero-sized and privately constructed everywhere
/// except [`Self::having_displayed`], which is the only function that can hand one out.
///
/// # Why a copy-key list, not a bare no-argument constructor
///
/// A zero-argument `WarningsShown::new()` would be exactly the one-line forge the removed `Copy`
/// derive allowed: satisfiable from anywhere with no evidence attached. Requiring the exact five
/// copy keys means only the paint code that actually rendered them -- the one place that KNOWS what
/// it displayed -- can produce a witness; a caller trying to skip straight to [`CreationGate::acknowledge`]
/// has to first name five keys it never painted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
