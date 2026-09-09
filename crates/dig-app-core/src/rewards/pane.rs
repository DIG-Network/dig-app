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
//! refill, the donation disclosure and the Activity mirror-claim record are built on top of this
//! in later commits on the same branch.

use crate::amount::format_asset_amount;
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
/// [`format_asset_amount`] -- never a raw base-unit integer, never divided by a compiled-in constant.
fn payout_sentence(reading: PayoutReading) -> String {
    match reading {
        PayoutReading::NeverRan => "No payout cycle has ever completed.".to_string(),
        PayoutReading::Paid {
            total_paid_out_base_units,
            last_cycle_completed_at,
        } => {
            let amount = format_asset_amount(Asset::DIG, total_paid_out_base_units)
                .unwrap_or_else(|| total_paid_out_base_units.to_string());
            format!(
                "{amount} $DIG paid out in total, as of the last completed cycle at unix time \
                 {last_cycle_completed_at}."
            )
        }
    }
}

/// One fact sentence for claim cadence (SPEC §6.5.1) -- a claim FREQUENCY, never a funding floor
/// (see this module's sibling [`super::cadence`] doc comment for why no minimum exists).
fn cadence_sentence(reading: CadenceReading) -> String {
    match reading {
        CadenceReading::EntryCountUnknown => {
            "The mirror set is not yet known, so a claim cadence cannot be stated.".to_string()
        }
        CadenceReading::NoMirrorsYet => {
            "No mirror is claiming yet, so there is no cadence to state.".to_string()
        }
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
    let entry_count_for_cadence = match entry_set_reading(record) {
        EntrySetReading::NeverWritten => Some(0),
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

    /// A zero entry count reads as "no mirrors yet" cadence, never a reassuring `0.0` days.
    #[test]
    fn zero_entry_count_cadence_is_no_mirrors_yet_not_a_reassuring_zero() {
        let record = base_record();
        let sections = rewards_sections(&record, 0, 1_000);
        let cadence_heading = sections[3].heading.as_deref().unwrap();
        assert_eq!(
            cadence_heading,
            "No mirror is claiming yet, so there is no cadence to state."
        );
    }
}

/// The creation flow's gate (DECISIONS-3253 Q1): the five warning blocks plus heading and closing
/// line MUST be shown, and a person must explicitly acknowledge them, before a create affordance
/// is reachable. This type exists so that invariant is enforced by the compiler rather than by a
/// paint-order convention: there is no constructor that hands out an already-acknowledged gate, and
/// [`CreationGate::may_create`] is the ONLY function that can say yes.
///
/// This does not decide WHERE the warning is painted or wire a create RPC — no create/mint
/// affordance ships in this pass (see this module's parent [`crate::rewards`] doc comment). It is
/// the state machine the eventual creation-flow paint code must hold, written now so that code has
/// nowhere honest to skip the gate when it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreationGate {
    acknowledged: bool,
}

impl CreationGate {
    /// A freshly opened creation flow. The warning has not yet been acknowledged.
    pub fn unacknowledged() -> Self {
        Self {
            acknowledged: false,
        }
    }

    /// The person clicked past every warning block. Consumes `self` and returns the acknowledged
    /// gate, so a caller cannot hold both an acknowledged and an unacknowledged handle to the same
    /// flow from one value.
    pub fn acknowledge(self) -> Self {
        Self { acknowledged: true }
    }

    /// Whether a create affordance may be shown. `false` until [`Self::acknowledge`] is called —
    /// there is no other path to `true`.
    pub fn may_create(&self) -> bool {
        self.acknowledged
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

    /// A freshly opened flow may never create — the warning has not been read yet.
    #[test]
    fn fresh_gate_may_not_create() {
        assert!(!CreationGate::unacknowledged().may_create());
        assert!(!CreationGate::default().may_create());
    }

    /// Acknowledging is the ONLY way `may_create` becomes true.
    #[test]
    fn acknowledging_unlocks_create() {
        let gate = CreationGate::unacknowledged().acknowledge();
        assert!(gate.may_create());
    }
}

/// A read-only record of being paid as a mirror (DECISIONS-3253 Q2), for the Activity tab. Carries
/// no verb: there is deliberately no action/button field, so a caller cannot attach one without
/// changing this type first, and [`super::tab_placement`]'s `activity_tab_emits_zero_action_rows`
/// guard is what catches a caller who tries anyway.
///
/// # Why this echoes the wire instead of computing anything
///
/// `paid_base_units` and `paid_at` are exactly [`super::reading::PayoutReading::Paid`]'s two
/// fields — this type adds no arithmetic of its own. A claim record that computed a share or a
/// running total here would be the same SPEC §2.6 clause 2 defect this module's sibling
/// [`super::wire::RewardDistributorCommitment`] doc comment names, one layer closer to the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorClaimRecord {
    pub paid_base_units: u64,
    pub paid_at: u64,
}

/// Builds the read-only Activity fact for a payout reading, or `None` when there is nothing paid
/// yet to record (SPEC §2.4 clause 2's `PayoutReading::NeverRan` — never rendered as a paid zero).
pub fn mirror_claim_record(reading: PayoutReading) -> Option<MirrorClaimRecord> {
    match reading {
        PayoutReading::NeverRan => None,
        PayoutReading::Paid {
            total_paid_out_base_units,
            last_cycle_completed_at,
        } => Some(MirrorClaimRecord {
            paid_base_units: total_paid_out_base_units,
            paid_at: last_cycle_completed_at,
        }),
    }
}

/// Renders a [`MirrorClaimRecord`] as the single fact sentence Activity shows, money formatted
/// only through [`format_asset_amount`] -- and as a [`Section`] with empty `rows`, the same
/// verb-free shape [`rewards_sections`] uses, so wiring this into Activity later cannot regress
/// `activity_tab_emits_zero_action_rows`.
pub fn mirror_claim_section(record: MirrorClaimRecord) -> Section {
    let amount = format_asset_amount(Asset::DIG, record.paid_base_units)
        .unwrap_or_else(|| record.paid_base_units.to_string());
    Section {
        heading: Some(format!(
            "Paid {amount} $DIG for mirroring, as of unix time {}.",
            record.paid_at
        )),
        rows: Vec::new(),
    }
}

#[cfg(test)]
mod mirror_claim_tests {
    use super::*;

    /// A prover that has never completed a cycle has nothing to claim yet -- `None`, never a
    /// zero-amount record (the reassuring-zero defect this module keeps refusing).
    #[test]
    fn never_ran_payout_has_no_claim_record() {
        assert_eq!(mirror_claim_record(PayoutReading::NeverRan), None);
    }

    /// A real payout round-trips into a record with no verb field to misuse -- checked at the type
    /// level: [`MirrorClaimRecord`] has exactly two fields, both echoed from the wire.
    #[test]
    fn a_paid_reading_becomes_a_record_with_the_same_two_numbers() {
        let reading = PayoutReading::Paid {
            total_paid_out_base_units: 2_500,
            last_cycle_completed_at: 99,
        };
        let record = mirror_claim_record(reading).expect("a paid reading has a claim record");
        assert_eq!(record.paid_base_units, 2_500);
        assert_eq!(record.paid_at, 99);
    }

    /// The rendered section carries the fact in its heading, money-formatted, with no rows -- the
    /// exact shape the Activity placement guard checks for.
    #[test]
    fn mirror_claim_section_has_no_rows_and_formats_money() {
        let record = MirrorClaimRecord {
            paid_base_units: 1_500,
            paid_at: 42,
        };
        let section = mirror_claim_section(record);
        assert!(section.rows.is_empty());
        let heading = section.heading.expect("heading carries the fact");
        assert!(heading.contains("1.5 $DIG"), "got: {heading}");
        assert!(!heading.contains("1500"));
    }
}
