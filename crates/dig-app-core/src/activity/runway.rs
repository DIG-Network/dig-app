//! The collateral runway (dig-app#306): how much $DIG the node says to hold, and when that is
//! worth interrupting somebody over.
//!
//! # This module renders an answer. It does not compute one.
//!
//! The buffer and the funding state both come from `control.collateral.buffer`
//! ([`read_buffer`](crate::collateral::node::read_buffer)). dig-app derives neither, and there is
//! deliberately no local fallback for a node that cannot answer.
//!
//! That is not fastidiousness about layering; the arithmetic is genuinely not available here.
//! A client-side buffer would be `posted_per_store * stores`, and every one of those three terms is
//! wrong in the same direction:
//!
//! - **The unreclaimed transition overlap is a term of the node's buffer and no client can see it.**
//!   During a changeover the node must cover the new epoch while the previous epoch's posting is
//!   not yet back. Nothing exposes reclaim state, so a client-side figure omits it silently.
//! - **A client's store count is the wrong unit.** [`HostedStore`](crate::hosted_stores::HostedStore)
//!   is keyed on `store_id` alone; the node counts `(owner, store, root)` pairs. One store served
//!   for two owners, or spanning a root transition, is one entry there and more than one here.
//! - **The escalation headroom depends on a horizon the node chose**, which travels in the payload
//!   precisely because escalation compounds — x1.12 at one epoch, x1.60 at four, x4.62 at thirteen —
//!   so the same buffer over a different horizon is a different claim.
//!
//! Each of those understates the shortfall, and **understating is the failure direction that costs
//! money**: an operator tops up the named amount, believes they are covered, and is not. A funding
//! warning naming too small a number is worse than no warning at all. When the node cannot answer,
//! the honest output is [`BufferReading::Unknown`], which shows no figure — and a "fallback"
//! computation would mean the wrong number still reaches a person, just less often and less
//! predictably.
//!
//! For the same reason the funding state is the node's verdict rather than a threshold applied
//! here: two clients thresholding the same numbers will eventually disagree, and the one that
//! disagrees about a funding warning is the one an operator acts on.
//!
//! # Three findings, and only two of them interrupt anybody
//!
//! | [`CollateralFundingState`] | meaning | surface |
//! |---|---|---|
//! | `ShortNow` | cannot cover the CURRENT epoch; stores are already uncollateralised | **notification** |
//! | `DangerouslyLow` | covers now, cannot cover the NEXT epoch at the escalation ceiling | **notification** |
//! | `BelowRecommendedBuffer` | funded for every epoch, but with no cushion | **readout only** |
//! | `Funded` | nothing to say | nothing |
//!
//! **The third row is the one this module exists to get right.** A healthy node sits in
//! `BelowRecommendedBuffer` much of the time — it is the ordinary state of a wallet that is funded
//! but not over-funded. Notifying on it would produce a recurring, ignorable alert, and a person
//! who learns to dismiss that alert has learned to dismiss the two above it, which are the ones
//! that cost them money.
//!
//! The rule is written down exactly once, in the contract's own
//! [`CollateralFundingState::is_shortfall`], and [`is_worth_announcing`] calls it rather than
//! restating the pair. `below_recommended_buffer` still carries a positive figure — the gap to the
//! recommendation — so the readout has a number to show while staying silent.
//!
//! # Say the number, not the alarm
//!
//! *"Balance low"* tells an operator to go and work out what to do. *"Add ~24 $DIG"* tells them what
//! to do. So [`body`] names [`NodeBuffer::add_with_unit`] and then shows the working the node sent
//! with it: the pairs served, the per-store requirement, the margin in force, and the horizon the
//! headroom assumed. A calculated buffer whose calculation is hidden is just a louder alarm.
//!
//! # Nothing here fires on an unknown
//!
//! Every entry point takes a [`BufferReading`], not a number. A pending read and a failed one both
//! produce silence and no figure — and, load-bearing, so does a node that answers `unknown`: the
//! contract's unknown variant has no representable numeric field, so there is no zero to mistake
//! for *no buffer needed*.

use crate::collateral::node::{BufferReading, CollateralFundingState, NodeBuffer};
use crate::notify::{Notification, Route};

/// The buffer, when the node stated one.
///
/// The single place a `BufferReading` is opened, so "an unknown never yields a figure" is one
/// function rather than a rule every renderer has to remember.
#[must_use]
pub const fn known(reading: &BufferReading) -> Option<&NodeBuffer> {
    match reading {
        BufferReading::Known(buffer) => Some(buffer),
        BufferReading::Pending | BufferReading::Unknown(_) => None,
    }
}

/// Whether this reading may interrupt somebody.
///
/// Delegates to the contract's own [`CollateralFundingState::is_shortfall`], which names the two
/// states that leave an epoch uncovered. Restating that pair here would be a second opinion about
/// which warnings matter, and the two would eventually differ.
#[must_use]
pub fn is_worth_announcing(reading: &BufferReading) -> bool {
    known(reading).is_some_and(|buffer| buffer.funding_state.is_shortfall())
}

/// The notification title. Leads with the action, never with the subsystem.
///
/// `None` for every state that must stay silent, including `BelowRecommendedBuffer` — which is what
/// [`notification`] is gated on.
#[must_use]
pub fn title(reading: &BufferReading) -> Option<String> {
    match known(reading)?.funding_state {
        CollateralFundingState::ShortNow => {
            Some("Add $DIG — your stores are uncollateralised".to_string())
        }
        CollateralFundingState::DangerouslyLow => {
            Some("Add $DIG — next epoch's collateral is not covered".to_string())
        }
        CollateralFundingState::BelowRecommendedBuffer | CollateralFundingState::Funded => None,
    }
}

/// The notification body: the amount to add, and the working the node sent with it.
///
/// The copy must not imply content is unavailable. Nothing gates a READ on collateral — the node
/// keeps serving every byte it served before. What is lost is discoverability and payment
/// eligibility: unseen and unpaid, not down. There is a test sweeping the words that would make
/// that claim false.
#[must_use]
pub fn body(reading: &BufferReading) -> Option<String> {
    let buffer = known(reading)?;
    let horizon = match buffer.funding_state {
        CollateralFundingState::ShortNow => format!("epoch {}", buffer.epoch),
        CollateralFundingState::DangerouslyLow => {
            format!("epoch {}", buffer.epoch.saturating_add(1))
        }
        CollateralFundingState::BelowRecommendedBuffer | CollateralFundingState::Funded => {
            return None
        }
    };
    Some(format!(
        "Add {} to cover {} for {}. Your node recommends holding {} across {} epochs at its {} margin. They stay online and readable, but other nodes cannot find them and they earn nothing.",
        buffer.add_with_unit(),
        pairs_phrase(buffer.pairs_served_by_this_node),
        horizon,
        crate::amount::amount_with_unit(
            crate::wallet::state::Asset::DIG,
            buffer.recommended_buffer_dig_base_units
        ),
        buffer.horizon_epochs,
        buffer.margin.percent_label(),
    ))
}

/// The whole notification, or `None` when this reading must stay silent.
///
/// `title()?`-gated, so the silence rule lives in exactly one place: a state with no title cannot
/// produce a toast however the body is written.
///
/// Carries [`Route::Deposit`] so a host that can deliver a click lands the person where funds are
/// added. **The copy never mentions the click**: on a host that cannot route one, a body reading
/// "click here" is a dead end, and this notification's whole job is to be actionable on its own.
#[must_use]
pub fn notification(reading: &BufferReading) -> Option<Notification> {
    Some(Notification {
        title: title(reading)?,
        body: body(reading)?,
        route: Some(Route::Deposit),
    })
}

/// `1 store` / `3 stores`, so no body carries its own plural.
///
/// The unit is the node's `(owner, store, root)` pair count, which a person reads as their stores.
fn pairs_phrase(pairs: u64) -> String {
    match pairs {
        1 => "1 store".to_string(),
        n => format!("{n} stores"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::node::{
        BufferUnknown, CollateralBufferUnknownReason, CollateralUnknown,
    };
    use crate::collateral::SafetyMargin;

    /// A complete node answer in `state`, with a real gap between the recommendation and the
    /// balance so every state carries a figure.
    ///
    /// The pair count (`12`) is deliberately NOT a plausible dig-app store-list length for the same
    /// fixture, and `overlap` and `escalation_headroom` are non-zero: an implementation that went
    /// back to assembling `posted_per_store * stores` could not reproduce this recommendation from
    /// the other fields, so the total is visibly the node's rather than a re-derivation.
    fn buffer(state: CollateralFundingState) -> BufferReading {
        BufferReading::Known(NodeBuffer {
            epoch: 7,
            protocol_version: 1,
            funding_state: state,
            recommended_buffer_dig_base_units: 32_400,
            spendable_dig_base_units: 14_050,
            pairs_served_by_this_node: 12,
            required_per_store_dig_base_units: 1_036,
            margin: SafetyMargin::of_basis_points(100),
            overlap_dig_base_units: 3_108,
            escalation_headroom_dig_base_units: 7_468,
            horizon_epochs: 4,
            escalation_ceiling_micros: 1_601_806,
        })
    }

    /// **`BelowRecommendedBuffer` NEVER raises a notification, and it is not silent by accident.**
    ///
    /// The fixture holds a real, positive gap to the recommendation — the ordinary state of a
    /// healthy node — so the silence cannot be explained by there being nothing to say. A test
    /// whose fixture had drifted to a zero gap would prove nothing at all.
    #[test]
    fn the_recommended_buffer_state_never_notifies() {
        let reading = buffer(CollateralFundingState::BelowRecommendedBuffer);
        let held = known(&reading).expect("the fixture states a buffer");
        assert!(
            held.add_dig_base_units() > 0,
            "the fixture must have a real gap or its silence proves nothing"
        );

        assert!(!is_worth_announcing(&reading));
        assert_eq!(title(&reading), None);
        assert_eq!(body(&reading), None);
        assert_eq!(notification(&reading), None, "a readout, never a toast");
    }

    /// **The two urgent states DO notify, and they say the number.**
    ///
    /// The control for the test above: without it, an implementation whose `notification` returned
    /// `None` unconditionally would satisfy the silence assertion perfectly.
    #[test]
    fn the_two_urgent_states_notify_and_name_the_amount() {
        for state in [
            CollateralFundingState::ShortNow,
            CollateralFundingState::DangerouslyLow,
        ] {
            let reading = buffer(state);
            assert!(is_worth_announcing(&reading), "{state:?}");
            let toast = notification(&reading).expect("an urgent state speaks");
            assert_eq!(toast.route, Some(Route::Deposit), "a click reaches deposit");
            let amount = known(&reading).expect("known").add_with_unit();
            assert!(
                toast.body.contains(&amount),
                "the body must NAME the amount to add; {amount} missing from {:?}",
                toast.body
            );
            assert!(
                toast.body.contains("$DIG"),
                "the amount must carry its unit"
            );
        }
    }

    /// **The announce rule is the NODE's `is_shortfall`, over every state the contract defines.**
    ///
    /// Swept across `CollateralFundingState::ALL` rather than the two states written above, so a
    /// fifth state added upstream is covered the day it lands instead of silently defaulting to
    /// whichever branch a local `matches!` happened to name. The assertion compares against the
    /// contract's own predicate, which is the point: this module must hold no second opinion about
    /// which warnings matter.
    #[test]
    fn announcing_tracks_the_nodes_own_shortfall_predicate() {
        for &state in CollateralFundingState::ALL {
            let reading = buffer(state);
            assert_eq!(
                is_worth_announcing(&reading),
                state.is_shortfall(),
                "{state:?} must announce exactly when the node says an epoch is uncovered"
            );
            assert_eq!(
                notification(&reading).is_some(),
                state.is_shortfall(),
                "{state:?}: the toast and the predicate must not disagree"
            );
        }

        // The control: the set is not trivially all-true or all-false, so the equality above is
        // a real correspondence rather than two constants matching.
        let announcing = CollateralFundingState::ALL
            .iter()
            .filter(|s| is_worth_announcing(&buffer(**s)))
            .count();
        assert_eq!(announcing, 2, "exactly two states interrupt anybody");
    }

    /// **No reading without a node answer can produce a notification or a number.**
    ///
    /// The sweep covers a pending read, a failed read, and — the one that matters most — a node
    /// that answered `unknown` for each of its own reasons. That last case is where a "fallback"
    /// computation would live, and it is the case in which a fabricated zero would read as *no
    /// buffer needed* and have an operator post nothing.
    #[test]
    fn no_reading_without_an_answer_speaks_or_shows_a_figure() {
        let mut silent = vec![
            BufferReading::Pending,
            BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead)),
            BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::Unauthorized)),
        ];
        silent.extend(
            CollateralBufferUnknownReason::ALL
                .iter()
                .map(|&reason| BufferReading::Unknown(BufferUnknown::NodeCannotSay(reason))),
        );

        for reading in &silent {
            assert!(!is_worth_announcing(reading), "{reading:?}");
            assert_eq!(notification(reading), None, "{reading:?}");
            assert_eq!(title(reading), None, "{reading:?}");
            assert_eq!(body(reading), None, "{reading:?}");
            assert!(
                known(reading).is_none(),
                "an unknown must yield no figure: {reading:?}"
            );
        }

        // The control: a real answer in the SAME shortfall position IS loud. So the silence above
        // is caused by the absent answer and not by the module being mute.
        let answered = buffer(CollateralFundingState::ShortNow);
        assert!(notification(&answered).is_some());
    }

    /// **The figure is the gap to the node's own recommendation, and it is never assembled.**
    ///
    /// Pinned as an exact value against fixture numbers that cannot be reached by
    /// `posted_per_store * pairs`: at the node's `required_per_store` of `1_036` and its `+1%`
    /// margin, twelve pairs come to `12_552`, which is neither the recommendation nor the gap. So a
    /// regression to client-side assembly changes this number rather than merely restyling it.
    #[test]
    fn the_amount_is_the_gap_to_the_nodes_recommendation() {
        let reading = buffer(CollateralFundingState::ShortNow);
        let held = known(&reading).expect("known");
        assert_eq!(held.add_dig_base_units(), 32_400 - 14_050);

        let assembled = held
            .margin
            .posted_per_store(held.required_per_store_dig_base_units)
            .saturating_mul(held.pairs_served_by_this_node);
        assert_ne!(
            held.recommended_buffer_dig_base_units, assembled,
            "the fixture must make an assembled buffer distinguishable from the node's"
        );
        assert!(
            assembled < held.recommended_buffer_dig_base_units,
            "and the assembled figure must be the SMALLER one -- understating is the direction \
             that costs an operator an epoch"
        );
    }

    /// **A met recommendation is a zero gap, not a negative one.**
    ///
    /// `Funded` is the state in which spendable exceeds the buffer, so the subtraction saturates.
    /// An unsaturated version would wrap to an enormous figure on the one state that must be
    /// silent.
    #[test]
    fn a_met_recommendation_yields_no_gap() {
        let BufferReading::Known(mut held) = buffer(CollateralFundingState::Funded) else {
            unreachable!()
        };
        held.spendable_dig_base_units = held.recommended_buffer_dig_base_units + 5_000;
        let reading = BufferReading::Known(held);
        assert_eq!(known(&reading).expect("known").add_dig_base_units(), 0);
        assert_eq!(notification(&reading), None);
    }

    /// **The body shows the node's working** — the pairs served, the recommendation, the horizon it
    /// covers, and the margin in force.
    ///
    /// The horizon assertion is the load-bearing one: escalation compounds, so the same buffer over
    /// four epochs and over one are different claims, and a body that omitted the horizon would
    /// state a figure nobody could check.
    #[test]
    fn the_body_shows_the_working_behind_the_number() {
        let reading = buffer(CollateralFundingState::ShortNow);
        let short = body(&reading).expect("ShortNow speaks");
        assert!(short.contains("12 stores"), "{short}");
        assert!(short.contains("across 4 epochs"), "the horizon: {short}");
        assert!(
            short.contains("1%"),
            "the node's margin, not an assumed one: {short}"
        );
        assert!(
            short.contains("epoch 7"),
            "the epoch it was computed for: {short}"
        );

        // And the forward-looking state names the NEXT epoch, not this one — the two must not share
        // a horizon or the figure and the sentence disagree.
        let low = body(&buffer(CollateralFundingState::DangerouslyLow)).expect("speaks");
        assert!(low.contains("epoch 8"), "{low}");
    }

    /// **A singular store reads as `1 store`.**
    #[test]
    fn one_store_is_not_pluralised() {
        let BufferReading::Known(mut held) = buffer(CollateralFundingState::ShortNow) else {
            unreachable!()
        };
        held.pairs_served_by_this_node = 1;
        let one = body(&BufferReading::Known(held)).expect("speaks");
        assert!(one.contains("cover 1 store for"), "{one}");
        assert!(!one.contains("1 stores"), "{one}");

        // The control: two DO pluralise, so the assertion above is about the plural rule and not
        // merely about the substring happening to appear.
        held.pairs_served_by_this_node = 2;
        let two = body(&BufferReading::Known(held)).expect("speaks");
        assert!(two.contains("cover 2 stores for"), "{two}");
    }

    /// **No notification claims content is unavailable.**
    ///
    /// Nothing gates a read on collateral: the node keeps serving every byte. A body saying
    /// "offline" or "unavailable" would be false, and it is the false claim a person is most likely
    /// to act on by panicking. Swept over every announcing state rather than one, because the two
    /// bodies take different branches.
    #[test]
    fn no_body_claims_content_went_offline() {
        let forbidden = [
            "offline",
            "unavailable",
            "cannot be read",
            "inaccessible",
            "down",
            "lost",
        ];
        for &state in CollateralFundingState::ALL {
            let reading = buffer(state);
            let Some(spoken) = body(&reading) else {
                continue;
            };
            let spoken = spoken.to_lowercase();
            for word in forbidden {
                assert!(
                    !spoken.contains(word),
                    "{word:?} claims content is unavailable, which is false: {spoken}"
                );
            }
            assert!(
                spoken.contains("online and readable"),
                "the body must say the content is fine: {spoken}"
            );
        }
    }
}
