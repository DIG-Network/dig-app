//! The collateral runway (dig-app#306): how many epochs this wallet can keep its stores
//! collateralised for, and how much $DIG to add.
//!
//! # Three findings, and only two of them interrupt anybody
//!
//! | state | meaning | surface |
//! |---|---|---|
//! | [`ShortNow`](Runway::ShortNow) | cannot cover the CURRENT epoch; stores are already uncollateralised | **notification** |
//! | [`DangerouslyLow`](Runway::DangerouslyLow) | covers now, cannot cover the NEXT epoch at the escalation ceiling | **notification** |
//! | [`BelowRecommendedBuffer`](Runway::BelowRecommendedBuffer) | funded for several epochs, but with no cushion | **readout only** |
//! | [`Comfortable`](Runway::Comfortable) | nothing to say | nothing |
//! | [`Unknown`](Runway::Unknown) | a fact is missing | **readout only, and never a number** |
//!
//! **The third row is the one this module exists to get right.** A healthy node sits in
//! `BelowRecommendedBuffer` much of the time — it is the ordinary state of a wallet that is funded
//! but not over-funded. Notifying on it would produce a recurring, ignorable alert, and a person
//! who learns to dismiss that alert has learned to dismiss the two above it, which are the ones
//! that cost them money. So [`Runway::notification`] returns `None` for it, and there is a test
//! whose whole job is to fail if that ever changes.
//!
//! This is the same rule [`super::funding`] applies to `WithheldUnsynced`, for the same reason, and
//! it is the reason both live in this module rather than being folded into one "how bad is it"
//! scale. They are not degrees of one problem.
//!
//! # Say the number, not the alarm
//!
//! *"Balance low"* tells an operator to go and work out what to do. *"Add ~24 $DIG"* tells them what
//! to do. Every notifying state therefore carries [`add_dig_base_units`](Shortfall::add_dig_base_units)
//! — the amount that would clear it — and the working behind it: the stores served, the current
//! per-store requirement, and the horizon the figure was computed against. A calculated buffer whose
//! calculation is hidden is just a louder alarm.
//!
//! # The escalation ceiling, and why it is one controller step
//!
//! "Cannot cover the next epoch" needs a next-epoch price, which does not exist yet. The honest
//! upper bound is the most the controller can raise the multiplier in ONE step, which is exactly
//! [`step_multiplier`](dig_mirror_collateral::step_multiplier) evaluated in its `Band::High` arm —
//! so this module calls that function with a saturation pinned at
//! [`SIGNAL_CAP_MICROS`](dig_mirror_collateral::SIGNAL_CAP_MICROS) rather than re-deriving the step.
//! There is one implementation of the controller's step rule and it lives in the consensus crate.
//!
//! **The owner count is held at the current census on purpose, and that is a stated limitation.**
//! The true worst case would also assume the small-network handicap vanishes, which in a young
//! network is a several-fold jump — and a bound that pessimistic would put an ordinary node into
//! `DangerouslyLow` permanently, which is the cry-wolf failure above. So the horizon escalates the
//! PRICE, which is the controller's own per-epoch movement, and not the network's size. A node whose
//! owner count doubles between epochs can still be surprised; that is a real gap and it is named
//! here rather than papered over.
//!
//! # Nothing here fires on an unknown
//!
//! [`Runway::of`] takes readings, not numbers. A missing requirement, a missing margin, an unread
//! store list, or an unmeasured balance all produce [`Runway::Unknown`], which never notifies and
//! never shows a figure. A zero balance and an unmeasured balance produce the same arithmetic and
//! only one of them is a reason to interrupt somebody.

use dig_mirror_collateral::{
    apply_safety_margin, required_per_store, step_multiplier, SIGNAL_CAP_MICROS,
};

use crate::amount::amount_with_unit;
use crate::collateral::node::{EpochRequirement, MarginReading, RequirementReading};
use crate::collateral::SafetyMargin;
use crate::hosted_stores::HostedStoresReading;
use crate::notify::{Notification, Route};
use crate::wallet::state::Asset;

/// How many epochs of cushion a comfortable wallet holds.
///
/// Below this the runway is reported ([`BelowRecommendedBuffer`](Runway::BelowRecommendedBuffer))
/// but never announced. It is a display threshold, not a protocol bound: three epochs is long enough
/// that a person has time to act between noticing and being short, and short enough that the
/// recommendation is not asking them to lock money they have no use for.
pub const RECOMMENDED_EPOCHS: u64 = 3;

/// What the runway was measured against — carried so a figure can show its working.
///
/// Every field comes from the node's own answer. None is assumed, and none is defaulted: the whole
/// struct exists only inside a state that already had all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Working {
    /// Stores this node serves, from its own hosted-store list.
    pub stores: u64,
    /// The current per-store requirement in $DIG base units, before the margin.
    pub required_per_store_dig_base_units: u64,
    /// What this node posts per store — the requirement with the node's margin applied.
    pub posted_per_store_dig_base_units: u64,
    /// The margin the NODE reports it is applying.
    pub margin: SafetyMargin,
    /// The epoch the current requirement governs.
    pub epoch: u64,
    /// How many whole epochs the confirmed balance covers at the current posting.
    ///
    /// Saturating at a large value rather than unbounded: a node serving no stores has an infinite
    /// runway, and a surface needs a number it can print.
    pub epochs_covered: u64,
}

/// A funding gap, with the amount that clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortfall {
    /// The $DIG to add, in base units. **Always the amount that clears the state it is attached
    /// to** — never a round number and never a suggestion.
    pub add_dig_base_units: u64,
    /// The facts the figure was derived from.
    pub working: Working,
}

impl Shortfall {
    /// The amount to add, as a person reads it — `"24.000 $DIG"`.
    #[must_use]
    pub fn add_with_unit(&self) -> String {
        amount_with_unit(Asset::DIG, self.add_dig_base_units)
    }
}

/// Where this wallet stands against its collateral obligations.
///
/// An enum rather than a number with thresholds applied at each call site, because the three
/// interesting states lead to three different behaviours and only two of them may interrupt. A
/// scalar "runway in epochs" would leave every surface to re-apply the rule, and one of them would
/// eventually apply it differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runway {
    /// The confirmed balance does not cover the CURRENT epoch. Stores are already going
    /// uncollateralised. **Notifies.**
    ShortNow(Shortfall),
    /// The current epoch is covered, but the next one is not if the controller raises the price as
    /// far as one step allows. **Notifies.**
    DangerouslyLow(Shortfall),
    /// Covered for the next epoch, but with fewer than [`RECOMMENDED_EPOCHS`] epochs of cushion.
    /// **Never notifies** — see the module docs.
    BelowRecommendedBuffer(Shortfall),
    /// At or above the recommended cushion. Nothing to say.
    Comfortable(Working),
    /// A fact needed to answer is missing. Never notifies, and never shows a figure.
    Unknown(RunwayUnknown),
}

/// Which fact stopped the runway being computed. **One variant per REMEDY**, so a surface can say
/// what to do rather than only that it does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunwayUnknown {
    /// A read the answer depends on is still in flight. A wait, not a fault.
    Pending,
    /// No node stated this epoch's requirement, and it carries the node's own reason.
    NoRequirement(crate::collateral::node::CollateralUnknown),
    /// The node's safety margin could not be read, so what it POSTS per store is not known — and
    /// the requirement alone does not answer the question.
    NoMargin(crate::collateral::node::CollateralUnknown),
    /// The store list could not be read, so the obligation cannot be totalled.
    NoStores(crate::hosted_stores::HostedStoresUnknown),
    /// The wallet balance has not been measured. **Not the same as a zero balance**, which is a
    /// measured fact and a real shortfall.
    NoBalance,
}

/// Everything [`Runway::of`] needs, as readings rather than numbers.
///
/// Taking readings is the point: a caller cannot hand this a figure it does not have, because there
/// is no field to put one in. That is what makes "never fires on unknown" a property of the type
/// instead of a rule every caller has to remember.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunwayFacts {
    /// Confirmed spendable $DIG in base units, or `None` when nobody has measured it.
    pub confirmed_dig_base_units: Option<u64>,
    /// This epoch's requirement, as the node reported it.
    pub requirement: RequirementReading,
    /// The margin the node reports it is applying.
    pub margin: MarginReading,
    /// The stores this node serves.
    pub stores: HostedStoresReading,
}

impl Runway {
    /// Where this wallet stands, given what the node has said.
    ///
    /// # Order of the unknowns
    ///
    /// A still-in-flight read is reported as [`Pending`](RunwayUnknown::Pending) before any named
    /// reason, because a reason invented while an answer is arriving sends someone to fix a problem
    /// they do not have. After that, the requirement is checked before the margin and the margin
    /// before the stores, which is the order in which each becomes relevant: without a requirement
    /// the margin has nothing to apply to.
    #[must_use]
    pub fn of(facts: &RunwayFacts) -> Self {
        let requirement = match &facts.requirement {
            RequirementReading::Pending => return Self::Unknown(RunwayUnknown::Pending),
            RequirementReading::Unknown(why) => {
                return Self::Unknown(RunwayUnknown::NoRequirement(why.clone()))
            }
            RequirementReading::Known(known) => *known,
        };
        let margin = match &facts.margin {
            MarginReading::Pending => return Self::Unknown(RunwayUnknown::Pending),
            MarginReading::Unknown(why) => {
                return Self::Unknown(RunwayUnknown::NoMargin(why.clone()))
            }
            MarginReading::Known(margin) => *margin,
        };
        let stores = match &facts.stores {
            HostedStoresReading::Pending => return Self::Unknown(RunwayUnknown::Pending),
            HostedStoresReading::Unknown(why) => {
                return Self::Unknown(RunwayUnknown::NoStores(why.clone()))
            }
            HostedStoresReading::Known(held) => held.len() as u64,
        };
        let Some(confirmed) = facts.confirmed_dig_base_units else {
            return Self::Unknown(RunwayUnknown::NoBalance);
        };

        Self::assess(confirmed, requirement, margin, stores)
    }

    /// The arithmetic, once every fact is in hand.
    ///
    /// Split from [`of`](Self::of) so the thresholds can be exercised directly on numbers, without
    /// four readings in the way — and so the unknown-handling above stays a short, readable list of
    /// guards rather than being interleaved with the sums.
    fn assess(
        confirmed_dig_base_units: u64,
        requirement: EpochRequirement,
        margin: SafetyMargin,
        stores: u64,
    ) -> Self {
        let posted_per_store =
            apply_safety_margin(requirement.required_per_store_dig_base_units, margin.margin_bp);
        let due_now = posted_per_store.saturating_mul(stores);

        let working = Working {
            stores,
            required_per_store_dig_base_units: requirement.required_per_store_dig_base_units,
            posted_per_store_dig_base_units: posted_per_store,
            margin,
            epoch: requirement.epoch,
            // A node serving nothing owes nothing, so its runway is unbounded. Reported as the
            // largest expressible figure rather than as a special case, because every consumer of
            // this field is comparing it against a small threshold.
            epochs_covered: match due_now {
                0 => u64::MAX,
                due => confirmed_dig_base_units / due,
            },
        };

        // Already short. Nothing about the next epoch matters while this one is unfunded, and
        // saying so first is what keeps the worse state from being reported as the milder one.
        if confirmed_dig_base_units < due_now {
            return Self::ShortNow(Shortfall {
                add_dig_base_units: due_now - confirmed_dig_base_units,
                working,
            });
        }

        // The next epoch at the most one controller step can raise the price. `step_multiplier` is
        // the consensus crate's own rule; pinning saturation at the signal cap selects its
        // `Band::High` arm, which is the ceiling by construction rather than by a re-derived `9/8`.
        let ceiling_multiplier = step_multiplier(requirement.multiplier_micros, SIGNAL_CAP_MICROS);
        let next_required = required_per_store(ceiling_multiplier, requirement.owners);
        let next_posted = apply_safety_margin(next_required, margin.margin_bp);
        let due_next = next_posted.saturating_mul(stores);

        if confirmed_dig_base_units < due_next {
            return Self::DangerouslyLow(Shortfall {
                add_dig_base_units: due_next - confirmed_dig_base_units,
                working,
            });
        }

        // The cushion, measured at the CURRENT price: a recommendation stated against a worst case
        // would recommend a buffer far larger than the situation warrants, every epoch.
        let recommended = due_now.saturating_mul(RECOMMENDED_EPOCHS);
        if confirmed_dig_base_units < recommended {
            return Self::BelowRecommendedBuffer(Shortfall {
                add_dig_base_units: recommended - confirmed_dig_base_units,
                working,
            });
        }

        Self::Comfortable(working)
    }

    /// The gap and its working, for the states that have one.
    ///
    /// [`Comfortable`](Self::Comfortable) and [`Unknown`](Self::Unknown) have no shortfall — and in
    /// the second case that is load-bearing: there is no accessor anywhere on this type that yields
    /// a number from an unknown.
    #[must_use]
    pub fn shortfall(&self) -> Option<&Shortfall> {
        match self {
            Self::ShortNow(s) | Self::DangerouslyLow(s) | Self::BelowRecommendedBuffer(s) => Some(s),
            Self::Comfortable(_) | Self::Unknown(_) => None,
        }
    }

    /// Whether this state may interrupt somebody.
    ///
    /// The single predicate the notification path goes through, so "is this worth a toast" has one
    /// answer rather than one per call site — and so the rule that
    /// [`BelowRecommendedBuffer`](Self::BelowRecommendedBuffer) stays silent is written down once.
    #[must_use]
    pub fn is_worth_announcing(&self) -> bool {
        matches!(self, Self::ShortNow(_) | Self::DangerouslyLow(_))
    }

    /// The notification title. Leads with the action, never with the subsystem.
    #[must_use]
    pub fn title(&self) -> Option<String> {
        match self {
            Self::ShortNow(_) => Some("Add $DIG — your stores are uncollateralised".to_string()),
            Self::DangerouslyLow(_) => {
                Some("Add $DIG — next epoch's collateral is not covered".to_string())
            }
            Self::BelowRecommendedBuffer(_) | Self::Comfortable(_) | Self::Unknown(_) => None,
        }
    }

    /// The notification body: the amount to add, and the working behind it.
    ///
    /// The copy must not imply content is unavailable. Nothing gates a READ on collateral — the node
    /// keeps serving every byte it served before. What is lost is discoverability and payment
    /// eligibility: unseen and unpaid, not down. There is a test sweeping the words that would make
    /// that claim false.
    #[must_use]
    pub fn body(&self) -> Option<String> {
        let shortfall = match self {
            Self::ShortNow(s) | Self::DangerouslyLow(s) => s,
            Self::BelowRecommendedBuffer(_) | Self::Comfortable(_) | Self::Unknown(_) => {
                return None
            }
        };
        let working = &shortfall.working;
        let horizon = match self {
            Self::ShortNow(_) => format!("epoch {}", working.epoch),
            _ => format!("epoch {}", working.epoch.saturating_add(1)),
        };
        Some(format!(
            "Add {} to cover {} for {}. Each store posts {} at your {} margin. They stay online and readable, but other nodes cannot find them and they earn nothing.",
            shortfall.add_with_unit(),
            stores_phrase(working.stores),
            horizon,
            amount_with_unit(Asset::DIG, working.posted_per_store_dig_base_units),
            working.margin.percent_label(),
        ))
    }

    /// The whole notification, or `None` when this state must stay silent.
    ///
    /// Carries [`Route::Deposit`] so a host that can deliver a click lands the person where funds
    /// are added. **The copy never mentions the click**: on a host that cannot route one, a body
    /// reading "click here" is a dead end, and this notification's whole job is to be actionable on
    /// its own.
    #[must_use]
    pub fn notification(&self) -> Option<Notification> {
        Some(Notification {
            title: self.title()?,
            body: self.body()?,
            route: Some(Route::Deposit),
        })
    }
}

/// `1 store` / `3 stores`, so no body carries its own plural.
fn stores_phrase(stores: u64) -> String {
    match stores {
        1 => "1 store".to_string(),
        n => format!("{n} stores"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::node::CollateralUnknown;
    use crate::hosted_stores::{HostedStore, HostedStoresUnknown};

    /// A mature-network epoch: multiplier at 1.0x with the handicap fully retired, so
    /// `required_per_store` is the equilibrium 5_000 base units and the next-epoch ceiling is a
    /// clean 9/8 of it. Chosen because both figures are exact, so an off-by-one in the escalation
    /// step is visible rather than absorbed by rounding.
    fn epoch() -> EpochRequirement {
        EpochRequirement {
            epoch: 7,
            protocol_version: 1,
            required_per_store_dig_base_units: required_per_store(1_000_000, 1_000),
            stores: 40,
            owners: 1_000,
            multiplier_micros: 1_000_000,
            handicap_dig_base_units: 0,
        }
    }

    /// A store list of `n` entries, for counting only.
    fn stores(n: usize) -> HostedStoresReading {
        HostedStoresReading::Known(
            (0..n)
                .map(|i| HostedStore {
                    store_id: format!("store-{i}"),
                    pinned: false,
                    capsule_count: 1,
                    total_bytes: 1,
                })
                .collect(),
        )
    }

    /// Facts with every reading answered and `confirmed` $DIG in the wallet.
    fn facts(confirmed: u64, held: usize) -> RunwayFacts {
        RunwayFacts {
            confirmed_dig_base_units: Some(confirmed),
            requirement: RequirementReading::Known(epoch()),
            margin: MarginReading::Known(SafetyMargin::default()),
            stores: stores(held),
        }
    }

    /// What one store posts at the default +1% margin, and what four of them owe this epoch.
    fn due_now(held: u64) -> u64 {
        apply_safety_margin(epoch().required_per_store_dig_base_units, 100) * held
    }

    /// What four stores owe next epoch if the controller steps the price up as far as it can.
    fn due_next(held: u64) -> u64 {
        let ceiling = step_multiplier(1_000_000, SIGNAL_CAP_MICROS);
        apply_safety_margin(required_per_store(ceiling, 1_000), 100) * held
    }

    /// **`BelowRecommendedBuffer` NEVER raises a notification.**
    ///
    /// The rule this module exists to hold. The fixture is a wallet sitting comfortably inside the
    /// next epoch's worst case but under the three-epoch cushion — the ordinary state of a healthy
    /// node, and therefore the state that would produce a recurring ignorable alert.
    ///
    /// Both halves are asserted: the state IS the buffer state (so the fixture has not drifted into
    /// `Comfortable`, where silence would be trivially satisfied), and it is silent. A test that
    /// only asserted silence would pass against a fixture that had wandered out of the state under
    /// test entirely.
    #[test]
    fn the_recommended_buffer_state_never_notifies() {
        // Above next epoch's ceiling, below three epochs of the current price.
        let held = 4;
        let balance = due_next(held) + 1;
        assert!(
            balance < due_now(held) * RECOMMENDED_EPOCHS,
            "fixture must sit UNDER the recommended cushion or it proves nothing"
        );
        let runway = Runway::of(&facts(balance, held as usize));

        let Runway::BelowRecommendedBuffer(shortfall) = &runway else {
            panic!("the fixture must be in the buffer state, got {runway:?}");
        };
        assert!(shortfall.add_dig_base_units > 0, "a cushion gap is a figure");
        assert!(!runway.is_worth_announcing());
        assert_eq!(runway.notification(), None, "a readout, never a toast");
        assert_eq!(runway.title(), None);
        assert_eq!(runway.body(), None);
    }

    /// **The two urgent states DO notify, and they say the number.**
    ///
    /// The control for the test above: without it, an implementation whose `notification()` returned
    /// `None` unconditionally would satisfy the silence assertion perfectly.
    #[test]
    fn the_two_urgent_states_notify_and_name_the_amount() {
        let held = 4;
        let short = Runway::of(&facts(due_now(held) - 1, held as usize));
        assert!(matches!(short, Runway::ShortNow(_)), "got {short:?}");

        // Covers this epoch exactly, cannot cover the escalated next one.
        let low = Runway::of(&facts(due_now(held), held as usize));
        assert!(matches!(low, Runway::DangerouslyLow(_)), "got {low:?}");

        for runway in [&short, &low] {
            assert!(runway.is_worth_announcing());
            let toast = runway.notification().expect("an urgent state speaks");
            assert_eq!(toast.route, Some(Route::Deposit), "a click reaches deposit");
            let amount = runway
                .shortfall()
                .expect("an urgent state has a shortfall")
                .add_with_unit();
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

    /// **The two urgent states are told apart by ONE base unit of balance.**
    ///
    /// The boundary between "cannot cover now" and "cannot cover next" is exactly `due_now`, and it
    /// is pinned from both sides: one under must be `ShortNow`, and at-bound must be
    /// `DangerouslyLow`. A threshold tested only from below can only confirm itself — an
    /// implementation using `<=` instead of `<` would report a fully-funded epoch as unfunded, which
    /// is a money lie in the alarming direction.
    #[test]
    fn the_current_epoch_boundary_is_pinned_from_both_sides() {
        let held = 4usize;
        let boundary = due_now(held as u64);
        assert!(matches!(
            Runway::of(&facts(boundary - 1, held)),
            Runway::ShortNow(_)
        ));
        assert!(matches!(
            Runway::of(&facts(boundary, held)),
            Runway::DangerouslyLow(_)
        ));
    }

    /// **The next-epoch boundary is pinned from both sides too**, and it is strictly above the
    /// current-epoch one.
    ///
    /// The ordering assertion is what makes the two boundaries distinguishable: if the escalation
    /// step were dropped and `due_next` equalled `due_now`, `DangerouslyLow` would become
    /// unreachable and every other test here would still pass.
    #[test]
    fn the_next_epoch_boundary_is_pinned_and_sits_above_the_current_one() {
        let held = 4u64;
        assert!(
            due_next(held) > due_now(held),
            "the escalation ceiling must actually escalate, or DangerouslyLow is unreachable"
        );
        assert!(matches!(
            Runway::of(&facts(due_next(held) - 1, held as usize)),
            Runway::DangerouslyLow(_)
        ));
        assert!(matches!(
            Runway::of(&facts(due_next(held), held as usize)),
            Runway::BelowRecommendedBuffer(_)
        ));
    }

    /// **The recommended-cushion boundary is pinned from both sides.**
    #[test]
    fn the_cushion_boundary_is_pinned_from_both_sides() {
        let held = 4u64;
        let cushion = due_now(held) * RECOMMENDED_EPOCHS;
        assert!(matches!(
            Runway::of(&facts(cushion - 1, held as usize)),
            Runway::BelowRecommendedBuffer(_)
        ));
        assert!(matches!(
            Runway::of(&facts(cushion, held as usize)),
            Runway::Comfortable(_)
        ));
    }

    /// **Every missing fact produces an Unknown that neither speaks nor shows a figure.**
    ///
    /// The fixture holds a balance of ZERO in each case — deliberately, because zero is the value an
    /// implementation that treated an unknown as "nothing" would compute a maximal shortfall from.
    /// A version defaulting any one of these readings would produce a confident, alarming, wrong
    /// notification here, and every other test in this file would stay green.
    #[test]
    fn no_missing_fact_can_produce_a_notification_or_a_number() {
        let complete = facts(0, 4);
        let incomplete = [
            RunwayFacts {
                requirement: RequirementReading::Pending,
                ..complete.clone()
            },
            RunwayFacts {
                requirement: RequirementReading::Unknown(CollateralUnknown::NodeCannotRead),
                ..complete.clone()
            },
            RunwayFacts {
                margin: MarginReading::Pending,
                ..complete.clone()
            },
            RunwayFacts {
                margin: MarginReading::Unknown(CollateralUnknown::Unauthorized),
                ..complete.clone()
            },
            RunwayFacts {
                stores: HostedStoresReading::Pending,
                ..complete.clone()
            },
            RunwayFacts {
                stores: HostedStoresReading::Unknown(HostedStoresUnknown::NoNode),
                ..complete.clone()
            },
            RunwayFacts {
                confirmed_dig_base_units: None,
                ..complete.clone()
            },
        ];
        for facts in &incomplete {
            let runway = Runway::of(facts);
            assert!(
                matches!(runway, Runway::Unknown(_)),
                "a missing fact must be unknown, got {runway:?}"
            );
            assert!(!runway.is_worth_announcing());
            assert_eq!(runway.notification(), None);
            assert_eq!(runway.shortfall(), None, "an unknown yields no figure");
        }

        // The control: the SAME zero balance with every fact present is a real, loud shortfall. So
        // the silence above is caused by the missing fact and not by the balance.
        let measured_zero = Runway::of(&complete);
        assert!(matches!(measured_zero, Runway::ShortNow(_)));
        assert!(measured_zero.notification().is_some());
    }

    /// **A measured zero balance is a shortfall; an unmeasured one is silence.**
    ///
    /// Stated as its own test because it is the single distinction the whole unknown machinery
    /// exists for, and the one a future refactor is most likely to collapse.
    #[test]
    fn a_measured_zero_is_not_an_unmeasured_balance() {
        assert!(matches!(Runway::of(&facts(0, 4)), Runway::ShortNow(_)));
        assert!(matches!(
            Runway::of(&RunwayFacts {
                confirmed_dig_base_units: None,
                ..facts(0, 4)
            }),
            Runway::Unknown(RunwayUnknown::NoBalance)
        ));
    }

    /// **An unknown carries its reason through**, rather than collapsing into one that names no
    /// remedy — the difference between "upgrade your node" and "check your control token".
    #[test]
    fn an_unknown_keeps_the_reason_that_names_its_remedy() {
        assert_eq!(
            Runway::of(&RunwayFacts {
                requirement: RequirementReading::Unknown(CollateralUnknown::NoChainSource),
                ..facts(0, 4)
            }),
            Runway::Unknown(RunwayUnknown::NoRequirement(CollateralUnknown::NoChainSource))
        );
        assert_eq!(
            Runway::of(&RunwayFacts {
                margin: MarginReading::Unknown(CollateralUnknown::Unauthorized),
                ..facts(0, 4)
            }),
            Runway::Unknown(RunwayUnknown::NoMargin(CollateralUnknown::Unauthorized))
        );
        assert_eq!(
            Runway::of(&RunwayFacts {
                stores: HostedStoresReading::Unknown(HostedStoresUnknown::Unauthorized),
                ..facts(0, 4)
            }),
            Runway::Unknown(RunwayUnknown::NoStores(HostedStoresUnknown::Unauthorized))
        );
    }

    /// **A node serving no stores owes nothing and is never short**, however empty its wallet.
    ///
    /// The answered-empty store list is a real answer, and the arithmetic must not divide by it.
    #[test]
    fn a_node_serving_nothing_is_never_short() {
        let runway = Runway::of(&facts(0, 0));
        let Runway::Comfortable(working) = &runway else {
            panic!("no stores means no obligation, got {runway:?}");
        };
        assert_eq!(working.stores, 0);
        assert_eq!(working.epochs_covered, u64::MAX);
        assert_eq!(runway.notification(), None);
    }

    /// **The body shows its working** — the stores served, what each posts, and the margin.
    ///
    /// A calculated buffer whose calculation is invisible is just a louder alarm, so the numbers a
    /// person would need to check the recommendation are asserted present.
    #[test]
    fn the_body_shows_the_working_behind_the_number() {
        let held = 4;
        let runway = Runway::of(&facts(0, held));
        let body = runway.body().expect("ShortNow speaks");
        assert!(body.contains("4 stores"), "{body}");
        assert!(body.contains("1%"), "the node's margin, not an assumed one: {body}");
        let posted = amount_with_unit(
            Asset::DIG,
            apply_safety_margin(epoch().required_per_store_dig_base_units, 100),
        );
        assert!(body.contains(&posted), "the per-store posting: {body}");
        assert!(body.contains("epoch 7"), "the horizon it was computed for: {body}");

        // And the forward-looking state names the NEXT epoch, not this one — the two must not share
        // a horizon or the figure and the sentence disagree.
        let low = Runway::of(&facts(due_now(held as u64), held));
        let low_body = low.body().expect("DangerouslyLow speaks");
        assert!(low_body.contains("epoch 8"), "{low_body}");
    }

    /// **A singular store reads as `1 store`.**
    #[test]
    fn one_store_is_not_pluralised() {
        let body = Runway::of(&facts(0, 1)).body().expect("speaks");
        assert!(body.contains("cover 1 store for"), "{body}");
        assert!(!body.contains("1 stores"), "{body}");

        // The control: two stores DO pluralise, so the assertion above is about the plural rule and
        // not merely about the substring happening to appear.
        let two = Runway::of(&facts(0, 2)).body().expect("speaks");
        assert!(two.contains("cover 2 stores for"), "{two}");
    }

    /// **No notification claims content is unavailable.**
    ///
    /// Nothing gates a read on collateral: the node keeps serving every byte. A body saying
    /// "offline" or "unavailable" would be false, and it is the false claim a person is most likely
    /// to act on by panicking. Swept over every announcing state rather than one, because the two
    /// bodies are written separately.
    #[test]
    fn no_body_claims_content_went_offline() {
        let held = 4u64;
        let announcing = [
            Runway::of(&facts(0, held as usize)),
            Runway::of(&facts(due_now(held), held as usize)),
        ];
        let forbidden = [
            "offline",
            "unavailable",
            "cannot be read",
            "inaccessible",
            "down",
            "lost",
        ];
        for runway in &announcing {
            assert!(runway.is_worth_announcing());
            let body = runway.body().expect("speaks").to_lowercase();
            for word in forbidden {
                assert!(
                    !body.contains(word),
                    "{word:?} claims content is unavailable, which is false: {body}"
                );
            }
            assert!(
                body.contains("online and readable"),
                "the body must say the content is fine: {body}"
            );
        }
    }

    /// **No unknown reason can be added without giving it a sentence.**
    ///
    /// An exhaustive match rather than a count: adding a variant makes this fail to COMPILE, which a
    /// numeric assertion cannot do until someone runs the suite — and which names the new variant at
    /// the point the compiler stops, rather than reporting that a number changed.
    #[test]
    fn every_unknown_reason_is_accounted_for() {
        fn remedy(reason: &RunwayUnknown) -> &'static str {
            match reason {
                RunwayUnknown::Pending => "wait",
                RunwayUnknown::NoRequirement(_) => "the node cannot state the requirement",
                RunwayUnknown::NoMargin(_) => "the node cannot state its margin",
                RunwayUnknown::NoStores(_) => "the store list could not be read",
                RunwayUnknown::NoBalance => "the balance has not been measured",
            }
        }
        let all = [
            RunwayUnknown::Pending,
            RunwayUnknown::NoRequirement(CollateralUnknown::NoNode),
            RunwayUnknown::NoMargin(CollateralUnknown::NoNode),
            RunwayUnknown::NoStores(HostedStoresUnknown::NoNode),
            RunwayUnknown::NoBalance,
        ];
        let mut said: Vec<&str> = all.iter().map(remedy).collect();
        said.sort_unstable();
        said.dedup();
        assert_eq!(said.len(), all.len(), "two reasons name the same remedy");
    }
}
