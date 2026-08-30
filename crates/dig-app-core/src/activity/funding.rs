//! The out-of-funds signal (dig-app#289) — one OS notification, repeating hourly until funded.
//!
//! # This decision is NOT the one that drives the notification today — and must not become a second one
//!
//! A shortfall notification IS raised on a running dig-app: [`crate::collateral::watch::CollateralWatch`]
//! is ticked from the binary, reads the node's `control.collateral.buffer` verdict, and offers what
//! [`crate::activity::runway::notification`] returns to the activity gate. Nothing here has a caller, and
//! that is deliberate rather than an omission somebody should close.
//!
//! The two are rivals over one question, and **wiring this one while that one is wired would produce two
//! alarms about a single shortfall** — precisely the "learn to silence it" failure the three-state rule
//! below exists to prevent. So: whichever drives the notification, the other is DELETED in the same unit
//! of work. This one survives only if the per-store distinction proves to be worth more than the node's
//! own verdict, and it cannot even be evaluated until the node serves the fact it consumes —
//! `control.mirror.bondStates`, declared in `dig-node-control-interface` 0.27.0 and not served by the
//! shipped node (dig-node#377).
//!
//! # There is no modal, deliberately
//!
//! An earlier spec on #289 described a modal with an always-on-top behaviour and a configurable
//! 12-hour "remind me later". **The user withdrew all three.** They are recorded here only so nobody
//! re-implements them from the earlier comments, which remain on the ticket as history. The whole
//! surface is a notification: no in-app blocking element, no snooze control.
//!
//! # The three states a store without a coin can be in, and only one is this notification
//!
//! Measured from the legacy `dig-propagation-server`, a maintained store with no mirror coin is in
//! one of three states, and they are not degrees of the same problem:
//!
//! | state | notification? | why |
//! |---|---|---|
//! | [`OutOfDig`](Shortfall::OutOfDig) | **yes** | no collateral available; new stores cannot be advertised |
//! | [`WithheldUnsynced`](StoreCoinState::WithheldUnsynced) | **no** | the node is behaving CORRECTLY |
//! | [`CannotReclaim`](Shortfall::CannotReclaim) | **yes, and worse** | funds locked with no way out |
//!
//! **The middle row is the one that matters most for a signal that repeats hourly.** A store the
//! node deliberately did not advertise because it has not finished syncing is not a funding problem
//! — advertising a store it cannot serve is the bug, and withholding is the fix. Counting those
//! stores into a shortfall makes the app cry wolf, every hour, about a node doing the right thing;
//! and a user who silences an hourly false alarm has silenced the true one too. So
//! [`Shortfall::of`] filters on [`StoreCoinState`] before it counts anything, and there is a test
//! whose fixture is an entirely-unsynced node asserting silence.
//!
//! # $DIG and XCH are not interchangeable
//!
//! * **Out of $DIG** — new stores cannot be collateralised. Existing coins are untouched, and
//!   reclaim still works because reclaim's cost is an XCH fee.
//! * **Out of XCH** — the node can neither create *nor reclaim*: `melt` pays its own fee in XCH
//!   (legacy `ServerCoin.ts:136`), so a wallet at zero XCH has $DIG locked on chain and no way to
//!   get it back. That is strictly the worse state and it gets its own wording.
//!
//! # What the copy may not say
//!
//! **It must not imply content is unavailable.** Nothing gates a read on a mirror coin; the node
//! keeps serving every byte it served before. What is lost is DISCOVERABILITY and payment
//! eligibility — the node is invisible to other nodes' sync and to the incentive round. Unseen and
//! unpaid, not down. [`Shortfall::body`] is swept by a test against the words that would make that
//! false claim.
//!
//! # Stopping is gated on the money, not on a clock
//!
//! [`Reminder::due`] asks the CURRENT shortfall on every tick. Funding the wallet stops the
//! repetition on the next tick regardless of how much of the hour is left, because the alternative —
//! a timer that has to run down after the problem is fixed — is a notification that lies about the
//! present. It is also the cheaper half of the mitigation for the one risk the user accepted
//! knowingly: an hourly notification is the kind of thing people silence at the OS level, which
//! kills it permanently and silently, including for the `CannotReclaim` case where their money is
//! stuck.

use std::time::Duration;

use crate::amount::amount_with_unit;
use crate::notify::{Notification, Route};
use crate::wallet::state::Asset;

/// How long between repeats while the shortfall persists.
pub const REPEAT_EVERY: Duration = Duration::from_secs(60 * 60);

/// Why one maintained store has no mirror coin.
///
/// Kept as an enum rather than a `bool` on the store because the three arms lead to three different
/// actions, and a boolean would force the two that are NOT funding problems to pick a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreCoinState {
    /// The store is collateralised. Nothing to say.
    Collateralised,
    /// The node wanted to collateralise it and the wallet was short. **A funding problem.**
    WantsCollateral,
    /// The node deliberately did not advertise it, because the store is not synced far enough to
    /// serve. **Correct behaviour, and never a funding problem** — see the module docs.
    WithheldUnsynced,
    /// The store's collateral should be released and cannot be, because reclaim needs an XCH fee.
    /// **The worst state: money locked with no way out.**
    WantsReclaim,
}

impl StoreCoinState {
    /// Whether this store's state is caused by the wallet being short.
    ///
    /// The single predicate every counter here goes through, so "is this a funding problem" has one
    /// answer rather than one per call site.
    pub fn is_a_funding_problem(self) -> bool {
        matches!(self, Self::WantsCollateral | Self::WantsReclaim)
    }
}

/// What the node needs, in the asset it needs it in.
///
/// [`None`](Self::None) is a first-class arm rather than an `Option` wrapper because "funded" is the
/// state the [`Reminder`] gates on, and giving it a name makes the gate read as what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shortfall {
    /// Nothing is short. The notification does not fire, and any repetition stops.
    None,
    /// Short of $DIG for collateral. Existing coins are fine and reclaim still works.
    OutOfDig {
        /// How much more $DIG is needed, in base units.
        short_base_units: u64,
        /// How many stores are waiting on it.
        stores: u32,
    },
    /// Short of XCH for fees, with nothing locked that needs releasing.
    OutOfXch {
        /// How much more XCH is needed, in mojos.
        short_mojos: u64,
        /// How many stores are waiting on it.
        stores: u32,
    },
    /// Short of XCH **and** collateral is stranded because reclaim cannot pay its own fee.
    ///
    /// Ranked above [`OutOfXch`](Self::OutOfXch) by [`Shortfall::of`] and worded differently,
    /// because the consequence is not "cannot do a thing" but "cannot undo a thing already done".
    CannotReclaim {
        /// How much more XCH is needed, in mojos.
        short_mojos: u64,
        /// How many stores hold collateral that cannot be released.
        stores: u32,
    },
}

/// What the node holds and what it needs, as the notifier sees it.
///
/// A plain struct of measured figures. It carries no `Option` for "unknown": a caller that has not
/// measured the wallet must not build one, because a zero balance and an unmeasured balance produce
/// the same shortfall arithmetic and only one of them is a reason to interrupt somebody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingFacts {
    /// Confirmed spendable $DIG, in base units.
    pub dig_base_units: u64,
    /// Confirmed spendable XCH, in mojos.
    pub xch_mojos: u64,
    /// $DIG needed per store that wants collateral, in base units.
    pub dig_per_store: u64,
    /// XCH needed per fee-paying action, in mojos.
    pub fee_mojos: u64,
    /// Each maintained store's coin state.
    pub stores: Vec<StoreCoinState>,
}

impl Shortfall {
    /// What the node is short of, given what it holds and what its stores need.
    ///
    /// # Ordering, and why XCH outranks $DIG
    ///
    /// A wallet can be short of both. Only one notification fires, so one has to win, and it is the
    /// XCH arm: without XCH the node can neither create nor reclaim, so adding $DIG first buys
    /// nothing at all. Telling someone to add $DIG while the actual blocker is a missing fee sends
    /// them to spend money that will not move the situation.
    pub fn of(facts: &FundingFacts) -> Self {
        let wanting_reclaim = facts
            .stores
            .iter()
            .filter(|state| matches!(state, StoreCoinState::WantsReclaim))
            .count() as u32;
        let wanting_collateral = facts
            .stores
            .iter()
            .filter(|state| matches!(state, StoreCoinState::WantsCollateral))
            .count() as u32;

        // Nothing is a funding problem, so nothing is said — however many stores are withheld for
        // being unsynced, which is the case this early return exists to keep silent.
        if wanting_reclaim == 0 && wanting_collateral == 0 {
            return Self::None;
        }

        // One fee per action the node still owes. A wallet that can pay for some but not all of them
        // is still short, which is why this compares against the total rather than against one fee.
        let fees_owed = u64::from(wanting_reclaim + wanting_collateral);
        let xch_needed = facts.fee_mojos.saturating_mul(fees_owed);
        if facts.xch_mojos < xch_needed {
            let short_mojos = xch_needed - facts.xch_mojos;
            return match wanting_reclaim {
                0 => Self::OutOfXch {
                    short_mojos,
                    stores: wanting_collateral,
                },
                stores => Self::CannotReclaim {
                    short_mojos,
                    stores,
                },
            };
        }

        let dig_needed = facts
            .dig_per_store
            .saturating_mul(u64::from(wanting_collateral));
        if facts.dig_base_units < dig_needed {
            return Self::OutOfDig {
                short_base_units: dig_needed - facts.dig_base_units,
                stores: wanting_collateral,
            };
        }

        Self::None
    }

    /// Whether this shortfall is worth interrupting somebody about.
    pub fn is_short(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// The notification title. Leads with the ACTION, not with the subsystem name — a toast is two
    /// lines and "DIG mirror-coin maintenance" spends the first one saying nothing actionable.
    pub fn title(&self) -> Option<String> {
        Some(match self {
            Self::None => return None,
            Self::OutOfDig { .. } => "Add $DIG to keep your stores discoverable".to_string(),
            Self::OutOfXch { .. } => "Add XCH to cover DIG's network fees".to_string(),
            Self::CannotReclaim { .. } => {
                "Add XCH — your locked $DIG cannot be released".to_string()
            }
        })
    }

    /// The notification body: how much, how many stores, and what it actually costs right now.
    pub fn body(&self) -> Option<String> {
        Some(match self {
            Self::None => return None,
            Self::OutOfDig {
                short_base_units,
                stores,
            } => format!(
                "{} short for {}. They stay online and readable, but other nodes cannot find them and they earn nothing.",
                amount_with_unit(Asset::DIG, *short_base_units),
                stores_phrase(*stores),
            ),
            Self::OutOfXch {
                short_mojos,
                stores,
            } => format!(
                "{} short for network fees on {}. They stay online and readable, but other nodes cannot find them and they earn nothing.",
                amount_with_unit(Asset::Xch, *short_mojos),
                stores_phrase(*stores),
            ),
            Self::CannotReclaim {
                short_mojos,
                stores,
            } => format!(
                "{} short for the fee that releases collateral, so the $DIG locked against {} is stuck until XCH arrives.",
                amount_with_unit(Asset::Xch, *short_mojos),
                stores_phrase(*stores),
            ),
        })
    }

    /// The whole notification, or `None` when there is nothing to say.
    ///
    /// Carries [`Route::Deposit`] so a host that can deliver a click lands the user where funds are
    /// added. **The copy never mentions the click**, and that is deliberate: on a host that cannot
    /// route one, a body reading "click here to add funds" is a dead end, and this notification's
    /// whole job is to be actionable on its own. There is a test over every arm pinning it.
    pub fn notification(&self) -> Option<Notification> {
        Some(Notification {
            title: self.title()?,
            body: self.body()?,
            route: Some(Route::Deposit),
        })
    }
}

/// `1 store` / `3 stores`, so no body has to carry its own plural.
fn stores_phrase(stores: u32) -> String {
    match stores {
        1 => "1 store".to_string(),
        n => format!("{n} stores"),
    }
}

/// The hourly repeat, as a pure decision over a clock the caller supplies.
///
/// # Why the shortfall is an argument to [`due`](Self::due) rather than stored
///
/// The stop condition is *"funds are sufficient"*, not *"an hour has not elapsed"*. Storing the
/// shortfall at the moment the first notification fired would mean the reminder keeps re-asking a
/// question it answered before the user topped up. Passing the CURRENT shortfall in on every tick is
/// what makes funding the wallet stop the repetition on the next tick, with no timer to run down.
///
/// # Why a changed shortfall fires immediately
///
/// A wallet that goes from "short of $DIG" to "cannot release your locked $DIG" has become a
/// materially worse situation, and holding that news for the remainder of the hour is holding the
/// one message that was urgent. So a change of arm resets the clock and speaks; only an UNCHANGED
/// shortfall waits out the hour.
#[derive(Debug, Clone, Default)]
pub struct Reminder {
    last: Option<(Shortfall, Duration)>,
}

impl Reminder {
    /// A reminder that has said nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The notification to show at `now`, or `None` to stay quiet.
    ///
    /// `now` is a monotonic elapsed duration rather than a wall-clock instant, so a machine that
    /// sleeps or has its clock corrected cannot produce a negative interval and silence the reminder
    /// indefinitely.
    pub fn due(&mut self, shortfall: &Shortfall, now: Duration) -> Option<Notification> {
        if !shortfall.is_short() {
            // Funded. Forget everything, so the NEXT shortfall speaks at once rather than waiting
            // out an hour measured from a problem that is over.
            self.last = None;
            return None;
        }

        let speak = match &self.last {
            None => true,
            Some((said, _)) if said != shortfall => true,
            Some((_, at)) => now.saturating_sub(*at) >= REPEAT_EVERY,
        };
        if !speak {
            return None;
        }
        self.last = Some((shortfall.clone(), now));
        shortfall.notification()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with plenty of everything and `stores` in the given states.
    fn facts(stores: Vec<StoreCoinState>) -> FundingFacts {
        FundingFacts {
            dig_base_units: 1_000_000,
            xch_mojos: 1_000_000_000_000,
            dig_per_store: 20_000,
            fee_mojos: 1_000_000,
            stores,
        }
    }

    /// **An entirely-unsynced node says nothing**, however many stores it is withholding.
    ///
    /// This is the crying-wolf case. The nearest wrong implementation counts every store without a
    /// coin, so the fixture is built so that the wrong version would find FIVE uncollateralised
    /// stores and fire — the count is deliberately large, and the wallet is deliberately rich, so
    /// the only thing that can produce silence is the state filter itself rather than an incidental
    /// zero somewhere.
    #[test]
    fn a_node_withholding_unsynced_stores_is_not_out_of_funds() {
        let unsynced = facts(vec![StoreCoinState::WithheldUnsynced; 5]);
        assert_eq!(Shortfall::of(&unsynced), Shortfall::None);
        assert!(Shortfall::of(&unsynced).notification().is_none());
    }

    /// **And an unsynced store beside a genuinely-short one does not inflate the count.**
    ///
    /// Varying ONE actor while keeping a truthful control: the same wallet, one store that really
    /// wants collateral and three that are merely unsynced. An implementation that counted all four
    /// would report a shortfall four times too large and name four stores, so the assertion checks
    /// the FIGURE, not merely that something fired.
    #[test]
    fn an_unsynced_store_is_not_counted_into_a_real_shortfall() {
        let mut mixed = facts(vec![
            StoreCoinState::WantsCollateral,
            StoreCoinState::WithheldUnsynced,
            StoreCoinState::WithheldUnsynced,
            StoreCoinState::WithheldUnsynced,
        ]);
        mixed.dig_base_units = 0;
        assert_eq!(
            Shortfall::of(&mixed),
            Shortfall::OutOfDig {
                short_base_units: 20_000,
                stores: 1,
            },
            "one store wants collateral; the other three are the node behaving correctly"
        );
    }

    /// **A collateralised store is not a shortfall either** — the truthful control for the filter.
    #[test]
    fn a_fully_collateralised_node_is_silent() {
        assert_eq!(
            Shortfall::of(&facts(vec![StoreCoinState::Collateralised; 3])),
            Shortfall::None
        );
    }

    /// **Missing XCH outranks missing $DIG**, because adding $DIG while the fee is unpayable buys
    /// nothing.
    ///
    /// The fixture is short of BOTH — which is the only input that can distinguish the ordering from
    /// either single-asset check. A version that tested $DIG first would return `OutOfDig` here and
    /// send the user to buy the wrong token.
    #[test]
    fn a_wallet_short_of_both_is_told_about_the_fee_first() {
        let mut broke = facts(vec![StoreCoinState::WantsCollateral]);
        broke.dig_base_units = 0;
        broke.xch_mojos = 0;
        assert_eq!(
            Shortfall::of(&broke),
            Shortfall::OutOfXch {
                short_mojos: 1_000_000,
                stores: 1,
            }
        );
    }

    /// **A store that needs releasing outranks one that needs creating**, and gets the worse-state
    /// wording.
    ///
    /// Both stores are present in the fixture, so the assertion distinguishes the ranking rather
    /// than confirming a single-arm input.
    #[test]
    fn stranded_collateral_outranks_an_uncreated_coin() {
        let mut stuck = facts(vec![
            StoreCoinState::WantsCollateral,
            StoreCoinState::WantsReclaim,
        ]);
        stuck.xch_mojos = 0;
        let shortfall = Shortfall::of(&stuck);
        assert_eq!(
            shortfall,
            Shortfall::CannotReclaim {
                short_mojos: 2_000_000,
                stores: 1,
            },
            "two fees are owed; one store's collateral is the stranded one"
        );
        let title = shortfall.title().expect("a shortfall speaks");
        assert!(
            title.contains("cannot be released"),
            "the worse state is worded as the worse state: {title}"
        );
    }

    /// **Out of $DIG says the existing coins are fine**, by not claiming otherwise, and names $DIG
    /// rather than XCH.
    #[test]
    fn the_two_assets_get_different_words() {
        let mut no_dig = facts(vec![StoreCoinState::WantsCollateral]);
        no_dig.dig_base_units = 0;
        let dig = Shortfall::of(&no_dig).notification().expect("fires");
        assert!(dig.title.contains("$DIG"), "{}", dig.title);
        assert!(dig.body.contains("20 $DIG"), "{}", dig.body);

        let mut no_xch = facts(vec![StoreCoinState::WantsCollateral]);
        no_xch.xch_mojos = 0;
        let xch = Shortfall::of(&no_xch).notification().expect("fires");
        assert!(xch.title.contains("XCH"), "{}", xch.title);
        assert!(
            !xch.title.contains("$DIG"),
            "an XCH shortfall must not send somebody to buy $DIG: {}",
            xch.title
        );
    }

    /// **No notification may imply the content went away.**
    ///
    /// Swept over every arm rather than the one being worked on, because the false claim is a
    /// property of the COPY and a new arm would arrive without this guard otherwise. The banned
    /// words are the ones a person reads as "my site is down".
    #[test]
    fn no_body_claims_the_content_is_unavailable() {
        let arms = [
            Shortfall::OutOfDig {
                short_base_units: 20_000,
                stores: 2,
            },
            Shortfall::OutOfXch {
                short_mojos: 1_000_000,
                stores: 2,
            },
            Shortfall::CannotReclaim {
                short_mojos: 1_000_000,
                stores: 2,
            },
        ];
        for arm in arms {
            let body = arm.body().expect("every short arm speaks");
            for banned in [
                "offline",
                "unavailable",
                "cannot be read",
                "stopped serving",
                "no longer available",
                "taken down",
            ] {
                assert!(
                    !body.to_lowercase().contains(banned),
                    "{arm:?} implies the content is gone via {banned:?}: {body}"
                );
            }
        }
    }

    /// **The two creation arms say what is actually lost**: discovery and earnings, not reads.
    #[test]
    fn the_body_names_discoverability_rather_than_availability() {
        let body = Shortfall::OutOfDig {
            short_base_units: 20_000,
            stores: 1,
        }
        .body()
        .expect("fires");
        assert!(body.contains("readable"), "{body}");
        assert!(body.contains("cannot find them"), "{body}");
        assert!(body.contains("earn nothing"), "{body}");
    }

    /// **Once an hour while it persists, and not more often.**
    ///
    /// The at-bound and one-under cases are BOTH pinned: 59m59s must stay silent and exactly 60m
    /// must speak, because a repeat interval tested only from one side can only confirm itself.
    #[test]
    fn an_unchanged_shortfall_repeats_hourly_and_not_sooner() {
        let short = Shortfall::OutOfDig {
            short_base_units: 20_000,
            stores: 1,
        };
        let mut reminder = Reminder::new();
        assert!(
            reminder.due(&short, Duration::ZERO).is_some(),
            "the first one is immediate"
        );
        assert!(
            reminder.due(&short, Duration::from_secs(3_599)).is_none(),
            "one second under the hour stays quiet"
        );
        assert!(
            reminder.due(&short, REPEAT_EVERY).is_some(),
            "exactly on the hour it repeats"
        );
        assert!(
            reminder
                .due(&short, REPEAT_EVERY + Duration::from_secs(1))
                .is_none(),
            "and the clock restarts from the repeat, not from the first"
        );
    }

    /// **Funding the wallet stops it on the very next tick**, mid-hour, with no timer to run down.
    ///
    /// The fixture ticks at 10 seconds — deep inside the hour — precisely because a version gated on
    /// the clock rather than on the money would still be quiet at that moment for the WRONG reason.
    /// So the test does not merely assert silence: it funds, ticks, and then asserts that a NEW
    /// shortfall at the same instant speaks immediately, which only holds if the funded tick
    /// genuinely cleared the state rather than coincidentally being early.
    #[test]
    fn sufficient_funds_stop_the_repetition_immediately() {
        let short = Shortfall::OutOfDig {
            short_base_units: 20_000,
            stores: 1,
        };
        let mut reminder = Reminder::new();
        assert!(reminder.due(&short, Duration::ZERO).is_some());

        let mid_hour = Duration::from_secs(10);
        assert!(
            reminder.due(&Shortfall::None, mid_hour).is_none(),
            "a funded wallet says nothing"
        );
        assert!(
            reminder.due(&short, mid_hour).is_some(),
            "and having been funded, a fresh shortfall speaks at once rather than waiting out an \
             hour measured from a problem that is over"
        );
    }

    /// **A shortfall that gets WORSE speaks immediately** rather than sitting on the urgent news for
    /// the rest of the hour.
    #[test]
    fn a_changed_shortfall_does_not_wait_out_the_hour() {
        let mut reminder = Reminder::new();
        let dig = Shortfall::OutOfDig {
            short_base_units: 20_000,
            stores: 1,
        };
        assert!(reminder.due(&dig, Duration::ZERO).is_some());
        let stuck = Shortfall::CannotReclaim {
            short_mojos: 1_000_000,
            stores: 1,
        };
        let spoken = reminder
            .due(&stuck, Duration::from_secs(5))
            .expect("the worse state is not held back");
        assert!(
            spoken.title.contains("cannot be released"),
            "{}",
            spoken.title
        );
    }

    /// **`None` never renders a notification**, at either layer — the title, the body and the whole
    /// thing all decline together, so no caller can assemble a toast out of half an answer.
    #[test]
    fn a_funded_wallet_has_nothing_to_render() {
        assert!(Shortfall::None.title().is_none());
        assert!(Shortfall::None.body().is_none());
        assert!(Shortfall::None.notification().is_none());
        assert!(!Shortfall::None.is_short());
    }

    /// **The funding-problem predicate is the filter the counters use.**
    #[test]
    fn only_two_states_are_funding_problems() {
        assert!(StoreCoinState::WantsCollateral.is_a_funding_problem());
        assert!(StoreCoinState::WantsReclaim.is_a_funding_problem());
        assert!(!StoreCoinState::WithheldUnsynced.is_a_funding_problem());
        assert!(!StoreCoinState::Collateralised.is_a_funding_problem());
    }

    /// **The copy never depends on the click working.**
    ///
    /// On a host that cannot deliver an activation — which is most of them today — a body reading
    /// "click here to add funds" is a dead end, and this is the notification whose whole job is to
    /// be actionable on its own. Swept over every arm rather than the one being written, because a
    /// new arm would arrive without this guard otherwise, and checked over the TITLE as well as the
    /// body since a title is the part people actually read.
    #[test]
    fn no_copy_instructs_the_user_to_click_the_notification() {
        for arm in [
            Shortfall::OutOfDig {
                short_base_units: 20_000,
                stores: 1,
            },
            Shortfall::OutOfXch {
                short_mojos: 1_000_000,
                stores: 1,
            },
            Shortfall::CannotReclaim {
                short_mojos: 1_000_000,
                stores: 1,
            },
        ] {
            let toast = arm.notification().expect("every short arm speaks");
            for text in [&toast.title, &toast.body] {
                for banned in ["click", "tap", "press here", "select this"] {
                    assert!(
                        !text.to_lowercase().contains(banned),
                        "{arm:?} promises an interaction the host may not deliver: {text}"
                    );
                }
            }
            assert!(
                toast.title.to_lowercase().starts_with("add "),
                "the actionable fact leads, not the subsystem name: {}",
                toast.title
            );
        }
    }

    /// **Every out-of-funds notification asks for deposit, and lands on the Wallet tab.**
    ///
    /// The route is checked through to the TAB rather than stopping at the enum, because "carries a
    /// route" and "reaches the place you add funds" are different claims and only the second is the
    /// requirement.
    #[test]
    fn the_notification_routes_to_where_funds_are_added() {
        let toast = Shortfall::OutOfDig {
            short_base_units: 20_000,
            stores: 1,
        }
        .notification()
        .expect("fires");
        assert_eq!(toast.route, Some(Route::Deposit));
        assert_eq!(
            toast.route.expect("routed").tab(),
            crate::window_model::TabId::Wallet
        );
    }

    /// **One store is `1 store`.**
    #[test]
    fn the_store_phrase_reads_at_every_count() {
        assert_eq!(stores_phrase(1), "1 store");
        assert_eq!(stores_phrase(4), "4 stores");
    }
}
