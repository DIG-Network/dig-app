//! The collateral **safety margin**: how much more than an epoch's requirement this node posts,
//! and what that choice costs (dig-app#298, epic dig_ecosystem#3173).
//!
//! # The margin is local. It is never consensus.
//!
//! A mirror advertisement is counted in an epoch only if it posts at least that epoch's derived
//! per-store requirement. The requirement is a consensus value: every node derives it from the
//! same chain census through [`dig_mirror_collateral`], and a single differing DIG base unit forks the
//! network. **This setting does not touch that derivation.** It changes only how much *this*
//! machine chooses to lock over the top, and nothing here enters a census, a controller signal,
//! or any value another node derives. That separation is why the arithmetic lives in the
//! consensus crate's one deliberately non-consensus function,
//! [`apply_safety_margin`](dig_mirror_collateral::apply_safety_margin), and why this module calls
//! it rather than re-deriving it — a second implementation of a rounding rule on a money path is
//! the byte-drift bug the ecosystem's crate-reuse rule exists to prevent.
//!
//! # Why the default errs high
//!
//! The failure is asymmetric. Posting under the requirement means the advertisement is not
//! counted and the node is likely skipped for that epoch's rewards. Posting over it carries no
//! penalty at all — only the opportunity cost of $DIG that could have been used elsewhere. So the
//! shipped default is [`SAFETY_MARGIN_BP_DEFAULT`] (+1%), and the presets bracket it.
//!
//! **None of that is a guarantee, and no copy here says it is.** The requirement is re-derived
//! every epoch and can rise by more than any margin an operator picked. A margin reduces the
//! chance of falling short; it does not promise inclusion.
//!
//! # Why the cost is a reading and not a number
//!
//! A bare "5%" tells an operator nothing they can decide on. What they need is the extra $DIG this
//! margin locks *at the current requirement, across the stores this node holds* — and that number
//! exists only when both of those facts are known.
//!
//! dig-app cannot derive the requirement for itself: like every chain value, it belongs to the
//! node (there is no `control.*` method that serves it today, so in production the requirement is
//! genuinely absent). Showing a cost computed from an assumed or stale requirement would be a
//! confident wrong number about money. So [`CostReading`] carries the same pending/known/unknown
//! split as [`BalanceReading`](crate::wallet::overview::BalanceReading) and
//! [`HostedStoresReading`](crate::hosted_stores::HostedStoresReading), for the same reason and
//! after the same defect: **there is no path in this module that turns an unknown into a zero.**

pub mod node;

use serde::{Deserialize, Serialize};

use crate::amount::amount_with_unit;
use crate::hosted_stores::{HostedStoresReading, HostedStoresUnknown};
use crate::wallet::state::Asset;

pub use dig_mirror_collateral::{
    SAFETY_MARGIN_BP_DEFAULT, SAFETY_MARGIN_BP_GENEROUS, SAFETY_MARGIN_BP_TIGHT,
    SAFETY_MARGIN_PRESETS_BP,
};

/// Basis points in one whole unit — 10 000, so 100 bp is 1%.
///
/// Re-exported from the consensus crate rather than restated, so the app and the arithmetic can
/// never disagree about what "1%" means.
pub use dig_mirror_collateral::BASIS_POINTS_SCALE;

/// The largest margin this app will store: 100% over the requirement.
///
/// Not a protocol bound — the arithmetic saturates safely far above it. It exists because a margin
/// is a form of self-harm past a point, and a value beyond doubling the requirement is far likelier
/// to be a slip than an intent. Nothing in the shipped UI can reach it (the presets stop at 5%);
/// it bounds what a hand-edited `agent.json` can put into effect.
pub const MAX_MARGIN_BP: u64 = 10_000;

/// How much over the epoch requirement this node posts, in basis points.
///
/// A newtype rather than a bare `u64` field on [`AgentConfig`](crate::config::AgentConfig) for the
/// reason [`AutoUpdate`](crate::auto_update::AutoUpdate) is one: an `agent.json` written before
/// this setting existed must load as the *shipped default*, not as `0`. A missing `u64` would
/// deserialize to zero — the exact under-collateralised state the default exists to avoid —
/// whereas a missing struct takes this type's [`Default`].
///
/// **Stored in basis points**, which is the unit
/// [`apply_safety_margin`](dig_mirror_collateral::apply_safety_margin) takes and the unit the
/// presets are already named in. The `dign` CLI (dig-node#388) persists the same integer under the
/// same key: a margin that meant 1% on one surface and something else on the other would be a
/// drift bug on a money path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyMargin {
    /// Basis points over the requirement. `100` is +1%.
    #[serde(default = "default_margin_bp")]
    pub margin_bp: u64,
}

fn default_margin_bp() -> u64 {
    SAFETY_MARGIN_BP_DEFAULT
}

impl Default for SafetyMargin {
    /// +1% — the shipped default, erring high because the failure is asymmetric (see the module
    /// documentation).
    fn default() -> Self {
        Self {
            margin_bp: SAFETY_MARGIN_BP_DEFAULT,
        }
    }
}

impl SafetyMargin {
    /// A margin of `margin_bp` basis points, clamped to [`MAX_MARGIN_BP`].
    ///
    /// Clamping rather than rejecting: every reachable caller is a preset or a file this app also
    /// writes, and a value past the ceiling is still a coherent instruction ("as much as you are
    /// allowed"). Refusing it would leave the node on whatever it held before, which is the
    /// *lower* posting — the direction a safety margin must never fail in.
    #[must_use]
    pub fn of_basis_points(margin_bp: u64) -> Self {
        Self {
            margin_bp: margin_bp.min(MAX_MARGIN_BP),
        }
    }

    /// What this node posts per store against `required_per_store_dig_base_units`.
    ///
    /// Delegated to [`dig_mirror_collateral::apply_safety_margin`] — the one implementation of this
    /// rounding, which rounds **up** so a margin can never leave the node a base unit short, and
    /// saturates rather than wrapping.
    #[must_use]
    pub fn posted_per_store(self, required_per_store_dig_base_units: u64) -> u64 {
        dig_mirror_collateral::apply_safety_margin(
            required_per_store_dig_base_units,
            self.margin_bp,
        )
    }

    /// This margin as a percentage a person reads — `"0.01%"`, `"1%"`, `"5%"`.
    ///
    /// Rendered from the stored basis points on integer arithmetic, never a float: the label and
    /// the value applied are the same number said two ways, and a formatter that rounded
    /// separately could show `1%` for a stored `99`.
    #[must_use]
    pub fn percent_label(self) -> String {
        let whole = self.margin_bp / 100;
        let hundredths = self.margin_bp % 100;
        match hundredths {
            0 => format!("{whole}%"),
            _ if hundredths % 10 == 0 => format!("{whole}.{}%", hundredths / 10),
            _ => format!("{whole}.{hundredths:02}%"),
        }
    }

    /// Whether this is one of the presets the pane offers, and which.
    #[must_use]
    pub fn preset_index(self) -> Option<usize> {
        SAFETY_MARGIN_PRESETS_BP
            .iter()
            .position(|&bp| bp == self.margin_bp)
    }
}

/// What the app can honestly say the margin costs: a figure, a read in flight, or the reason there
/// is no figure.
///
/// The three states are separate variants, and [`Known`](CostReading::Known) can only be built
/// from a requirement the node actually reported together with a store list it actually answered.
/// So a zero here is always "this node holds no stores", never "nobody could tell us".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostReading {
    /// A read the cost depends on is under way and nothing has failed.
    Pending,
    /// Both facts are in hand, and this is what the margin costs.
    Known(MarginCost),
    /// No cost can be shown, and which thing is missing.
    Unknown(CostUnknown),
}

/// What a margin costs at a known requirement across a known number of stores.
///
/// Every field is derived from the two inputs and carried rather than recomputed by a renderer, so
/// the sentence a person reads and the amount the node would lock come from one calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarginCost {
    /// The epoch's derived requirement per store, in $DIG base units, **exactly as the node
    /// reported it**. The margin never alters this: it is the consensus value, and it is carried so
    /// the surface can show what is required beside what is posted.
    pub required_per_store_dig_base_units: u64,
    /// What this node posts per store — the requirement with the margin applied, rounded up.
    pub posted_per_store_dig_base_units: u64,
    /// How many stores this node holds, from the node's own answer.
    pub stores: u64,
    /// The total this node would lock across those stores at this margin.
    pub total_posted_dig_base_units: u64,
    /// The part of that total which is the margin — the extra $DIG locked, and the number the
    /// setting actually exists to let a person weigh.
    pub extra_locked_dig_base_units: u64,
}

impl MarginCost {
    /// The extra $DIG this margin locks, as a person reads it — `"0.24 $DIG"`.
    #[must_use]
    pub fn extra_with_unit(&self) -> String {
        amount_with_unit(Asset::DIG, self.extra_locked_dig_base_units)
    }

    /// The total this node would lock at this margin, as a person reads it.
    #[must_use]
    pub fn total_with_unit(&self) -> String {
        amount_with_unit(Asset::DIG, self.total_posted_dig_base_units)
    }
}

/// Why no cost figure is available. **One variant per remedy**, never per rough category — the
/// reason is the only thing that tells a person whether to wait, start their node, or upgrade it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostUnknown {
    /// No node has reported an epoch collateral requirement. Today this is the ordinary case: no
    /// `control.*` method serves the requirement yet, so the app cannot know it. Named rather than
    /// approximated — a cost computed from an assumed requirement would be a confident wrong number
    /// about money.
    NoRequirement,
    /// The requirement is known, but the node's store list could not be read, so the cost cannot be
    /// totalled. Carries the store reading's own reason, which already names its remedy.
    StoresUnknown(HostedStoresUnknown),
}

/// What this margin costs, given what the node has said about the requirement and the stores.
///
/// `required_per_store_dig_base_units` is the node's reported epoch requirement, `None` when nobody has
/// reported one. It is used **untouched** — the margin is applied to it, never folded into it.
///
/// Ordering of the states is deliberate. An absent requirement is [`CostUnknown::NoRequirement`]
/// even while the store list is still arriving, because that is the fact the operator can act on
/// and waiting on a store read would only delay saying so.
#[must_use]
pub fn cost(
    margin: SafetyMargin,
    required_per_store_dig_base_units: Option<u64>,
    stores: &HostedStoresReading,
) -> CostReading {
    let Some(required_per_store_dig_base_units) = required_per_store_dig_base_units else {
        return CostReading::Unknown(CostUnknown::NoRequirement);
    };
    let stores = match stores {
        HostedStoresReading::Pending => return CostReading::Pending,
        HostedStoresReading::Unknown(why) => {
            return CostReading::Unknown(CostUnknown::StoresUnknown(why.clone()))
        }
        HostedStoresReading::Known(held) => held.len() as u64,
    };

    let posted_per_store_dig_base_units =
        margin.posted_per_store(required_per_store_dig_base_units);
    // Saturating, for the reason the crate's own function saturates: an overflow that wrapped here
    // would render an enormous commitment as a tiny one, which is the single direction a surface
    // about locked money must never fail in.
    let total_posted_dig_base_units = posted_per_store_dig_base_units.saturating_mul(stores);
    let total_required_dig_base_units = required_per_store_dig_base_units.saturating_mul(stores);

    CostReading::Known(MarginCost {
        required_per_store_dig_base_units,
        posted_per_store_dig_base_units,
        stores,
        total_posted_dig_base_units,
        extra_locked_dig_base_units: total_posted_dig_base_units
            .saturating_sub(total_required_dig_base_units),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted_stores::HostedStore;

    /// A store list of `n` entries, for counting only — the fields do not participate in the cost.
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

    /// **The margin never posts LESS than the requirement it was given.**
    ///
    /// The one direction this arithmetic must never fail in, asserted here as well as in the crate
    /// because it is the property a user's money depends on and this app is the thing that picks
    /// the margin. The fixture deliberately includes `u64::MAX` on both axes: an unchecked
    /// implementation overflows exactly there and returns a *smaller* number than it was handed,
    /// which is how the safety margin becomes the failure it exists to prevent.
    #[test]
    fn a_margin_never_posts_less_than_the_requirement() {
        let requirements = [
            0,
            1,
            999,
            1_000,
            1_036,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        let margins = [0, 1, 100, 500, MAX_MARGIN_BP, u64::MAX];
        for required in requirements {
            for margin_bp in margins {
                let posted = SafetyMargin { margin_bp }.posted_per_store(required);
                assert!(
                    posted >= required,
                    "margin {margin_bp}bp posted {posted} against a requirement of {required}"
                );
            }
        }
    }

    /// **The default is +1% and it rounds UP.**
    ///
    /// `1_036` is chosen because 1% of it is `10.36` — a value with a fraction, so an
    /// implementation that truncated would post `1_046` and be a base unit short of the `1_046.36` it
    /// owes. A requirement whose margin divided evenly could not tell the two apart.
    #[test]
    fn the_default_margin_is_one_percent_rounded_up() {
        let margin = SafetyMargin::default();
        assert_eq!(margin.margin_bp, 100);
        assert_eq!(margin.posted_per_store(1_036), 1_047);
        assert_eq!(margin.percent_label(), "1%");
    }

    /// **A zero margin posts exactly the requirement**, not one base unit over.
    ///
    /// The control for the round-up above: without it, an implementation that unconditionally added
    /// one would satisfy every "never short" assertion in this file.
    #[test]
    fn a_zero_margin_posts_exactly_the_requirement() {
        assert_eq!(SafetyMargin { margin_bp: 0 }.posted_per_store(1_036), 1_036);
    }

    /// **Every shipped preset is offered, is distinct, and reads as the percentage it is.**
    #[test]
    fn the_presets_are_the_crates_own_and_read_correctly() {
        assert_eq!(SAFETY_MARGIN_PRESETS_BP, [1, 100, 500]);
        let labels: Vec<String> = SAFETY_MARGIN_PRESETS_BP
            .iter()
            .map(|&bp| SafetyMargin { margin_bp: bp }.percent_label())
            .collect();
        assert_eq!(labels, ["0.01%", "1%", "5%"]);
        assert_eq!(
            SafetyMargin::default().preset_index(),
            Some(1),
            "the default must be reachable in one press, not only by typing"
        );
        assert_eq!(
            SafetyMargin { margin_bp: 250 }.preset_index(),
            None,
            "a hand-edited margin is not silently drawn as a preset"
        );
        assert_eq!(SafetyMargin { margin_bp: 250 }.percent_label(), "2.5%");
    }

    /// **An unknown requirement is never drawn as a zero cost.**
    ///
    /// The fixture holds a store list that ANSWERED — three real stores — so the only missing fact
    /// is the requirement. A version that defaulted an absent requirement to `0` would produce a
    /// perfectly well-formed `Known` reading here, costing `0 $DIG`, and every "the total is
    /// right" assertion elsewhere would still pass.
    #[test]
    fn an_unknown_requirement_is_never_drawn_as_a_zero_cost() {
        let reading = cost(SafetyMargin::default(), None, &stores(3));
        assert_eq!(reading, CostReading::Unknown(CostUnknown::NoRequirement));
    }

    /// **A store read still in flight is pending, not a node holding nothing.**
    ///
    /// Distinguished from the answered-empty case below by the same fixture with a different store
    /// reading — so the pair fails if the two are ever collapsed, which is the defect
    /// `HostedStoresReading` was split to prevent.
    #[test]
    fn a_pending_store_read_is_not_an_empty_one() {
        let pending = cost(
            SafetyMargin::default(),
            Some(1_036),
            &HostedStoresReading::Pending,
        );
        assert_eq!(pending, CostReading::Pending);

        let answered_empty = cost(SafetyMargin::default(), Some(1_036), &stores(0));
        let CostReading::Known(held) = answered_empty else {
            panic!("a node that answered with no stores has a real, zero cost");
        };
        assert_eq!(held.stores, 0);
        assert_eq!(held.extra_locked_dig_base_units, 0);
    }

    /// **An unreadable store list carries its own remedy through**, rather than collapsing into a
    /// generic unknown that names nothing to do.
    #[test]
    fn an_unreadable_store_list_keeps_its_reason() {
        let reading = cost(
            SafetyMargin::default(),
            Some(1_036),
            &HostedStoresReading::Unknown(HostedStoresUnknown::Unauthorized),
        );
        assert_eq!(
            reading,
            CostReading::Unknown(CostUnknown::StoresUnknown(
                HostedStoresUnknown::Unauthorized
            ))
        );
    }

    /// **The cost is the extra locked across every store, and the requirement is carried
    /// untouched.**
    ///
    /// Four stores rather than one: with a single store the total and the per-store figure are the
    /// same number, so a version that forgot to multiply would be indistinguishable. And the extra
    /// is asserted as `posted - required` per store times the count (`11 * 4 = 44`), which a
    /// version that applied the margin to the TOTAL instead of to the per-store requirement would
    /// get wrong by the rounding — the placement this module exists to fix.
    #[test]
    fn the_cost_is_the_extra_locked_across_every_store() {
        let CostReading::Known(held) = cost(SafetyMargin::default(), Some(1_036), &stores(4))
        else {
            panic!("both facts are known here");
        };
        assert_eq!(
            held.required_per_store_dig_base_units, 1_036,
            "consensus value, untouched"
        );
        assert_eq!(held.posted_per_store_dig_base_units, 1_047);
        assert_eq!(held.stores, 4);
        assert_eq!(held.total_posted_dig_base_units, 1_047 * 4);
        assert_eq!(held.extra_locked_dig_base_units, 11 * 4);
        assert_eq!(held.extra_with_unit(), "0.044 $DIG");
        assert_eq!(held.total_with_unit(), "4.188 $DIG");
    }

    /// **A margin past the ceiling is clamped, never rejected into the lower posting.**
    #[test]
    fn an_absurd_margin_is_clamped_to_the_ceiling() {
        assert_eq!(
            SafetyMargin::of_basis_points(u64::MAX).margin_bp,
            MAX_MARGIN_BP
        );
        assert_eq!(SafetyMargin::of_basis_points(500).margin_bp, 500);
    }

    /// **An enormous requirement across many stores saturates rather than wrapping.**
    ///
    /// A wrapped total would render the largest commitment expressible as a trivial one — the same
    /// failure direction the crate's own saturation exists for, one layer up where the
    /// multiplication by the store count happens.
    #[test]
    fn an_enormous_total_saturates_rather_than_wrapping() {
        let CostReading::Known(held) = cost(
            SafetyMargin { margin_bp: 500 },
            Some(u64::MAX / 2),
            &stores(8),
        ) else {
            panic!("both facts are known here");
        };
        assert_eq!(held.total_posted_dig_base_units, u64::MAX);
        assert!(held.extra_locked_dig_base_units <= held.total_posted_dig_base_units);
    }
}
