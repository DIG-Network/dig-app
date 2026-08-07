//! The one place dig-app turns a base-unit integer into a figure a person reads.
//!
//! # Why this is a module and not a function in each surface
//!
//! An amount is meaningless without the number of decimals its asset carries, and the two assets
//! dig-app holds do NOT agree: native Chia is 12 decimals (mojos), while $DIG is a CAT and carries
//! **3** — `1 $DIG = 1_000` base units. A formatter that takes only the integer therefore renders one
//! of the two assets wrong by a factor of a billion, silently and confidently, which is exactly the
//! defect dig_ecosystem#2295 fixed: the Wallet tab showed a whole $DIG as `0.000000001`.
//!
//! That defect existed *beside* a correct asset-aware formatter in the same crate, and beside a
//! doc-comment in [`crate::decode`] warning against the mistake in prose. Two implementations of a
//! money rendering will drift, and the drift is a wrong number on a money surface — so there is one
//! implementation, here, and every surface asks it. The asset decides the divisor; a caller cannot
//! omit the asset, because the type will not let it.

use crate::wallet::state::Asset;

/// Decimal places in native Chia: one XCH is 10^12 mojos.
pub const XCH_DECIMALS: u32 = 12;

/// Decimal places in a Chia CAT, $DIG included: one $DIG is 10^3 base units.
///
/// This is the CAT convention, not a dig-app choice — see [`crate::decode`], whose decoder refuses to
/// render CAT amounts as XCH for the same reason.
pub const CAT_DECIMALS: u32 = 3;

impl Asset {
    /// How many decimal places this asset's base unit sits behind one whole coin.
    pub const fn decimals(self) -> u32 {
        match self {
            Asset::Xch => XCH_DECIMALS,
            Asset::Dig => CAT_DECIMALS,
        }
    }
}

/// Render a base-unit amount of `asset` as a whole-coin decimal (`1`, `2.5`, `0`).
///
/// The inverse never has to be guessed: `format_asset_amount(Asset::Dig, 1_000) == "1"`, because a
/// $DIG carries [`CAT_DECIMALS`] places.
pub fn format_asset_amount(asset: Asset, base_units: u64) -> String {
    format_units(u128::from(base_units), asset.decimals())
}

/// Render a base-unit amount as a whole-coin decimal, given the asset's decimal places.
///
/// Trailing zeros are trimmed so the value is glanceable (`1.5`, not `1.500000000000`), but nothing is
/// ROUNDED away: a sub-unit amount renders every place it needs, because a held amount displayed as
/// `0` is how a person concludes their money is gone.
///
/// Takes `decimals` rather than an [`Asset`] so that the surfaces which cannot name one still share
/// this arithmetic instead of copying it: the notification path knows an asset only as an on-chain id
/// and must render CATs there is no [`Asset`] variant for, and the confirm window's spend summary is
/// XCH-only by construction. Deliberately `pub(crate)` — it is the one way to reach the arithmetic
/// without naming an asset, and outside the crate that hatch would be the next wrong divisor.
pub(crate) fn format_units(base_units: u128, decimals: u32) -> String {
    let divisor = 10u128.pow(decimals);
    let whole = base_units / divisor;
    let fraction = base_units % divisor;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:0width$}", width = decimals as usize);
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two assets do not share a divisor.** Both expectations are derived from the CONTRACT —
    /// one whole coin is `10^decimals` base units — rather than transcribed from a run, because the
    /// test this replaces recorded the output of the wrong constant and passed on the bug.
    #[test]
    fn one_whole_coin_renders_as_one_in_each_asset() {
        assert_eq!(
            format_asset_amount(Asset::Dig, 10u64.pow(CAT_DECIMALS)),
            "1"
        );
        assert_eq!(
            format_asset_amount(Asset::Xch, 10u64.pow(XCH_DECIMALS)),
            "1"
        );
    }

    /// The literal a person would type: 1000 base units is one $DIG, and a whole $DIG is NOT
    /// 10^12 base units — under the pre-#2295 divisor that value was 3.4 billion $DIG.
    #[test]
    fn a_dig_is_a_thousand_base_units_not_a_trillion() {
        assert_eq!(format_asset_amount(Asset::Dig, 1_000), "1");
        assert_eq!(
            format_asset_amount(Asset::Dig, 1_000_000_000_000),
            "1000000000"
        );
    }

    /// A fraction renders its own asset's precision, in both assets, with trailing zeros trimmed.
    #[test]
    fn fractions_carry_each_assets_own_precision() {
        assert_eq!(format_asset_amount(Asset::Dig, 1_500), "1.5");
        assert_eq!(format_asset_amount(Asset::Xch, 1_500_000_000_000), "1.5");
        // The smallest holdable amount of each asset is shown, never rounded to a zero.
        assert_eq!(format_asset_amount(Asset::Dig, 1), "0.001");
        assert_eq!(format_asset_amount(Asset::Xch, 1), "0.000000000001");
    }

    /// A genuine zero is a bare `0` in either asset — no decimal point, no false precision.
    #[test]
    fn zero_renders_as_a_bare_zero_in_both_assets() {
        assert_eq!(format_asset_amount(Asset::Dig, 0), "0");
        assert_eq!(format_asset_amount(Asset::Xch, 0), "0");
    }

    /// The largest holdable amount does not overflow or lose a digit in either asset.
    #[test]
    fn the_maximum_holding_renders_exactly() {
        assert_eq!(
            format_asset_amount(Asset::Xch, u64::MAX),
            "18446744.073709551615"
        );
        assert_eq!(
            format_asset_amount(Asset::Dig, u64::MAX),
            "18446744073709551.615"
        );
    }

    /// The decimals a caller gets are the asset's own, so a new surface cannot pick the wrong one.
    #[test]
    fn each_asset_states_its_own_decimals() {
        assert_eq!(Asset::Xch.decimals(), XCH_DECIMALS);
        assert_eq!(Asset::Dig.decimals(), CAT_DECIMALS);
        assert_ne!(Asset::Xch.decimals(), Asset::Dig.decimals());
    }
}
