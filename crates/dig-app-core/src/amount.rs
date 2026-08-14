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

/// Why a typed amount is not a number of base units.
///
/// One variant per thing a person can be TOLD, because the remedy differs: a field that answered
/// "invalid amount" to all five would leave someone who typed thirteen decimal places guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountProblem {
    /// Nothing was typed yet. Not an error a form should shout about — see the Wallet pane.
    Empty,
    /// The text is not a plain decimal number: a sign, a letter, a separator, a second point, or a
    /// point with no digits on one side of it.
    NotANumber,
    /// More decimal places than the asset HAS. Refused rather than rounded, because rounding a
    /// person's typed amount is the app deciding what they meant to pay.
    TooManyDecimals {
        /// How many places this asset carries.
        allowed: u32,
    },
    /// More base units than can exist: the asset's own arithmetic is `u64`.
    TooLarge,
}

/// Read a whole-coin decimal a person typed (`1`, `0.5`, `12.000000000001`) as base units of `asset`.
///
/// The exact inverse of [`format_asset_amount`], and it lives here for that reason: the divisor and
/// the multiplier are the same fact, and a second copy of it somewhere else is the drift that rendered
/// $DIG a billion times too small (dig_ecosystem#2295).
///
/// # Why the arithmetic is on the DIGITS and never on a float
///
/// `f64` carries about 15-17 significant decimal digits, and one XCH is 10^12 mojos — so a whole-coin
/// figure with twelve places needs up to 19. `"0.1"` is not representable at all. Parsing to `f64` and
/// multiplying therefore misstates an amount at the exact moment a person is authorising it, quietly
/// and by a few mojos. Here the integer part and the fraction part are parsed as integers and combined
/// as integers, so what is charged is what was typed.
///
/// # What is refused
///
/// Everything that is not an unsigned decimal with digits on both sides of any point: a leading `-` or
/// `+`, a bare `.5`, a trailing `1.`, thousands separators, exponents, and any amount whose base-unit
/// value exceeds [`u64::MAX`]. A fraction longer than the asset's own precision is refused rather than
/// truncated — see [`AmountProblem::TooManyDecimals`].
///
/// # Errors
///
/// [`AmountProblem`], naming which of those it was.
pub fn parse_asset_amount(asset: Asset, typed: &str) -> Result<u64, AmountProblem> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err(AmountProblem::Empty);
    }
    let decimals = asset.decimals();
    let (whole, fraction) = match typed.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (typed, ""),
    };
    // Digits on BOTH sides of the point, always. `.5` and `1.` are each one keystroke away from a
    // different number, and a form that guesses which one guesses about money.
    if !is_digits(whole) || (typed.contains('.') && !is_digits(fraction)) {
        return Err(AmountProblem::NotANumber);
    }
    if fraction.len() as u32 > decimals {
        return Err(AmountProblem::TooManyDecimals { allowed: decimals });
    }

    let whole: u128 = whole.parse().map_err(|_| AmountProblem::TooLarge)?;
    // The fraction's digits are scaled to the asset's own precision by PADDING, never by dividing:
    // "5" under twelve places is 500_000_000_000 base units, and every step of that is an integer.
    let scaled_fraction: u128 = match fraction.is_empty() {
        true => 0,
        false => {
            fraction
                .parse::<u128>()
                .map_err(|_| AmountProblem::TooLarge)?
                * 10u128.pow(decimals - fraction.len() as u32)
        }
    };
    whole
        .checked_mul(10u128.pow(decimals))
        .and_then(|units| units.checked_add(scaled_fraction))
        .and_then(|units| u64::try_from(units).ok())
        .ok_or(AmountProblem::TooLarge)
}

/// Whether `text` is a non-empty run of ASCII digits and nothing else.
///
/// ASCII deliberately: `char::is_numeric` accepts Devanagari and fullwidth digits, which `str::parse`
/// then refuses — two rules disagreeing about one field.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
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

    /// **What was typed round-trips through the formatter, at each asset's own scale.**
    ///
    /// The property both directions share: `parse(format(n)) == n`. Asserted at `u64::MAX` as well as
    /// at the small values, and that is the fixture that matters — a parser built on `f64` renders
    /// `18446744.073709551615` back as a value that has lost its last four digits, because the product
    /// needs 20 significant decimal digits and a double carries about 16. Small round numbers cannot
    /// see that; the maximum can.
    #[test]
    fn every_formatted_amount_parses_back_to_the_same_base_units() {
        for asset in [Asset::Xch, Asset::Dig] {
            for units in [
                0,
                1,
                1_000,
                1_500,
                10u64.pow(asset.decimals()),
                123_456_789,
                u64::MAX / 3,
                u64::MAX,
            ] {
                let rendered = format_asset_amount(asset, units);
                assert_eq!(
                    parse_asset_amount(asset, &rendered),
                    Ok(units),
                    "{asset:?} lost {units} base units through {rendered}"
                );
            }
        }
    }

    /// **The same text means different amounts in the two assets, and neither uses the other's
    /// divisor.**
    ///
    /// `"1"` is 10^12 mojos and 1,000 $DIG base units. A parser with one hardcoded divisor gets
    /// exactly one of these right, which is dig_ecosystem#2295 read backwards.
    #[test]
    fn one_whole_coin_parses_to_each_assets_own_base_units() {
        assert_eq!(parse_asset_amount(Asset::Xch, "1"), Ok(1_000_000_000_000));
        assert_eq!(parse_asset_amount(Asset::Dig, "1"), Ok(1_000));
        assert_eq!(parse_asset_amount(Asset::Xch, "0.5"), Ok(500_000_000_000));
        assert_eq!(parse_asset_amount(Asset::Dig, "0.5"), Ok(500));
    }

    /// **A short fraction is PADDED to the asset's precision, not read as its own integer.**
    ///
    /// `0.5` XCH is half an XCH, never five mojos. The trap this pins is the implementation that
    /// parses the fraction digits and adds them unscaled, which is right only for a fraction that
    /// happens to be full-length.
    #[test]
    fn a_short_fraction_is_scaled_rather_than_added_as_written() {
        assert_eq!(parse_asset_amount(Asset::Xch, "0.000000000001"), Ok(1));
        assert_eq!(parse_asset_amount(Asset::Xch, "0.1"), Ok(100_000_000_000));
        assert_eq!(
            parse_asset_amount(Asset::Xch, "2.25"),
            Ok(2_250_000_000_000)
        );
        assert_eq!(parse_asset_amount(Asset::Dig, "0.001"), Ok(1));
        assert_eq!(parse_asset_amount(Asset::Dig, "12.5"), Ok(12_500));
    }

    /// **More decimals than the asset carries is REFUSED, never rounded or truncated.**
    ///
    /// A thirteenth place in XCH, or a fourth in $DIG, is an amount the chain cannot express. Silently
    /// dropping it would charge a person a number they did not type; the field says so instead. Both
    /// assets, because the limit is per-asset, and the at-bound value must still pass — a rule tested
    /// only from above could be an off-by-one that refuses legitimate precision.
    #[test]
    fn an_over_precise_amount_is_refused_and_the_last_valid_place_still_passes() {
        assert_eq!(
            parse_asset_amount(Asset::Xch, "0.0000000000001"),
            Err(AmountProblem::TooManyDecimals { allowed: 12 })
        );
        assert_eq!(parse_asset_amount(Asset::Xch, "0.000000000001"), Ok(1));
        assert_eq!(
            parse_asset_amount(Asset::Dig, "0.0001"),
            Err(AmountProblem::TooManyDecimals { allowed: 3 })
        );
        assert_eq!(parse_asset_amount(Asset::Dig, "0.001"), Ok(1));
    }

    /// **Everything that is not an unsigned decimal is refused, and each refusal names its own
    /// reason.**
    ///
    /// The half-typed forms are the point: `.5` and `1.` are each one keystroke from a different
    /// number, so a parser that guessed would be guessing about money. A negative amount is not a
    /// smaller payment, and a `u64` cannot hold one at all.
    #[test]
    fn only_an_unsigned_decimal_with_digits_on_both_sides_is_accepted() {
        for text in [
            ".5", "1.", "-1", "+1", "1e12", "1,000", "1 000", "abc", "1.2.3", ".", "١",
        ] {
            assert_eq!(
                parse_asset_amount(Asset::Xch, text),
                Err(AmountProblem::NotANumber),
                "{text:?} was accepted as an amount"
            );
        }
        assert_eq!(
            parse_asset_amount(Asset::Xch, ""),
            Err(AmountProblem::Empty)
        );
        assert_eq!(
            parse_asset_amount(Asset::Xch, "   "),
            Err(AmountProblem::Empty),
            "a field holding only spaces is an empty field, not a malformed number"
        );
        // Surrounding whitespace is a paste artefact, not a typo, and is forgiven.
        assert_eq!(parse_asset_amount(Asset::Xch, "  1  "), Ok(10u64.pow(12)));
    }

    /// **An amount larger than the asset can hold is refused rather than wrapped.**
    ///
    /// One over the maximum, and the maximum itself, so the bound is pinned from both sides: a check
    /// tested only from above passes on an implementation that refuses everything large.
    #[test]
    fn an_amount_past_the_maximum_holding_is_refused_and_the_maximum_is_not() {
        let max = format_asset_amount(Asset::Xch, u64::MAX);
        assert_eq!(parse_asset_amount(Asset::Xch, &max), Ok(u64::MAX));
        assert_eq!(
            parse_asset_amount(Asset::Xch, "18446744.073709551616"),
            Err(AmountProblem::TooLarge)
        );
        assert_eq!(
            parse_asset_amount(Asset::Xch, "99999999999999999999999999"),
            Err(AmountProblem::TooLarge)
        );
        assert_eq!(
            parse_asset_amount(Asset::Dig, "18446744073709551.615"),
            Ok(u64::MAX)
        );
        assert_eq!(
            parse_asset_amount(Asset::Dig, "18446744073709551.616"),
            Err(AmountProblem::TooLarge)
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
