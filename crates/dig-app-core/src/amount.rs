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

use crate::wallet::state::{Asset, AssetId};

/// Decimal places in native Chia: one XCH is 10^12 mojos.
pub const XCH_DECIMALS: u32 = 12;

/// Decimal places in a Chia CAT, $DIG included: one $DIG is 10^3 base units.
///
/// This is the CAT convention, not a dig-app choice — see [`crate::decode`], whose decoder refuses to
/// render CAT amounts as XCH for the same reason.
pub const CAT_DECIMALS: u32 = 3;

/// How many decimal places `asset`'s base unit sits behind one whole coin, or `None` when dig-app
/// does not know this token's precision.
///
/// # An unknown precision is NOT three
///
/// Three is the Chia CAT *convention*, not a rule: a CAT's decimals live in an off-chain registry
/// and a token is free to carry any number of them. dig-app knows exactly two assets by definition
/// — native XCH at [`XCH_DECIMALS`], and $DIG at [`CAT_DECIMALS`] — and for a CAT a person added by
/// asset id it knows nothing at all. Answering `3` there would be a GUESS applied as a divisor, and
/// a wrong divisor is precisely how dig_ecosystem#2295 showed a whole $DIG as `0.000000001`. The
/// only difference is that this guess would be wrong by an unknown factor rather than a known one,
/// so nothing would look obviously broken.
///
/// `None` is therefore load-bearing: it forces every caller to render base units WITH the words
/// (see [`amount_with_unit`]) instead of a numeral that reads like a whole-coin figure. It is the
/// same discipline as
/// [`BalanceReading::Unknown`](crate::wallet::overview::BalanceReading::Unknown) — a thing the app
/// does not know is never rendered as a number a person could act on.
///
/// Resolving a CAT's real decimals needs its registry metadata (`dig_cat::resolve_metadata`), which
/// is a network call to a third party and a decision of its own: dig_ecosystem#3116.
pub fn decimals(asset: Asset) -> Option<u32> {
    match asset {
        Asset::Xch => Some(XCH_DECIMALS),
        // Recognised BY VALUE through the contract's own `is_dig`, never by a second copy of the
        // asset id in this crate: `Asset::DIG` is an associated constant, so it cannot be a pattern,
        // and re-spelling the id here to make it one is how a wallet ends up with two ideas of which
        // token $DIG is.
        Asset::Cat(_) if asset.is_dig() => Some(CAT_DECIMALS),
        Asset::Cat(_) => None,
    }
}

/// Render a base-unit amount of `asset` as a whole-coin decimal (`1`, `2.5`, `0`), or `None` when
/// this asset's precision is unknown.
///
/// The inverse never has to be guessed: `format_asset_amount(Asset::DIG, 1_000) == Some("1")`,
/// because a $DIG carries [`CAT_DECIMALS`] places.
///
/// Returns `Option` rather than falling back to base units so that a caller cannot accidentally
/// print an unconverted integer where a whole-coin figure belongs — the two are the same characters
/// and differ only by a factor nobody would notice on screen. A surface that must render every
/// asset uses [`amount_with_unit`], which carries the unit words along with the figure.
pub fn format_asset_amount(asset: Asset, base_units: u64) -> Option<String> {
    decimals(asset).map(|decimals| format_units(u128::from(base_units), decimals))
}

/// Render an amount of mojos as whole XCH (`500_000_000_000` -> `"0.5"`).
///
/// A total function, because native Chia's precision is fixed by the chain itself and is the one
/// figure this crate can always state. Use it where the XCH-ness is the CALLER's invariant — a fee,
/// a native-only spend summary — rather than reaching for [`format_asset_amount`] and unwrapping,
/// which is the same thing written in a way that would also silently unwrap a CAT.
pub fn format_xch(mojos: u64) -> String {
    format_units(u128::from(mojos), XCH_DECIMALS)
}

/// A mojo amount as XCH **with its ticker**, for a sentence a person reads (`500_000_000_000` ->
/// `"0.5 XCH"`).
///
/// # Why this sits beside [`format_xch`] rather than being written out at each call site
///
/// Twelve decimal places is the full precision of a mojo and unreadable, so trailing zeros are
/// dropped — but never the leading digit, and never rounded UP: a shortfall reported as smaller
/// than it is would send somebody to fund an amount that still does not cover what they are paying
/// for. Both halves of the phrase come from this module — the figure from [`format_xch`], the unit
/// from [`ticker`] — so neither can be re-derived at a call site.
///
/// It is the XCH-only counterpart of [`amount_with_unit`] and agrees with it by construction for
/// [`Asset::Xch`] (pinned by `the_xch_phrase_agrees_with_the_asset_aware_one`). Use this where the
/// XCH-ness is the CALLER's invariant — a mint cost, a shortfall, a fee — rather than reaching for
/// the asset-aware function and unwrapping, which is the same thing written in a way that would
/// also silently unwrap a CAT.
///
/// This crate has put a money figure on screen through the wrong divisor twice (a `$DIG` row using
/// the CAT divisor, dig_ecosystem#2879, and a send dialog reading 50,000,000 mojos out as
/// `50000000 XCH`), both times because a second conversion existed for a test to agree with. There
/// is one conversion, in [`format_units`], and everything here appends to its output.
pub(crate) fn xch_with_unit(mojos: u64) -> String {
    format!("{} {}", format_xch(mojos), ticker(Asset::Xch))
}

/// Render an amount of $DIG base units as whole $DIG (`1_500` -> `"1.5"`).
///
/// Total for [`format_xch`]'s reason: $DIG's precision is one dig-app knows by definition. Every
/// OTHER CAT goes through [`amount_with_unit`], which cannot state a decimal point it has not been
/// told about.
pub fn format_dig(base_units: u64) -> String {
    format_units(u128::from(base_units), CAT_DECIMALS)
}

/// How `asset` is named to a person: `XCH`, `$DIG`, or a shortened asset id for a CAT dig-app has
/// only ever been told the id of.
///
/// The one place these names are written, so a sentence about a $DIG shortfall can never quote an
/// XCH ticker, and an unfamiliar CAT is never named after a familiar one.
pub fn ticker(asset: Asset) -> String {
    match asset {
        Asset::Xch => "XCH".to_string(),
        _ if asset.is_dig() => "$DIG".to_string(),
        Asset::Cat(id) => short_asset_id(&id),
    }
}

/// A CAT's asset id shortened for display: the first and last six hex characters.
///
/// Long enough that two tokens a person holds are distinguishable at a glance, short enough to sit
/// in a row beside a figure. The FULL id is always available to copy from the token's own row — a
/// shortened id is a label, never the thing you check a payment against.
fn short_asset_id(id: &AssetId) -> String {
    short_asset_id_str(&id.to_hex())
}

/// [`short_asset_id`] over an id dig-app holds only as a string.
///
/// **The abbreviation rule lives here once, and the notification path calls it.** That path knows an
/// asset as an on-chain `AssetId` from a different crate and cannot construct the [`AssetId`] this
/// module is keyed on, so it kept its own copy of this formatting — and the copy drifted to five
/// trailing characters. The same unfamiliar token then read `a628c1…2913` on the arrival toast and
/// `a628c1…832913` on the Coins card, both inside the Wallet tab. The figure was right on both
/// sides; the identifier a person uses to tell two unfamiliar tokens apart was not. A shared rule is
/// the only thing that keeps them equal, because nothing about either call site looks wrong alone.
///
/// An id no longer than the abbreviation is returned whole — there is nothing to shorten, and a
/// label that grew an ellipsis without losing anything would be a worse label. Counted in
/// characters rather than bytes so an id that is not hex cannot panic on a slice boundary.
pub(crate) fn short_asset_id_str(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 12 {
        return id.to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}…{tail}")
}

/// An amount of `asset` together with its unit, as one inseparable phrase.
///
/// **This is the function a surface that renders arbitrary assets must use**, because the figure and
/// the unit are only true together. For a known asset it reads `1.5 $DIG`; for a CAT whose precision
/// dig-app does not know it reads `1500 base units of a1b2c3…f80912`, which states the same holding
/// without asserting a decimal point that nothing measured.
///
/// The words are not a placeholder for a nicer rendering later: "1500 base units" and "1500" are
/// different claims about someone's money, and only the first one is true here.
pub fn amount_with_unit(asset: Asset, base_units: u64) -> String {
    match format_asset_amount(asset, base_units) {
        Some(figure) => format!("{figure} {}", ticker(asset)),
        None => format!("{base_units} base units of {}", ticker(asset)),
    }
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
///
/// **This is the crate's ONLY base-units-to-decimal conversion, and that is now true by construction**
/// (dig_ecosystem#2957): every caller reaches the divisor through here, including
/// [`xch_with_unit`], which used to divide by its own `MOJOS_PER_XCH` and now only appends the unit
/// to this function's output. Two implementations agreeing today is not the same property — it is
/// the state both wrong-divisor incidents started from.
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
    /// A decimal point was typed for a token dig-app does not know the precision of.
    ///
    /// Refused rather than assumed: scaling the fraction needs a power of ten nobody has, and
    /// guessing one sends an amount nobody typed. The whole number IS accepted for such a token —
    /// it is read as base units, the unit the token is also displayed in — so the remedy here is
    /// specific and achievable, which is why this is its own case rather than a
    /// [`NotANumber`](Self::NotANumber).
    PrecisionUnknown,
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
    // A token whose precision dig-app does not know is typed in BASE UNITS — the same unit
    // `amount_with_unit` displays it in, so what a person reads and what they type are one unit. That
    // is why an unknown precision becomes zero decimal places here rather than a refusal: zero is not
    // a guess about the token, it is this app declining to talk about anything smaller than the unit
    // the chain actually moves. A typed decimal point is refused outright below, because THAT would
    // need the divisor nobody has.
    let known_decimals = decimals(asset);
    let decimals = known_decimals.unwrap_or(0);
    let (whole, fraction) = match typed.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (typed, ""),
    };
    // Digits on BOTH sides of the point, always. `.5` and `1.` are each one keystroke away from a
    // different number, and a form that guesses which one guesses about money.
    if !is_digits(whole) || (typed.contains('.') && !is_digits(fraction)) {
        return Err(AmountProblem::NotANumber);
    }
    if !fraction.is_empty() && known_decimals.is_none() {
        return Err(AmountProblem::PrecisionUnknown);
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
            format_asset_amount(Asset::DIG, 10u64.pow(CAT_DECIMALS)).unwrap(),
            "1"
        );
        assert_eq!(
            format_asset_amount(Asset::Xch, 10u64.pow(XCH_DECIMALS)).unwrap(),
            "1"
        );
    }

    /// One whole XCH in mojos, so the boundary tests below read as amounts rather than as digits.
    const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

    /// **The rendered STRING is pinned, not the arithmetic** (dig_ecosystem#2957).
    ///
    /// Equality between two renderers is not enough on its own: the send dialog's `50000000 XCH`
    /// defect survived precisely because its test asserted the same wrong string the code produced.
    /// These are literals a person could read aloud, including the exact figure that went wrong.
    #[test]
    fn the_xch_phrase_reads_as_the_literal_strings_a_person_sees() {
        assert_eq!(xch_with_unit(0), "0 XCH");
        assert_eq!(xch_with_unit(1), "0.000000000001 XCH");
        assert_eq!(xch_with_unit(MOJOS_PER_XCH), "1 XCH");
        assert_eq!(xch_with_unit(MOJOS_PER_XCH + 5_000_000), "1.000005 XCH");
        // The send dialog once read this out as `50000000 XCH` — a divisor short by twelve places.
        assert_eq!(xch_with_unit(50_000_000), "0.00005 XCH");
        assert_eq!(xch_with_unit(u64::MAX), "18446744.073709551615 XCH");
    }

    /// **The XCH-only phrase and the asset-aware one are the same phrase**, byte for byte.
    ///
    /// [`xch_with_unit`] exists so a caller whose XCH-ness is an invariant does not unwrap an
    /// `Option` that would also silently unwrap a CAT — not so there can be a second rendering of
    /// XCH. This checks the boundaries where a hand-written second copy would most plausibly
    /// diverge: the carry either side of a whole XCH, the smallest representable amount, and the
    /// top of the `u64` range.
    #[test]
    fn the_xch_phrase_agrees_with_the_asset_aware_one() {
        for mojos in [
            0,
            1,
            MOJOS_PER_XCH - 1,
            MOJOS_PER_XCH,
            MOJOS_PER_XCH + 1,
            u64::MAX,
        ] {
            assert_eq!(
                xch_with_unit(mojos),
                amount_with_unit(Asset::Xch, mojos),
                "{mojos} mojos rendered differently by the two spellings"
            );
        }
    }

    /// The literal a person would type: 1000 base units is one $DIG, and a whole $DIG is NOT
    /// 10^12 base units — under the pre-#2295 divisor that value was 3.4 billion $DIG.
    #[test]
    fn a_dig_is_a_thousand_base_units_not_a_trillion() {
        assert_eq!(format_asset_amount(Asset::DIG, 1_000).unwrap(), "1");
        assert_eq!(
            format_asset_amount(Asset::DIG, 1_000_000_000_000).unwrap(),
            "1000000000"
        );
    }

    /// A fraction renders its own asset's precision, in both assets, with trailing zeros trimmed.
    #[test]
    fn fractions_carry_each_assets_own_precision() {
        assert_eq!(format_asset_amount(Asset::DIG, 1_500).unwrap(), "1.5");
        assert_eq!(
            format_asset_amount(Asset::Xch, 1_500_000_000_000).unwrap(),
            "1.5"
        );
        // The smallest holdable amount of each asset is shown, never rounded to a zero.
        assert_eq!(format_asset_amount(Asset::DIG, 1).unwrap(), "0.001");
        assert_eq!(
            format_asset_amount(Asset::Xch, 1).unwrap(),
            "0.000000000001"
        );
    }

    /// A genuine zero is a bare `0` in either asset — no decimal point, no false precision.
    #[test]
    fn zero_renders_as_a_bare_zero_in_both_assets() {
        assert_eq!(format_asset_amount(Asset::DIG, 0).unwrap(), "0");
        assert_eq!(format_asset_amount(Asset::Xch, 0).unwrap(), "0");
    }

    /// The largest holdable amount does not overflow or lose a digit in either asset.
    #[test]
    fn the_maximum_holding_renders_exactly() {
        assert_eq!(
            format_asset_amount(Asset::Xch, u64::MAX).unwrap(),
            "18446744.073709551615"
        );
        assert_eq!(
            format_asset_amount(Asset::DIG, u64::MAX).unwrap(),
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
        for asset in [Asset::Xch, Asset::DIG] {
            for units in [
                0,
                1,
                1_000,
                1_500,
                10u64.pow(decimals(asset).expect("both assets have a known precision")),
                123_456_789,
                u64::MAX / 3,
                u64::MAX,
            ] {
                let rendered =
                    format_asset_amount(asset, units).expect("both assets have a known precision");
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
        assert_eq!(parse_asset_amount(Asset::DIG, "1"), Ok(1_000));
        assert_eq!(parse_asset_amount(Asset::Xch, "0.5"), Ok(500_000_000_000));
        assert_eq!(parse_asset_amount(Asset::DIG, "0.5"), Ok(500));
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
        assert_eq!(parse_asset_amount(Asset::DIG, "0.001"), Ok(1));
        assert_eq!(parse_asset_amount(Asset::DIG, "12.5"), Ok(12_500));
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
            parse_asset_amount(Asset::DIG, "0.0001"),
            Err(AmountProblem::TooManyDecimals { allowed: 3 })
        );
        assert_eq!(parse_asset_amount(Asset::DIG, "0.001"), Ok(1));
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
        let max = format_asset_amount(Asset::Xch, u64::MAX).expect("XCH precision is known");
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
            parse_asset_amount(Asset::DIG, "18446744073709551.615"),
            Ok(u64::MAX)
        );
        assert_eq!(
            parse_asset_amount(Asset::DIG, "18446744073709551.616"),
            Err(AmountProblem::TooLarge)
        );
    }

    /// The decimals a caller gets are the asset's own, so a new surface cannot pick the wrong one.
    #[test]
    fn each_asset_states_its_own_decimals() {
        assert_eq!(decimals(Asset::Xch), Some(XCH_DECIMALS));
        assert_eq!(decimals(Asset::DIG), Some(CAT_DECIMALS));
        assert_ne!(decimals(Asset::Xch), decimals(Asset::DIG));
    }
}
