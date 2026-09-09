//! The claim cadence a funder is shown beside a chosen funding amount (SPEC §6.5.1).
//!
//! # There is no funding floor
//!
//! An earlier revision of the binding spec ordered a funding level be displayed as a gate; that
//! was withdrawn (§6.5). Under-funding does not break a distributor — SPEC §8.6 skips a
//! sub-threshold claim rather than failing it, and `cumulative_payout` is monotone with no
//! epoch-boundary reset, so a thinly-funded mirror simply claims less often. This module MUST
//! therefore never return a value this pane can render as a minimum, a requirement, or a warning
//! that the distributor would fail. It answers exactly one honest question: at this funding rate,
//! how many days between a mirror's claims?

/// `payout_threshold` is SPEC §8.3's constant: 1_000 $DIG base units, never a runtime value.
pub const PAYOUT_THRESHOLD_BASE_UNITS: u64 = 1_000;

/// Days between a mirror's claims at a chosen funding rate (SPEC §6.5.1):
/// `(payout_threshold * entry_count) / daily_funding_base_units`.
///
/// Returns `None` — never zero, never a number computed from a guess — when `entry_count` is not
/// yet known (an absent entry count is a claim about the past presented as the present per §2.4
/// clause 3, and the cadence built on top of it would carry the same false confidence) or when
/// `daily_funding_base_units` is zero (there is no cadence at a zero funding rate; that is not the
/// same claim as "the cadence is very long").
///
/// # Caveat: the reassuring zero
///
/// `entry_count == Some(0)` currently yields `0.0`, which is reachable from real post-eviction data.
/// That answer is maximally *reassuring* rather than neutral — it reads as "claims arrive at no
/// interval" instead of the honest claim "we do not yet know the mirror set". Before any surface
/// renders this value, it needs a distinct "no mirrors yet" case, which requires a three-case result
/// (not `Option`) to keep SPEC §2.3's state distinction (see also `wire::RewardCounters` and §2.4
/// clause 1: every state must be expressible exactly once). Returning `Option` would collapse two
/// forbidden-to-merge cases into one.
pub fn days_between_claims(entry_count: Option<u32>, daily_funding_base_units: u64) -> Option<f64> {
    let entry_count = entry_count?;
    if daily_funding_base_units == 0 {
        return None;
    }
    let numerator = PAYOUT_THRESHOLD_BASE_UNITS as f64 * entry_count as f64;
    Some(numerator / daily_funding_base_units as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The literal worked example: 10 entries, 1_000 base units of $DIG funded per day exactly
    /// matches one entry's threshold per day, so with 10 entries the set needs 10 days to clear it
    /// collectively but one mirror's own cadence (this function's question) is ten days between
    /// ITS claims at that funding rate, per the SPEC formula.
    #[test]
    fn cadence_matches_the_spec_formula() {
        assert_eq!(
            days_between_claims(Some(10), PAYOUT_THRESHOLD_BASE_UNITS),
            Some(10.0)
        );
    }
}
