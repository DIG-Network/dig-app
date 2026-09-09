//! The claim cadence a funder is shown beside a chosen funding amount (SPEC 6.5.1).
//!
//! # There is no funding floor
//!
//! An earlier revision of the binding spec ordered a funding level be displayed as a gate; that
//! was withdrawn (6.5). Under-funding does not break a distributor -- SPEC 8.6 skips a
//! sub-threshold claim rather than failing it, and `cumulative_payout` is monotone with no
//! epoch-boundary reset, so a thinly-funded mirror simply claims less often. This module MUST
//! therefore never return a value this pane can render as a minimum, a requirement, or a warning
//! that the distributor would fail. It answers exactly one honest question: at this funding rate,
//! how many days between a mirror's claims?

/// `payout_threshold` is SPEC 8.3's constant: 1_000 $DIG base units, never a runtime value.
pub const PAYOUT_THRESHOLD_BASE_UNITS: u64 = 1_000;

/// SPEC §8.6's `CLAIM_CADENCE_SECONDS`: the peer's OWN claim-attempt cadence, not the funder's
/// accrual rate. A mirror cannot claim more often than once per this many seconds no matter how
/// fast it accrues, so a computed cadence below one day (see [`super::pane`]'s rendering) is
/// unachievable, not merely fast -- the finding this constant exists to let the pane clamp against.
pub const CLAIM_CADENCE_SECONDS: u64 = 86_400;

/// What this pane may honestly say about a mirror's claim cadence at a chosen funding rate.
///
/// Four cases, not `Option<f64>`: `entry_count == Some(0)` is real post-eviction data and must
/// NOT collapse into the same bare `0.0` a genuinely-unknown entry count would have produced under
/// the old `Option` shape -- that answer reads as "claims arrive at no interval" (the maximally
/// reassuring reading) instead of the honest "we do not yet know the mirror set". A zero CHOSEN
/// funding rate is a third, again different, fact: mirrors may well exist and be claiming under a
/// rate the funder has not chosen yet, which is not the same sentence as "no mirror is claiming".
/// This enum keeps SPEC 2.3's rule that every state be expressible exactly once (see also
/// `wire::RewardCounters` and 2.4 clause 1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CadenceReading {
    /// `entry_count` is not yet known. Never rendered as a number.
    EntryCountUnknown,
    /// `entry_count` is known to be zero: no mirror has ever been admitted (or all have been
    /// evicted). There is no cadence to state -- a cadence needs at least one mirror to divide the
    /// funding rate across -- and this is a different fact from `EntryCountUnknown`.
    NoMirrorsYet,
    /// `entry_count` is known and nonzero, but no funding rate has been chosen yet
    /// (`daily_funding_base_units == 0`). A different fact from [`Self::NoMirrorsYet`]: mirrors may
    /// exist and be claiming under whatever rate is already funded -- this says only that THIS
    /// pane has nothing chosen to divide across yet.
    NoFundingRateChosen,
    /// Days between one mirror's claims at the given funding rate.
    Days(f64),
}

/// Days between a mirror's claims at a chosen funding rate (SPEC 6.5.1):
/// `(payout_threshold * entry_count) / daily_funding_base_units`.
pub fn days_between_claims(
    entry_count: Option<u32>,
    daily_funding_base_units: u64,
) -> CadenceReading {
    let Some(entry_count) = entry_count else {
        return CadenceReading::EntryCountUnknown;
    };
    if entry_count == 0 {
        return CadenceReading::NoMirrorsYet;
    }
    if daily_funding_base_units == 0 {
        return CadenceReading::NoFundingRateChosen;
    }
    let numerator = PAYOUT_THRESHOLD_BASE_UNITS as f64 * entry_count as f64;
    CadenceReading::Days(numerator / daily_funding_base_units as f64)
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
            CadenceReading::Days(10.0)
        );
    }

    /// An absent entry count is never rendered as a number -- the original `Option` shape's
    /// honest half, preserved.
    #[test]
    fn unknown_entry_count_is_never_a_number() {
        assert_eq!(
            days_between_claims(None, PAYOUT_THRESHOLD_BASE_UNITS),
            CadenceReading::EntryCountUnknown
        );
    }

    /// The defect this module was rewritten to close: `entry_count == Some(0)` must not answer a
    /// bare `0.0`. It is real, reachable-from-eviction data, and the honest answer is "no mirrors
    /// yet", not "claims never wait".
    #[test]
    fn zero_entry_count_is_no_mirrors_yet_not_a_reassuring_zero() {
        let reading = days_between_claims(Some(0), PAYOUT_THRESHOLD_BASE_UNITS);
        assert_eq!(reading, CadenceReading::NoMirrorsYet);
        assert_ne!(reading, CadenceReading::Days(0.0));
    }

    /// A zero funding rate with mirrors PRESENT is `NoFundingRateChosen`, never `NoMirrorsYet` --
    /// the two are different sentences ("no mirror is claiming" vs. "you haven't chosen a rate")
    /// and the adversarial gate's F5: a test asserting only `!= Days(0.0)` sits below this decision
    /// and passes under the defect this pins against directly.
    #[test]
    fn zero_funding_rate_with_mirrors_present_is_no_funding_rate_chosen_not_no_mirrors_yet() {
        let reading = days_between_claims(Some(5), 0);
        assert_eq!(reading, CadenceReading::NoFundingRateChosen);
        assert_ne!(reading, CadenceReading::NoMirrorsYet);
        assert_ne!(reading, CadenceReading::Days(0.0));
    }

    /// A zero funding rate and a zero mirror count are BOTH absent, but for different reasons, and
    /// must not collapse into the same variant: `entry_count == 0` wins because there is nothing to
    /// divide the rate across regardless of what the funder picks.
    #[test]
    fn zero_entry_count_wins_over_zero_funding_rate() {
        assert_eq!(days_between_claims(Some(0), 0), CadenceReading::NoMirrorsYet);
    }
}
