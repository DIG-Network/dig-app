//! The one date/time-humanising helper in `dig-app-core` (dig_ecosystem#3297).
//!
//! `pane.rs`'s own comment named the gap when it shipped: "dig-app-core has no date-formatting
//! helper yet (tracked separately)". Confirmed again for this ticket: `grep -rn` over every
//! `Cargo.toml` in this workspace finds no `time`, `chrono` or `jiff` dependency anywhere, and
//! `grep -rn "chrono::\|jiff::\|time::"` over `crates/dig-app-core/src` finds no existing
//! ad-hoc humanising code either -- this is the FIRST one, not a second convention beside an
//! existing helper.
//!
//! # Why no new dependency
//!
//! Every call site this module exists for renders a RELATIVE fact ("3 hours ago", "in 2 days"),
//! never a calendar date, a timezone-aware instant, or a formatted clock time. A relative phrase
//! needs only integer division against fixed-length buckets (minute/hour/day) -- a calendar
//! library's actual job (leap years, months of varying length, timezone databases, localized
//! calendar formatting) is not needed anywhere on this path. Reaching for `time`/`chrono`/`jiff`
//! here would add a dependency, its transitive tree and its `-D warnings` surface to buy
//! machinery none of the seven call sites this module was written for use.
//!
//! # Past vs. future
//!
//! [`ago`] and [`until`] are deliberately two functions, not one signed-duration formatter that
//! prints "ago" or "in" depending on the sign: [`crate::rewards::clawback`]'s `epoch_start_date`
//! names a FUTURE instant (an epoch that has not started yet), and "3 days ago" would be an
//! outright false claim about a commitment that has not begun, not merely an awkward phrasing of
//! a true one -- the exact honesty bar the rest of this crate holds money and status sentences to.

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// A relative phrase for a PAST instant, e.g. `"3 hours ago"`. `now < at` (a small clock skew)
/// reads as `"less than a minute ago"` rather than underflowing.
pub fn ago(now: u64, at: u64) -> String {
    format!("{} ago", span(now.saturating_sub(at)))
}

/// A relative phrase for a FUTURE instant, e.g. `"in 3 hours"`. Never `"ago"` -- see this
/// module's doc for why that word is wrong for a promise rather than a record.
pub fn until(now: u64, at: u64) -> String {
    format!("in {}", span(at.saturating_sub(now)))
}

/// A bare duration span with no "ago"/"in" -- e.g. `"3 hours"`, for a sentence that supplies its
/// own preposition (`"has not reported for { $duration }"`).
pub fn span(seconds: u64) -> String {
    if seconds < MINUTE {
        return "less than a minute".to_string();
    }
    if seconds < HOUR {
        let minutes = seconds / MINUTE;
        return format!("{minutes} minute{}", plural(minutes));
    }
    if seconds < DAY {
        let hours = seconds / HOUR;
        return format!("{hours} hour{}", plural(hours));
    }
    let days = seconds / DAY;
    format!("{days} day{}", plural(days))
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_minute_reads_as_less_than_a_minute() {
        assert_eq!(span(0), "less than a minute");
        assert_eq!(span(59), "less than a minute");
    }

    #[test]
    fn minutes_hours_days_pluralise_correctly() {
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(120), "2 minutes");
        assert_eq!(span(3_600), "1 hour");
        assert_eq!(span(7_200), "2 hours");
        assert_eq!(span(86_400), "1 day");
        assert_eq!(span(172_800), "2 days");
    }

    #[test]
    fn ago_and_until_carry_the_right_preposition() {
        assert_eq!(ago(1_000, 400), "10 minutes ago");
        assert_eq!(until(1_000, 1_600), "in 10 minutes");
    }

    /// The property dig_ecosystem#3297 exists to hold: never an epoch-shaped (9-11 digit) run in
    /// a rendered phrase, for any input up to a plausible far-future timestamp.
    ///
    /// # What this test proves, and what it does NOT
    ///
    /// This calls `ago`/`until` directly and scans THEIR OWN return value -- it proves the helper
    /// itself never emits a raw epoch, but it is NOT independent of the helper: a call site that
    /// forgot to route a timestamp through `humanize` at all would render fine here and still be
    /// wrong in the app. `super::super::pane::rewards_sections_tests::
    /// no_rendered_reward_sentence_contains_an_epoch_shaped_digit_run` is the independent proof --
    /// it renders through the real `rewards_sections` call path and scans the resulting `Section`
    /// headings, so a call site that skipped this helper would be caught there even if this test
    /// stayed green.
    #[test]
    fn no_output_contains_an_epoch_shaped_digit_run() {
        let epoch_shaped = |s: &str| {
            let mut run = 0;
            for c in s.chars() {
                if c.is_ascii_digit() {
                    run += 1;
                } else {
                    run = 0;
                }
                if (9..=11).contains(&run) {
                    return true;
                }
            }
            false
        };
        for (now, at) in [
            (0u64, 0u64),
            (1_700_000_000, 0),
            (1_700_000_000, 1_800_000_000),
        ] {
            assert!(
                !epoch_shaped(&ago(now, at)),
                "{now},{at} -> {}",
                ago(now, at)
            );
            assert!(
                !epoch_shaped(&until(now, at)),
                "{now},{at} -> {}",
                until(now, at)
            );
        }
    }
}
