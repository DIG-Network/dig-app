//! Shared `#[cfg(test)]` helper for the dig_ecosystem#3297 digit-run guards in
//! [`super::pane`] and [`super::clawback`]. The source-scanning helpers that used to live here
//! (a comment stripper, a string-literal extractor, a marker-to-marker function slicer) are
//! replaced by the parse-based [`super::source_scan`] (dig_ecosystem#3437).

#![cfg(test)]

/// The longest run of consecutive ASCII digits in `s`, or `None` if it contains no digit.
/// Shared by every dig_ecosystem#3297 digit-run guard ([`super::pane`]'s and
/// [`super::clawback`]'s) so "what counts as an epoch-shaped run" is answered in exactly one
/// place -- moved here rather than kept as `pane.rs`'s own private copy once a second module
/// needed the identical check (loop-security adversarial finding, PR #410: a guard over an
/// enumeration can only check the enumeration, so the enumeration must be complete).
pub(crate) fn longest_ascii_digit_run(s: &str) -> Option<usize> {
    let mut longest = 0;
    let mut current = 0;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    if longest == 0 {
        None
    } else {
        Some(longest)
    }
}
