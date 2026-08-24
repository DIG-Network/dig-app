//! One detector for the copy defect that no substring assertion can see: a sentence with a hole
//! torn through it.
//!
//! # Why this exists as a shared function rather than as an assertion in one test
//!
//! The damage has shipped repeatedly, in unrelated modules, and every time it passed every test the
//! module had — because the WORDS are all present and in the right order, and only the SPACING is
//! wrong. A reader sees `this wallet holds 0 XCH against a` followed by eighteen spaces; a
//! `contains("against a fee")` assertion sees nothing at all.
//!
//! Each module that owns user-facing copy therefore points its own exhaustive list of rendered
//! messages at [`torn_run`]. Sharing the DETECTOR while keeping the lists local is deliberate: a
//! single global sweep would have to guess which strings reach a person, and the modules already
//! know.
//!
//! # Two shapes, one detector
//!
//! | shape | what the source looks like | what a person reads |
//! |---|---|---|
//! | escaped-newline | an escaped newline followed by the file's indentation | a line break plus a gap |
//! | bare-run | a literal run of spaces, no escape involved | a gap |
//!
//! Only the first is visible to a source scanner looking for an escape, and the second is the one
//! that reached production. So this reads the COMPILED value, where both shapes are the same thing:
//! a run of spaces inside a sentence. That makes it correct without needing to know how the run got
//! there — worth stating, because the cause has been mis-attributed before and a detector built on a
//! cause hypothesis inherits the hypothesis.
//!
//! # Why the needle is narrow
//!
//! Runs of spaces are ORDINARY in source: indentation inside a `concat!`, deliberate two-space
//! alignment in a table, padding in a diagnostic. A rule of "no run of spaces anywhere" produces
//! dozens of false positives and is switched off within a week. The signature of the DEFECT is
//! narrower and does not occur on purpose: a run of three or more spaces sitting **between two
//! lowercase letters**, which is to say mid-word or mid-sentence, where prose was interrupted.

/// The first torn run in `text`, as a short excerpt naming it, or `None` when the text is clean.
///
/// Torn means: three or more consecutive spaces with an ASCII lowercase letter immediately before
/// and an ASCII lowercase letter somewhere after on the same line. Two spaces are left alone — they
/// are how a sentence break is sometimes typed, and flagging them would drown the signal.
///
/// The excerpt is returned rather than a bare `bool` because a failing assertion has to show the
/// reader WHERE, and a message that only says "this string is torn" sends them hunting through a
/// paragraph.
pub(super) fn torn_run(text: &str) -> Option<String> {
    for line in text.lines() {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b' ' {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i] == b' ' {
                i += 1;
            }
            let run = i - start;
            let before_is_prose = start > 0 && bytes[start - 1].is_ascii_lowercase();
            let after_is_prose = i < bytes.len() && bytes[i].is_ascii_lowercase();
            if run >= 3 && before_is_prose && after_is_prose {
                let from = start.saturating_sub(24);
                let to = (i + 24).min(bytes.len());
                return Some(line[from..to].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The detector fires on the damage and stays silent on ordinary layout.**
    ///
    /// Both directions in one test, because each half alone is worthless: a detector that flagged
    /// everything would pass the first, a detector that flagged nothing would pass the second, and
    /// only the pair pins the needle where it belongs.
    ///
    /// The torn fixture is the REAL string that shipped (`sending.rs`'s fee sentence, dig-app#258),
    /// not an invented one, so this cannot pass on a needle tuned to a fixture nobody ever read.
    #[test]
    fn a_torn_sentence_is_found_and_deliberate_layout_is_not() {
        let torn = format!(
            "and this wallet holds 0 XCH against a{}fee of 0.000005 XCH.",
            " ".repeat(18)
        );
        let found = torn_run(&torn).expect("the shipped defect must be detected");
        assert!(
            found.contains("against a"),
            "the excerpt must locate it: {found}"
        );

        // Two spaces after a full stop: how a sentence break is sometimes typed. Not damage.
        assert_eq!(
            None,
            torn_run("One payment is on its way.  Send again once it settles.")
        );

        // Indentation inside a rendered block, and an aligned table row. The run is at the start of
        // a line or follows punctuation, never between two prose letters.
        assert_eq!(None, torn_run("Heading\n    an indented detail line"));
        assert_eq!(None, torn_run("fee:      0.000005 XCH"));

        // A run of three between two lowercase letters IS the defect, at the minimum width the rule
        // claims to catch — pinning the bound from the tight side, so the threshold cannot silently
        // drift upward.
        assert!(torn_run("holds XCH against a   fee of XCH").is_some());
        // And one space below it must stay clean, or the bound is only asserted from one side.
        assert_eq!(None, torn_run("holds XCH against a  fee of XCH"));
    }
}
