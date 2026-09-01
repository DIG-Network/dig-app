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
/// and either an ASCII lowercase letter or a format placeholder's `{` after. Two spaces are left
/// alone — they
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
            // A `{` counts as prose on the RIGHT because a format placeholder is where a word goes:
            // `answered a coin labelled` + thirty spaces + `{:?}` is the same torn sentence as one
            // ending in a word, and it shipped on the mint-funding path (dig-app#294). It is safe to
            // admit on this side only: alignment padding like `fee:      {amount}` is already
            // excluded by `before_is_prose`, which a colon fails.
            let after_is_prose =
                i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i] == b'{');
            if run >= 3 && before_is_prose && after_is_prose {
                // Widened to the nearest CHAR boundary in each direction. Slicing a `str` at a
                // raw byte offset panics inside a multi-byte character, and an em dash 24 bytes
                // from a torn run is enough to turn this detector into a crash (dig-app#318).
                let from = floor_boundary(line, start.saturating_sub(24));
                let to = ceil_boundary(line, (i + 24).min(line.len()));
                return Some(line[from..to].to_string());
            }
        }
    }
    None
}

/// The greatest char boundary at or below `i`.
fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// The least char boundary at or above `i`.
fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
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

        // A run between prose and a format PLACEHOLDER is the same tear. This is the real string
        // that shipped on the mint-funding path (dig-app#294), where the words end and the hole sits
        // in front of the value.
        assert!(torn_run("answered a coin labelled   {:?}").is_some());
        // Alignment padding in front of a placeholder is NOT the tear, and the two are told apart by
        // what precedes the run: a colon is not prose. Without this the widened needle would flag
        // every aligned diagnostic in the crate.
        assert_eq!(None, torn_run("fee:      {amount}"));
    }

    /// **No source literal anywhere in this crate carries a torn run.**
    ///
    /// The per-module lists this file was built for share one weakness, and it is the weakness that
    /// let the damage through twice more: **they are written by hand.** A module whose copy nobody
    /// remembered to enumerate is a module the detector never sees, and
    /// `every_wrapped_sentence_is_reachable_by_the_whitespace_guard` patches that for exactly one
    /// file — `pane::copy`. `chain::source` and `pane::activity` were never on any list, and each
    /// shipped a torn sentence: a 22-space hole in the refusal a genuinely-short wallet reads, a
    /// 30-space hole in the asset-mislabelling refusal, and three more in the activity summary.
    ///
    /// So this reads the SOURCE TREE rather than a list. It cannot be forgotten by a new module, it
    /// needs no maintenance when copy moves, and it fails in the commit that introduces the tear
    /// rather than in whichever later commit adds the string to a list.
    ///
    /// # Why this does not replace the compiled-value lists
    ///
    /// It sees only what is spelled out in source. A sentence assembled at runtime from two halves,
    /// or one whose run arrives through a `format!` argument, is invisible here and visible to
    /// [`torn_run`] applied to the rendered message. The two are complementary: this one is
    /// exhaustive over literals, the lists are exhaustive over renderings. Neither is redundant.
    ///
    /// # Why it is not noisy
    ///
    /// Measured over all 251 source files at the time of writing: **9 candidate lines, 6 of them
    /// genuine damage.** The needle does the work — a run of 3+ spaces between prose on the left and
    /// prose or a placeholder on the right does not occur on purpose. `//` lines are skipped because
    /// a prose comment may legitimately align a table, and only comments may.
    #[test]
    fn no_source_literal_in_this_crate_carries_a_torn_run() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut torn: Vec<String> = Vec::new();
        let mut files = 0usize;
        visit(&root, &mut files, &mut torn);

        // Without this the test passes when the walk finds nothing — a green that measures the
        // walker rather than the crate. This is the failure the whole file exists to name.
        assert!(
            files > 100,
            "the walk found only {files} source files, so it is measuring itself"
        );
        assert!(
            torn.is_empty(),
            "a source literal carries a run of spaces mid-sentence, which reaches the screen verbatim. Write it as ONE line: a backslash continuation is collapsed by `cargo fmt`, and its indentation becomes part of the string. {torn:#?}"
        );
    }

    /// Every `.rs` file under `dir`, reporting each line whose literal carries a torn run.
    ///
    /// Stops at the first `#[cfg(test)]` in each file: a test module's fixtures may hold a torn
    /// string ON PURPOSE — the detector's own test above does — and flagging those would make the
    /// guard unable to test itself.
    fn visit(dir: &std::path::Path, files: &mut usize, torn: &mut Vec<String>) {
        let entries = std::fs::read_dir(dir).expect("the crate's own source tree is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files, torn);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            *files += 1;
            let source = std::fs::read_to_string(&path).expect("a source file is readable");
            for (ix, line) in source.lines().enumerate() {
                if line.trim() == "#[cfg(test)]" {
                    break;
                }
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || !line.contains('"') {
                    continue;
                }
                // Split on the two-character backslash-n ESCAPE before testing. `torn_run` already
                // splits on REAL newlines, so indentation after a line break is a line START and
                // cannot be a tear. In SOURCE that same break is still two ordinary characters, and
                // the `n` of the escape reads as the prose letter preceding the run — so without
                // this split every deliberately indented block inside a literal is reported.
                //
                // Splitting here is what makes the scanner AGREE with the compiled-value detector
                // rather than being stricter than it, which is the property that keeps one needle
                // rather than two.
                for piece in line.split("\\n") {
                    if let Some(excerpt) = torn_run(piece) {
                        torn.push(format!("{}:{}: {excerpt}", path.display(), ix + 1));
                        break;
                    }
                }
            }
        }
    }
}
