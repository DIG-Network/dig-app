//! The torn-sentence guard: one detector, and the scan that points it at this
//! crate's own source.
//!
//! [`detector`] holds the needle and its two-direction test. It lives in its own
//! file so the tray shell (`dig-app`) and the CLI (`diga`) can share it by
//! `#[path]` inclusion from their own test crates: their sources are just as
//! user-facing -- `argv.rs` builds the whole `--help` screen -- and until
//! dig-app#204 neither was scanned by anything, because the scan below is
//! scoped to `CARGO_MANIFEST_DIR/src` and that is this crate.
//!
//! Sharing the FILE rather than widening the API keeps the decision this module
//! was written with: the detector has no production caller and is not meant to
//! acquire one. Sharing the file rather than the RULE matters more -- a second
//! needle that disagreed with this one is how a defect ends up caught by
//! neither, and this module's whole subject is damage every existing test
//! agreed was absent.
//!
//! The scan below could not be shared the same way: it asserts a floor of 100
//! source files, which is a statement about THIS crate. Each crate therefore
//! owns its own walk and its own floor, over the one shared needle.

mod detector;

pub(crate) use detector::torn_run;

#[cfg(test)]
mod tests {
    use super::*;

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
