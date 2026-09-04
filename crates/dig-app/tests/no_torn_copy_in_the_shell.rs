//! The tray shell's own source gets the torn-sentence scan (dig-app#204).
//!
//! `dig-app-core` has guarded its copy since `copy_hygiene.rs` landed, and its
//! scan is exhaustive over that crate's literals. It is scoped to
//! `CARGO_MANIFEST_DIR/src`, though, so it has never seen a line of THIS
//! crate -- including `argv.rs`, which builds the entire `--help` screen an
//! operator reads. Thirteen source files of user-facing copy were outside
//! every gate in the workspace.
//!
//! # Why the detector is included rather than re-implemented
//!
//! `copy_hygiene` is `#[cfg(test)]` in `dig-app-core` and its module docs say
//! plainly that the detector "has no production caller, and is not meant to
//! acquire one". Widening it to `pub` to reach it from here would overturn
//! that decision to save an `#[path]` attribute. Re-implementing the rule
//! would be worse still: a second needle that disagrees with the first is how
//! a defect ends up caught by neither, and this file's whole subject is a
//! defect that every existing test agreed was absent.
//!
//! So the detector's FILE is shared -- `copy_hygiene/detector.rs`, which
//! holds the needle and its own two-direction test and nothing else. One
//! rule, one set of tests for that rule, no production surface added. The
//! SCAN is not shared, because its file-count floor is a claim about one
//! crate; each crate owns its walk and its own floor.
//!
//! # Why `//` lines and the `\n` escape are handled here too
//!
//! Both are properties of scanning SOURCE rather than of the needle, and both
//! are copied deliberately from `dig-app-core`'s own walker so the two scans
//! agree: a comment may legitimately align a table, and a literal's escaped
//! newline makes the following indentation a line START, which cannot be a
//! tear.

#[path = "../../dig-app-core/src/copy_hygiene/detector.rs"]
mod detector;

use std::path::Path;

use detector::torn_run;

/// Every `.rs` file under `dir`, reporting each line whose literal is torn.
fn visit(dir: &Path, files: &mut usize, torn: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).expect("the crate's own source tree is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path, files, torn);
            continue;
        }
        // `Option::is_none_or` reads better but is stable only since 1.82, and
        // this workspace's MSRV is 1.75. Clippy lets the identical call pass in
        // `copy_hygiene.rs` because `incompatible_msrv` skips `#[cfg(test)]`
        // items; an integration test is its own crate, so it does not.
        #[allow(clippy::unnecessary_map_or)]
        if path.extension().map_or(true, |e| e != "rs") {
            continue;
        }
        *files += 1;
        let source = std::fs::read_to_string(&path).expect("a source file is readable");
        for (ix, line) in source.lines().enumerate() {
            // A test module's fixtures may hold a torn string ON PURPOSE.
            if line.trim() == "#[cfg(test)]" {
                break;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !line.contains('"') {
                continue;
            }
            for piece in line.split("\\n") {
                if let Some(excerpt) = torn_run(piece) {
                    torn.push(format!("{}:{}: {excerpt}", path.display(), ix + 1));
                    break;
                }
            }
        }
    }
}

#[test]
fn no_source_literal_in_the_shell_carries_a_torn_run() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut torn: Vec<String> = Vec::new();
    let mut files = 0usize;
    visit(&root, &mut files, &mut torn);

    // Without this the test passes when the walk finds nothing -- a green that
    // measures the walker rather than the crate, which is the failure mode the
    // whole guard exists to name. This crate has thirteen source files today.
    assert!(
        files > 5,
        "the walk found only {files} source files in the shell, so it is measuring itself"
    );
    assert!(
        torn.is_empty(),
        "a source literal carries a run of spaces mid-sentence, which reaches the screen verbatim. \
         Write it as ONE line: a backslash continuation is collapsed by `cargo fmt`, and its \
         indentation becomes part of the string. {torn:#?}"
    );
}

/// The guard is proven RED before it is trusted, on the string that shipped.
///
/// `no_source_literal_in_the_shell_carries_a_torn_run` passes today because
/// the shell is clean, and a green that has never been red is indistinguishable
/// from a walk that reads nothing. This drives the same detector over the exact
/// copy dig-app#204 measured reaching users, plus the correct form of the same
/// sentence, so the scan above is known to be capable of failing.
#[test]
fn the_detector_this_scan_relies_on_fails_on_the_copy_that_shipped() {
    let shipped_torn =
        "Nothing was sent to the blockchain and no XCH was spent. Your profile is unchanged - \
         you          can change what you typed and try again.";
    assert!(
        torn_run(shipped_torn).is_some(),
        "the scan above cannot be trusted: its detector does not see the tear that shipped"
    );

    let repaired = "Nothing was sent to the blockchain and no XCH was spent. Your profile is \
                    unchanged - you can change what you typed and try again.";
    assert_eq!(
        torn_run(repaired),
        None,
        "the repaired sentence must be clean, or the guard fires on correct copy and gets disabled"
    );

    // The backslash continuation directly above is itself the negative case:
    // its second and third source lines carry deep indentation that rustc
    // strips, so a scanner reading SOURCE lines would flag correct code here.
}
