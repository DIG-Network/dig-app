//! The `diga` CLI's own source gets the torn-sentence scan (dig-app#204).
//!
//! Companion to `dig-app/tests/no_torn_copy_in_the_shell.rs`; that file
//! carries the full reasoning for why the detector is INCLUDED by `#[path]`
//! rather than re-implemented or promoted to a public API. In short:
//! `dig-app-core`'s scan is scoped to its own `src`, `copy_hygiene` is
//! deliberately `#[cfg(test)]` with no production caller, and a second needle
//! that disagreed with the first would be worse than none.
//!
//! This crate is small -- three files -- but every string in it is printed
//! straight at an operator's terminal, so it is exactly the copy a tear
//! reaches a person through.

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
        if path.extension().is_none_or(|e| e != "rs") {
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
fn no_source_literal_in_the_cli_carries_a_torn_run() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut torn: Vec<String> = Vec::new();
    let mut files = 0usize;
    visit(&root, &mut files, &mut torn);

    // A walk that reads nothing reports a clean crate, which is
    // indistinguishable from success. `diga` has three source files today, so
    // the floor sits just under that rather than at dig-app-core's 100.
    assert!(
        files >= 3,
        "the walk found only {files} source files in the CLI, so it is measuring itself"
    );
    assert!(
        torn.is_empty(),
        "a source literal carries a run of spaces mid-sentence, which reaches the terminal \
         verbatim. Write it as ONE line: a backslash continuation is collapsed by `cargo fmt`, \
         and its indentation becomes part of the string. {torn:#?}"
    );
}
