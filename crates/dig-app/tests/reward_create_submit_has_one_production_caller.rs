//! `dig_app_core::rewards::create_card::submit` is the sole production caller of
//! [`dig_app_core::rewards::mint::DistributorMintDoor::begin`] outside `mint.rs` -- proven in
//! `dig-app-core`'s own `create_card::subject_tests::begin_has_exactly_one_production_caller_outside_mint_rs`.
//! This test proves the OTHER half of the chain: the tray binary itself calls `create_card::submit`
//! exactly once, from `reward_create_job` -- the worker body the `create_sink` job runs on
//! (dig_ecosystem#3253 §6). A second call site would mean a second, unwitnessed way to spend into a
//! reward-distributor launch.
//!
//! # Why this is a source-text test
//!
//! `bin/dig-app.rs` is a binary with `#[cfg(feature = "tray")]` paths that draw native windows and
//! open a live node connection -- no test can call `reward_create_job` directly. What can be held is
//! that the binary's OWN source names `create_card::submit(` exactly once, comment-stripped so the
//! sentence you are reading right now cannot self-match. Mirrors
//! `honest_copy_reaches_the_tray_surface.rs`'s own approach for the same reason it gives.
//!
//! # Crate-wide, not per-file (dig_ecosystem#3367)
//!
//! The predecessor of this test proved only that `bin/dig-app.rs` itself names the call once; it
//! never checked that NO OTHER file anywhere in the workspace also names it -- a second caller
//! living in, say, `dig-app-core` would have passed silently. `other_workspace_sources_never_call_it`
//! below closes that gap by walking every `.rs` file under `crates/` (all three packages) rather
//! than the one file the earlier scan happened to be handed.

/// The tray binary's code, with every comment line dropped -- see this file's own doc comment for
/// why stripping comments is required for correctness, not tidiness.
fn tray_code() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/dig-app.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the tray binary is readable at {}: {e}", path.display()));
    strip_comment_lines(&source)
}

fn strip_comment_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every `.rs` file under this repo's `crates/` directory, walked at test time (the file set is
/// not knowable at compile time). `target/` is skipped -- build output, never source. A vacuity
/// assert: a walk that silently found zero files would pass every "no other caller" assertion
/// below for the worst possible reason.
fn workspace_rust_sources() -> Vec<(String, String)> {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-app sits directly under crates/")
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust_files(&crates_dir, &mut files);
    assert!(
        files.len() > 20,
        "workspace_rust_sources walked only {} files under {} -- the walk is broken, not the \
         codebase",
        files.len(),
        crates_dir.display()
    );
    files
}

fn collect_rust_files(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(src) = std::fs::read_to_string(&path) {
                out.push((path.display().to_string(), src));
            }
        }
    }
}

#[test]
fn create_card_submit_is_called_exactly_once_and_only_from_reward_create_job() {
    let code = tray_code();
    // Assembled with `format!` rather than written as one literal, so this test's own source can
    // never self-match the needle it is scanning for.
    let needle = format!("{}{}", "create_card::sub", "mit(");

    let call_count = code.matches(&needle).count();
    assert_eq!(
        call_count, 1,
        "bin/dig-app.rs must call `create_card::submit(` exactly once, found {call_count}"
    );

    let fn_start = code
        .find("fn reward_create_job(")
        .expect("bin/dig-app.rs must define reward_create_job");
    let fn_end = code[fn_start..]
        .find("\n    fn ")
        .map(|rel| fn_start + rel)
        .unwrap_or(code.len());
    assert!(
        code[fn_start..fn_end].contains(&needle),
        "the one `create_card::submit(` call must live inside reward_create_job"
    );
}

/// The crate-wide half (dig_ecosystem#3367): no file anywhere under `crates/` other than
/// `bin/dig-app.rs` itself may name `create_card::submit(` in production code. `create_card.rs`
/// is excluded -- it defines `submit`, and its own doc calls itself `submit` unqualified, never
/// `create_card::submit(`, so it would not self-match anyway, but excluding it keeps the intent
/// explicit.
#[test]
fn other_workspace_sources_never_call_it() {
    let needle = format!("{}{}", "create_card::sub", "mit(");
    for (path, src) in workspace_rust_sources() {
        // `path.display()` uses the platform separator, so match on a normalized copy rather than
        // a literal with a baked-in `/` -- the Windows form is `...\bin\dig-app.rs`.
        let normalized = path.replace('\\', "/");
        if normalized.ends_with("src/bin/dig-app.rs")
            || normalized.ends_with("create_card.rs")
            // An integration-test crate under a package's `tests/` directory carries no
            // `#[cfg(test)]` marker of its own (the whole file IS the test crate), so the
            // `#[cfg(test)]`-split below cannot cut it -- its every line would otherwise read as
            // production, including this very file's own needle-bearing doc comments.
            || normalized.contains("/tests/")
        {
            continue;
        }
        let production = strip_test_and_comments(&src);
        assert!(
            !production.contains(&needle),
            "{path} must not call `create_card::submit(` -- only bin/dig-app.rs's \
             reward_create_job may"
        );
    }
}

// strip_test_and_comments and its helpers below are kept identical (modulo indentation) to the
// copy in `dig-app-core/src/rewards/create_card.rs` -- see
// `the_cut_algorithm_matches_its_copy_in_the_dig_app_core_crate` below, which enforces that
// automatically (dig_ecosystem#3367 review round 1).
// === BEGIN SHARED CUT ALGORITHM ===

/// Cuts every `#[cfg(test)]`-gated item out of `src`, leaving every other line untouched --
/// including production code that comes AFTER a `#[cfg(test)] mod tests { .. }` block, which
/// the single `src.split("#[cfg(test)]").next()` this replaces used to discard wholesale
/// along with the rest of the file (dig_ecosystem#3367 review round 1): any production
/// caller written below a file's test module was invisible to the crate-wide sole-caller
/// scans.
///
/// For each `#[cfg(test)]` occurrence: skip any stacked attributes that follow it (e.g.
/// `#[path = "..."]`), then remove through the attributed item's end -- its matching `}` if
/// the item opens a brace block (`mod tests { .. }`, `fn helper() { .. }`, `struct S { .. }`,
/// `impl Foo { .. }`, `thread_local! { .. }`), or its terminating `;` if it has none (`mod
/// fixture;`, `use x::y;`, `static X: T = v;`). `(`/`)` and `[`/`]` stay depth-tracked while
/// scanning for that end, so a `;` inside an array length (`[u8; 32]`) or a nested attribute
/// inside a parameter list cannot be mistaken for the item's own terminator.
///
/// What this does NOT understand: `//` comments and string literals. A `{`, `}` or `;`
/// written inside one, if it fell inside the span being cut, would be read as real code.
/// That is an accepted limitation for this codebase's style rather than something worth a
/// real tokenizer for -- doc comments here precede attributes, never follow them, and no
/// `#[cfg(test)]`-gated item's signature quotes a brace or semicolon in a string. If that
/// ever changes, the needle scans this feeds are themselves the tripwire: whatever text
/// survives a wrong cut is exactly what they read.
fn strip_test_and_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    const MARKER: &str = "#[cfg(test)]";

    while let Some(marker_at) = rest.find(MARKER) {
        out.push_str(&rest[..marker_at]);
        let cursor = marker_at + MARKER.len();
        let cursor = skip_stacked_attributes(rest, cursor);
        let item_end = find_item_end(rest, cursor);
        rest = &rest[item_end..];
    }
    out.push_str(rest);

    out.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Advances past whitespace and any further attributes stacked after a `#[cfg(test)]`
/// (e.g. `#[path = "..."]` before `mod name;`), returning the index of the item they gate.
fn skip_stacked_attributes(src: &str, from: usize) -> usize {
    let mut cursor = from;
    loop {
        let tail = &src[cursor..];
        let non_ws = tail.find(|c: char| !c.is_whitespace());
        let ws_end = cursor + non_ws.unwrap_or(tail.len());
        if !src[ws_end..].starts_with("#[") {
            return ws_end;
        }
        cursor = find_matching_bracket_end(src, ws_end + 1);
    }
}

/// Finds where the item starting at `src[start..]` ends: the index just past its matching
/// `}` if it opens a brace block, or just past its terminating `;` if it has none --
/// whichever comes first while `(`/`)` and `[`/`]` stay balanced. Falls back to `src.len()`
/// if neither is ever found (malformed input, never expected from real source).
fn find_item_end(src: &str, start: usize) -> usize {
    let mut depth = 0i32;
    for (i, c) in src[start..].char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ';' if depth == 0 => return start + i + 1,
            '{' if depth == 0 => return find_matching_brace_end(src, start + i),
            _ => {}
        }
    }
    src.len()
}

/// The index just past the `}` matching the `{` at `src[open..]`. See
/// `strip_test_and_comments`'s doc comment for what this does not understand.
fn find_matching_brace_end(src: &str, open: usize) -> usize {
    find_matching_end(src, open, '{', '}')
}

/// The index just past the `]` matching the `[` at `src[open..]`. Used to skip a stacked
/// attribute's own brackets (`#[path = "..."]`), which may contain a string literal but,
/// per this codebase's style, never a literal `]`.
fn find_matching_bracket_end(src: &str, open: usize) -> usize {
    find_matching_end(src, open, '[', ']')
}

/// The index just past the `closer` matching the `opener` at `src[open..]`, by
/// depth-counting the pair from there.
fn find_matching_end(src: &str, open: usize, opener: char, closer: char) -> usize {
    let mut depth = 0i32;
    for (i, c) in src[open..].char_indices() {
        if c == opener {
            depth += 1;
        } else if c == closer {
            depth -= 1;
            if depth == 0 {
                return open + i + 1;
            }
        }
    }
    src.len()
}
// === END SHARED CUT ALGORITHM ===

/// (dig_ecosystem#3367 review round 1) `strip_test_and_comments` and its helpers above live in
/// TWO places -- this file and `dig-app-core/src/rewards/create_card.rs` -- because this is a
/// different crate's integration test and cannot depend on that crate's test-only code to share
/// it; giving `dig-app-core` a new `pub` API just so this test could call it would be a worse
/// trade than keeping two copies honest. This test is what keeps them honest: it reads the
/// sibling file's own source at test time and checks its shared-cut-algorithm block matches this
/// one's, so a fix applied to one copy and forgotten in the other fails loudly instead of
/// silently reopening dig_ecosystem#3367's review-round-1 gap in whichever copy nobody touched.
#[test]
fn the_cut_algorithm_matches_its_copy_in_the_dig_app_core_crate() {
    let mine = shared_cut_algorithm_block(include_str!(
        "reward_create_submit_has_one_production_caller.rs"
    ));

    let sibling_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-app sits directly under crates/")
        .join("dig-app-core/src/rewards/create_card.rs");
    let sibling_src = std::fs::read_to_string(&sibling_path).unwrap_or_else(|e| {
        panic!(
            "the sibling copy at {} must be readable: {e}",
            sibling_path.display()
        )
    });
    let theirs = shared_cut_algorithm_block(&sibling_src);

    assert_eq!(
        mine, theirs,
        "strip_test_and_comments and its helpers must match (modulo indentation) in \
         create_card.rs and reward_create_submit_has_one_production_caller.rs -- copy this \
         file's marked block over the other's"
    );
}

/// The text between the `BEGIN SHARED CUT ALGORITHM` and `END SHARED CUT ALGORITHM` marker
/// comments, with each line's leading whitespace trimmed -- so
/// [`the_cut_algorithm_matches_its_copy_in_the_dig_app_core_crate`] can compare the two copies
/// without caring that one sits inside a `mod` and the other does not.
fn shared_cut_algorithm_block(src: &str) -> String {
    let begin_marker = "BEGIN SHARED CUT ALGORITHM";
    let end_marker = "END SHARED CUT ALGORITHM";
    let start = src
        .find(begin_marker)
        .expect("the shared-cut-algorithm start marker is present");
    let end = src[start..]
        .find(end_marker)
        .map(|rel| start + rel)
        .expect("the shared-cut-algorithm end marker is present");
    src[start..end]
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join("\n")
}
