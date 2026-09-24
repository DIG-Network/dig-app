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
        let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
        let production = strip_comment_lines(production);
        assert!(
            !production.contains(&needle),
            "{path} must not call `create_card::submit(` -- only bin/dig-app.rs's \
             reward_create_job may"
        );
    }
}
