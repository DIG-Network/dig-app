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
//! that the binary's OWN parsed source calls `create_card::submit(` exactly once. Parsed rather than
//! text-matched, so the sentence you are reading right now is a comment, not a call. Mirrors
//! `honest_copy_reaches_the_tray_surface.rs`'s own approach for the same reason it gives.
//!
//! # Crate-wide, not per-file (dig_ecosystem#3367)
//!
//! The predecessor of this test proved only that `bin/dig-app.rs` itself names the call once; it
//! never checked that NO OTHER file anywhere in the workspace also names it -- a second caller
//! living in, say, `dig-app-core` would have passed silently. `other_workspace_sources_never_call_it`
//! below closes that gap by walking every `.rs` file under `crates/` (all three packages) rather
//! than the one file the earlier scan happened to be handed.
//!
//! # One scanner, shared by `#[path]` (dig_ecosystem#3437)
//!
//! The parse-based scanner is `dig-app-core`'s own `rewards/source_scan.rs`, compiled into this
//! test crate too, so there is exactly one implementation and no second copy to keep in step. A
//! file it cannot parse fails the test naming the file.

#[path = "../../dig-app-core/src/rewards/source_scan.rs"]
mod source_scan;

/// The tray binary, parsed: every item, test code included -- the binary has none of its own to
/// prune, and the scan below is of what `reward_create_job` really calls.
fn tray_code() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/dig-app.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the tray binary is readable at {}: {e}", path.display()));
    source_scan::production_at(&path.display().to_string(), &source)
}

/// The sole-caller path, assembled so this test's own source never contains it spelled out.
const SUBMIT: &str = concat!("create_card::sub", "mit");
const MODULE: &str = "create_card";
const ITEM: &str = concat!("sub", "mit");

#[test]
fn create_card_submit_is_called_exactly_once_and_only_from_reward_create_job() {
    let code = tray_code();

    // Calls AND references: `let f = create_card::submit;`, `.map(create_card::submit)` and
    // `use .. as s;` reach the fn without a call spelled by name, and the count of references
    // must equal the count of calls (see `source_scan::module_item_uses`). The one thing this
    // does not follow is a call through a bound value, `(d.begin)(x)` -- syn has no types.
    let uses = source_scan::module_item_uses(&code, MODULE, ITEM);
    assert_eq!(
        uses.calls, 1,
        "bin/dig-app.rs must call `create_card::submit(` exactly once, found {}",
        uses.calls
    );
    assert_eq!(
        uses.references, uses.calls,
        "bin/dig-app.rs names `create_card::submit` {} time(s) but calls it {}: the other \
         mention is a fn pointer or an import, a second way in",
        uses.references, uses.calls
    );
    assert!(
        uses.escapes.is_empty(),
        "bin/dig-app.rs hides `create_card::submit` behind a `use`: {:?}",
        uses.escapes
    );

    let job = source_scan::fn_named(&code, "reward_create_job")
        .expect("bin/dig-app.rs must define reward_create_job");
    assert_eq!(
        source_scan::count_path_calls(&job, SUBMIT),
        1,
        "the one `create_card::submit(` call must live inside reward_create_job"
    );
}

/// The crate-wide half (dig_ecosystem#3367): no file anywhere under `crates/` other than
/// `bin/dig-app.rs` itself may call `create_card::submit(` in production code. `create_card.rs`
/// is excluded -- it defines `submit` and never names itself `create_card::submit(` -- which keeps
/// the intent explicit.
#[test]
fn other_workspace_sources_never_call_it() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-app sits directly under crates/");
    // The walk fails on anything unreadable and on a set of 20 files or fewer, so a scan that saw
    // nothing cannot pass.
    for (path, src) in source_scan::workspace_rust_sources(crates_dir) {
        // `path.display()` uses the platform separator, so match on a normalized copy rather than
        // a literal with a baked-in `/` -- the Windows form is `...\bin\dig-app.rs`.
        let normalized = path.replace('\\', "/");
        if normalized.ends_with("src/bin/dig-app.rs")
            || normalized.ends_with("create_card.rs")
            // An integration-test crate under a package's `tests/` directory carries no
            // `#[cfg(test)]` marker of its own (the whole file IS the test crate), so pruning
            // cannot cut it -- its every line would otherwise read as production. Searched below
            // `crates/` only: a checkout under some `tests/` directory hides nothing.
            || source_scan::is_integration_test_file(crates_dir, &path)
        {
            continue;
        }
        let production = source_scan::production_at(&path, &src);
        let uses = source_scan::module_item_uses(&production, MODULE, ITEM);
        assert_eq!(
            uses.references, 0,
            "{path} must not name `create_card::submit` (call, fn pointer or import) -- only \
             bin/dig-app.rs's reward_create_job may"
        );
        assert!(
            uses.escapes.is_empty(),
            "{path} hides `create_card::submit` behind a `use`: {:?}",
            uses.escapes
        );
    }
}
