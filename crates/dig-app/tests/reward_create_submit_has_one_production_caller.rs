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

/// The tray binary's code, with every comment line dropped -- see this file's own doc comment for
/// why stripping comments is required for correctness, not tidiness.
fn tray_code() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/dig-app.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the tray binary is readable at {}: {e}", path.display()));
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
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
