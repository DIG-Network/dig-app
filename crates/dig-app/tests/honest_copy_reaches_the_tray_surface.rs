//! The honest copy must reach the surfaces that can actually PRODUCE an unusable account folder.
//!
//! # The defect this exists to catch, which really shipped
//!
//! `UnlockFailure::Unusable` was added for the tray's `Unlock` action — and `Unlock` **cannot produce
//! it**. `KeystoreError::UnsafeRoot` and `InsecurePermissions` are raised by the keystore backend's
//! WRITE; the unlock path only reads. The flows that do write — create, restore, and the replacement
//! enrolments — each called an `Option`-returning wrapper that discarded the verdict, so every one of
//! them answered an unusable folder with an invitation to try again. The new verdict was correct, the
//! new words were correct, and the pair was wired to the one path where the condition never occurs.
//!
//! # Why this is a source-text test
//!
//! The routing lives in `bin/dig-app.rs`, which is a binary with `#[cfg(feature = "tray")]` paths that
//! draw native windows: no test can call them, and a library-side assertion on
//! [`dig_app_core::account::boot::failure_notice`] proves only that the right words EXIST. What has to
//! be held is that the binary asks for them instead of writing its own — so that is asserted where it
//! is decidable, in the source.
//!
//! It is honest about being narrow: it cannot see copy assembled at runtime, and it would not notice
//! the same mistake in a different file. What it catches is the cheap-to-reintroduce regression —
//! putting a retry invitation back at a call site that cannot honour it.

/// The tray binary's CODE, with every comment line dropped.
///
/// Stripping comments is required for correctness, not tidiness: the routing is DOCUMENTED at each
/// call site by quoting the misleading sentence it replaced, so a naive search over the whole file
/// matches the explanation of the defect and fails on a correct file.
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

/// Every account-establishing failure is answered by words the LIBRARY chose from the verdict.
///
/// The two literals asserted absent are the exact sentences that shipped: they are what an unusable
/// account folder used to be answered with, and reverting either call site to `open_account` brings the
/// literal back here rather than merely changing an enum.
#[test]
fn the_create_and_restore_paths_choose_their_words_from_the_verdict() {
    let code = tray_code();

    for flow in ["AccountAction::Create", "AccountAction::Restore"] {
        assert!(
            code.contains(&format!("failure_notice({flow}")),
            "the {flow} path must ask the library for its words, so the choice is testable"
        );
    }

    for retry in [
        "You can start again from the DIG tray menu",
        "you can try again from the DIG menu whenever you are ready",
    ] {
        assert!(
            !code.contains(retry),
            "a retry invitation is hardcoded at a call site again: {retry:?} — it must come from \
             `failure_notice`, which withholds it when the folder cannot hold an account"
        );
    }

    // Every flow that WRITES must see the verdict. `open_account` discards it, which is what made the
    // honest copy unreachable from the only paths that can raise the condition.
    assert!(
        code.matches("create_account_reporting(").count() >= 4,
        "all four writing flows (create, import, restore, replace-from-phrase) must report their \
         verdict; found {}",
        code.matches("create_account_reporting(").count()
    );
    assert!(
        !code.contains("open_account(&"),
        "a writing flow is back on the verdict-discarding wrapper"
    );
}

/// The at-rest consequence of a failed unlock is derived in the library, never written here.
///
/// `OpenAttempt::Wedged` is the single value that reaches the window whose only remedy is to replace
/// the account. While that mapping was one line in this test-free target, changing it left the whole
/// suite green and clippy silent.
#[test]
fn the_destructive_state_is_never_assigned_in_the_binary() {
    let code = tray_code();

    assert!(
        code.contains("attempt_after(failure)"),
        "the unlock arm must derive the at-rest state with `boot::attempt_after`"
    );
    assert!(
        !code.contains("OpenAttempt::Wedged"),
        "the state whose remedy destroys the account is being assigned in a target no test can reach"
    );
}
