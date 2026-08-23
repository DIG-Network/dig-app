//! The OS screen lock is NOT a session-lock trigger, and no future edit may make it one again
//! (dig_ecosystem#2953).
//!
//! # The policy this defends
//!
//! An unlocked dig-app session re-locks on exactly three things: the user taps **Lock now**, 24 hours
//! pass with no user activity, or the app is closed and reopened. Locking the SCREEN is none of those —
//! a person who locks their machine to go to lunch has not asked dig-app to forget their session, and
//! the app re-locking behind that is friction with no custody benefit (§908: the node never holds the
//! user's key, and signing is local and per-operation, so this window governs how often a person
//! retypes a password to authorise their OWN local actions).
//!
//! # Why a source scan rather than a behavioural test
//!
//! The property is an ABSENCE, and absence has no runtime witness: there is no call to make that would
//! observe the trigger failing to exist. A behavioural test would pass identically in a build where a
//! platform listener had been re-added, which is exactly the regression this exists to catch. So the
//! witness is the source itself.
//!
//! Only `src/` trees are scanned, never `tests/` — the forbidden tokens appear in THIS file as data,
//! and a scan that included its own text could never pass.

use std::path::{Path, PathBuf};

/// The API and platform-listener spellings that would re-introduce an OS-screen-lock trigger: the two
/// native notification mechanisms (Windows Terminal Services session change, the macOS distributed
/// notification) and the crate-level seam that used to carry them into [`SessionLock`].
const FORBIDDEN: &[&str] = &[
    "WTSRegisterSessionNotification",
    "WM_WTSSESSION_CHANGE",
    "WTS_SESSION_LOCK",
    "com.apple.screenIsLocked",
    "screenIsLocked",
    "on_screen_locked",
    "ScreenLockSource",
    "PlatformScreenLockSource",
    "ScreenLockGuard",
    "panic_safe_lock_callback",
];

/// The `src/` trees that make up the app: the core crate and the binary crates that wire it.
fn scanned_source_roots() -> Vec<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-app-core lives inside crates/")
        .to_path_buf();
    vec![
        workspace.join("dig-app-core").join("src"),
        workspace.join("dig-app").join("src"),
        workspace.join("diga").join("src"),
    ]
}

/// Every `.rs` file under `root`, recursively.
fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn no_source_file_wires_an_os_screen_lock_trigger() {
    let mut offences = Vec::new();
    let mut scanned = 0;
    for root in scanned_source_roots() {
        assert!(
            root.is_dir(),
            "expected a source tree at {}",
            root.display()
        );
        for file in rust_sources(&root) {
            scanned += 1;
            let text = std::fs::read_to_string(&file).expect("a source file is readable");
            for (line_no, line) in text.lines().enumerate() {
                for token in FORBIDDEN {
                    if line.contains(token) {
                        offences.push(format!("{}:{}: {token}", file.display(), line_no + 1));
                    }
                }
            }
        }
    }

    assert!(
        scanned >= 100,
        "the screen-lock guard scanned only {scanned} source files; a scan that reads almost nothing passes for the wrong reason"
    );

    assert!(
        offences.is_empty(),
        "an OS screen-lock trigger was re-introduced.\n\n{}\n\nA dig-app session re-locks on exactly \
         three things (dig_ecosystem#2953): the user taps Lock now, 24 hours pass with no USER \
         activity, or the app is closed and reopened. Locking the screen is not one of them — the \
         session must survive it. If this policy is ever revisited, change the policy (SPEC §3.6) \
         first and this test with it; do not delete the test to make a listener compile.",
        offences.join("\n")
    );
}
