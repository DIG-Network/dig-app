//! The recovery round trip, through the **production** account path (dig_ecosystem#1752).
//!
//! # Why this test exists alongside the unit tests
//!
//! `dig-app-core`'s own tests prove a phrase restores the same identity over an in-memory keystore. That
//! is the right place for the logic, but it cannot catch the failure that actually costs a user their
//! account: a mismatch between the *production* wiring on both sides — the real per-user `FileBackend`,
//! the real OS credential store, the real `open_account` entry point the tray and `dign` both call.
//!
//! So this drives exactly what a person does, in order:
//!
//! 1. **Set up** an account in a fresh per-user directory, capturing the 24 words that were shown.
//! 2. **Lose the machine** — delete that directory entirely, so nothing survives but the words.
//! 3. **Restore** into a second, empty directory from the words alone.
//! 4. Assert the DIG ID is **identical**, and that a wrong phrase reaches a different one.
//!
//! # Why it is `#[ignore]`d
//!
//! It requires a real OS credential store (Windows Credential Manager / macOS Keychain) for the
//! zero-prompt unlock password, which a Linux CI runner does not have — `open_account` correctly returns
//! `None` there rather than inventing a custody root. Run it on a desktop:
//!
//! ```text
//! cargo test -p dig-app --test recovery_round_trip -- --ignored --nocapture
//! ```

#![cfg(any(target_os = "windows", target_os = "macos"))]

use dig_app_core::account::boot::open_account;
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::recovery::RecoveryPhrase;

/// Captures the phrase the setup flow showed, and confirms retention — standing in for a user who wrote
/// the words down. Capturing (rather than approving blindly) is the point: the test can only prove a
/// restore if it restores from the words the user was actually given.
#[derive(Default)]
struct CapturingPresenter {
    shown: std::sync::Mutex<Option<String>>,
}

impl PhrasePresenter for CapturingPresenter {
    fn present_new_phrase(&self, phrase: &RecoveryPhrase) -> RetentionDecision {
        *self.shown.lock().unwrap() = Some(phrase.words().join(" "));
        RetentionDecision::Confirmed
    }
}

/// Create an account under `dir` and return (the words shown, the DIG ID).
fn set_up(dir: &std::path::Path) -> Option<(String, String)> {
    let presenter = CapturingPresenter::default();
    let booted = open_account(dir, Seeding::NewPhrase(&presenter))?;
    let shown = presenter.shown.lock().unwrap().clone()?;
    Some((shown, booted.profile_id))
}

#[test]
#[ignore = "needs a real OS credential store (Windows Credential Manager / macOS Keychain)"]
fn a_recovery_phrase_restores_the_same_dig_id_on_a_clean_machine() {
    let first_machine = tempfile::tempdir().expect("a temp per-user directory");
    let Some((words, original_id)) = set_up(first_machine.path()) else {
        panic!("setup did not complete — is an OS credential store available?");
    };
    assert_eq!(
        words.split_whitespace().count(),
        24,
        "the user was shown 24 words"
    );
    println!("set up: DIG ID {original_id}");

    // Lose the machine: nothing of the account survives except the words the user wrote down.
    drop(first_machine);

    let second_machine = tempfile::tempdir().expect("a second, empty per-user directory");
    let phrase = RecoveryPhrase::parse(&words).expect("the shown words re-parse");
    let restored = open_account(second_machine.path(), Seeding::Restore(&phrase))
        .expect("a restore enrols from the phrase");
    println!("restored: DIG ID {}", restored.profile_id);

    assert_eq!(
        restored.profile_id, original_id,
        "restoring from the phrase alone MUST reach the identical identity"
    );
    assert!(
        restored.recoverable,
        "a restored account must itself be recoverable — its phrase is vaulted like any other"
    );
}

/// The control: a DIFFERENT phrase must reach a DIFFERENT identity. Without it, the test above would
/// still pass if `profile_id` were a constant or derived from the machine rather than the seed.
#[test]
#[ignore = "needs a real OS credential store (Windows Credential Manager / macOS Keychain)"]
fn a_different_phrase_restores_a_different_dig_id() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let first = open_account(a.path(), Seeding::Restore(&RecoveryPhrase::generate()))
        .expect("a credential store is available");
    let second = open_account(b.path(), Seeding::Restore(&RecoveryPhrase::generate()))
        .expect("a credential store is available");

    assert_ne!(first.profile_id, second.profile_id);
}
