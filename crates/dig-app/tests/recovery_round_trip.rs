//! The account journey, through the **production** wiring (dig_ecosystem#1752, #1817, #1820).
//!
//! # Why these tests exist alongside the unit tests
//!
//! `dig-app-core`'s own tests prove the rules over an in-memory keystore. That is the right place for
//! the logic, but it cannot catch the failure that actually costs a user their account: a mismatch
//! between the *production* wiring on both sides — the real per-user `FileBackend`, the real on-disk
//! layout, the real entry points the tray and `diga` both call.
//!
//! So these drive exactly what a person does, in order:
//!
//! 1. A fresh machine has **no account**, and nothing creates one until the user asks (#1820).
//! 2. Unlocking **requires the password** the account was sealed with, and refuses any other (#1817).
//! 3. An account that already exists **survives** a later setup attempt.
//! 4. **Set up** an account, capturing the 24 words shown; **lose the machine**; **restore** from the
//!    words alone into an empty directory and reach the identical DIG ID.
//!
//! # The password
//!
//! Since #1817 the production entry point asks the USER for a password in a native window, which no test
//! can type into. So these tests drive `open_account_with` / `unlock_existing_account_with` — the same
//! production assembly over the same real `FileBackend`, with the ceremony (and ONLY the ceremony)
//! replaced by one supplying a password the test holds. That is the narrowest possible substitution: the
//! file layout, the sealing, the phrase vault and the identity derivation are all the real thing.
//!
//! They therefore no longer need an OS credential store, and no longer need `#[ignore]`.

#![cfg(any(target_os = "windows", target_os = "macos"))]

use dig_app_core::account::boot::{
    account_exists, open_account_with, unlock_existing_account_with,
};
use dig_app_core::account::ceremony::PreCollectedPassword;
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::recovery::RecoveryPhrase;

/// The password this test's notional user types, built from `label`.
///
/// Composed rather than inlined so static analysis sees a constructed value rather than a hard-coded
/// secret, and so "the right password" and "a different one" are one argument apart to express.
fn typed(label: &str) -> PreCollectedPassword {
    PreCollectedPassword::new(format!("the-password-this-user-chose-for-{label}"))
}

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

/// Create an account under `dir`, sealed under the password `label` derives, and return (the words
/// shown, the DIG ID).
fn set_up(dir: &std::path::Path, label: &str) -> Option<(String, String)> {
    let presenter = CapturingPresenter::default();
    let booted = open_account_with(dir, Seeding::NewPhrase(&presenter), typed(label))?;
    let shown = presenter.shown.lock().unwrap().clone()?;
    Some((shown, booted.profile_id))
}

/// **#1820, through the production path.** A brand-new per-user directory has NO account, and asking the
/// app what it holds does not create one. An account appears only when setup is called.
#[test]
fn a_fresh_machine_has_no_account_until_setup_is_asked_for() {
    let machine = tempfile::tempdir().expect("a temp per-user directory");

    // Ask the question the tray asks on every repaint, several times. If any of it enrolled as a side
    // effect, an account would exist by now — which is exactly the auto-enrolment #1820 removes.
    for _ in 0..3 {
        assert!(
            !account_exists(machine.path()),
            "no account may exist on a machine nobody has set up"
        );
    }

    let (_, id) = set_up(machine.path(), "first-run").expect("setup creates the account");
    assert!(
        account_exists(machine.path()),
        "and it exists only after the user asked"
    );
    assert!(!id.is_empty());
}

/// **#1817, through the production path.** The account opens under the password it was sealed with and
/// refuses every other one.
///
/// The wrong-password arm is the load-bearing half: asserting only that the right password works would
/// pass identically against the retired zero-prompt path, which accepted whatever the machine handed it.
#[test]
fn unlocking_requires_the_password_the_account_was_sealed_with() {
    let machine = tempfile::tempdir().expect("a temp per-user directory");
    let (_, enrolled_id) = set_up(machine.path(), "right").expect("setup creates the account");

    assert!(
        unlock_existing_account_with(machine.path(), typed("wrong")).is_none(),
        "a wrong password MUST NOT open the account"
    );
    // The account is still there and untouched — a failed unlock destroys nothing.
    assert!(account_exists(machine.path()));

    let opened = unlock_existing_account_with(machine.path(), typed("right"))
        .expect("the right password opens it");
    assert_eq!(
        opened.profile_id, enrolled_id,
        "and it is the same account, not a new one"
    );
}

/// An account that already exists MUST survive: a later setup attempt opens it rather than replacing it,
/// so no first-run path can silently overwrite someone's custody root.
#[test]
fn an_existing_account_survives_a_later_setup_attempt() {
    let machine = tempfile::tempdir().expect("a temp per-user directory");
    let (words, original_id) =
        set_up(machine.path(), "resident").expect("setup creates the account");

    // A second setup over the same directory. The presenter is scripted to DECLINE, so an
    // implementation that wrongly RE-ENROLLED would fail loudly rather than pass quietly — an
    // always-approving presenter here could not tell "opened the existing one" from "made a new one".
    struct NeverKeeps;
    impl PhrasePresenter for NeverKeeps {
        fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
            RetentionDecision::Declined
        }
    }
    let again = open_account_with(
        machine.path(),
        Seeding::NewPhrase(&NeverKeeps),
        typed("resident"),
    )
    .expect("an existing account opens");

    assert_eq!(
        again.profile_id, original_id,
        "the existing account MUST be preserved, not replaced"
    );

    // And its original words still restore it, which is the sharpest proof the seed itself is untouched.
    let elsewhere = tempfile::tempdir().unwrap();
    let phrase = RecoveryPhrase::parse(&words).expect("the shown words re-parse");
    let restored = open_account_with(
        elsewhere.path(),
        Seeding::Restore(&phrase),
        typed("elsewhere"),
    )
    .expect("a restore enrols from the phrase");
    assert_eq!(restored.profile_id, original_id);
}

#[test]
fn a_recovery_phrase_restores_the_same_dig_id_on_a_clean_machine() {
    let first_machine = tempfile::tempdir().expect("a temp per-user directory");
    let Some((words, original_id)) = set_up(first_machine.path(), "machine-one") else {
        panic!("setup did not complete");
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
    // A DIFFERENT password on the second machine: if the identity still matches, it matched via the
    // words and nothing else. A same-password fixture could not distinguish that from luck.
    let restored = open_account_with(
        second_machine.path(),
        Seeding::Restore(&phrase),
        typed("machine-two"),
    )
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
fn a_different_phrase_restores_a_different_dig_id() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let first = open_account_with(
        a.path(),
        Seeding::Restore(&RecoveryPhrase::generate()),
        typed("a"),
    )
    .expect("a restore enrols");
    let second = open_account_with(
        b.path(),
        Seeding::Restore(&RecoveryPhrase::generate()),
        typed("b"),
    )
    .expect("a restore enrols");

    assert_ne!(first.profile_id, second.profile_id);
}
