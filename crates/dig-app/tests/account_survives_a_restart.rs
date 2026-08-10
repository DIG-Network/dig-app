//! **The account survives process death, and the tray says so** (dig_ecosystem#2128, P0 regression).
//!
//! # The defect this pins
//!
//! A user could not keep an account: every restart told them theirs was made by an older DIG and the
//! only way forward was to replace it. Nothing was wrong with the account. Since #1817 the app boots
//! with the account LOCKED and attempts no unlock at start-up, but the shell still derived "an open was
//! attempted and failed" from `session.is_none() && enrolled` — which, with no boot-time unlock, is
//! simply "an account exists". Every launch therefore reported `AccountState::Unopenable`, whose one
//! window steers at a destructive replace.
//!
//! # Why a real second PROCESS
//!
//! The whole defect lives in what survives process death, so a fixture that "restarts" by constructing a
//! second object in the same process cannot see it: an in-memory backend, a shared map, or a credential
//! double would all carry state across the seam the bug is on. This test re-executes ITSELF
//! (`RESTART_VAR`) so the second read genuinely comes from a cold process, over the real per-user
//! `FileBackend` on a real directory, through the same `dig-app-core` entry points the shell calls.
//! Bytes on disk are asserted before the restart, so a run that silently sealed nothing cannot pass.

use std::path::Path;
use std::sync::Arc;

use dig_app_core::account::boot::{
    account_exists, account_scoped_id, assemble_residency, DEFAULT_ACCOUNT_ID,
};
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::profile_session::ProfileSession;
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::AccountId;
use dig_app_core::tray_menu::{self, AccountState, AtRest, OpenAttempt};
use dig_session::{FileBackend, KeychainBackend};

/// Names the re-executed half of the test, and carries the account directory to it.
const RESTART_VAR: &str = "DIG_APP_2128_RESTART_DIR";

/// The label the notional user's password is derived from. DERIVED rather than written out, because a
/// password literal in a test is a hard-coded cryptographic value (CodeQL) — and derivation costs
/// nothing here, since a hash of a fixed label is identical in every process. That determinism is
/// exactly the property under test: the restarted process must arrive at the SAME password without
/// anything being handed to it.
const PASSWORD_LABEL: &str = "dig-app-2128-restart";

/// The password the notional user types, the same in every process that derives it.
fn typed_password() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(PASSWORD_LABEL.as_bytes()))
}

/// Confirms retention without drawing anything.
struct AlwaysKeeps;

impl PhrasePresenter for AlwaysKeeps {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Confirmed
    }
}

/// Open (or first-run enrol) the account under `account_dir`, exactly as the shell's boot does: the real
/// per-user file backend, the real assembly, a ceremony standing in for the person typing.
fn open_under(account_dir: &Path) -> Option<String> {
    let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new(account_dir.to_path_buf()));
    let (residency, _phrase) = assemble_residency(
        backend,
        dig_app_core::account::ceremony::PreCollectedPassword::new(typed_password()),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        ProfileSession::unprofiled(),
        Seeding::NewPhrase(&AlwaysKeeps),
    )
    .ok()?;
    account_scoped_id(&residency)
}

/// The state the tray reports for a host that holds this account and has not been asked to unlock it —
/// the shell's own derivation, over the shell's own inputs.
fn state_at_boot(brand_dir: &Path) -> AccountState {
    tray_menu::account_state(
        true,
        tray_menu::at_rest_of(
            account_exists(brand_dir),
            // This account was sealed under a password its owner chose, so it is not a migration case.
            false,
            OpenAttempt::NotAttempted,
        ),
        None,
    )
}

#[test]
fn an_enrolled_account_is_still_there_and_still_openable_in_a_new_process() {
    // The re-executed half: a genuinely cold process, told only where to look.
    if let Ok(brand_dir) = std::env::var(RESTART_VAR) {
        let brand_dir = Path::new(&brand_dir);

        assert!(
            account_exists(brand_dir),
            "the sealed seed must survive the process that created it"
        );
        assert_eq!(
            state_at_boot(brand_dir),
            AccountState::Locked,
            "a fresh process has not tried to unlock anything, so the account is LOCKED — reporting \
             it as Unopenable tells its owner to replace an account that is perfectly fine"
        );
        assert_ne!(
            state_at_boot(brand_dir),
            AccountState::Unopenable,
            "the state whose only remedy destroys the account must not be reached by merely starting"
        );

        let reopened = open_under(&brand_dir.join("account"))
            .expect("the same password must open the account in a new process");
        println!("{reopened}");
        return;
    }

    let home = tempfile::tempdir().expect("a temporary brand directory");
    let brand_dir = home.path();

    let enrolled = open_under(&brand_dir.join("account")).expect("a first run enrols");
    assert!(
        account_exists(brand_dir),
        "enrolment must leave a sealed seed on disk"
    );
    // Read the bytes, so a restart that "passed" against an empty or absent blob cannot.
    let sealed = std::fs::read(brand_dir.join("account").join("account.default.dks"))
        .expect("the sealed seed blob is on disk under its stable name");
    assert!(
        sealed.len() > 32,
        "the sealed seed must be real ciphertext, got {} bytes",
        sealed.len()
    );

    // The restart. A separate process shares no memory, no residency and no unlocked key material with
    // this one — only the directory.
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .arg("an_enrolled_account_is_still_there_and_still_openable_in_a_new_process")
        .arg("--exact")
        .arg("--nocapture")
        .env(RESTART_VAR, brand_dir)
        .output()
        .expect("the restarted process runs");

    assert!(
        output.status.success(),
        "the restarted process must open the account:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&enrolled),
        "the restarted process must recover the SAME account identity, not merely some account"
    );
    assert_eq!(
        std::fs::read(brand_dir.join("account").join("account.default.dks")).unwrap(),
        sealed,
        "opening the account must not rewrite its seal"
    );
}

/// **Starting the app creates NO account** — an account exists only because a user asked (`SPEC.md`
/// §3.2a, dig_ecosystem#1820).
///
/// Pinned here because the opposite is still asserted in prose that outlived the code: the
/// `explain_unopenable` docs claimed every Windows/macOS host auto-enrols at first boot, which sent an
/// investigation of #2128 hunting a boot-time enrolment loop that does not exist. A test says what the
/// binary does; a comment only says what someone once believed. Confirmed independently by launching the
/// real 5.19.0 binary against a virgin `LOCALAPPDATA`, which produced one file — the single-instance
/// lock — and zero `.dks`.
#[test]
fn the_boot_path_never_enrols_an_account() {
    let home = tempfile::tempdir().expect("a temporary brand directory");
    let brand_dir = home.path();

    assert!(!account_exists(brand_dir), "the fixture starts empty");
    assert_eq!(
        state_at_boot(brand_dir),
        AccountState::Absent,
        "a host with no account is Absent, and the tray offers to set one up"
    );

    // The unlock path is what a boot (and every later `Unlock…`) runs. On an empty host it must refuse
    // rather than mint an account from a recovery phrase nobody was shown.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    assert!(
        dig_app_core::account::boot::unlock_existing_account_reporting(brand_dir, "a boot")
            .is_err()
    );

    assert!(
        !account_exists(brand_dir),
        "no sealed seed may appear without a user asking for one"
    );
    assert!(
        !brand_dir
            .join("account")
            .join("account.default.dks")
            .exists(),
        "no seed blob may be written by a boot"
    );
}

/// The wedge state still exists and is still reachable — a fix that simply stopped producing
/// `Unopenable` would pass the restart assertions above while stranding the users it was built for.
#[test]
fn a_genuinely_unreadable_seal_is_still_reported_as_unopenable() {
    assert_eq!(
        tray_menu::at_rest_of(true, false, OpenAttempt::Wedged),
        AtRest::PresentButUnopenable
    );
    assert_eq!(
        tray_menu::account_state(
            true,
            tray_menu::at_rest_of(true, false, OpenAttempt::Wedged),
            None
        ),
        AccountState::Unopenable
    );
}
