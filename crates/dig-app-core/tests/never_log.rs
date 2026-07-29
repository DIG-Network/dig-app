//! Never-log regression tests (#934, dig-logging SPEC §7).
//!
//! `dig-app-core` holds the user's private keys and the account master password — the highest-value
//! secrets in the ecosystem — so no `tracing` field or message it emits may EVER carry one, even though
//! this crate never installs a subscriber itself (only the `dig-app`/`dign` binaries do). These tests
//! install a scoped capturing subscriber, drive the REAL master-HD boot/unlock flow (the live custody
//! path after the #1530 switchover) with a sentinel password live in scope, and assert it never reached
//! the captured output. A future edit that logs the master password fails HERE, not in a field incident.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

use dig_account::AccountId;
use dig_app_core::account::boot::{
    assemble_residency, finish_boot, reunlock_into, DEFAULT_ACCOUNT_ID,
};
use dig_app_core::account::journey::{reveal_phrase, WindowedPresenter};
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::migrate::{
    legacy_password_key, migrate_to_user_password, MigrationOutcome,
};
use dig_app_core::account::passphrase::PasswordCeremony;
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::confirm::{
    ClaimPrompt, ConfirmDecision, ConnectPrompt, InputOutcome, InputPrompt, NativeConfirmer,
    NoticePrompt, PairPrompt, RevealPrompt, SignPrompt,
};
use dig_app_core::keystore::{CredentialStore, KeystoreError};
use dig_app_core::session_lock::SessionKeys;
use dig_keystore::MemoryBackend;
use dig_session::KeychainBackend;

/// A sentinel account master password that must never surface in a log line.
///
/// Since dig_ecosystem#1817 the password is TYPED by the user, so this is what the scripted input window
/// below answers with — which makes it the account's real unlock secret for the whole boot, and puts it
/// through exactly the path a real password takes.
const SENTINEL_PASSWORD: &str = "correct-horse-battery-staple-sentinel-9f2c";

/// A sentinel for the OLD machine-held password, used only by the migration test: it must not leak
/// either, and it must be DISTINCT from [`SENTINEL_PASSWORD`] so the test can tell which one leaked.
const SENTINEL_MACHINE_PASSWORD: &str = "machine-held-sentinel-4b71-do-not-log";

/// An in-memory [`CredentialStore`] pre-seedable with a known password, so a test can model a host whose
/// account is still sealed under the retired machine-held password.
#[derive(Clone, Default)]
struct MemCred(Arc<Mutex<HashMap<String, String>>>);

impl MemCred {
    /// Seed the legacy machine-password entry for the default account.
    fn seeded() -> Self {
        let this = Self::default();
        this.0.lock().unwrap().insert(
            legacy_password_key(&account()),
            SENTINEL_MACHINE_PASSWORD.to_string(),
        );
        this
    }
}

impl CredentialStore for MemCred {
    fn get(&self, a: &str) -> Result<Option<String>, KeystoreError> {
        Ok(self.0.lock().unwrap().get(a).cloned())
    }
    fn set(&self, a: &str, s: &str) -> Result<(), KeystoreError> {
        self.0.lock().unwrap().insert(a.into(), s.into());
        Ok(())
    }
    fn delete(&self, a: &str) -> Result<(), KeystoreError> {
        self.0.lock().unwrap().remove(a);
        Ok(())
    }
}

/// An in-memory sink a `tracing_subscriber::fmt` layer writes formatted records into, so a test can
/// read back everything that was logged.
#[derive(Clone, Default)]
struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl CaptureBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for CaptureBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureBuffer {
    type Writer = CaptureBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `body` with a scoped capturing subscriber at `TRACE` (so even the lowest-level events are
/// captured) and return everything it logged.
fn capture(body: impl FnOnce()) -> String {
    let buffer = CaptureBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(buffer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    buffer.contents()
}

fn account() -> AccountId {
    AccountId::new(DEFAULT_ACCOUNT_ID)
}

/// A presenter that confirms retention without drawing anything — the boot fixture for these tests,
/// which are about what gets LOGGED, not about what gets shown.
struct SilentlyKeeps;

impl PhrasePresenter for SilentlyKeeps {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Confirmed
    }
}

/// A confirmer whose input window answers with a SCRIPT of typed strings and approves every claim.
///
/// The point of driving the real [`PasswordCeremony`] rather than a bypass double is that the sentinel
/// then travels the exact route a user's password travels — through the window seam, the ceremony, the
/// auth provider and the keystore — which is the route a leak would happen on.
struct Prompted(Mutex<std::collections::VecDeque<String>>);

impl Prompted {
    /// A window that types `text` `times` times (a new-password ceremony asks twice, an unlock once).
    fn typing(text: &str, times: usize) -> Arc<Self> {
        // `std::iter::repeat_n` is stable only since 1.82 and the workspace MSRV is 1.75.
        Arc::new(Self(Mutex::new(
            std::iter::repeat(text.to_string()).take(times).collect(),
        )))
    }

    fn confirmer(self: &Arc<Self>) -> Arc<dyn NativeConfirmer> {
        Arc::clone(self) as Arc<dyn NativeConfirmer>
    }
}

impl NativeConfirmer for Prompted {
    fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_reveal(&self, _p: &RevealPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_claim(&self, _p: &ClaimPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
        match self.0.lock().unwrap().pop_front() {
            Some(text) => InputOutcome::Provided(zeroize::Zeroizing::new(text)),
            None => InputOutcome::Cancelled,
        }
    }
}

/// Enrol a fresh account over `backend` under the typed [`SENTINEL_PASSWORD`], confirming the phrase.
fn boot(backend: Arc<dyn KeychainBackend>) -> (AccountResidency, Option<RecoveryPhrase>) {
    assemble_residency(
        backend,
        PasswordCeremony::for_a_new_account(Prompted::typing(SENTINEL_PASSWORD, 2).confirmer()),
        account(),
        Seeding::NewPhrase(&SilentlyKeeps),
    )
    .unwrap()
}

/// Unlock the existing account over `backend` by typing the sentinel once.
fn unlock(backend: Arc<dyn KeychainBackend>) -> (AccountResidency, Option<RecoveryPhrase>) {
    assemble_residency(
        backend,
        PasswordCeremony::to_unlock(Prompted::typing(SENTINEL_PASSWORD, 1).confirmer()),
        account(),
        Seeding::NewPhrase(&SilentlyKeeps),
    )
    .unwrap()
}

/// Enrolling + unlocking the master-HD account under the sentinel password must never log the password,
/// even though it is live in scope for the whole boot.
#[test]
fn account_boot_never_logs_the_master_password() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());

    let logged = capture(|| {
        // First boot enrols + seals the seed under the typed sentinel; a second unlocks with it.
        boot(backend.clone());
        unlock(backend.clone());
    });

    assert!(
        !logged.contains(SENTINEL_PASSWORD),
        "the account master password must NEVER reach a log record (dig-logging SPEC §7): {logged}"
    );
}

/// A FAILED re-unlock must be logged as the signal an operator needs — but the (seeded) master password
/// must still never appear.
#[test]
fn a_failed_reunlock_logs_the_outcome_never_the_password() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    // Enrol under the sentinel password, then lock.
    let (residency, _phrase) = boot(backend.clone());
    residency.lock_all();

    let logged = capture(|| {
        // A DIFFERENT typed password, so the re-unlock fails closed on the AEAD tag.
        let ok = reunlock_into(
            backend.clone(),
            PasswordCeremony::to_unlock(
                Prompted::typing("a-different-password-entirely", 1).confirmer(),
            ),
            account(),
            &residency,
        );
        assert!(!ok, "a wrong-password re-unlock must fail closed");
    });

    assert!(
        logged.contains("re-unlock failed"),
        "a failed re-unlock must be logged so an operator can notice repeated attempts: {logged}"
    );
    assert!(
        !logged.contains(SENTINEL_PASSWORD),
        "the master password must NEVER reach a log record: {logged}"
    );
}

/// A confirmer that approves everything and records nothing — the reveal path needs a real confirmer to
/// reach the vault, and these tests care only about what is LOGGED.
struct ApproveAll;

impl NativeConfirmer for ApproveAll {
    fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_reveal(&self, _p: &RevealPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
}

/// **The recovery phrase must never reach a log record** — it is the whole account in 24 words, so a
/// single leaked log line is a total compromise (dig_ecosystem#1752, dig-logging SPEC §7).
///
/// The fixture drives the phrase through every path that HANDLES it — enrolment, vaulting, and a full
/// reveal — and then asserts on each individual word, not on the joined phrase. Searching for the joined
/// string would miss the realistic leak, which is a structured field or a `{:?}` printing the words
/// one per line or space-normalized differently.
#[test]
fn the_recovery_phrase_never_reaches_a_log_record() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let mut words: Vec<String> = Vec::new();

    let logged = capture(|| {
        let (residency, phrase) = boot(backend.clone());
        let phrase = phrase.expect("a first run yields the phrase it enrolled from");
        words = phrase.words().iter().map(|w| w.to_string()).collect();

        // Vault it (the enrolment path), then read it all the way back out through the reveal journey.
        let booted = finish_boot(dir.path(), residency, Some(phrase));
        let vault = dig_app_core::account::boot::vault_for(dir.path(), &booted.residency)
            .expect("the account is unlocked");
        let _ = reveal_phrase(&ApproveAll, &vault);
        // And the display-once presenter, which formats the words for a window.
        let _ = WindowedPresenter::new(&ApproveAll).present_new_phrase(&RecoveryPhrase::generate());

        // The RESTORE leg: enrolling from a phrase the USER supplied, on a fresh store. This is the path
        // `dign account restore` and (once native input lands) the tray's restore prompt both drive, and
        // it handles the words at their most exposed — they arrive from outside the process.
        let restored_from = RecoveryPhrase::parse(&words.join(" ")).expect("the phrase re-parses");
        let fresh: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let restored = assemble_residency(
            fresh,
            PasswordCeremony::for_a_new_account(Prompted::typing(SENTINEL_PASSWORD, 2).confirmer()),
            AccountId::new("restored"),
            Seeding::Restore(&restored_from),
        );
        assert!(restored.is_ok(), "the restore leg must actually run");
    });

    assert_no_phrase_in(&logged, &words);
}

/// Assert that none of `words` (a recovery phrase, in order) leaked into `logged`.
///
/// # Why this checks PAIRS and not single words
///
/// The obvious assertion — "no individual word appears" — is wrong, and flakily so. BIP-39 words are
/// ordinary English, and several of them appear in this crate's own log output: **`account` is a BIP-39
/// word**, and it occurs in module targets (`dig_app_core::account::boot`) and in message text
/// ("account boot deferred", "account re-unlock failed"). So roughly one generated phrase in eighty
/// would fail the test spuriously — a false RED, the same class of defect as `cover` sitting inside
/// "recovery".
///
/// A single common word is therefore not evidence of a leak. A *run* of the phrase's words in order is:
/// any real leak — the joined string, a `{:?}`, a structured field, the numbered block — emits at least
/// two consecutive words together, while "bulk crew" appearing in log prose is not something that
/// happens. Checking every adjacent pair is strictly stronger than checking only the fully joined
/// phrase (which a partial or re-wrapped leak would slip past) and carries no collision risk.
fn assert_no_phrase_in(logged: &str, words: &[String]) {
    assert_eq!(words.len(), 24, "the fixture must be a full phrase");
    let haystack = words_only(logged);

    assert!(
        !haystack.contains(&words.join(" ")),
        "the whole recovery phrase reached a log record: {logged}"
    );
    for pair in words.windows(2) {
        let run = pair.join(" ");
        assert!(
            !haystack.contains(&run),
            "the recovery-phrase words {run:?} reached a log record together: {logged}"
        );
    }
}

/// Reduce `text` to lowercase words separated by single spaces, discarding all punctuation.
///
/// This is what makes the pair check see through a leak's FORMATTING. A `tracing` field rendered with
/// `{:?}` emits `["bulk", "crew"]`, so a naive search for `"bulk crew"` — or for `"bulk\ncrew"` — finds
/// nothing and the test passes on a real leak. Verified by injecting exactly that: a `?&words[3..6]`
/// slice slipped past the unnormalized check and is caught by this one. Normalizing collapses every
/// plausible rendering (quoted, comma-separated, `key=value`, newline-wrapped, ANSI-coloured) onto the
/// same word sequence.
fn words_only(text: &str) -> String {
    let letters: String = text
        .chars()
        .map(|c| if c.is_ascii_alphabetic() { c } else { ' ' })
        .collect();
    letters
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// **The migration must leak neither password nor phrase.** It is the one flow that holds the OLD
/// machine-held password, the NEW typed password and the recovery phrase all at once, which makes it the
/// densest concentration of account secrets anywhere in the app.
///
/// Two distinct sentinels, so a failure names WHICH secret leaked rather than only that one did.
#[test]
fn the_password_migration_never_logs_a_password_or_the_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let cred = MemCred::seeded();

    // Set the host up the way a pre-#1817 machine really is: sealed under the machine-held password,
    // with its phrase in the vault. Done OUTSIDE the capture, so only the migration's own output is
    // under test.
    let (residency, phrase) = assemble_residency(
        backend.clone(),
        PasswordCeremony::for_a_new_account(
            Prompted::typing(SENTINEL_MACHINE_PASSWORD, 2).confirmer(),
        ),
        account(),
        Seeding::NewPhrase(&SilentlyKeeps),
    )
    .expect("the legacy-shaped account enrols");
    let phrase = phrase.expect("a first run yields its phrase");
    let words: Vec<String> = phrase.words().iter().map(|w| w.to_string()).collect();
    let booted = finish_boot(dir.path(), residency, Some(phrase));
    booted.residency.lock_all();

    let logged = capture(|| {
        let outcome = migrate_to_user_password(
            Arc::new(dig_account::AccountStore::new(backend.clone())),
            &account(),
            &cred,
            &Prompted::typing(SENTINEL_PASSWORD, 2).confirmer(),
            dir.path(),
        );
        assert_eq!(
            outcome,
            MigrationOutcome::Migrated,
            "the migration must actually run, or this test proves nothing"
        );
    });

    assert!(
        !logged.contains(SENTINEL_MACHINE_PASSWORD),
        "the OLD machine-held password reached a log record: {logged}"
    );
    assert!(
        !logged.contains(SENTINEL_PASSWORD),
        "the NEW user password reached a log record: {logged}"
    );
    assert_no_phrase_in(&logged, &words);
}
