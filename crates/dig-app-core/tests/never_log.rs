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
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::confirm::{
    ConfirmDecision, ConnectPrompt, NativeConfirmer, NoticePrompt, PairPrompt, RevealPrompt,
    SignPrompt,
};
use dig_app_core::keystore::{CredentialStore, KeystoreError};
use dig_app_core::session_lock::SessionKeys;
use dig_keystore::MemoryBackend;
use dig_session::KeychainBackend;

/// A sentinel account master password that must never surface in a log line. The credential ceremony
/// reads an EXISTING stored password verbatim, so pre-seeding this into the store makes it the account's
/// real unlock secret for the whole boot.
const SENTINEL_PASSWORD: &str = "correct-horse-battery-staple-sentinel-9f2c";

/// An in-memory [`CredentialStore`] pre-seedable with a known password, so a test can make
/// [`SENTINEL_PASSWORD`] the account's live unlock secret.
#[derive(Clone, Default)]
struct MemCred(Arc<Mutex<HashMap<String, String>>>);

impl MemCred {
    /// Seed the master password entry for the default account with [`SENTINEL_PASSWORD`].
    fn seeded() -> Self {
        let this = Self::default();
        this.0.lock().unwrap().insert(
            format!("{DEFAULT_ACCOUNT_ID}.master-password"),
            SENTINEL_PASSWORD.to_string(),
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

/// Boot an account over `backend` + `cred`, confirming any recovery phrase.
fn boot(
    backend: Arc<dyn KeychainBackend>,
    cred: MemCred,
) -> (AccountResidency, Option<RecoveryPhrase>) {
    assemble_residency(backend, cred, account(), Seeding::NewPhrase(&SilentlyKeeps)).unwrap()
}

/// Enrolling + unlocking the master-HD account under the sentinel password must never log the password,
/// even though it is live in scope for the whole boot.
#[test]
fn account_boot_never_logs_the_master_password() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let cred = MemCred::seeded();

    let logged = capture(|| {
        // First boot enrols + seals the seed under the sentinel; a second boot unlocks with it.
        boot(backend.clone(), cred.clone());
        boot(backend.clone(), cred.clone());
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
    let (residency, _phrase) = boot(backend.clone(), MemCred::seeded());
    residency.lock_all();

    let logged = capture(|| {
        // An EMPTY credential store generates a fresh (wrong) password, so the re-unlock fails closed.
        let ok = reunlock_into(backend.clone(), MemCred::default(), account(), &residency);
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
        let (residency, phrase) = boot(backend.clone(), MemCred::seeded());
        let phrase = phrase.expect("a first run yields the phrase it enrolled from");
        words = phrase.words().iter().map(|w| w.to_string()).collect();

        // Vault it (the enrolment path), then read it all the way back out through the reveal journey.
        let booted = finish_boot(dir.path(), residency, Some(phrase));
        let vault = dig_app_core::account::boot::vault_for(dir.path(), &booted.residency)
            .expect("the account is unlocked");
        let _ = reveal_phrase(&ApproveAll, &vault);
        // And the display-once presenter, which formats the words for a window.
        let _ = WindowedPresenter::new(&ApproveAll).present_new_phrase(&RecoveryPhrase::generate());
    });

    for word in &words {
        assert!(
            !logged.contains(word.as_str()),
            "the recovery-phrase word {word:?} reached a log record: {logged}"
        );
    }
}
