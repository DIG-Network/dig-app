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
use dig_app_core::account::boot::{assemble_residency, reunlock_into, DEFAULT_ACCOUNT_ID};
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

/// Enrolling + unlocking the master-HD account under the sentinel password must never log the password,
/// even though it is live in scope for the whole boot.
#[test]
fn account_boot_never_logs_the_master_password() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let cred = MemCred::seeded();

    let logged = capture(|| {
        // First boot enrols + seals the seed under the sentinel; a second boot unlocks with it.
        assemble_residency(backend.clone(), cred.clone(), account()).unwrap();
        assemble_residency(backend.clone(), cred.clone(), account()).unwrap();
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
    let residency = assemble_residency(backend.clone(), MemCred::seeded(), account()).unwrap();
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
