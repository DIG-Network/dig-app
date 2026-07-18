//! Never-log regression tests (#934, dig-logging SPEC §7).
//!
//! `dig-app-core` holds the user's private keys and passphrases — the highest-value secrets in the
//! ecosystem — so no `tracing` field or message it emits may EVER carry one, even though this crate
//! never installs a subscriber itself (only the `dig-app`/`dign` binaries do). These tests install a
//! scoped capturing subscriber, drive the real keystore/profile/session flows with sentinel secrets
//! live in scope, and assert none of them reached the captured output. A future edit that logs a
//! passphrase, a sealed blob, or a raw key fails HERE, not in a field incident.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

use dig_app_core::keystore::{IdentitySecrets, ProfileVault};

/// A sentinel passphrase that must never surface in a log line.
const SENTINEL_PASSPHRASE: &str = "correct-horse-battery-staple-sentinel-9f2c";

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

/// Sealing + unlocking an identity in the passphrase-fallback path logs the outcome but must never
/// log the passphrase itself, even though it is live in scope for the whole call.
#[test]
fn vault_create_and_unlock_never_log_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let vault = ProfileVault::with_backend(
        "did-hash-sentinel",
        dir.path(),
        None,
        dig_keystore::KdfParams::FAST_TEST,
    );
    let secrets = IdentitySecrets::generate();

    let logged = capture(|| {
        vault.create(&secrets, Some(SENTINEL_PASSPHRASE)).unwrap();
        vault.unlock(Some(SENTINEL_PASSPHRASE)).unwrap();
    });

    assert!(
        logged.contains("did-hash-sentinel"),
        "the did_hash is the useful diagnostic and must be logged: {logged}"
    );
    assert!(
        !logged.contains(SENTINEL_PASSPHRASE),
        "a passphrase must NEVER reach a log record (dig-logging SPEC §7): {logged}"
    );
}

/// A WRONG passphrase must be logged as a failed unlock — the signal an operator needs — but the
/// attempted (wrong) passphrase must still never appear.
#[test]
fn a_failed_unlock_logs_the_outcome_never_the_attempted_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let vault = ProfileVault::with_backend(
        "did-hash-wrong-unlock",
        dir.path(),
        None,
        dig_keystore::KdfParams::FAST_TEST,
    );
    vault
        .create(&IdentitySecrets::generate(), Some("the-real-passphrase"))
        .unwrap();

    let logged = capture(|| {
        let _ = vault.unlock(Some(SENTINEL_PASSPHRASE));
    });

    assert!(
        logged.contains("identity unlock failed"),
        "a failed unlock must be logged so an operator can notice repeated attempts: {logged}"
    );
    assert!(
        !logged.contains(SENTINEL_PASSPHRASE),
        "the attempted passphrase must NEVER reach a log record: {logged}"
    );
}
