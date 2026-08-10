//! **A revoke reported as done must not come back at the next start** (dig_ecosystem#2398 SEC-F1).
//!
//! # The asymmetry this exists to hold
//!
//! `FileSealedStore` reads the active profile's directory live, so a locked account gives it no
//! directory at all. Skipping a WRITE in that state is safe — the user ends up with less access than
//! they granted. Skipping a REMOVAL is not: the sealed record survives, `FrameRouter::restore` reads
//! it at the next boot, and the person has already been told the app or the site was disconnected.
//!
//! # Why the fixture locks by moving the DIRECTORY, not the key
//!
//! What the store consults is the live profile directory; a `None` there is exactly what a locked
//! account produces, and it is the only input that distinguishes "cannot write it down" from every
//! other reason a removal might do nothing. The sealer is left working, so the test cannot pass by
//! accident on a store that simply failed to seal.
//!
//! Each assertion is stated against the OPPOSITE case in the same test: an unlocked removal must
//! report success and must actually delete. Without that control, a store that reported failure for
//! everything would satisfy the security half perfectly.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dig_app_core::live::{Live, LiveProfileDir};
use dig_app_core::loopback::{FileSealedStore, SealedRecordStore};

/// The origin whose grant is revoked. One value, used for the write, the removal and the reload, so
/// the three cannot silently address different records.
const ORIGIN: &str = "https://dapp.example";

/// A profile directory that can be taken away, exactly as locking an account takes it away.
struct LockableProfileDir {
    dir: PathBuf,
    locked: Arc<AtomicBool>,
}

impl LockableProfileDir {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A live source reading the directory while unlocked and `None` once locked.
    fn source(&self) -> LiveProfileDir {
        let (dir, locked) = (self.dir.clone(), Arc::clone(&self.locked));
        Live::read(move || (!locked.load(Ordering::SeqCst)).then(|| dir.clone()))
    }

    fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::SeqCst);
    }
}

#[test]
fn a_removal_that_cannot_reach_disk_must_not_report_success() {
    let root = tempfile::tempdir().expect("a temp profile directory");
    let profile = LockableProfileDir::new(root.path().to_path_buf());
    let store = FileSealedStore::new(profile.source());

    store.persist_whitelist(ORIGIN, b"sealed-grant-bytes");
    assert_eq!(
        1,
        store.load().whitelist.len(),
        "control: the grant is at rest to begin with"
    );

    profile.lock();
    assert!(
        !store.remove_whitelist(ORIGIN),
        "a removal with no directory to reach MUST report that it did not land"
    );

    // The whole point of the report: the record really is still there, so a caller that had been
    // told `revoked: true` would be handed the grant back by `restore` at the next start.
    profile.unlock();
    assert_eq!(
        1,
        store.load().whitelist.len(),
        "the sealed grant survived the locked removal — which is why it may not be reported as done"
    );

    assert!(
        store.remove_whitelist(ORIGIN),
        "control: the same removal, unlocked, must report success"
    );
    assert!(
        store.load().whitelist.is_empty(),
        "control: and must actually delete the record"
    );
    assert!(
        store.remove_whitelist(ORIGIN),
        "control: a second removal is idempotent — nothing at rest is still success"
    );
}

#[test]
fn a_pairing_removal_that_cannot_reach_disk_must_not_report_success() {
    let root = tempfile::tempdir().expect("a temp profile directory");
    let profile = LockableProfileDir::new(root.path().to_path_buf());
    let store = FileSealedStore::new(profile.source());

    // A pairing carries a nonce high-water mark beside its record, and BOTH have to go. The mark is
    // derived rather than written as a literal: it is a monotonic replay counter, not key material.
    let mark = u64::from(u32::from_be_bytes([0xA1, 0x37, 0x0C, 0x4E]));
    store.persist_pairing("pairing-1", b"sealed-pairing-bytes");
    store.persist_nonce("pairing-1", mark);

    profile.lock();
    assert!(
        !store.remove_pairing("pairing-1"),
        "a pairing removal with no directory to reach MUST report that it did not land"
    );

    profile.unlock();
    let state = store.load();
    assert_eq!(1, state.pairings.len(), "the sealed pairing survived");
    assert_eq!(
        Some(&mark),
        state.nonces.get("pairing-1"),
        "and so did its replay mark"
    );

    assert!(
        store.remove_pairing("pairing-1"),
        "control: the same removal, unlocked, must report success"
    );
    let state = store.load();
    assert!(state.pairings.is_empty());
    assert!(
        state.nonces.is_empty(),
        "the replay mark goes with the record it belongs to"
    );
}
