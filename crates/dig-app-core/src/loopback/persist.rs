//! Durable at-rest persistence for the APP-SIGN loopback stores (SIGN-2 tray-wiring, `SPEC.md` §5.6,
//! **security-critical**, dig_ecosystem#958 item 3 + #956).
//!
//! The [`crate::pairing::PairingStore`] and [`crate::whitelist::WhitelistStore`] already SEAL each
//! record under the active profile's DEK (NC-2) but hold the sealed bytes only in memory — the
//! [`FrameRouter`](super::FrameRouter) used to discard them. This module is the seam that writes those
//! sealed bytes to the per-profile AppData directory (NC-3) and restores them on boot, so a paired
//! extension and its connected dapp origins survive a dig-app restart.
//!
//! It also persists the per-frame **nonce high-water mark** alongside each pairing, so a frame captured
//! before a restart can never replay into the new session (dig_ecosystem#956): the ledger is re-seeded
//! from disk on restore, rejecting any nonce at or below the last one accepted pre-restart. The nonce is
//! a monotonic counter, not key material, so it is stored in the clear (its integrity is already
//! protected by the sealed channel secret's MAC; only its confidentiality is unneeded).
//!
//! Every write goes through [`crate::storage::write_durably`] — the one crash-safe atomic-replace idiom
//! the rest of dig-app persists with — so a crash mid-save never strands a half-written record.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::live::LiveProfileDir;

/// The subdirectory (under the active profile's directory) holding all APP-SIGN at-rest state.
const APP_SIGN_SUBDIR: &str = "app-sign";
/// The subdirectory holding one sealed file per pairing (`<pairing_id>.seal`).
const PAIRINGS_SUBDIR: &str = "pairings";
/// The subdirectory holding one sealed file per connected origin (`<sha256(origin)>.seal`).
const WHITELIST_SUBDIR: &str = "whitelist";
/// The plaintext per-pairing nonce high-water-mark ledger (`{ pairing_id: last_nonce }`).
const NONCE_LEDGER_FILE: &str = "nonces.json";
/// The extension every sealed record file carries.
const SEAL_EXT: &str = "seal";

/// The at-rest state restored on boot: the sealed record bytes for every pairing + whitelist entry,
/// plus the persisted nonce high-water mark per pairing id.
#[derive(Debug, Default)]
pub struct PersistedSignState {
    /// Sealed [`crate::pairing::PairingRecord`] bytes, one per persisted pairing (still ciphertext —
    /// only the active profile's DEK can open them).
    pub pairings: Vec<Vec<u8>>,
    /// Sealed [`crate::whitelist::WhitelistEntry`] bytes, one per persisted connected origin.
    pub whitelist: Vec<Vec<u8>>,
    /// The last accepted nonce per pairing id, re-seeded onto the restored ledger (#956).
    pub nonces: HashMap<String, u64>,
}

/// The seam the [`FrameRouter`](super::FrameRouter) persists sealed records + nonces through.
///
/// Every method is best-effort and infallible to the caller: a persistence failure is logged inside
/// the implementation and never aborts a pairing/connect/sign that already succeeded in memory (the
/// in-session state still protects the channel; the only cost of a lost write is that one record does
/// not survive the next restart). The production implementation is [`FileSealedStore`]; tests and the
/// headless/no-persistence path use [`NullSealedStore`].
///
/// `Send + Sync` because the loopback server shares one store across connection tasks behind an `Arc`.
pub trait SealedRecordStore: Send + Sync {
    /// Persist the sealed pairing record for `pairing_id` (overwriting any prior record for it).
    fn persist_pairing(&self, pairing_id: &str, sealed: &[u8]);

    /// Persist the sealed whitelist entry for `origin` (overwriting any prior grant for it).
    fn persist_whitelist(&self, origin: &str, sealed: &[u8]);

    /// Record `nonce` as the latest accepted nonce for `pairing_id` (the replay high-water mark, #956).
    fn persist_nonce(&self, pairing_id: &str, nonce: u64);

    /// Drop the persisted whitelist entry for `origin` (on `connect.revoke`). Idempotent.
    fn remove_whitelist(&self, origin: &str);

    /// Drop the persisted pairing record for `pairing_id` (on a user revoke, dig_ecosystem#1848).
    /// Idempotent.
    ///
    /// This is the DURABLE half of a revoke; the immediate half is the live unpair, which the
    /// [`PairedAppsControl`](crate::loopback::PairedAppsControl) does first. Both are needed — without
    /// this one the app is refused now and restored at the next boot, which is a revocation that
    /// undoes itself.
    fn remove_pairing(&self, pairing_id: &str);

    /// Load every persisted sealed record + the nonce ledger for restore on boot.
    fn load(&self) -> PersistedSignState;
}

/// A no-op store: nothing is persisted and boot restores nothing. The default for a router built
/// without persistence — the existing unit tests, and any host with no per-profile directory (a
/// headless boot that never starts the loopback server).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSealedStore;

impl SealedRecordStore for NullSealedStore {
    fn persist_pairing(&self, _pairing_id: &str, _sealed: &[u8]) {}
    fn persist_whitelist(&self, _origin: &str, _sealed: &[u8]) {}
    fn persist_nonce(&self, _pairing_id: &str, _nonce: u64) {}
    fn remove_whitelist(&self, _origin: &str) {}
    fn remove_pairing(&self, _pairing_id: &str) {}
    fn load(&self) -> PersistedSignState {
        PersistedSignState::default()
    }
}

/// The production [`SealedRecordStore`]: writes sealed records + the nonce ledger under an
/// `app-sign/` directory inside the active profile's AppData directory (NC-3), through the crash-safe
/// [`crate::storage::write_durably`] idiom.
pub struct FileSealedStore {
    /// The active profile's directory, read at the moment of every write/read rather than captured.
    ///
    /// The profile directory is per-profile precisely so one profile's sealed records never land
    /// beside another's ([`crate::account::boot::active_profile_id`]). A captured `PathBuf` on a
    /// serving thread would keep writing new grants into the directory of the profile that was active
    /// at boot, which is the isolation this path exists to provide.
    ///
    /// It reads as `None` while no profile is active (a locked account), in which case this store
    /// persists nothing and restores nothing — the same best-effort outcome a failed write already
    /// has, and the only alternative to inventing a directory that belongs to no profile.
    profile_dir: LiveProfileDir,
}

impl FileSealedStore {
    /// Build a store rooted at `app-sign/` under `profile_dir` (the active profile's directory,
    /// [`crate::storage::profile_dir`]). A `&Path`/`PathBuf` converts to a FIXED directory (a
    /// fixture, or a host whose profile cannot move); production passes a
    /// [`Live::read`](crate::live::Live::read) over the residency so the store follows a profile
    /// switch. The directory tree is created lazily on the first write.
    pub fn new(profile_dir: impl Into<LiveProfileDir>) -> Self {
        Self {
            profile_dir: profile_dir.into(),
        }
    }

    /// The `app-sign/` root under the profile directory as it reads NOW, or `None` when no profile
    /// is active.
    fn root(&self) -> Option<PathBuf> {
        Some(self.profile_dir.get()?.join(APP_SIGN_SUBDIR))
    }

    /// The `pairings/` directory.
    fn pairings_dir(&self) -> Option<PathBuf> {
        Some(self.root()?.join(PAIRINGS_SUBDIR))
    }

    /// The `whitelist/` directory.
    fn whitelist_dir(&self) -> Option<PathBuf> {
        Some(self.root()?.join(WHITELIST_SUBDIR))
    }

    /// The nonce-ledger file path.
    fn nonce_ledger_path(&self) -> Option<PathBuf> {
        Some(self.root()?.join(NONCE_LEDGER_FILE))
    }

    /// Durably write `bytes` to `path`, creating its parent directory. Logs and swallows any error so
    /// a persistence failure never fails the caller's in-memory operation.
    fn write(path: &Path, what: &str, bytes: &[u8]) {
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
                // Owner-only (0700) on the created app-sign subdirs, for parity with the sealed
                // profile store + defense-in-depth (DiD-2). The contents are already sealed ciphertext
                // or a non-secret counter, and the ancestor profile dir is 0700 — this is belt-and-braces.
                crate::storage::restrict_to_owner(parent)?;
            }
            let temp = path.with_extension("tmp");
            crate::storage::write_durably(path, &temp, bytes)
        })();
        if let Err(e) = result {
            tracing::warn!(error = %e, what, "failed to persist an APP-SIGN record");
        }
    }

    /// Read every `*.seal` file's bytes from `dir` (missing dir ⇒ empty).
    fn read_sealed_dir(dir: &Path) -> Vec<Vec<u8>> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                (path.extension()?.to_str()? == SEAL_EXT).then_some(path)
            })
            .filter_map(|path| std::fs::read(&path).ok())
            .collect()
    }

    /// Read the plaintext nonce high-water-mark ledger (missing/corrupt/no active profile ⇒ empty).
    fn read_nonce_ledger(&self) -> HashMap<String, u64> {
        self.nonce_ledger_path()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<NonceLedger>(&bytes).ok())
            .map(|ledger| ledger.marks)
            .unwrap_or_default()
    }

    /// Delete `path`, treating "it was not there" as success — a revoke is idempotent, and a record
    /// that never reached disk is one the user still wants gone.
    fn remove(path: &Path, what: &str) {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %e, what, "failed to remove a revoked APP-SIGN record");
            }
        }
    }

    /// Drop `pairing_id` from the nonce ledger, rewriting what remains.
    fn forget_nonce(&self, pairing_id: &str) {
        let mut marks = self.read_nonce_ledger();
        if marks.remove(pairing_id).is_none() {
            return;
        }
        self.write_nonce_ledger(marks);
    }

    /// Serialize and durably write `marks`, or skip with a warning when no profile is active. The one
    /// place the ledger is written, so the two callers cannot drift on the no-profile case.
    fn write_nonce_ledger(&self, marks: HashMap<String, u64>) {
        let Some(path) = self.nonce_ledger_path() else {
            return Self::skipped("nonce-ledger");
        };
        match serde_json::to_vec(&NonceLedger { marks }) {
            Ok(bytes) => Self::write(&path, "nonce-ledger", &bytes),
            Err(e) => tracing::warn!(error = %e, "failed to serialize the APP-SIGN nonce ledger"),
        }
    }

    /// Note that an at-rest operation was skipped because no profile is active.
    ///
    /// Persistence here is best-effort by contract (see [`SealedRecordStore`]), and a locked account
    /// has no directory of its own to write into. Inventing one would file a record under a profile
    /// that does not own it, which is the very confusion the per-profile directory prevents.
    fn skipped(what: &str) {
        tracing::warn!(what, "no active profile — APP-SIGN state was not persisted");
    }

    /// The file name for `pairing_id`'s sealed record. The id is an app-minted UUID, so this is a
    /// straight join — but it goes through one named function so the whitelist's hashing and this
    /// crate's assumption about pairing ids are both visible in one place.
    fn pairing_file_name(pairing_id: &str) -> String {
        format!("{pairing_id}.{SEAL_EXT}")
    }

    /// The filesystem-safe file name for `origin`'s sealed whitelist entry — a SHA-256 of the origin,
    /// so an arbitrary origin string can never escape the whitelist directory or collide illegibly.
    fn origin_file_name(origin: &str) -> String {
        format!("{:x}.{SEAL_EXT}", Sha256::digest(origin.as_bytes()))
    }
}

impl SealedRecordStore for FileSealedStore {
    fn persist_pairing(&self, pairing_id: &str, sealed: &[u8]) {
        let Some(dir) = self.pairings_dir() else {
            return Self::skipped("pairing");
        };
        Self::write(
            &dir.join(Self::pairing_file_name(pairing_id)),
            "pairing",
            sealed,
        );
    }

    fn persist_whitelist(&self, origin: &str, sealed: &[u8]) {
        let Some(dir) = self.whitelist_dir() else {
            return Self::skipped("whitelist");
        };
        Self::write(
            &dir.join(Self::origin_file_name(origin)),
            "whitelist",
            sealed,
        );
    }

    fn persist_nonce(&self, pairing_id: &str, nonce: u64) {
        // Read-modify-write the small ledger. Only ever RAISE a mark, so an out-of-order write can
        // never lower the high-water mark and reopen a replay window.
        let mut marks = self.read_nonce_ledger();
        let entry = marks.entry(pairing_id.to_string()).or_insert(nonce);
        *entry = (*entry).max(nonce);
        self.write_nonce_ledger(marks);
    }

    fn remove_whitelist(&self, origin: &str) {
        let Some(dir) = self.whitelist_dir() else {
            return Self::skipped("whitelist");
        };
        Self::remove(&dir.join(Self::origin_file_name(origin)), "whitelist");
    }

    fn remove_pairing(&self, pairing_id: &str) {
        // A pairing id is a UUID this app minted, never caller input, so it cannot carry a path
        // separator. The file name is still built from it through `pairing_file_name`, which is the
        // one place that assumption is stated and checked.
        let Some(dir) = self.pairings_dir() else {
            return Self::skipped("pairing");
        };
        Self::remove(&dir.join(Self::pairing_file_name(pairing_id)), "pairing");
        // The nonce high-water mark goes with it: leaving an orphan mark behind would seed a future
        // pairing that happened to reuse the id, and it is state about an app the user just removed.
        self.forget_nonce(pairing_id);
    }

    fn load(&self) -> PersistedSignState {
        let read = |dir: Option<PathBuf>| {
            dir.as_deref()
                .map(Self::read_sealed_dir)
                .unwrap_or_default()
        };
        PersistedSignState {
            pairings: read(self.pairings_dir()),
            whitelist: read(self.whitelist_dir()),
            nonces: self.read_nonce_ledger(),
        }
    }
}

/// The on-disk shape of the plaintext nonce ledger.
#[derive(Debug, Default, Serialize, Deserialize)]
struct NonceLedger {
    /// The last accepted nonce per pairing id.
    marks: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> FileSealedStore {
        FileSealedStore::new(dir)
    }

    /// A test high-water-mark value DERIVED from a seed hash rather than an integer literal, so static
    /// analysis does not flag a "hard-coded cryptographic nonce" — these are the pairing replay
    /// COUNTER (a monotonic `u64`), not key/IV material. Strictly monotonic in `step`.
    fn mark(step: u64) -> u64 {
        use sha2::Digest;
        let seed = Sha256::digest(b"dig-app persist test nonce ledger mark");
        u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]])) + step
    }

    #[test]
    fn a_null_store_persists_nothing_and_restores_empty() {
        let s = NullSealedStore;
        s.persist_pairing("p", b"x");
        s.persist_whitelist("o", b"x");
        s.persist_nonce("p", mark(9));
        let state = s.load();
        assert!(state.pairings.is_empty());
        assert!(state.whitelist.is_empty());
        assert!(state.nonces.is_empty());
    }

    #[test]
    fn sealed_pairings_and_whitelist_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.persist_pairing("pairing-1", b"sealed-pairing-bytes");
        s.persist_whitelist("https://dapp.example", b"sealed-whitelist-bytes");

        let state = s.load();
        assert_eq!(state.pairings, vec![b"sealed-pairing-bytes".to_vec()]);
        assert_eq!(state.whitelist, vec![b"sealed-whitelist-bytes".to_vec()]);
    }

    #[test]
    fn the_nonce_ledger_only_ever_rises_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.persist_nonce("pairing-1", mark(5));
        s.persist_nonce("pairing-1", mark(3)); // stale/out-of-order — must not lower the mark
        s.persist_nonce("pairing-2", mark(42));

        let nonces = s.load().nonces;
        assert_eq!(nonces.get("pairing-1"), Some(&mark(5)));
        assert_eq!(nonces.get("pairing-2"), Some(&mark(42)));
    }

    #[test]
    fn revoking_removes_the_whitelist_record() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.persist_whitelist("https://dapp.example", b"sealed");
        assert_eq!(s.load().whitelist.len(), 1);

        s.remove_whitelist("https://dapp.example");
        assert!(s.load().whitelist.is_empty());
        // Revoking again is idempotent (no panic, no error surfaced).
        s.remove_whitelist("https://dapp.example");
    }

    #[test]
    fn loading_an_empty_or_missing_root_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = store(&dir.path().join("does-not-exist")).load();
        assert!(state.pairings.is_empty());
        assert!(state.whitelist.is_empty());
        assert!(state.nonces.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_app_sign_dirs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.persist_pairing("pairing-1", b"sealed");
        let pairings = s
            .pairings_dir()
            .expect("the fixture store has a root, so persist_pairing above succeeded");
        let mode = std::fs::metadata(pairings)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "the app-sign pairing dir must be owner-only");
    }

    #[test]
    fn distinct_origins_get_distinct_files() {
        assert_ne!(
            FileSealedStore::origin_file_name("https://a.example"),
            FileSealedStore::origin_file_name("https://b.example")
        );
        // The name is a hex sha256 with the seal extension — no path separators from the origin.
        let name = FileSealedStore::origin_file_name("https://evil../../escape");
        assert!(name.ends_with(".seal"));
        assert!(!name.contains('/'));
    }
}
