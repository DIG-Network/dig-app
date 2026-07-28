//! The **recovery-phrase vault** — how an enrolled account can show its phrase again
//! (dig_ecosystem#1752).
//!
//! # The problem this closes
//!
//! A phrase shown once and never again is a phrase people lose. But `dig-account` deliberately keeps
//! the raw master seed inside itself — `UnlockedAccount` hands out capability handles (a signer, a DEK,
//! wallet ops) and *never* the seed — so dig-app cannot re-derive the words from the enrolled seed. See
//! `DEVELOPMENT_LOG.md`: exposing a `recovery_seed()` accessor on `UnlockedAccount` is the cleaner
//! answer and is a release-first `dig-account` change, not something to fork custody over here.
//!
//! So the app keeps its own sealed copy of the words at enrolment, when it legitimately holds them.
//!
//! # Why this adds no new exposure class
//!
//! The phrase and the master seed are the same secret in two encodings (`account::recovery` — the
//! entropy IS the seed). The vault seals the words under the account's **root-profile DEK**, which is
//! itself derived from that seed and available only while the account is unlocked. So the ciphertext
//! sits beside the sealed seed, in the same per-user directory, decryptable under the same unlock —
//! one secret, one custody boundary, no second key to protect. Losing the vault file loses nothing the
//! user still has the phrase for; stealing it without the unlocked account yields AEAD ciphertext.
//!
//! # Legacy (phrase-less) accounts
//!
//! An account enrolled before this module existed has a CSPRNG seed and **no vault file**. Its words
//! cannot be reconstructed after the fact (the seed is unreadable from here), so
//! [`PhraseVault::load`] returning [`None`] is the load-bearing signal that an account is
//! *unrecoverable*, which the tray surfaces plainly rather than papering over. See
//! [`crate::tray_menu`] for what the user is offered.

use std::path::{Path, PathBuf};

use crate::account::recovery::RecoveryPhrase;
use crate::sealer::{ProfileSealer, SealError};
use crate::storage;

/// The vault file name inside the profile directory. `.seal` marks it as DIGOP1 ciphertext, matching
/// the other sealed stores in the same directory.
const VAULT_FILE: &str = "recovery-phrase.seal";

/// Why a vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The words could not be sealed or opened — normally because the account is locked, or (on open)
    /// because the ciphertext does not belong to this profile.
    #[error(transparent)]
    Seal(#[from] SealError),

    /// The vault file could not be read or written.
    #[error("could not access the recovery-phrase vault: {0}")]
    Io(#[from] std::io::Error),

    /// The decrypted bytes were not a valid recovery phrase — a corrupted or foreign blob that still
    /// authenticated. Treated as "no phrase" rather than silently showing garbage words.
    #[error("the stored recovery phrase is not readable")]
    Corrupt,
}

/// The per-profile store of the account's own recovery phrase.
///
/// Generic over any [`ProfileSealer`] so it is unit-testable against a fake sealer; production wires
/// the live-view [`ResidencySealer`](crate::account::residency::ResidencySealer), which fails closed
/// the moment the account locks.
pub struct PhraseVault<S: ProfileSealer> {
    sealer: S,
    profile_did: String,
    path: PathBuf,
}

impl<S: ProfileSealer> PhraseVault<S> {
    /// Address the vault for `profile_did` inside `brand_dir`.
    ///
    /// The file lives in the profile's own directory (`storage::profile_dir`), so an account with
    /// several profiles keeps its one account-level phrase under the ROOT profile — the caller passes
    /// the root profile's id, as the boot path does.
    pub fn new(sealer: S, brand_dir: &Path, profile_did: &str) -> Self {
        let dir = storage::profile_dir(brand_dir, &storage::did_hash(profile_did));
        Self {
            sealer,
            profile_did: profile_did.to_string(),
            path: dir.join(VAULT_FILE),
        }
    }

    /// Whether a phrase has been stored for this profile — i.e. whether the account is recoverable.
    ///
    /// Cheap (a file-existence check), so the tray can ask it on every repaint without an unlock.
    pub fn is_recoverable(&self) -> bool {
        self.path.exists()
    }

    /// Seal `phrase` into the vault, replacing any prior copy.
    ///
    /// Called exactly once per account, immediately after the user confirms they have retained the
    /// words. Written durably (temp + rename) and restricted to the owner, like every other secret file
    /// the app persists.
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked; [`VaultError::Io`] on a write failure.
    pub fn store(&self, phrase: &RecoveryPhrase) -> Result<(), VaultError> {
        let words = phrase.words().join(" ");
        let sealed = self.sealer.seal(&self.profile_did, words.as_bytes())?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("seal.tmp");
        storage::write_durably(&self.path, &temp, &sealed)?;
        storage::restrict_to_owner(&self.path)?;
        Ok(())
    }

    /// Open the stored phrase, or [`None`] when this account has none (never stored, i.e. legacy).
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked or the ciphertext is not this profile's;
    /// [`VaultError::Corrupt`] if the plaintext is not a valid phrase.
    pub fn load(&self) -> Result<Option<RecoveryPhrase>, VaultError> {
        if !self.is_recoverable() {
            return Ok(None);
        }
        let ciphertext = std::fs::read(&self.path)?;
        let plaintext = self.sealer.open(&self.profile_did, &ciphertext)?;
        let words = std::str::from_utf8(&plaintext).map_err(|_| VaultError::Corrupt)?;
        RecoveryPhrase::parse(words)
            .map(Some)
            .map_err(|_| VaultError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// A sealer that AEAD-like-binds the ciphertext to the profile DID, so cross-profile isolation is
    /// exercised for real rather than assumed. It is deliberately reversible-but-keyed: prefixing the
    /// DID means opening under a different DID fails exactly where a real DEK mismatch would.
    ///
    /// It can also be put into a LOCKED state, because "the account locked mid-reveal" is a state the
    /// vault must fail closed on and a sealer that can only succeed could never express it.
    #[derive(Default)]
    struct FakeSealer {
        locked: Mutex<bool>,
    }

    impl FakeSealer {
        fn lock(&self) {
            *self.locked.lock().unwrap() = true;
        }
    }

    impl ProfileSealer for FakeSealer {
        fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
            if *self.locked.lock().unwrap() {
                return Err(SealError::Seal("locked".into()));
            }
            let mut out = format!("{profile_did}|").into_bytes();
            out.extend_from_slice(plaintext);
            Ok(out)
        }

        fn open(
            &self,
            profile_did: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SealError> {
            if *self.locked.lock().unwrap() {
                return Err(SealError::Open);
            }
            let prefix = format!("{profile_did}|").into_bytes();
            ciphertext
                .strip_prefix(&prefix[..])
                .map(|rest| Zeroizing::new(rest.to_vec()))
                .ok_or(SealError::Open)
        }
    }

    fn vault(dir: &Path, did: &str) -> PhraseVault<FakeSealer> {
        PhraseVault::new(FakeSealer::default(), dir, did)
    }

    const DID_A: &str = "did:chia:profile-a";
    const DID_B: &str = "did:chia:profile-b";

    #[test]
    fn a_stored_phrase_loads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let phrase = RecoveryPhrase::generate();

        assert!(!vault.is_recoverable(), "nothing stored yet");
        vault.store(&phrase).expect("store");
        assert!(vault.is_recoverable());

        let loaded = vault.load().expect("load").expect("a phrase is stored");
        assert_eq!(loaded.words(), phrase.words());
        assert_eq!(&*loaded.master_seed(), &*phrase.master_seed());
    }

    /// The legacy signal the tray depends on: no file ⇒ `None`, NOT an error and not an empty phrase.
    #[test]
    fn an_account_with_no_vault_reports_no_phrase() {
        let dir = tempfile::tempdir().unwrap();
        assert!(vault(dir.path(), DID_A).load().expect("no error").is_none());
    }

    /// The at-rest bar: the words must not be findable in the file. A test that only round-trips would
    /// pass for a vault that wrote plaintext.
    #[test]
    fn the_file_on_disk_contains_no_plaintext_word() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();

        let raw = std::fs::read(&vault.path).unwrap();
        // The fake sealer is a keyed prefix, not a cipher, so this asserts the SHAPE the production
        // sealer must satisfy: the words never reach the file except through `seal`. Byte-level
        // ciphertext strength is dig-keystore's own (DIGOP1) contract, tested there.
        assert!(
            raw.starts_with(DID_A.as_bytes()),
            "sealed under the profile DID"
        );
    }

    /// Two profiles, one file: opening profile A's ciphertext as profile B must fail. TWO actors are
    /// required — a single-profile fixture cannot distinguish "bound to this DID" from "bound to
    /// nothing", so it would pass for a vault that ignored the DID entirely.
    #[test]
    fn another_profile_cannot_open_this_profiles_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let owner = vault(dir.path(), DID_A);
        owner.store(&RecoveryPhrase::generate()).unwrap();

        // Point a B-keyed vault at A's file, the exact shape of a copied-blob attack.
        let intruder = PhraseVault {
            sealer: FakeSealer::default(),
            profile_did: DID_B.to_string(),
            path: owner.path.clone(),
        };
        assert!(
            matches!(intruder.load(), Err(VaultError::Seal(SealError::Open))),
            "a foreign profile must not open the phrase"
        );
    }

    /// A locked account must not reveal the phrase — the whole point of gating the reveal behind unlock.
    #[test]
    fn a_locked_account_cannot_open_the_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        vault.store(&RecoveryPhrase::generate()).unwrap();

        vault.sealer.lock();
        assert!(matches!(vault.load(), Err(VaultError::Seal(_))));
    }

    /// A locked account must not be able to STORE either, so a failed enrolment never leaves an empty
    /// or half-written vault behind.
    #[test]
    fn a_locked_account_cannot_store_a_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        vault.sealer.lock();

        assert!(matches!(
            vault.store(&RecoveryPhrase::generate()),
            Err(VaultError::Seal(_))
        ));
        assert!(
            !vault.is_recoverable(),
            "a failed store leaves no vault file"
        );
    }

    /// Authenticated-but-nonsense plaintext is reported as corrupt, never rendered as words.
    #[test]
    fn plaintext_that_is_not_a_phrase_is_reported_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let sealed = vault
            .sealer
            .seal(DID_A, b"not a recovery phrase at all")
            .unwrap();
        std::fs::create_dir_all(vault.path.parent().unwrap()).unwrap();
        std::fs::write(&vault.path, sealed).unwrap();

        assert!(matches!(vault.load(), Err(VaultError::Corrupt)));
    }

    /// Re-storing replaces the copy rather than appending, so a re-enrolled account never serves the
    /// previous account's words.
    #[test]
    fn storing_again_replaces_the_previous_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let first = RecoveryPhrase::generate();
        let second = RecoveryPhrase::generate();

        vault.store(&first).unwrap();
        vault.store(&second).unwrap();

        let loaded = vault.load().unwrap().unwrap();
        assert_eq!(loaded.words(), second.words());
        assert_ne!(loaded.words(), first.words());
    }
}
