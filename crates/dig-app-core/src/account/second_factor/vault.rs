//! The at-rest **second-factor enrolment record** (dig_ecosystem#1840).
//!
//! Mirrors [`PhraseVault`](crate::account::phrase_vault::PhraseVault) deliberately: same directory,
//! same [`ProfileSealer`] seam, same durable-write discipline, same fail-closed behaviour the instant
//! the account locks. Two vaults with two shapes would be two places for the at-rest rules to drift.
//!
//! # The envelope, and what it is for
//!
//! The sealed plaintext is [`ENVELOPE_MAGIC`] followed by the record's JSON. The magic is not a
//! checksum — the AEAD already authenticates the bytes — it is DOMAIN SEPARATION: both vaults in this
//! directory are sealed under the same profile DEK, so without a domain tag a recovery-phrase blob
//! renamed over this file would decrypt successfully and only then fail to parse. With it, the
//! confusion is refused at the boundary, by the tag the AEAD itself protects. It also carries a
//! version, so a future record shape can be recognised rather than guessed at.
//!
//! # What "verifying a code" means here
//!
//! [`SecondFactorVault::challenge`] is the ONE place a code is judged, and it enforces three rules the
//! arithmetic in [`totp`](super::totp) cannot:
//!
//! 1. **A TOTP step is accepted at most once.** RFC 6238 §5.2 — a code is valid for a whole 30-second
//!    window, so one read off a screen would otherwise work again for the rest of that window.
//! 2. **A recovery code is spent when used.**
//! 3. **Both outcomes are persisted before the caller is told "yes".** A crash between accepting and
//!    recording would otherwise silently restore a spent code.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::recovery_codes::{self, RecoveryCodeSet, StoredRecoveryCode};
use super::totp::{SecretError, TotpSecret};
use crate::sealer::{ProfileSealer, SealError};
use crate::storage;

/// The vault file name inside the profile directory. `.seal` marks it as DIGOP1 ciphertext, matching
/// the recovery-phrase vault beside it.
///
/// Crate-visible so account removal can sweep for it by name, exactly as it does for the phrase vault:
/// once an account is destroyed its profile directory can no longer be computed, so the sweep needs
/// the literal.
pub(crate) const VAULT_FILE: &str = "second-factor.seal";

/// The domain tag every second-factor blob starts with, inside the sealed plaintext.
const ENVELOPE_MAGIC: &[u8] = b"DIG2FA1\n";

/// What the disable path needs of an enrolment: whether one exists, and how to remove it.
///
/// # Why removal is a seam and reading is not
///
/// Reading the record requires the profile's DEK, so it is inherently gated on an unlocked account.
/// REMOVING it only deletes a file, and its authorization is the platform biometric rather than the
/// account — so it can and must work while the account is locked, or an account that will not open
/// could never have its factor removed and would be permanently unreplaceable (see
/// [`two_factor_row`](crate::tray_menu)). This trait is what lets one journey serve both cases without
/// pretending a locked account can open its vault.
pub trait Enrolment {
    /// Whether a second factor is enrolled.
    fn is_enrolled(&self) -> bool;

    /// Remove the enrolment. Removing one that is not there succeeds, so a half-torn-down state can
    /// always be finished.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] when a file exists and cannot be deleted.
    fn remove(&self) -> Result<(), VaultError>;
}

/// The unlock-free view of every profile's enrolment under one brand directory.
///
/// Addresses the enrolment FILES by name — the same directory scan the account-discard sweep uses —
/// rather than by profile id, which is what makes it usable on a locked or unopenable account.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryEnrolment<'a> {
    brand_dir: &'a Path,
}

impl<'a> DirectoryEnrolment<'a> {
    /// View the enrolments under `brand_dir`.
    pub fn new(brand_dir: &'a Path) -> Self {
        Self { brand_dir }
    }

    /// Every enrolment file present, in no particular order.
    fn files(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.brand_dir.join("profiles")) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|profile| profile.path().join(VAULT_FILE))
            .filter(|path| path.exists())
            .collect()
    }
}

impl Enrolment for DirectoryEnrolment<'_> {
    fn is_enrolled(&self) -> bool {
        !self.files().is_empty()
    }

    fn remove(&self) -> Result<(), VaultError> {
        for path in self.files() {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(VaultError::Io(e)),
            }
        }
        Ok(())
    }
}

/// Whether ANY profile under `brand_dir` has a second-factor enrolment, WITHOUT unlocking the account.
///
/// The gate on the destructive verbs reads enrolment through this rather than through
/// [`SecondFactorVault::is_enrolled`], because a gate that could only see the factor while unlocked
/// would be walked around by clicking `Lock now` first.
pub fn enrolment_present(brand_dir: &Path) -> bool {
    DirectoryEnrolment::new(brand_dir).is_enrolled()
}

/// Why a vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The record could not be sealed or opened — normally because the account is locked.
    #[error(transparent)]
    Seal(#[from] SealError),

    /// The vault file could not be read or written.
    #[error("could not access the second-factor vault: {0}")]
    Io(#[from] std::io::Error),

    /// The decrypted bytes were not a second-factor record: a wrong domain tag, unparseable JSON, or a
    /// secret of the wrong length. Never rendered as a working enrolment.
    #[error("the stored second-factor enrolment is not readable")]
    Corrupt,
}

impl From<SecretError> for VaultError {
    fn from(_: SecretError) -> Self {
        Self::Corrupt
    }
}

/// The enrolment record, as it is sealed.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    /// The shared secret, hex-encoded so the record is plain JSON.
    secret: String,
    /// The salted digests of the recovery codes.
    recovery_codes: Vec<StoredRecoveryCode>,
    /// The most recent TOTP step accepted, so it cannot be accepted again.
    ///
    /// `None` until the first code is verified, which is also the enrolment moment.
    last_accepted_step: Option<u64>,
}

/// What a challenge concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeOutcome {
    /// A correct, unused authenticator code.
    Accepted,
    /// A correct, unspent recovery code. Carries how many remain, so the user can be told plainly
    /// rather than discovering at the worst moment that they are out.
    AcceptedRecoveryCode {
        /// How many unspent recovery codes are left.
        remaining: usize,
    },
    /// A code that is arithmetically correct but has ALREADY been used inside its own window.
    ///
    /// Reported separately from a plain rejection because it means something different to the user
    /// ("wait for the next code", not "you typed it wrong") — and because collapsing the two would hide
    /// the replay guard from every test.
    AlreadyUsed,
    /// Neither a valid code nor a valid recovery code.
    Rejected,
}

/// The per-profile store of the account's second-factor enrolment.
///
/// Generic over any [`ProfileSealer`] so it is unit-testable against a fake sealer; production wires
/// the live-view [`ResidencySealer`](crate::account::residency::ResidencySealer), which fails closed
/// the moment the account locks.
pub struct SecondFactorVault<S: ProfileSealer> {
    sealer: S,
    profile_did: String,
    path: PathBuf,
}

impl<S: ProfileSealer> SecondFactorVault<S> {
    /// Address the vault for `profile_did` inside `brand_dir`.
    pub fn new(sealer: S, brand_dir: &Path, profile_did: &str) -> Self {
        let dir = storage::profile_dir(brand_dir, &storage::did_hash(profile_did));
        Self {
            sealer,
            profile_did: profile_did.to_string(),
            path: dir.join(VAULT_FILE),
        }
    }

    /// Complete an enrolment: seal `secret` and the digests of `codes`.
    ///
    /// Called only after a code has been verified against `secret` (see
    /// [`journey`](super::journey)) — writing before verification is precisely how a person ends up
    /// locked out by a setup flow.
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked; [`VaultError::Io`] on a write failure.
    pub fn enrol(&self, secret: &TotpSecret, codes: &RecoveryCodeSet) -> Result<(), VaultError> {
        self.write(&Record {
            secret: hex::encode(secret.as_bytes()),
            recovery_codes: codes.to_stored(),
            last_accepted_step: None,
        })
    }

    /// Judge `typed` — an authenticator code or a recovery code — as of `now` (unix seconds), and
    /// persist whatever it consumed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked (so a locked account can never satisfy a
    /// challenge), [`VaultError::Corrupt`] if the record is unreadable, [`VaultError::Io`] on a write
    /// failure. A challenge that cannot be *recorded* is not reported as accepted.
    pub fn challenge(&self, typed: &str, now: u64) -> Result<ChallengeOutcome, VaultError> {
        let mut record = self.read()?;
        let secret =
            TotpSecret::from_bytes(&hex::decode(&record.secret).map_err(|_| VaultError::Corrupt)?)?;

        if let Some(step) = secret.matching_step(typed, now) {
            // Rule 1: a step is spendable once. `>=` rather than `>` because the LAST accepted step is
            // itself already spent.
            if record.last_accepted_step.is_some_and(|last| step <= last) {
                return Ok(ChallengeOutcome::AlreadyUsed);
            }
            record.last_accepted_step = Some(step);
            self.write(&record)?;
            return Ok(ChallengeOutcome::Accepted);
        }

        if recovery_codes::spend(&mut record.recovery_codes, typed) {
            let remaining = recovery_codes::remaining(&record.recovery_codes);
            self.write(&record)?;
            return Ok(ChallengeOutcome::AcceptedRecoveryCode { remaining });
        }

        Ok(ChallengeOutcome::Rejected)
    }

    /// How many recovery codes remain unspent, for telling the user where they stand.
    ///
    /// # Errors
    ///
    /// As [`challenge`](Self::challenge): the record must be readable, which means unlocked.
    pub fn remaining_recovery_codes(&self) -> Result<usize, VaultError> {
        Ok(recovery_codes::remaining(&self.read()?.recovery_codes))
    }

    /// Open and parse the sealed record.
    fn read(&self) -> Result<Record, VaultError> {
        let ciphertext = std::fs::read(&self.path)?;
        let plaintext = self.sealer.open(&self.profile_did, &ciphertext)?;
        let body = plaintext
            .strip_prefix(ENVELOPE_MAGIC)
            .ok_or(VaultError::Corrupt)?;
        serde_json::from_slice(body).map_err(|_| VaultError::Corrupt)
    }

    /// Seal and durably replace the record.
    fn write(&self, record: &Record) -> Result<(), VaultError> {
        let mut plaintext = ENVELOPE_MAGIC.to_vec();
        // `to_vec` cannot fail for this record (no maps with non-string keys, no non-finite floats).
        plaintext.extend_from_slice(&serde_json::to_vec(record).map_err(|_| VaultError::Corrupt)?);
        let sealed = self.sealer.seal(&self.profile_did, &plaintext)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("seal.tmp");
        storage::write_durably(&self.path, &temp, &sealed)?;
        storage::restrict_to_owner(&self.path)?;
        Ok(())
    }
}

impl<S: ProfileSealer> Enrolment for SecondFactorVault<S> {
    /// Cheap (a file-existence check) and needs no unlock, so the tray can ask it on every repaint.
    fn is_enrolled(&self) -> bool {
        self.path.exists()
    }

    /// Remove this profile's enrolment. Authorization is the CALLER's job and happens before this is
    /// reached (see [`journey::disable`](super::journey::disable)) — this is the storage half only.
    fn remove(&self) -> Result<(), VaultError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::second_factor::totp::STEP_SECONDS;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// The same keyed-prefix fake the phrase vault uses: reversible but DID-bound, so cross-profile
    /// isolation is exercised for real, and lockable, because "the account locked mid-challenge" is a
    /// state a sealer that can only succeed could never express.
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

    const DID_A: &str = "did:chia:profile-a";
    const DID_B: &str = "did:chia:profile-b";
    /// An explicit, pinned "now" — never `SystemTime::now`. A fixture that reads the wall clock cannot
    /// place a code at a chosen step, and a test group that passed small literals through a wall-clock
    /// API would be exercising only the far-past path.
    const NOW: u64 = 1_700_000_000;

    fn vault(dir: &Path, did: &str) -> SecondFactorVault<FakeSealer> {
        SecondFactorVault::new(FakeSealer::default(), dir, did)
    }

    /// Enrol a vault and hand back the secret and codes the "user" holds.
    fn enrolled(dir: &Path) -> (SecondFactorVault<FakeSealer>, TotpSecret, RecoveryCodeSet) {
        let vault = vault(dir, DID_A);
        let secret = TotpSecret::generate();
        let codes = RecoveryCodeSet::generate();
        vault.enrol(&secret, &codes).expect("enrol");
        (vault, secret, codes)
    }

    #[test]
    fn an_enrolment_round_trips_and_accepts_the_users_code() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        assert!(!vault.is_enrolled(), "nothing enrolled yet");

        let (vault, secret, _) = enrolled(dir.path());
        assert!(vault.is_enrolled());
        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
    }

    /// RFC 6238 §5.2's single-use rule. The SECOND presentation of the same code inside its own window
    /// must be refused — and refused as `AlreadyUsed`, not as a typo, because the two mean different
    /// things to the person at the keyboard.
    #[test]
    fn the_same_code_cannot_be_used_twice_inside_its_window() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());
        let code = secret.code_at(NOW);

        assert_eq!(
            vault.challenge(&code, NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.challenge(&code, NOW + 5).unwrap(),
            ChallengeOutcome::AlreadyUsed,
            "still inside the same 30s window"
        );
    }

    /// …and the NEXT window works normally, so the replay guard is not a one-shot lockout. Without this
    /// control the guard could be "accept exactly one code, ever" and the test above would not notice.
    #[test]
    fn the_next_windows_code_is_accepted_after_one_was_spent() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());
        let later = NOW + STEP_SECONDS;

        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.challenge(&secret.code_at(later), later).unwrap(),
            ChallengeOutcome::Accepted
        );
    }

    /// A code from a window BEFORE the one already spent must not be replayed either — the skew window
    /// reaches backwards, so `<=` rather than `==` is what closes it. A guard written as "not the same
    /// step" would pass the test above and fail this one.
    #[test]
    fn an_older_code_cannot_be_replayed_after_a_newer_one() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());
        let previous = secret.code_at(NOW - STEP_SECONDS);

        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.challenge(&previous, NOW).unwrap(),
            ChallengeOutcome::AlreadyUsed,
            "a code from the previous step is still inside the skew window and must not be replayed"
        );
    }

    /// The lost-phone path, which is the reason recovery codes exist: with NO valid authenticator code
    /// available, a recovery code still gets the user in — once — and the count drops.
    #[test]
    fn a_recovery_code_gets_the_user_in_without_the_phone() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, codes) = enrolled(dir.path());

        assert_eq!(
            vault.challenge(codes.code(0), NOW).unwrap(),
            ChallengeOutcome::AcceptedRecoveryCode {
                remaining: recovery_codes::CODE_COUNT - 1
            }
        );
        assert_eq!(
            vault.challenge(codes.code(0), NOW).unwrap(),
            ChallengeOutcome::Rejected,
            "a spent recovery code is gone"
        );
        assert_eq!(
            vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT - 1
        );
    }

    /// Spending one recovery code must leave the rest usable — the property a single-code fixture
    /// cannot see.
    #[test]
    fn the_other_recovery_codes_survive_one_being_spent() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, codes) = enrolled(dir.path());

        vault.challenge(codes.code(0), NOW).unwrap();
        assert!(matches!(
            vault.challenge(codes.code(1), NOW).unwrap(),
            ChallengeOutcome::AcceptedRecoveryCode { .. }
        ));
    }

    /// A wrong code is rejected and consumes nothing, so a mistyped code never costs a recovery code.
    #[test]
    fn a_wrong_code_is_rejected_and_consumes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        assert_eq!(
            vault.challenge("000000", NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        assert_eq!(
            vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT
        );
        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "the real code still works after a failed attempt"
        );
    }

    /// A locked account cannot satisfy a challenge — the second factor must not become a way AROUND
    /// the first one.
    #[test]
    fn a_locked_account_cannot_answer_a_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());
        let code = secret.code_at(NOW);

        vault.sealer.lock();
        assert!(matches!(
            vault.challenge(&code, NOW),
            Err(VaultError::Seal(_))
        ));
    }

    /// A locked account cannot ENROL either, so a failed setup never leaves a half-written vault whose
    /// codes nobody has.
    #[test]
    fn a_locked_account_cannot_enrol() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        vault.sealer.lock();

        assert!(matches!(
            vault.enrol(&TotpSecret::generate(), &RecoveryCodeSet::generate()),
            Err(VaultError::Seal(_))
        ));
        assert!(!vault.is_enrolled(), "a failed enrol leaves no vault file");
    }

    /// Turning the second factor off removes the enrolment, and doing it twice is not an error — a
    /// half-torn-down state must always be finishable.
    #[test]
    fn disabling_removes_the_enrolment_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        vault.remove().expect("disable");
        assert!(!vault.is_enrolled());
        vault.remove().expect("disabling again is not an error");
    }

    /// Another profile must not open this profile's enrolment. TWO actors are required: a single-profile
    /// fixture cannot distinguish "bound to this DID" from "bound to nothing".
    #[test]
    fn another_profile_cannot_open_this_enrolment() {
        let dir = tempfile::tempdir().unwrap();
        let (owner, secret, _) = enrolled(dir.path());
        let intruder = SecondFactorVault {
            sealer: FakeSealer::default(),
            profile_did: DID_B.to_string(),
            path: owner.path.clone(),
        };

        assert!(matches!(
            intruder.challenge(&secret.code_at(NOW), NOW),
            Err(VaultError::Seal(SealError::Open))
        ));
    }

    /// The domain tag doing its job: a blob sealed by the SAME profile DEK but belonging to another
    /// vault decrypts successfully and is still refused.
    ///
    /// The fixture is the real confusion — the recovery-phrase vault's own plaintext shape, sealed
    /// under the same DID — rather than random bytes, which the JSON parser would have rejected anyway
    /// and which therefore could not tell a domain check from a parse check.
    #[test]
    fn a_blob_from_the_other_vault_is_refused_even_though_it_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let foreign = vault
            .sealer
            .seal(DID_A, b"abandon abandon abandon")
            .unwrap();
        std::fs::create_dir_all(vault.path.parent().unwrap()).unwrap();
        std::fs::write(&vault.path, foreign).unwrap();

        assert!(matches!(
            vault.challenge("123456", NOW),
            Err(VaultError::Corrupt)
        ));
    }

    /// A correctly-tagged but structurally wrong record is corrupt, not a working enrolment. This is
    /// the SECOND half of the check above: together they pin that the tag and the parse are both
    /// required, so neither can be dropped without a test noticing.
    #[test]
    fn a_tagged_but_unparseable_record_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let mut plaintext = ENVELOPE_MAGIC.to_vec();
        plaintext.extend_from_slice(b"{\"not\":\"a record\"}");
        let sealed = vault.sealer.seal(DID_A, &plaintext).unwrap();
        std::fs::create_dir_all(vault.path.parent().unwrap()).unwrap();
        std::fs::write(&vault.path, sealed).unwrap();

        assert!(matches!(
            vault.challenge("123456", NOW),
            Err(VaultError::Corrupt)
        ));
    }

    /// The at-rest bar: neither the secret nor a recovery code may be findable in the file. A
    /// round-trip test alone would pass for a vault that wrote plaintext.
    #[test]
    fn the_file_on_disk_carries_no_readable_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, codes) = enrolled(dir.path());
        let raw = String::from_utf8_lossy(&std::fs::read(&vault.path).unwrap()).to_string();

        assert!(
            !raw.contains(&*secret.base32()),
            "the base32 secret is on disk"
        );
        for i in 0..codes.len() {
            let code: String = codes.code(i).chars().filter(|c| *c != '-').collect();
            assert!(!raw.contains(&code), "recovery code {i} is on disk");
        }
    }

    /// A vault that was never enrolled reports so rather than erroring, which is what lets the tray ask
    /// on every repaint.
    #[test]
    fn an_unenrolled_vault_is_simply_not_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!vault(dir.path(), DID_A).is_enrolled());
    }

    /// The unlock-free check sees a real enrolment and nothing else.
    ///
    /// The negative control is a profile directory holding the OTHER vault's file: without it, a scan
    /// that reported "any file in any profile directory" would pass — and the gate would then block
    /// every destructive verb on every account that has ever shown a recovery phrase.
    #[test]
    fn the_unlock_free_check_sees_an_enrolment_and_not_its_neighbour() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!enrolment_present(dir.path()), "nothing at all");

        let profile = dir.path().join("profiles").join("hash");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("recovery-phrase.seal"), b"x").unwrap();
        assert!(
            !enrolment_present(dir.path()),
            "the phrase vault is not a second factor"
        );

        std::fs::write(profile.join(VAULT_FILE), b"x").unwrap();
        assert!(enrolment_present(dir.path()));
    }

    /// The unlock-free view can also REMOVE an enrolment — the escape hatch for an account that can
    /// never be unlocked, and therefore can never answer a challenge.
    ///
    /// It must remove the enrolment and LEAVE the recovery-phrase vault beside it: a sweep that took
    /// everything would silently make a recoverable account unrecoverable, and a fixture with only the
    /// one file could not see that.
    #[test]
    fn the_unlock_free_view_removes_the_enrolment_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        let profile = std::fs::read_dir(dir.path().join("profiles"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let phrase = profile.join("recovery-phrase.seal");
        std::fs::write(&phrase, b"sealed").unwrap();

        let view = DirectoryEnrolment::new(dir.path());
        assert!(view.is_enrolled());
        view.remove().expect("remove");

        assert!(!view.is_enrolled(), "the enrolment is gone");
        assert!(phrase.exists(), "the recovery phrase must survive");
    }

    /// It must agree with the vault's own view, so the tray and the gate can never disagree about
    /// whether a factor is enrolled.
    #[test]
    fn the_unlock_free_check_agrees_with_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        assert!(vault.is_enrolled() && enrolment_present(dir.path()));
        vault.remove().unwrap();
        assert!(!vault.is_enrolled() && !enrolment_present(dir.path()));
    }
}
