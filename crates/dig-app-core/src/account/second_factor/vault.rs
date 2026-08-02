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
//! [`SecondFactorVault::challenge`] is the ONE place a code is judged, and it enforces four rules the
//! arithmetic in [`totp`](super::totp) cannot:
//!
//! 1. **A TOTP step is accepted at most once.** RFC 6238 §5.2 — a code is valid for a whole 30-second
//!    window, so one read off a screen would otherwise work again for the rest of that window.
//! 2. **A recovery code is spent when used.**
//! 3. **Both outcomes are persisted before the caller is told "yes".** A crash between accepting and
//!    recording would otherwise silently restore a spent code.
//! 4. **Wrong attempts are bounded — persistently (dig_ecosystem#1847).** A consecutive-failure count
//!    and an escalating next-allowed-attempt instant ride the sealed record, so closing and reopening
//!    the window cannot hand an attacker a fresh unbounded run at a ~3-in-10^6 code. It is a rate limit,
//!    not a lockout, and it fails closed against a rolled-back clock.

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

/// How many consecutive failed challenges are absorbed with NO delay (dig_ecosystem#1847).
///
/// A person who fat-fingers the code, or whose phone clock has just ticked over, should not be made to
/// wait — three mirrors the enrolment retry budget ([`journey::VERIFY_ATTEMPTS`](super::journey)) and is
/// small enough that an actual attacker is throttled almost at once. The delay begins on the failure
/// AFTER this budget is spent.
const FREE_CHALLENGE_ATTEMPTS: u32 = 3;

/// The first enforced delay, in seconds, imposed on the failure after the free budget is spent
/// (dig_ecosystem#1847). It doubles with each further consecutive failure: 5s, 10s, 20s, 40s…
const BACKOFF_BASE_SECONDS: u64 = 5;

/// The ceiling on the escalating delay, in seconds — fifteen minutes (dig_ecosystem#1847).
///
/// This is a RATE LIMIT, never a hard lockout: a permanent lockout would be a denial-of-service against
/// the account's own owner, forcing them onto a recovery code they may not have. The delay grows without
/// bound only up to here. Even pinned at this cap the arithmetic is decisive: a 6-digit TOTP with a ±1
/// step tolerance is ~3-in-10^6 live per attempt (see [`totp`](super::totp)), so at four attempts an
/// hour an attacker needs on the order of tens of thousands of hours — years — to reach an even chance,
/// while a legitimate owner who waits fifteen minutes is always let back in.
const BACKOFF_MAX_SECONDS: u64 = 900;

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

    /// How many challenges have failed IN A ROW (dig_ecosystem#1847).
    ///
    /// Persisted with the sealed record — not held in the challenge window — precisely because the
    /// defect was that reopening the window reset it to zero. Reset on any accepted code.
    /// `#[serde(default)]` so a record written before this field existed (an already-enrolled user)
    /// reads back as zero prior failures rather than failing to parse.
    #[serde(default)]
    consecutive_failures: u32,

    /// The earliest unix second at which the NEXT challenge may be judged, once the free budget is
    /// spent (dig_ecosystem#1847). `None` means no delay is in force. Persisted, so the escalating
    /// delay cannot be walked around by closing and reopening the window.
    #[serde(default)]
    throttle_until: Option<u64>,

    /// The greatest instant this record has ever observed — the anti-rollback anchor
    /// (dig_ecosystem#1847). A wall clock reading earlier than this has been moved backwards; the
    /// challenge then treats time as frozen here, so a rollback can neither shorten a throttle nor
    /// replay an old code at its original window.
    #[serde(default)]
    clock_high_water: Option<u64>,
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
    /// Too many challenges have failed in a row, so the next attempt must WAIT (dig_ecosystem#1847).
    ///
    /// A rate limit, NOT a lockout: the required delay escalates with each failure but the account is
    /// never permanently sealed out of its own recovery path. The code was not even judged — a
    /// throttled attempt learns nothing about whether its guess was close.
    RateLimited {
        /// Whole seconds the caller must wait before another code will be looked at.
        retry_after_seconds: u64,
    },
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
            consecutive_failures: 0,
            throttle_until: None,
            clock_high_water: None,
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
    /// The bound the challenge window used to lack (dig_ecosystem#1847): a persistent, escalating
    /// rate limit. Every failure — a wrong TOTP code OR a wrong recovery code — advances a counter that
    /// rides the sealed record, so closing and reopening the window can no longer hand an attacker a
    /// fresh unbounded run. Once [`FREE_CHALLENGE_ATTEMPTS`] is spent, a required delay is imposed and
    /// doubled per failure up to [`BACKOFF_MAX_SECONDS`]; any accepted code clears it.
    pub fn challenge(&self, typed: &str, now: u64) -> Result<ChallengeOutcome, VaultError> {
        let mut record = self.read()?;

        // Anti-rollback anchor. If the wall clock reads earlier than the greatest instant this record
        // has seen, it has been moved backwards — freeze time at the high-water mark rather than trust
        // the smaller value, so a rollback can neither shorten the throttle below nor replay a code at
        // its original (now-past) window. Residual assumption, documented in SPEC §3.1e: an attacker
        // who can move the clock FORWARD at will already has the root-level control the threat model
        // (see the module docs) explicitly does not claim to defend against; the escalating delay only
        // ever RAISES the bar for the unlocked-machine attacker it is actually for.
        let effective_now = anchored_now(&record, now);
        record.clock_high_water = Some(effective_now);

        // The throttle is enforced BEFORE the code is judged: a rate-limited attempt must not even
        // learn whether its guess was arithmetically close.
        if let Some(until) = record.throttle_until {
            if effective_now < until {
                self.write(&record)?;
                return Ok(ChallengeOutcome::RateLimited {
                    retry_after_seconds: until - effective_now,
                });
            }
        }

        let secret =
            TotpSecret::from_bytes(&hex::decode(&record.secret).map_err(|_| VaultError::Corrupt)?)?;

        if let Some(step) = secret.matching_step(typed, effective_now) {
            // Rule 1: a step is spendable once. `<=` rather than `<` because the LAST accepted step is
            // itself already spent. A replayed-but-correct code is neither a fresh guess nor a success:
            // it does not advance the failure bound and does not clear it — only the clock anchor moved.
            if record.last_accepted_step.is_some_and(|last| step <= last) {
                self.write(&record)?;
                return Ok(ChallengeOutcome::AlreadyUsed);
            }
            record.last_accepted_step = Some(step);
            clear_failure_bound(&mut record);
            self.write(&record)?;
            return Ok(ChallengeOutcome::Accepted);
        }

        if recovery_codes::spend(&mut record.recovery_codes, typed) {
            let remaining = recovery_codes::remaining(&record.recovery_codes);
            clear_failure_bound(&mut record);
            self.write(&record)?;
            return Ok(ChallengeOutcome::AcceptedRecoveryCode { remaining });
        }

        // A wrong code — TOTP or recovery-code-shaped alike — advances the bound and, past the free
        // budget, arms the escalating delay. Counting the recovery path too is deliberate: ten codes
        // with unbounded guesses would be a weaker secret than it looks.
        record_failure(&mut record, effective_now);
        self.write(&record)?;
        Ok(ChallengeOutcome::Rejected)
    }

    /// Peek at the challenge throttle WITHOUT judging a code or writing anything.
    ///
    /// Returns `Some(retry_after_seconds)` iff a challenge attempted at `now` (unix seconds) would be
    /// turned away by the escalating rate limit that [`challenge`](Self::challenge) enforces, else
    /// `None`.
    ///
    /// # Why this is — and must stay — a pure, non-mutating read
    ///
    /// It exists so a caller ([`journey::challenge`](super::journey::challenge)) can tell a throttled
    /// user to WAIT *before* a code-input window is drawn, instead of after they have typed a whole
    /// code only to have it refused unread. To be safe to call speculatively it reveals nothing and
    /// changes nothing: it reads only the throttle timer — never a code, so it cannot leak whether a
    /// guess is arithmetically close — records NO failure, and, critically, does NOT persist the
    /// anti-rollback anchor. Advancing `clock_high_water` here would let a mere peek move the record
    /// forward, so [`anchored_now`] is computed in memory and discarded; only a real
    /// [`challenge`](Self::challenge) commits the anchor. A locked or unreadable vault fails closed via
    /// [`read`](Self::read) — it can never answer "not throttled" for a vault it could not open.
    ///
    /// # Errors
    ///
    /// As [`challenge`](Self::challenge): [`VaultError::Seal`] if the account is locked,
    /// [`VaultError::Corrupt`] if the record is unreadable.
    pub fn current_throttle(&self, now: u64) -> Result<Option<u64>, VaultError> {
        let record = self.read()?;
        let effective_now = anchored_now(&record, now);
        Ok(record
            .throttle_until
            .filter(|&until| effective_now < until)
            .map(|until| until - effective_now))
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

/// The instant the throttle math treats as "now": never earlier than the greatest instant this record
/// has already seen, so a clock wound backwards can neither shorten an armed throttle nor replay a code
/// at its original window. This is the READ half of the anti-rollback anchor (see
/// [`challenge`](SecondFactorVault::challenge)); persisting the advance onto `clock_high_water` is a
/// separate, write-side step that only a real challenge performs — a peek must not.
fn anchored_now(record: &Record, now: u64) -> u64 {
    record.clock_high_water.map_or(now, |seen| now.max(seen))
}

/// Clear the failure bound after a code is accepted — the account is back in the owner's hands.
fn clear_failure_bound(record: &mut Record) {
    record.consecutive_failures = 0;
    record.throttle_until = None;
}

/// Advance the failure bound by one and arm the escalating delay once the free budget is spent.
fn record_failure(record: &mut Record, now: u64) {
    record.consecutive_failures = record.consecutive_failures.saturating_add(1);
    record.throttle_until = backoff_delay(record.consecutive_failures).map(|delay| now + delay);
}

/// The required wait after `failures` consecutive wrong codes, or `None` while inside the free budget.
///
/// Zero for the first [`FREE_CHALLENGE_ATTEMPTS`] failures, then `BACKOFF_BASE_SECONDS * 2^(n-1)` for the
/// n-th failure past the budget, capped at [`BACKOFF_MAX_SECONDS`]. `checked_shl` only guards the shift
/// AMOUNT (a shift of ≥64 bits is undefined) — it does NOT bound the value; the trailing
/// `.min(BACKOFF_MAX_SECONDS)` is the real cap, holding the 0–63-bit range (where the shift itself can
/// value-wrap once the product exceeds `u64`) down to [`BACKOFF_MAX_SECONDS`] rather than a tiny wrapped
/// delay.
fn backoff_delay(failures: u32) -> Option<u64> {
    let past_budget = failures
        .checked_sub(FREE_CHALLENGE_ATTEMPTS)
        .filter(|&n| n > 0)?;
    let delay = BACKOFF_BASE_SECONDS
        .checked_shl(past_budget - 1)
        .unwrap_or(BACKOFF_MAX_SECONDS)
        .min(BACKOFF_MAX_SECONDS);
    Some(delay)
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

    // ──────────────── The persistent challenge bound (dig_ecosystem#1847) ────────────────

    /// **THE regression for #1847.** The attempt bound must survive the challenge window CLOSING. Every
    /// attempt here goes through a FRESH vault handle re-read from disk — the exact "close and reopen
    /// the window" the unbounded version reset to zero. Past the free budget a brand-new handle is told
    /// to WAIT rather than being handed a clean, unbounded run.
    ///
    /// Load-bearing check: revert the persistence (hold the counter in the handle rather than the
    /// sealed record) and every fresh handle sees zero failures, so the final attempt is `Rejected`, not
    /// `RateLimited`, and this fails.
    #[test]
    fn the_attempt_bound_survives_the_challenge_window_closing() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());

        // Spend the free budget, then one more — each through a brand-new handle (a reopened window).
        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                vault(dir.path(), DID_A).challenge("000000", NOW).unwrap(),
                ChallengeOutcome::Rejected
            );
        }

        match vault(dir.path(), DID_A).challenge("000000", NOW).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => assert!(
                retry_after_seconds > 0,
                "a throttle with no wait is no throttle"
            ),
            other => panic!("reopening the window bypassed the bound: {other:?}"),
        }
    }

    /// The escalating delay must be exactly that — escalating. The second armed delay is longer than the
    /// first, so patience does not buy an attacker a stable cheap retry rate.
    #[test]
    fn the_required_delay_grows_with_each_further_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        // Drive just past the budget to arm the first delay, read it, wait it out, fail again, read the
        // second. The second must be strictly longer.
        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            vault.challenge("000000", NOW).unwrap();
        }
        let first = match vault.challenge("000000", NOW).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            other => panic!("expected a throttle, got {other:?}"),
        };
        // Past the first delay, one more wrong code arms a longer one.
        let after_first = NOW + first;
        assert_eq!(
            vault.challenge("000000", after_first).unwrap(),
            ChallengeOutcome::Rejected
        );
        let second = match vault.challenge("000000", after_first).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            other => panic!("expected a second throttle, got {other:?}"),
        };
        assert!(
            second > first,
            "the delay must escalate: {second} was not longer than {first}"
        );
    }

    /// A legitimate owner who fat-fingers a code is NOT locked out: two wrong codes then the right one
    /// gets in, with no recovery code spent. The free budget exists precisely so honest mistakes cost
    /// nothing.
    #[test]
    fn two_wrong_codes_then_the_right_one_still_gets_the_owner_in() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        assert_eq!(
            vault.challenge("000000", NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        assert_eq!(
            vault.challenge("111111", NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "an honest mistake within the budget must not throttle the real code"
        );
        assert_eq!(
            vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT,
            "no recovery code was spent"
        );
    }

    /// An accepted code CLEARS the bound: after a success, the free budget is restored, so a later
    /// honest mistake is not met with a residual delay left over from before.
    #[test]
    fn a_successful_code_clears_the_failure_bound() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        // Arm a throttle, wait it out, and succeed.
        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            vault.challenge("000000", NOW).unwrap();
        }
        let wait = match vault.challenge("000000", NOW).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            other => panic!("expected a throttle, got {other:?}"),
        };
        let unblocked = NOW + wait;
        assert_eq!(
            vault
                .challenge(&secret.code_at(unblocked), unblocked)
                .unwrap(),
            ChallengeOutcome::Accepted
        );

        // The slate is clean: the whole free budget of wrong codes is available again with no delay.
        for _ in 0..FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                vault.challenge("000000", unblocked).unwrap(),
                ChallengeOutcome::Rejected,
                "the free budget must be restored after a success"
            );
        }
    }

    /// Wrong RECOVERY-code attempts count toward the same bound, not just wrong TOTP codes — otherwise
    /// the ten recovery codes would be a secret an attacker could guess without limit.
    #[test]
    fn wrong_recovery_code_attempts_count_toward_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());

        // A recovery-code-SHAPED wrong guess (dashed, in the alphabet) never matches a stored digest, so
        // it falls through to the failure path exactly as a wrong TOTP code does.
        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                vault(dir.path(), DID_A)
                    .challenge("ZZZZZ-ZZZZZ", NOW)
                    .unwrap(),
                ChallengeOutcome::Rejected
            );
        }
        assert!(
            matches!(
                vault(dir.path(), DID_A)
                    .challenge("ZZZZZ-ZZZZZ", NOW)
                    .unwrap(),
                ChallengeOutcome::RateLimited { .. }
            ),
            "recovery-code guesses must be throttled too"
        );
    }

    /// **Backwards compatibility (#1847).** A record written BEFORE the attempt-bound fields existed
    /// must still deserialize — an already-enrolled user's vault cannot be bricked by an update — and
    /// must read as zero prior failures. The fixture is a hand-written legacy record carrying only the
    /// three original fields.
    #[test]
    fn a_pre_bound_record_reads_as_zero_prior_failures() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let secret = TotpSecret::generate();

        let legacy = format!(
            r#"{{"secret":"{}","recovery_codes":[],"last_accepted_step":null}}"#,
            hex::encode(secret.as_bytes())
        );
        let mut plaintext = ENVELOPE_MAGIC.to_vec();
        plaintext.extend_from_slice(legacy.as_bytes());
        let sealed = vault.sealer.seal(DID_A, &plaintext).unwrap();
        std::fs::create_dir_all(vault.path.parent().unwrap()).unwrap();
        std::fs::write(&vault.path, sealed).unwrap();

        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "a legacy record must open and behave as a clean slate"
        );
    }

    /// **Clock tamper (#1847).** Rolling the wall clock BACK must not grant a free attempt. An attacker
    /// who captured a code from a past window rolls the clock back to it; the persisted high-water anchor
    /// freezes time at the present, so the stale code is judged as of now and refused.
    ///
    /// Load-bearing check: drop the anchor (judge at the raw `now`) and the stale code matches its
    /// original step and is `Accepted`, so this fails.
    #[test]
    fn a_clock_rolled_back_to_an_old_codes_window_grants_no_free_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        // One present-day attempt anchors the record's clock at NOW.
        assert_eq!(
            vault.challenge("000000", NOW).unwrap(),
            ChallengeOutcome::Rejected
        );

        // The attacker winds the clock ten steps into the past and replays a code from that window.
        let past = NOW - 10 * STEP_SECONDS;
        assert_eq!(
            vault.challenge(&secret.code_at(past), past).unwrap(),
            ChallengeOutcome::Rejected,
            "a code from a rolled-back window must not be accepted"
        );
    }

    /// A rollback must not shorten an ARMED throttle either: once a delay is in force, winding the clock
    /// back leaves the wait in place rather than expiring it early.
    #[test]
    fn rolling_the_clock_back_does_not_shorten_an_armed_throttle() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            vault.challenge("000000", NOW).unwrap();
        }
        assert!(matches!(
            vault.challenge("000000", NOW).unwrap(),
            ChallengeOutcome::RateLimited { .. }
        ));

        match vault.challenge("000000", NOW - 100_000).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => assert!(retry_after_seconds > 0, "a rollback must not zero the wait"),
            other => panic!("a rollback bypassed the throttle: {other:?}"),
        }
    }

    /// The backoff schedule itself: zero inside the budget, then a doubling sequence capped at the
    /// ceiling. Pinned from BOTH sides of the cap so neither the escalation nor the ceiling can silently
    /// change.
    #[test]
    fn the_backoff_schedule_is_zero_then_doubles_up_to_the_cap() {
        assert_eq!(backoff_delay(0), None);
        assert_eq!(
            backoff_delay(FREE_CHALLENGE_ATTEMPTS),
            None,
            "budget edge is free"
        );
        assert_eq!(
            backoff_delay(FREE_CHALLENGE_ATTEMPTS + 1),
            Some(BACKOFF_BASE_SECONDS)
        );
        assert_eq!(
            backoff_delay(FREE_CHALLENGE_ATTEMPTS + 2),
            Some(BACKOFF_BASE_SECONDS * 2)
        );
        assert_eq!(
            backoff_delay(FREE_CHALLENGE_ATTEMPTS + 3),
            Some(BACKOFF_BASE_SECONDS * 4)
        );
        // Far past the budget the delay is pinned at the cap and never overflows to a tiny value.
        assert_eq!(backoff_delay(1_000), Some(BACKOFF_MAX_SECONDS));
    }

    /// The peek reports no throttle for a fresh enrolment and a positive wait once one is armed — and
    /// the wait it reports matches what a real challenge would impose.
    #[test]
    fn current_throttle_reports_the_armed_wait_and_nothing_when_clear() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _, _) = enrolled(dir.path());
        assert_eq!(
            v.current_throttle(NOW).unwrap(),
            None,
            "a fresh enrolment is not throttled"
        );

        // Arm the throttle past the free budget through fresh handles (window closed between guesses).
        for _ in 0..6 {
            let _ = vault(dir.path(), DID_A).challenge("000000", NOW);
        }
        let peeked = vault(dir.path(), DID_A)
            .current_throttle(NOW)
            .unwrap()
            .expect("a wait is now armed");
        assert!(peeked > 0, "an armed throttle reports a positive wait");
    }

    /// The peek is a PURE read: calling it must record no failure, arm no throttle, and advance no clock
    /// anchor. A vault that is not throttled stays not throttled no matter how many times it is peeked,
    /// and a real code still passes afterwards — proof the peek wrote nothing.
    #[test]
    fn current_throttle_neither_writes_nor_consumes_an_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        for _ in 0..10 {
            assert_eq!(vault.current_throttle(NOW).unwrap(), None);
        }
        // Had the peek recorded failures, the bound would have armed; the correct code still passes.
        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "peeking must not consume the free-attempt budget"
        );
    }

    /// Peeking must NOT persist the anti-rollback anchor: a forward peek at a far-future instant must
    /// not push `clock_high_water` ahead, which would leave a later honest challenge judging codes at a
    /// clock the user never actually reached. The current code at the real time still passes after a
    /// far-future peek.
    #[test]
    fn peeking_far_in_the_future_does_not_advance_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = enrolled(dir.path());

        assert_eq!(vault.current_throttle(NOW + 10_000_000).unwrap(), None);
        assert_eq!(
            vault.challenge(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "a far-future peek must not have advanced the clock anchor"
        );
    }

    /// A locked vault fails CLOSED: the peek must surface the error, never quietly answer "not
    /// throttled" for a record it could not even open.
    #[test]
    fn current_throttle_fails_closed_on_a_locked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());
        vault.sealer.lock();
        assert!(
            vault.current_throttle(NOW).is_err(),
            "a locked vault must not report 'not throttled'"
        );
    }
}
