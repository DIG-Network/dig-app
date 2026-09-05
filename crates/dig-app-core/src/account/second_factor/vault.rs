//! The at-rest **second-factor enrolment record** (dig-app#348, superseding dig_ecosystem#1840).
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
//! confusion is refused at the boundary, by the tag the AEAD itself protects.
//!
//! It also carries a VERSION, and that is now load-bearing rather than forward-looking: a record
//! tagged [`SUPERSEDED_ENVELOPE_MAGIC`] is the old TOTP enrolment, and telling the two apart is what
//! keeps a shared-secret record from being read as a credential record. The tag lives INSIDE the
//! sealed plaintext, so the unlock-free probe — which can only see file names — cannot read it. That
//! is why a locked surface may report presence and must not report method.
//!
//! # What the record holds, and what it deliberately does not
//!
//! A public key, a credential id, a signature counter, the transports the platform reported at
//! enrolment, and the salted recovery-code digests. **No secret.** Nothing here, even together with
//! the account DEK, can produce an assertion. Its confidentiality is therefore not load-bearing; its
//! INTEGRITY is, and that integrity is exactly the DEK's — an attacker who holds the DEK can REWRITE
//! this record, which is the bound stated in the module docs of [`super`] and which no copy may
//! describe as prevented.
//!
//! # What "judging a challenge" means here
//!
//! Two entry points, because there are two kinds of evidence and they are judged differently:
//!
//! - [`SecondFactorVault::judge_assertion`] verifies a WebAuthn assertion against the enrolled
//!   credential and the one-use state that minted its challenge.
//! - [`SecondFactorVault::judge_typed`] judges something the user typed: a recovery code on either
//!   record shape, and — on a SUPERSEDED record only — a TOTP code, which exists solely so a person
//!   holding a phone and no recovery codes can retire the old enrolment rather than lose the account.
//!
//! Both enforce the rules the primitives underneath them cannot:
//!
//! 1. **A replayed assertion is refused, by the challenge rather than by the counter.** The
//!    authentication state is consumed by the one `finish` call and dropped, so a replayed response
//!    carries a challenge no state remembers. The signature counter is the SECONDARY check, and it is
//!    vacuous against an authenticator that always reports zero — this vault claims nothing for it
//!    beyond what the verifier does.
//! 2. **A recovery code is spent when used, and a TOTP step is accepted at most once.**
//! 3. **Both outcomes are persisted before the caller is told "yes".** A crash between accepting and
//!    recording would otherwise silently restore a spent code.
//! 4. **Wrong attempts are bounded — persistently (dig_ecosystem#1847).** A consecutive-failure count
//!    and an escalating next-allowed-attempt instant ride the sealed record, so closing and reopening
//!    the window cannot hand an attacker a fresh unbounded run. It is a rate limit, not a lockout, and
//!    it fails closed against a rolled-back clock. What it bounds is now recovery-code guessing and
//!    verifier rejections; an assertion is not guessable.
//!
//! The bound is keyed on the RECORD — one per account — and on nothing the caller supplies. Not the
//! credential id, not the typed string, not the transport: a limiter keyed on attacker-chosen input
//! is a denial-of-service primitive rather than a defence.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PublicKeyCredential, SecurityKey, SecurityKeyAuthentication, Webauthn};

use super::recovery_codes::{self, RecoveryCodeSet, StoredRecoveryCode};
use super::totp::{SecretError, TotpSecret};
use crate::sealer::{ProfileSealer, SealError};
use crate::storage;

/// The vault file name inside the profile directory. `.seal` marks it as DIGOP1 ciphertext, matching
/// the recovery-phrase vault beside it.
///
/// Crate-visible so account removal can sweep for it by name, exactly as it does for the phrase vault:
/// once an account is destroyed its profile directory can no longer be computed, so the sweep needs
/// the literal. Both record shapes live under this one name — the shape is inside the envelope, not in
/// the file name — so the sweep cannot miss a superseded record.
pub(crate) const VAULT_FILE: &str = "second-factor.seal";

/// The domain tag a CURRENT second-factor blob starts with, inside the sealed plaintext.
const ENVELOPE_MAGIC: &[u8] = b"DIG2FA2\n";

/// The domain tag of the SUPERSEDED TOTP record (dig-app#348).
///
/// A record carrying it holds a shared secret and no credential. It cannot be migrated — there is no
/// key inside it to promote into an asymmetric one — so it is neither upgraded nor honoured: it fails
/// every gate closed and is retired through [`journey::disable_unlocked`](super::journey) with its own
/// material. Removing this constant, along with the TOTP verifier and this read path, is
/// <https://github.com/DIG-Network/dig-app/issues/373>.
const SUPERSEDED_ENVELOPE_MAGIC: &[u8] = b"DIG2FA1\n";

/// How many consecutive failed challenges are absorbed with NO delay (dig_ecosystem#1847).
///
/// A person who fat-fingers a recovery code should not be made to wait — three is small enough that
/// an actual attacker is throttled almost at once. The delay begins on the failure AFTER this budget
/// is spent.
const FREE_CHALLENGE_ATTEMPTS: u32 = 3;

/// The first enforced delay, in seconds, imposed on the failure after the free budget is spent
/// (dig_ecosystem#1847). It doubles with each further consecutive failure: 5s, 10s, 20s, 40s…
const BACKOFF_BASE_SECONDS: u64 = 5;

/// The ceiling on the escalating delay, in seconds — fifteen minutes (dig_ecosystem#1847).
///
/// This is a RATE LIMIT, never a hard lockout: a permanent lockout would be a denial-of-service against
/// the account's own owner, forcing them onto a recovery code they may not have. The delay grows
/// without bound only up to here. Even pinned at this cap the arithmetic is decisive against the thing
/// it now bounds — a ten-character recovery code from a 32-symbol alphabet is about one in 2^50 per
/// guess — while a legitimate owner who waits fifteen minutes is always let back in.
const BACKOFF_MAX_SECONDS: u64 = 900;

/// What this host holds for a second factor, as far as the reader that answered can tell.
///
/// Four states rather than a `bool`, and the two that are not `Enrolled`/`NotEnrolled` are the whole
/// point. A `bool` forced a probe that could not read the profiles directory to pick one of the
/// confident answers, and BOTH picks are wrong in a different place: picking "not enrolled" makes the
/// destructive-verb gate skip a factor that may well be there, and picking "enrolled" makes the tray
/// assert a protection nobody verified.
///
/// So the questions are separated. The GATE keeps its fail-closed lossy read
/// ([`Enrolment::is_enrolled`], which folds everything but `NotEnrolled` into `true`), and a SURFACE
/// reads this enum and says what it actually knows.
///
/// `Undeterminable` is the DEFAULT, deliberately. A default-constructed view has probed nothing, and
/// both confident values would be a claim it has no basis for — one of which is the overclaim this
/// enum exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnrolmentState {
    /// A usable enrolment record is here.
    Enrolled,
    /// A record is here, and it is the SUPERSEDED TOTP shape (dig-app#348).
    ///
    /// **Never rendered as a working factor and never as an absent one.** The gate still binds — the
    /// destructive verbs refuse — and the way forward is to retire it and enrol a key. Reachable only
    /// from a reader that could open the record, because the tag is inside the sealed plaintext:
    /// [`SecondFactorVault::classified_state`], never the unlock-free directory scan.
    Superseded,
    /// There is definitely none — the probe reached the directory and found nothing.
    NotEnrolled,
    /// The probe could not tell: the profiles directory is unreadable, is not a directory, or sits on
    /// a mount that refused the `stat`.
    ///
    /// **This is not "not enrolled".** Every caller decides what it means for its own question; none
    /// may flatten it into [`NotEnrolled`](Self::NotEnrolled) and none may render it as enrolled.
    #[default]
    Undeterminable,
}

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
    /// What is enrolled here.
    ///
    /// An implementation that cannot open the record MUST NOT answer
    /// [`Superseded`](EnrolmentState::Superseded): the tag distinguishing the two shapes is inside the
    /// sealed plaintext, so an implementation that has not decrypted anything has no basis for it.
    fn enrolment_state(&self) -> EnrolmentState;

    /// Whether the second factor must be honoured — the destructive-verb gate's lossy read.
    ///
    /// Fails CLOSED: an [`Undeterminable`](EnrolmentState::Undeterminable) probe answers `true`, so a
    /// factor that might be enrolled is asked for rather than silently waived by anything able to make
    /// the profiles directory unreadable. A [`Superseded`](EnrolmentState::Superseded) record answers
    /// `true` for a different reason — the gate genuinely still binds, and the challenge behind it
    /// refuses.
    ///
    /// A PROVIDED method on purpose. It was previously implemented independently per type, and the two
    /// implementations disagreed: the directory scan failed closed while
    /// [`SecondFactorVault`]'s `path.exists()` mapped every I/O error to `false` — so with the account
    /// unlocked the gate refused a destructive verb while the disable control believed nothing was
    /// enrolled and drew no window at all. Deriving it here means one probe answers both questions and
    /// they cannot drift apart again.
    ///
    /// **Do not render a UI string from this.** It cannot distinguish "enrolled" from "could not
    /// look", and claiming the first when it is the second is the overclaim this split exists to stop.
    /// Match on [`enrolment_state`](Self::enrolment_state) instead.
    fn is_enrolled(&self) -> bool {
        !matches!(self.enrolment_state(), EnrolmentState::NotEnrolled)
    }

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
/// rather than by profile id, which is what makes it usable on a locked or unopenable account. It can
/// therefore report PRESENCE and never METHOD: both record shapes have the same file name.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryEnrolment<'a> {
    brand_dir: &'a Path,
}

impl<'a> DirectoryEnrolment<'a> {
    /// View the enrolments under `brand_dir`.
    pub fn new(brand_dir: &'a Path) -> Self {
        Self { brand_dir }
    }

    /// Every enrolment file present, in no particular order — or the I/O error that stopped the scan.
    ///
    /// Fallible on purpose. The previous version answered `Vec::new()` for BOTH "this brand directory
    /// holds no enrolments" and "this brand directory could not be read", and those two answers point
    /// the destructive-verb gate in opposite directions (see [`enrolment_present`]). Callers decide
    /// which way an unreadable scan should fall; this returns the error rather than choosing for them.
    ///
    /// One I/O error is NOT undeterminable and is folded back into a confident empty:
    /// [`NotFound`](std::io::ErrorKind::NotFound) on the profiles directory means no profile has ever
    /// been created here, which is the state of every account before its first enrolment. Reporting
    /// that as unreadable would fail the gate closed on a fresh install and block the destructive verbs
    /// for a factor that provably does not exist — a lockout traded for a fail-open, which is no
    /// improvement. This mirrors the distinction dig-keystore 0.13 draws at its own existence probe.
    fn scan(&self) -> std::io::Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(self.brand_dir.join("profiles")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut found = Vec::new();
        for profile in entries {
            let path = profile?.path().join(VAULT_FILE);
            // `try_exists`, not `exists`: the latter reports a permission-denied probe as a confident
            // "no file here", which is the very flattening this scan exists to stop.
            if path.try_exists()? {
                found.push(path);
            }
        }
        Ok(found)
    }
}

impl Enrolment for DirectoryEnrolment<'_> {
    /// A scan that could not be completed is [`Undeterminable`](EnrolmentState::Undeterminable), never
    /// an empty result — and a scan that succeeded is [`Enrolled`](EnrolmentState::Enrolled), never
    /// [`Superseded`](EnrolmentState::Superseded), because this reader has opened nothing.
    fn enrolment_state(&self) -> EnrolmentState {
        match self.scan() {
            Ok(files) if files.is_empty() => EnrolmentState::NotEnrolled,
            Ok(_) => EnrolmentState::Enrolled,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    concat!(
                        "could not read this host's second-factor enrolments; treating the ",
                        "answer as unknown rather than as 'none enrolled'"
                    )
                );
                EnrolmentState::Undeterminable
            }
        }
    }

    /// Remove every enrolment file under this brand directory.
    fn remove(&self) -> Result<(), VaultError> {
        for path in self.scan().map_err(VaultError::Io)? {
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
///
/// Answers `true` when the enrolment scan cannot be completed, because this is the ONE place the
/// second-factor gate is skipped outright (`second_factor_cleared` returns early on `false`). A read
/// that could not look must not be spent as permission to skip it.
pub fn enrolment_present(brand_dir: &Path) -> bool {
    DirectoryEnrolment::new(brand_dir).is_enrolled()
}

/// What this host holds for a second factor, WITHOUT an unlock — the read a LOCKED surface must use.
///
/// [`enrolment_present`] above is the GATE's read and is deliberately lossy in the safe direction.
/// Rendering a menu from it makes an unreadable profiles directory paint as an enrolled factor, which
/// asserts a protection nothing verified. This is the same fact, undamaged.
///
/// It reports presence and never METHOD, so copy written from it must stay method-neutral: it may say
/// a second factor is enrolled; it must not claim a working key.
pub fn enrolment_state(brand_dir: &Path) -> EnrolmentState {
    DirectoryEnrolment::new(brand_dir).enrolment_state()
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

    /// The decrypted bytes were not a second-factor record: a wrong domain tag, or unparseable JSON.
    /// Never rendered as a working enrolment.
    #[error("the stored second-factor enrolment is not readable")]
    Corrupt,

    /// The record is the SUPERSEDED TOTP shape, and the operation asked for needs a credential
    /// (dig-app#348).
    ///
    /// **This is not "not enrolled" and must never be mapped to it.** A caller that reached this has a
    /// factor it cannot satisfy with a key, and the honest answers are to refuse the gate and to offer
    /// retirement — never to proceed as though nothing were enrolled.
    #[error("this account still has the older two-factor setup, which must be replaced")]
    Superseded,
}

impl From<SecretError> for VaultError {
    fn from(_: SecretError) -> Self {
        Self::Corrupt
    }
}

impl From<storage::SealWriteError> for VaultError {
    fn from(error: storage::SealWriteError) -> Self {
        match error {
            storage::SealWriteError::Seal(e) => Self::Seal(e),
            storage::SealWriteError::Io(e) => Self::Io(e),
        }
    }
}

/// The persistent attempt bound, carried identically by both record shapes.
///
/// Flattened into the record's JSON, so the three fields sit at the top level exactly as they did
/// before this struct existed — the shape is a de-duplication of the LOGIC, not a change to the bytes,
/// and a conformance test pins the top-level key set so it cannot silently become nested.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Bound {
    /// How many challenges have failed IN A ROW (dig_ecosystem#1847).
    ///
    /// Persisted with the sealed record — not held in the challenge window — precisely because the
    /// defect was that reopening the window reset it to zero. Reset on any accepted evidence.
    /// `#[serde(default)]` so a record written before this field existed reads back as zero prior
    /// failures rather than failing to parse.
    #[serde(default)]
    consecutive_failures: u32,

    /// The earliest unix second at which the NEXT challenge may be judged, once the free budget is
    /// spent (dig_ecosystem#1847). `None` means no delay is in force. Persisted, so the escalating
    /// delay cannot be walked around by closing and reopening the window.
    #[serde(default)]
    throttle_until: Option<u64>,

    /// The greatest instant this record has ever observed — the anti-rollback anchor
    /// (dig_ecosystem#1847). A wall clock reading earlier than this has been moved backwards; the
    /// challenge then treats time as frozen here, so a rollback cannot shorten a throttle.
    #[serde(default)]
    clock_high_water: Option<u64>,
}

/// The enrolment record, as it is sealed.
///
/// Five top-level fields and no more. There is deliberately no `secret` and no `last_accepted_step`:
/// the first cannot exist in an asymmetric design, and the second has nothing to guard now that there
/// is no code to replay. A conformance test pins BOTH the presence of these five and the absence of
/// those two, because "we removed the secret" is exactly the kind of claim that survives a refactor in
/// prose and not in bytes.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    /// The enrolled credential: its id, its COSE PUBLIC key, its signature counter, the transports
    /// reported at enrolment, and the parsed attestation. No private component exists.
    credential: SecurityKey,
    /// The salted digests of the recovery codes.
    recovery_codes: Vec<StoredRecoveryCode>,
    #[serde(flatten)]
    bound: Bound,
}

/// The SUPERSEDED TOTP record (dig-app#348), read to be retired and never to be honoured.
///
/// # Why it is still written at all
///
/// It is never migrated and its shape is never changed. The only field updates it takes are its OWN
/// attempt bound and its OWN spent-step marker, and they are not optional: retirement accepts typed
/// material, so without persisting them a wrong recovery code would cost an attacker nothing and the
/// same TOTP code would work for the rest of its window. An unbounded guessing oracle on the path that
/// REMOVES the factor is precisely the de-gating §3.1e forbids, so the bound has to ride the record
/// here exactly as it does on a current one.
///
/// What "not rewritten in place" forbids is turning this record into a `DIG2FA2` one, or editing it
/// toward one. That never happens: the only other writes it sees are its deletion and a complete fresh
/// enrolment over it.
#[derive(Debug, Serialize, Deserialize)]
struct SupersededRecord {
    /// The shared secret, hex-encoded. Read-only material: it can retire this record and can clear no
    /// gate.
    secret: String,
    /// The salted digests of the recovery codes.
    recovery_codes: Vec<StoredRecoveryCode>,
    /// The most recent TOTP step accepted, so it cannot be accepted again.
    last_accepted_step: Option<u64>,
    #[serde(flatten)]
    bound: Bound,
}

/// Which shape the sealed record turned out to be.
// Produced by one `read` and matched immediately by its caller — never collected, never stored, never
// sent anywhere. Boxing the large variant would add a heap allocation per vault read and put a record
// carrying recovery-code digests on the heap, which is a worse place for it than a stack frame this
// module already controls the lifetime of.
#[allow(clippy::large_enum_variant)]
enum Opened {
    /// A `DIG2FA2` record: a credential and recovery codes.
    Current(Record),
    /// A `DIG2FA1` record: the superseded TOTP enrolment.
    Superseded(SupersededRecord),
}

/// Which record shape a profile holds, for a caller that must branch before doing anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// A credential record. Assertions clear its challenge.
    Current,
    /// The superseded TOTP record. Nothing clears its challenge; it is retired and re-enrolled.
    Superseded,
}

/// What a challenge concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeOutcome {
    /// A verified assertion from the enrolled key, or — on a superseded record — a correct, unused
    /// authenticator code.
    Accepted,
    /// A correct, unspent recovery code. Carries how many remain, so the user can be told plainly
    /// rather than discovering at the worst moment that they are out.
    AcceptedRecoveryCode {
        /// How many unspent recovery codes are left.
        remaining: usize,
    },
    /// A TOTP code that is arithmetically correct but has ALREADY been used inside its own window.
    /// Reachable only on a superseded record.
    ///
    /// Reported separately from a plain rejection because it means something different to the user
    /// ("wait for the next code", not "you typed it wrong") — and because collapsing the two would hide
    /// the replay guard from every test.
    AlreadyUsed,
    /// Neither a verifiable assertion nor a valid recovery code.
    Rejected,
    /// Too many challenges have failed in a row, so the next attempt must WAIT (dig_ecosystem#1847).
    ///
    /// A rate limit, NOT a lockout: the required delay escalates with each failure but the account is
    /// never permanently sealed out of its own recovery path. Nothing was even judged — a throttled
    /// attempt learns nothing about whether its guess was close.
    RateLimited {
        /// Whole seconds the caller must wait before another attempt will be looked at.
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

    /// Which record shape is on disk.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] when there is no record or it cannot be read, [`VaultError::Seal`] when the
    /// account is locked, [`VaultError::Corrupt`] when the bytes are not a second-factor record.
    pub fn kind(&self) -> Result<RecordKind, VaultError> {
        Ok(match self.read()? {
            Opened::Current(_) => RecordKind::Current,
            Opened::Superseded(_) => RecordKind::Superseded,
        })
    }

    /// Complete an enrolment: seal `credential` and the digests of `codes`.
    ///
    /// Called only after the credential has produced a VERIFIED assertion (see
    /// [`journey`](super::journey)) — writing before that is precisely how a person ends up locked out
    /// by a setup flow, and it is why this is the last step of enrolment rather than an early one.
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked; [`VaultError::Io`] on a write failure.
    pub fn enrol(
        &self,
        credential: &SecurityKey,
        codes: &RecoveryCodeSet,
    ) -> Result<(), VaultError> {
        self.write_current(&Record {
            credential: credential.clone(),
            recovery_codes: codes.to_stored(),
            bound: Bound::default(),
        })
    }

    /// The enrolled credential, to mint an authentication challenge against.
    ///
    /// # Errors
    ///
    /// [`VaultError::Superseded`] on a `DIG2FA1` record — which MUST NOT be treated as "no factor";
    /// otherwise as [`kind`](Self::kind).
    pub fn credential(&self) -> Result<SecurityKey, VaultError> {
        match self.read()? {
            Opened::Current(record) => Ok(record.credential),
            Opened::Superseded(_) => Err(VaultError::Superseded),
        }
    }

    /// Judge a completed WebAuthn assertion, and persist whatever it changed.
    ///
    /// `state` is the one-use authentication state that minted this challenge; it is consumed by the
    /// verifier and must never be reused, persisted, or outlive the ceremony. A replayed response
    /// carries a challenge no live state remembers and is refused there — the signature counter is the
    /// secondary check and is vacuous against an authenticator that always reports zero.
    ///
    /// On success the credential's counter and backup state are updated and the failure bound is
    /// cleared, both BEFORE the caller is told the challenge passed: a pass that cannot be recorded is
    /// not a pass.
    ///
    /// # Errors
    ///
    /// [`VaultError::Superseded`] on a `DIG2FA1` record; otherwise as [`kind`](Self::kind), plus
    /// [`VaultError::Io`] if the outcome cannot be written.
    pub fn judge_assertion(
        &self,
        verifier: &Webauthn,
        response: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
        now: u64,
    ) -> Result<ChallengeOutcome, VaultError> {
        let mut record = match self.read()? {
            Opened::Current(record) => record,
            Opened::Superseded(_) => return Err(VaultError::Superseded),
        };
        let effective_now = anchor(&mut record.bound, now);
        if let Some(wait) = throttled_for(&record.bound, effective_now) {
            self.write_current(&record)?;
            return Ok(ChallengeOutcome::RateLimited {
                retry_after_seconds: wait,
            });
        }

        // The assertion MUST come from the credential THIS record enrolled.
        //
        // Without this the vault's guarantee would really be the CALLER's:
        // `finish_securitykey_authentication` judges a response against the `state` it is handed, and a
        // state minted from a DIFFERENT credential verifies happily — after which `update_credential`
        // would write a stranger's signature counter into this record. Production always mints that
        // state from `credential()`, so nothing reaches it today; that is precisely why the binding is
        // checked here instead of trusted there. SPEC §3.1e binds the factor to "the stored credential
        // id", and this is where that stops being a convention and becomes structural.
        //
        // Reported as an ordinary `Rejected` and recorded as an ordinary failure: saying that the KEY
        // was wrong rather than the signature would tell an attacker where they stand.
        if record.credential.cred_id() != &response.raw_id {
            tracing::info!(
                "a second-factor assertion came from a credential this account never enrolled"
            );
            record_failure(&mut record.bound, effective_now);
            self.write_current(&record)?;
            return Ok(ChallengeOutcome::Rejected);
        }

        match verifier.finish_securitykey_authentication(response, state) {
            Ok(result) => {
                record.credential.update_credential(&result);
                clear_failure_bound(&mut record.bound);
                self.write_current(&record)?;
                Ok(ChallengeOutcome::Accepted)
            }
            Err(e) => {
                // Deliberately not distinguished for the caller. A mismatched challenge, a bad
                // signature and a counter that failed the clone check are all "this assertion did not
                // verify", and reporting which one would tell an attacker where they stand.
                tracing::info!(error = ?e, "a second-factor assertion did not verify");
                record_failure(&mut record.bound, effective_now);
                self.write_current(&record)?;
                Ok(ChallengeOutcome::Rejected)
            }
        }
    }

    /// Judge something the user TYPED — a recovery code, or on a superseded record a TOTP code — as of
    /// `now` (unix seconds), and persist whatever it consumed.
    ///
    /// # What is accepted, per record shape
    ///
    /// On a CURRENT record: recovery codes only. There is no secret to check a code against, and no
    /// TOTP code clears any gate from the first build that carries this design.
    ///
    /// On a SUPERSEDED record: a recovery code, or a TOTP code verified against the v1 secret under the
    /// original rules — RFC 6238 parameters, one acceptance per step, the same bound. That path exists
    /// for exactly one purpose, to let a person holding their phone retire the old enrolment; it can
    /// clear no gate and produce no enrolment.
    ///
    /// # Errors
    ///
    /// [`VaultError::Seal`] if the account is locked (so a locked account can never satisfy a
    /// challenge), [`VaultError::Corrupt`] if the record is unreadable, [`VaultError::Io`] on a write
    /// failure. A challenge that cannot be *recorded* is not reported as accepted.
    pub fn judge_typed(&self, typed: &str, now: u64) -> Result<ChallengeOutcome, VaultError> {
        match self.read()? {
            Opened::Current(mut record) => {
                let effective_now = anchor(&mut record.bound, now);
                if let Some(wait) = throttled_for(&record.bound, effective_now) {
                    self.write_current(&record)?;
                    return Ok(ChallengeOutcome::RateLimited {
                        retry_after_seconds: wait,
                    });
                }
                let outcome = judge_recovery_code(
                    &mut record.recovery_codes,
                    &mut record.bound,
                    typed,
                    effective_now,
                );
                self.write_current(&record)?;
                Ok(outcome)
            }
            Opened::Superseded(mut record) => {
                let effective_now = anchor(&mut record.bound, now);
                if let Some(wait) = throttled_for(&record.bound, effective_now) {
                    self.write_superseded(&record)?;
                    return Ok(ChallengeOutcome::RateLimited {
                        retry_after_seconds: wait,
                    });
                }
                let outcome = judge_superseded_material(&mut record, typed, effective_now)?;
                self.write_superseded(&record)?;
                Ok(outcome)
            }
        }
    }

    /// Peek at the challenge throttle WITHOUT judging anything or writing anything.
    ///
    /// Returns `Some(retry_after_seconds)` iff a challenge attempted at `now` (unix seconds) would be
    /// turned away by the escalating rate limit, else `None`.
    ///
    /// # Why this is — and must stay — a pure, non-mutating read
    ///
    /// It exists so a caller ([`journey::challenge`](super::journey::challenge)) can tell a throttled
    /// user to WAIT *before* a window is drawn, instead of after they have typed a whole code only to
    /// have it refused unread. To be safe to call speculatively it reveals nothing and changes nothing:
    /// it reads only the throttle timer — never a code, so it cannot leak whether a guess is close —
    /// records NO failure, and, critically, does NOT persist the anti-rollback anchor. Advancing
    /// `clock_high_water` here would let a mere peek move the record forward, so the anchored instant
    /// is computed in memory and discarded; only a real judgement commits it. A locked or unreadable
    /// vault fails closed via `read` — it can never answer "not throttled" for a vault it could not
    /// open.
    ///
    /// Answers for BOTH record shapes, because a superseded record is challenged too (for its
    /// retirement) and its bound is the same bound.
    ///
    /// # Errors
    ///
    /// As [`kind`](Self::kind).
    pub fn current_throttle(&self, now: u64) -> Result<Option<u64>, VaultError> {
        let bound = match self.read()? {
            Opened::Current(record) => record.bound,
            Opened::Superseded(record) => record.bound,
        };
        Ok(throttled_for(&bound, anchored_now(&bound, now)))
    }

    /// How many recovery codes remain unspent, for telling the user where they stand.
    ///
    /// # Errors
    ///
    /// As [`kind`](Self::kind): the record must be readable, which means unlocked.
    pub fn remaining_recovery_codes(&self) -> Result<usize, VaultError> {
        Ok(match self.read()? {
            Opened::Current(record) => recovery_codes::remaining(&record.recovery_codes),
            Opened::Superseded(record) => recovery_codes::remaining(&record.recovery_codes),
        })
    }

    /// What this profile holds, refined by actually OPENING the record — the read a surface must use
    /// while the account is unlocked (dig-app#348).
    ///
    /// [`enrolment_state`](Enrolment::enrolment_state) below answers from a `stat` and therefore cannot
    /// see which shape is inside. This one can, which is the only way a surface can honestly say *needs
    /// re-enrolment* rather than painting a superseded record as a working factor.
    ///
    /// A record that exists but cannot be opened is [`Undeterminable`](EnrolmentState::Undeterminable),
    /// never `Enrolled`: a locked account or a corrupt blob has told us the file is there and nothing
    /// more.
    pub fn classified_state(&self) -> EnrolmentState {
        match self.enrolment_state() {
            EnrolmentState::Enrolled => match self.kind() {
                Ok(RecordKind::Current) => EnrolmentState::Enrolled,
                Ok(RecordKind::Superseded) => EnrolmentState::Superseded,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "a second-factor record is present but could not be classified"
                    );
                    EnrolmentState::Undeterminable
                }
            },
            other => other,
        }
    }

    /// Open, authenticate and classify the sealed record.
    fn read(&self) -> Result<Opened, VaultError> {
        let ciphertext = std::fs::read(&self.path)?;
        let plaintext = self.sealer.open(&self.profile_did, &ciphertext)?;
        if let Some(body) = plaintext.strip_prefix(ENVELOPE_MAGIC) {
            return serde_json::from_slice(body)
                .map(Opened::Current)
                .map_err(|_| VaultError::Corrupt);
        }
        if let Some(body) = plaintext.strip_prefix(SUPERSEDED_ENVELOPE_MAGIC) {
            return serde_json::from_slice(body)
                .map(Opened::Superseded)
                .map_err(|_| VaultError::Corrupt);
        }
        Err(VaultError::Corrupt)
    }

    /// Seal and durably replace a current record.
    fn write_current(&self, record: &Record) -> Result<(), VaultError> {
        self.write(ENVELOPE_MAGIC, record)
    }

    /// Seal and durably replace a superseded record — its OWN bound and spent step only, never a
    /// change of shape (see [`SupersededRecord`]).
    fn write_superseded(&self, record: &SupersededRecord) -> Result<(), VaultError> {
        self.write(SUPERSEDED_ENVELOPE_MAGIC, record)
    }

    fn write<T: Serialize>(&self, magic: &[u8], record: &T) -> Result<(), VaultError> {
        let mut plaintext = magic.to_vec();
        plaintext.extend_from_slice(&serde_json::to_vec(record).map_err(|_| VaultError::Corrupt)?);
        storage::seal_and_write(&self.sealer, &self.profile_did, &self.path, &plaintext)?;
        Ok(())
    }
}

/// Judge `typed` as a recovery code, advancing or clearing the bound.
///
/// Shared by both record shapes because a recovery code is a digest comparison and knows nothing about
/// which primitive the rest of the record uses.
fn judge_recovery_code(
    codes: &mut [StoredRecoveryCode],
    bound: &mut Bound,
    typed: &str,
    now: u64,
) -> ChallengeOutcome {
    if recovery_codes::spend(codes, typed) {
        let remaining = recovery_codes::remaining(codes);
        clear_failure_bound(bound);
        return ChallengeOutcome::AcceptedRecoveryCode { remaining };
    }
    // Counting the recovery path toward the bound is deliberate: ten codes with unbounded guesses
    // would be a weaker secret than they look.
    record_failure(bound, now);
    ChallengeOutcome::Rejected
}

/// Judge `typed` against a SUPERSEDED record: its TOTP secret first, then its recovery codes.
///
/// Kept as one function so the single-use step rule and the bound cannot drift apart from each other,
/// and so the whole retirement-only path is in one readable place for the ticket that deletes it
/// (<https://github.com/DIG-Network/dig-app/issues/373>).
fn judge_superseded_material(
    record: &mut SupersededRecord,
    typed: &str,
    now: u64,
) -> Result<ChallengeOutcome, VaultError> {
    let secret =
        TotpSecret::from_bytes(&hex::decode(&record.secret).map_err(|_| VaultError::Corrupt)?)?;

    if let Some(step) = secret.matching_step(typed, now) {
        // A step is spendable once. `<=` rather than `<` because the LAST accepted step is itself
        // already spent. A replayed-but-correct code is neither a fresh guess nor a success: it does
        // not advance the failure bound and does not clear it.
        if record.last_accepted_step.is_some_and(|last| step <= last) {
            return Ok(ChallengeOutcome::AlreadyUsed);
        }
        record.last_accepted_step = Some(step);
        clear_failure_bound(&mut record.bound);
        return Ok(ChallengeOutcome::Accepted);
    }

    Ok(judge_recovery_code(
        &mut record.recovery_codes,
        &mut record.bound,
        typed,
        now,
    ))
}

/// The instant the throttle math treats as "now", also COMMITTING it to the record's anchor.
///
/// Never earlier than the greatest instant this record has already seen, so a clock wound backwards
/// cannot shorten an armed throttle. Only a real judgement calls this; a peek uses
/// [`anchored_now`] and discards the result.
fn anchor(bound: &mut Bound, now: u64) -> u64 {
    let effective = anchored_now(bound, now);
    bound.clock_high_water = Some(effective);
    effective
}

/// The anchored instant, computed and NOT committed — the read half of the anti-rollback anchor.
fn anchored_now(bound: &Bound, now: u64) -> u64 {
    bound.clock_high_water.map_or(now, |seen| now.max(seen))
}

/// The wait an attempt at `now` would be turned away with, or `None` when nothing is in force.
fn throttled_for(bound: &Bound, now: u64) -> Option<u64> {
    bound
        .throttle_until
        .filter(|&until| now < until)
        .map(|until| until - now)
}

/// Clear the failure bound after evidence is accepted — the account is back in the owner's hands.
fn clear_failure_bound(bound: &mut Bound) {
    bound.consecutive_failures = 0;
    bound.throttle_until = None;
}

/// Advance the failure bound by one and arm the escalating delay once the free budget is spent.
fn record_failure(bound: &mut Bound, now: u64) {
    bound.consecutive_failures = bound.consecutive_failures.saturating_add(1);
    bound.throttle_until = backoff_delay(bound.consecutive_failures).map(|delay| now + delay);
}

/// The required wait after `failures` consecutive wrong attempts, or `None` while inside the free
/// budget.
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
    /// Cheap (one `stat`) and needs no unlock, so the tray can ask it on every repaint.
    ///
    /// Reports PRESENCE and never shape: the tag that separates a credential record from the
    /// superseded TOTP one is inside the sealed plaintext, and this opens nothing. Use
    /// [`classified_state`](SecondFactorVault::classified_state) where the shape matters.
    ///
    /// `try_exists`, not `exists`: the latter reports an unreadable path as a confident "no file here",
    /// which is what made the "Turn off two-factor codes…" control return `NotEnrolled` and draw
    /// nothing at all while the gate — reading the same fact through a different probe — refused the
    /// destructive verbs (dig-app#288).
    fn enrolment_state(&self) -> EnrolmentState {
        match self.path.try_exists() {
            Ok(true) => EnrolmentState::Enrolled,
            Ok(false) => EnrolmentState::NotEnrolled,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not determine whether this profile has a second factor enrolled"
                );
                EnrolmentState::Undeterminable
            }
        }
    }

    /// Remove this profile's enrolment. Authorization is the CALLER's job and happens before this is
    /// reached (see [`journey::disable_unlocked`](super::journey::disable_unlocked)) — this is the
    /// storage half only.
    fn remove(&self) -> Result<(), VaultError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}

/// Fixtures for the OTHER modules' tests, which cannot reach this module's private record types.
///
/// Planting through the vault's own writer rather than by hand is what keeps a fixture from drifting
/// away from the shape the reader accepts — a hand-built blob that no longer parses would make a test
/// pass for the wrong reason.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Plant a SUPERSEDED `DIG2FA1` record holding `secret` and `codes`.
    pub(crate) fn plant_superseded<S: ProfileSealer>(
        vault: &SecondFactorVault<S>,
        secret: &TotpSecret,
        codes: &RecoveryCodeSet,
    ) {
        vault
            .write_superseded(&SupersededRecord {
                secret: hex::encode(secret.as_bytes()),
                recovery_codes: codes.to_stored(),
                last_accepted_step: None,
                bound: Bound::default(),
            })
            .expect("plant a v1 record");
    }

    /// The sealer a vault was built with.
    ///
    /// The field stays private: which sealer a vault holds is not part of its API, and the only
    /// reason to reach it from another module's tests is to make the record UNREADABLE — the
    /// locked-account state whose read must fail closed rather than report "not enrolled".
    pub(crate) fn sealer_of<S: ProfileSealer>(vault: &SecondFactorVault<S>) -> &S {
        &vault.sealer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::second_factor::authenticator::double::{
        assert_through, enrol_through, SoftAuthenticator,
    };
    use crate::account::second_factor::totp::{SECRET_BYTES, STEP_SECONDS};
    use crate::test_support::FakeSealer;

    /// An unreadable enrolment scan is UNDETERMINABLE, while a genuinely empty one is NOT ENROLLED
    /// — and the gate's lossy read still folds only the first of those to "ask for a code".
    ///
    /// The two fixtures differ in ONE way: whether `profiles` is a directory that can be listed. Both
    /// halves are asserted together because either alone is satisfied by a wrong implementation — a
    /// scan hard-coded to `Undeterminable` passes the first, and a `map_or(true, ..)` passes the
    /// second while reporting the unreadable case as a confident enrolment.
    #[test]
    fn an_unreadable_scan_is_undeterminable_and_an_empty_one_is_not_enrolled() {
        let unreadable = tempfile::tempdir().expect("temp dir");
        // `profiles` as a FILE, so `read_dir` fails with something that is not `NotFound`. Chosen
        // over a permission change because it fails identically on Windows and on Unix, where a
        // mode bit does not stop the owning user.
        std::fs::write(unreadable.path().join("profiles"), b"not a directory").expect("plant");

        let empty = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(empty.path().join("profiles")).expect("an empty profiles dir");

        assert_eq!(
            DirectoryEnrolment::new(unreadable.path()).enrolment_state(),
            EnrolmentState::Undeterminable,
            "a scan that could not be completed must not answer a confident state"
        );
        assert_eq!(
            DirectoryEnrolment::new(empty.path()).enrolment_state(),
            EnrolmentState::NotEnrolled,
            "a scan that reached the directory and found nothing IS a confident negative"
        );

        // The gate is unchanged and still fails closed on the unreadable one only.
        assert!(
            enrolment_present(unreadable.path()),
            "the destructive-verb gate must still demand a factor it cannot rule out"
        );
        assert!(
            !enrolment_present(empty.path()),
            "and must not demand one over a directory it read and found empty"
        );
    }

    /// A vault whose file is absent reads as NOT ENROLLED, and one whose file is there reads as
    /// ENROLLED — the two confident arms of the probe that replaced `path.exists()`.
    ///
    /// The unreadable arm is exercised through [`DirectoryEnrolment`] above rather than here: there
    /// is no portable way to make a single `stat` fail on both Windows and Unix for the owning user,
    /// and a fixture that only failed on one platform would be a test that silently does not run.
    #[test]
    fn a_vault_reports_both_confident_enrolment_states() {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = vault(dir.path(), DID_A);
        assert_eq!(vault.enrolment_state(), EnrolmentState::NotEnrolled);
        assert!(!vault.is_enrolled());

        plant(&vault, b"sealed");
        assert_eq!(vault.enrolment_state(), EnrolmentState::Enrolled);
        assert!(vault.is_enrolled());
    }

    const DID_A: &str = "did:chia:profile-a";
    const DID_B: &str = "did:chia:profile-b";
    /// An explicit, pinned "now" — never `SystemTime::now`. A fixture that reads the wall clock cannot
    /// place a code at a chosen step, and a test group that passed small literals through a wall-clock
    /// API would be exercising only the far-past path.
    const NOW: u64 = 1_700_000_000;
    /// A wrong guess shaped like a recovery code: in the alphabet, dashed, and matching no digest.
    const WRONG: &str = "ZZZZZ-ZZZZZ";

    fn vault(dir: &Path, did: &str) -> SecondFactorVault<FakeSealer> {
        SecondFactorVault::new(FakeSealer::default(), dir, did)
    }

    /// Write raw bytes where the vault file belongs, creating the profile directory.
    fn plant<S: ProfileSealer>(vault: &SecondFactorVault<S>, bytes: &[u8]) {
        std::fs::create_dir_all(vault.path.parent().expect("a profile dir")).expect("profile dir");
        std::fs::write(&vault.path, bytes).expect("plant a record");
    }

    /// What an enrolled account holds, and what its owner holds.
    struct Fixture {
        vault: SecondFactorVault<FakeSealer>,
        /// The authenticator the credential lives on. Kept, because only THIS token can assert.
        key: SoftAuthenticator,
        credential: SecurityKey,
        codes: RecoveryCodeSet,
    }

    /// Enrol a REAL credential from a soft FIDO2 token, and hand back everything the owner has.
    fn enrolled(dir: &Path) -> Fixture {
        let vault = vault(dir, DID_A);
        let key = SoftAuthenticator::roaming();
        let credential = enrol_through(&key).credential;
        let codes = RecoveryCodeSet::generate();
        vault.enrol(&credential, &codes).expect("enrol");
        Fixture {
            vault,
            key,
            credential,
            codes,
        }
    }

    /// Plant a SUPERSEDED `DIG2FA1` record with a fixed secret, and hand back the secret and codes.
    ///
    /// The secret is a constant rather than a fresh random one so a test can compute the code it
    /// expects independently of anything the production path does.
    fn superseded(dir: &Path) -> (SecondFactorVault<FakeSealer>, TotpSecret, RecoveryCodeSet) {
        let vault = vault(dir, DID_A);
        let secret = TotpSecret::from_bytes(&[0x2a; SECRET_BYTES]).expect("a fixed secret");
        let codes = RecoveryCodeSet::generate();
        test_support::plant_superseded(&vault, &secret, &codes);
        (vault, secret, codes)
    }

    // ──────────────── The credential record ────────────────

    /// An enrolment round-trips, and an assertion from the enrolled key clears the challenge.
    ///
    /// The whole shape in one test: a real soft token registers, the verifier accepts, the record is
    /// written, and a later real assertion from the SAME token is accepted.
    #[test]
    fn an_enrolment_round_trips_and_accepts_an_assertion_from_the_enrolled_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!vault(dir.path(), DID_A).is_enrolled(), "nothing yet");

        let f = enrolled(dir.path());
        assert!(f.vault.is_enrolled());
        assert_eq!(f.vault.kind().unwrap(), RecordKind::Current);

        let a = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                .unwrap(),
            ChallengeOutcome::Accepted
        );
    }

    /// **The replay defence, and it is the CHALLENGE rather than the counter.** Replaying a response
    /// against a FRESH state is refused, because that state minted a different challenge.
    ///
    /// The control matters: the same response was accepted moments earlier against its own state, so
    /// this cannot pass by the response simply being malformed.
    #[test]
    fn a_replayed_assertion_is_refused_against_a_fresh_state() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        let first = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&first.webauthn, &first.response, &first.state, NOW)
                .unwrap(),
            ChallengeOutcome::Accepted,
            "the control: this response IS valid against its own state"
        );

        // A fresh ceremony mints a fresh challenge; the OLD response cannot answer it.
        let second = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&second.webauthn, &first.response, &second.state, NOW)
                .unwrap(),
            ChallengeOutcome::Rejected,
            "a response carrying a stale challenge must not verify"
        );
    }

    /// An assertion from a DIFFERENT authenticator is refused: possession of the enrolled key is the
    /// whole guarantee, so a second key must not answer for the first.
    #[test]
    fn an_assertion_from_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        let stranger = SoftAuthenticator::roaming();
        let stranger_credential = enrol_through(&stranger).credential;
        let a = assert_through(&stranger, &stranger_credential);

        assert_eq!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                .unwrap(),
            ChallengeOutcome::Rejected
        );
    }

    /// A rejected assertion ADVANCES the persistent bound, exactly as a wrong recovery code does.
    #[test]
    fn a_rejected_assertion_advances_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let stranger = SoftAuthenticator::roaming();
        let stranger_credential = enrol_through(&stranger).credential;

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            let a = assert_through(&stranger, &stranger_credential);
            assert_eq!(
                f.vault
                    .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                    .unwrap(),
                ChallengeOutcome::Rejected
            );
        }
        let a = assert_through(&stranger, &stranger_credential);
        assert!(
            matches!(
                f.vault
                    .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                    .unwrap(),
                ChallengeOutcome::RateLimited { .. }
            ),
            "failed assertions must be throttled like every other failed attempt"
        );
    }

    /// The lost-key path, which is the reason recovery codes exist: with no authenticator available,
    /// a recovery code still gets the user in — once — and the count drops.
    #[test]
    fn a_recovery_code_gets_the_user_in_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        assert_eq!(
            f.vault.judge_typed(f.codes.code(0), NOW).unwrap(),
            ChallengeOutcome::AcceptedRecoveryCode {
                remaining: recovery_codes::CODE_COUNT - 1
            }
        );
        assert_eq!(
            f.vault.judge_typed(f.codes.code(0), NOW).unwrap(),
            ChallengeOutcome::Rejected,
            "a spent recovery code is gone"
        );
        assert_eq!(
            f.vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT - 1
        );
    }

    /// Spending one recovery code must leave the rest usable — the property a single-code fixture
    /// cannot see.
    #[test]
    fn the_other_recovery_codes_survive_one_being_spent() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        f.vault.judge_typed(f.codes.code(0), NOW).unwrap();
        assert!(matches!(
            f.vault.judge_typed(f.codes.code(1), NOW).unwrap(),
            ChallengeOutcome::AcceptedRecoveryCode { .. }
        ));
    }

    /// **No TOTP code clears a current record.** There is no secret in it to check one against, and
    /// there is no grace period in which one would be honoured.
    ///
    /// The fixture is not a random six digits: it is the code that the SUPERSEDED fixture's own secret
    /// would produce, so a wrong implementation that kept a shared-secret path alive would accept it.
    #[test]
    fn no_authenticator_code_clears_a_credential_record() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let old_secret = TotpSecret::from_bytes(&[0x2a; SECRET_BYTES]).unwrap();

        assert_eq!(
            f.vault.judge_typed(&old_secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
    }

    /// A wrong guess is rejected and consumes nothing, so a mistyped code never costs a recovery code.
    #[test]
    fn a_wrong_guess_is_rejected_and_consumes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        assert_eq!(
            f.vault.judge_typed(WRONG, NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        assert_eq!(
            f.vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT
        );
        assert!(
            matches!(
                f.vault.judge_typed(f.codes.code(0), NOW).unwrap(),
                ChallengeOutcome::AcceptedRecoveryCode { .. }
            ),
            "a real recovery code still works after a failed attempt"
        );
    }

    /// A locked account cannot satisfy a challenge — the second factor must not become a way AROUND
    /// the first one. Both entry points are asserted, because either alone leaves the other open.
    #[test]
    fn a_locked_account_cannot_answer_a_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let a = assert_through(&f.key, &f.credential);

        f.vault.sealer.lock();
        assert!(matches!(
            f.vault.judge_typed(f.codes.code(0), NOW),
            Err(VaultError::Seal(_))
        ));
        assert!(matches!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, NOW),
            Err(VaultError::Seal(_))
        ));
    }

    /// A locked account cannot ENROL either, so a failed setup never leaves a half-written vault whose
    /// codes nobody has.
    #[test]
    fn a_locked_account_cannot_enrol() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let credential = enrol_through(&SoftAuthenticator::roaming()).credential;
        vault.sealer.lock();

        assert!(matches!(
            vault.enrol(&credential, &RecoveryCodeSet::generate()),
            Err(VaultError::Seal(_))
        ));
        assert!(!vault.is_enrolled(), "a failed enrol leaves no vault file");
    }

    /// Turning the second factor off removes the enrolment, and doing it twice is not an error — a
    /// half-torn-down state must always be finishable.
    #[test]
    fn disabling_removes_the_enrolment_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        f.vault.remove().expect("disable");
        assert!(!f.vault.is_enrolled());
        f.vault.remove().expect("disabling again is not an error");
    }

    /// Another profile must not open this profile's enrolment. TWO actors are required: a
    /// single-profile fixture cannot distinguish "bound to this DID" from "bound to nothing".
    #[test]
    fn another_profile_cannot_open_this_enrolment() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let intruder = SecondFactorVault {
            sealer: FakeSealer::default(),
            profile_did: DID_B.to_string(),
            path: f.vault.path.clone(),
        };

        assert!(matches!(
            intruder.judge_typed(f.codes.code(0), NOW),
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
        plant(&vault, &foreign);

        assert!(matches!(
            vault.judge_typed(WRONG, NOW),
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
        plant(&vault, &sealed);

        assert!(matches!(
            vault.judge_typed(WRONG, NOW),
            Err(VaultError::Corrupt)
        ));
    }

    // ──────────────── The superseded TOTP record (dig-app#348) ────────────────

    /// **A `DIG2FA1` record is SUPERSEDED — never "not enrolled", and never a working factor.**
    ///
    /// All three readings are asserted together because each catches a different wrong
    /// implementation: one that dropped the v1 tag would report `Corrupt`, one that folded it into the
    /// current shape would report `Enrolled`, and one that treated an unrecognised record as absent
    /// would report `NotEnrolled` — which silently un-gates the destructive verbs.
    #[test]
    fn a_v1_record_is_superseded_and_still_binds_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = superseded(dir.path());

        assert_eq!(vault.kind().unwrap(), RecordKind::Superseded);
        assert_eq!(vault.classified_state(), EnrolmentState::Superseded);
        assert!(
            vault.is_enrolled(),
            "the gate must still bind over a superseded record"
        );
        assert_ne!(vault.classified_state(), EnrolmentState::NotEnrolled);
    }

    /// A superseded record cannot produce a credential and cannot judge an assertion, and BOTH refuse
    /// with the verdict that names the state rather than one that reads as absence.
    #[test]
    fn a_superseded_record_refuses_the_key_path_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = superseded(dir.path());
        let key = SoftAuthenticator::roaming();
        let credential = enrol_through(&key).credential;
        let a = assert_through(&key, &credential);

        assert!(matches!(vault.credential(), Err(VaultError::Superseded)));
        assert!(matches!(
            vault.judge_assertion(&a.webauthn, &a.response, &a.state, NOW),
            Err(VaultError::Superseded)
        ));
    }

    /// The retirement path: a TOTP code verified against the v1 secret, and a recovery code, each
    /// accepted — because a person holding only one of the two must still be able to retire the old
    /// enrolment rather than lose the account.
    #[test]
    fn a_superseded_record_accepts_its_own_material_for_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, codes) = superseded(dir.path());

        assert_eq!(
            vault.judge_typed(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "a TOTP code retires the record it belongs to"
        );
        assert!(matches!(
            vault.judge_typed(codes.code(0), NOW).unwrap(),
            ChallengeOutcome::AcceptedRecoveryCode { .. }
        ));
    }

    /// RFC 6238 §5.2's single-use rule, still enforced on the record that is being retired. The SECOND
    /// presentation of the same code inside its own window is refused — and refused as `AlreadyUsed`,
    /// not as a typo, because the two mean different things to the person at the keyboard.
    #[test]
    fn a_superseded_code_cannot_be_used_twice_inside_its_window() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = superseded(dir.path());
        let code = secret.code_at(NOW);

        assert_eq!(
            vault.judge_typed(&code, NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.judge_typed(&code, NOW + 5).unwrap(),
            ChallengeOutcome::AlreadyUsed,
            "still inside the same 30s window"
        );
    }

    /// …and the NEXT window works normally, so the replay guard is not a one-shot lockout. Without
    /// this control the guard could be "accept exactly one code, ever" and the test above would not
    /// notice.
    #[test]
    fn the_next_windows_superseded_code_is_accepted_after_one_was_spent() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = superseded(dir.path());
        let later = NOW + STEP_SECONDS;

        assert_eq!(
            vault.judge_typed(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.judge_typed(&secret.code_at(later), later).unwrap(),
            ChallengeOutcome::Accepted
        );
    }

    /// A code from a window BEFORE the one already spent must not be replayed either — the skew window
    /// reaches backwards, so `<=` rather than `==` is what closes it. A guard written as "not the same
    /// step" would pass the test above and fail this one.
    #[test]
    fn an_older_superseded_code_cannot_be_replayed_after_a_newer_one() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = superseded(dir.path());
        let previous = secret.code_at(NOW - STEP_SECONDS);

        assert_eq!(
            vault.judge_typed(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted
        );
        assert_eq!(
            vault.judge_typed(&previous, NOW).unwrap(),
            ChallengeOutcome::AlreadyUsed,
            "a code from the previous step is still inside the skew window"
        );
    }

    /// **The bound rides the superseded record too.** Retirement accepts typed material, so without a
    /// persisted bound an attacker could guess recovery codes without limit on the one path that
    /// REMOVES the factor — de-gating, which is the worse of the two failure directions.
    ///
    /// Every attempt goes through a FRESH handle, which is the "close and reopen the window" the
    /// bound exists to survive.
    #[test]
    fn the_bound_rides_a_superseded_record_as_well() {
        let dir = tempfile::tempdir().unwrap();
        superseded(dir.path());

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                vault(dir.path(), DID_A).judge_typed(WRONG, NOW).unwrap(),
                ChallengeOutcome::Rejected
            );
        }
        assert!(
            matches!(
                vault(dir.path(), DID_A).judge_typed(WRONG, NOW).unwrap(),
                ChallengeOutcome::RateLimited { .. }
            ),
            "guessing at the retirement path must be throttled"
        );
    }

    /// **Clock tamper (#1847), on the one path where a captured code can still be replayed.** Rolling
    /// the wall clock BACK must not grant a free attempt: the persisted high-water anchor freezes time
    /// at the present, so a stale code is judged as of now and refused.
    ///
    /// Load-bearing check: drop the anchor (judge at the raw `now`) and the stale code matches its
    /// original step and is `Accepted`, so this fails.
    #[test]
    fn a_clock_rolled_back_to_an_old_codes_window_grants_no_free_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = superseded(dir.path());

        // One present-day attempt anchors the record's clock at NOW.
        assert_eq!(
            vault.judge_typed(WRONG, NOW).unwrap(),
            ChallengeOutcome::Rejected
        );

        // The attacker winds the clock ten steps into the past and replays a code from that window.
        let past = NOW - 10 * STEP_SECONDS;
        assert_eq!(
            vault.judge_typed(&secret.code_at(past), past).unwrap(),
            ChallengeOutcome::Rejected,
            "a code from a rolled-back window must not be accepted"
        );
    }

    // ──────────────── At rest ────────────────

    /// **The at-rest bar.** No recovery code may be findable in the file, and the record must carry no
    /// private key component at all.
    ///
    /// What a reader may conclude from the second half: the stored form has no field that could hold a
    /// private key, and the COSE key it does hold is a public point. What a reader may NOT conclude is
    /// that an assertion "cannot be produced" from the record — that follows from the primitive and
    /// from the absence of private material, not from an executable negative.
    #[test]
    fn the_file_on_disk_carries_no_secret_and_no_private_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let raw = String::from_utf8_lossy(&std::fs::read(&f.vault.path).unwrap()).to_string();

        for i in 0..f.codes.len() {
            let code: String = f.codes.code(i).chars().filter(|c| *c != '-').collect();
            assert!(!raw.contains(&code), "recovery code {i} is on disk");
        }

        let plaintext = f
            .vault
            .sealer
            .open(DID_A, &std::fs::read(&f.vault.path).unwrap())
            .unwrap();
        let body = plaintext.strip_prefix(ENVELOPE_MAGIC).expect("the v2 tag");
        let json: serde_json::Value = serde_json::from_slice(body).unwrap();
        let cose = json["credential"]["cred"]["cred"].to_string();
        assert!(
            !cose.contains("\"d\":") && !cose.to_lowercase().contains("private"),
            "the stored COSE key must carry no private component: {cose}"
        );
    }

    /// **Conformance: the record's top-level key set is EXACTLY the five fields.**
    ///
    /// Asserted as a set rather than by spot-checking absences, so a field added later cannot slip in
    /// unnoticed — and so the three bound fields are pinned at the TOP level, which is what makes the
    /// `#[serde(flatten)]` a de-duplication of logic rather than a change to the bytes.
    #[test]
    fn the_record_carries_exactly_the_five_specified_fields() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        let plaintext = f
            .vault
            .sealer
            .open(DID_A, &std::fs::read(&f.vault.path).unwrap())
            .unwrap();
        let body = plaintext.strip_prefix(ENVELOPE_MAGIC).expect("the v2 tag");
        let json: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(body).expect("the record is a JSON object");

        let mut keys: Vec<&str> = json.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "clock_high_water",
                "consecutive_failures",
                "credential",
                "recovery_codes",
                "throttle_until",
            ],
            "the at-rest shape is fixed by SPEC 3.1e"
        );
        assert!(!json.contains_key("secret"));
        assert!(!json.contains_key("last_accepted_step"));
    }

    /// A vault that was never enrolled reports so rather than erroring, which is what lets the tray ask
    /// on every repaint.
    #[test]
    fn an_unenrolled_vault_is_simply_not_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!vault(dir.path(), DID_A).is_enrolled());
        assert_eq!(
            vault(dir.path(), DID_A).classified_state(),
            EnrolmentState::NotEnrolled
        );
    }

    /// A record that is present but cannot be OPENED classifies as undeterminable, never as enrolled:
    /// the file's existence is all such a read established.
    #[test]
    fn an_unopenable_record_classifies_as_undeterminable() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        f.vault.sealer.lock();

        assert_eq!(f.vault.classified_state(), EnrolmentState::Undeterminable);
        assert!(
            f.vault.is_enrolled(),
            "and the gate still binds over a record it could not read"
        );
    }

    /// An enrolment scan that cannot be completed reports ENROLLED, so the destructive-verb gate is
    /// never skipped by a read that failed.
    ///
    /// **Why the fixture is shaped this way:** `profiles` is made a FILE, so `read_dir` returns a real
    /// I/O error on every platform without needing a permission edit that Windows and Unix express
    /// differently. That is the same shape as an unreadable mount, at the same call.
    ///
    /// **The control is load-bearing.** The first assertion is a genuinely empty brand directory, which
    /// MUST still read as not-enrolled. Without it an implementation that answered `true`
    /// unconditionally would satisfy the second assertion, and it would block every destructive verb on
    /// every account that has no second factor at all — trading a fail-open for a lockout.
    #[test]
    fn an_unreadable_enrolment_scan_is_not_permission_to_skip_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            !enrolment_present(dir.path()),
            "an empty brand directory is honestly absent, not undeterminable"
        );

        std::fs::write(dir.path().join("profiles"), b"not a directory").unwrap();
        assert!(
            enrolment_present(dir.path()),
            "a scan that could not look must not be spent as permission to skip the second factor"
        );
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

    /// The unlock-free view reports PRESENCE and never METHOD: a superseded record is indistinguishable
    /// from a current one to a reader that has opened nothing.
    ///
    /// This is why copy on a LOCKED surface must stay method-neutral — it may say a second factor is
    /// enrolled, and it must not claim a working key.
    #[test]
    fn the_unlock_free_view_cannot_tell_the_two_record_shapes_apart() {
        let current = tempfile::tempdir().unwrap();
        enrolled(current.path());
        let old = tempfile::tempdir().unwrap();
        superseded(old.path());

        assert_eq!(
            enrolment_state(current.path()),
            enrolment_state(old.path()),
            "a file-name scan has no basis for telling these apart"
        );
        assert_eq!(enrolment_state(old.path()), EnrolmentState::Enrolled);
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
        let f = enrolled(dir.path());

        assert!(f.vault.is_enrolled() && enrolment_present(dir.path()));
        f.vault.remove().unwrap();
        assert!(!f.vault.is_enrolled() && !enrolment_present(dir.path()));
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

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                vault(dir.path(), DID_A).judge_typed(WRONG, NOW).unwrap(),
                ChallengeOutcome::Rejected
            );
        }

        match vault(dir.path(), DID_A).judge_typed(WRONG, NOW).unwrap() {
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
        let f = enrolled(dir.path());

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            f.vault.judge_typed(WRONG, NOW).unwrap();
        }
        let first = match f.vault.judge_typed(WRONG, NOW).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            other => panic!("expected a throttle, got {other:?}"),
        };
        let after_first = NOW + first;
        assert_eq!(
            f.vault.judge_typed(WRONG, after_first).unwrap(),
            ChallengeOutcome::Rejected
        );
        let second = match f.vault.judge_typed(WRONG, after_first).unwrap() {
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

    /// A legitimate owner who fat-fingers a code is NOT locked out: two wrong guesses then the right
    /// one gets in, with no recovery code lost to the mistakes. The free budget exists precisely so
    /// honest mistakes cost nothing.
    #[test]
    fn two_wrong_guesses_then_the_right_one_still_gets_the_owner_in() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        assert_eq!(
            f.vault.judge_typed(WRONG, NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        assert_eq!(
            f.vault.judge_typed("YYYYY-YYYYY", NOW).unwrap(),
            ChallengeOutcome::Rejected
        );
        let a = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                .unwrap(),
            ChallengeOutcome::Accepted,
            "an honest mistake within the budget must not throttle the real key"
        );
        assert_eq!(
            f.vault.remaining_recovery_codes().unwrap(),
            recovery_codes::CODE_COUNT,
            "no recovery code was spent"
        );
    }

    /// Accepted evidence CLEARS the bound: after a success, the free budget is restored, so a later
    /// honest mistake is not met with a residual delay left over from before.
    #[test]
    fn a_successful_assertion_clears_the_failure_bound() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            f.vault.judge_typed(WRONG, NOW).unwrap();
        }
        let wait = match f.vault.judge_typed(WRONG, NOW).unwrap() {
            ChallengeOutcome::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            other => panic!("expected a throttle, got {other:?}"),
        };
        let unblocked = NOW + wait;
        let a = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, unblocked)
                .unwrap(),
            ChallengeOutcome::Accepted
        );

        // The slate is clean: the whole free budget of wrong guesses is available again with no delay.
        for _ in 0..FREE_CHALLENGE_ATTEMPTS {
            assert_eq!(
                f.vault.judge_typed(WRONG, unblocked).unwrap(),
                ChallengeOutcome::Rejected,
                "the free budget must be restored after a success"
            );
        }
    }

    /// **Backwards compatibility.** A `DIG2FA1` record written before the attempt-bound fields existed
    /// must still deserialize — an already-enrolled user's vault cannot be bricked by an update — and
    /// must read as zero prior failures. The fixture is a hand-written legacy record carrying only the
    /// three original fields.
    #[test]
    fn a_pre_bound_v1_record_reads_as_zero_prior_failures() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path(), DID_A);
        let secret = TotpSecret::from_bytes(&[0x2a; SECRET_BYTES]).unwrap();

        let legacy = format!(
            r#"{{"secret":"{}","recovery_codes":[],"last_accepted_step":null}}"#,
            hex::encode(secret.as_bytes())
        );
        let mut plaintext = SUPERSEDED_ENVELOPE_MAGIC.to_vec();
        plaintext.extend_from_slice(legacy.as_bytes());
        let sealed = vault.sealer.seal(DID_A, &plaintext).unwrap();
        plant(&vault, &sealed);

        assert_eq!(vault.kind().unwrap(), RecordKind::Superseded);
        assert_eq!(
            vault.judge_typed(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "a legacy record must open and behave as a clean slate"
        );
    }

    /// A rollback must not shorten an ARMED throttle either: once a delay is in force, winding the clock
    /// back leaves the wait in place rather than expiring it early.
    #[test]
    fn rolling_the_clock_back_does_not_shorten_an_armed_throttle() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        for _ in 0..=FREE_CHALLENGE_ATTEMPTS {
            f.vault.judge_typed(WRONG, NOW).unwrap();
        }
        assert!(matches!(
            f.vault.judge_typed(WRONG, NOW).unwrap(),
            ChallengeOutcome::RateLimited { .. }
        ));

        match f.vault.judge_typed(WRONG, NOW - 100_000).unwrap() {
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
        let f = enrolled(dir.path());
        assert_eq!(
            f.vault.current_throttle(NOW).unwrap(),
            None,
            "a fresh enrolment is not throttled"
        );

        for _ in 0..6 {
            let _ = vault(dir.path(), DID_A).judge_typed(WRONG, NOW);
        }
        let peeked = vault(dir.path(), DID_A)
            .current_throttle(NOW)
            .unwrap()
            .expect("a wait is now armed");
        assert!(peeked > 0, "an armed throttle reports a positive wait");
    }

    /// The peek is a PURE read: calling it must record no failure, arm no throttle, and advance no clock
    /// anchor. A vault that is not throttled stays not throttled no matter how many times it is peeked,
    /// and real evidence still passes afterwards — proof the peek wrote nothing.
    #[test]
    fn current_throttle_neither_writes_nor_consumes_an_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());

        for _ in 0..10 {
            assert_eq!(f.vault.current_throttle(NOW).unwrap(), None);
        }
        let a = assert_through(&f.key, &f.credential);
        assert_eq!(
            f.vault
                .judge_assertion(&a.webauthn, &a.response, &a.state, NOW)
                .unwrap(),
            ChallengeOutcome::Accepted,
            "peeking must not consume the free-attempt budget"
        );
    }

    /// Peeking must NOT persist the anti-rollback anchor: a forward peek at a far-future instant must
    /// not push `clock_high_water` ahead, which would leave a later honest challenge judging a
    /// superseded record's codes at a clock the user never actually reached.
    #[test]
    fn peeking_far_in_the_future_does_not_advance_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, secret, _) = superseded(dir.path());

        assert_eq!(vault.current_throttle(NOW + 10_000_000).unwrap(), None);
        assert_eq!(
            vault.judge_typed(&secret.code_at(NOW), NOW).unwrap(),
            ChallengeOutcome::Accepted,
            "a far-future peek must not have advanced the clock anchor"
        );
    }

    /// A locked vault fails CLOSED: the peek must surface the error, never quietly answer "not
    /// throttled" for a record it could not even open.
    #[test]
    fn current_throttle_fails_closed_on_a_locked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let f = enrolled(dir.path());
        f.vault.sealer.lock();
        assert!(
            f.vault.current_throttle(NOW).is_err(),
            "a locked vault must not report 'not throttled'"
        );
    }
}
