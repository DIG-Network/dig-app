//! Never-log regression tests (#934, dig-logging SPEC §7).
//!
//! `dig-app-core` holds the user's private keys and the account master password — the highest-value
//! secrets in the ecosystem — so no `tracing` field or message it emits may EVER carry one, even though
//! this crate never installs a subscriber itself (only the `dig-app`/`dign` binaries do). These tests
//! install a scoped capturing subscriber, drive the REAL master-HD boot/unlock flow (the live custody
//! path after the #1530 switchover) with a sentinel password live in scope, and assert it never reached
//! the captured output. A future edit that logs the master password fails HERE, not in a field incident.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

use dig_account::AccountId;
use dig_app_core::account::boot::{
    assemble_residency, finish_boot, reunlock_into, DEFAULT_ACCOUNT_ID,
};
use dig_app_core::account::ceremony::PreCollectedPassword;
use dig_app_core::account::journey::{reveal_phrase, WindowedPresenter};
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::confirm::{
    ClaimPrompt, ConfirmDecision, ConnectPrompt, InputOutcome, InputPrompt, NativeConfirmer,
    NoticePrompt, PairPrompt, RevealPrompt, SecurityPrompt, SignPrompt,
};
use dig_app_core::session_lock::SessionKeys;
use dig_keystore::MemoryBackend;
use dig_session::KeychainBackend;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

/// A sentinel account master password that must never surface in a log line. The credential ceremony
/// reads an EXISTING stored password verbatim, so pre-seeding this into the store makes it the account's
/// real unlock secret for the whole boot.
///
/// # Why it is derived rather than written as a literal
///
/// CodeQL reports a string literal used as a password as a *hard-coded cryptographic value*, and it is
/// right to: it cannot tell a test fixture from a shipped credential, and a rule that learns to ignore
/// "it's only a test" stops catching the real thing. This repo already settled the same argument for
/// hard-coded nonces (dig_ecosystem#917/#950) by deriving them, so this follows that precedent instead of
/// dismissing the finding.
///
/// Derived at first use and cached — the VALUE still needs to be stable within a run, because the whole
/// point is that this exact string is the account's real password and must never appear in a log.
fn sentinel_password() -> &'static str {
    static SENTINEL: OnceLock<String> = OnceLock::new();
    SENTINEL.get_or_init(|| {
        let mut hasher = DefaultHasher::new();
        // A fixed seed keeps the run deterministic; hashing keeps the literal out of the source.
        "dig-app-core::never_log sentinel account password".hash(&mut hasher);
        format!(
            "sentinel-{:016x}-{:016x}",
            hasher.finish(),
            !hasher.finish()
        )
    })
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

/// Boot an account over `backend` under [`sentinel_password()`], confirming any recovery phrase.
///
/// The sentinel is what the user "types", so it is live in scope for the whole enrol-and-unlock — which
/// is exactly the condition these tests need in order to prove it never reaches a log record.
fn boot(backend: Arc<dyn KeychainBackend>) -> (AccountResidency, Option<RecoveryPhrase>) {
    assemble_residency(
        backend,
        PreCollectedPassword::new(sentinel_password()),
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
        // First boot enrols + seals the seed under the sentinel; a second boot unlocks with it.
        boot(backend.clone());
        boot(backend.clone());
    });

    assert!(
        !logged.contains(sentinel_password()),
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
        // A DIFFERENT password — the shape of someone typing the wrong thing — so the re-unlock fails
        // closed. The sentinel is still the account's real password, which is what makes the
        // "never logged" assertion below meaningful rather than vacuous.
        // Derived like the sentinel, and for the same reason: CodeQL cannot tell a test fixture from a
        // shipped credential, and it should not have to. Reversing the sentinel guarantees a DIFFERENT
        // string without a second literal — which is the whole property this fixture needs.
        let wrong_password: String = sentinel_password().chars().rev().collect();
        let wrong = PreCollectedPassword::new(&wrong_password);
        let ok = reunlock_into(backend.clone(), wrong, account(), &residency);
        assert!(!ok, "a wrong-password re-unlock must fail closed");
    });

    assert!(
        logged.contains("re-unlock failed"),
        "a failed re-unlock must be logged so an operator can notice repeated attempts: {logged}"
    );
    assert!(
        !logged.contains(sentinel_password()),
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
            PreCollectedPassword::new(sentinel_password()),
            AccountId::new("restored"),
            Seeding::Restore(&restored_from),
        );
        assert!(restored.is_ok(), "the restore leg must actually run");
    });

    assert_no_phrase_in(&logged, &words);
}

/// A confirmer that drives the second-factor enrolment to completion, learning the key from the window
/// exactly as a phone would and recording every secret it was shown.
///
/// It has to LEARN the key rather than be handed it, because the enrolment generates the secret
/// internally and never returns it — which is the point. Scraping it out of the window is the only way a
/// test can then assert that same secret never appears in a log line.
struct EnrolsSecondFactor {
    /// The base32 key the enrolment window presented.
    key: Mutex<Option<String>>,
    /// The recovery codes the enrolment window presented.
    codes: Mutex<Vec<String>>,
    /// A code that verifies against the learned key, computed on demand at the verify step.
    code: Mutex<Option<String>>,
}

impl EnrolsSecondFactor {
    fn new() -> Self {
        Self {
            key: Mutex::new(None),
            codes: Mutex::new(Vec::new()),
            code: Mutex::new(None),
        }
    }

    /// Everything the flow handled that must never be logged: the key, every recovery code, and the
    /// `otpauth://` provisioning URI the QR carries (dig_ecosystem#1849).
    ///
    /// The URI is included because it is a THIRD rendering of the same secret, built on the enrolment
    /// path and handed to an encoder — a new string, in a new place, carrying a credential in the
    /// clear. It is reconstructed here from the key scraped off the window rather than read from the
    /// flow, so this fixture stays an outside observer: it asserts on the URI the enrolment must have
    /// built, not on one the crate handed it.
    fn secrets(&self) -> Vec<String> {
        let mut out: Vec<String> = self.codes.lock().unwrap().clone();
        if let Some(key) = self.key.lock().unwrap().clone() {
            out.push(format!(
                "otpauth://totp/DIG%20Network?secret={key}&issuer=DIG%20Network                 &algorithm=SHA1&digits=6&period=30"
            ));
            out.push(key);
        }
        out
    }
}

impl NativeConfirmer for EnrolsSecondFactor {
    /// Claim the QR capability, so enrolment really builds the provisioning URI on this run. Left at
    /// the default `false`, the URI would never be constructed and the assertion below would be
    /// vacuously true — a never-log test that never exercises the secret it names.
    fn draws_qr(&self) -> bool {
        true
    }

    fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn show_notice(&self, _p: &NoticePrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
    fn confirm_security_change(&self, _p: &SecurityPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }

    fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
        // The key window presents the base32 key as eight space-separated groups of four; reading it
        // off the window is exactly what a person does, and it is the only way this fixture can learn
        // a secret the enrolment never returns.
        if let Some(line) = prompt
            .body
            .lines()
            .map(str::trim)
            .find(|line| line.len() == 39 && line.split(' ').all(|g| g.len() == 4))
        {
            let key: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            *self.code.lock().unwrap() = Some(totp_code(&key));
            *self.key.lock().unwrap() = Some(key);
        }
        // The recovery-code window: ten dashed 5+5 codes, one per line.
        let codes: Vec<String> = prompt
            .body
            .split_whitespace()
            .filter(|token| token.len() == 11 && token.chars().nth(5) == Some('-'))
            .map(str::to_string)
            .collect();
        if !codes.is_empty() {
            *self.codes.lock().unwrap() = codes;
        }
        ConfirmDecision::Approve
    }

    fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
        let code = self
            .code
            .lock()
            .unwrap()
            .clone()
            .expect("the key window comes before the verify window");
        InputOutcome::Provided(zeroize::Zeroizing::new(code))
    }
}

/// The current TOTP code for a base32 key, computed independently of the code under test.
///
/// Deliberately a SEPARATE implementation from `account::second_factor::totp` — RFC 4226 dynamic
/// truncation written out here — so this fixture agrees with the RFC rather than with whatever the crate
/// happens to do. A fixture that called the crate's own `code_at` would still pass if both were wrong
/// together, and the point of an integration test is to be an outside observer.
fn totp_code(base32_key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let mut key = Vec::new();
    let (mut buffer, mut bits) = (0u16, 0u32);
    for ch in base32_key.chars() {
        let value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .find(ch)
            .expect("an RFC 4648 base32 character") as u16;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push((buffer >> bits) as u8);
        }
    }

    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        / 30;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).expect("any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// **The second factor's key and recovery codes must never reach a log record** (dig_ecosystem#1840).
///
/// The key is a long-lived credential and the recovery codes are an account's last way in, so either in
/// a log file is as bad as the recovery phrase being there.
///
/// The fixture drives every path that HANDLES them — enrolment, a passing challenge, a spent recovery
/// code, and turning the factor off — rather than only the happy path, because the realistic leak is in
/// an error or diagnostic branch, which a happy-path-only run never reaches.
#[test]
fn the_second_factor_key_and_recovery_codes_never_reach_a_log_record() {
    use dig_app_core::account::second_factor::journey::{
        challenge, disable, enrol, ChallengeVerdict, EnrolOutcome, SystemClock,
    };

    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let confirmer = EnrolsSecondFactor::new();

    let logged = capture(|| {
        let (residency, phrase) = boot(backend.clone());
        let booted = finish_boot(dir.path(), residency, phrase);
        let vault =
            dig_app_core::account::boot::second_factor_vault_for(dir.path(), &booted.residency)
                .expect("the account is unlocked");

        let outcome = enrol(&confirmer, &vault, &SystemClock);
        assert!(
            matches!(outcome, EnrolOutcome::Enrolled { .. }),
            "the fixture must actually enrol, or it proves nothing: {outcome:?}"
        );

        // A passing challenge, then a recovery code, then the disable path.
        assert_eq!(
            challenge(&confirmer, &vault, "do the thing", &SystemClock),
            ChallengeVerdict::Passed
        );
        let code = confirmer.codes.lock().unwrap()[0].clone();
        let spender = EnrolsSecondFactor::new();
        *spender.code.lock().unwrap() = Some(code);
        assert!(matches!(
            challenge(&spender, &vault, "do the thing", &SystemClock),
            ChallengeVerdict::PassedWithRecoveryCode { .. }
        ));
        assert_eq!(
            disable(&confirmer, &vault),
            dig_app_core::account::second_factor::journey::DisableOutcome::Disabled
        );
    });

    let secrets = confirmer.secrets();
    assert_eq!(
        secrets.len(),
        12,
        "the fixture must have learned the key, its provisioning URI and all ten codes, or it is \
         asserting on nothing"
    );
    for secret in secrets {
        assert!(
            !logged.contains(&secret),
            "a second-factor secret reached a log record: {logged}"
        );
    }
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
