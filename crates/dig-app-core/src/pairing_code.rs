//! The pairing CODE — the trust anchor for callers DIG does not ship (dig_ecosystem#1848,
//! `SPEC.md` §5.6.3a, **security-critical**).
//!
//! # Why this exists
//!
//! [`crate::loopback`] admits a caller on the strength of a PINNED extension id: the `Origin` guard and
//! [`FrameRouter`](crate::loopback::FrameRouter) both check `ext_id ∈ allowed_ext_ids`, a fixed set of
//! DIG's own published extension ids. That works precisely because DIG controls both ends. A genuine
//! third party has no pin and therefore cannot pair at all — by construction, not by oversight.
//!
//! The code REPLACES the pin for those callers, which makes it the one thing standing between any local
//! process and the user's identity agent. Everything below follows from that.
//!
//! # The direction of the flow is the control
//!
//! **dig-app generates the code and shows it to the USER**, who carries it to the app. Never the
//! reverse. An app that proposes its own code has paired itself, and the human has authorized a number
//! they were shown rather than a number they chose to hand over. Concretely: only the tray can
//! [`issue`](PairingCodeIssuer::issue); the loopback channel can only [`redeem`](PairingCodeIssuer::redeem).
//! A caller that arrives with no code outstanding is refused with no window drawn at all, so a hostile
//! local process cannot make a consent prompt appear, let alone fish for a mis-click.
//!
//! # Entropy against the window
//!
//! The alphabet is Crockford base32 (32 symbols) and a code is [`CODE_SYMBOLS`] = 8 of them, so the
//! space is 32^8 = 2^40 ≈ 1.10 × 10^12. That number alone is not the security argument — an unbounded
//! guess loop against a loopback port would walk it — so the code is bounded on three axes at once:
//!
//! - **Single-use.** A redeemed code is destroyed; there is never a second chance at the same secret.
//! - **Short-lived.** It expires [`CODE_TTL_SECS`] = 120 s after issue, which is how long it takes a
//!   person to read eight characters and type them into another window.
//! - **Attempt-bounded.** [`MAX_ATTEMPTS`] = 5 wrong guesses DESTROY the code — not merely refuse the
//!   sixth. This is the axis that matters, and it is the defect filed against the 2FA challenge window
//!   in dig_ecosystem#1847, deliberately not reproduced here.
//!
//! So an attacker gets at most 5 guesses at one 2^40 secret per code a human chooses to issue:
//! P(success) ≤ 5 / 2^40 ≈ 4.5 × 10^-12. For comparison, the unbounded case is not close — at a
//! loopback-realistic 10,000 guesses/second an attacker covers 1.2 × 10^6 of the space inside the
//! 120-second window, or one chance in ~900,000 per issued code, ~200,000 times worse. The bound, not
//! the length, is doing the work; the length is what makes the bound affordable to type.
//!
//! # One failure, no oracle
//!
//! [`CodeFailure`] distinguishes why a redemption failed for the LOG and for the tests. The loopback
//! layer collapses every variant to one wire error on purpose: telling a caller "no code is outstanding
//! right now" reveals whether a human is mid-pairing, which is exactly the signal a process racing to
//! redeem someone else's code would want.

use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::constant_time::constant_time_eq;

/// How many symbols a pairing code carries. Eight Crockford-base32 symbols is 2^40 — see the module
/// docs for why that number is sized against the attempt bound rather than against a brute-force rate.
pub const CODE_SYMBOLS: usize = 8;

/// How long an issued code stays redeemable, in seconds. Two minutes is a person reading eight
/// characters off one window and typing them into another, with room to be interrupted once.
pub const CODE_TTL_SECS: u64 = 120;

/// How many wrong guesses an issued code survives. The sixth does not merely fail — the fifth failure
/// DESTROYS the code, so a guessing loop cannot continue against the same secret (dig_ecosystem#1847).
pub const MAX_ATTEMPTS: u32 = 5;

/// Crockford's base32 alphabet: the digits plus the uppercase letters, MINUS `I`, `L`, `O` and `U`.
///
/// `I`/`L` are dropped because they are read as `1`, `O` because it is read as `0`, and `U` because
/// excluding it keeps a randomly-generated code from spelling something the user would rather not read
/// aloud. Dropping them costs nothing — the alternative to a 32-symbol alphabet with no confusable
/// pairs is a 36-symbol one where a mis-read is a support ticket.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a [`redeem`](PairingCodeIssuer::redeem) was refused.
///
/// Every variant means the same thing to the caller — no pairing — and the loopback layer maps them all
/// to ONE wire error so the channel is not an oracle for whether a human is mid-pairing (module docs).
/// The distinction exists for the log and for the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFailure {
    /// No code has been issued, or the last one was already redeemed, expired, or exhausted.
    NoneOutstanding,
    /// A code was outstanding but its time-to-live had passed. The code is destroyed by the attempt.
    Expired,
    /// The code did not match. The attempt budget has been decremented.
    Mismatch,
    /// The attempt budget ran out. The code has been destroyed, so even the CORRECT code now fails —
    /// which is the point: the only way forward is for the human to issue a new one.
    Exhausted,
}

/// An issued pairing code, held only long enough to put it on the user's screen.
///
/// [`Debug`] is implemented by hand and REDACTS the value: this is the secret that admits an unpinned
/// caller to the identity channel, and a derived `Debug` would put it into any log line or test failure
/// that formatted it (`tests/never_log.rs` pins the rule for the rest of the app's secrets).
pub struct PairingCode {
    /// The canonical (normalized, ungrouped) symbols. Zeroized when the code is dropped.
    symbols: Zeroizing<String>,
}

impl PairingCode {
    /// The form shown to the user: the symbols in two groups of four, `ABCD-EFGH`.
    ///
    /// Grouping is for the eye only — [`normalize`] discards the separator — so the window may show it
    /// however it reads best without the wire caring.
    pub fn display(&self) -> String {
        let (left, right) = self.symbols.split_at(CODE_SYMBOLS / 2);
        format!("{left}-{right}")
    }
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

/// The one outstanding code and its budget. At most one exists at a time — issuing replaces whatever
/// was there, so a user who clicks "pair an app" twice cannot leave a forgotten code alive behind them.
struct Outstanding {
    symbols: Zeroizing<String>,
    issued_at: u64,
    attempts_left: u32,
}

/// Issues pairing codes for the tray and redeems them for the loopback channel.
///
/// Interior-mutable ([`Mutex`]) and `Send + Sync` so the tray thread and the loopback connection tasks
/// share ONE issuer behind an `Arc` — which is what makes "at most one code is outstanding" true across
/// the whole process rather than per-caller.
///
/// The clock is passed IN to every method rather than read here, so expiry is exercised at pinned
/// instants in tests instead of against a wall clock that has already moved.
pub struct PairingCodeIssuer {
    outstanding: Mutex<Option<Outstanding>>,
}

impl Default for PairingCodeIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingCodeIssuer {
    /// An issuer with no code outstanding.
    pub fn new() -> Self {
        Self {
            outstanding: Mutex::new(None),
        }
    }

    /// Mint a fresh code, replacing any outstanding one, and start its clock at `now`
    /// (Unix-epoch seconds).
    ///
    /// **Only the tray calls this.** It is the whole of the direction rule in the module docs: nothing
    /// reachable from the loopback channel can reach this method, so no remote caller can cause a code
    /// to exist, and therefore none can cause a consent window to be drawn.
    pub fn issue(&self, now: u64) -> PairingCode {
        let symbols = Zeroizing::new(random_symbols());
        *self.lock() = Some(Outstanding {
            symbols: symbols.clone(),
            issued_at: now,
            attempts_left: MAX_ATTEMPTS,
        });
        PairingCode { symbols }
    }

    /// Redeem `candidate` at `now`. On success the code is consumed — a second redemption of the same
    /// code fails [`CodeFailure::NoneOutstanding`], because a pairing code authorizes exactly one
    /// pairing.
    ///
    /// The comparison is constant-time, so a wrong guess reveals nothing about how many leading symbols
    /// it got right; a timing-leaky compare would turn one 2^40 search into eight 32-way ones and make
    /// the attempt budget irrelevant.
    ///
    /// # Errors
    ///
    /// [`CodeFailure`] — and in EVERY failing case the caller must refuse the pairing outright. Note
    /// that an expired or exhausted code is destroyed by the attempt that discovers it, so the failure
    /// is terminal for that code rather than something to retry.
    pub fn redeem(&self, candidate: &str, now: u64) -> Result<(), CodeFailure> {
        let mut slot = self.lock();
        let Some(code) = slot.as_mut() else {
            return Err(CodeFailure::NoneOutstanding);
        };

        // Expiry first: an expired code is not a wrong guess and must not consume a budget slot, and it
        // must not be redeemable however correct the candidate is.
        if now.saturating_sub(code.issued_at) > CODE_TTL_SECS {
            *slot = None;
            return Err(CodeFailure::Expired);
        }

        if constant_time_eq(normalize(candidate).as_bytes(), code.symbols.as_bytes()) {
            *slot = None;
            return Ok(());
        }

        // A wrong guess. Decrement first, and DESTROY the code when the budget is gone — refusing only
        // the next attempt would leave the secret alive for a caller that simply keeps trying
        // (dig_ecosystem#1847).
        code.attempts_left = code.attempts_left.saturating_sub(1);
        if code.attempts_left == 0 {
            *slot = None;
            return Err(CodeFailure::Exhausted);
        }
        Err(CodeFailure::Mismatch)
    }

    /// Whether a code is outstanding and still within its time-to-live at `now`.
    ///
    /// For the tray's own display only. It deliberately does NOT expire the code as a side effect — a
    /// question about state must not change it — so a stale code is cleared by the next
    /// [`redeem`](Self::redeem) or [`issue`](Self::issue).
    pub fn has_outstanding(&self, now: u64) -> bool {
        self.lock()
            .as_ref()
            .is_some_and(|code| now.saturating_sub(code.issued_at) <= CODE_TTL_SECS)
    }

    /// Destroy any outstanding code — the user's way to take a code back after showing it to the wrong
    /// window. Idempotent.
    pub fn cancel(&self) {
        *self.lock() = None;
    }

    /// A poisoned mutex means another thread panicked mid-update — fail loudly rather than redeem
    /// against half-updated state.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Outstanding>> {
        self.outstanding
            .lock()
            .expect("pairing-code mutex poisoned")
    }
}

/// The current Unix time in whole seconds — the ONE wall-clock read the pairing surface makes.
///
/// Every function in this module takes `now` as an argument instead of reading the clock, so expiry is
/// exercised at pinned instants rather than against a clock that has already moved. This is where the
/// real reading happens, at the outermost edge (the tray handler and the frame router), and it is
/// public so those two callers share one definition rather than each keeping their own.
///
/// A clock before the epoch is impossible on a sane host; clamp to 0 rather than panic if it ever
/// happens.
pub fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Draw [`CODE_SYMBOLS`] symbols from the CSPRNG, uniformly over [`ALPHABET`].
///
/// The alphabet is exactly 32 symbols, so masking a byte to its low 5 bits indexes it with NO modulo
/// bias — every symbol is drawn with probability exactly 1/32, which is what lets the module docs claim
/// the full 2^40 rather than an effective space some fraction smaller.
fn random_symbols() -> String {
    let mut bytes = Zeroizing::new([0u8; CODE_SYMBOLS]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[(byte & 0b0001_1111) as usize] as char)
        .collect()
}

/// Reduce a typed code to its canonical symbols: uppercase, Crockford's confusable letters folded onto
/// the digits they are read as, and everything else — spaces, the display hyphen, punctuation a phone
/// keyboard inserted — dropped.
///
/// Folding is not a weakening. `I`, `L` and `O` are not IN the alphabet, so no generated code contains
/// them; mapping them onto `1` and `0` only rescues a person who wrote down what they saw, and removes
/// zero entropy from the generated space. Dropping unknown characters rather than rejecting them keeps
/// `abcd-efgh`, `ABCD EFGH` and `ABCDEFGH` the same code — but note a candidate of the wrong LENGTH can
/// never match, so dropping is not a way to smuggle a shorter guess past the comparison.
pub fn normalize(typed: &str) -> String {
    typed
        .chars()
        .filter_map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => Some('1'),
            'O' => Some('0'),
            upper if ALPHABET.contains(&(upper as u8)) => Some(upper),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PINNED instant, not a wall clock. Every expiry assertion below is relative to this, so the
    /// test's idea of "now" cannot drift past the TTL between issue and redeem — the failure mode where
    /// a group of tests silently only ever exercises the expired path.
    const NOW: u64 = 1_800_000_000;

    /// A code that is certainly not the issued one, whatever the issuer drew. Same length and alphabet,
    /// so a wrong guess is rejected on its VALUE rather than on its shape.
    fn wrong_guess(issued: &str) -> String {
        // Rotate every symbol one place along the alphabet: same length, same alphabet, never equal.
        issued
            .bytes()
            .map(|b| {
                let index = ALPHABET.iter().position(|&a| a == b).expect("in alphabet");
                ALPHABET[(index + 1) % ALPHABET.len()] as char
            })
            .collect()
    }

    #[test]
    fn an_issued_code_is_eight_symbols_from_the_alphabet() {
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let symbols = normalize(&code.display());
        assert_eq!(symbols.len(), CODE_SYMBOLS);
        assert!(
            symbols.bytes().all(|b| ALPHABET.contains(&b)),
            "every symbol must come from the confusable-free alphabet: {symbols}"
        );
        // The displayed form is grouped for the eye and normalizes back to the same symbols.
        assert_eq!(code.display().len(), CODE_SYMBOLS + 1);
        assert!(code.display().contains('-'));
    }

    #[test]
    fn successive_codes_differ() {
        // A generator returning a constant — or one seeded once — would pass every other test here.
        let issuer = PairingCodeIssuer::new();
        let first = issuer.issue(NOW).display();
        let second = issuer.issue(NOW).display();
        assert_ne!(first, second);
    }

    #[test]
    fn the_correct_code_redeems() {
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        assert_eq!(issuer.redeem(&code.display(), NOW), Ok(()));
    }

    #[test]
    fn a_code_redeems_exactly_once() {
        // Single-use is the property; an implementation that verifies without consuming passes every
        // other assertion in this file.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        assert_eq!(issuer.redeem(&code.display(), NOW), Ok(()));
        assert_eq!(
            issuer.redeem(&code.display(), NOW),
            Err(CodeFailure::NoneOutstanding)
        );
        assert!(!issuer.has_outstanding(NOW));
    }

    #[test]
    fn a_caller_arriving_with_no_outstanding_code_is_refused() {
        // The whole of "an app cannot pair itself": with nothing issued, no candidate works.
        let issuer = PairingCodeIssuer::new();
        assert!(!issuer.has_outstanding(NOW));
        assert_eq!(
            issuer.redeem("ABCD-EFGH", NOW),
            Err(CodeFailure::NoneOutstanding)
        );
    }

    #[test]
    fn issuing_again_destroys_the_previous_code() {
        // At most ONE code outstanding. Otherwise a user who clicked twice leaves a forgotten secret
        // alive for the rest of its TTL.
        let issuer = PairingCodeIssuer::new();
        let first = issuer.issue(NOW);
        let second = issuer.issue(NOW);
        assert_eq!(
            issuer.redeem(&first.display(), NOW),
            Err(CodeFailure::Mismatch),
            "the superseded code must no longer redeem"
        );
        assert_eq!(issuer.redeem(&second.display(), NOW), Ok(()));
    }

    #[test]
    fn a_code_is_redeemable_at_the_ttl_boundary_and_not_one_second_past_it() {
        // The bound is pinned from BOTH sides. Tested only from below, an off-by-one that never expired
        // anything would pass.
        let issuer = PairingCodeIssuer::new();
        let at_bound = issuer.issue(NOW);
        assert_eq!(
            issuer.redeem(&at_bound.display(), NOW + CODE_TTL_SECS),
            Ok(()),
            "a code must still work at the last second of its life"
        );

        let past_bound = issuer.issue(NOW);
        assert_eq!(
            issuer.redeem(&past_bound.display(), NOW + CODE_TTL_SECS + 1),
            Err(CodeFailure::Expired)
        );
    }

    #[test]
    fn an_expired_code_is_destroyed_rather_than_merely_refused() {
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        assert_eq!(
            issuer.redeem(&code.display(), NOW + CODE_TTL_SECS + 1),
            Err(CodeFailure::Expired)
        );
        // Nothing survives the expiry — not even for a caller whose clock disagrees.
        assert!(!issuer.has_outstanding(NOW));
        assert_eq!(
            issuer.redeem(&code.display(), NOW),
            Err(CodeFailure::NoneOutstanding)
        );
    }

    #[test]
    fn expiry_does_not_consume_the_attempt_budget() {
        // An expired code is not a wrong guess. If expiry burned a slot, a user who left the window
        // open would silently arrive at the next code with a reduced budget.
        let issuer = PairingCodeIssuer::new();
        let stale = issuer.issue(NOW);
        assert_eq!(
            issuer.redeem(&stale.display(), NOW + CODE_TTL_SECS + 1),
            Err(CodeFailure::Expired)
        );

        let fresh = issuer.issue(NOW);
        let wrong = wrong_guess(&normalize(&fresh.display()));
        for _ in 0..MAX_ATTEMPTS - 1 {
            assert_eq!(issuer.redeem(&wrong, NOW), Err(CodeFailure::Mismatch));
        }
        assert_eq!(
            issuer.redeem(&fresh.display(), NOW),
            Ok(()),
            "the fresh code must arrive with a FULL budget"
        );
    }

    #[test]
    fn the_last_attempt_within_the_budget_still_works() {
        // The lower side of the attempt bound: MAX_ATTEMPTS - 1 wrong guesses must NOT destroy the
        // code. Without this, an implementation that destroyed one guess too early would look correct
        // to the exhaustion test below.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let wrong = wrong_guess(&normalize(&code.display()));
        for attempt in 0..MAX_ATTEMPTS - 1 {
            assert_eq!(
                issuer.redeem(&wrong, NOW),
                Err(CodeFailure::Mismatch),
                "guess {attempt} is inside the budget"
            );
        }
        assert_eq!(issuer.redeem(&code.display(), NOW), Ok(()));
    }

    #[test]
    fn exhausting_the_budget_destroys_the_code_so_even_the_correct_one_fails() {
        // THE load-bearing assertion of the whole module, and the one dig_ecosystem#1847 is about.
        //
        // Asserting only that the sixth guess is refused would be satisfied by an implementation that
        // keeps the secret alive — the attacker's loop would stop, but a code the user is still holding
        // would remain redeemable, and a budget that reset per connection would restore the loop. The
        // fixture that distinguishes those is the CORRECT code after the budget is gone.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let wrong = wrong_guess(&normalize(&code.display()));

        for _ in 0..MAX_ATTEMPTS - 1 {
            assert_eq!(issuer.redeem(&wrong, NOW), Err(CodeFailure::Mismatch));
        }
        assert_eq!(
            issuer.redeem(&wrong, NOW),
            Err(CodeFailure::Exhausted),
            "the last slot in the budget destroys the code"
        );
        assert_eq!(
            issuer.redeem(&code.display(), NOW),
            Err(CodeFailure::NoneOutstanding),
            "the CORRECT code must be dead once the budget is exhausted"
        );
        assert!(!issuer.has_outstanding(NOW));
    }

    #[test]
    fn a_brute_force_run_never_gets_more_than_the_budget() {
        // The bound holds across a long run, not just the first six calls — a budget that reset on some
        // interval would show up here as more than MAX_ATTEMPTS non-terminal refusals.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let wrong = wrong_guess(&normalize(&code.display()));

        let mut guesses_that_reached_a_live_code = 0;
        for _ in 0..1_000 {
            match issuer.redeem(&wrong, NOW) {
                Err(CodeFailure::Mismatch) | Err(CodeFailure::Exhausted) => {
                    guesses_that_reached_a_live_code += 1;
                }
                Err(CodeFailure::NoneOutstanding) => {}
                other => panic!("a wrong guess must never succeed: {other:?}"),
            }
        }
        assert_eq!(
            guesses_that_reached_a_live_code, MAX_ATTEMPTS,
            "1000 guesses must reach a live code exactly MAX_ATTEMPTS times"
        );
    }

    #[test]
    fn the_typed_form_is_forgiving_about_case_grouping_and_confusable_letters() {
        // A person copies what they SEE. `1` written as `l`, `0` as `O`, the group separator typed as a
        // space or omitted — all of it must reach the same code, or the feature fails in the field
        // while passing every test that feeds it back its own output.
        assert_eq!(normalize("abcd-efgh"), "ABCDEFGH");
        assert_eq!(normalize("ABCD EFGH"), "ABCDEFGH");
        assert_eq!(normalize("A B\tC-D_E.F/G,H"), "ABCDEFGH");
        assert_eq!(normalize("lI0O"), "1100", "I/L read as 1, O read as 0");
        assert_eq!(normalize("li0o"), "1100", "lowercase too");
    }

    #[test]
    fn a_forgivingly_typed_code_actually_redeems() {
        // normalize() being right is not the same as redeem() using it.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let sloppy = code.display().to_lowercase().replace('-', " ");
        assert_eq!(issuer.redeem(&sloppy, NOW), Ok(()));
    }

    #[test]
    fn a_shorter_or_longer_candidate_never_matches() {
        // Dropping unknown characters must not let a prefix through: the comparison is length-checked.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let symbols = normalize(&code.display());
        assert_eq!(
            issuer.redeem(&symbols[..CODE_SYMBOLS - 1], NOW),
            Err(CodeFailure::Mismatch)
        );
        assert_eq!(
            issuer.redeem(&format!("{symbols}Z"), NOW),
            Err(CodeFailure::Mismatch)
        );
        // …and the full code still works, so the two above were rejected on length, not on damage.
        assert_eq!(issuer.redeem(&code.display(), NOW), Ok(()));
    }

    #[test]
    fn cancelling_destroys_the_outstanding_code() {
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        issuer.cancel();
        assert!(!issuer.has_outstanding(NOW));
        assert_eq!(
            issuer.redeem(&code.display(), NOW),
            Err(CodeFailure::NoneOutstanding)
        );
        issuer.cancel(); // idempotent
    }

    #[test]
    fn has_outstanding_reports_the_ttl_and_does_not_consume_it() {
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        assert!(issuer.has_outstanding(NOW));
        assert!(issuer.has_outstanding(NOW + CODE_TTL_SECS));
        assert!(!issuer.has_outstanding(NOW + CODE_TTL_SECS + 1));
        // Asking did not destroy it — the code is still good inside its window.
        assert_eq!(issuer.redeem(&code.display(), NOW), Ok(()));
    }

    #[test]
    fn the_code_is_redacted_in_debug_output() {
        // This value admits an unpinned caller to the identity channel; it must not reach a log line.
        let issuer = PairingCodeIssuer::new();
        let code = issuer.issue(NOW);
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "PairingCode(<redacted>)");
        assert!(!rendered.contains(&normalize(&code.display())));
    }
}
