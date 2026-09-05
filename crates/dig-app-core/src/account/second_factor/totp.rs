//! RFC 6238 time-based one-time passwords — **retained READ-ONLY, to retire the superseded
//! enrolment** (dig-app#348, originally dig_ecosystem#1840).
//!
//! # What is left here, and what is deliberately gone
//!
//! The second factor is now an asymmetric WebAuthn credential ([`super`]). **No TOTP code clears any
//! gate.** What survives is the ability to VERIFY a code against a secret already on disk, and it
//! exists for exactly one purpose: letting someone whose account still carries the old `DIG2FA1`
//! record retire it with a code from the authenticator app they set it up with.
//!
//! Everything that could CREATE a TOTP enrolment is gone — secret generation, the base32 rendering,
//! the `otpauth://` provisioning URI and the issuer label. That is not tidying: with them removed
//! there is no expression anywhere in this crate that can produce a new shared secret, so "the
//! transition is one-way" is a property of the code rather than a rule someone has to keep.
//!
//! Removing what remains, together with the `DIG2FA1` read path, is
//! <https://github.com/DIG-Network/dig-app/issues/373>.
//!
//! # Why the parameters are the boring ones
//!
//! 30-second step, SHA-1, 6 digits. Not because they are the strongest available — SHA-256 and 8
//! digits both exist in RFC 6238 — but because these are what the authenticator apps that hold the
//! surviving records were configured with, and a verifier that disagreed with them would refuse every
//! honest code. HMAC-SHA1 here is a keyed MAC over a counter, not a collision-resistance claim, so
//! SHA-1's collision weakness does not apply to it.
//!
//! # What this module does NOT do
//!
//! It does not decide whether a code is *acceptable* — only whether it is *arithmetically correct for
//! some step near now*. Single-use enforcement (a code must not be replayed inside its own 30-second
//! window) needs persistent state, so it lives with the enrolment record in [`super::vault`]. Keeping
//! the two apart is what lets this file be exhaustively tested against the RFC's own vectors with no
//! I/O at all.
//!
//! # Secret handling
//!
//! The secret is [`Zeroizing`]. Nothing here logs, and [`Debug`] on [`TotpSecret`] is written by hand
//! to redact.

// The ONE constant-time comparison the app owns. A `==` on the code would leak, through timing, how
// many leading digits a guess got right, turning a 10^6 search into six 10-way searches. It is shared
// with the pairing code (dig_ecosystem#1848), which needs the identical guarantee — two copies is how
// one of them regresses to `==`.
use crate::constant_time::constant_time_eq;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

/// The time step, in seconds — RFC 6238's default and what every authenticator assumes.
pub const STEP_SECONDS: u64 = 30;

/// How many digits a code has. Six is the universal default.
pub const CODE_DIGITS: usize = 6;

/// How many steps either side of "now" are accepted.
///
/// One step (±30s) is RFC 6238 §5.2's own recommendation: it absorbs the phone-vs-PC clock drift and
/// the seconds a person spends typing, and it widens the guessing window only from one code to three
/// — 3 in 10^6 per attempt, which the vault's attempt bound keeps far below anything useful.
pub const SKEW_STEPS: u64 = 1;

/// The shared-secret length in bytes.
///
/// 160 bits, matching HMAC-SHA1's block-independent key size and RFC 4226 §4 R6's recommendation.
pub const SECRET_BYTES: usize = 20;

/// A TOTP shared secret, read back from a superseded enrolment record.
///
/// There is no constructor that invents one. The only way to obtain a value of this type outside of
/// tests is [`from_bytes`](Self::from_bytes) over bytes that were already on disk, which is what makes
/// the retirement path incapable of producing a new enrolment.
///
/// Held in a [`Zeroizing`] buffer and never rendered by [`Debug`]: an authenticator secret is a
/// long-lived credential, so a derived `Debug` would be enough to put it into a panic message.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Zeroizing<[u8; SECRET_BYTES]>);

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

/// Why a byte string could not be read as a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// The stored secret was not [`SECRET_BYTES`] long — a corrupt or foreign blob.
    #[error("the stored second-factor secret is not readable")]
    WrongLength,
}

impl TotpSecret {
    /// Adopt raw secret bytes read out of a superseded enrolment record.
    ///
    /// # Errors
    ///
    /// [`SecretError::WrongLength`] when `bytes` is not [`SECRET_BYTES`] long, so a corrupt blob is
    /// rejected rather than silently padded into a secret no authenticator agrees with.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretError> {
        let array: [u8; SECRET_BYTES] = bytes.try_into().map_err(|_| SecretError::WrongLength)?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// The raw secret.
    ///
    /// Test-only. Production never needs these bytes back: the record stores them, `from_bytes` reads
    /// them, and nothing writes a secret any more. A fixture that plants a superseded record does need
    /// them, and that is the whole remaining use.
    #[cfg(test)]
    pub(super) fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }

    /// The code for the step containing `unix_seconds`, zero-padded to [`CODE_DIGITS`].
    ///
    /// Test-only, and that asymmetry is the point: production VERIFIES codes and never produces one.
    /// A fixture that could not mint the code it is about to submit could only ever test the
    /// rejection path.
    #[cfg(test)]
    pub(crate) fn code_at(&self, unix_seconds: u64) -> Zeroizing<String> {
        self.code_for_step(unix_seconds / STEP_SECONDS)
    }

    /// The code for an explicit step counter — the RFC's `T`.
    fn code_for_step(&self, step: u64) -> Zeroizing<String> {
        // HMAC-SHA1 accepts a key of any length, so this cannot fail for our fixed-length secret.
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&*self.0)
            .expect("HMAC accepts a key of any length");
        mac.update(&step.to_be_bytes());
        let digest = mac.finalize().into_bytes();

        // RFC 4226 §5.4 dynamic truncation: the low nibble of the last byte picks a 4-byte window,
        // whose high bit is cleared so the value is positive in the RFC's signed-integer terms.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let modulus = 10u32.pow(CODE_DIGITS as u32);
        Zeroizing::new(format!("{:0width$}", binary % modulus, width = CODE_DIGITS))
    }

    /// Whether `candidate` is a correct code for some step within [`SKEW_STEPS`] of `now`, and if so
    /// WHICH step it was.
    ///
    /// The step is returned rather than a bare `bool` because the caller must refuse to accept the
    /// same step twice — a code shoulder-surfed or read off a screen is valid for the rest of its
    /// 30-second window, and RFC 6238 §5.2 requires exactly one acceptance per step. A `bool` cannot
    /// express that, so this signature is what makes the replay guard possible at all.
    ///
    /// Whitespace is stripped before comparison: people type `123 456`.
    pub fn matching_step(&self, candidate: &str, now: u64) -> Option<u64> {
        let typed: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
        if typed.len() != CODE_DIGITS || !typed.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let current = now / STEP_SECONDS;
        // Every candidate step is evaluated — no early return — so the number of HMACs computed does
        // not depend on WHICH step matched. Combined with the constant-time comparison below, a
        // caller cannot learn the receiver's clock offset by timing this.
        let mut hit = None;
        for step in current.saturating_sub(SKEW_STEPS)..=current.saturating_add(SKEW_STEPS) {
            if constant_time_eq(self.code_for_step(step).as_bytes(), typed.as_bytes()) {
                hit = Some(step);
            }
        }
        hit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B's SHA-1 seed: the ASCII string `12345678901234567890`.
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_bytes(b"12345678901234567890").expect("20 bytes")
    }

    /// The RFC's own vectors. This is the only test that can tell a correct implementation from one
    /// that is merely self-consistent: a wrong truncation, a wrong counter endianness or a wrong
    /// modulus all round-trip perfectly against themselves and disagree with every phone on earth.
    ///
    /// Appendix B publishes 8-digit codes; the 6-digit code is their low six digits, because both come
    /// from the same dynamic-truncation value modulo a power of ten.
    #[test]
    fn the_rfc_6238_vectors_reproduce_exactly() {
        for (time, eight_digit) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            let expected = &eight_digit[eight_digit.len() - CODE_DIGITS..];
            assert_eq!(
                &*rfc_secret().code_at(time),
                expected,
                "RFC 6238 vector at t={time}"
            );
        }
    }

    /// A code is accepted one step early and one step late, and refused two steps out.
    ///
    /// The fixture pins an explicit `NOW` well away from zero and generates the codes for the
    /// NEIGHBOURING steps rather than asserting on the current one: a test that only offered the
    /// current code could not distinguish ±1 tolerance from no tolerance at all.
    #[test]
    fn a_code_is_accepted_one_step_either_side_and_no_further() {
        const NOW: u64 = 1_700_000_000;
        let secret = rfc_secret();
        let step = NOW / STEP_SECONDS;

        for offset in [-1i64, 0, 1] {
            let at = ((step as i64 + offset) as u64) * STEP_SECONDS;
            let code = secret.code_at(at);
            assert_eq!(
                secret.matching_step(&code, NOW),
                Some((step as i64 + offset) as u64),
                "a code {offset} step(s) away must be accepted, and report its own step"
            );
        }
        for offset in [-2i64, 2] {
            let at = ((step as i64 + offset) as u64) * STEP_SECONDS;
            let code = secret.code_at(at);
            assert_eq!(
                secret.matching_step(&code, NOW),
                None,
                "a code {offset} steps away is outside the window"
            );
        }
    }

    /// The step a match reports is the step the code was MINTED for, not the receiver's current step.
    ///
    /// This is what the replay guard is built on: recording "the current step" instead would let a code
    /// from the previous window be replayed once per window forever.
    #[test]
    fn a_match_reports_the_step_the_code_belongs_to() {
        const NOW: u64 = 1_700_000_045;
        let secret = rfc_secret();
        let previous_step = NOW / STEP_SECONDS - 1;
        let code = secret.code_at(previous_step * STEP_SECONDS);

        assert_eq!(secret.matching_step(&code, NOW), Some(previous_step));
        assert_ne!(
            previous_step,
            NOW / STEP_SECONDS,
            "the fixture must straddle a step boundary"
        );
    }

    /// Two different secrets must not accept each other's codes — otherwise `matching_step` could be
    /// ignoring the secret entirely and every test above would still pass.
    #[test]
    fn another_secret_does_not_accept_this_secrets_code() {
        const NOW: u64 = 1_700_000_000;
        let mine = rfc_secret();
        let theirs = TotpSecret::from_bytes(&[0x2a; SECRET_BYTES]).expect("20 bytes");
        let code = mine.code_at(NOW);

        assert_ne!(mine, theirs, "the fixture must use two distinct secrets");
        assert!(mine.matching_step(&code, NOW).is_some());
        assert_eq!(theirs.matching_step(&code, NOW), None);
    }

    /// Typed noise is refused rather than parsed loosely: a 6-character non-numeric string, a short
    /// code and a long one all fail. Whitespace, and only whitespace, is forgiven.
    #[test]
    fn malformed_input_is_refused_but_spaces_are_forgiven() {
        const NOW: u64 = 1_700_000_000;
        let secret = rfc_secret();
        let code = secret.code_at(NOW);
        let spaced = format!("{} {}", &code[..3], &code[3..]);

        assert!(
            secret.matching_step(&spaced, NOW).is_some(),
            "spaces forgiven"
        );
        for bad in ["", "12345", "1234567", "abcdef", "12 34 5"] {
            assert_eq!(secret.matching_step(bad, NOW), None, "input {bad:?}");
        }
    }

    /// A secret of the wrong length is rejected, so a corrupt vault blob never becomes a secret that
    /// silently disagrees with the user's phone.
    #[test]
    fn a_wrong_length_secret_is_rejected() {
        assert_eq!(
            TotpSecret::from_bytes(b"too short"),
            Err(SecretError::WrongLength)
        );
    }

    /// The redacting `Debug` — a derived one would print the secret into any panic or log line that
    /// formatted the value.
    #[test]
    fn debug_never_prints_the_secret() {
        let secret = rfc_secret();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "TotpSecret(<redacted>)");
        assert!(!rendered.contains("12345678901234567890"));
        assert!(!rendered.contains(&hex::encode(secret.as_bytes())));
    }
}
