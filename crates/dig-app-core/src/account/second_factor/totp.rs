//! RFC 6238 time-based one-time passwords — the arithmetic half of the second factor
//! (dig_ecosystem#1840).
//!
//! # Why the parameters are the boring ones
//!
//! 30-second step, SHA-1, 6 digits. Not because they are the strongest available — SHA-256 and 8
//! digits both exist in RFC 6238 — but because a second factor is worth nothing if the user's
//! authenticator cannot hold it, and SHA-1/6/30 is the only combination every shipping authenticator
//! (Google Authenticator, Authy, 1Password, Aegis, Bitwarden, iOS Passwords) reads without special
//! configuration. HMAC-SHA1 here is a keyed MAC over a counter, not a collision-resistance claim, so
//! SHA-1's collision weakness does not apply to it.
//!
//! # The `otpauth://` URI, and why it went away and came back
//!
//! That URI exists to be carried by a QR code, and the first build of this feature offered no QR — so
//! the URI had no consumer, and it was removed rather than left as public API nobody called. It was
//! also unshowable: rendered as TEXT it is ~130 unbreakable characters, which the native window's
//! `STATIC` control silently CLIPS, and a screenshot of that build caught exactly that.
//!
//! The QR is now drawn (dig_ecosystem#1849), so [`TotpSecret::provisioning_uri`] is back — for the QR
//! encoder and for nothing else. It is deliberately NOT shown as text: the QR is the machine path and
//! the grouped base32 key is the human one, and a third rendering of the same secret would be a third
//! place it can be photographed. (The clipping itself is fixed at its root in the window layer, which
//! now breaks any unwrappable run rather than trusting callers to pass short strings.)
//!
//! # What this module does NOT do
//!
//! It does not decide whether a code is *acceptable* — only whether it is *arithmetically correct for
//! some step near now*. Single-use enforcement (a code must not be replayed inside its own 30-second
//! window) needs persistent state, so it lives with the enrolment record in
//! [`super::vault`](super::vault). Keeping the two apart is what lets this file be exhaustively tested
//! against the RFC's own vectors with no I/O at all.
//!
//! # Secret handling
//!
//! The shared secret, its base32 rendering and the `otpauth://` URI all carry the same secret, so all
//! three are [`Zeroizing`]. Nothing here logs, and [`Debug`] on [`TotpSecret`] is written by hand to
//! redact.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
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
/// 160 bits, matching HMAC-SHA1's block-independent key size and RFC 4226 §4 R6's recommendation. It
/// is also the length every authenticator's manual-entry field is sized for (32 base32 characters).
pub const SECRET_BYTES: usize = 20;

/// The name DIG asks the user to give the entry in their authenticator, so a person with several
/// codes knows which one is DIG.
pub const ISSUER: &str = "DIG Network";

/// A TOTP shared secret.
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
    /// Draw a fresh secret from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        OsRng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// Adopt raw secret bytes, e.g. after opening the vault.
    ///
    /// # Errors
    ///
    /// [`SecretError::WrongLength`] when `bytes` is not [`SECRET_BYTES`] long, so a corrupt blob is
    /// rejected rather than silently padded into a secret no authenticator agrees with.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretError> {
        let array: [u8; SECRET_BYTES] = bytes.try_into().map_err(|_| SecretError::WrongLength)?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// The raw secret, for sealing it. Deliberately crate-visible: nothing outside the vault has a
    /// reason to hold these bytes.
    pub(super) fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }

    /// The secret in RFC 4648 base32 — what a person types into an authenticator by hand.
    pub fn base32(&self) -> Zeroizing<String> {
        Zeroizing::new(base32_encode(&*self.0))
    }

    /// The base32 secret in space-separated groups of four, which is how it is meant to be READ.
    ///
    /// A 32-character unbroken string is transcribed wrongly by most people at least once; the groups
    /// exist so a person copying it onto a phone can keep their place. Authenticators ignore spaces,
    /// so the grouped form can also be typed in verbatim.
    pub fn base32_grouped(&self) -> Zeroizing<String> {
        let flat = self.base32();
        let mut out = String::with_capacity(flat.len() + flat.len() / 4);
        for (i, ch) in flat.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(ch);
        }
        Zeroizing::new(out)
    }

    /// The `otpauth://totp/...` URI an authenticator imports when it scans the enrolment QR.
    ///
    /// # What is in it, and what deliberately is not
    ///
    /// The label is the ISSUER ALONE — no account name, no DID, no profile. The user names the entry
    /// themselves, so nothing identifying this DIG Account needs to reach a phone's screen or its
    /// backup, and the enrolment flow was already written that way for the typed path.
    ///
    /// Every parameter is derived from this module's own constants rather than written as a literal.
    /// `digits=6` typed by hand next to a `CODE_DIGITS` that later became 8 is a QR that imports
    /// cleanly and then disagrees with this code forever, which is indistinguishable to the user from
    /// a broken phone.
    ///
    /// The secret is the FLAT base32, never [`base32_grouped`](Self::base32_grouped): a query parameter
    /// containing spaces is not the same URI, and an authenticator that does not strip them imports a
    /// different secret.
    ///
    /// # Secret handling
    ///
    /// The URI CONTAINS the secret in the clear, so it is [`Zeroizing`] like the secret itself. It must
    /// not be logged, written to a file, or put on the clipboard — see the module docs.
    pub fn provisioning_uri(&self) -> Zeroizing<String> {
        let issuer = percent_encode(ISSUER);
        Zeroizing::new(format!(
            "otpauth://totp/{issuer}?secret={secret}&issuer={issuer}\
             &algorithm=SHA1&digits={digits}&period={period}",
            secret = *self.base32(),
            digits = CODE_DIGITS,
            period = STEP_SECONDS,
        ))
    }

    /// The code for the step containing `unix_seconds`, zero-padded to [`CODE_DIGITS`].
    pub fn code_at(&self, unix_seconds: u64) -> Zeroizing<String> {
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

/// Compare two byte strings without an early exit on the first differing byte.
///
/// A `==` on the code would leak, through timing, how many leading digits a guess got right, which
/// turns a 10^6 search into six 10-way searches. This is the standard accumulate-the-difference
/// comparison, not a new primitive; the RustCrypto `hmac` dependency's own `verify_slice` does the
/// same thing for MAC tags, but it cannot be applied to a decimal string.
///
/// Lengths are compared first and in the clear: the length of a TOTP code is public (it is always
/// six), so nothing is learned from it.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Percent-encode `text` for use inside a URI path segment or query value (RFC 3986 §2.3).
///
/// Everything outside the unreserved set becomes `%XX`. Hand-written for the same reason
/// [`base32_encode`] is: this is an ENCODING, not a primitive, and the alternative was a dependency in
/// a binary holding master seeds in order to turn one space into `%20`.
///
/// It is deliberately CONSERVATIVE — it escapes everything it is not certain about, including
/// characters some encoders leave alone. Over-escaping is always readable by the other side; under-
/// escaping produces a URI that parses into a different string, which for a `secret=` parameter means
/// an authenticator that imports silently and never agrees with this code again.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The RFC 4648 base32 alphabet, unpadded — the encoding every authenticator's manual-entry field uses.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `bytes` as unpadded RFC 4648 base32.
///
/// Hand-written rather than pulled from a crate on purpose: base32 is an ENCODING, not a cryptographic
/// primitive, so NC-1's "never invent primitives" does not reach it, and the alternative was adding a
/// dependency to a binary that holds master seeds in order to spell out 20 bytes. It is pinned against
/// RFC 4648 §10's own test vectors below.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    // Accumulate bits in a buffer and emit a character for every whole 5 bits, which is the entire
    // algorithm; the trailing partial group is left-padded, exactly as the RFC specifies.
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
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

    /// RFC 4648 §10's base32 vectors, so the encoder is pinned to the standard rather than to itself.
    /// Two of these end on a partial group, which is where a hand-written encoder goes wrong.
    #[test]
    fn base32_matches_the_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(input.as_bytes()), expected, "input {input:?}");
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
        let mine = TotpSecret::generate();
        let theirs = TotpSecret::generate();
        let code = mine.code_at(NOW);

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

    /// A generated secret is 20 bytes and different every time — a stub returning a constant would
    /// pass every other test in this file.
    #[test]
    fn generated_secrets_are_full_length_and_distinct() {
        let a = TotpSecret::generate();
        let b = TotpSecret::generate();
        assert_eq!(a.as_bytes().len(), SECRET_BYTES);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// The grouped rendering is the same characters with spaces every four, and an authenticator that
    /// strips spaces gets the identical secret back.
    #[test]
    fn the_grouped_secret_is_the_flat_secret_with_spaces() {
        let secret = rfc_secret();
        let grouped = secret.base32_grouped();

        assert_eq!(
            grouped.replace(' ', ""),
            *secret.base32(),
            "grouping must not change the secret"
        );
        assert!(grouped.contains(' '), "it must actually be grouped");
    }

    /// The URI's `secret=` parameter, decoded back to bytes with a base32 DECODER written for this test
    /// alone.
    ///
    /// Deliberately not `base32_encode` run forwards: comparing the URI against the same encoder that
    /// built it proves only that the function is self-consistent, which it would also be if it were
    /// encoding the wrong twenty bytes. Going the other way — URI text back to a secret, and then
    /// asking whether that secret mints THE SAME CODES — is the only check that fails when the URI
    /// carries something other than this secret.
    fn secret_parsed_out_of(uri: &str) -> TotpSecret {
        let value = uri
            .split("secret=")
            .nth(1)
            .expect("the URI carries a secret")
            .split('&')
            .next()
            .expect("the parameter ends");
        let mut bytes = Vec::new();
        let (mut buffer, mut bits) = (0u16, 0u32);
        for ch in value.chars() {
            let index = BASE32_ALPHABET
                .iter()
                .position(|c| *c as char == ch)
                .unwrap_or_else(|| panic!("{ch:?} is not in the base32 alphabet"));
            buffer = (buffer << 5) | index as u16;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes.push((buffer >> bits) as u8);
            }
        }
        TotpSecret::from_bytes(&bytes).expect("the URI's secret is 20 bytes")
    }

    /// The URI carries THIS secret — proved by minting codes from the secret parsed back out of it and
    /// checking they are the codes this secret accepts, at several instants.
    ///
    /// A phone imports the URI and nothing else, so this is the only property that decides whether
    /// enrolment works: a URI that is well-formed but carries a different, a truncated, or a
    /// space-separated secret produces an authenticator that looks correctly set up and whose every
    /// code is refused.
    #[test]
    fn the_uri_carries_the_same_secret_this_object_holds() {
        let secret = TotpSecret::generate();
        let imported = secret_parsed_out_of(&secret.provisioning_uri());

        for now in [1_700_000_000u64, 1_700_000_031, 2_000_000_000] {
            let code = imported.code_at(now);
            assert!(
                secret.matching_step(&code, now).is_some(),
                "a code minted from the URI's secret must be accepted at t={now}"
            );
        }
    }

    /// A secret imported the way a PHONE imports one — read out of a provisioning URI — produces codes
    /// this crate accepts, checked against values computed by a different implementation entirely.
    ///
    /// The expected codes were produced by Python's `hmac`/`hashlib` from the URI decoded off a
    /// PHOTOGRAPH of the rendered enrolment window (dig_ecosystem#1849), not by this crate. That is the
    /// point: every other test here compares this code against itself, and a wrong dynamic truncation
    /// or a wrong counter endianness is perfectly self-consistent. Pinning the numbers a foreign
    /// implementation produced is what makes the round trip — pixels, to URI, to secret, to a code the
    /// app accepts — a claim rather than an assertion about our own arithmetic.
    ///
    /// The secret is `JBSWY3DPEHPK3PXP` twice, a published example value; nothing here is a live
    /// credential.
    #[test]
    fn a_secret_imported_from_a_scanned_uri_produces_the_codes_a_phone_would() {
        const SCANNED: &str = "otpauth://totp/DIG%20Network?secret=JBSWY3DPEHPK3PXPJBSWY3DP\
                               EHPK3PXP&issuer=DIG%20Network&algorithm=SHA1&digits=6&period=30";
        let imported = secret_parsed_out_of(SCANNED);

        for (at, expected) in [
            (59u64, "503347"),
            (1_111_111_109, "088309"),
            (1_700_000_000, "406058"),
        ] {
            assert_eq!(&*imported.code_at(at), expected, "at t={at}");
            assert!(
                imported.matching_step(expected, at).is_some(),
                "the app must ACCEPT the code its own scanned secret mints, at t={at}"
            );
        }
    }

    /// The URI's parameters come from this module's constants, and the label carries no account.
    ///
    /// The digits and period are asserted against `CODE_DIGITS`/`STEP_SECONDS` rather than against `6`
    /// and `30`, so changing either constant without changing the URI fails here instead of in a user's
    /// authenticator. The scheme and the encoded issuer are pinned because a raw space in the label is
    /// a URI most scanners reject outright.
    #[test]
    fn the_uri_states_this_modules_parameters_and_names_no_account() {
        let uri = rfc_secret().provisioning_uri();

        assert!(uri.starts_with("otpauth://totp/"), "{}", uri.as_str());
        assert!(uri.contains("issuer=DIG%20Network"), "{}", uri.as_str());
        assert!(
            !uri.contains("DIG Network"),
            "a raw space is not percent-encoded: {}",
            uri.as_str()
        );
        assert!(
            uri.contains(&format!("digits={CODE_DIGITS}")),
            "{}",
            uri.as_str()
        );
        assert!(
            uri.contains(&format!("period={STEP_SECONDS}")),
            "{}",
            uri.as_str()
        );
        assert!(uri.contains("algorithm=SHA1"), "{}", uri.as_str());
        // The label is the issuer and nothing else — no `Issuer:account` pair — so no DIG identifier
        // reaches the phone's screen or its cloud backup.
        let label = uri
            .trim_start_matches("otpauth://totp/")
            .split('?')
            .next()
            .expect("a label");
        assert_eq!(label, "DIG%20Network");
    }

    /// The secret in the URI is the FLAT base32, never the space-grouped human rendering.
    ///
    /// The grouped form is the nearest wrong implementation — it is the one already on screen, and
    /// substituting it produces a URI that still parses, still names the right issuer, and imports a
    /// secret truncated at the first space.
    #[test]
    fn the_uri_carries_the_flat_secret_not_the_grouped_one() {
        let secret = rfc_secret();
        let uri = secret.provisioning_uri();

        assert!(uri.contains(&*secret.base32()), "{}", uri.as_str());
        assert!(
            !uri.contains(' ') && !uri.contains("%20&") && !uri.contains("secret=%20"),
            "the secret parameter must not be grouped: {}",
            uri.as_str()
        );
    }

    /// The conservative percent-encoder, against RFC 3986's unreserved set and the characters an issuer
    /// or a query value could plausibly carry. Reserved and non-ASCII bytes both escape; the unreserved
    /// set passes through untouched, because escaping THOSE would also be wrong.
    #[test]
    fn percent_encoding_escapes_everything_outside_the_unreserved_set() {
        assert_eq!(percent_encode("DIG Network"), "DIG%20Network");
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(percent_encode("a&b=c?d/e#f"), "a%26b%3Dc%3Fd%2Fe%23f");
        // Multi-byte UTF-8 escapes per BYTE, which is what RFC 3986 §2.5 requires.
        assert_eq!(percent_encode("é"), "%C3%A9");
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
        assert!(!rendered.contains(&*secret.base32()));
    }
}
