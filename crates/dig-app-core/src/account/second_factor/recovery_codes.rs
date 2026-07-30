//! The **recovery codes** — the way back in when the phone is gone (dig_ecosystem#1840).
//!
//! # Why these matter more than the codes themselves
//!
//! This app's entire custody story is that loss is permanent: nobody, including DIG, can restore an
//! account. Adding a second factor whose device can be dropped in a river therefore adds a brand-new
//! way to lose an account for good — unless the user is handed something that works without the phone.
//! That is what this module is. It is the single most important safety property of the whole feature,
//! which is why the enrolment flow refuses to complete without the user CLAIMING they saved these.
//!
//! # Why only the hashes are stored
//!
//! The vault seals its blob, so plaintext codes would already be at rest under AEAD. Storing salted
//! SHA-256 digests instead buys two further things, both of which change behaviour rather than merely
//! sounding prudent:
//!
//! - **The app cannot re-display them.** "Shown once" becomes a property of the data rather than a
//!   promise made by the UI, so no future screen can leak them by accident.
//! - **A code that has been used is gone.** Each digest is consumed on use, so a code read off a
//!   screenshot after the fact is worth nothing once it has been spent.
//!
//! The salt is per-code and random. It is not defending a low-entropy password — a code carries ~50
//! bits — but it makes the digests of two accounts that happened to draw the same code differ, so the
//! stored form never reveals a collision.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How many codes are issued at enrolment.
///
/// Ten is the industry convention (GitHub, Google, AWS all issue ten), and the reasoning holds here:
/// enough that spending a few over the years does not force a re-enrolment, few enough to fit on one
/// piece of paper a person will actually keep.
pub const CODE_COUNT: usize = 10;

/// Characters per code, excluding the separating dash.
///
/// Ten characters over the 32-symbol alphabet below is ~50 bits — far beyond guessing, and short
/// enough to transcribe by hand without error.
const CODE_CHARS: usize = 10;

/// Where the dash goes, purely so a human can read the code back.
const GROUP: usize = 5;

/// How many codes are printed on one line. See [`RecoveryCodeSet::printable`] for why this is not one.
const PER_LINE: usize = 2;

/// The alphabet, chosen for TRANSCRIPTION rather than density.
///
/// Crockford's base32 set: no `I`, `L`, `O` or `U`. The first three are indistinguishable from `1` and
/// `0` in most fonts on a printed page, which is exactly the medium these are meant to live on, and
/// `U` is dropped so a random draw cannot spell something unfortunate.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The per-code salt length. 16 bytes is the usual floor for a random salt.
const SALT_BYTES: usize = 16;

/// A freshly-minted set of recovery codes, in plaintext — the ONLY moment they exist in this form.
///
/// Kept in [`Zeroizing`] buffers and never persisted: [`RecoveryCodeSet::to_stored`] converts them to
/// digests, and this value is dropped once the enrolment window has shown them.
pub struct RecoveryCodeSet(Vec<Zeroizing<String>>);

impl std::fmt::Debug for RecoveryCodeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryCodeSet(<{} redacted codes>)", self.0.len())
    }
}

impl RecoveryCodeSet {
    /// Draw [`CODE_COUNT`] fresh codes from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(
            (0..CODE_COUNT)
                .map(|_| Zeroizing::new(draw_code()))
                .collect(),
        )
    }

    /// The codes as the user must see them: [`PER_LINE`] to a line, so the block can be written down
    /// or printed.
    ///
    /// Two per line rather than one is a LAYOUT constraint, not a style choice: the native window's
    /// `STATIC` control does not scroll and silently clips text past the height reserved for it, so ten
    /// separate lines plus the surrounding warning overflows the window that is drawing them — and a
    /// clipped recovery code is one the user never gets. Pairing them halves the block.
    pub fn printable(&self) -> Zeroizing<String> {
        let mut out = String::new();
        for pair in self.0.chunks(PER_LINE) {
            let line: Vec<&str> = pair.iter().map(|code| code.as_str()).collect();
            out.push_str(&line.join("    "));
            out.push('\n');
        }
        Zeroizing::new(out)
    }

    /// The stored (salted, digested, unspent) form. This is what the vault persists.
    pub fn to_stored(&self) -> Vec<StoredRecoveryCode> {
        self.0
            .iter()
            .map(|code| StoredRecoveryCode::of(code))
            .collect()
    }

    /// How many codes are in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty. Present because clippy asks for it beside `len`; a generated set never
    /// is.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// One code, for tests that must present a code the user was given.
    #[cfg(test)]
    pub(super) fn code(&self, index: usize) -> &str {
        &self.0[index]
    }
}

/// One recovery code as it is kept at rest: a random salt, the digest, and whether it has been spent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredRecoveryCode {
    /// The per-code salt, hex-encoded so the record is plain JSON.
    salt: String,
    /// `SHA-256(salt || normalized code)`, hex-encoded.
    digest: String,
    /// Whether this code has already been used. A spent code is kept rather than deleted so the UI can
    /// report how many remain out of how many were issued.
    used: bool,
}

impl StoredRecoveryCode {
    /// Salt and digest one plaintext code.
    fn of(code: &str) -> Self {
        let salt = random_salt();
        Self {
            digest: digest_of(&salt, code),
            salt: hex::encode(salt),
            used: false,
        }
    }

    /// Whether this code is unspent AND matches `candidate`.
    fn matches(&self, candidate: &str) -> bool {
        if self.used {
            return false;
        }
        let Ok(salt) = hex::decode(&self.salt) else {
            // A record whose salt is not hex cannot be checked, so it can never match. Failing closed
            // here rather than panicking keeps one damaged entry from taking the whole vault down.
            return false;
        };
        // Both sides are hex digests of the same length, so a plain comparison leaks nothing an
        // attacker does not already control; the SECRET side is the candidate they typed.
        digest_of(&salt, candidate) == self.digest
    }

    /// Whether this code has been spent.
    pub fn is_used(&self) -> bool {
        self.used
    }
}

/// Spend the first unspent code matching `candidate`, reporting whether one was found.
///
/// Lives here rather than on the vault so the "one code, once" rule is expressed where the codes are,
/// and is testable with no I/O.
pub(super) fn spend(codes: &mut [StoredRecoveryCode], candidate: &str) -> bool {
    let normalized = normalize(candidate);
    match codes.iter_mut().find(|code| code.matches(&normalized)) {
        Some(code) => {
            code.used = true;
            true
        }
        None => false,
    }
}

/// How many of `codes` are still unspent.
pub(super) fn remaining(codes: &[StoredRecoveryCode]) -> usize {
    codes.iter().filter(|code| !code.used).count()
}

/// Draw a fresh random salt from the OS CSPRNG.
///
/// Written as a per-byte draw rather than the usual `let mut salt = [0u8; N]; OsRng.fill_bytes(&mut
/// salt);` because that idiom's zero-initialiser is, to a static analyser, indistinguishable from a
/// hard-coded salt — CodeQL's `rust/hard-coded-cryptographic-value` reports it as a critical finding.
/// Here every byte provably originates in the CSPRNG and no literal ever reaches the salt, so the
/// property is structural rather than something a reviewer has to trace. Proven by
/// `two_codes_never_share_a_salt`.
fn random_salt() -> [u8; SALT_BYTES] {
    // Truncating each draw to its low byte is uniform: `next_u32` is uniform over its whole range and
    // 2^32 is an exact multiple of 2^8, so no value is favoured.
    std::array::from_fn(|_| OsRng.next_u32() as u8)
}

/// `SHA-256(salt || normalized code)`, hex-encoded.
fn digest_of(salt: &[u8], code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(normalize(code).as_bytes());
    hex::encode(hasher.finalize())
}

/// Reduce a typed code to its canonical form: upper-case, with every non-alphanumeric character
/// dropped.
///
/// People retype these from paper, so the dash, stray spaces and lower case must not matter. Dropping
/// separators rather than requiring them is what lets `abcde-fghjk`, `ABCDE FGHJK` and `ABCDEFGHJK`
/// all be the same code.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Draw one code, dashed for readability.
///
/// The alphabet is a power of two in size, so masking the low five bits of a random byte is uniform —
/// there is deliberately no modulo, which would bias the draw toward the start of the alphabet.
fn draw_code() -> String {
    let mut bytes = Zeroizing::new([0u8; CODE_CHARS]);
    OsRng.fill_bytes(&mut *bytes);
    let mut out = String::with_capacity(CODE_CHARS + 1);
    for (i, byte) in bytes.iter().enumerate() {
        if i == GROUP {
            out.push('-');
        }
        out.push(ALPHABET[(byte & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A code the user was given opens the account, and is then spent — the second presentation of the
    /// SAME code must fail. Two attempts with one code is the whole single-use property, and a test
    /// that only tried once would pass for a set that never marked anything used.
    #[test]
    fn a_recovery_code_works_once_and_only_once() {
        let set = RecoveryCodeSet::generate();
        let mut stored = set.to_stored();
        let code = set.code(3).to_string();

        assert!(spend(&mut stored, &code), "the first use is accepted");
        assert!(
            !spend(&mut stored, &code),
            "the same code must not work twice"
        );
        assert_eq!(remaining(&stored), CODE_COUNT - 1);
    }

    /// Spending one code must not spend or invalidate the others — otherwise "you have ten" would be a
    /// lie the first time one was used. Requires a SECOND code as a control; a one-code fixture cannot
    /// see this.
    #[test]
    fn spending_one_code_leaves_the_others_usable() {
        let set = RecoveryCodeSet::generate();
        let mut stored = set.to_stored();

        assert!(spend(&mut stored, set.code(0)));
        assert!(
            spend(&mut stored, set.code(1)),
            "a different code still works"
        );
        assert!(spend(&mut stored, set.code(9)), "and so does the last one");
        assert_eq!(remaining(&stored), CODE_COUNT - 3);
    }

    /// Transcription tolerance: the dash, the case and stray spaces must not matter, because these are
    /// copied off paper by hand.
    #[test]
    fn a_code_is_accepted_however_it_was_transcribed() {
        let set = RecoveryCodeSet::generate();
        let canonical = set.code(0).to_string();

        for typed in [
            canonical.to_lowercase(),
            canonical.replace('-', ""),
            canonical.replace('-', " "),
            format!("  {canonical}  "),
        ] {
            let mut stored = set.to_stored();
            assert!(spend(&mut stored, &typed), "typed as {typed:?}");
        }
    }

    /// A code from a DIFFERENT enrolment must not be accepted. Without a second set this test could not
    /// distinguish "checks the digest" from "accepts anything code-shaped".
    #[test]
    fn another_accounts_code_is_refused() {
        let mine = RecoveryCodeSet::generate();
        let theirs = RecoveryCodeSet::generate();
        let mut stored = mine.to_stored();

        assert!(!spend(&mut stored, theirs.code(0)));
        assert_eq!(remaining(&stored), CODE_COUNT, "nothing was spent");
    }

    /// The at-rest form must not contain the code. A round-trip test alone would pass for a store that
    /// kept plaintext.
    #[test]
    fn the_stored_form_contains_no_plaintext_code() {
        let set = RecoveryCodeSet::generate();
        let stored = set.to_stored();
        let json = serde_json::to_string(&stored).unwrap();

        for i in 0..set.len() {
            let code = normalize(set.code(i));
            assert!(
                !json.contains(&code),
                "code {i} is recoverable from the record"
            );
        }
    }

    /// The printable block must carry EVERY code and fit the window that draws it.
    ///
    /// Both halves matter together: pairing the codes to save vertical space is worthless if a code is
    /// dropped in the process, and a test that only counted lines could not tell the two apart.
    #[test]
    fn the_printable_block_carries_every_code_in_half_the_lines() {
        let set = RecoveryCodeSet::generate();
        let printed = set.printable();
        let lines: Vec<&str> = printed.trim_end().lines().collect();

        assert_eq!(lines.len(), CODE_COUNT / PER_LINE, "two codes to a line");
        for i in 0..set.len() {
            assert!(
                printed.contains(set.code(i)),
                "code {i} is missing from the block the user is shown"
            );
        }
    }

    /// Every code gets its OWN random salt.
    ///
    /// Two assertions, and both are needed: a constant salt would round-trip perfectly through every
    /// other test in this file, and a salt of the right LENGTH could still be all zeroes if the CSPRNG
    /// draw were dropped — which is exactly the shape a static analyser worries about.
    #[test]
    fn two_codes_never_share_a_salt() {
        let stored = RecoveryCodeSet::generate().to_stored();
        let salts: HashSet<&str> = stored.iter().map(|code| code.salt.as_str()).collect();

        assert_eq!(salts.len(), CODE_COUNT, "each code carries its own salt");
        for salt in salts {
            assert_eq!(salt.len(), SALT_BYTES * 2, "hex of {SALT_BYTES} bytes");
            assert_ne!(
                salt,
                "0".repeat(SALT_BYTES * 2),
                "a salt that was never drawn"
            );
        }
    }

    /// Codes must be distinct and full length — a generator returning a constant, or one biased into a
    /// tiny space, would satisfy every other test here.
    #[test]
    fn codes_are_distinct_and_full_length() {
        let set = RecoveryCodeSet::generate();
        let codes: HashSet<String> = (0..set.len()).map(|i| set.code(i).to_string()).collect();

        assert_eq!(codes.len(), CODE_COUNT, "all ten codes differ");
        for code in &codes {
            assert_eq!(normalize(code).len(), CODE_CHARS);
            assert!(code.contains('-'), "dashed for transcription");
        }
    }

    /// The alphabet must exclude the characters that are misread off paper — the reason the set is
    /// Crockford's rather than plain base32.
    #[test]
    fn the_alphabet_omits_the_characters_that_are_misread() {
        let alphabet = std::str::from_utf8(ALPHABET).unwrap();
        for ambiguous in ['I', 'L', 'O', 'U'] {
            assert!(
                !alphabet.contains(ambiguous),
                "{ambiguous} is misread on paper"
            );
        }
        assert_eq!(
            alphabet.len(),
            32,
            "a power of two, so the draw is unbiased"
        );
    }

    /// An empty or junk entry must never be accepted — normalization strips separators, so an all-dash
    /// string reduces to the empty string, and an empty candidate must not match anything.
    #[test]
    fn empty_and_junk_input_is_refused() {
        let set = RecoveryCodeSet::generate();
        let mut stored = set.to_stored();

        for junk in ["", "-----", "not a code", "0000000000"] {
            assert!(!spend(&mut stored, junk), "input {junk:?}");
        }
        assert_eq!(remaining(&stored), CODE_COUNT);
    }

    /// The redacting `Debug` — a derived one would print every recovery code.
    #[test]
    fn debug_never_prints_the_codes() {
        let set = RecoveryCodeSet::generate();
        let rendered = format!("{set:?}");
        assert_eq!(rendered, "RecoveryCodeSet(<10 redacted codes>)");
        assert!(!rendered.contains(set.code(0)));
    }
}
