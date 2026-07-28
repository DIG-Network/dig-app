//! The BIP-39 **recovery phrase** — the one portable root of an account (#1500, dig_ecosystem#1752).
//!
//! # Why this exists
//!
//! Before this module an account's master seed came straight from the OS CSPRNG and was sealed under a
//! machine-generated password held in the OS credential store. That blob is decryptable on exactly one
//! machine, and nothing about it is writable down — so losing the machine lost the account, its DID, its
//! address and every per-profile DEK. The #1500 decision ratified the **derived** model instead: ONE
//! BIP-39 master seed per account, from which every profile's identity, wallet key and DEK derive at its
//! [`ProfileIx`](dig_account::ProfileIx). One 24-word phrase therefore recovers *everything*.
//!
//! # The entropy IS the master seed (a deliberate, load-bearing choice)
//!
//! [`dig_session::SEED_LEN`] is 32, and a 24-word BIP-39 phrase carries **exactly 32 bytes** of
//! entropy. This module therefore maps a phrase to a master seed by taking its entropy verbatim, which
//! makes phrase ⇄ seed a *lossless bijection*: [`RecoveryPhrase::master_seed`] and
//! [`RecoveryPhrase::from_master_seed`] round-trip byte-identically, so a restore reaches the same
//! identity with no stored state at all.
//!
//! The consequence, stated plainly because it is a real trade-off: this is **not** the standard Chia
//! mnemonic derivation. A Chia wallet (Sage, chia-blockchain) maps a phrase to a key through the
//! 64-byte PBKDF2 seed of BIP-39 §5, so the SAME phrase yields a DIFFERENT wallet address in Sage than
//! it does here. Adopting the Chia path would require widening `SEED_LEN` to 64 in `dig-session` (a
//! `10-primitives` crate), cascading through `dig-account` and `dig-wallet-backend`, and would break
//! at-rest compatibility for every already-enrolled account — a cross-crate breaking change tracked
//! separately, not something to fork custody over here.
//!
//! # Handling rules (security-critical)
//!
//! A [`RecoveryPhrase`] is the account. It therefore:
//!
//! - holds its words in a [`Zeroizing`] buffer and wipes them on drop;
//! - redacts its [`Debug`] rendering, so no `{:?}` anywhere can leak it;
//! - implements no `Display`, `Serialize`, or `Clone` — it cannot be formatted into a log line, written
//!   to disk, or duplicated by accident. The ONLY way to read the words is
//!   [`words`](RecoveryPhrase::words), which callers use to draw them on screen and nothing else.

use std::fmt;

use bip39::{Language, Mnemonic};
use dig_session::SEED_LEN;
use zeroize::Zeroizing;

/// The number of words in a DIG recovery phrase. 24 words is the 256-bit BIP-39 strength, and its
/// 32-byte entropy is exactly [`SEED_LEN`] — see the module docs for why that identity matters.
pub const PHRASE_WORDS: usize = 24;

/// Why a recovery phrase could not be accepted.
///
/// Deliberately coarse: a phrase is either usable or it is not, and a more granular error (which word,
/// which position) would be an oracle over secret material. The messages are user-facing copy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// The phrase did not have exactly [`PHRASE_WORDS`] words.
    #[error("a DIG recovery phrase is {PHRASE_WORDS} words; this one has {found}")]
    WrongLength {
        /// How many whitespace-separated words were supplied.
        found: usize,
    },
    /// The words are not a valid BIP-39 phrase — an unknown word, or a failed checksum (usually a typo
    /// or two words swapped).
    #[error("that is not a valid recovery phrase — check for a mistyped or out-of-order word")]
    Invalid,
}

/// A 24-word BIP-39 recovery phrase: the portable custody root of one account.
///
/// Obtain one by [`generate`](RecoveryPhrase::generate) (first-run enrolment, where it MUST be shown to
/// the user once and its retention confirmed before enrolling) or [`parse`](RecoveryPhrase::parse)
/// (restoring an account on a new machine). See the module docs for the handling rules this type
/// enforces.
pub struct RecoveryPhrase {
    /// The space-joined words, zeroized on drop. Stored as the canonical string form because that is
    /// what both consumers need — rendering and re-deriving entropy — and keeping ONE representation
    /// means there is only one buffer to wipe.
    words: Zeroizing<String>,
}

impl RecoveryPhrase {
    /// Draw a fresh 24-word phrase from the OS CSPRNG.
    ///
    /// This is the only place an account's custody root is created. The caller MUST display the words
    /// and confirm the user has retained them before enrolling — see
    /// [`PhrasePresenter`](crate::account::lifecycle::PhrasePresenter).
    ///
    /// # Panics
    ///
    /// Never in practice: the only failure mode of the underlying generator is an unsupported word
    /// count, and [`PHRASE_WORDS`] is a valid BIP-39 length.
    pub fn generate() -> Self {
        let mnemonic = Mnemonic::generate_in(Language::English, PHRASE_WORDS)
            .expect("24 is a valid BIP-39 word count");
        Self::from_mnemonic(&mnemonic)
    }

    /// Parse a user-supplied phrase, normalizing whitespace and case.
    ///
    /// Accepts any run of whitespace between words and any capitalization, because a person reading
    /// words off paper should not fail on formatting. The BIP-39 checksum still has to hold.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::WrongLength`] if the phrase is not [`PHRASE_WORDS`] words;
    /// [`RecoveryError::Invalid`] if a word is unknown or the checksum fails.
    pub fn parse(input: &str) -> Result<Self, RecoveryError> {
        let normalized = Zeroizing::new(
            input
                .split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" "),
        );
        let found = normalized.split_whitespace().count();
        if found != PHRASE_WORDS {
            return Err(RecoveryError::WrongLength { found });
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|_| RecoveryError::Invalid)?;
        Ok(Self::from_mnemonic(&mnemonic))
    }

    /// Re-render the phrase for a master seed — the inverse of [`master_seed`](Self::master_seed).
    ///
    /// Used to show the phrase for an account whose seed is already enrolled (the tray's "show my
    /// recovery phrase" path), which is possible precisely because the entropy↔seed mapping is a
    /// bijection. An account enrolled before this module existed has a CSPRNG seed that was never a
    /// phrase; rendering its 32 bytes as words here still yields a phrase that restores that exact
    /// seed, so the mapping is honest for those accounts too.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is a valid BIP-39 entropy length.
    pub fn from_master_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, seed)
            .expect("32 bytes is a valid BIP-39 entropy length");
        Self::from_mnemonic(&mnemonic)
    }

    /// The 32-byte account master seed this phrase encodes — the value handed to
    /// [`AccountSession::enroll`](dig_account::AccountSession::enroll).
    ///
    /// # Panics
    ///
    /// Never: every `RecoveryPhrase` is [`PHRASE_WORDS`] words by construction, whose entropy is
    /// exactly [`SEED_LEN`] bytes.
    pub fn master_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.words)
            .expect("a RecoveryPhrase is valid BIP-39 by construction");
        let (entropy, len) = mnemonic.to_entropy_array();
        debug_assert_eq!(len, SEED_LEN, "24 words carry exactly SEED_LEN bytes");
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(&entropy[..SEED_LEN]);
        seed
    }

    /// The words, in order, for drawing on screen. The ONLY read path — see the module handling rules.
    pub fn words(&self) -> Vec<&str> {
        self.words.split(' ').collect()
    }

    /// The words as numbered lines (`" 1. abandon"`), the form the display-once window renders.
    ///
    /// Numbering matters: a person copying 24 words needs to know they got 24 of them in order, and
    /// numbered lines are what every wallet that has learned this lesson shows.
    pub fn numbered_lines(&self) -> Zeroizing<String> {
        let mut out = String::new();
        for (i, word) in self.words().iter().enumerate() {
            out.push_str(&format!("{:>2}. {word}\n", i + 1));
        }
        Zeroizing::new(out)
    }

    /// Wrap a validated mnemonic. Private so every `RecoveryPhrase` is valid by construction.
    fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        Self {
            words: Zeroizing::new(mnemonic.to_string()),
        }
    }
}

/// Redacted: a `{:?}` of the custody root must never print it (the `never_log` regression suite
/// asserts this holds for every emitted record).
impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<redacted 24 words>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that makes recovery work at all, asserted on the ROUND TRIP rather than on either
    /// half: a generated phrase's seed, re-rendered as words, is the same phrase — and re-parsing those
    /// words reaches the same seed. A one-directional check would pass for a mapping that silently
    /// truncated or padded.
    #[test]
    fn a_generated_phrase_round_trips_through_its_master_seed() {
        let generated = RecoveryPhrase::generate();
        let seed = generated.master_seed();

        let rendered = RecoveryPhrase::from_master_seed(&seed);
        assert_eq!(
            rendered.words(),
            generated.words(),
            "the seed must re-render as the identical phrase"
        );
        assert_eq!(
            &*RecoveryPhrase::parse(&rendered.words().join(" "))
                .expect("a rendered phrase re-parses")
                .master_seed(),
            &*seed,
            "re-parsing the words must reach the identical master seed"
        );
    }

    /// Two generated phrases must differ — the fixture that distinguishes a real CSPRNG draw from a
    /// constant, which the round-trip test above would happily accept.
    #[test]
    fn two_generated_phrases_differ() {
        assert_ne!(
            RecoveryPhrase::generate().words(),
            RecoveryPhrase::generate().words(),
            "each account must get its own custody root"
        );
    }

    #[test]
    fn a_generated_phrase_has_exactly_24_words() {
        assert_eq!(RecoveryPhrase::generate().words().len(), PHRASE_WORDS);
    }

    /// A person reading words off paper types them however they like; only the checksum is sacred.
    #[test]
    fn parsing_normalizes_case_and_whitespace() {
        let phrase = RecoveryPhrase::generate();
        let canonical = phrase.words().join(" ");
        let messy = format!("  {}  ", canonical.to_uppercase().replace(' ', "\n  "));

        assert_eq!(
            &*RecoveryPhrase::parse(&messy).expect("messy input parses").master_seed(),
            &*phrase.master_seed(),
            "case + whitespace must not change the seed"
        );
    }

    #[test]
    fn a_short_phrase_is_rejected_by_length() {
        let err = RecoveryPhrase::parse("abandon abandon abandon").unwrap_err();
        assert_eq!(err, RecoveryError::WrongLength { found: 3 });
    }

    /// A 24-word phrase with a valid word list but a BROKEN CHECKSUM must fail. The fixture is a real
    /// generated phrase with its LAST word swapped for a different valid word — the nearest wrong
    /// input to a correct phrase, and the one a length check or a wordlist check alone would accept.
    #[test]
    fn a_valid_length_phrase_with_a_bad_checksum_is_rejected() {
        let phrase = RecoveryPhrase::generate();
        let mut words: Vec<String> = phrase.words().iter().map(|w| w.to_string()).collect();
        // Every checksum-preserving alternative for the last word is astronomically unlikely to be the
        // one we pick, and "abandon"/"zoo" are both real wordlist entries, so this stays a wordlist-
        // valid phrase whose checksum is wrong.
        let last = words.len() - 1;
        words[last] = if words[last] == "zoo" { "abandon" } else { "zoo" }.to_string();

        assert_eq!(
            RecoveryPhrase::parse(&words.join(" ")).unwrap_err(),
            RecoveryError::Invalid,
            "a checksum failure must be rejected, not silently accepted as a different seed"
        );
    }

    #[test]
    fn an_unknown_word_is_rejected() {
        let phrase = RecoveryPhrase::generate();
        let mut words: Vec<String> = phrase.words().iter().map(|w| w.to_string()).collect();
        words[0] = "notabip39word".to_string();

        assert_eq!(
            RecoveryPhrase::parse(&words.join(" ")).unwrap_err(),
            RecoveryError::Invalid
        );
    }

    /// The display form is what the user copies, so it must carry all 24 words, numbered.
    #[test]
    fn numbered_lines_carry_every_word_in_order() {
        let phrase = RecoveryPhrase::generate();
        let rendered = phrase.numbered_lines();
        let lines: Vec<&str> = rendered.trim_end().lines().collect();

        assert_eq!(lines.len(), PHRASE_WORDS);
        for (i, (line, word)) in lines.iter().zip(phrase.words()).enumerate() {
            assert_eq!(line.trim(), format!("{}. {word}", i + 1));
        }
    }

    /// The custody root must not be printable by accident — the whole reason `Debug` is hand-written.
    #[test]
    fn debug_redacts_the_words() {
        let phrase = RecoveryPhrase::generate();
        let rendered = format!("{phrase:?}");
        for word in phrase.words() {
            assert!(
                !rendered.contains(word),
                "Debug leaked the word {word:?}: {rendered}"
            );
        }
        assert!(rendered.contains("redacted"));
    }

    /// An account enrolled BEFORE this module existed has a raw CSPRNG seed. Rendering it as words must
    /// still restore that exact seed — otherwise the migration path would hand a legacy user a phrase
    /// that silently recovers a different account.
    #[test]
    fn a_legacy_csprng_seed_renders_as_a_phrase_that_restores_it() {
        // A fixed, non-uniform pattern (not all-zero, not all-same) so a byte-order or padding bug in
        // the entropy mapping shows up as a mismatch rather than hiding behind a symmetric value.
        let legacy: [u8; SEED_LEN] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));

        let phrase = RecoveryPhrase::from_master_seed(&legacy);
        assert_eq!(
            &*phrase.master_seed(),
            &legacy,
            "a legacy seed's rendered phrase must restore the identical seed"
        );
    }
}
