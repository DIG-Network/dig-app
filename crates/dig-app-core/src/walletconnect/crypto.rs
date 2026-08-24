//! The WalletConnect v2 envelope: what a relay actually carries, and the key exchange that produces
//! the session it is sealed under.
//!
//! Every byte on a WalletConnect relay is an envelope. The relay is an untrusted intermediary — it
//! sees topics and ciphertext and nothing else — so this module is what makes that true, and any
//! looseness here is looseness in the only thing standing between a dapp session and the relay
//! operator.
//!
//! # The two envelope shapes
//!
//! | type | layout (before base64) | used for |
//! |---|---|---|
//! | `0` | `00 ‖ iv[12] ‖ sealed` | everything on an ESTABLISHED topic, under a known symmetric key |
//! | `1` | `01 ‖ senderPublicKey[32] ‖ iv[12] ‖ sealed` | the session-propose RESPONSE, which must carry the wallet's X25519 public key because the dapp cannot yet derive the session key without it |
//!
//! `sealed` is ChaCha20-Poly1305 over the plaintext with the 12-byte `iv` as nonce. Base64 is
//! STANDARD alphabet with padding, which is what `@walletconnect/utils` emits — URL-safe base64 is a
//! different string and the relay is byte-exact about it.
//!
//! # No hand-rolled crypto
//!
//! Every primitive is RustCrypto (`chacha20poly1305`, `hkdf`, `sha2`) or `x25519-dalek`, all already
//! in this workspace for the DIGCHAT1 seal. Nothing here invents a construction; this module only
//! frames the pieces in the order WalletConnect specifies.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Bytes in a symmetric key, an X25519 public key, and a topic. All 32, all sha256-shaped.
pub const KEY_LEN: usize = 32;

/// Bytes in the ChaCha20-Poly1305 nonce WalletConnect calls the `iv`.
///
/// Twelve, which is ChaCha20-Poly1305's native nonce width — NOT the 24-byte extended nonce of
/// XChaCha20. Using the extended form here would produce envelopes no other WalletConnect
/// implementation can open, so the width is pinned by a test rather than left to the type.
pub const IV_LEN: usize = 12;

/// The envelope type byte for a sealed message under an already-shared key.
const ENVELOPE_TYPE_0: u8 = 0;

/// The envelope type byte for a sealed message that also carries the sender's X25519 public key.
const ENVELOPE_TYPE_1: u8 = 1;

/// Why an envelope could not be opened.
///
/// Deliberately coarse where an attacker is watching: a wrong key and a tampered body both yield
/// [`Undecryptable`](Self::Undecryptable), because distinguishing them tells a prober whether they
/// have guessed the key. The structural variants are safe to distinguish — they describe bytes that
/// never authenticated under anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The payload was not valid standard base64.
    NotBase64,
    /// The decoded bytes are shorter than the header the type byte promises.
    TooShort,
    /// A type byte this wallet does not implement.
    UnknownType(u8),
    /// The AEAD did not authenticate: a wrong key, a tampered body, or a re-addressed envelope.
    /// Which one is deliberately not distinguished.
    Undecryptable,
    /// It decrypted, and what came out was not UTF-8. Structurally impossible from a conforming
    /// peer, so it is reported rather than lossily repaired.
    NotUtf8,
}

/// An opened envelope: the plaintext, plus the sender's key when the envelope carried one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The JSON-RPC frame that was sealed.
    pub plaintext: String,
    /// The sender's X25519 public key, present only for a type-1 envelope.
    ///
    /// # This value is NOT authenticated. Do not derive a key from it.
    ///
    /// WalletConnect seals the body with an EMPTY AAD, so the envelope header — the type byte, this
    /// key, and the nonce — is outside the AEAD's protection. Anyone who can write to the topic can
    /// substitute a different key here and the body still decrypts perfectly, because the body was
    /// never sealed to it.
    ///
    /// The safe source for a peer's public key is the one inside the DECRYPTED plaintext, which the
    /// AEAD does cover — and that is where [`super::client::parse_propose`] reads the proposer's key
    /// from. This field is surfaced for completeness and for logging, never as an input to
    /// [`derive_session_key`].
    pub sender_public_key: Option<[u8; KEY_LEN]>,
}

/// Seal `plaintext` under `key` as a type-0 envelope.
///
/// The nonce is drawn from the OS CSPRNG per envelope. A counter would be smaller but would have to
/// survive a restart to stay unique, and a nonce reused under ChaCha20-Poly1305 loses
/// confidentiality outright — so the randomness is the cheaper correctness.
pub fn seal_type0(key: &[u8; KEY_LEN], plaintext: &str) -> String {
    let nonce = random_nonce();
    let sealed = encrypt(key, &nonce, plaintext);
    let mut out = Vec::with_capacity(1 + IV_LEN + sealed.len());
    out.push(ENVELOPE_TYPE_0);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    BASE64.encode(out)
}

/// Seal `plaintext` under `key` as a type-1 envelope, publishing `sender_public_key` alongside it.
///
/// Used for exactly one message in the protocol — the response to `wc_sessionPropose` — because the
/// dapp needs this wallet's X25519 public key to derive the same session key, and there is no other
/// channel to send it on.
pub fn seal_type1(
    key: &[u8; KEY_LEN],
    sender_public_key: &[u8; KEY_LEN],
    plaintext: &str,
) -> String {
    let nonce = random_nonce();
    let sealed = encrypt(key, &nonce, plaintext);
    let mut out = Vec::with_capacity(1 + KEY_LEN + IV_LEN + sealed.len());
    out.push(ENVELOPE_TYPE_1);
    out.extend_from_slice(sender_public_key);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    BASE64.encode(out)
}

/// Open an envelope of either type under `key`.
pub fn open(key: &[u8; KEY_LEN], envelope: &str) -> Result<Opened, EnvelopeError> {
    let bytes = BASE64
        .decode(envelope.trim())
        .map_err(|_| EnvelopeError::NotBase64)?;
    let (&type_byte, rest) = bytes.split_first().ok_or(EnvelopeError::TooShort)?;

    let (sender_public_key, rest) = match type_byte {
        ENVELOPE_TYPE_0 => (None, rest),
        ENVELOPE_TYPE_1 => {
            let (key_bytes, rest) = split_at_checked(rest, KEY_LEN)?;
            let mut pk = [0u8; KEY_LEN];
            pk.copy_from_slice(key_bytes);
            (Some(pk), rest)
        }
        other => return Err(EnvelopeError::UnknownType(other)),
    };

    let (iv, sealed) = split_at_checked(rest, IV_LEN)?;
    // `split_at_checked` already proved the length, so this conversion cannot fail; it is written
    // fallibly anyway because an `expect` on attacker-supplied input is a crash waiting for a proof
    // to be refactored away from underneath it.
    let iv: [u8; IV_LEN] = iv.try_into().map_err(|_| EnvelopeError::TooShort)?;
    let plaintext = decrypt(key, &iv, sealed)?;
    Ok(Opened {
        plaintext,
        sender_public_key,
    })
}

/// The relay topic a key is published on: `sha256(key)`, lowercase hex.
///
/// A topic is thus a public commitment to a key nobody but the two peers holds, which is what lets
/// an untrusted relay route to a session it cannot read.
pub fn topic_of(key: &[u8; KEY_LEN]) -> String {
    hex::encode(Sha256::digest(key))
}

/// Derive the SESSION symmetric key both peers will use, from this wallet's X25519 secret and the
/// dapp's public key.
///
/// `HKDF-SHA256` over the raw X25519 shared secret with NO salt and NO info, expanded to 32 bytes —
/// which is precisely what `@walletconnect/utils` `deriveSymKey` does. Any added salt or info would
/// be a strictly stronger construction that no dapp on earth could match, so the parameters are
/// fixed by interoperability rather than chosen.
pub fn derive_session_key(secret: &StaticSecret, peer_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(&[], &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Mint a fresh X25519 keypair for one session proposal.
///
/// One per proposal, never reused: the secret is what binds a session to this pairing, and a shared
/// one would make two dapps' sessions derivable from each other.
pub fn new_keypair() -> (StaticSecret, [u8; KEY_LEN]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

/// Draw a fresh nonce from the OS CSPRNG.
///
/// Uses the AEAD crate's OWN generator rather than filling a local buffer. Two reasons, and the
/// second is not cosmetic: the crate's generator is the API this construction is meant to be used
/// through, and a hand-filled `[0u8; IV_LEN]` buffer leaves a zero literal flowing into the nonce
/// position that static analysis reads as a hard-coded IV - correctly, in the sense that it cannot
/// see the overwrite. Removing the literal removes the question rather than answering it every time.
fn random_nonce() -> Nonce {
    ChaCha20Poly1305::generate_nonce(&mut OsRng)
}

fn encrypt(key: &[u8; KEY_LEN], nonce: &Nonce, plaintext: &str) -> Vec<u8> {
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: &[],
            },
        )
        .expect("ChaCha20-Poly1305 encryption of an in-memory buffer cannot fail")
}

fn decrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], sealed: &[u8]) -> Result<String, EnvelopeError> {
    let opened = ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &Nonce::from(*iv),
            Payload {
                msg: sealed,
                aad: &[],
            },
        )
        .map_err(|_| EnvelopeError::Undecryptable)?;
    String::from_utf8(opened).map_err(|_| EnvelopeError::NotUtf8)
}

/// `split_at` that reports a short buffer instead of panicking on it.
///
/// The input is attacker-supplied, so an index panic here is a remotely-triggerable crash of the
/// tray process rather than a programming error.
fn split_at_checked(bytes: &[u8], at: usize) -> Result<(&[u8], &[u8]), EnvelopeError> {
    if bytes.len() < at {
        return Err(EnvelopeError::TooShort);
    }
    Ok(bytes.split_at(at))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    #[test]
    fn a_type0_envelope_round_trips() {
        let sealed = seal_type0(&KEY, "{\"id\":1}");
        let opened = open(&KEY, &sealed).expect("opens");
        assert_eq!(opened.plaintext, "{\"id\":1}");
        assert_eq!(opened.sender_public_key, None);
    }

    #[test]
    fn a_type1_envelope_round_trips_and_carries_the_sender_key() {
        let pk = [9u8; KEY_LEN];
        let sealed = seal_type1(&KEY, &pk, "{\"id\":2}");
        let opened = open(&KEY, &sealed).expect("opens");
        assert_eq!(opened.plaintext, "{\"id\":2}");
        assert_eq!(opened.sender_public_key, Some(pk));
    }

    /// The header layout is the interop contract, so it is asserted on the BYTES rather than only
    /// through a round-trip. A round-trip is symmetric and would pass just as happily if this
    /// implementation put the iv before the type byte and no other implementation could read it.
    #[test]
    fn the_type0_header_is_one_type_byte_then_a_twelve_byte_iv() {
        let raw = BASE64.decode(seal_type0(&KEY, "x")).unwrap();
        assert_eq!(raw[0], 0, "type byte");
        // 1 type + 12 iv + 1 plaintext byte + 16 Poly1305 tag.
        assert_eq!(raw.len(), 1 + IV_LEN + 1 + 16);
    }

    #[test]
    fn the_type1_header_puts_the_sender_key_before_the_iv() {
        let pk = [3u8; KEY_LEN];
        let raw = BASE64.decode(seal_type1(&KEY, &pk, "x")).unwrap();
        assert_eq!(raw[0], 1, "type byte");
        assert_eq!(
            &raw[1..1 + KEY_LEN],
            &pk,
            "sender key follows the type byte"
        );
        assert_eq!(raw.len(), 1 + KEY_LEN + IV_LEN + 1 + 16);
    }

    /// The nonce must differ per envelope or ChaCha20-Poly1305 loses confidentiality outright. Sealing
    /// the SAME plaintext under the SAME key twice is the fixture that can see a fixed nonce; a test
    /// over two different plaintexts could not, because their ciphertexts differ regardless.
    #[test]
    fn the_same_plaintext_seals_differently_each_time() {
        let a = seal_type0(&KEY, "identical");
        let b = seal_type0(&KEY, "identical");
        assert_ne!(a, b, "a fixed nonce would make these equal");
    }

    #[test]
    fn a_wrong_key_does_not_open_an_envelope() {
        let sealed = seal_type0(&KEY, "secret");
        assert_eq!(
            open(&[8u8; KEY_LEN], &sealed),
            Err(EnvelopeError::Undecryptable)
        );
    }

    /// Tampering must be caught by the AEAD tag rather than surfacing as plaintext. The mutation
    /// targets the CIPHERTEXT body, past the header, so it cannot be caught by a length check.
    #[test]
    fn a_tampered_body_does_not_open() {
        let sealed = seal_type0(&KEY, "the amount is 1 XCH");
        let mut raw = BASE64.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert_eq!(
            open(&KEY, &BASE64.encode(raw)),
            Err(EnvelopeError::Undecryptable)
        );
    }

    /// A wrong key and a tampered body report the SAME error on purpose. If they differed, a prober
    /// could tell whether a guessed key was right, which is the whole game.
    #[test]
    fn a_wrong_key_and_a_tampered_body_are_indistinguishable() {
        let sealed = seal_type0(&KEY, "secret");
        let mut raw = BASE64.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert_eq!(
            open(&KEY, &BASE64.encode(raw)),
            open(&[8u8; KEY_LEN], &sealed)
        );
    }

    /// The header is OUTSIDE the AEAD, and this test says so out loud.
    ///
    /// It rewrites the sender key in a type-1 envelope and asserts the body STILL OPENS — the
    /// opposite of what a reader would assume from a sealed envelope, and precisely why
    /// `Opened::sender_public_key` must never feed a key derivation. If a future change starts
    /// authenticating the header, this test fails and the field's warning can be relaxed
    /// deliberately rather than by accident.
    #[test]
    fn the_sender_key_in_a_type1_header_is_unauthenticated() {
        let honest = [9u8; KEY_LEN];
        let forged = [0xEEu8; KEY_LEN];
        let sealed = seal_type1(&KEY, &honest, "the body is untouched");
        let mut raw = BASE64.decode(&sealed).unwrap();
        raw[1..1 + KEY_LEN].copy_from_slice(&forged);

        let opened = open(&KEY, &BASE64.encode(raw)).expect("the body is still authentic");
        assert_eq!(opened.plaintext, "the body is untouched");
        assert_eq!(
            opened.sender_public_key,
            Some(forged),
            "the header carries whatever an attacker wrote, which is why it must not be trusted"
        );
    }

    /// The type byte is unauthenticated too, but flipping it fails CLOSED: the header lengths
    /// differ, so the wrong bytes land in the nonce and ciphertext positions and the AEAD refuses.
    /// That is what keeps an unauthenticated header from becoming a parsing-confusion attack.
    #[test]
    fn flipping_the_envelope_type_fails_closed_rather_than_confusing_the_parser() {
        // Which error comes back is incidental and differs by direction — reading a type-0 body as
        // type 1 consumes 32 bytes that are not there, so it fails on LENGTH before the tag is even
        // reached. The property is that neither direction yields plaintext, so that is what is
        // asserted; pinning a specific error here would be pinning an implementation detail.
        for (from, to) in [(1u8, 0u8), (0, 1)] {
            let sealed = if from == 1 {
                seal_type1(&KEY, &[9u8; KEY_LEN], "body")
            } else {
                seal_type0(&KEY, "body")
            };

            // The CONTROL, and it is what keeps the refusal below from being vacuous: the very same
            // envelope, untampered, must still open. Without it "no plaintext came out" is satisfied
            // just as well by an `open` that never works at all, or by a fixture rejected by some
            // earlier guard that would have rejected a valid envelope too.
            assert_eq!(
                open(&KEY, &sealed)
                    .expect("the untampered control must open")
                    .plaintext,
                "body",
                "the fixture is not on the real decrypt path"
            );

            let mut raw = BASE64.decode(&sealed).unwrap();
            raw[0] = to;
            assert!(
                open(&KEY, &BASE64.encode(raw)).is_err(),
                "a type {from} envelope read as type {to} produced plaintext"
            );
        }
    }

    #[test]
    fn a_non_base64_payload_is_named_as_such() {
        assert_eq!(open(&KEY, "not base64!!!"), Err(EnvelopeError::NotBase64));
    }

    #[test]
    fn an_unknown_type_byte_is_reported_with_its_value() {
        let raw = BASE64.encode([9u8, 1, 2, 3]);
        assert_eq!(open(&KEY, &raw), Err(EnvelopeError::UnknownType(9)));
    }

    /// The truncation family, one case per header boundary. Each of these is a remote crash in a
    /// naive `split_at`, so they are tested individually rather than as one representative.
    #[test]
    fn every_truncated_header_is_refused_without_panicking() {
        assert_eq!(
            open(&KEY, &BASE64.encode([] as [u8; 0])),
            Err(EnvelopeError::TooShort)
        );
        // Type 0 with only part of an iv.
        assert_eq!(
            open(&KEY, &BASE64.encode([0u8, 1, 2, 3])),
            Err(EnvelopeError::TooShort)
        );
        // Type 1 with only part of a sender key.
        assert_eq!(
            open(&KEY, &BASE64.encode([1u8, 1, 2, 3])),
            Err(EnvelopeError::TooShort)
        );
        // Type 1 with a full sender key but a truncated iv.
        let mut short = vec![1u8];
        short.extend_from_slice(&[0u8; KEY_LEN]);
        short.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            open(&KEY, &BASE64.encode(short)),
            Err(EnvelopeError::TooShort)
        );
    }

    /// An envelope with a header and an EMPTY body is not short, so it reaches the AEAD, which
    /// rejects it for having no tag. This is the case a length check alone would let through.
    #[test]
    fn a_headers_only_envelope_fails_the_aead_rather_than_the_length_check() {
        let mut raw = vec![0u8];
        raw.extend_from_slice(&[0u8; IV_LEN]);
        assert_eq!(
            open(&KEY, &BASE64.encode(raw)),
            Err(EnvelopeError::Undecryptable)
        );
    }

    #[test]
    fn a_topic_is_the_lowercase_hex_sha256_of_its_key() {
        let topic = topic_of(&[0u8; KEY_LEN]);
        assert_eq!(topic.len(), 64);
        assert_eq!(
            topic, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "sha256 of 32 zero bytes"
        );
    }

    /// Both sides must land on the SAME session key from opposite halves of the exchange. A test
    /// that only derived once would confirm the function is deterministic, not that it agrees with
    /// a peer — which is the property the session depends on.
    #[test]
    fn both_peers_derive_the_same_session_key() {
        let (wallet_secret, wallet_public) = new_keypair();
        let (dapp_secret, dapp_public) = new_keypair();
        assert_eq!(
            derive_session_key(&wallet_secret, &dapp_public),
            derive_session_key(&dapp_secret, &wallet_public)
        );
    }

    #[test]
    fn a_different_peer_derives_a_different_session_key() {
        let (wallet_secret, _) = new_keypair();
        let (_, dapp_public) = new_keypair();
        let (_, other_public) = new_keypair();
        assert_ne!(
            derive_session_key(&wallet_secret, &dapp_public),
            derive_session_key(&wallet_secret, &other_public)
        );
    }

    #[test]
    fn each_proposal_gets_a_fresh_keypair() {
        let (_, a) = new_keypair();
        let (_, b) = new_keypair();
        assert_ne!(a, b);
    }

    /// A session key derived from a real exchange must actually open envelopes sealed under it —
    /// the two halves of this module wired together, which neither half's own tests can see.
    #[test]
    fn a_derived_session_key_opens_envelopes_sealed_by_the_peer() {
        let (wallet_secret, wallet_public) = new_keypair();
        let (dapp_secret, dapp_public) = new_keypair();
        let dapp_view = derive_session_key(&dapp_secret, &wallet_public);
        let wallet_view = derive_session_key(&wallet_secret, &dapp_public);
        let from_dapp = seal_type0(&dapp_view, "{\"method\":\"wc_sessionRequest\"}");
        assert_eq!(
            open(&wallet_view, &from_dapp).unwrap().plaintext,
            "{\"method\":\"wc_sessionRequest\"}"
        );
    }
}
