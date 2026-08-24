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
    /// AEAD does cover — and that is where the client reads the proposer key
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
///
/// # Returns `None` for a peer key that contributes nothing
///
/// `peer_public` is 32 bytes chosen by a stranger — it arrives in `params.proposer.publicKey` on the
/// pairing topic, before any human has approved anything. X25519 has a small set of **low-order
/// points** whose shared secret is all zeroes **whatever secret they are combined with**, so a dapp
/// that offers one makes this function return a value that does not depend on the wallet at all.
///
/// The consequence is not subtle. The session key becomes a constant every implementation of this
/// function can compute; the topic, being `sha256(key)`, becomes one public constant that EVERY
/// victim lands on; and the relay — an untrusted intermediary that is only ever meant to see
/// ciphertext — can read and write that session at will. That falsifies this module's central claim
/// (see the module docs) and NC-1.
///
/// So a non-contributory exchange is REFUSED rather than used. `was_contributory` is
/// `x25519-dalek`'s own check for exactly this, and refusing costs nothing in practice: no
/// conforming dapp sends a low-order key, because doing so breaks its own session too.
pub fn derive_session_key(
    secret: &StaticSecret,
    peer_public: &[u8; KEY_LEN],
) -> Option<[u8; KEY_LEN]> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(&[], &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Some(out)
}

/// The X25519 low-order points, as lowercase hex.
///
/// Every public key here yields an **all-zero shared secret whatever secret it is combined with**,
/// which is what makes them dangerous: a peer offering one fixes the session key to a value the
/// wallet contributed nothing to. [`derive_session_key`] refuses them.
///
/// Hex rather than byte arrays because a mistyped byte in an array is invisible, and this list is
/// only useful if it is right — `every_published_low_order_point_is_genuinely_non_contributory`
/// checks each one against the curve rather than trusting the transcription. That test earned its
/// place: an eighth candidate (`cdeb7a…b880`) was in this list until it failed, because
/// `x25519-dalek` masks the high bit and the masked value is an ordinary point.
///
/// Published rather than kept in the test module so a reader can see exactly what is refused.
pub const LOW_ORDER_POINT_HEX: [&str; 7] = [
    // The canonical small-order set for Curve25519, as libsodium's `has_small_order` carries it.
    //
    // Deliberately WITHOUT a per-entry group order. An earlier revision annotated each one and three
    // of the labels were wrong — an unverified claim sitting beside a verified list, which is the
    // more misleading arrangement of the two, because the correctness of the values lends the labels
    // a credibility nothing established. The property that matters is checked rather than asserted:
    // `every_published_low_order_point_is_genuinely_non_contributory` confirms each yields the
    // all-zero shared secret, which is the only thing this list is used for.
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// The low-order points as raw keys, decoded from [`LOW_ORDER_POINT_HEX`].
///
/// # Panics
///
/// If a published vector is not 32 bytes of hex, which a test also catches.
pub fn low_order_points() -> Vec<[u8; KEY_LEN]> {
    LOW_ORDER_POINT_HEX
        .iter()
        .map(|hex_str| {
            let mut out = [0u8; KEY_LEN];
            hex::decode_to_slice(hex_str, &mut out).expect("a published vector is 32 bytes of hex");
            out
        })
        .collect()
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
        let dapp_view = derive_session_key(&dapp_secret, &wallet_public).expect("honest keys");
        let wallet_view = derive_session_key(&wallet_secret, &dapp_public).expect("honest keys");
        let from_dapp = seal_type0(&dapp_view, "{\"method\":\"wc_sessionRequest\"}");
        assert_eq!(
            open(&wallet_view, &from_dapp).unwrap().plaintext,
            "{\"method\":\"wc_sessionRequest\"}"
        );
    }

    /// **The gating defect, pinned against the real vectors.**
    ///
    /// A low-order point makes X25519 yield an all-zero shared secret WHATEVER secret it is combined
    /// with. Before the contributory check, every one of these produced the same session key and
    /// therefore the same `sha256` topic — a public constant that every victim would land on and
    /// that the relay, which must only ever see ciphertext, could read and write at will.
    ///
    /// The fixture varies BOTH sides deliberately. Two independent wallet secrets across every
    /// low-order point is what shows the result does not depend on the wallet at all; a single
    /// secret would show only that one key is refused, which a hard-coded rejection of one vector
    /// would satisfy too.
    #[test]
    fn a_low_order_peer_key_is_refused_rather_than_producing_a_public_session() {
        let (first, _) = new_keypair();
        let (second, _) = new_keypair();
        for (index, point) in low_order_points().iter().enumerate() {
            assert_eq!(
                derive_session_key(&first, point),
                None,
                "low-order point {index} was accepted"
            );
            assert_eq!(
                derive_session_key(&second, point),
                None,
                "low-order point {index} was accepted under a second wallet secret"
            );
        }
    }

    /// The CONTROL that stops the refusal above from being vacuous.
    ///
    /// Without it, a `derive_session_key` that returned `None` for absolutely everything would pass
    /// the low-order battery perfectly while breaking every honest pairing — so an ordinary exchange
    /// must still succeed, and the two wallets must still agree.
    #[test]
    fn an_honest_peer_key_still_derives_and_both_sides_still_agree() {
        let (wallet_secret, wallet_public) = new_keypair();
        let (dapp_secret, dapp_public) = new_keypair();
        let ours = derive_session_key(&wallet_secret, &dapp_public).expect("an honest key derives");
        let theirs =
            derive_session_key(&dapp_secret, &wallet_public).expect("an honest key derives");
        assert_eq!(ours, theirs);
    }

    /// The topic collision, stated as its own fact because it is the part that makes the defect
    /// catastrophic rather than merely weak: the refusal is what prevents many unrelated victims
    /// from being routed onto ONE relay topic.
    ///
    /// Asserted through `topic_of` over the derived key, so it fails if either the refusal or the
    /// topic derivation regresses.
    #[test]
    fn refusing_a_low_order_key_is_what_keeps_victims_off_a_shared_topic() {
        let (first, _) = new_keypair();
        let (second, _) = new_keypair();
        let point = &low_order_points()[2];

        // Neither wallet can reach a topic at all, which is the point.
        assert!(derive_session_key(&first, point).is_none());
        assert!(derive_session_key(&second, point).is_none());

        // Whereas two honest pairings land on two DIFFERENT topics — the property being protected.
        let (_, dapp_a) = new_keypair();
        let (_, dapp_b) = new_keypair();
        let topic_a = topic_of(&derive_session_key(&first, &dapp_a).expect("derives"));
        let topic_b = topic_of(&derive_session_key(&second, &dapp_b).expect("derives"));
        assert_ne!(topic_a, topic_b);
    }

    /// **Why the refusal exists, shown rather than asserted.**
    ///
    /// The tests above prove the key is refused. This one proves what would happen if it were not:
    /// two INDEPENDENT wallet secrets, combined with the same low-order point, produce the identical
    /// shared secret — so the session key, and therefore the `sha256` topic, would be the same
    /// constant for every victim in the world, readable and writable by the relay.
    ///
    /// It reaches past `derive_session_key` to the raw exchange deliberately, because the fix has
    /// made that outcome unreachable through the public function. Without this, the module records
    /// a refusal whose motivation lives only in a comment.
    #[test]
    fn two_unrelated_wallets_would_otherwise_land_on_the_identical_secret() {
        let (first, _) = new_keypair();
        let (second, _) = new_keypair();
        for point in low_order_points() {
            let a = first.diffie_hellman(&PublicKey::from(point));
            let b = second.diffie_hellman(&PublicKey::from(point));
            assert_eq!(
                a.as_bytes(),
                b.as_bytes(),
                "the collision this refusal prevents"
            );
            assert_eq!(
                a.as_bytes(),
                &[0u8; KEY_LEN],
                "and it is the all-zero secret"
            );
        }

        // The control: honest keys do NOT collide, so the equality above is a property of the
        // low-order point rather than of this test comparing something with itself.
        let (_, honest) = new_keypair();
        assert_ne!(
            first.diffie_hellman(&PublicKey::from(honest)).as_bytes(),
            second.diffie_hellman(&PublicKey::from(honest)).as_bytes()
        );
    }

    /// The published vectors must be the ones the curve actually rejects. If a byte were mistyped,
    /// the battery above would be testing ordinary keys that are refused for no reason — green, and
    /// proving nothing about low-order points.
    #[test]
    fn every_published_low_order_point_is_genuinely_non_contributory() {
        let (secret, _) = new_keypair();
        for (index, point) in low_order_points().iter().enumerate() {
            let shared = secret.diffie_hellman(&PublicKey::from(*point));
            assert!(
                !shared.was_contributory(),
                "vector {index} is not actually a low-order point; the battery would be vacuous"
            );
        }
    }
}
