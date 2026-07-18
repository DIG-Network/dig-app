//! The unlocked, in-memory user identity keys — the material that never touches disk in the clear
//! and never crosses the IPC boundary to the engine (§2.3 of `SPEC.md`).
//!
//! A profile's identity is two keys, matching the `dig-identity` standard key slots:
//!
//! - the **Ed25519 signing key** (slot `0x0010`) — signs spends, profile SMT writes, and the
//!   engine's `sign` callback challenges;
//! - the **X25519 encryption key** (slot `0x0011`) — the identity key end-to-end sealing derives
//!   from (ecosystem §5.4).
//!
//! Both live only in [`IdentitySecrets`], which zeroizes its secret bytes on drop (via the dalek
//! crates' own `Zeroize` impls). Its at-rest form is a fixed 64-byte layout — `signing_seed(32) ||
//! encryption_scalar(32)` — that [`crate::keystore::vault`] DIGOP1-seals; nothing else serializes
//! the private material.

use dig_keystore::{opaque, KdfParams, Password};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use super::KeystoreError;

/// HKDF domain separator for the per-profile data-encryption key. Bumping the version suffix is how
/// a future DEK-derivation change stays distinguishable from this one.
const DEK_INFO: &[u8] = b"dig-app:profile-dek:v1";

/// HKDF salt for the per-profile DEK. A fixed, non-secret domain constant: the identity secret is
/// the entropy source, so the salt only needs to separate this derivation from any other HKDF use.
const DEK_SALT: &[u8] = b"dig-app:dek-salt:v1";

/// The number of bytes an Ed25519 signing seed and an X25519 secret scalar each occupy.
const KEY_LEN: usize = 32;

/// The length of the [`IdentitySecrets`] at-rest serialization: the signing seed followed by the
/// encryption scalar.
pub const SEALED_SECRET_LEN: usize = KEY_LEN * 2;

/// The length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The unlocked private keys of one profile's DID identity. Held only in memory; its secret bytes
/// are zeroized on drop.
///
/// This is the sole owner of the user's private key material while a profile is unlocked. Callers
/// obtain one from [`crate::keystore::ProfileVault::unlock`] and drop it (logout / detach) to erase
/// the keys from memory.
pub struct IdentitySecrets {
    signing: SigningKey,
    encryption: StaticSecret,
}

impl IdentitySecrets {
    /// Generate a fresh identity from a cryptographic RNG. Production callers use
    /// [`IdentitySecrets::generate`]; the RNG is injectable so tests can pin deterministic keys.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            signing: SigningKey::generate(rng),
            encryption: StaticSecret::random_from_rng(rng),
        }
    }

    /// Generate a fresh identity using the operating system's CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::OsRng)
    }

    /// The Ed25519 signing public key — `dig-identity` slot `0x0010`. This is published to the DID
    /// profile; the private half never leaves this process.
    pub fn signing_public_key(&self) -> [u8; KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 encryption public key — `dig-identity` slot `0x0011`. Counterparties seal
    /// end-to-end messages to this key (ecosystem §5.4).
    pub fn encryption_public_key(&self) -> [u8; KEY_LEN] {
        X25519Public::from(&self.encryption).to_bytes()
    }

    /// Sign `message` with the Ed25519 signing key, returning the 64-byte signature. This is the
    /// in-process signing primitive every §2.3 flow funnels through — the key itself is never
    /// exposed to callers.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Seal `plaintext` — a per-profile secret blob (wallet state, subscriptions, prefs) — under
    /// this profile's data-encryption key (DEK). The DEK is HKDF-derived from the identity, so the
    /// unlocked identity is the single root that unlocks every other per-profile blob (§3 key
    /// hierarchy). Sealing reuses the audited DIGOP1 container, so there is exactly one at-rest
    /// crypto path in the app.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::Seal`] if the underlying DIGOP1 seal fails (an allocation/parameter error;
    /// never a caller-input error).
    pub fn seal_data(&self, plaintext: &[u8], kdf: KdfParams) -> Result<Vec<u8>, KeystoreError> {
        opaque::seal(&self.dek_password(), plaintext, kdf).map_err(KeystoreError::Seal)
    }

    /// Open a blob produced by [`seal_data`](Self::seal_data) with this profile's DEK.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::DataUnlock`] on any decrypt/authentication failure — fail-closed, never
    /// returning partial plaintext (e.g. a blob sealed by a different profile's DEK).
    pub fn open_data(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        opaque::open(&self.dek_password(), blob).map_err(|_| KeystoreError::DataUnlock)
    }

    /// Derive this profile's DEK from the identity secret and present it as a DIGOP1 [`Password`].
    /// The DEK bytes live only inside the returned zeroizing password for the duration of one
    /// seal/open call.
    fn dek_password(&self) -> Password {
        let ikm = self.to_sealed_bytes();
        let hkdf = Hkdf::<Sha256>::new(Some(DEK_SALT), &*ikm);
        let mut dek = Zeroizing::new([0u8; 32]);
        hkdf.expand(DEK_INFO, &mut *dek)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Password::new(*dek)
    }

    /// Serialize the private material into its fixed 64-byte at-rest layout, wrapped in
    /// [`Zeroizing`] so the plaintext is erased once the caller (the vault sealer) is done with it.
    pub(super) fn to_sealed_bytes(&self) -> Zeroizing<[u8; SEALED_SECRET_LEN]> {
        let mut bytes = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        bytes[..KEY_LEN].copy_from_slice(&self.signing.to_bytes());
        bytes[KEY_LEN..].copy_from_slice(&self.encryption.to_bytes());
        bytes
    }

    /// Reconstruct the identity from its 64-byte at-rest layout (the inverse of
    /// [`to_sealed_bytes`](Self::to_sealed_bytes)).
    ///
    /// # Errors
    ///
    /// [`KeystoreError::MalformedSecret`] if `bytes` is not exactly [`SEALED_SECRET_LEN`] long —
    /// which, after a successful DIGOP1 open, would mean the sealed blob was written by an
    /// incompatible version rather than tampered with (tampering fails the AEAD tag first).
    pub(super) fn from_sealed_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        let bytes: &[u8; SEALED_SECRET_LEN] = bytes
            .try_into()
            .map_err(|_| KeystoreError::MalformedSecret)?;
        // Hold the split-out raw key halves in scrubbing buffers: the Ed25519 seed and the X25519
        // scalar are private material, so their stack copies must be zeroized on drop rather than
        // left in freed memory (the dalek key types zeroize themselves, but these intermediates
        // would not). `StaticSecret::from` consumes an owned array, so the scalar copy it takes is
        // in turn owned + zeroized by the resulting `StaticSecret`.
        let signing_seed: Zeroizing<[u8; KEY_LEN]> =
            Zeroizing::new(bytes[..KEY_LEN].try_into().expect("32-byte slice"));
        let encryption_scalar: Zeroizing<[u8; KEY_LEN]> =
            Zeroizing::new(bytes[KEY_LEN..].try_into().expect("32-byte slice"));
        Ok(Self {
            signing: SigningKey::from_bytes(&signing_seed),
            encryption: StaticSecret::from(*encryption_scalar),
        })
    }
}

/// Verify an Ed25519 `signature` over `message` against a `signing_public_key` (slot `0x0010`). A
/// free function because verification needs only the public key — callers (and tests) verify
/// signatures without holding an [`IdentitySecrets`].
pub fn verify_signature(
    signing_public_key: &[u8; KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(signing_public_key) else {
        return false;
    };
    verifying_key
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn seeded() -> IdentitySecrets {
        IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(7))
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let id = seeded();
        let msg = b"attach challenge";
        let sig = id.sign(msg);
        assert!(verify_signature(&id.signing_public_key(), msg, &sig));
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let id = seeded();
        let sig = id.sign(b"pay 5 XCH to alice");
        assert!(!verify_signature(
            &id.signing_public_key(),
            b"pay 5 XCH to mallory",
            &sig
        ));
    }

    #[test]
    fn verify_rejects_a_foreign_signer() {
        let signer = seeded();
        let other = IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(99));
        let sig = signer.sign(b"msg");
        assert!(!verify_signature(&other.signing_public_key(), b"msg", &sig));
    }

    #[test]
    fn sealed_bytes_round_trip_preserves_both_keys() {
        let id = seeded();
        let bytes = id.to_sealed_bytes();
        assert_eq!(bytes.len(), SEALED_SECRET_LEN);
        let restored = IdentitySecrets::from_sealed_bytes(&*bytes).unwrap();
        assert_eq!(restored.signing_public_key(), id.signing_public_key());
        assert_eq!(restored.encryption_public_key(), id.encryption_public_key());
        // A signature from the restored key verifies against the original's public key.
        let sig = restored.sign(b"x");
        assert!(verify_signature(&id.signing_public_key(), b"x", &sig));
    }

    #[test]
    fn from_sealed_bytes_rejects_a_wrong_length() {
        assert!(matches!(
            IdentitySecrets::from_sealed_bytes(&[0u8; 10]),
            Err(KeystoreError::MalformedSecret)
        ));
    }

    #[test]
    fn dek_seal_open_round_trips() {
        let id = seeded();
        let blob = id.seal_data(b"wallet state", KdfParams::FAST_TEST).unwrap();
        assert_ne!(
            &blob[..],
            b"wallet state",
            "data must be ciphertext at rest"
        );
        let opened = id.open_data(&blob).unwrap();
        assert_eq!(&*opened, b"wallet state");
    }

    #[test]
    fn dek_is_bound_to_the_identity_a_foreign_dek_cannot_open() {
        let owner = seeded();
        let stranger = IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(1234));
        let blob = owner
            .seal_data(b"subscriptions", KdfParams::FAST_TEST)
            .unwrap();
        assert!(matches!(
            stranger.open_data(&blob),
            Err(KeystoreError::DataUnlock)
        ));
    }

    #[test]
    fn two_generations_differ() {
        let a = IdentitySecrets::generate();
        let b = IdentitySecrets::generate();
        assert_ne!(a.signing_public_key(), b.signing_public_key());
        assert_ne!(a.encryption_public_key(), b.encryption_public_key());
    }
}
