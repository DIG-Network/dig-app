//! The unlocked, in-memory user identity key — the material that never touches disk in the clear
//! and never crosses the IPC boundary to the engine (§2.3 of `SPEC.md`).
//!
//! A profile's identity is ONE key, matching the `dig-identity` v2 key model (SPEC §6a):
//!
//! - the **BLS12-381 G1 identity key** (slot `0x0010`) — a 48-byte compressed G1 public key whose
//!   private scalar does BOTH jobs: it signs (BLS G2, AugScheme — spends, profile SMT writes, the
//!   IPC session attach challenge, and the engine's `sign` callback) AND it is the DH key end-to-end
//!   sealing derives from (G1 ECDH via [`dig_identity::g1_dh`], ecosystem §5.4). There is no separate
//!   encryption key — the v1 X25519 slot `0x0011` is retired.
//!
//! The key lives only in [`IdentitySecrets`], which zeroizes its secret scalar on drop. Its at-rest
//! form is a versioned layout — `version(1) || bls_scalar(32)` — that [`crate::keystore::vault`]
//! DIGOP1-seals; nothing else serializes the private material. The version byte lets a reader
//! distinguish this BLS format from any future one AND fail-closed on a legacy v1 (Ed25519) 64-byte
//! blob rather than misparsing it (§5.1 back-compat: keys are non-convertible across the v1→v2 key
//! model, so a legacy identity is re-provisioned, never silently reinterpreted).

use chia_bls::SecretKey;
use dig_identity::{
    derive_identity_sk, master_secret_key_from_seed, public_key_bytes, sign_message,
    verify_signature as bls_verify_signature,
};
use dig_keystore::{opaque, KdfParams, Password};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::KeystoreError;

/// HKDF domain separator for the per-profile data-encryption key. Bumping the version suffix is how
/// a future DEK-derivation change stays distinguishable from this one. `v2` marks the BLS key model
/// (the DEK is now keyed off the versioned BLS at-rest bytes, so it never collides with a v1 DEK).
const DEK_INFO: &[u8] = b"dig-app:profile-dek:v2";

/// HKDF salt for the per-profile DEK. A fixed, non-secret domain constant: the identity secret is
/// the entropy source, so the salt only needs to separate this derivation from any other HKDF use.
const DEK_SALT: &[u8] = b"dig-app:dek-salt:v1";

/// The number of bytes in a BLS12-381 secret-key scalar (`chia_bls::SecretKey`).
const SCALAR_LEN: usize = 32;

/// The version tag of the current (BLS12-381 G1) at-rest identity layout. Byte 0 of the sealed
/// plaintext; a reader dispatches on it so the format is self-describing and future-proof.
pub const SEALED_IDENTITY_VERSION: u8 = 2;

/// The length of the [`IdentitySecrets`] at-rest serialization: one version byte followed by the
/// 32-byte BLS secret scalar.
pub const SEALED_SECRET_LEN: usize = 1 + SCALAR_LEN;

/// The length of a legacy v1 (Ed25519 seed + X25519 scalar) at-rest blob. A reader recognises this
/// exact length to fail-closed with [`KeystoreError::LegacyEd25519Identity`] instead of misparsing
/// it as a BLS key (§5.1).
const LEGACY_ED25519_SEALED_LEN: usize = 64;

/// The number of bytes in a compressed BLS12-381 **G1** signing public key (`dig-identity` slot
/// `0x0010`).
pub const SIGNING_KEY_LEN: usize = 48;

/// The number of bytes in a compressed BLS12-381 **G2** AugScheme signature.
pub const SIGNATURE_LEN: usize = 96;

/// The unlocked private key of one profile's DID identity. Held only in memory; its secret scalar
/// is zeroized on drop (via `chia_bls::SecretKey`'s own `ZeroizeOnDrop`).
///
/// This is the sole owner of the user's private key material while a profile is unlocked. Callers
/// obtain one from [`crate::keystore::ProfileVault::unlock`] and drop it (logout / detach) to erase
/// the key from memory.
pub struct IdentitySecrets {
    /// The BLS12-381 G1 identity secret scalar (slot `0x0010`) — signs (G2 AugScheme) and is the DH
    /// key for end-to-end sealing (G1 ECDH). The single key of the v2 model.
    identity: SecretKey,
}

impl IdentitySecrets {
    /// Generate a fresh identity from a cryptographic RNG. Production callers use
    /// [`IdentitySecrets::generate`]; the RNG is injectable so tests can pin deterministic keys.
    ///
    /// A 32-byte seed is drawn from `rng`, expanded into the EIP-2333 master key
    /// ([`master_secret_key_from_seed`]), and the dig-identity key is derived at the standard
    /// derivation path ([`derive_identity_sk`]) — so a generated profile key sits at the SAME path a
    /// real wallet would publish, and generation stays deterministic under an injected RNG.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; SCALAR_LEN]);
        rng.fill_bytes(&mut *seed);
        let master = master_secret_key_from_seed(&*seed);
        Self {
            identity: derive_identity_sk(&master),
        }
    }

    /// Generate a fresh identity using the operating system's CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::OsRng)
    }

    /// The 48-byte compressed BLS12-381 G1 signing public key — `dig-identity` slot `0x0010`. This is
    /// published to the DID profile; the private half never leaves this process.
    pub fn signing_public_key(&self) -> [u8; SIGNING_KEY_LEN] {
        public_key_bytes(&self.identity)
    }

    /// Sign `message` with the BLS12-381 identity key, returning the 96-byte G2 AugScheme signature.
    /// This is the in-process signing primitive every §2.3 flow funnels through — the key itself is
    /// never exposed to callers.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        sign_message(&self.identity, message)
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

    /// Serialize the private material into its versioned at-rest layout —
    /// `version(1) || bls_scalar(32)` — wrapped in [`Zeroizing`] so the plaintext is erased once the
    /// caller (the vault sealer) is done with it.
    pub(super) fn to_sealed_bytes(&self) -> Zeroizing<[u8; SEALED_SECRET_LEN]> {
        let mut bytes = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        bytes[0] = SEALED_IDENTITY_VERSION;
        let scalar = Zeroizing::new(self.identity.to_bytes());
        bytes[1..].copy_from_slice(&*scalar);
        bytes
    }

    /// Reconstruct the identity from its versioned at-rest layout (the inverse of
    /// [`to_sealed_bytes`](Self::to_sealed_bytes)).
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::LegacyEd25519Identity`] if `bytes` is a legacy v1 (64-byte Ed25519 + X25519)
    ///   blob. The v1→v2 key models are non-convertible, so a reader NEVER reinterprets those bytes as
    ///   a BLS scalar — it fails closed so onboarding re-provisions a fresh v2 identity (§5.1).
    /// - [`KeystoreError::MalformedSecret`] if `bytes` is neither the current versioned layout nor a
    ///   recognised legacy blob — which, after a successful DIGOP1 open, means the sealed blob was
    ///   written by an incompatible version rather than tampered with (tampering fails the AEAD tag
    ///   first).
    pub(super) fn from_sealed_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        // Recognise a legacy v1 blob by its exact length and fail closed — never misparse Ed25519
        // seed bytes as a BLS scalar.
        if bytes.len() == LEGACY_ED25519_SEALED_LEN {
            return Err(KeystoreError::LegacyEd25519Identity);
        }
        let bytes: &[u8; SEALED_SECRET_LEN] = bytes
            .try_into()
            .map_err(|_| KeystoreError::MalformedSecret)?;
        if bytes[0] != SEALED_IDENTITY_VERSION {
            return Err(KeystoreError::MalformedSecret);
        }
        // Hold the split-out raw scalar in a scrubbing buffer: it is private material, so its stack
        // copy must be zeroized on drop rather than left in freed memory (the `SecretKey` zeroizes
        // itself, but this intermediate would not).
        let scalar: Zeroizing<[u8; SCALAR_LEN]> =
            Zeroizing::new(bytes[1..].try_into().expect("32-byte slice"));
        let identity =
            SecretKey::from_bytes(&scalar).map_err(|_| KeystoreError::MalformedSecret)?;
        Ok(Self { identity })
    }
}

/// Verify a BLS12-381 G2 `signature` over `message` against a 48-byte G1 `signing_public_key` (slot
/// `0x0010`). A free function because verification needs only the public key — callers (and tests)
/// verify signatures without holding an [`IdentitySecrets`].
pub fn verify_signature(
    signing_public_key: &[u8; SIGNING_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    bls_verify_signature(signing_public_key, message, signature)
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
    fn signing_public_key_is_a_48_byte_g1_key() {
        assert_eq!(seeded().signing_public_key().len(), SIGNING_KEY_LEN);
        assert_eq!(SIGNING_KEY_LEN, 48);
    }

    #[test]
    fn a_signature_is_a_96_byte_g2_signature() {
        assert_eq!(seeded().sign(b"m").len(), SIGNATURE_LEN);
        assert_eq!(SIGNATURE_LEN, 96);
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
    fn sealed_bytes_round_trip_preserves_the_key() {
        let id = seeded();
        let bytes = id.to_sealed_bytes();
        assert_eq!(bytes.len(), SEALED_SECRET_LEN);
        assert_eq!(bytes[0], SEALED_IDENTITY_VERSION);
        let restored = IdentitySecrets::from_sealed_bytes(&*bytes).unwrap();
        assert_eq!(restored.signing_public_key(), id.signing_public_key());
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
    fn from_sealed_bytes_rejects_an_unknown_version() {
        let mut blob = [0u8; SEALED_SECRET_LEN];
        blob[0] = 0xFF; // not SEALED_IDENTITY_VERSION
        assert!(matches!(
            IdentitySecrets::from_sealed_bytes(&blob),
            Err(KeystoreError::MalformedSecret)
        ));
    }

    #[test]
    fn from_sealed_bytes_fails_closed_on_a_legacy_ed25519_blob() {
        // A legacy v1 (Ed25519 seed || X25519 scalar) 64-byte blob is NEVER misparsed as a BLS
        // scalar — it fails closed so onboarding re-provisions a fresh v2 identity (§5.1).
        let legacy = [7u8; LEGACY_ED25519_SEALED_LEN];
        assert!(matches!(
            IdentitySecrets::from_sealed_bytes(&legacy),
            Err(KeystoreError::LegacyEd25519Identity)
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
    }
}
