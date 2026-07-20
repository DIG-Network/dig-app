//! The unlocked, in-memory user identity key — the material that never touches disk in the clear
//! and never crosses the IPC boundary to the engine (§2.3 of `SPEC.md`).
//!
//! A profile's identity is ONE key, matching the `dig-identity` v2 key model (SPEC §2.2 / §3.1):
//!
//! - the **BLS12-381 G1 identity key** (slot `0x0010`) — a 48-byte compressed G1 public key whose
//!   private scalar does BOTH jobs: it signs (BLS G2, AugScheme — spends, profile SMT writes, the
//!   IPC session attach challenge, and the engine's `sign` callback) AND it is the DH key end-to-end
//!   sealing derives from (G1 ECDH via [`dig_identity::g1_dh`], ecosystem §5.4). There is no separate
//!   encryption key — the v1 X25519 slot `0x0011` is retired.
//!
//! The key lives only in [`IdentitySecrets`]. Because `chia_bls::SecretKey` (0.26) does NOT
//! self-zeroize (it implements no `Zeroize`/`Drop` scrub), [`IdentitySecrets`] stores the raw 32-byte
//! scalar in a [`Zeroizing`] buffer — which IS scrubbed on drop — and reconstructs a transient
//! `SecretKey` only per operation, so the private scalar is erased on logout / detach / lock. Its at-rest
//! form is a versioned layout — `version(1) || bls_scalar(32)` — that [`crate::keystore::vault`]
//! DIGOP1-seals; nothing else serializes the private material. The version byte lets a reader
//! distinguish this BLS format from any future one AND fail-closed on a legacy v1 (Ed25519) 64-byte
//! blob rather than misparsing it (§5.1 back-compat: keys are non-convertible across the v1→v2 key
//! model, so a legacy identity is re-provisioned, never silently reinterpreted).

use chia_bls::SecretKey;
use dig_constants::{DEK_SALT, IDENTITY_IKM_VERSION, PROFILE_DEK_LABEL, SYMMETRIC_KEY_LEN};
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

// The per-profile DEK at-rest byte contract — the HKDF salt (`DEK_SALT`), the IKM version prefix
// (`IDENTITY_IKM_VERSION`), the info/label (`PROFILE_DEK_LABEL`), and the output length
// (`SYMMETRIC_KEY_LEN`) — is sourced from `dig_constants` as the single source of truth, so it can
// never drift from the byte-identical copy dig-session's `UnlockedIdentity::derive_symmetric_key`
// derives from the same crate (dig_ecosystem §5.1 back-compat / §4.1). See dig-constants' "Profile
// DEK at-rest byte contract" section for the authoritative definition + golden vector.

/// The number of bytes in a BLS12-381 secret-key scalar (`chia_bls::SecretKey`).
const SCALAR_LEN: usize = 32;

/// The version tag of the current (BLS12-381 G1) at-rest identity layout. Byte 0 of the sealed
/// plaintext; a reader dispatches on it so the format is self-describing and future-proof. It is the
/// same byte as the DEK's [`IDENTITY_IKM_VERSION`] prefix (both mark the v2 BLS key model), sourced
/// canonically from `dig_constants` rather than a local literal so the two can never disagree.
pub const SEALED_IDENTITY_VERSION: u8 = IDENTITY_IKM_VERSION;

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
/// is scrubbed from memory on drop.
///
/// `chia_bls::SecretKey` (0.26) implements no `Zeroize`/`Drop` scrub — the crate does not even depend
/// on `zeroize` — so storing a live `SecretKey` would leave the 32-byte identity scalar lingering in
/// freed heap after logout / detach / profile lock. We therefore keep the raw scalar in a
/// [`Zeroizing`] buffer (which IS scrubbed on drop) and reconstruct a **transient** `SecretKey` only
/// inside each operation that needs the private key, letting it fall out of scope immediately. This
/// mirrors the proven pattern in [`crate::wallet::signing::WalletKey`].
///
/// This is the sole owner of the user's private key material while a profile is unlocked. Callers
/// obtain one from [`crate::keystore::ProfileVault::unlock`] and drop it (logout / detach) to erase
/// the key from memory.
pub struct IdentitySecrets {
    /// The BLS12-381 G1 identity secret scalar (slot `0x0010`), held as its 32 raw bytes in a
    /// zeroizing buffer so the private material is scrubbed on drop. The transient `SecretKey` is
    /// reconstructed per-op ([`IdentitySecrets::secret_key`]). This one key does BOTH jobs of the v2
    /// model — it signs (G2 AugScheme) and is the DH key for end-to-end sealing (G1 ECDH).
    identity_scalar: Zeroizing<[u8; SCALAR_LEN]>,
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
        // `master` and the derived identity key are transient `chia_bls::SecretKey` locals; chia-bls
        // 0.26 does not scrub them on drop, so we immediately capture the identity scalar into a
        // zeroizing buffer (the persisted form) and let the locals fall out of scope.
        let identity_scalar = Zeroizing::new(derive_identity_sk(&master).to_bytes());
        Self { identity_scalar }
    }

    /// Generate a fresh identity using the operating system's CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::OsRng)
    }

    /// Reconstruct the transient identity signing key from its zeroizing bytes, for the duration of
    /// one operation. Crate-internal; the key is never handed to a caller and drops at end of scope.
    fn secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.identity_scalar).expect("32 stored bytes are a valid SecretKey")
    }

    /// The 48-byte compressed BLS12-381 G1 signing public key — `dig-identity` slot `0x0010`. This is
    /// published to the DID profile; the private half never leaves this process.
    pub fn signing_public_key(&self) -> [u8; SIGNING_KEY_LEN] {
        public_key_bytes(&self.secret_key())
    }

    /// Sign `message` with the BLS12-381 identity key, returning the 96-byte G2 AugScheme signature.
    /// This is the in-process signing primitive every §2.3 flow funnels through — the key itself is
    /// never exposed to callers.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        sign_message(&self.secret_key(), message)
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
        let mut dek = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
        hkdf.expand(PROFILE_DEK_LABEL, &mut *dek)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Password::new(*dek)
    }

    /// Serialize the private material into its versioned at-rest layout —
    /// `version(1) || bls_scalar(32)` — wrapped in [`Zeroizing`] so the plaintext is erased once the
    /// caller (the vault sealer) is done with it.
    pub(super) fn to_sealed_bytes(&self) -> Zeroizing<[u8; SEALED_SECRET_LEN]> {
        let mut bytes = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        bytes[0] = SEALED_IDENTITY_VERSION;
        bytes[1..].copy_from_slice(&*self.identity_scalar);
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
        // Hold the split-out raw scalar in the scrubbing buffer that becomes this identity's stored
        // form: it is private material, so it must be zeroized on drop rather than left in freed
        // memory. Reconstruct a transient `SecretKey` purely to validate the scalar is well-formed
        // (fail-closed on malformed bytes); it drops immediately — only the bytes are retained.
        let identity_scalar: Zeroizing<[u8; SCALAR_LEN]> =
            Zeroizing::new(bytes[1..].try_into().expect("32-byte slice"));
        SecretKey::from_bytes(&identity_scalar).map_err(|_| KeystoreError::MalformedSecret)?;
        Ok(Self { identity_scalar })
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
    fn repeated_ops_reconstruct_the_same_transient_key() {
        // The identity scalar is stored as raw bytes and a transient `SecretKey` is rebuilt per op;
        // this proves that reconstruction is stable — the public key and a signature are identical
        // across separate calls, so nothing is lost by not retaining a live `SecretKey`.
        let id = seeded();
        assert_eq!(id.signing_public_key(), id.signing_public_key());
        assert_eq!(id.sign(b"same message"), id.sign(b"same message"));
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

    /// §5.1 back-compat gate for WS1 (dig-constants adoption): the per-profile DEK derivation is
    /// byte-identical BEFORE and AFTER sourcing its salt/version/label/length from `dig_constants`.
    ///
    /// This reconstructs the PRE-refactor DEK construction from the OLD hard-coded literals (the
    /// exact bytes shipped before this change: salt `dig-app:dek-salt:v1`, IKM prefix `2`, label
    /// `dig-app:profile-dek:v2`, 32-byte output) and proves a blob sealed with the OLD-derived DEK
    /// opens under the NEW [`open_data`](IdentitySecrets::open_data) path, AND a blob sealed with the
    /// NEW [`seal_data`](IdentitySecrets::seal_data) path opens under the OLD-derived DEK. If the
    /// dig-constants values ever drift from these frozen literals, this test fails — which is what
    /// keeps already-sealed profiles readable (a drift would lock users out).
    #[test]
    fn dek_is_byte_identical_across_the_dig_constants_swap() {
        // The OLD construction, reproduced from literals exactly as it was before WS1.
        fn old_dek_password(id: &IdentitySecrets) -> Password {
            const OLD_DEK_SALT: &[u8] = b"dig-app:dek-salt:v1";
            const OLD_DEK_INFO: &[u8] = b"dig-app:profile-dek:v2";
            let ikm = id.to_sealed_bytes(); // 0x02 || scalar — the versioned at-rest layout
            let hkdf = Hkdf::<Sha256>::new(Some(OLD_DEK_SALT), &*ikm);
            let mut dek = Zeroizing::new([0u8; 32]);
            hkdf.expand(OLD_DEK_INFO, &mut *dek)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            Password::new(*dek)
        }

        let id = seeded();

        // OLD-sealed blob opens under the NEW path.
        let old_sealed = opaque::seal(
            &old_dek_password(&id),
            b"profile blob",
            KdfParams::FAST_TEST,
        )
        .unwrap();
        assert_eq!(
            &*id.open_data(&old_sealed).unwrap(),
            b"profile blob",
            "a blob sealed with the pre-swap DEK must open under the dig-constants-sourced DEK"
        );

        // NEW-sealed blob opens under the OLD-derived DEK.
        let new_sealed = id.seal_data(b"profile blob", KdfParams::FAST_TEST).unwrap();
        let reopened = opaque::open(&old_dek_password(&id), &new_sealed).unwrap();
        assert_eq!(
            &reopened[..],
            b"profile blob",
            "a blob sealed with the dig-constants-sourced DEK must open under the pre-swap DEK"
        );
    }

    #[test]
    fn two_generations_differ() {
        let a = IdentitySecrets::generate();
        let b = IdentitySecrets::generate();
        assert_ne!(a.signing_public_key(), b.signing_public_key());
    }
}
