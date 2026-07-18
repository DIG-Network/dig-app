//! The REAL [`ProfileSealer`] — U4 key management wired into the U5 profile layer (security-critical).
//!
//! This is the production side of the [`sealer`](super::sealer) seam. Where U5 owns *which* bytes are
//! sealed and *where* they live, this module supplies the *crypto*: every per-profile blob is sealed
//! with dig-keystore **DIGOP1** (AES-256-GCM) under that profile's own **data-encryption key (DEK)**,
//! and the DEK is [HKDF-derived from that profile's identity key](crate::keystore::IdentitySecrets::seal_data)
//! (SPEC §3.1). There is exactly one at-rest crypto path in the app — this one.
//!
//! # Cross-profile isolation is cryptographic, not conventional (the F1 property)
//!
//! Each profile is provisioned with its OWN freshly generated [`IdentitySecrets`], so each profile's
//! DEK is a distinct 256-bit key derived from distinct key material. Sealing profile A's data uses
//! A's identity-DEK; opening it requires that same DEK. Profile B holds a different identity, hence a
//! different DEK, so B's `open` fails the AEAD authentication tag — B can never read A's blob. The
//! isolation therefore holds by the cipher, not by a filesystem convention: even an attacker who
//! swaps sealed files between profile directories gains nothing, because the bytes are undecryptable
//! without the owning profile's key.
//!
//! # Which identities can seal — the session store
//!
//! A [`ProfileSealer`] is addressed by a profile DID, so the sealer must map a DID to that profile's
//! unlocked identity. That mapping is the [`UnlockedIdentities`] session store, shared with the
//! provisioner that generates the keys ([`super::keygen_provisioner`]). Only an *unlocked* profile
//! (its identity present in the store) can seal or open its data; a locked profile fails closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dig_keystore::KdfParams;

use crate::keystore::IdentitySecrets;

use super::sealer::{ProfileSealer, SealError};

/// The profile identities unlocked in the current session, keyed by DID.
///
/// Shared (cheap-clone [`Arc`]) between the [`KeystoreSealer`] — which seals/opens each profile's
/// blobs under its identity-DEK — and the provisioner that generates a new profile's identity and
/// registers it here. A profile whose identity is not in this store is *locked*: its data cannot be
/// sealed or opened until it is unlocked (SPEC §3, the bootstrap-unlock step).
#[derive(Clone, Default)]
pub struct UnlockedIdentities {
    inner: Arc<Mutex<HashMap<String, IdentitySecrets>>>,
}

impl UnlockedIdentities {
    /// A fresh, empty session store (no profile unlocked yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `identity` as the unlocked identity for `did`, so its blobs can be sealed and opened.
    pub fn unlock(&self, did: impl Into<String>, identity: IdentitySecrets) {
        self.lock_map().insert(did.into(), identity);
    }

    /// Drops the unlocked identity for `did` (logout / profile detach), erasing its keys from memory
    /// and locking its data again.
    pub fn lock_profile(&self, did: &str) {
        self.lock_map().remove(did);
    }

    /// Drops EVERY unlocked identity from memory (a whole-session lock), erasing all profile keys and
    /// locking all profile data again. This is the primitive a session-lock event
    /// ([`crate::session_lock`]) drives on idle timeout / OS screen lock / one-tap lock-now: the
    /// `IdentitySecrets` values are zeroized on drop, so clearing the map re-seals the session.
    pub fn lock_all(&self) {
        self.lock_map().clear();
    }

    /// Whether any profile is currently unlocked in this session. A session-lock controller reads this
    /// to know whether a lock event actually has key material to drop, and to gate whether the next
    /// signing needs re-authentication.
    pub fn is_any_unlocked(&self) -> bool {
        !self.lock_map().is_empty()
    }

    /// Whether `did`'s identity is currently unlocked in this session (its data can be sealed/opened).
    pub fn is_unlocked(&self, did: &str) -> bool {
        self.lock_map().contains_key(did)
    }

    /// The Ed25519 signing public key of `did`'s unlocked identity, or `None` if it is locked. The
    /// private key never leaves the session — only its public half is exposed.
    pub fn signing_public_key(&self, did: &str) -> Option<[u8; 32]> {
        self.with_identity(did, |identity| identity.signing_public_key())
    }

    /// Sign `message` with `did`'s unlocked Ed25519 identity key (slot `0x0010`), returning only the
    /// detached signature, or `None` if that profile is locked. The private key never leaves the
    /// session — the caller receives a signature, never the key — so this is the custody-preserving
    /// seam a [`crate::session::SessionSigner`] over the active profile delegates to.
    ///
    /// The caller is responsible for domain-separating `message` (every 0x0010 signature carries a
    /// unique per-purpose tag); this method signs exactly the bytes it is given.
    pub fn sign(&self, did: &str, message: &[u8]) -> Option<[u8; crate::keystore::SIGNATURE_LEN]> {
        self.with_identity(did, |identity| identity.sign(message))
    }

    /// Runs `f` against the unlocked identity for `did`, or returns `None` if that profile is locked.
    fn with_identity<T>(&self, did: &str, f: impl FnOnce(&IdentitySecrets) -> T) -> Option<T> {
        self.lock_map().get(did).map(f)
    }

    /// A poisoned mutex means another thread panicked mid-seal — an unrecoverable custody-state bug,
    /// so we fail loudly rather than risk operating on half-updated key material.
    fn lock_map(&self) -> std::sync::MutexGuard<'_, HashMap<String, IdentitySecrets>> {
        self.inner
            .lock()
            .expect("unlocked-identities mutex poisoned")
    }
}

/// The production [`ProfileSealer`]: seals per-profile blobs under each profile's identity-derived
/// DEK via U4's [`IdentitySecrets`], resolving the profile's identity from a shared
/// [`UnlockedIdentities`] session store.
pub struct KeystoreSealer {
    identities: UnlockedIdentities,
    kdf: KdfParams,
}

impl KeystoreSealer {
    /// Builds a sealer over `identities` using the production KDF cost parameters.
    pub fn new(identities: UnlockedIdentities) -> Self {
        Self::with_kdf(identities, KdfParams::DEFAULT)
    }

    /// Builds a sealer with explicit KDF parameters. Production uses [`KeystoreSealer::new`]; tests
    /// pass [`KdfParams::FAST_TEST`] to keep Argon2 cheap.
    pub fn with_kdf(identities: UnlockedIdentities, kdf: KdfParams) -> Self {
        Self { identities, kdf }
    }
}

impl ProfileSealer for KeystoreSealer {
    fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        self.identities
            .with_identity(profile_did, |identity| {
                identity.seal_data(plaintext, self.kdf)
            })
            .ok_or_else(|| SealError::Seal(format!("profile {profile_did} is locked")))?
            .map_err(|e| SealError::Seal(e.to_string()))
    }

    fn open(
        &self,
        profile_did: &str,
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SealError> {
        // A locked profile cannot attempt an open; an unlocked profile whose DEK did not seal these
        // bytes fails the AEAD tag and surfaces `Open` — the cross-profile isolation signal. The
        // plaintext stays in the zeroizing buffer U4 returns (F-3) — no `to_vec()` copy escapes it.
        self.identities
            .with_identity(profile_did, |identity| identity.open_data(ciphertext))
            .ok_or_else(|| SealError::Seal(format!("profile {profile_did} is locked")))?
            .map_err(|_| SealError::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "did:chia:profile-a";
    const B: &str = "did:chia:profile-b";

    /// Builds a fast (test-KDF) sealer with `dids` unlocked to fresh, distinct identities.
    fn sealer_with(dids: &[&str]) -> KeystoreSealer {
        let identities = UnlockedIdentities::new();
        for did in dids {
            identities.unlock(*did, IdentitySecrets::generate());
        }
        KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST)
    }

    #[test]
    fn seal_then_open_round_trips_for_the_owning_profile() {
        let sealer = sealer_with(&[A]);
        let blob = sealer.seal(A, b"subscriptions").unwrap();
        assert_ne!(blob, b"subscriptions", "data must be ciphertext at rest");
        assert_eq!(&sealer.open(A, &blob).unwrap()[..], b"subscriptions");
    }

    #[test]
    fn a_foreign_profiles_dek_cannot_open_the_blob() {
        // The F1 property at the unit level: A's blob is undecryptable under B's distinct identity.
        let sealer = sealer_with(&[A, B]);
        let blob = sealer.seal(A, b"secret").unwrap();
        assert!(matches!(sealer.open(B, &blob), Err(SealError::Open)));
    }

    #[test]
    fn a_locked_profile_fails_closed_on_seal_and_open() {
        let sealer = sealer_with(&[]);
        assert!(matches!(sealer.seal(A, b"x"), Err(SealError::Seal(_))));
        assert!(matches!(sealer.open(A, b"x"), Err(SealError::Seal(_))));
    }

    #[test]
    fn locking_a_profile_revokes_its_ability_to_open() {
        let identities = UnlockedIdentities::new();
        identities.unlock(A, IdentitySecrets::generate());
        let sealer = KeystoreSealer::with_kdf(identities.clone(), KdfParams::FAST_TEST);
        let blob = sealer.seal(A, b"data").unwrap();

        identities.lock_profile(A);
        assert!(
            matches!(sealer.open(A, &blob), Err(SealError::Seal(_))),
            "a locked profile can no longer open its own data"
        );
    }

    #[test]
    fn lock_all_drops_every_unlocked_identity() {
        let identities = UnlockedIdentities::new();
        identities.unlock(A, IdentitySecrets::generate());
        identities.unlock(B, IdentitySecrets::generate());
        assert!(identities.is_any_unlocked());

        identities.lock_all();

        assert!(
            !identities.is_any_unlocked(),
            "a whole-session lock drops all DEKs"
        );
        assert!(!identities.is_unlocked(A));
        assert!(!identities.is_unlocked(B));
    }

    #[test]
    fn is_any_unlocked_tracks_the_session() {
        let identities = UnlockedIdentities::new();
        assert!(
            !identities.is_any_unlocked(),
            "a fresh session has nothing unlocked"
        );
        identities.unlock(A, IdentitySecrets::generate());
        assert!(identities.is_any_unlocked());
        identities.lock_profile(A);
        assert!(!identities.is_any_unlocked());
    }

    #[test]
    fn production_kdf_constructor_round_trips() {
        // `new` uses the production Argon2 cost; one round-trip proves the DEFAULT path is wired.
        let identities = UnlockedIdentities::new();
        identities.unlock(A, IdentitySecrets::generate());
        let sealer = KeystoreSealer::new(identities);
        let blob = sealer.seal(A, b"prod").unwrap();
        assert_eq!(&sealer.open(A, &blob).unwrap()[..], b"prod");
    }
}
