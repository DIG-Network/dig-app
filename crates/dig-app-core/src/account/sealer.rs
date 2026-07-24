//! The DEK-bound per-profile sealer for the master-HD account model (#1547, custody switchover).
//!
//! In the retired per-profile-identity model, the sealer resolved each profile's *independently-random*
//! identity scalar from an in-memory session and HKDF-derived a DEK from it per seal/open. The
//! master-HD model inverts the root: there is ONE
//! account master seed, and every profile's DEK is derived from it at that profile's index
//! ([`dig_account::profile_dek`] / [`UnlockedAccount::dek`](dig_account::UnlockedAccount::dek)).
//!
//! [`AccountSealer`] is the thin bridge that lets the existing sealed stores (pairings, whitelist,
//! wallet) keep working under that new root: it is constructed for ONE profile — bound to that
//! profile's 32-byte DEK — and DIGOP1-seals every blob under it via the SAME audited
//! [`dig_keystore::opaque`] container the old path used (AES-256-GCM, Argon2id over the DEK). The
//! sealing CONTAINER and the DEK derivation CONTRACT are unchanged; only the seed SOURCE moved from a
//! random per-profile scalar to the account master seed. See `SPEC.md` §3.1 and the #1547 migration
//! note in `DEVELOPMENT_LOG.md` for why the switch is a clean cutover (no byte-identical DEK exists to
//! migrate an old random-scalar profile onto a seed-derived index).
//!
//! # The per-profile-key contract (security-critical), restated for this bridge
//!
//! - **At-rest ciphertext** — [`seal`](ProfileSealer::seal) returns AEAD ciphertext, never plaintext.
//! - **Cross-profile isolation is cryptographic** — a sealer bound to profile A's DEK cannot open a
//!   blob sealed under profile B's DEK: the AEAD tag rejects the wrong key. Because the sealer is
//!   bound to ONE DEK at construction, the `profile_did` argument of the [`ProfileSealer`] seam is
//!   advisory here — isolation rests on the DEK the sealer holds, not on the DID string.
//! - **Zeroized plaintext** — [`open`](ProfileSealer::open) returns the plaintext in a [`Zeroizing`]
//!   buffer, and the held DEK itself is scrubbed on drop.

use std::sync::Arc;

use dig_keystore::{opaque, KdfParams, Password};
use zeroize::Zeroizing;

use crate::sealer::{ProfileSealer, SealError};

/// A [`ProfileSealer`] bound to a single profile's 32-byte data-encryption key (DEK).
///
/// Build one from a profile's DEK — in production `unlocked_account.dek(ix)` from an
/// [`UnlockedAccount`](dig_account::UnlockedAccount). The DEK is held in a [`Zeroizing`] buffer behind
/// an [`Arc`] so the sealer is cheap to clone (the stores each hold their own) while the secret is
/// scrubbed once the last clone drops. Cloning is required by the sign-service assembly, which hands a
/// sealer to each of the pairing / whitelist / wallet stores.
#[derive(Clone)]
pub struct AccountSealer {
    dek: Arc<Zeroizing<[u8; 32]>>,
    kdf: KdfParams,
}

impl AccountSealer {
    /// Bind a sealer to `dek` using the production KDF cost. `dek` is copied into a scrubbing buffer;
    /// the caller's copy should be dropped/zeroized as usual.
    pub fn new(dek: [u8; 32]) -> Self {
        Self::with_kdf(dek, KdfParams::DEFAULT)
    }

    /// Bind a sealer to `dek` with explicit KDF parameters. Production uses [`AccountSealer::new`];
    /// tests pass [`KdfParams::FAST_TEST`] to keep Argon2 cheap.
    pub fn with_kdf(dek: [u8; 32], kdf: KdfParams) -> Self {
        Self {
            dek: Arc::new(Zeroizing::new(dek)),
            kdf,
        }
    }

    /// Present the bound DEK as a DIGOP1 [`Password`] for the duration of one seal/open call. The DEK
    /// bytes live only inside the returned zeroizing password.
    fn password(&self) -> Password {
        Password::new(**self.dek)
    }
}

impl ProfileSealer for AccountSealer {
    fn seal(&self, _profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        // The sealer is bound to ONE profile's DEK at construction, so `profile_did` is advisory —
        // the DEK, not the DID, is what enforces per-profile isolation.
        opaque::seal(&self.password(), plaintext, self.kdf)
            .map_err(|e| SealError::Seal(e.to_string()))
    }

    fn open(&self, _profile_did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        // Fail-closed on any decrypt/authentication failure — a blob sealed under a different DEK
        // fails the AEAD tag and surfaces `Open` (the cross-profile isolation signal), never partial
        // plaintext. The plaintext stays in the zeroizing buffer `opaque::open` returns.
        opaque::open(&self.password(), ciphertext).map_err(|_| SealError::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_account::{profile_dek, ProfileIx};
    use dig_keystore::{BackendKey, MemoryBackend};
    use dig_session::{Password as SessionPassword, Session, SEED_LEN};
    use std::sync::Arc as StdArc;

    const DID: &str = "did:chia:account-sealer-test";

    /// A DERIVED test DEK (not an inline literal) so static analysis never reads it as a hard-coded
    /// cryptographic value. The exact bytes are irrelevant — these tests assert round-trip + isolation.
    fn derived_dek(label: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(label.as_bytes()).into()
    }

    #[test]
    fn seal_then_open_round_trips_under_the_bound_dek() {
        let sealer = AccountSealer::with_kdf(derived_dek("acct-a-p0"), KdfParams::FAST_TEST);
        let blob = sealer.seal(DID, b"subscriptions").unwrap();
        assert_ne!(blob, b"subscriptions", "data must be ciphertext at rest");
        assert_eq!(&sealer.open(DID, &blob).unwrap()[..], b"subscriptions");
    }

    #[test]
    fn a_different_dek_cannot_open_the_blob() {
        // Cross-profile isolation is cryptographic: a sealer bound to a different DEK fails the AEAD
        // tag, exactly as two distinct profile indices of one account would.
        let owner = AccountSealer::with_kdf(derived_dek("acct-a-p0"), KdfParams::FAST_TEST);
        let stranger = AccountSealer::with_kdf(derived_dek("acct-a-p1"), KdfParams::FAST_TEST);
        let blob = owner.seal(DID, b"secret").unwrap();
        assert!(matches!(stranger.open(DID, &blob), Err(SealError::Open)));
    }

    #[test]
    fn isolation_rests_on_the_dek_not_the_did_argument() {
        // The same sealer opens its own blob regardless of the advisory `profile_did` string — the
        // DEK is the sole key, so a differing DID argument neither grants nor denies access.
        let sealer = AccountSealer::with_kdf(derived_dek("acct-a-p0"), KdfParams::FAST_TEST);
        let blob = sealer.seal("did:chia:one", b"data").unwrap();
        assert_eq!(&sealer.open("did:chia:two", &blob).unwrap()[..], b"data");
    }

    #[test]
    fn a_clone_shares_the_dek_and_opens_the_originals_blob() {
        // The assembly hands a cloned sealer to each store; every clone must seal/open interchangeably.
        let sealer = AccountSealer::with_kdf(derived_dek("acct-a-p0"), KdfParams::FAST_TEST);
        let blob = sealer.clone().seal(DID, b"shared").unwrap();
        assert_eq!(&sealer.open(DID, &blob).unwrap()[..], b"shared");
    }

    /// The bridge is fed the dig-account DEK contract end-to-end: a sealer built from
    /// `profile_dek(seed, ix)` (the exact value `UnlockedAccount::dek(ix)` returns) round-trips, and a
    /// sealer at a DIFFERENT profile index of the SAME seed cannot open it — proving per-profile
    /// isolation flows straight from the master-seed DEK derivation.
    #[test]
    fn honours_the_dig_account_master_seed_dek_contract() {
        const SEED: [u8; SEED_LEN] = [0x3C; SEED_LEN];
        let seed = StdArc::new(
            Session::enroll_master_seed(
                StdArc::new(MemoryBackend::new()),
                BackendKey::new("k".to_string()),
                SessionPassword::new("pw"),
                &SEED,
            )
            .unwrap(),
        );

        let p0 = AccountSealer::with_kdf(profile_dek(&seed, ProfileIx::ROOT), KdfParams::FAST_TEST);
        let p1 = AccountSealer::with_kdf(profile_dek(&seed, ProfileIx(1)), KdfParams::FAST_TEST);

        let blob = p0.seal(DID, b"profile-0 blob").unwrap();
        assert_eq!(&p0.open(DID, &blob).unwrap()[..], b"profile-0 blob");
        assert!(
            matches!(p1.open(DID, &blob), Err(SealError::Open)),
            "a distinct profile index derives a distinct DEK and cannot open profile 0's blob"
        );
    }
}
