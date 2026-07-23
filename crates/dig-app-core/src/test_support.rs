//! Shared test doubles for the master-HD custody path (test-only).
//!
//! The retired per-profile-identity tests built a `KeystoreSealer` + `ProfileSessionSigner` over an
//! in-memory `UnlockedIdentities` session. The live path is the master-HD
//! [`AccountResidency`](crate::account::residency::AccountResidency), so these helpers give every test
//! module ONE way to build the two seams the loopback/pairing/whitelist/wallet stores depend on:
//!
//! - [`test_sealer`] — a cheap-KDF [`AccountSealer`] at a deterministic per-label DEK. Two sealers
//!   built from the SAME label share a DEK (so a "restart" round-trips a sealed blob); DISTINCT labels
//!   derive DISTINCT DEKs, which is exactly the model's cross-profile isolation (isolation rests on the
//!   DEK, not on the advisory DID argument — see [`crate::account::sealer`]).
//! - [`test_residency`] — a freshly-enrolled, unlocked residency; call `.signer(ProfileIx::ROOT)` for
//!   its live-view [`SessionSigner`], which fails closed the instant the residency is locked
//!   ([`lock_all`](crate::session_lock::SessionKeys::lock_all)).

use std::sync::Arc;

use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
use dig_keystore::{KdfParams, MemoryBackend};
use dig_session::{Password, SEED_LEN};
use sha2::{Digest, Sha256};

use crate::account::residency::AccountResidency;
use crate::account::sealer::AccountSealer;

/// A cheap-KDF [`AccountSealer`] bound to a DEK deterministically derived from `label`. Same label →
/// same DEK (a persisted blob re-opens across a simulated restart); different label → different DEK
/// (cross-profile isolation, cryptographically enforced by the AEAD tag).
pub fn test_sealer(label: &str) -> AccountSealer {
    let dek: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    AccountSealer::with_kdf(dek, KdfParams::FAST_TEST)
}

/// A freshly-enrolled, unlocked master-HD residency over a random seed. Cheap (an in-memory keystore
/// backend); each call is an independent account with its own key material.
pub fn test_residency() -> AccountResidency {
    use rand_core::RngCore;
    let mut seed = [0u8; SEED_LEN];
    rand_core::OsRng.fill_bytes(&mut seed);
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("test-account"),
        Password::new("pw"),
        &seed,
        ProfileIx::ROOT,
    )
    .expect("enrol a fresh test account");
    AccountResidency::new(unlocked)
}
