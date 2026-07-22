//! Acceptance e2e for the master-HD custody model (#1024 Phase 2, Model A / #997): ONE master seed
//! enrolled at rest, LOCKED (handle dropped), UNLOCKED again from the persisted keystore, then a
//! per-profile identity signature that VERIFIES against the per-profile public key — plus
//! cross-profile isolation (profile 1's keys + DEK are distinct from profile 0's).
//!
//! This exercises the real dig-session storage path (FileBackend + on-disk keystore, AES-256-GCM +
//! Argon2id at rest, NC-2/NC-3) end to end, using the exact primitives dig-app routes through after
//! the cutover — never a hand-rolled cipher or signature.

use std::sync::Arc;

use dig_constants::PROFILE_DEK_LABEL;
use dig_identity::verify_signature;
use dig_session::{BackendKey, FileBackend, Password, Session, SEED_LEN};

const SEED: [u8; SEED_LEN] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
const PASSWORD: &str = "correct horse battery staple";
const WRONG_PASSWORD: &str = "Tr0ub4dor&3";

#[test]
fn enroll_lock_unlock_then_a_profile_signature_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FileBackend::new(dir.path()));
    let key = BackendKey::new("master-seed");

    // ENROLL: persist the master seed encrypted at rest, capture profile-0's public key for later.
    let profile0_pk = {
        let handle = Session::enroll_master_seed(
            backend.clone(),
            key.clone(),
            Password::new(PASSWORD),
            &SEED,
        )
        .expect("enroll");
        handle.profile_public_key(0)
        // LOCK: the handle drops here — the seed is wiped from memory, only the ciphertext remains.
    };

    // UNLOCK: re-open the persisted keystore with the password and sign as profile 0.
    let handle =
        Session::unlock_master_seed(backend, key, Password::new(PASSWORD)).expect("unlock");
    let message = b"DIGNET-SIGN-v1: attach challenge";
    let signature = handle.profile_sign(0, message);

    // VERIFY: the signature verifies against the pre-lock profile-0 public key — proving the same key
    // survived lock→unlock and that signing routes through the dig-identity BLS primitive.
    assert_eq!(handle.profile_public_key(0), profile0_pk);
    assert!(
        verify_signature(&profile0_pk, message, &signature),
        "a profile-0 signature must verify against profile-0's public key after lock→unlock"
    );
}

#[test]
fn unlock_with_a_wrong_password_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FileBackend::new(dir.path()));
    let key = BackendKey::new("master-seed");
    Session::enroll_master_seed(backend.clone(), key.clone(), Password::new(PASSWORD), &SEED)
        .expect("enroll");

    // A wrong password fails the AEAD tag — no seed, no key material recovered (fail-closed).
    assert!(
        Session::unlock_master_seed(backend, key, Password::new(WRONG_PASSWORD)).is_err(),
        "a wrong password must fail closed, never yielding a usable handle"
    );
}

#[test]
fn profiles_are_cryptographically_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FileBackend::new(dir.path()));
    let handle = Session::enroll_master_seed(
        backend,
        BackendKey::new("master-seed"),
        Password::new(PASSWORD),
        &SEED,
    )
    .expect("enroll");

    // Distinct identity keys per profile index.
    assert_ne!(handle.profile_public_key(0), handle.profile_public_key(1));

    // Distinct DEKs per profile index — profile 0's DEK can never open profile 1's blob.
    let dek0 = handle.profile_derive_symmetric_key(0, PROFILE_DEK_LABEL);
    let dek1 = handle.profile_derive_symmetric_key(1, PROFILE_DEK_LABEL);
    assert_ne!(&*dek0, &*dek1);

    // A profile-1 signature does NOT verify under profile-0's key (no cross-profile forgery).
    let sig1 = handle.profile_sign(1, b"msg");
    assert!(!verify_signature(
        &handle.profile_public_key(0),
        b"msg",
        &sig1
    ));
}
