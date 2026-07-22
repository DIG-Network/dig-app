//! Custody byte-contract: the per-profile DEK derived through dig-session's master-HD facade is
//! byte-identical to dig-app's prior (pre-cutover) `keystore/secrets.rs` HKDF construction for the
//! same identity scalar (#1024 Phase 2, §5.1 at-rest back-compat / NC-2).
//!
//! This is the load-bearing custody proof of the identity/DEK cutover. After the cutover, dig-app
//! routes ALL at-rest DEK derivation through `UnlockedMasterSeed::profile_derive_symmetric_key` —
//! never a local re-derive. If that facade's output ever drifted from the frozen construction, every
//! already-sealed profile blob would become unreadable (a permanent lock-out). These tests fail
//! CLOSED on any such drift.
//!
//! The reference construction here is deliberately reproduced from LITERAL bytes (not imported from
//! production code), so a drift on EITHER side — dig-session's facade OR dig-app's frozen contract —
//! is caught rather than masked by a shared helper.

use std::sync::Arc;

use dig_constants::{DEK_SALT, IDENTITY_IKM_VERSION, PROFILE_DEK_LABEL};
use dig_identity::{
    derive_identity_sk, derive_identity_sk_at, master_secret_key_from_seed, public_key_bytes,
};
use dig_keystore::{opaque, KdfParams};
use dig_session::{BackendKey, FileBackend, Password, Session, SEED_LEN};
use hkdf::Hkdf;
use sha2::Sha256;

/// A fixed 32-byte master seed — the golden anchor. Every derived value below is deterministic in it.
const SEED: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const PASSWORD: &str = "correct horse battery staple";

/// A live master-seed handle enrolled to a throwaway file-backed keystore. The `FileBackend` +
/// on-disk keystore is the real production storage path (no test-only backend feature needed).
fn enrolled_handle(dir: &std::path::Path) -> dig_session::UnlockedMasterSeed {
    let backend = Arc::new(FileBackend::new(dir));
    Session::enroll_master_seed(
        backend,
        BackendKey::new("seed"),
        Password::new(PASSWORD),
        &SEED,
    )
    .expect("enroll master seed")
}

/// Independently reconstruct dig-app's pre-cutover per-profile DEK from a raw identity scalar, using
/// the EXACT literal HKDF construction that shipped in `keystore/secrets.rs::dek_password`
/// (`HKDF-SHA256(ikm = 0x02 || scalar, salt = "dig-app:dek-salt:v1", info = label) -> 32B`). Kept as
/// literals so a drift in the frozen contract is caught here, not silently absorbed.
fn dig_app_reference_dek(identity_scalar: &[u8; 32], label: &[u8]) -> [u8; 32] {
    // The pre-cutover IKM is the versioned at-rest layout: SEALED_IDENTITY_VERSION (0x02) || scalar.
    let mut ikm = Vec::with_capacity(33);
    ikm.push(0x02u8);
    ikm.extend_from_slice(identity_scalar);

    let hkdf = Hkdf::<Sha256>::new(Some(b"dig-app:dek-salt:v1"), &ikm);
    let mut dek = [0u8; 32];
    hkdf.expand(label, &mut dek).unwrap();
    dek
}

#[test]
fn the_frozen_dig_constants_match_the_literal_pre_cutover_bytes() {
    // Guards the reference above: the canonical constants dig-session derives from ARE the exact
    // literals dig-app shipped pre-cutover. If dig-constants ever changed these, the whole back-compat
    // guarantee (and every already-sealed profile) would be silently invalidated.
    assert_eq!(DEK_SALT, b"dig-app:dek-salt:v1");
    assert_eq!(IDENTITY_IKM_VERSION, 0x02);
    assert_eq!(PROFILE_DEK_LABEL, b"dig-app:profile-dek:v2");
}

#[test]
fn profile0_dek_through_dig_session_equals_the_pre_cutover_construction() {
    // THE cross-round-trip byte-contract: the DEK dig-app now derives via the facade
    // (`profile_derive_symmetric_key(0, PROFILE_DEK_LABEL)`) is byte-identical to the DEK dig-app
    // derived pre-cutover for the same identity scalar. Profile 0 is the default/back-compat path.
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_handle(dir.path());

    let profile0_scalar = derive_identity_sk_at(&master_secret_key_from_seed(&SEED), 0).to_bytes();
    let reference = dig_app_reference_dek(&profile0_scalar, PROFILE_DEK_LABEL);

    let via_facade = handle.profile_derive_symmetric_key(0, PROFILE_DEK_LABEL);

    assert_eq!(
        &*via_facade, &reference,
        "dig-session's profile-0 DEK must be byte-identical to dig-app's pre-cutover DEK — a drift \
         would permanently lock out every already-sealed profile blob"
    );
}

#[test]
fn a_blob_sealed_under_the_facade_dek_opens_under_the_reference_dek_and_vice_versa() {
    // The at-rest back-compat guarantee end-to-end: a blob sealed with the facade-derived DEK opens
    // under the independently-reconstructed pre-cutover DEK, and vice versa — proving already-sealed
    // data stays readable after the cutover (§5.1 / NC-2).
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_handle(dir.path());

    let profile0_scalar = derive_identity_sk_at(&master_secret_key_from_seed(&SEED), 0).to_bytes();
    let reference_dek = dig_app_reference_dek(&profile0_scalar, PROFILE_DEK_LABEL);
    let facade_dek = handle.profile_derive_symmetric_key(0, PROFILE_DEK_LABEL);

    // Facade-sealed opens under the reference DEK.
    let facade_sealed = opaque::seal(
        &Password::new(*facade_dek),
        b"profile blob",
        KdfParams::FAST_TEST,
    )
    .unwrap();
    let opened = opaque::open(&Password::new(reference_dek), &facade_sealed).unwrap();
    assert_eq!(&opened[..], b"profile blob");

    // Reference-sealed opens under the facade DEK.
    let ref_sealed = opaque::seal(
        &Password::new(reference_dek),
        b"profile blob",
        KdfParams::FAST_TEST,
    )
    .unwrap();
    let opened = opaque::open(&Password::new(*facade_dek), &ref_sealed).unwrap();
    assert_eq!(&opened[..], b"profile blob");
}

#[test]
fn profile0_public_key_equals_the_default_identity_key() {
    // Additive property (#5.1): profile index 0 IS the pre-cutover default identity, so
    // `profile_public_key(0)` byte-equals the canonical `derive_identity_sk` key the DID anchors.
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_handle(dir.path());

    let expected = public_key_bytes(&derive_identity_sk(&master_secret_key_from_seed(&SEED)));
    assert_eq!(handle.profile_public_key(0), expected);
    assert_eq!(handle.profile_public_key(0), handle.public_key());
}

#[test]
fn distinct_profiles_yield_distinct_keys_and_deks() {
    // Cross-profile isolation at the derivation level: each profile index yields a distinct identity
    // key AND a distinct DEK, so one profile's DEK can never open another's blob.
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_handle(dir.path());

    assert_ne!(handle.profile_public_key(0), handle.profile_public_key(1));
    assert_ne!(
        &*handle.profile_derive_symmetric_key(0, PROFILE_DEK_LABEL),
        &*handle.profile_derive_symmetric_key(1, PROFILE_DEK_LABEL),
    );
}
