//! Custody byte-contract: the DIG buyer key re-sourced from the ONE master seed (post-cutover)
//! reproduces the EXACT synthetic standard-layer key + puzzle hash the pre-cutover separate
//! `WalletKey` seed produced (#1024 Phase 2, money-path Option A / Model A).
//!
//! The cutover collapses the separately-stored wallet seed onto the single dig-session master seed:
//! `UnlockedMasterSeed::master_seed()` → `master_to_wallet_unhardened(master, 0).derive_synthetic()`
//! (chip35, UNCHANGED). This proves that for the same 32-byte value used both as the old wallet seed
//! AND the new master seed, the derived on-chain key/address are identical — so a user who re-onboards
//! with the same mnemonic keeps every existing DIG/XCH coin spendable. The derivation itself is never
//! hand-rolled: it is chip35's canonical `master_to_wallet_unhardened(..).derive_synthetic()`.

use std::sync::Arc;

use chia_bls::SecretKey;
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chip35_dl_coin::master_to_wallet_unhardened;
use dig_app_core::wallet::signing::WalletKey;
use dig_session::{BackendKey, FileBackend, Password, Session, SEED_LEN};

/// A fixed 32-byte master seed — the golden anchor shared by the identity and money paths.
const SEED: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const PASSWORD: &str = "correct horse battery staple";

fn enrolled_master_seed(dir: &std::path::Path) -> dig_session::UnlockedMasterSeed {
    let backend = Arc::new(FileBackend::new(dir));
    Session::enroll_master_seed(
        backend,
        BackendKey::new("seed"),
        Password::new(PASSWORD),
        &SEED,
    )
    .expect("enroll master seed")
}

#[test]
fn buyer_key_resourced_from_the_master_seed_reproduces_the_pre_cutover_synthetic_key() {
    // THE money-path byte-contract: build the wallet key from the master seed exposed by dig-session
    // and assert it equals the pre-cutover WalletKey built directly from the same 32-byte seed. Since
    // the derivation function (chip35) is unchanged, an identical seed must give an identical key.
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_master_seed(dir.path());
    let master_seed = handle.master_seed();

    let resourced = WalletKey::from_seed(*master_seed);
    let pre_cutover = WalletKey::from_seed(SEED);

    assert_eq!(
        resourced.public_key(),
        pre_cutover.public_key(),
        "the master-seed-sourced buyer key must reproduce the pre-cutover synthetic public key"
    );
    assert_eq!(
        resourced.puzzle_hash(),
        pre_cutover.puzzle_hash(),
        "same synthetic key ⇒ same standard puzzle hash ⇒ existing coins stay spendable"
    );
}

#[test]
fn the_resourced_key_matches_the_canonical_chip35_derivation() {
    // Independently re-derive via chip35's canonical public-only path from the master seed and assert
    // equality — proving the buyer key is exactly the synthetic standard-layer key on-chain coins pay,
    // and that dig-session's master_seed() feeds the derivation the correct seed bytes.
    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_master_seed(dir.path());
    let master_seed = handle.master_seed();

    let expected =
        master_to_wallet_unhardened(&SecretKey::from_seed(&*master_seed).public_key(), 0)
            .derive_synthetic();
    let expected_ph: chia_protocol::Bytes32 = StandardArgs::curry_tree_hash(expected).into();

    let resourced = WalletKey::from_seed(*master_seed);
    assert_eq!(resourced.public_key(), expected);
    assert_eq!(resourced.puzzle_hash(), expected_ph);
}

#[test]
fn the_agg_sig_unsafe_signing_oracle_guard_still_rejects_a_non_payment_message() {
    // The audited signing-oracle guard (wallet/signing.rs:146-171) must survive the cutover: a
    // caller-fabricated AGG_SIG_UNSAFE over attacker-chosen bytes, addressed to the wallet's own key,
    // fails CLOSED — the re-sourced wallet key is no more a signing oracle than the pre-cutover one.
    use chia_protocol::{Bytes, Coin, CoinSpend};
    use chia_sdk_driver::SpendContext;
    use chia_sdk_types::conditions::{AggSig, AggSigKind};

    let dir = tempfile::tempdir().unwrap();
    let handle = enrolled_master_seed(dir.path());
    let key = WalletKey::from_seed(*handle.master_seed());

    // A fabricated identity-puzzle coin emitting AGG_SIG_UNSAFE(wallet_pk, attacker_message).
    let mut ctx = SpendContext::new();
    let identity_puzzle = ctx.alloc(&1).unwrap();
    let conditions = vec![AggSig::new(
        AggSigKind::Unsafe,
        key.public_key(),
        Bytes::from(b"transfer all funds to mallory".to_vec()),
    )];
    let solution = ctx.alloc(&conditions).unwrap();
    let puzzle_reveal = ctx.serialize(&identity_puzzle).unwrap();
    let solution = ctx.serialize(&solution).unwrap();
    let coin = Coin {
        parent_coin_info: chia_protocol::Bytes32::new([2u8; 32]),
        puzzle_hash: chia_protocol::Bytes32::new([3u8; 32]),
        amount: 1,
    };
    let spends = vec![CoinSpend::new(coin, puzzle_reveal, solution)];

    assert!(
        key.sign_bundle(spends).is_err(),
        "the signing-oracle guard must reject an AGG_SIG_UNSAFE bundle after the cutover"
    );
}
