//! HD derivation is **deactivated, not removed** (dig_ecosystem#2236).
//!
//! The app pins every wallet operation to one derivation index
//! ([`ACTIVE_PROFILES`](dig_app_core::account::ACTIVE_PROFILES)). This file guards the OTHER half of
//! that instruction: the HD machinery underneath must still be whole, so multi-address support returns
//! by widening a declaration rather than by restoring deleted code.
//!
//! # Why this shape of test
//!
//! A test that asserted only "the wallet address is `xch1cs3…`" would pass just as happily against an
//! implementation with the HD path ripped out and index 0 hard-coded — it cannot tell deactivation
//! from removal. So the fixture varies the ONE thing that must still matter: the index. It opens the
//! SAME seed at the pinned index and at a deactivated one, and requires the two to disagree AND the
//! deactivated one to match a derivation computed here, out of tree, from `chia_bls` directly.

use std::sync::Arc;

use chia_bls::{master_to_wallet_unhardened, SecretKey};
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chia_sdk_utils::Address;
use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx, UnlockedAccount};
use dig_app_core::account::{is_active, ActiveProfile};
use dig_app_core::session::SessionSigner;
use dig_keystore::MemoryBackend;
use dig_session::{Password, ENTROPY_LEN};

/// One fixed entropy for every derivation here, so the only variable in the comparison is the index.
const SEED: [u8; ENTROPY_LEN] = [0x3b; ENTROPY_LEN];

/// The first index the app is deliberately NOT active on — the nearest thing to the pinned index, and
/// so the one a hard-coded derivation would be most likely to be confused with.
const DEACTIVATED: ProfileIx = ProfileIx(1);

/// Unlock a fresh in-memory account over [`SEED`] whose default profile is `ix`.
///
/// This goes through `dig-account` directly rather than through
/// [`open_or_enroll`](dig_app_core::account::lifecycle::open_or_enroll) precisely BECAUSE the app's
/// funnel will not accept a deactivated index — that refusal is the pinning, and reaching underneath
/// it is how this file inspects the machinery the pinning sits on top of.
fn account_at(ix: ProfileIx) -> UnlockedAccount {
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    AccountSession::enroll(
        store,
        AccountId::new(format!("hd-{ix}")),
        Password::new("pw"),
        &SEED,
        ix,
    )
    .expect("a fresh in-memory account enrols")
}

/// The canonical Chia receive address for [`SEED`] at `ix`, derived HERE from `chia_bls` — BIP-39
/// expansion → unhardened wallet path → synthetic key → standard p2 puzzle hash → bech32m.
///
/// Deliberately touches none of dig-account's derivation code, so agreement between this and the
/// account handle is agreement between two implementations rather than a value read back from one.
fn independent_address_at(ix: ProfileIx) -> String {
    let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
        .expect("32 bytes is valid 24-word BIP-39 entropy")
        .to_seed("");
    let master = SecretKey::from_seed(&expanded);
    let synthetic = master_to_wallet_unhardened(&master, ix.0).derive_synthetic();
    let puzzle_hash = StandardArgs::curry_tree_hash(synthetic.public_key());
    Address::new(puzzle_hash.into(), "xch".to_string())
        .encode()
        .expect("a 32-byte puzzle hash encodes")
}

/// The HD wallet path still derives correctly at an index the app has deactivated.
///
/// Three claims, and the first two are what removal could not survive:
///
/// 1. the deactivated index yields a DIFFERENT address from the pinned one (a hard-coded index 0
///    would make them equal);
/// 2. that address is the *right* one for index 1, per an out-of-tree derivation (merely different is
///    not enough — a stubbed-out path could return garbage that also differs);
/// 3. and the app still refuses to be active on it, so (1) and (2) are dormant capability rather than
///    a leak in the pinning.
#[test]
fn the_hd_wallet_path_still_derives_at_a_deactivated_index() {
    let pinned = account_at(ActiveProfile::SOLE.ix())
        .wallet_ops()
        .address()
        .expect("the pinned index encodes an address");
    let deactivated = account_at(DEACTIVATED)
        .wallet_ops()
        .address()
        .expect("a deactivated index still encodes an address");

    assert_ne!(
        pinned, deactivated,
        "the wallet address must still VARY with the derivation index — equal addresses mean the HD \
         path was removed and the index hard-coded"
    );
    assert_eq!(
        independent_address_at(DEACTIVATED),
        deactivated,
        "the deactivated index must derive the canonical Chia address for that index"
    );
    assert_eq!(
        independent_address_at(ActiveProfile::SOLE.ix()),
        pinned,
        "the pinned index must derive the canonical Chia address for the active index"
    );

    assert!(
        !is_active(DEACTIVATED) && ActiveProfile::new(DEACTIVATED).is_none(),
        "the HD path works at {DEACTIVATED}, and the app is still not active on it"
    );
}

/// The per-profile identity + at-rest plumbing beneath the wallet is intact at a deactivated index
/// too: signing keys, DEKs, and sealing keys all still separate by index.
///
/// Without this, "deactivated" could quietly mean "every profile collapsed onto one", which would
/// re-key nothing today but would silently break the day the set is widened.
#[test]
fn the_per_profile_plumbing_still_separates_by_index() {
    let account = account_at(ActiveProfile::SOLE.ix());
    let pinned = ActiveProfile::SOLE.ix();

    assert_ne!(
        account.profile_signer(pinned).signing_public_key(),
        account.profile_signer(DEACTIVATED).signing_public_key(),
        "identity signing keys must still differ by profile index"
    );
    assert_ne!(
        account.dek(pinned),
        account.dek(DEACTIVATED),
        "per-profile DEKs must still differ by profile index"
    );
    assert_ne!(
        account.profile_sealing_public_key(pinned),
        account.profile_sealing_public_key(DEACTIVATED),
        "per-profile sealing keys must still differ by profile index"
    );
}
