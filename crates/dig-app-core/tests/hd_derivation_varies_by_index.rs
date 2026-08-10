//! HD derivation genuinely VARIES BY INDEX (dig_ecosystem#2236, #2398).
//!
//! #2236 pinned the app to one index and this file guarded the other half of that instruction — that
//! the HD machinery underneath stayed whole. #2398 makes the index dynamic, so the guard is no longer
//! about dormant capability: these are now live contracts the multi-profile model rests on directly.
//!
//! # Why this shape of test
//!
//! A test that asserted only "the wallet address is `xch1cs3…`" would pass just as happily against an
//! implementation with the HD path ripped out and index 0 hard-coded — it cannot tell derivation from
//! a constant. So the fixture varies the ONE thing that must matter: the index. It opens the SAME seed
//! at two indices and requires the two to disagree AND each to match a derivation computed here, out
//! of tree, from `chia_bls` directly.
//!
//! The refusal half of #2236 survives in a stricter form, and lives where a compiler can enforce it:
//! there is no constructor for a wallet slot at an index the registry does not vouch for
//! (`tests/compile_fail/*.rs`, driven by `tests/wallet_slot_has_no_bare_constructor.rs`).

use std::sync::Arc;

use chia_bls::{master_to_wallet_unhardened, SecretKey};
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chia_sdk_utils::Address;
use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx, UnlockedAccount};
use dig_app_core::session::SessionSigner;
use dig_keystore::MemoryBackend;
use dig_session::{Password, ENTROPY_LEN};

/// One fixed entropy for every derivation here, so the only variable in the comparison is the index.
const SEED: [u8; ENTROPY_LEN] = [0x3b; ENTROPY_LEN];

/// The account's bootstrap index — where an unprofiled account, and the first profile, derive.
const FIRST: ProfileIx = ProfileIx::ROOT;

/// The SECOND profile's index — the nearest thing to [`FIRST`], and so the one a hard-coded
/// derivation would be most likely to be confused with.
const SECOND: ProfileIx = ProfileIx(1);

/// Unlock a fresh in-memory account over [`SEED`] whose default profile is `ix`.
///
/// This goes through `dig-account` directly rather than through
/// [`open_or_enroll`](dig_app_core::account::lifecycle::open_or_enroll) precisely BECAUSE the app's
/// funnel accepts only a `WalletSlot` the registry vouched for — reaching underneath it is how this
/// file inspects the derivation machinery the funnel sits on top of.
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

/// The HD wallet path derives a DIFFERENT and CORRECT address at each profile index.
///
/// Two claims, and the second is what a stub could not survive:
///
/// 1. the second index yields a different address from the first (a hard-coded index 0 makes them
///    equal);
/// 2. each address is the *right* one for its index, per an out-of-tree derivation — merely
///    different is not enough, because a stubbed path could return garbage that also differs.
#[test]
fn the_hd_wallet_path_derives_a_distinct_correct_address_per_index() {
    let pinned = account_at(FIRST)
        .wallet_ops()
        .address()
        .expect("the pinned index encodes an address");
    let second = account_at(SECOND)
        .wallet_ops()
        .address()
        .expect("the second index also encodes an address");

    assert_ne!(
        pinned, second,
        "the wallet address must still VARY with the derivation index — equal addresses mean the HD \
         path was removed and the index hard-coded"
    );
    assert_eq!(
        independent_address_at(SECOND),
        second,
        "the second index must derive the canonical Chia address for that index"
    );
    assert_eq!(
        independent_address_at(FIRST),
        pinned,
        "the first index must derive the canonical Chia address for that index"
    );
}

/// The per-profile identity + at-rest plumbing separates by index: signing keys, DEKs, and sealing
/// keys all differ.
///
/// Without this, two profiles would share one identity and one at-rest key — so switching would
/// change nothing a user could see, and the DEK isolation the whole per-profile directory model rests
/// on would be decorative.
#[test]
fn the_per_profile_plumbing_separates_by_index() {
    let account = account_at(FIRST);
    let pinned = FIRST;

    assert_ne!(
        account.profile_signer(pinned).signing_public_key(),
        account.profile_signer(SECOND).signing_public_key(),
        "identity signing keys must still differ by profile index"
    );
    assert_ne!(
        account.dek(pinned),
        account.dek(SECOND),
        "per-profile DEKs must still differ by profile index"
    );
    assert_ne!(
        account.profile_sealing_public_key(pinned),
        account.profile_sealing_public_key(SECOND),
        "per-profile sealing keys must still differ by profile index"
    );
}
