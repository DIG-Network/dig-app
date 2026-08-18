//! One real Chia offer, shared by every gallery example that photographs the Offers card.
//!
//! # Why it is built rather than pasted
//!
//! A literal `offer1…` string in a gallery would go on describing whatever `dig_offers::summarize`
//! reported on the day it was copied. Built here, the picture is of what the crate reports TODAY, so
//! a change in how an offer is summarised shows up in the next capture instead of hiding behind a
//! frozen fixture.
//!
//! # Why it is not the test fixture
//!
//! `wallet::offer_fixture` is `#[cfg(test)]` and an example cannot see a test-only module. The SHAPE
//! here is deliberately the same as that fixture's, so the pictures and the tests describe one
//! offer — if the two ever diverge, the tested one is authoritative and this is what should move.

/// A real `offer1…` string for the Wallet tab's offer card: 400 mojos offered for 1,000 requested,
/// so the two sides are visibly different rather than a symmetric pair that would look the same
/// under a swapped mapping.
///
/// Built here rather than imported from `wallet::offer_fixture`, which is `#[cfg(test)]` and reaches
/// for `chia-sdk-test`; an example cannot see a test-only module. The SHAPE is deliberately the same
/// as that fixture's so the picture and the tests describe one offer — if the two ever diverge, the
/// tested one is authoritative and this is what should move.
pub fn gallery_offer() -> String {
    use chia_protocol::{Bytes32, Coin, SpendBundle};
    use chia_sdk_driver::SpendContext;
    use chia_sdk_test::BlsPair;
    use chia_wallet_sdk::prelude::Signature;
    use dig_offers::{OfferedSide, RequestedSide};

    let maker = BlsPair::new(1);
    let mut keys = indexmap::IndexMap::new();
    keys.insert(maker.puzzle_hash, maker.pk);
    let mut ctx = SpendContext::new();

    let unsigned = dig_offers::make_build(
        &mut ctx,
        OfferedSide {
            change_puzzle_hash: maker.puzzle_hash,
            owner_keys: keys,
            xch_coins: vec![Coin::new(
                Bytes32::new([0xA1; 32]),
                maker.puzzle_hash,
                1_500,
            )],
            cat_coins: Vec::new(),
            nfts: Vec::new(),
            offer_xch: 400,
            offer_cats: Vec::new(),
            _pd: std::marker::PhantomData,
        },
        RequestedSide {
            payee_puzzle_hash: maker.puzzle_hash,
            xch: 1_000,
            cats: Vec::new(),
            nfts: Vec::new(),
        },
        0,
    )
    .expect("the preview offer must build");

    dig_offers::make_assemble(
        &mut ctx,
        SpendBundle::new(unsigned.coin_spends, Signature::default()),
        unsigned.requested_payments,
        unsigned.requested_asset_info,
    )
    .expect("the preview offer must encode")
}
