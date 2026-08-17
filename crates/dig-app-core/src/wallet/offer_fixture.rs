//! Real `offer1…` fixtures, built by the canonical crate rather than pasted as literals.
//!
//! # Why these are BUILT and not checked in as strings
//!
//! An offer literal is opaque: nothing in a test can tell a correct one from a stale one, and a
//! fixture that silently stopped decoding would take every assertion that reads it green-but-vacuous.
//! Building each offer through [`dig_offers::make_build`] + [`dig_offers::make_assemble`] means the
//! fixture is exactly what the crate produces today, and a fixture that stops being takeable fails
//! loudly at construction.
//!
//! The maker's signature here is the empty aggregate. Nothing these fixtures feed — the parser, the
//! summarizer, the taker builder, or dig-account's custody gate — verifies a BLS signature; they all
//! read puzzles and solutions. A fixture that signed for real would prove nothing extra and would tie
//! every test to a network's `AGG_SIG_ME` constant. Settlement on a live chain is out of scope here
//! by design: these fixtures exist to measure what this app does with an offer, not what the chain
//! does with one.

use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::BlsPair;
use chia_wallet_sdk::prelude::Signature;
use dig_offers::{OfferedSide, RequestedSide, TakerFunds};
use indexmap::IndexMap;
use std::marker::PhantomData;

/// The shape of a fixture offer.
#[derive(Debug, Clone, Copy)]
pub enum OfferShape {
    /// 1,000 mojos offered for 400 mojos requested.
    ///
    /// The two amounts DIFFER so that a test reading the two sides can distinguish them; an offer of
    /// equal amounts reads identically under an implementation that swapped the sides.
    XchForXch,
}

/// 1,000 mojos offered for 400 requested — see [`OfferShape::XchForXch`].
pub const XCH_FOR_XCH: OfferShape = OfferShape::XchForXch;

/// The maker's deterministic key — also the payee the requested payment is made to. Distinct from
/// [`taker`] so a spend built for one is never accidentally satisfiable by the other, and so a test
/// can tell the payment leg from the taker's own change.
#[must_use]
pub fn maker() -> BlsPair {
    BlsPair::new(1)
}

/// The taker's deterministic key.
pub fn taker() -> BlsPair {
    BlsPair::new(2)
}

/// A funding coin belonging to `owner`, unique per `(owner, amount, seed)`.
fn coin_of(owner: &BlsPair, amount: u64, seed: u8) -> Coin {
    Coin::new(Bytes32::new([seed; 32]), owner.puzzle_hash, amount)
}

/// One key map naming `owner` as the signer for its own puzzle hash.
fn keys_of(owner: &BlsPair) -> IndexMap<Bytes32, chia_wallet_sdk::prelude::PublicKey> {
    let mut keys = IndexMap::new();
    keys.insert(owner.puzzle_hash, owner.pk);
    keys
}

/// Build a real, decodable `offer1…` string of the given `shape`.
///
/// # Panics
/// If the canonical crate cannot build or encode the offer — which is a fixture that has gone stale,
/// and must fail loudly rather than yield an unusable string.
#[must_use]
pub fn an_offer_of(shape: OfferShape) -> String {
    let OfferShape::XchForXch = shape;
    let maker = maker();
    let mut ctx = SpendContext::new();

    let unsigned = dig_offers::make_build(
        &mut ctx,
        OfferedSide {
            change_puzzle_hash: maker.puzzle_hash,
            owner_keys: keys_of(&maker),
            xch_coins: vec![coin_of(&maker, 1_500, 0xA1)],
            cat_coins: Vec::new(),
            nfts: Vec::new(),
            offer_xch: 1_000,
            offer_cats: Vec::new(),
            _pd: PhantomData,
        },
        RequestedSide {
            payee_puzzle_hash: maker.puzzle_hash,
            xch: 400,
            cats: Vec::new(),
            nfts: Vec::new(),
        },
        0,
    )
    .expect("the fixture offer must build");

    let signed = SpendBundle::new(unsigned.coin_spends, Signature::default());
    dig_offers::make_assemble(
        &mut ctx,
        signed,
        unsigned.requested_payments,
        unsigned.requested_asset_info,
    )
    .expect("the fixture offer must encode")
}

/// Build the TAKER's unsigned coin spends for `offer` — the exact bytes a take would hand the custody
/// gate.
///
/// Funded generously (2,000 mojos against a 400-mojo request) so that a refusal from anything
/// downstream is never a shortfall in the fixture.
///
/// # Panics
/// If the take cannot be built, which would mean the fixture offer is not takeable at all.
#[must_use]
pub fn taker_spends_for(offer: &str) -> Vec<chia_protocol::CoinSpend> {
    let taker = taker();
    let mut ctx = SpendContext::new();
    dig_offers::take_build(
        &mut ctx,
        offer,
        TakerFunds {
            change_puzzle_hash: taker.puzzle_hash,
            owner_keys: keys_of(&taker),
            xch_coins: vec![coin_of(&taker, 2_000, 0xB2)],
            cat_coins: Vec::new(),
            nfts: Vec::new(),
            _pd: PhantomData,
        },
        0,
    )
    .expect("the fixture take must build")
    .coin_spends
}
