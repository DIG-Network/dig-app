//! **The closed loop**: an offer built from this app's own draft mapping is readable, says what the
//! person asked for, and can be cancelled by this app's own cancel arguments (dig_ecosystem#3077).
//!
//! # Why this file exists rather than more unit tests
//!
//! Every step of make and cancel is unit-tested where it lives, and every one of those tests would
//! stay green under the single most likely defect in this feature: a give/want mapping built the
//! wrong way round. Such an offer encodes, decodes, summarizes and is takeable — it simply trades in
//! the opposite direction from the one the person filled in. Nothing local to either module can see
//! that, because each module is individually consistent with itself.
//!
//! So this file runs the real chain of canonical calls — draft → [`dig_offers::make_build`] →
//! [`dig_offers::make_assemble`] → [`ReviewedOffer::read`] → [`dig_offers::cancel_build`] — and asks
//! whether the offer that comes out is the offer that was asked for, and whether the wallet that made
//! it can take its coins back.
//!
//! # What a green here does and does not prove
//!
//! It proves the ARGUMENT SHAPES this app passes to the canonical builders are mutually coherent:
//! the offered side is what the form gave, the requested side is what the form wanted, the payee is
//! the maker, and the maker's own key reclaims the offered coins.
//!
//! It does NOT prove either operation settles on a live chain. Nothing here touches a network and
//! nothing here signs — the maker's signature is the empty aggregate, exactly as in
//! [`crate::wallet::offer_fixture`], because no step exercised here verifies a signature. A make and
//! a cancel against real mainnet coins remain unmeasured by any test in this repo.

use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_sdk_driver::SpendContext;
use chia_sdk_test::BlsPair;
use chia_wallet_sdk::prelude::{PublicKey, Signature};
use dig_offers::OfferedSide;
use indexmap::IndexMap;
use std::marker::PhantomData;

use crate::wallet::making::{MakeDraft, Wanted};
use crate::wallet::offer::{OfferLeg, ReviewedOffer};

/// How much XCH the draft commits: half a whole coin, so the figure is recognisable in a rendered
/// sentence and is not confusable with the amount asked for.
const GIVE_MOJOS: u64 = 500_000_000_000;

/// How much $DIG the draft asks for, in base units — 1.5 $DIG.
///
/// A **CAT** deliberately, and not more XCH. A CAT leg is the case the whole confirm-prompt finding
/// is about: it nets ~0 XCH through the spend, so a summary that could only see mojos would show
/// dust while a token changed hands. It is also a different ASSET from the given side, so a
/// transposed mapping cannot produce a coincidentally-identical offer.
const WANT_BASE_UNITS: u64 = 1_500;

/// The maker's deterministic key.
fn maker() -> BlsPair {
    BlsPair::new(7)
}

/// The maker's funding coin, comfortably larger than what is offered so a build failure is never a
/// shortfall in the fixture.
fn funding() -> Coin {
    Coin::new(
        Bytes32::new([0xC3; 32]),
        maker().puzzle_hash,
        GIVE_MOJOS * 3,
    )
}

/// One key map naming the maker as the signer for its own puzzle hash.
fn maker_keys() -> IndexMap<Bytes32, PublicKey> {
    let maker = maker();
    let mut keys = IndexMap::new();
    keys.insert(maker.puzzle_hash, maker.pk);
    keys
}

/// The draft a person would fill in: give half an XCH, want 1.5 $DIG.
fn a_draft() -> MakeDraft {
    MakeDraft::checked(
        GIVE_MOJOS,
        Wanted::Cat {
            asset_id: dig_constants::DIG_ASSET_ID,
            amount: WANT_BASE_UNITS,
        },
    )
    .expect("both sides are non-zero")
}

/// Build the offer `draft` describes, through the same argument shapes
/// [`crate::wallet::making::MakeSession::make`] uses.
///
/// The one thing this does NOT reproduce is the custody gate, which needs an unlocked account. The
/// signature is the empty aggregate for the reason [`crate::wallet::offer_fixture`] records: no step
/// downstream of here verifies one.
fn an_offer_from(draft: &MakeDraft) -> String {
    let maker = maker();
    let mut ctx = SpendContext::new();

    let unsigned = dig_offers::make_build(
        &mut ctx,
        OfferedSide {
            change_puzzle_hash: maker.puzzle_hash,
            owner_keys: maker_keys(),
            xch_coins: vec![funding()],
            cat_coins: Vec::new(),
            nfts: Vec::new(),
            offer_xch: draft.give_mojos(),
            offer_cats: Vec::new(),
            _pd: PhantomData,
        },
        crate::wallet::making::requested_side(draft, maker.puzzle_hash),
        0,
    )
    .expect("an offer this app's form describes must build");

    dig_offers::make_assemble(
        &mut ctx,
        SpendBundle::new(unsigned.coin_spends, Signature::default()),
        unsigned.requested_payments,
        unsigned.requested_asset_info,
    )
    .expect("an offer this app builds must encode")
}

/// **The offer that comes out trades in the direction the form was filled in.**
///
/// The assertion reads the offer back through the app's OWN parser rather than through the values it
/// was built from, so nothing here can agree with itself: the terms come from decoded bytes.
///
/// The two sides are different ASSETS and different magnitudes, which is what makes a transposition
/// visible. Under a mapping built the wrong way round, `you_pay` would be half an XCH and
/// `you_receive` would be 1.5 $DIG — both assertions below fail, and neither could be satisfied by
/// accident.
///
/// Remember the direction `OfferTerms` speaks in: it is the TAKER's view. So the maker's given side
/// is what a taker RECEIVES, and the maker's wanted side is what a taker PAYS.
#[test]
fn an_offer_this_app_makes_trades_the_way_the_form_was_filled_in() {
    let reviewed = ReviewedOffer::read(&an_offer_from(&a_draft())).expect("it must read back");

    assert_eq!(
        reviewed.terms().you_receive,
        vec![OfferLeg::Xch { mojos: GIVE_MOJOS }],
        "what the maker gave must be what a taker receives"
    );
    assert_eq!(
        reviewed.terms().you_pay,
        vec![OfferLeg::Cat {
            asset_id: hex::encode(dig_constants::DIG_ASSET_ID),
            amount: WANT_BASE_UNITS,
        }],
        "what the maker wanted must be what a taker pays"
    );
}

/// **The confirm prompt for that offer names 0.5 XCH and 1.5 $DIG, not a mojo count and not dust.**
///
/// This is dig_ecosystem#3109 read forward through the make path. The $DIG leg is the one the
/// re-derived spend summary cannot state at all, and the XCH figure is the one that used to be
/// printed as its raw base-unit count. Both are asserted positively AND their wrong forms negatively,
/// because a body that printed both would be no less misleading than one that printed only the wrong
/// one.
#[test]
fn the_make_prompt_states_both_sides_in_the_units_a_person_typed() {
    let body = a_draft().narrative().render();

    assert!(body.contains("0.5 XCH"), "{body}");
    assert!(body.contains("1.5 $DIG"), "{body}");
    assert!(
        !body.contains("500000000000"),
        "the given side was stated as its raw mojo count: {body}"
    );
    assert!(
        !body.contains("1500 base units"),
        "$DIG's known precision was not applied: {body}"
    );
}

/// **The wallet that made the offer can take its coins back.**
///
/// The closed loop, and the assertion the cancel path is otherwise missing: `cancel_build` refuses an
/// offer whose offered coins it has no key for, so a green here says the reclaim address and the key
/// map this app passes actually match the coins its own make committed.
///
/// The reclaim spends are non-empty AND the offered coin is among them, so a builder that returned
/// some unrelated spend cannot pass.
#[test]
fn the_wallet_that_made_an_offer_can_cancel_it() {
    let offer = an_offer_from(&a_draft());
    let maker = maker();
    let mut ctx = SpendContext::new();

    let unsigned = dig_offers::cancel_build(&mut ctx, &offer, maker.puzzle_hash, &maker_keys(), 0)
        .expect("the maker holds the key to its own offered coins");

    assert!(
        !unsigned.coin_spends.is_empty(),
        "a cancellation with no spends reclaims nothing"
    );
    assert!(
        unsigned
            .coin_spends
            .iter()
            .any(|spend| spend.coin.puzzle_hash == maker.puzzle_hash),
        "the reclaim must spend the maker's own offered coin"
    );
}

/// **A stranger cannot cancel somebody else's offer, and is told why.**
///
/// The control on the offer card is offered on ANY readable offer, because whether its coins are
/// still yours to reclaim is a chain question the card cannot answer. That design is only acceptable
/// if the refusal is real and legible, so this pins both: it fails, and it fails with a reason a
/// person can act on rather than a generic build error.
///
/// The key map is the stranger's, which is exactly the state a person is in when they paste an offer
/// somebody sent them and press Cancel.
#[test]
fn a_stranger_cannot_cancel_an_offer_and_the_refusal_says_so() {
    let offer = an_offer_from(&a_draft());
    let stranger = BlsPair::new(8);
    let mut stranger_keys = IndexMap::new();
    stranger_keys.insert(stranger.puzzle_hash, stranger.pk);

    let mut ctx = SpendContext::new();
    let refusal =
        dig_offers::cancel_build(&mut ctx, &offer, stranger.puzzle_hash, &stranger_keys, 0)
            .expect_err("a wallet with no key to the offered coins cannot reclaim them")
            .to_string();

    assert!(
        refusal.contains("no key for offered coin"),
        "the refusal must name the reason, not merely fail: {refusal}"
    );
}
