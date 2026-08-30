//! What the Coins card SAYS, per state — the part that must never collapse two claims into one.
//!
//! These test the card's decisions rather than its pixels: which sentence a walk's ending earns,
//! and what one coin's row states. The layout is exercised by the pane sweep in
//! [`super::super::mod`]'s tests; the sentences are what a person acts on.

use super::*;
use crate::wallet::coin_list::{ListedCoin, TruncatedBecause};

/// A $DIG coin worth 1.234 $DIG (1 234 CAT mojos), confirmed at a real mainnet-scale height.
fn dig_coin(reservation: Reservation, confirmed_height: Option<u32>) -> ListedCoin {
    ListedCoin {
        coin_id: "ab".repeat(32),
        asset: Asset::DIG,
        amount: 1_234,
        confirmed_height,
        reservation,
    }
}

/// **The three ways a walk can end produce three DIFFERENT captions — and only one of them is
/// silence.**
///
/// This is the rendering half of the `complete`-has-three-states rule. A card that gave
/// [`WalkEnd::Unpaged`] the partial caption would tell somebody their list might be missing coins
/// when it is whole; one that gave it silence would claim a completeness the node never stated.
///
/// Asserted pairwise rather than against fixed strings, so rewording the copy cannot make two of
/// them equal without this failing.
#[test]
fn the_three_walk_endings_are_three_different_sentences() {
    let complete = end_caption(WalkEnd::Complete);
    let unpaged = end_caption(WalkEnd::Unpaged);
    let truncated = end_caption(WalkEnd::Truncated(TruncatedBecause::NoCursor));

    assert_eq!(
        complete, None,
        "a list the node called complete needs no caveat"
    );
    assert!(unpaged.is_some() && truncated.is_some());
    assert_ne!(
        unpaged, truncated,
        "an older node's WHOLE list and a node's PARTIAL list are opposite claims and must not \
         share a sentence"
    );
}

/// **Every reason a walk stopped short earns the partial caption, not just the one that was
/// written first.**
///
/// Three different faults, one honest sentence: whichever way the node stopped, what the reader
/// needs to know is that the list is incomplete. A match that named only `NoCursor` would show a
/// budget-exhausted list as though it were whole.
#[test]
fn every_truncation_reason_says_the_list_is_partial() {
    for why in [
        TruncatedBecause::NoCursor,
        TruncatedBecause::PageBudget,
        TruncatedBecause::RepeatedCursor,
    ] {
        assert_eq!(
            end_caption(WalkEnd::Truncated(why)),
            Some(copy::wallet::COINS_PARTIAL),
            "a walk that stopped for {why:?} produced a list that is partial"
        );
    }
}

/// **A row states the amount, the height, and the coin id — and the id is the mono value.**
///
/// The amount is 1 234 CAT mojos of $DIG, which reads as `1.234`. That figure is wrong by three
/// orders of magnitude under a bare `1000` divisor and by nine under XCH's, so a row built with a
/// local divisor cannot pass here.
#[test]
fn a_row_states_the_amount_the_height_and_the_whole_coin_id() {
    let row = coin_row(&dig_coin(Reservation::Free, Some(9_172_077)));

    assert!(
        row.label.contains("1.234"),
        "the $DIG figure went through the asset's own formatter: {:?}",
        row.label
    );
    assert!(
        row.label.contains("9,172,077") || row.label.contains("9 172 077"),
        "the confirmation height is stated: {:?}",
        row.label
    );
    assert_eq!(
        row.value,
        Value::Identifier("ab".repeat(32)),
        "the WHOLE coin id, in the mono style a person reads character by character"
    );
}

/// **An unconfirmed coin says so in words rather than showing a height of zero.**
///
/// The fixture pairs it against a confirmed coin so the test cannot pass by dropping heights
/// entirely.
#[test]
fn an_unconfirmed_coin_says_so_rather_than_showing_a_zero_height() {
    let pending = coin_row(&dig_coin(Reservation::Free, None));
    let confirmed = coin_row(&dig_coin(Reservation::Free, Some(9_172_077)));

    assert!(pending.label.contains(copy::wallet::COINS_UNCONFIRMED));
    assert!(
        !pending.label.contains("height 0"),
        "a coin with no height must never be given one: {:?}",
        pending.label
    );
    assert!(confirmed.label.contains("9,172,077") || confirmed.label.contains("9 172 077"));
}

/// **A held coin and a coin whose hold status was never read say DIFFERENT things, and a free coin
/// says neither.**
///
/// Three fixtures differing in exactly one field. The one that matters is `Unknown`: silence there
/// reads as *free to spend*, and nothing measured that. A card that treated `Unknown` as `Free`
/// would pass a test that only checked `Held`.
#[test]
fn the_three_reservation_states_are_three_different_rows() {
    let free = coin_row(&dig_coin(Reservation::Free, Some(10))).label;
    let held = coin_row(&dig_coin(Reservation::Held, Some(10))).label;
    let unread = coin_row(&dig_coin(Reservation::Unknown, Some(10))).label;

    assert!(held.contains(copy::wallet::COINS_RESERVED));
    assert!(unread.contains(copy::wallet::COINS_RESERVATION_UNREAD));
    assert_ne!(held, unread);
    assert_ne!(free, unread, "an unread hold status is not a free coin");
    assert!(
        !free.contains(copy::wallet::COINS_RESERVED)
            && !free.contains(copy::wallet::COINS_RESERVATION_UNREAD),
        "a measured-free coin carries no caveat: {free:?}"
    );
}

/// **The card's two sections are the two assets, and they are not the same asset twice.**
///
/// Guards the shape the section labels are drawn from: a card that read one asset and drew it under
/// both headings would show a $DIG holder their $DIG twice and their XCH never.
#[test]
fn the_card_covers_both_assets() {
    let [first, second] = section_assets();
    assert_eq!(first, Asset::Xch);
    assert_eq!(second, Asset::DIG);
    assert_ne!(first, second);
}

/// **The list grows by a fixed step and cannot run backwards.**
#[test]
fn showing_more_lengthens_the_list_from_its_starting_length() {
    let start = initially_shown();
    assert!(start > 0, "a list that starts at zero shows nothing at all");
    assert_eq!(grown(start), start + VISIBLE_STEP);
    assert_eq!(
        grown(usize::MAX),
        usize::MAX,
        "the step saturates rather than wrapping to a list length of nearly zero"
    );
}
