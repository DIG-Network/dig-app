//! What the Coins card SAYS, per state — the part that must never collapse two claims into one.
//!
//! These test the card's decisions rather than its pixels: which sentence a walk's ending earns,
//! what a section does with a reading it could not make, and which SEPARATE cell each of a coin's
//! four facts lands in. The layout is exercised by the pane sweep in [`super::super::mod`]'s tests
//! and by [`super::super::table`]'s own; the claims are what a person acts on.
//!
//! # Why every assertion here is about two fixtures rather than one
//!
//! The defect this card is one interpolated string away from is *two different facts rendering the
//! same*. A test that reads one fixture and finds the value it expected cannot see that, because
//! the wrong implementation produces that value too. So each property is asserted by varying ONE
//! field and requiring the output to change — an unconfirmed coin against a coin confirmed at
//! height zero, a held coin against one whose hold was never read, an unreadable section against
//! an empty one.

use super::*;
use crate::wallet::coin_list::{ListedCoin, TruncatedBecause};
use crate::wallet::overview::BalanceUnknown;

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

/// The text a cell shows, or the empty string for a cell that draws nothing.
fn shown(cell: &Option<Value>) -> &str {
    cell.as_ref().map_or("", Value::shown)
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

/// **A coin's four facts land in four SEPARABLE cells, and no cell carries another cell's fact.**
///
/// The property the em-dash-joined label could not have. It is asserted as an exclusion rather
/// than an inclusion — the amount cell must NOT contain the height, the height cell must NOT
/// contain the amount — because "the row states all four values" is exactly what the one flattened
/// string did, and an inclusion test passes on it unchanged.
///
/// The amount is 1 234 CAT mojos of $DIG, which reads as `1.234`. That figure is wrong by three
/// orders of magnitude under a bare `1000` divisor and by nine under XCH's, so a cell built with a
/// local divisor cannot pass here either.
#[test]
fn a_coins_four_facts_are_four_separable_cells() {
    let row = coin_row(&dig_coin(Reservation::Held, Some(9_172_077)));

    assert!(
        row.amount.shown().contains("1.234"),
        "the amount cell went through the asset's own formatter: {:?}",
        row.amount
    );
    assert!(
        row.height.shown().contains("9,172,077"),
        "the height cell states the height: {:?}",
        row.height
    );
    assert_eq!(shown(&row.hold), copy::wallet::COINS_RESERVED);
    assert_eq!(row.coin_id, Value::Identifier("ab".repeat(32)));

    assert!(
        !row.amount.shown().contains("9,172,077") && !row.amount.shown().contains("172"),
        "the amount cell is the amount ALONE — a cell holding both is the flattened label again: \
         {:?}",
        row.amount
    );
    assert!(
        !row.height.shown().contains("1.234"),
        "the height cell is the height alone: {:?}",
        row.height
    );
    assert!(
        !row.amount.shown().contains(copy::wallet::COINS_RESERVED)
            && !row.height.shown().contains(copy::wallet::COINS_RESERVED),
        "the hold status has its own column and is not appended to another cell"
    );
}

/// **The whole coin id is one cell of its own, and no part of it leaks into a shortened form.**
///
/// A 64-character hex id is read character by character against a block explorer, so a truncation
/// this app performed would be a claim this app made about which coin it is. Asserted against the
/// FULL string and by length, because an implementation that shortened to `ab…ab` would still
/// satisfy a `starts_with` check.
#[test]
fn the_coin_id_cell_holds_the_whole_untruncated_id() {
    let id = "ab".repeat(32);
    let row = coin_row(&dig_coin(Reservation::Free, Some(9_172_077)));

    assert_eq!(
        row.coin_id,
        Value::Identifier(id.clone()),
        "the WHOLE coin id, in the mono style a person reads character by character"
    );
    assert_eq!(
        row.coin_id.shown().len(),
        64,
        "every character of the id survived: {:?}",
        row.coin_id
    );
    assert!(
        !row.coin_id.shown().contains('…') && !row.coin_id.shown().contains(".."),
        "nothing elided the middle of the id: {:?}",
        row.coin_id
    );
}

/// **An unconfirmed coin's height cell says so in words, and is not the cell a coin confirmed at
/// height ZERO gets.**
///
/// The fixture that matters is `Some(0)`. A cell rendered from `unwrap_or_default()` produces the
/// same output for both, and a test pairing "unconfirmed" against a mainnet-scale height cannot
/// see that — the two differ there for the wrong reason. Height zero is also why the cell may not
/// simply be left EMPTY: an empty cell in a column of numbers reads as a zero, so the unconfirmed
/// state is carried as [`Value::Unknown`], which draws its own sentence.
#[test]
fn an_unconfirmed_coin_is_distinguishable_from_a_coin_confirmed_at_height_zero() {
    let unconfirmed = coin_row(&dig_coin(Reservation::Free, None)).height;
    let at_zero = coin_row(&dig_coin(Reservation::Free, Some(0))).height;

    assert_ne!(
        unconfirmed, at_zero,
        "a coin in the mempool and a coin confirmed in block 0 are different facts"
    );
    assert_eq!(unconfirmed.shown(), copy::wallet::COINS_UNCONFIRMED);
    assert!(
        !unconfirmed.is_known(),
        "an absent height is an absence, not a figure: {unconfirmed:?}"
    );
    assert!(
        !unconfirmed.shown().is_empty(),
        "an empty cell in a column of heights reads as a zero"
    );
    assert_eq!(at_zero.shown(), "0", "a real height of 0 is stated as one");
    assert!(at_zero.is_known());
}

/// **A held coin, a coin whose hold was never read, and a measured-free coin produce three
/// different cells — and only the free one is empty.**
///
/// The one that matters is `Unknown`: an empty cell there would assert a freedom nothing measured.
/// Three fixtures differing in exactly one field, asserted pairwise, so an implementation that
/// folded `Unknown` into `Free` fails here rather than passing a test that only checked `Held`.
#[test]
fn the_three_reservation_states_are_three_different_cells() {
    let free = coin_row(&dig_coin(Reservation::Free, Some(10))).hold;
    let held = coin_row(&dig_coin(Reservation::Held, Some(10))).hold;
    let unread = coin_row(&dig_coin(Reservation::Unknown, Some(10))).hold;

    assert_ne!(held, unread, "held and never-read are different claims");
    assert_ne!(
        free, unread,
        "an unread hold status is not a free coin, and an empty cell would say it was"
    );
    assert_ne!(free, held);

    assert_eq!(free, None, "a measured-free coin carries no caveat");
    assert!(
        unread.is_some(),
        "the unmeasured state is STATED, never left blank"
    );
    assert_eq!(shown(&held), copy::wallet::COINS_RESERVED);
    assert_eq!(shown(&unread), copy::wallet::COINS_RESERVATION_UNREAD);
}

/// **A section nobody could read is not a section that read nothing.**
///
/// Both end with no rows in the table, which is exactly why the difference has to live somewhere
/// the table cannot flatten: an empty list is the positive claim *this address holds no coins*,
/// and an unreadable section has made no claim at all. Asserted against the reason TEXT as well as
/// against the variant, because a body that carried the variant and drew nothing for it would put
/// an unread section on screen looking like an empty one.
#[test]
fn an_unreadable_section_is_not_an_empty_one() {
    let unreadable = section_body(&CoinsReading::Unknown(BalanceUnknown::NoNode), 10);
    let empty = section_body(
        &CoinsReading::Known {
            coins: Vec::new(),
            end: WalkEnd::Complete,
        },
        10,
    );
    let pending = section_body(&CoinsReading::Pending, 10);

    assert_ne!(unreadable, empty);
    assert_ne!(unreadable, pending);
    assert_ne!(
        empty, pending,
        "a read that has not answered has not found an empty address"
    );
    assert!(
        matches!(&unreadable, SectionBody::Unreadable(why) if !why.is_empty()),
        "an unreadable section names its reason: {unreadable:?}"
    );
    assert!(matches!(empty, SectionBody::Empty));
}

/// **A section shows at most `shown` coins, and says so when it is holding some back.**
#[test]
fn a_section_draws_no_more_rows_than_it_was_asked_for() {
    let coins = vec![dig_coin(Reservation::Free, Some(10)); 12];
    let body = section_body(
        &CoinsReading::Known {
            coins,
            end: WalkEnd::Complete,
        },
        10,
    );

    match body {
        SectionBody::Coins { rows, more, .. } => {
            assert_eq!(rows.len(), 10);
            assert!(
                more,
                "two coins are still unshown, so the control is offered"
            );
        }
        other => panic!("a known list of coins is drawn as rows: {other:?}"),
    }
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

/// **The coin id is drawn BENEATH the cells, never inside one of them.**
///
/// `coin_row` only builds the four facts; this is the mapping that decides WHERE each one is drawn,
/// and it is the mapping the card's headline property rests on. A 64-character hex string laid into
/// the Amount column — a ~160 px share of a 480 px window — could only be drawn by cutting it, and
/// a truncation this app performed would be a claim this app made about which coin it is. So the
/// assertion is about PLACEMENT: the id spans, the three cells are amount / height / hold in that
/// order, and no cell carries the id.
///
/// Asserted over two rows differing only in hold status, so a row whose Hold cell is legitimately
/// empty still cannot be the row that lost its id: the free coin has a `None` third cell AND a
/// whole id beneath it, which an implementation that packed the id into the vacant cell would fail.
#[test]
fn the_coin_id_spans_beneath_the_row_rather_than_occupying_a_column() {
    for reservation in [Reservation::Held, Reservation::Free] {
        let listed = dig_coin(reservation, Some(4_242_424));
        let row = coin_row(&listed);
        let drawn = row.as_table_row();

        assert_eq!(
            drawn.beneath,
            Some(row.coin_id.clone()),
            "the whole id must span beneath the cells, uncut"
        );
        assert_eq!(
            drawn.beneath,
            Some(Value::Identifier(listed.coin_id.clone())),
            "and it must still be the coin's OWN id, in the monospaced identifier treatment"
        );

        assert_eq!(drawn.cells.len(), 3, "amount, height, hold — and nothing else");
        assert_eq!(drawn.cells[0], Some(row.amount.clone()), "the amount is the first column");
        assert_eq!(drawn.cells[1], Some(row.height.clone()), "the height is the second");
        assert_eq!(drawn.cells[2], row.hold.clone(), "the hold status is the third");

        // Stated as an explicit ABSENCE rather than inferred from the three equalities above: an
        // implementation that drew the id in both places would satisfy every assertion so far.
        assert!(
            !drawn.cells.contains(&Some(row.coin_id.clone())),
            "no column may carry the id; the column widths cannot hold it without cutting it"
        );
    }
}

/// **The Hold column is empty for a free coin, and that emptiness survives the mapping.**
///
/// The two rows above differ in exactly one field, so this pins the difference REACHES the drawn
/// row: a mapping that filled every cell would render a free coin as though its hold status had
/// been read and found to say something.
#[test]
fn a_free_coin_reaches_the_table_with_an_empty_hold_cell_and_a_held_one_does_not() {
    let free = coin_row(&dig_coin(Reservation::Free, Some(4_242_424))).as_table_row();
    let held = coin_row(&dig_coin(Reservation::Held, Some(4_242_424))).as_table_row();

    assert_eq!(free.cells[2], None, "silence is the honest reading for a measured-free coin");
    assert!(held.cells[2].is_some(), "a held coin says so in the same column");
    assert_eq!(
        free.cells[..2],
        held.cells[..2],
        "and the two rows differ ONLY in that cell"
    );
}
