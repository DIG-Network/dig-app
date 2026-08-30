//! What a page MEANS, and what a walk over pages must never do.
//!
//! Every fixture here is built to separate the rule under test from the nearest implementation that
//! would also pass. The three that matter are called out on their own tests: an absent `complete`
//! against one that defaults to `false`, a cursor walk against one that resumes from the wrong id,
//! and an exactly-full final page against one that derives *has more* from the page's length.

use std::cell::RefCell;

use dig_node_control_interface::results::{WalletCoinRecord, WalletCoinsResult, WalletReadSource};

use super::coin_list::{
    mark_reservations, read_page, walk, CoinPage, ListedCoin, PageEnd, Reservation,
    TruncatedBecause, WalkEnd, MAX_PAGES,
};
use super::reservations::{HeldCoin, NodeHeld};
use super::state::Asset;

/// A coin id with a stable, ASCENDING hex order: id(1) < id(2) < … lexicographically, which is the
/// order the contract makes the coins read return in.
fn id(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// A node record for the coin at `n`, worth `amount`, confirmed at `height`.
fn record(n: u8, amount: u64, height: Option<u32>) -> WalletCoinRecord {
    WalletCoinRecord {
        coin_id: id(n),
        asset: Some(Asset::DIG),
        amount,
        parent_coin_info: id(0),
        puzzle_hash: id(255),
        created_height: height,
        spent_height: None,
    }
}

/// A whole `control.wallet.coins` answer carrying `coins`, with the paging keys set explicitly.
fn result(
    coins: Vec<WalletCoinRecord>,
    complete: Option<bool>,
    cursor: Option<&str>,
) -> WalletCoinsResult {
    WalletCoinsResult {
        coins,
        complete,
        cursor: cursor.map(str::to_owned),
        source: Some(WalletReadSource::Db),
        synced: true,
        peak_height: Some(9_172_077),
    }
}

/// **An absent `complete` is a node that never paged — never a truncated page.**
///
/// The fixture carries a NON-NULL cursor alongside the absent `complete`, which is what separates
/// this from the two nearest wrong readings. `complete.unwrap_or(false)` and "resume whenever a
/// cursor is present" both produce [`PageEnd::More`] here; only reading the absence itself produces
/// [`PageEnd::Unpaged`]. A fixture with `cursor: None` would pass under all three, because there
/// would be nothing to resume from either way.
#[test]
fn an_unpaged_answer_from_an_older_node_is_not_read_as_a_truncated_page() {
    let page = read_page(&result(vec![record(1, 5, Some(10))], None, Some(&id(1))));

    assert_eq!(
        page.end,
        PageEnd::Unpaged,
        "a node that omits `complete` served this read unpaged; its answer is the whole set"
    );
    assert_eq!(
        page.end.cursor(),
        None,
        "an unpaged answer must offer no resume point, whatever cursor it happened to carry"
    );
}

/// **And the walk stops after ONE page against such a node, rather than walking forever.**
///
/// The scripted node here behaves the way a pre-0.25 node actually does: it IGNORES
/// `after_coin_id` and serves the same page to every request. So a walker that resumed on an absent
/// `complete` would not merely ask twice — it would ask [`MAX_PAGES`] times and return the same coin
/// sixty-four times, and would then report that duplicate-filled list as a truncated read.
///
/// Asserting the request COUNT rather than only the returned coins is what makes this
/// load-bearing: a walker that de-duplicated by coin id would return the right list from the wrong
/// behaviour.
#[test]
fn a_walk_against_an_unpaged_node_asks_once_and_does_not_loop() {
    let asks = RefCell::new(Vec::new());

    let walked = walk::<()>(|cursor| {
        asks.borrow_mut().push(cursor.map(str::to_owned));
        // The old node's actual behaviour: the cursor is not a parameter it knows, so page one is
        // the answer to every question.
        Ok(read_page(&result(
            vec![record(1, 5, Some(10))],
            None,
            Some(&id(1)),
        )))
    })
    .expect("the scripted node does not fail");

    assert_eq!(
        asks.borrow().as_slice(),
        &[None],
        "exactly one request, with no cursor — resuming an unpaged node re-serves page one forever"
    );
    assert_eq!(walked.end, WalkEnd::Unpaged);
    assert_eq!(walked.coins.len(), 1, "and the one coin is reported once");
}

/// **A cursor walk visits every coin exactly once — no duplicates, no gaps.**
///
/// The scripted node is backed by a real six-coin table and resolves `after_coin_id` by taking the
/// rows STRICTLY after it, exactly as the contract specifies. That is what makes a wrong cursor
/// visible rather than harmless: a walker that resumed from the FIRST id of the page it just read
/// would re-serve that page's second coin, and one that resumed from an invented id would skip
/// rows. Both show up as a changed id sequence.
///
/// Six coins over pages of two, so a wrong boundary is off by a coin the assertion can see, and the
/// final page is asked for on its own cursor rather than being the first page.
#[test]
fn a_cursor_walk_visits_every_coin_exactly_once() {
    let table: Vec<WalletCoinRecord> = (1..=6)
        .map(|n| record(n, u64::from(n) * 100, Some(1_000 + u32::from(n))))
        .collect();
    let asks = RefCell::new(Vec::new());

    let walked = walk::<()>(|cursor| {
        asks.borrow_mut().push(cursor.map(str::to_owned));
        // Strictly after the cursor, in the table's ascending order — the contract's own rule.
        let start = match cursor {
            None => 0,
            Some(after) => table
                .iter()
                .position(|row| row.coin_id == after)
                .map(|at| at + 1)
                .expect("the walker must only ever resume from an id this node handed it"),
        };
        let page: Vec<WalletCoinRecord> = table.iter().skip(start).take(2).cloned().collect();
        let remaining = table.len() - start - page.len();
        let last = page.last().map(|row| row.coin_id.clone());
        Ok(read_page(&result(
            page,
            Some(remaining == 0),
            last.as_deref(),
        )))
    })
    .expect("the scripted node does not fail");

    assert_eq!(walked.end, WalkEnd::Complete);
    let seen: Vec<&str> = walked
        .coins
        .iter()
        .map(|coin| coin.coin_id.as_str())
        .collect();
    let expected: Vec<String> = (1..=6).map(id).collect();
    assert_eq!(
        seen,
        expected.iter().map(String::as_str).collect::<Vec<_>>(),
        "every coin in the table, once each, in ascending order"
    );
    assert_eq!(
        asks.borrow().as_slice(),
        &[None, Some(id(2)), Some(id(4))],
        "each page is resumed from the LAST id of the page before it"
    );
    // Stated separately from the sequence assertion above so that a future change to the table size
    // cannot quietly weaken it into "the ids happen to be unique".
    let mut unique = walked.coins.clone();
    unique.dedup_by(|a, b| a.coin_id == b.coin_id);
    assert_eq!(
        unique.len(),
        walked.coins.len(),
        "no coin is delivered twice"
    );
}

/// **A final page that is exactly full is not walked one page further.**
///
/// Every page here is exactly two coins, including the last, so page LENGTH cannot distinguish the
/// final page from the others — which is precisely the case where deriving *has more* from whether
/// the page filled goes wrong. The node states `complete: true` on that full last page and the walk
/// must believe it.
///
/// The assertion is on the request COUNT, because that is where a length-deriving walker differs: it
/// would ask a third time and be handed an empty page, and would then return the same four coins
/// this test expects. Asserting only the coins would go green either way.
#[test]
fn an_exactly_full_final_page_is_not_reported_as_having_more() {
    let asks = RefCell::new(0usize);

    let walked = walk::<()>(|cursor| {
        *asks.borrow_mut() += 1;
        let page = match cursor {
            None => vec![record(1, 100, Some(10)), record(2, 200, Some(11))],
            Some(_) => vec![record(3, 300, Some(12)), record(4, 400, Some(13))],
        };
        let last = page.last().map(|row| row.coin_id.clone());
        // The second page is FULL and is also the last one.
        let complete = cursor.is_some();
        Ok(read_page(&result(page, Some(complete), last.as_deref())))
    })
    .expect("the scripted node does not fail");

    assert_eq!(*asks.borrow(), 2, "two pages were asked for, and no third");
    assert_eq!(walked.end, WalkEnd::Complete);
    assert_eq!(walked.coins.len(), 4);
}

/// **A node that says there is more and hands back no cursor has not reported a complete list.**
///
/// The two ends are opposite claims about the same set, and folding this one into `Complete` would
/// present a partial list of somebody's money as whole.
#[test]
fn a_truncated_page_without_a_cursor_is_not_reported_as_complete() {
    let page = read_page(&result(vec![record(1, 5, Some(10))], Some(false), None));
    assert_eq!(page.end, PageEnd::TruncatedWithoutCursor);
    assert_eq!(page.end.cursor(), None);

    let walked = walk::<()>(|_| Ok(page.clone())).expect("the scripted node does not fail");
    assert_eq!(walked.end, WalkEnd::Truncated(TruncatedBecause::NoCursor));
}

/// **A node that repeats a cursor stops the walk instead of looping on it.**
///
/// The page budget alone would turn this into a slow loop that returned the same coin sixty-four
/// times and called the result truncated for the wrong reason. The count assertion is what separates
/// the two.
#[test]
fn a_repeated_cursor_stops_the_walk_rather_than_looping() {
    let asks = RefCell::new(0usize);

    let walked = walk::<()>(|_| {
        *asks.borrow_mut() += 1;
        Ok(read_page(&result(
            vec![record(1, 5, Some(10))],
            Some(false),
            Some(&id(9)),
        )))
    })
    .expect("the scripted node does not fail");

    assert_eq!(
        *asks.borrow(),
        2,
        "the second page repeats the first cursor and the walk stops"
    );
    assert_eq!(
        walked.end,
        WalkEnd::Truncated(TruncatedBecause::RepeatedCursor)
    );
}

/// **A node that never says it is done exhausts the budget and reports the walk as truncated.**
///
/// Each page hands back a FRESH cursor, so the repeated-cursor guard above cannot be what stops this
/// one — the budget has to.
#[test]
fn a_node_that_never_completes_exhausts_the_budget_and_says_so() {
    let asks = RefCell::new(0usize);

    let walked = walk::<()>(|_| {
        let mut count = asks.borrow_mut();
        *count += 1;
        let nth = u8::try_from(*count % 251).unwrap_or(0);
        Ok(read_page(&result(
            vec![record(nth, 5, Some(10))],
            Some(false),
            Some(&id(nth)),
        )))
    })
    .expect("the scripted node does not fail");

    assert_eq!(*asks.borrow(), MAX_PAGES);
    assert_eq!(
        walked.end,
        WalkEnd::Truncated(TruncatedBecause::PageBudget),
        "a partial walk is never reported as complete"
    );
}

/// **A read failure travels out of the walk rather than becoming a short, complete-looking list.**
#[test]
fn a_failing_page_fails_the_walk_rather_than_truncating_it() {
    let outcome = walk::<&'static str>(|cursor| match cursor {
        None => Ok(read_page(&result(
            vec![record(1, 5, Some(10))],
            Some(false),
            Some(&id(1)),
        ))),
        Some(_) => Err("the node stopped answering"),
    });

    assert_eq!(outcome, Err("the node stopped answering"));
}

/// **An unread reservation table leaves every coin `Unknown`, never `Free`.**
///
/// An unread table and an empty one are the same shape and the opposite claim: only the second one
/// licenses a person to plan a spend against these coins.
#[test]
fn an_unread_reservation_table_leaves_every_coin_unknown_rather_than_free() {
    let mut coins = read_page(&result(
        vec![record(1, 5, Some(10)), record(2, 7, Some(11))],
        Some(true),
        None,
    ))
    .coins;

    mark_reservations(&mut coins, None);

    assert!(
        coins
            .iter()
            .all(|coin| coin.reservation == Reservation::Unknown),
        "nothing was read, so nothing may be claimed"
    );
}

/// **A read table marks the held coin held and the others free.**
///
/// Two coins, exactly ONE of them held, so the test can tell a correct marking from a blanket one in
/// either direction. A fixture where every coin was held would go green against an implementation
/// that marked everything.
#[test]
fn a_read_reservation_table_marks_only_the_held_coin() {
    let mut coins = read_page(&result(
        vec![record(1, 5, Some(10)), record(2, 7, Some(11))],
        Some(true),
        None,
    ))
    .coins;

    let held = NodeHeld {
        reserved: vec![HeldCoin {
            coin_id: chia_protocol::Bytes32::new(
                hex::decode(id(2))
                    .expect("a 32-byte hex id")
                    .try_into()
                    .expect("32 bytes"),
            ),
            reservation_id: "hold-1".to_owned(),
            expires_at_unix: 1_800_000_000,
        }],
        as_of_unix: 1_799_999_000,
    };
    mark_reservations(&mut coins, Some(&held));

    assert_eq!(coins[0].reservation, Reservation::Free);
    assert_eq!(coins[1].reservation, Reservation::Held);
}

/// **A coin the node did not classify is not listed.**
///
/// The contract forbids a `null` asset on this read, so one arriving means the answer did not come
/// from the method it claims to be. Listing it would attribute an amount to an asset nothing
/// verified. The fixture keeps a classified coin beside it so the test cannot pass by dropping
/// everything.
#[test]
fn a_coin_the_node_did_not_classify_is_not_listed() {
    let mut unclassified = record(2, 7, Some(11));
    unclassified.asset = None;

    let page = read_page(&result(
        vec![record(1, 5, Some(10)), unclassified],
        Some(true),
        None,
    ));

    assert_eq!(page.coins.len(), 1);
    assert_eq!(page.coins[0].coin_id, id(1));
}

/// **An amount and a height are carried through untouched, and an unconfirmed coin keeps its
/// `None`.**
///
/// The amount is a $DIG figure of 1 234 CAT mojos, which is 1.234 $DIG — a value that is wrong by
/// three orders of magnitude under a bare divisor and wrong by nine under XCH's. Nothing here
/// divides it; that is [`crate::amount::format_asset_amount`]'s job alone.
#[test]
fn amounts_and_heights_cross_unchanged_and_an_unconfirmed_coin_has_no_height() {
    let page = read_page(&result(
        vec![record(1, 1_234, Some(9_172_077)), record(2, 1, None)],
        Some(true),
        None,
    ));

    assert_eq!(
        page.coins[0],
        ListedCoin {
            coin_id: id(1),
            asset: Asset::DIG,
            amount: 1_234,
            confirmed_height: Some(9_172_077),
            reservation: Reservation::Unknown,
        }
    );
    assert_eq!(
        page.coins[1].confirmed_height, None,
        "a coin still in the mempool has no height, and that is not a height of zero"
    );
}

/// **An empty page is an answer.**
///
/// `coins: []` with `complete: true` is the node saying this address holds nothing — it is never
/// what a caller gets when a chain could not be reached, which is a catalogued error instead.
#[test]
fn an_empty_complete_page_is_an_answer_and_not_a_fault() {
    let walked = walk::<()>(|_| Ok(read_page(&result(Vec::new(), Some(true), None))))
        .expect("the scripted node does not fail");

    assert_eq!(walked.end, WalkEnd::Complete);
    assert!(walked.coins.is_empty());
}

/// A page's coins are what `read_page` produced, so this guards the one hand-written mapping left:
/// that the walk concatenates pages rather than replacing them.
#[test]
fn a_walk_concatenates_pages_rather_than_keeping_only_the_last() {
    let page_one = CoinPage {
        coins: read_page(&result(vec![record(1, 5, Some(10))], Some(true), None)).coins,
        end: PageEnd::More { cursor: id(1) },
    };
    let page_two = read_page(&result(vec![record(2, 7, Some(11))], Some(true), None));
    let pages = RefCell::new(vec![page_two, page_one]);

    let walked = walk::<()>(|_| Ok(pages.borrow_mut().pop().expect("a scripted page")))
        .expect("the scripted node does not fail");

    assert_eq!(walked.coins.len(), 2);
    assert_eq!(walked.coins[0].coin_id, id(1));
    assert_eq!(walked.coins[1].coin_id, id(2));
}
