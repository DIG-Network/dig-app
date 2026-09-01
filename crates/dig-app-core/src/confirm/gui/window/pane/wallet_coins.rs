//! The Coins card: the actual coins behind the balance (dig_ecosystem#3170).
//!
//! The balance above it is one number. This is what that number is made of — each coin's amount,
//! its id, and the height it was confirmed at — per asset, a page at a time.
//!
//! # A table, because the reader's question is a comparison
//!
//! Each coin is drawn as a ROW of separable cells through [`super::table`], not as one sentence
//! (dig_ecosystem#334). The question somebody opens this card with is *do I hold enough free
//! $DIG*, and answering it means comparing the same field down twenty rows. Until #334 the four
//! facts were joined with em-dashes into a single label, so every row started its amount at a
//! different x and nothing could be scanned — the reader had to read each row as prose to find the
//! one number they came for.
//!
//! The four facts stay four values, each carrying its own honesty: an unconfirmed coin's height is
//! a [`Value::Unknown`] rather than a blank cell, because a blank in a column of numbers reads as a
//! zero, and an unread hold status is stated rather than left silent, because silence in that
//! column reads as *free to spend*.
//!
//! # The card never says "no coins" unless a node said so
//!
//! [`CoinsReading`] has the same three states as [`BalanceReading`](crate::wallet::overview::BalanceReading)
//! and this card draws each as itself: a read in flight is the sentence saying so, an unknown is the
//! reason named in [`crate::wallet::overview::unknown_reason`]'s words, and only a `Known` empty
//! list is allowed to state that the address holds nothing. An empty list drawn for an unread
//! wallet is the defect `no_tab_paints_a_zero_when_nothing_has_been_read` exists to catch.
//!
//! That distinction is why [`section_body`] exists as its own decision: an unreadable section and
//! an empty one both end with zero rows in the table, so the difference has to be settled BEFORE
//! anything is laid out, where a test can see it.
//!
//! # Three different endings, three different sentences
//!
//! A list that is short can be short for three reasons and they are not interchangeable:
//!
//! | walk ended | the caption says |
//! |---|---|
//! | [`WalkEnd::Complete`] | nothing — the list speaks for itself |
//! | [`WalkEnd::Unpaged`] | the node sent everything in one answer and cannot page |
//! | [`WalkEnd::Truncated`] | the list is PARTIAL, and there may be more |
//!
//! The middle one is the one worth spelling out. A pre-0.25 node's answer IS complete; it simply
//! cannot say so. Drawing it with the partial caption would tell a person their list might be
//! missing coins when it is not, and drawing it with no caption at all would claim a confirmation
//! nothing gave.
//!
//! # Nothing here divides an amount
//!
//! Every figure goes through [`crate::amount::amount_with_unit`], which is the one place that knows
//! $DIG carries three decimals and XCH twelve. A local divisor is what rendered $DIG a billion times
//! too small in dig_ecosystem#2295.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Value};
use super::flow::Flow;
use super::table::{self, Column};
use super::text;
use crate::amount::amount_with_unit;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::wallet::coin_list::{CoinListing, CoinsReading, ListedCoin, Reservation, WalkEnd};
use crate::wallet::overview::{grouped_height, unknown_reason};
// Only the section-label pin below names an asset; the card itself never branches on one.
#[cfg(test)]
use crate::wallet::state::Asset;

/// How many coins are drawn before the list asks to be lengthened.
///
/// A page for the READER, which is not the node's page: the node's is sized for a request and this
/// one is sized for a glance. Ten rows fits the 480 px window without scrolling past the card below
/// it, and a wallet with more than ten coins is exactly the one whose owner needs the control rather
/// than an unbounded wall of hex.
///
/// The table keeps that budget. A row is the same three lines the label-over-value readout was — the
/// aligned cells, then the id spanning beneath them — and the only thing #334 added to the card's
/// height is one heading line per asset.
const VISIBLE_STEP: usize = 10;

/// The columns a coin is drawn in, and the share of the width each takes.
///
/// The shares are read off the content: an amount and a height are short and fixed-ish, and the
/// hold status is a phrase (`held by a payment in flight`), so it gets the room. The coin id is
/// deliberately NOT here — see [`super::table::Row::beneath`].
fn coin_columns() -> [Column; 3] {
    [
        Column {
            heading: copy::wallet::COINS_COLUMN_AMOUNT,
            share: 3.0,
        },
        Column {
            heading: copy::wallet::COINS_COLUMN_HEIGHT,
            share: 2.0,
        },
        Column {
            heading: copy::wallet::COINS_COLUMN_HOLD,
            share: 4.0,
        },
    ]
}

/// Draw the Coins card, and report whether the person asked for more of the list.
///
/// Takes the whole [`CoinListing`] rather than one asset's reading, because the two assets are one
/// card: a wallet holding $DIG and no XCH should see both facts stated, and two cards would put an
/// empty one on screen for most people most of the time.
///
/// The control is drawn ONCE for the card rather than per asset. It lengthens both lists, which is
/// the honest reading of "show more coins" on a card that shows coins — a per-asset control would
/// need per-asset state and would put two identical buttons on screen whenever both lists are long.
pub(crate) fn card(flow: &mut Flow, t: &Tokens, listing: &CoinListing, shown: usize) -> bool {
    let live = flow.live();
    let more = |flow: &mut Flow, more_to_show: bool| -> bool {
        if !more_to_show {
            return false;
        }
        let action = Action {
            label: copy::wallet::COINS_SHOW_MORE.to_owned(),
            weight: Weight::Ghost,
            enabled: true,
            id: (),
            element: egui::Id::new("dig-window-wallet-coins-more"),
        };
        flow.gap(space::S4);
        flow.place(|ui, at| {
            let (height, pressed) = action::buttons(ui, at, t, live, std::slice::from_ref(&action));
            (height, pressed.is_some())
        })
    };

    let mut pressed = false;
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::wallet::COINS_CARD), |inner| {
                let mut truncated = asset_section(inner, t, "XCH", &listing.xch, shown);
                inner.gap(space::S4);
                truncated |= asset_section(inner, t, "$DIG", &listing.dig, shown);
                pressed = more(inner, truncated);
            }),
            (),
        )
    });
    pressed
}

/// One asset's section, and whether its list wants to be longer.
fn asset_section(
    flow: &mut Flow,
    t: &Tokens,
    label: &str,
    reading: &CoinsReading,
    shown: usize,
) -> bool {
    flow.place(|ui, at| (text::caption(ui, at, t, label), ()));
    flow.gap(space::S2);

    match section_body(reading, shown) {
        // Not a fault, so it names no reason — and above all not an empty table, which would state
        // that the address holds nothing before anything had asked.
        SectionBody::Pending => {
            flow.place(|ui, at| (text::body(ui, at, t, copy::wallet::COINS_PENDING), ()));
            false
        }
        // Drawn as a readout rather than as a table with no rows, because a heading row over
        // nothing is a table promising columns that are not there. The reason is in the SAME words
        // the balance uses for the same fault, so the two readings of one node cannot contradict
        // each other on the same screen.
        SectionBody::Unreadable(why) => {
            let row = [Readout::new(label, Value::Unknown(why))];
            flow.place(|ui, at| (data::rows(ui, at, t, &row), ()));
            false
        }
        SectionBody::Empty => {
            flow.place(|ui, at| (text::body(ui, at, t, copy::wallet::COINS_EMPTY), ()));
            false
        }
        SectionBody::Coins {
            rows,
            caption,
            more,
        } => {
            let columns = coin_columns();
            let drawn: Vec<table::Row> = rows.iter().map(CoinRow::as_table_row).collect();
            flow.place(|ui, at| (table::table(ui, at, t, &columns, &drawn), ()));
            if let Some(caption) = caption {
                flow.gap(space::S3);
                flow.place(|ui, at| (text::caption(ui, at, t, caption), ()));
            }
            more
        }
    }
}

/// What a section has to say, decided before anything is laid out.
///
/// Separate from the drawing so that the one distinction a table cannot express — an unreadable
/// section against an empty one, both of which have zero rows — is settled in a value a test can
/// compare.
#[derive(Debug, PartialEq, Eq)]
enum SectionBody {
    /// A read is under way. Not a fault, and not a finding.
    Pending,
    /// Nothing could be read, and the sentence saying why.
    Unreadable(String),
    /// A node read the address and it holds no coins. A positive claim, unlike the two above.
    Empty,
    /// The coins to draw, the caveat bounding what the list covers, and whether more are held back.
    Coins {
        /// The rows, already cut to the visible length.
        rows: Vec<CoinRow>,
        /// The sentence bounding what the list COVERS, or `None` when it is known to be whole.
        caption: Option<&'static str>,
        /// Whether the list has coins beyond the ones drawn.
        more: bool,
    },
}

/// Which of the four things a section has to say, for a reading and a visible length.
fn section_body(reading: &CoinsReading, shown: usize) -> SectionBody {
    match reading {
        CoinsReading::Pending => SectionBody::Pending,
        CoinsReading::Unknown(why) => SectionBody::Unreadable(unknown_reason(why)),
        CoinsReading::Known { coins, .. } if coins.is_empty() => SectionBody::Empty,
        CoinsReading::Known { coins, end } => {
            let visible = shown.min(coins.len());
            SectionBody::Coins {
                rows: coins[..visible].iter().map(coin_row).collect(),
                caption: end_caption(*end),
                more: visible < coins.len(),
            }
        }
    }
}

/// One coin's four facts, each in its own cell.
///
/// Four fields rather than one string, and that IS the fix for dig_ecosystem#334: values joined
/// into a label cannot be aligned, cannot be compared down a column, and cannot be asserted about
/// separately — a test on the joined form passes whichever fact it actually found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CoinRow {
    /// What the coin is worth, through the asset's own formatter.
    amount: Value,
    /// The height it was confirmed at, or the absence saying it has none yet.
    height: Value,
    /// The hold status, or `None` for a coin measured free.
    hold: Option<Value>,
    /// The whole coin id.
    coin_id: Value,
}

impl CoinRow {
    /// This coin as a table row: three aligned cells, with the id spanning beneath them.
    ///
    /// The id spans rather than taking a fourth column because a 64-character hex string in Space
    /// Mono is about 450 px of the 480 px window: an inline column for it could only be made to fit
    /// by cutting it, and a truncation this app performed would be a claim this app made about
    /// which coin it is.
    fn as_table_row(&self) -> table::Row {
        table::Row {
            cells: vec![
                Some(self.amount.clone()),
                Some(self.height.clone()),
                self.hold.clone(),
            ],
            beneath: Some(self.coin_id.clone()),
        }
    }
}

/// One coin's facts, split into the cells the table draws.
///
/// The ID is a [`Value::Identifier`], which is what sets it in Space Mono: a 64-character hex
/// string is read character by character, and a person checking a coin against a block explorer has
/// to be able to tell `1` from `l`.
fn coin_row(coin: &ListedCoin) -> CoinRow {
    CoinRow {
        amount: Value::Word(amount_with_unit(coin.asset, coin.amount)),
        height: match coin.confirmed_height {
            Some(height) => Value::Word(grouped_height(height)),
            // An absence carrying its own words, never a zero and never a blank cell: a coin in the
            // mempool has no height, a numeral there would be a block that does not exist, and an
            // empty cell in a column of numbers is read as a zero by everyone who does not stop to
            // wonder why it is empty.
            None => Value::Unknown(copy::wallet::COINS_UNCONFIRMED.to_owned()),
        },
        // Stated on every coin whose hold status is anything but measured-free, because silence in
        // this column reads as "free to spend" and only one of the two non-free states has been
        // measured at all. `Held` is a reading and takes the value treatment; `Unknown` is the
        // absence of one and takes the faint sentence, so the two cannot be mistaken for each other
        // even at a glance.
        hold: match coin.reservation {
            Reservation::Free => None,
            Reservation::Held => Some(Value::Word(copy::wallet::COINS_RESERVED.to_owned())),
            Reservation::Unknown => Some(Value::Unknown(
                copy::wallet::COINS_RESERVATION_UNREAD.to_owned(),
            )),
        },
        coin_id: Value::Identifier(coin.coin_id.clone()),
    }
}

/// The sentence bounding what a list COVERS, or `None` when the list is known to be whole.
fn end_caption(end: WalkEnd) -> Option<&'static str> {
    match end {
        WalkEnd::Complete => None,
        WalkEnd::Unpaged => Some(copy::wallet::COINS_UNPAGED),
        WalkEnd::Truncated(_) => Some(copy::wallet::COINS_PARTIAL),
    }
}

/// How many coins to show after a press, capped so the control cannot run past the list.
pub(crate) fn grown(shown: usize) -> usize {
    shown.saturating_add(VISIBLE_STEP)
}

/// The list length a freshly opened tab starts at.
pub(crate) const fn initially_shown() -> usize {
    VISIBLE_STEP
}

/// The asset a section is labelled with, for the tests that pin the two apart.
#[cfg(test)]
pub(crate) fn section_assets() -> [Asset; 2] {
    [Asset::Xch, Asset::DIG]
}

#[cfg(test)]
#[path = "wallet_coins_tests.rs"]
mod tests;
