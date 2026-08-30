//! The Coins card: the actual coins behind the balance (dig_ecosystem#3170).
//!
//! The balance above it is one number. This is what that number is made of — each coin's amount,
//! its id, and the height it was confirmed at — per asset, a page at a time.
//!
//! # The card never says "no coins" unless a node said so
//!
//! [`CoinsReading`] has the same three states as [`BalanceReading`](crate::wallet::overview::BalanceReading)
//! and this card draws each as itself: a read in flight is the sentence saying so, an unknown is the
//! reason named in [`crate::wallet::overview::unknown_reason`]'s words, and only a `Known` empty
//! list is allowed to state that the address holds nothing. An empty list drawn for an unread
//! wallet is the defect `no_tab_paints_a_zero_when_nothing_has_been_read` exists to catch.
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
const VISIBLE_STEP: usize = 10;

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

    match reading {
        // Not a fault, so it names no reason — and above all not an empty list, which would state
        // that the address holds nothing before anything had asked.
        CoinsReading::Pending => {
            flow.place(|ui, at| (text::body(ui, at, t, copy::wallet::COINS_PENDING), ()));
            false
        }
        // The reason in the SAME words the balance uses for the same fault, so the two readings of
        // one node cannot contradict each other on the same screen.
        CoinsReading::Unknown(why) => {
            let row = [Readout::new(label, Value::Unknown(unknown_reason(why)))];
            flow.place(|ui, at| (data::rows(ui, at, t, &row), ()));
            false
        }
        CoinsReading::Known { coins, .. } if coins.is_empty() => {
            flow.place(|ui, at| (text::body(ui, at, t, copy::wallet::COINS_EMPTY), ()));
            false
        }
        CoinsReading::Known { coins, end } => {
            let visible = shown.min(coins.len());
            let rows: Vec<Readout> = coins[..visible].iter().map(coin_row).collect();
            flow.place(|ui, at| (data::rows(ui, at, t, &rows), ()));
            if let Some(caption) = end_caption(*end) {
                flow.gap(space::S3);
                flow.place(|ui, at| (text::caption(ui, at, t, caption), ()));
            }
            visible < coins.len()
        }
    }
}

/// One coin as a row: what it is worth and when it landed, above its id.
///
/// The ID is the VALUE rather than the label because [`Value::Identifier`] is what sets it in Space
/// Mono, and a 64-character hex string is read character by character — a person checking a coin
/// against a block explorer has to be able to tell `1` from `l`. The whole id is shown; a truncation
/// this app performed would be a claim this app made about which coin it is.
fn coin_row(coin: &ListedCoin) -> Readout {
    let mut label = format!(
        "{} — {}",
        amount_with_unit(coin.asset, coin.amount),
        match coin.confirmed_height {
            Some(height) => format!("at height {}", grouped_height(height)),
            // Its own words, never a zero: a coin in the mempool has no height, and a numeral there
            // would be a block that does not exist.
            None => copy::wallet::COINS_UNCONFIRMED.to_owned(),
        }
    );
    // Stated on every coin whose hold status is anything but measured-free, because silence here
    // reads as "free to spend" and only one of the two non-free states has been measured at all.
    match coin.reservation {
        Reservation::Free => {}
        Reservation::Held => {
            label.push_str(" — ");
            label.push_str(copy::wallet::COINS_RESERVED);
        }
        Reservation::Unknown => {
            label.push_str(" — ");
            label.push_str(copy::wallet::COINS_RESERVATION_UNREAD);
        }
    }
    Readout::new(label, Value::Identifier(coin.coin_id.clone()))
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
