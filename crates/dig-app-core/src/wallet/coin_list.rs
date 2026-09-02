//! The unspent coins at a watched address, one page at a time (dig_ecosystem#3170).
//!
//! A balance is a single number with nothing behind it. This module is what is behind it: the
//! actual coins, each with its id, its amount and the height it was confirmed at, walked page by
//! page off `control.wallet.coins`.
//!
//! It decides only what a page MEANS. How the question reaches dig-node is
//! [`crate::wallet::node::NodeWalletEngine`], and how the answer is drawn is the Wallet pane. The split is
//! the same one [`crate::wallet::reservations_control`] makes and for the same reason: a wrong transport
//! turns a busy node into an empty wallet, while a wrong reading here turns a truncated list into a
//! complete one — and only the second is silent.
//!
//! # `complete` has THREE states and they must never collapse into two
//!
//! [`WalletCoinsResult::complete`](dig_node_control_interface::results::WalletCoinsResult::complete) is an `Option<bool>`, and each value is a different sentence:
//!
//! | node says | means | this module |
//! |---|---|---|
//! | `Some(true)` | this page is the whole set | [`PageEnd::Complete`](crate::wallet::coin_list::PageEnd::Complete) |
//! | `Some(false)` | more coins exist beyond it | [`PageEnd::More`](crate::wallet::coin_list::PageEnd::More) |
//! | `None` / absent | a pre-0.25 node that never paged, so its answer IS the whole set | [`PageEnd::Unpaged`](crate::wallet::coin_list::PageEnd::Unpaged) |
//!
//! **`None` must not be read as `Some(false)`.** A node that omits the key also ignores
//! `after_coin_id`, so a caller that read the absence as *truncated* and resumed would be served
//! page one again, and again — an infinite walk against a node that is behaving correctly. That is
//! why [`PageEnd::Unpaged`](crate::wallet::coin_list::PageEnd::Unpaged) exists as its own variant rather than as a `Complete` with a comment:
//! the two are the same STOP but they are not the same claim, and only one of them can be paged
//! further if the node is later upgraded.
//!
//! # A truncated page with no cursor is a fourth thing, and it is not complete
//!
//! The contract says a `Some(false)` answer carries the `cursor` to resume from. A node that says
//! *there is more* and hands back no resume point has told us the list is partial and given us no
//! way to finish it. Folding that into [`PageEnd::Complete`](crate::wallet::coin_list::PageEnd::Complete) would present a partial list as whole,
//! which on a money surface reads as missing funds. It becomes
//! [`PageEnd::TruncatedWithoutCursor`](crate::wallet::coin_list::PageEnd::TruncatedWithoutCursor) and the surface says so.
//!
//! # Nothing here divides an amount
//!
//! A [`ListedCoin`](crate::wallet::coin_list::ListedCoin) carries its amount in the asset's BASE UNIT, exactly as the node reported it,
//! and the one place that knows $DIG has three decimals and XCH has twelve is
//! [`crate::amount::format_asset_amount`]. A local divisor is what rendered $DIG a billion times
//! too small in dig_ecosystem#2295.

use std::collections::BTreeSet;

use dig_node_control_interface::results::{WalletCoinRecord, WalletCoinsResult};

use super::reservations::NodeHeld;
use super::state::Asset;

/// How far a walk may go before it stops and says it stopped.
///
/// A walk follows a cursor the NODE chose, so its length is not this app's to bound by trust. The
/// cap is a liveness guard, not a policy: a node that never sets `complete` to `true` would
/// otherwise spin here forever. Sized so that at the contract's default page size it covers far
/// more coins than any watched address plausibly holds, and a walk that hits it reports
/// [`WalkEnd::Truncated`] rather than passing its partial result off as the whole set.
pub const MAX_PAGES: usize = 64;

/// One coin, as a person reads it: what it is worth, which coin it is, and when it landed.
///
/// The heights the node also reports for a coin's SPEND are absent by construction — this read is
/// unspent-only, so `spent_height` is `null` on every record it returns and a field for it here
/// could only ever hold `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedCoin {
    /// The coin id, lowercase 64-hex.
    pub coin_id: String,
    /// The asset the coin is denominated in.
    pub asset: Asset,
    /// The amount, in the asset's base unit — mojos for XCH, CAT mojos for $DIG. Never divided here.
    pub amount: u64,
    /// The height the coin was confirmed at, or `None` while it is still only in the mempool.
    ///
    /// `None` is *not yet in a block*, and it is a different sentence from a height of zero. A
    /// surface renders it as its own words rather than as a numeral.
    pub confirmed_height: Option<u32>,
    /// Whether an in-flight spend is holding this coin.
    pub reservation: Reservation,
}

/// Whether a coin is free to spend, as far as anything has actually been measured.
///
/// The third state is the point. `control.wallet.reservations.held` is its own read and it can
/// fail; a coin whose hold status was never read is not thereby free, and showing it as free
/// invites a person to plan a spend that the node will refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reservation {
    /// The reservation table was read and does not hold this coin.
    Free,
    /// The reservation table was read and an in-flight spend is holding this coin.
    Held,
    /// The reservation table was not read, so nothing is known either way.
    #[default]
    Unknown,
}

/// How ONE page ended, from [`crate::paging`].
///
/// Re-exported rather than redefined: this module and `coin_records_by_parent` each had their own
/// page-walk, and one shared vocabulary is what stops a third read growing a third (dig-app#323).
pub use crate::paging::PageEnd;

/// One page of coins and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinPage {
    /// The coins in this page, ascending by `coin_id` per the contract.
    pub coins: Vec<ListedCoin>,
    /// What the node said about what lies beyond it.
    pub end: PageEnd,
}

/// Read one `control.wallet.coins` answer as a page.
///
/// The node's record is a superset — it also carries the parent and the puzzle hash, which a spend
/// needs to rebuild a `Coin` and a reader does not. The drop happens HERE, visibly, rather than in a
/// tolerant deserializer.
///
/// A record the node did not classify (`asset: null`) is skipped: the contract forbids a `null`
/// asset on this read, so one arriving means the answer did not come from the method it claims to
/// be, and counting it would attribute an amount to an asset nobody verified.
pub fn read_page(result: &WalletCoinsResult) -> CoinPage {
    CoinPage {
        coins: result.coins.iter().filter_map(listed_coin).collect(),
        end: page_end(result),
    }
}

/// What [`WalletCoinsResult`]'s two paging keys say, as one of four sentences.
///
/// The THREE-state constructor, because this contract's `complete` is an `Option<bool>` whose
/// missing value means a pre-0.25 node that never paged.
fn page_end(result: &WalletCoinsResult) -> PageEnd {
    PageEnd::of_optional_complete(result.complete, result.cursor.as_deref())
}

/// One node record as a [`ListedCoin`], or `None` when it does not answer the question asked.
fn listed_coin(record: &WalletCoinRecord) -> Option<ListedCoin> {
    let Some(asset) = record.asset else {
        tracing::debug!(
            coin_id = %record.coin_id,
            "the node returned a coin it did not classify; it is not listed"
        );
        return None;
    };
    Some(ListedCoin {
        coin_id: record.coin_id.clone(),
        asset,
        amount: record.amount,
        confirmed_height: record.created_height,
        reservation: Reservation::Unknown,
    })
}

/// Say which of `coins` an in-flight spend is holding.
///
/// `held` being `None` is the reservation table not having been read, and every coin stays
/// [`Reservation::Unknown`]. It is deliberately not "nothing is held": an unread table and an empty
/// one are the same shape and the opposite claim, and the second one licenses a spend.
pub fn mark_reservations(coins: &mut [ListedCoin], held: Option<&NodeHeld>) {
    let Some(held) = held else {
        return;
    };
    let reserved: BTreeSet<String> = held
        .reserved
        .iter()
        .map(|coin| hex::encode(coin.coin_id))
        .collect();
    for coin in coins {
        coin.reservation = match reserved.contains(&coin.coin_id) {
            true => Reservation::Held,
            false => Reservation::Free,
        };
    }
}

/// How a whole walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// Every coin at the address was seen — the node said so with `complete: true`.
    Complete,
    /// The answering node does not page. Its one answer is the whole set it knows of, and no
    /// further page can be asked for.
    Unpaged,
    /// The walk stopped before the node said it was done: [`MAX_PAGES`] was reached, the node
    /// truncated without a cursor, or it repeated a cursor it had already given.
    Truncated(TruncatedBecause),
}

/// Why a walk stopped short. Each is a different fault and none of them is "there were no more".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncatedBecause {
    /// The node reported more coins and handed back no cursor to resume from.
    NoCursor,
    /// [`MAX_PAGES`] pages were read and the node still had not said it was done.
    PageBudget,
    /// The node handed back a cursor it had already handed back, which would loop forever.
    RepeatedCursor,
}

impl WalkEnd {
    /// This surface's words for a [`crate::paging::Stop`].
    ///
    /// Exhaustive with no wildcard arm: a stop added to the shared walk must be given a sentence
    /// here rather than folding into whichever neighbour a `_ =>` pointed at, and on this surface
    /// the neighbours are *"that was all of them"* and *"that was not".*
    fn of(stop: crate::paging::Stop) -> Self {
        match stop {
            crate::paging::Stop::Complete => Self::Complete,
            crate::paging::Stop::Unpaged => Self::Unpaged,
            crate::paging::Stop::NoCursor => Self::Truncated(TruncatedBecause::NoCursor),
            crate::paging::Stop::RepeatedCursor => {
                Self::Truncated(TruncatedBecause::RepeatedCursor)
            }
            crate::paging::Stop::PageBudget => Self::Truncated(TruncatedBecause::PageBudget),
        }
    }
}

/// The result of walking every page at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinWalk {
    /// Every coin seen, in the order the pages delivered them.
    pub coins: Vec<ListedCoin>,
    /// Whether that is all of them, and if not, why the walk stopped.
    pub end: WalkEnd,
}

/// Walk every page at an address by following the cursor the node hands back.
///
/// `fetch` is given the `after_coin_id` for the page it should read — `None` for the first — and
/// returns that page. It is a closure rather than a trait so that the paging RULE can be tested
/// against a scripted node without a transport, which is where the three ways this goes wrong live.
///
/// # What stops the walk
///
/// A [`PageEnd::Unpaged`] stops it after ONE page, and that is the load-bearing behaviour: an older
/// node ignores `after_coin_id`, so resuming would re-serve page one until the budget ran out and
/// then report a duplicate-filled list as truncated.
///
/// A repeated cursor stops it too. The contract says the cursor advances, but a caller walking a
/// stranger's answer cannot assume that, and a node that repeats one is a loop that a page budget
/// alone would only turn into a slow loop.
pub fn walk<E>(fetch: impl FnMut(Option<&str>) -> Result<CoinPage, E>) -> Result<CoinWalk, E> {
    let mut fetch = fetch;
    let walked = crate::paging::walk(MAX_PAGES, |cursor| {
        fetch(cursor).map(|page| crate::paging::Page {
            items: page.coins,
            end: page.end,
        })
    })?;
    Ok(CoinWalk {
        coins: walked.items,
        end: WalkEnd::of(walked.stop),
    })
}

/// What this app can honestly say about the coins at the watched address.
///
/// The three states are [`BalanceReading`](super::overview::BalanceReading)'s, deliberately — same
/// split, same words for the same fault, via the same [`why_unread`](super::overview::why_unread).
/// A fourth shape invented here is how a coin list comes to say *no node* on the frame the balance
/// beside it says *still syncing*, about one read of one node.
///
/// **An empty `Known` is not the same as an `Unknown`, and neither is drawn as "0 coins".** The
/// guard test `no_tab_paints_a_zero_when_nothing_has_been_read` exists because that went wrong
/// before.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CoinsReading {
    /// The coins were read. An empty list here is a positive statement that the address holds none.
    Known {
        /// The coins, in the order the pages delivered them.
        coins: Vec<ListedCoin>,
        /// Whether that is all of them — and, when it is not, why the walk stopped.
        end: WalkEnd,
    },
    /// A read is under way and has not answered yet. Not a fault, so it names no reason.
    #[default]
    Pending,
    /// No coins could be read, and which thing was missing.
    Unknown(super::overview::BalanceUnknown),
}

/// The listing the Wallet pane draws, per asset.
///
/// Held as a process-global for the same reason [`super::activity`]'s log is: the pane repaints
/// from a snapshot it does not own, and threading a second reading through `TrayView` would put two
/// lanes into one struct whose equality check destructures without a rest pattern.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoinListing {
    /// The XCH coins at the watched address.
    pub xch: CoinsReading,
    /// The $DIG coins at the watched address.
    pub dig: CoinsReading,
}

/// This process's coin listing.
fn app_listing() -> &'static std::sync::Mutex<CoinListing> {
    static LISTING: std::sync::OnceLock<std::sync::Mutex<CoinListing>> = std::sync::OnceLock::new();
    LISTING.get_or_init(|| std::sync::Mutex::new(CoinListing::default()))
}

/// Record what a read of the watched address found.
pub fn remember(listing: CoinListing) {
    let mut held = app_listing().lock().unwrap_or_else(|e| e.into_inner());
    *held = listing;
}

/// What the last read found — [`CoinsReading::Pending`] on both assets before any read has run.
pub fn listing() -> CoinListing {
    app_listing()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Read every coin at `address` for both assets, and record the result.
///
/// Each asset is a SEPARATE read and each keeps its own outcome: `control.wallet.coins` is scoped to
/// one asset, so a node that answers for XCH and refuses for $DIG has said two different things and
/// a single shared outcome would have to discard one of them.
pub fn refresh(
    address: &str,
    mut read: impl FnMut(&str, Asset) -> Result<CoinWalk, super::WalletError>,
    held: Option<&NodeHeld>,
) -> CoinListing {
    let listing = CoinListing {
        xch: one_asset(address, Asset::Xch, &mut read, held),
        dig: one_asset(address, Asset::DIG, &mut read, held),
    };
    remember(listing.clone());
    listing
}

/// One asset's reading, with reservations marked on it.
fn one_asset(
    address: &str,
    asset: Asset,
    read: &mut impl FnMut(&str, Asset) -> Result<CoinWalk, super::WalletError>,
    held: Option<&NodeHeld>,
) -> CoinsReading {
    match read(address, asset) {
        Ok(walked) => {
            let mut coins = walked.coins;
            mark_reservations(&mut coins, held);
            CoinsReading::Known {
                coins,
                end: walked.end,
            }
        }
        Err(error) => CoinsReading::Unknown(super::overview::why_unread(error)),
    }
}
