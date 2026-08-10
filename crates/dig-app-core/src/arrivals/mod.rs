//! Confirmed incoming-funds detection (dig_ecosystem#2548) — the model behind the "you were paid"
//! toast.
//!
//! A notification is a CLAIM ABOUT SOMEBODY'S MONEY, so this module exists to make the four ways
//! that claim can be false structurally hard to write rather than merely avoided by care:
//!
//! | Failure | What stops it here |
//! |---|---|
//! | The first sync announces the whole address history | [`ArrivalLedger`] has no baseline until its first observation, and an observation without a baseline ADOPTS silently |
//! | A restart, a re-sync or a reorg re-scan re-announces | the ledger is durable ([`store`]) and keyed on coin id, so a coin is accounted for exactly once across processes |
//! | A mempool sighting is announced as money | a [`ConfirmedCoin`] cannot hold an absent height, and a [`ChainView`] cannot be built from a read that did not prove it was caught up |
//! | The user's own change is announced as a payment | a coin whose parent is a coin this ledger already holds can only have come from spending our own coin, and is suppressed |
//!
//! # The seam
//!
//! [`ArrivalSource`] is the ONE thing the rest of the app depends on: something that can hand over a
//! [`ChainView`] — a confirmed, caught-up picture of the watched address. [`watch`] implements it
//! over the node's `control.wallet.coins` today. When dig-node grows a pushed
//! `WalletEvent::FundsReceived` stream, the new producer implements this same trait and nothing
//! above it changes.
//!
//! # The limitation this design does not hide
//!
//! **Nothing is notified while dig-app is not running.** There is no background service behind this
//! — the detection runs inside the tray process, off its own poll. A payment that lands while the
//! app is closed is not announced when the app next starts either: it arrived before that run's
//! ledger caught up with it, and re-announcing history on launch is the first failure in the table
//! above. The wallet surface still shows it; only the toast is missed. Making a closed app speak
//! would need a node-side notifier, which is a different component.

pub mod store;
pub mod watch;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::wallet::state::Asset;

/// How many coin ids a ledger remembers before it starts forgetting the oldest.
///
/// A personal wallet does not reach this — it is the bound that keeps `arrivals.json` from growing
/// without limit over years rather than a number tuned to anything. See [`ArrivalLedger::prune`] for
/// what forgetting costs.
pub const LEDGER_CAPACITY: usize = 20_000;

/// One confirmed, unspent coin at a watched address.
///
/// `confirmed_height` is a `u32` and not an `Option<u32>` on purpose: the node reports a coin that is
/// only in the mempool with no created height, and this type is the boundary that refuses to carry
/// one. A mempool sighting therefore cannot reach the ledger at all — there is no value of this
/// struct that expresses "seen but not confirmed" (dig_ecosystem#2548, trap 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedCoin {
    /// The coin id, lowercase 64-hex, unprefixed — the identity the ledger dedups on.
    pub coin_id: String,
    /// The id of the coin that was spent to create this one.
    ///
    /// This is the ONLY thing that separates a payment from the user's own change, so it is carried
    /// even though nothing displays it: a coin whose parent is a coin we already hold could only
    /// have been created by spending our own coin.
    pub parent_coin_id: String,
    /// Which asset the coin is denominated in.
    pub asset: Asset,
    /// The amount, in that asset's base unit (mojos for XCH, base units for $DIG).
    pub amount: u64,
    /// The block height the coin was created at.
    pub confirmed_height: u32,
}

/// A confirmed, caught-up picture of a watched address.
///
/// Built ONLY through [`ChainView::of_read`], which refuses every read that cannot bound its own
/// confirmation. There is deliberately no public constructor and no public field: a caller cannot
/// assemble a view out of an answer the node declined to vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    peak_height: u32,
    coins: Vec<ConfirmedCoin>,
}

impl ChainView {
    /// The view a chain read produced, or `None` when the read cannot support one.
    ///
    /// Two refusals, both fail-closed:
    ///
    /// - `synced == false` — the node said these figures are stale or came from the third-party
    ///   oracle tier. A stale coin set is indistinguishable from a current one once it is a toast.
    /// - `peak_height == None` — the contract is explicit that a null peak MUST be read as unknown
    ///   and never as height zero, which every block is trivially above. Without a peak there is
    ///   nothing to set a baseline from, so there is no honest first observation.
    pub fn of_read(
        synced: bool,
        peak_height: Option<u32>,
        coins: Vec<ConfirmedCoin>,
    ) -> Option<Self> {
        match (synced, peak_height) {
            (true, Some(peak_height)) => Some(Self { peak_height, coins }),
            _ => None,
        }
    }

    /// The peak height these coins reflect.
    pub fn peak_height(&self) -> u32 {
        self.peak_height
    }

    /// The confirmed coins the read found.
    pub fn coins(&self) -> &[ConfirmedCoin] {
        &self.coins
    }
}

/// A confirmed payment INTO the watched address — the thing a notification may honestly announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {
    /// The coin that arrived.
    pub coin_id: String,
    /// Which asset it is denominated in.
    pub asset: Asset,
    /// How much, in that asset's base unit.
    pub amount: u64,
    /// The height it was confirmed at.
    pub confirmed_height: u32,
}

/// What this process has already accounted for — the durable memory that makes an arrival a
/// once-in-a-lifetime event for a given coin.
///
/// Persisted by [`store`]; see the module docs for the four properties it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrivalLedger {
    /// The height at or below which a newly-noticed coin is HISTORY rather than an arrival.
    ///
    /// `None` means this ledger has never observed anything, which is what makes the first
    /// observation an adoption rather than a flood of toasts.
    #[serde(default)]
    baseline_height: Option<u32>,
    /// Every coin id this ledger has accounted for, and the height it was confirmed at.
    ///
    /// Spent coins are kept, not dropped: a spent coin is exactly the parent a change coin points
    /// at, and forgetting it is what would let the user's own change read as a payment.
    #[serde(default)]
    seen: BTreeMap<String, u32>,
}

impl ArrivalLedger {
    /// A ledger that has observed nothing. Its first [`observe`](Self::observe) adopts.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The height below which coins are history, or `None` before the first observation.
    pub fn baseline_height(&self) -> Option<u32> {
        self.baseline_height
    }

    /// How many coin ids are remembered.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }

    /// Account for `view`, and report the confirmed arrivals in it.
    ///
    /// The first call on a fresh ledger ADOPTS: every coin is recorded, the baseline is set to the
    /// view's peak, and nothing is announced. Somebody who installs dig-app on a wallet with ten
    /// years of history is told about the next payment, not the last thousand.
    ///
    /// Afterwards a coin is an arrival when ALL of these hold, and each is a separate way to be
    /// wrong:
    ///
    /// - it is not already in [`seen`](Self::seen) — a re-scan, a reorg re-walk or a restart
    ///   re-presents the same coins, and each is accounted for once;
    /// - it was confirmed ABOVE the baseline — a coin at or below it belongs to the history this
    ///   ledger adopted, even if this is the first read that happened to include it;
    /// - its parent is not a coin we hold — that would make it the output of spending our own coin,
    ///   i.e. change.
    ///
    /// Every coin is recorded whatever the verdict, so a suppressed coin is suppressed exactly once
    /// and can itself be a change coin's parent next time.
    pub fn observe(&mut self, view: &ChainView) -> Vec<Arrival> {
        let Some(baseline) = self.baseline_height else {
            self.adopt(view);
            return Vec::new();
        };

        // Ascending height so a parent recorded in the same batch is already present when its child
        // is judged. Coins at one height are ordered by id, so the outcome does not depend on the
        // order the node happened to list them in.
        let mut coins: Vec<&ConfirmedCoin> = view.coins.iter().collect();
        coins.sort_by(|a, b| {
            a.confirmed_height
                .cmp(&b.confirmed_height)
                .then_with(|| a.coin_id.cmp(&b.coin_id))
        });

        let mut arrivals = Vec::new();
        for coin in coins {
            if self.seen.contains_key(&coin.coin_id) {
                continue;
            }
            let is_history = coin.confirmed_height <= baseline;
            let is_own_change = self.seen.contains_key(&coin.parent_coin_id);
            self.seen
                .insert(coin.coin_id.clone(), coin.confirmed_height);
            if is_history || is_own_change {
                continue;
            }
            arrivals.push(Arrival {
                coin_id: coin.coin_id.clone(),
                asset: coin.asset,
                amount: coin.amount,
                confirmed_height: coin.confirmed_height,
            });
        }
        self.prune();
        arrivals
    }

    /// Record everything in `view` as already-known history and set the baseline.
    fn adopt(&mut self, view: &ChainView) {
        for coin in &view.coins {
            self.seen
                .insert(coin.coin_id.clone(), coin.confirmed_height);
        }
        self.baseline_height = Some(view.peak_height);
        self.prune();
    }

    /// Forget the oldest coins once [`LEDGER_CAPACITY`] is exceeded, raising the baseline to cover
    /// what was forgotten.
    ///
    /// Raising the baseline is what keeps forgetting safe for the dedup property: a forgotten coin
    /// re-presented by a re-scan is at or below the new baseline and is read as history rather than
    /// as a fresh arrival.
    ///
    /// **What it does not cover, stated plainly:** change whose PARENT was forgotten. The parent is
    /// old (that is why it was forgotten) while the change coin is new, so the parent test cannot
    /// see it and the change would be announced once as a payment. Reaching this needs more than
    /// [`LEDGER_CAPACITY`] coins at one address, which a personal wallet does not do; a node-side
    /// producer that sees spends directly (see the module docs' seam) removes the case entirely.
    fn prune(&mut self) {
        if self.seen.len() <= LEDGER_CAPACITY {
            return;
        }
        let mut by_height: Vec<(String, u32)> =
            self.seen.iter().map(|(id, h)| (id.clone(), *h)).collect();
        by_height.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let drop_count = self.seen.len() - LEDGER_CAPACITY;
        let mut highest_dropped = 0u32;
        for (id, height) in by_height.into_iter().take(drop_count) {
            self.seen.remove(&id);
            highest_dropped = highest_dropped.max(height);
        }
        self.baseline_height = Some(self.baseline_height.unwrap_or(0).max(highest_dropped));
    }
}

/// Why a chain view could not be taken.
///
/// `NotConfirmable` is deliberately not an error a surface reports: it is the ordinary state of a
/// node that is still catching up, and the honest response is to try again later rather than to say
/// anything about money.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArrivalSourceError {
    /// The node answered, but the answer could not bound its own confirmation (not synced, or no
    /// peak height). Nothing is claimed and nothing is recorded.
    #[error("the node's answer did not prove it was caught up")]
    NotConfirmable,
    /// The read failed — unreachable node, a refusal, a timeout.
    #[error("{0}")]
    Unavailable(String),
}

/// The seam confirmed chain state arrives through.
///
/// Implemented today by [`watch::ControlPlaneSource`] over `control.wallet.coins`. A future
/// dig-node that PUSHES confirmed funds events implements this same trait over that stream, and
/// [`ArrivalLedger`] — which is where every honesty property lives — does not change.
pub trait ArrivalSource {
    /// The confirmed, caught-up picture of the watched address right now.
    fn view(&self) -> Result<ChainView, ArrivalSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(id: &str, parent: &str, height: u32) -> ConfirmedCoin {
        ConfirmedCoin {
            coin_id: id.to_string(),
            parent_coin_id: parent.to_string(),
            asset: Asset::Xch,
            amount: 1_000_000_000_000,
            confirmed_height: height,
        }
    }

    fn view(peak: u32, coins: Vec<ConfirmedCoin>) -> ChainView {
        ChainView::of_read(true, Some(peak), coins).expect("a synced read with a peak")
    }

    fn ids(arrivals: &[Arrival]) -> Vec<&str> {
        arrivals.iter().map(|a| a.coin_id.as_str()).collect()
    }

    // ------------------------------------------------------------------------------------------
    // TRAP 1 — the first sync must not notify
    // ------------------------------------------------------------------------------------------

    /// **A fresh ledger's first read announces nothing, however much history it contains.**
    ///
    /// The naive implementation — "a coin I have not recorded is an arrival" — fires once per
    /// historical coin the moment the app is installed on a wallet that has ever been used. The
    /// fixture is deliberately a wallet with several old coins so that implementation cannot pass.
    #[test]
    fn the_first_observation_adopts_history_without_announcing_it() {
        let mut ledger = ArrivalLedger::empty();
        let announced = ledger.observe(&view(
            500,
            vec![
                coin("a", "parent-a", 10),
                coin("b", "parent-b", 200),
                coin("c", "parent-c", 499),
            ],
        ));
        assert!(
            announced.is_empty(),
            "the first sync announced {:?}",
            ids(&announced)
        );
        assert_eq!(ledger.baseline_height(), Some(500));
        assert_eq!(ledger.remembered(), 3, "the history must be accounted for");
    }

    /// **A coin first SEEN after adoption but CONFIRMED at or below the baseline is still history.**
    ///
    /// Adoption records what one read happened to contain. A coin can legitimately show up in a
    /// later read while belonging to the same history — a paging difference, an asset the first
    /// read did not cover, a node that had not finished its own catch-up. The baseline, not the
    /// adoption snapshot, is what decides.
    #[test]
    fn a_coin_confirmed_at_or_below_the_baseline_is_history_not_an_arrival() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(500, vec![coin("a", "parent-a", 10)]));

        let at_the_baseline = ledger.observe(&view(600, vec![coin("old", "stranger", 500)]));
        assert!(
            at_the_baseline.is_empty(),
            "a coin confirmed at the baseline was announced: {:?}",
            ids(&at_the_baseline)
        );

        // The control: one block ABOVE the baseline is a real arrival, so the assertion above is
        // about the boundary rather than about the ledger having stopped announcing anything.
        let above = ledger.observe(&view(600, vec![coin("new", "stranger", 501)]));
        assert_eq!(ids(&above), vec!["new"]);
    }

    // ------------------------------------------------------------------------------------------
    // TRAP 2 — a restart must not re-notify
    // ------------------------------------------------------------------------------------------

    /// **The same coin is announced exactly once, however many times it is re-presented.**
    ///
    /// Covers all three ways a coin comes round again: an ordinary repeat poll, a reorg re-scan
    /// that re-walks the range, and a restart that reloads the ledger from disk.
    #[test]
    fn a_coin_is_announced_once_across_repeats_rescans_and_restarts() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(100, vec![coin("old", "stranger", 50)]));

        let first = ledger.observe(&view(
            200,
            vec![coin("old", "stranger", 50), coin("paid", "stranger", 150)],
        ));
        assert_eq!(
            ids(&first),
            vec!["paid"],
            "the arrival must be announced once"
        );

        // The same poll again.
        let repeat = ledger.observe(&view(
            201,
            vec![coin("old", "stranger", 50), coin("paid", "stranger", 150)],
        ));
        assert!(
            repeat.is_empty(),
            "a repeat poll re-announced {:?}",
            ids(&repeat)
        );

        // A reorg re-scan: the node re-walks from lower down and re-presents the coin.
        let rescan = ledger.observe(&view(
            210,
            vec![coin("paid", "stranger", 150), coin("old", "stranger", 50)],
        ));
        assert!(
            rescan.is_empty(),
            "a re-scan re-announced {:?}",
            ids(&rescan)
        );

        // A RESTART: the ledger is serialized, the process ends, a new one loads it.
        let json = serde_json::to_string(&ledger).expect("serializable");
        let mut after_restart: ArrivalLedger = serde_json::from_str(&json).expect("deserializable");
        let restarted = after_restart.observe(&view(220, vec![coin("paid", "stranger", 150)]));
        assert!(
            restarted.is_empty(),
            "a restart re-announced {:?} — the dedup is not durable",
            ids(&restarted)
        );
    }

    // ------------------------------------------------------------------------------------------
    // TRAP 3 — only confirmed arrivals
    // ------------------------------------------------------------------------------------------

    /// **A read that cannot bound its own confirmation yields no view at all.**
    ///
    /// Both refusals are separate facts and both are asserted: an unsynced answer, and an answer
    /// with no peak height. The control at the end is what stops this passing on a constructor that
    /// refuses everything.
    #[test]
    fn a_read_that_cannot_prove_it_is_caught_up_yields_no_view() {
        let coins = vec![coin("a", "stranger", 10)];
        assert_eq!(
            ChainView::of_read(false, Some(100), coins.clone()),
            None,
            "an unsynced read produced a view"
        );
        assert_eq!(
            ChainView::of_read(true, None, coins.clone()),
            None,
            "a read with no peak height produced a view — null was read as a height"
        );
        assert_eq!(
            ChainView::of_read(false, None, coins.clone()),
            None,
            "neither synced nor heighted, and it still produced a view"
        );
        assert!(
            ChainView::of_read(true, Some(100), coins).is_some(),
            "a synced read WITH a peak must produce a view, or nothing is ever announced"
        );
    }

    // ------------------------------------------------------------------------------------------
    // TRAP 4 — change is not an arrival
    // ------------------------------------------------------------------------------------------

    /// **A coin created by spending one of our own coins is change, not a payment.**
    ///
    /// The fixture is the shape a real send leaves behind: a coin we hold disappears (it was spent)
    /// and a new coin at our own address appears in its place, carrying the spent coin's id as its
    /// parent. The control — the identical coin with a parent nobody here has ever held — is what
    /// makes this a test about parentage rather than about the ledger having gone quiet.
    #[test]
    fn the_users_own_change_is_not_announced_as_a_payment() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(100, vec![coin("mine", "stranger", 50)]));

        // The send: `mine` is gone from the unspent set, and `change` took its place.
        let after_send = ledger.observe(&view(120, vec![coin("change", "mine", 110)]));
        assert!(
            after_send.is_empty(),
            "the user's own change was announced as a payment: {:?}",
            ids(&after_send)
        );

        // The control: the SAME shape of coin, from a parent this wallet never held.
        let payment = ledger.observe(&view(130, vec![coin("gift", "somebody-elses-coin", 125)]));
        assert_eq!(
            ids(&payment),
            vec!["gift"],
            "a real payment must still be announced"
        );
    }

    /// **A suppressed change coin is itself remembered, so the NEXT change is suppressed too.**
    ///
    /// Without this the parent chain breaks after one hop: spend the change, and the change of the
    /// change has a parent nobody recorded, which reads as a stranger paying us.
    #[test]
    fn change_of_change_is_still_change() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(100, vec![coin("mine", "stranger", 50)]));
        ledger.observe(&view(110, vec![coin("change1", "mine", 105)]));
        let second = ledger.observe(&view(120, vec![coin("change2", "change1", 115)]));
        assert!(
            second.is_empty(),
            "the change of the change was announced: {:?}",
            ids(&second)
        );
    }

    /// **A parent recorded in the SAME batch still suppresses its child.**
    ///
    /// Coins are judged in height order rather than in the order the node listed them, so a batch
    /// containing both a new coin and something descended from it cannot depend on the node's
    /// ordering. The fixture lists the child FIRST, which is the order that fails a naive loop.
    #[test]
    fn a_parent_seen_in_the_same_batch_still_suppresses_its_child() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(100, vec![]));
        let batch = ledger.observe(&view(
            200,
            vec![coin("child", "paid", 150), coin("paid", "stranger", 140)],
        ));
        assert_eq!(
            ids(&batch),
            vec!["paid"],
            "the child of a coin in the same batch was announced as its own payment"
        );
    }

    // ------------------------------------------------------------------------------------------
    // The ordinary path + the bound
    // ------------------------------------------------------------------------------------------

    /// **The amount and asset an arrival carries are the coin's own, not a default.**
    #[test]
    fn an_arrival_carries_the_coins_own_asset_and_amount() {
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(100, vec![]));
        let arrivals = ledger.observe(&view(
            200,
            vec![
                ConfirmedCoin {
                    coin_id: "dig".into(),
                    parent_coin_id: "stranger".into(),
                    asset: Asset::Dig,
                    amount: 2_500,
                    confirmed_height: 150,
                },
                ConfirmedCoin {
                    coin_id: "xch".into(),
                    parent_coin_id: "stranger".into(),
                    asset: Asset::Xch,
                    amount: 1_500_000_000_000,
                    confirmed_height: 151,
                },
            ],
        ));
        assert_eq!(arrivals.len(), 2);
        let dig = arrivals
            .iter()
            .find(|a| a.coin_id == "dig")
            .expect("the DIG coin");
        assert_eq!(dig.asset, Asset::Dig);
        assert_eq!(dig.amount, 2_500);
        let xch = arrivals
            .iter()
            .find(|a| a.coin_id == "xch")
            .expect("the XCH coin");
        assert_eq!(xch.asset, Asset::Xch);
        assert_eq!(xch.amount, 1_500_000_000_000);
    }

    /// **Forgetting the oldest coins raises the baseline over them, so they cannot come back as new.**
    #[test]
    fn pruning_raises_the_baseline_over_what_it_forgot() {
        let mut ledger = ArrivalLedger::empty();
        let history: Vec<ConfirmedCoin> = (0..LEDGER_CAPACITY + 10)
            .map(|i| coin(&format!("coin-{i:06}"), "stranger", i as u32 + 1))
            .collect();
        let oldest = history[0].clone();
        ledger.observe(&view(1, history));

        assert_eq!(ledger.remembered(), LEDGER_CAPACITY, "the bound must hold");
        assert!(
            ledger.baseline_height().unwrap() >= oldest.confirmed_height,
            "the baseline did not cover the coins that were forgotten"
        );
        let re_presented = ledger.observe(&view(999_999, vec![oldest]));
        assert!(
            re_presented.is_empty(),
            "a forgotten coin came back as a new arrival: {:?}",
            ids(&re_presented)
        );
    }
}
