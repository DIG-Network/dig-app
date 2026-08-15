//! What a chain write is doing right now, and the one place every surface reads it from.
//!
//! # Why this exists (dig_ecosystem#2995)
//!
//! A person pressed **Create my profile** and the window stopped repainting for the length of a
//! two-bundle mainnet ceremony. Nothing was broken — the DID and the store both confirmed — but from
//! outside it was indistinguishable from a crash, and the natural response to a frozen window is to
//! force-quit, which is the one action a creation cannot survive.
//!
//! Two things had to change, and neither is worth anything without the other: the ceremony had to
//! leave the painting thread, and the progress it makes has to be somewhere the window can read.
//! This module is the second half — a small, honest record of what is happening, written by whatever
//! worker is doing the work and read by whatever surface is drawing.
//!
//! # The honesty rule, which is the whole point
//!
//! **Pushed is not confirmed.** A bundle the node accepted is a bundle in a mempool: it may be
//! included in the next block, in twenty blocks, or never. So [`Stage::Pushed`] is a state of its
//! own, it carries the id a person can look up, and NOTHING in this module lets a surface render it
//! as finished — [`Stage::is_confirmed`] is true for exactly one variant, and that variant can only
//! be built from a height the chain reported.
//!
//! This mirrors the discipline dig-account already holds on the same path: its `MintStatus` and
//! `MintedDid` carry a `confirmed_height` taken from evidence, never from a successful broadcast.
//!
//! # What this is NOT
//!
//! Not a transaction history, not a store, and not a queue. It holds the CURRENT write, because the
//! app performs one at a time and the surface that asked for it is the one waiting on it. A history
//! is a separate ticket and a separate shape.

use std::sync::{Arc, Mutex, OnceLock};

use crate::amount::format_asset_amount;
use crate::wallet::state::Asset;

/// How far along a chain write is.
///
/// The order is the real lifecycle, and it is one-way: nothing here moves backwards, because a
/// height the chain reported cannot become un-reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// The spend bundle is being assembled. Nothing has been signed and nothing has been sent.
    Building,
    /// The bundle is being signed, locally.
    ///
    /// The node never sees a key: it is handed a bundle that is already signed (§908), so this stage
    /// is work happening on this machine and nowhere else.
    Signing,
    /// The bundle has been broadcast and **nothing is proven**.
    Pushed {
        /// What a person can look this up by — a coin id, a launcher id, a bundle name.
        ///
        /// Shown verbatim. It is the only handle they have if they want to check the chain
        /// themselves, and a truncated or prettified id is a handle that does not work.
        id: String,
    },
    /// The chain has it, at a height the chain reported.
    Confirmed {
        /// The block height it was seen at.
        height: u32,
        /// What now exists, in the words of the thing that made it.
        made: String,
    },
    /// It did not finish.
    Failed {
        /// Why, in the deciding party's own words.
        why: String,
        /// What the person can do about it — never blank, because a dead end is not an answer.
        next: String,
    },
}

impl Stage {
    /// Whether the chain has PROVED this write.
    ///
    /// The only place in the app allowed to answer that question, so that no surface can come to its
    /// own conclusion about a broadcast. True for exactly one variant, and that variant carries the
    /// height it was proved at.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Whether this write is over — proved or failed — so nothing more will happen to it.
    pub fn is_settled(&self) -> bool {
        matches!(self, Self::Confirmed { .. } | Self::Failed { .. })
    }

    /// Whether money has certainly left the wallet by the time this stage is reached.
    ///
    /// Deliberately conservative in the direction that costs the person nothing to be told: a push
    /// is an acceptance, not an inclusion, so [`Pushed`](Self::Pushed) does not claim it. It is the
    /// same line `CreationStep::money_certainly_moved` draws, for the same reason.
    pub fn money_certainly_moved(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// The word this stage is announced by — short enough for a badge.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Building => "Preparing",
            Self::Signing => "Signing",
            Self::Pushed { .. } => "Waiting for the blockchain",
            Self::Confirmed { .. } => "Confirmed",
            Self::Failed { .. } => "Stopped",
        }
    }

    /// The sentence under the word: what is true right now, and what it does not yet mean.
    ///
    /// The `Pushed` line is the load-bearing one. It says the chain has NOT confirmed it, in the
    /// same breath as saying it was sent, because "Sent" on its own is read as "done".
    pub fn detail(&self) -> String {
        match self {
            Self::Building => "DIG is putting the transaction together. Nothing has been sent."
                .to_string(),
            Self::Signing => {
                "DIG is signing on this device. Your keys never leave it, and nothing has been sent \
                 yet."
                    .to_string()
            }
            Self::Pushed { id } => format!(
                "Sent to the blockchain. It is NOT confirmed yet — a transaction waits in the \
                 mempool until a block includes it, which usually takes a minute or two.\n\n{id}"
            ),
            Self::Confirmed { height, made } => {
                format!("The blockchain confirmed it in block {height}.\n\n{made}")
            }
            Self::Failed { why, next } => format!("{why}\n\n{next}"),
        }
    }
}

/// A chain write in progress, as everything a surface needs to draw it honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// What this write IS, in the person's words — "Creating your profile", "Sending XCH".
    pub what: String,
    /// How far it has got.
    pub stage: Stage,
    /// What it costs, when that is known.
    ///
    /// `None` is not free — it is UNKNOWN, and the surface says nothing rather than showing a zero.
    /// A displayed `0 XCH` on a spend is the money lie this whole module exists to avoid.
    pub money: Option<Money>,
}

impl Transaction {
    /// Start a write at [`Stage::Building`].
    pub fn starting(what: impl Into<String>, money: Option<Money>) -> Self {
        Self {
            what: what.into(),
            stage: Stage::Building,
            money,
        }
    }

    /// The same write, at a new stage.
    pub fn at(&self, stage: Stage) -> Self {
        Self {
            what: self.what.clone(),
            stage,
            money: self.money.clone(),
        }
    }
}

/// What a write costs, in the units the wallet actually spends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    /// What is being moved or committed, in mojos.
    pub amount_mojos: u64,
    /// The network fee, in mojos.
    pub fee_mojos: u64,
}

impl Money {
    /// The amount as a person reads it, whole-coin.
    pub fn amount(&self) -> String {
        format_asset_amount(Asset::Xch, self.amount_mojos)
    }

    /// The fee as a person reads it, whole-coin.
    pub fn fee(&self) -> String {
        format_asset_amount(Asset::Xch, self.fee_mojos)
    }

    /// One line naming both, because a person deciding about a spend needs both at once.
    pub fn line(&self) -> String {
        format!(
            "{} XCH, plus a {} XCH network fee",
            self.amount(),
            self.fee()
        )
    }
}

/// Where the app's current chain write is published.
///
/// # Why one shared feed and not a plumbed handle
///
/// The app performs one chain write at a time and there is one window to show it in. A handle
/// threaded through the tray session, the window host and three constructors would be the same
/// single value with more places to get it wrong — and the writer is a worker thread the shell never
/// sees, so the two ends have no call site in common to pass it through.
///
/// The cost of a shared value is that a test could see another test's transaction, so
/// [`Feed::detached`] exists and every test uses it. Only the app itself reaches for [`Feed::app`].
#[derive(Debug, Clone, Default)]
pub struct Feed {
    /// The current write, or nothing when the app is not writing to the chain.
    current: Arc<Mutex<Option<Transaction>>>,
}

/// The process-wide feed the app's window reads and its workers write.
static APP_FEED: OnceLock<Feed> = OnceLock::new();

impl Feed {
    /// The app's one feed.
    pub fn app() -> Self {
        APP_FEED.get_or_init(Feed::default).clone()
    }

    /// A feed connected to nothing, for tests and galleries.
    pub fn detached() -> Self {
        Self::default()
    }

    /// Publish `transaction` as what is happening now.
    ///
    /// A poisoned lock is dropped silently: the alternative is a panic inside a worker driving a
    /// mainnet ceremony, and a status nobody can read is a far cheaper loss than a creation nobody
    /// finishes.
    pub fn publish(&self, transaction: Transaction) {
        if let Ok(mut slot) = self.current.lock() {
            *slot = Some(transaction);
        }
    }

    /// What is happening now, or `None` when nothing is.
    pub fn read(&self) -> Option<Transaction> {
        self.current.lock().ok().and_then(|slot| slot.clone())
    }

    /// Forget the current write.
    ///
    /// For a settled transaction whose surface has been dismissed. Never called on one still in
    /// flight — clearing that would make an unconfirmed spend vanish from the app, which is the same
    /// class of lie as showing it as done.
    pub fn clear_if_settled(&self) {
        if let Ok(mut slot) = self.current.lock() {
            let settled = slot
                .as_ref()
                .is_some_and(|current| current.stage.is_settled());
            if settled {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A pushed transaction is never confirmed, and never claims the money moved.**
    ///
    /// The defect this whole module exists to prevent, asserted on the two predicates every surface
    /// asks. A push is an acceptance into a mempool; the block that includes it may be twenty blocks
    /// away and may never come.
    #[test]
    fn a_push_is_not_a_confirmation() {
        let pushed = Stage::Pushed {
            id: "0xe4e2b74f915e7f4a739b305aa086aa657a09a8a4df231d9307bb265c528ecc12".to_string(),
        };
        assert!(
            !pushed.is_confirmed(),
            "a broadcast bundle read as confirmed"
        );
        assert!(
            !pushed.is_settled(),
            "a broadcast bundle read as finished, so a surface would stop watching it"
        );
        assert!(
            !pushed.money_certainly_moved(),
            "a broadcast bundle claimed the money certainly left the wallet"
        );
    }

    /// **The pushed state SAYS it is not confirmed, in words, and shows the id.**
    ///
    /// The predicates above are what code reads; this is what the person reads, and they can
    /// disagree. A stage correctly modelled as unconfirmed and captioned `Sent` is still a screen
    /// that says the transaction is done.
    #[test]
    fn the_pushed_wording_denies_the_confirmation_it_does_not_have() {
        let id = "0x111eb8bce53a9b46bedc6a8883b50b6e503ee333384930e93ef3054b25e992be";
        let detail = Stage::Pushed { id: id.to_string() }.detail();
        assert!(
            detail.contains("NOT confirmed"),
            "the pushed line does not deny the confirmation it lacks: {detail}"
        );
        assert!(
            detail.contains(id),
            "the pushed line drops the id, so there is nothing to look up: {detail}"
        );
    }

    /// **Only a chain-reported height reads as confirmed, and the height is shown.**
    #[test]
    fn a_confirmation_carries_the_height_the_chain_reported() {
        let stage = Stage::Confirmed {
            height: 9_154_450,
            made: "did:chia:1mhdr5h6".to_string(),
        };
        assert!(stage.is_confirmed());
        assert!(stage.is_settled());
        assert!(stage.money_certainly_moved());
        assert!(
            stage.detail().contains("9154450"),
            "a confirmation that does not say which block it is in: {}",
            stage.detail()
        );
    }

    /// **A failure names a next action.**
    ///
    /// A stopped ceremony with no next step is a dead end, which `professional-ui` forbids
    /// outright — and this is the state where the person is most likely to reach for the one action
    /// that makes it worse.
    #[test]
    fn a_failure_says_what_to_do_next() {
        let stage = Stage::Failed {
            why: "DIG lost its connection to the node.".to_string(),
            next: "Leave DIG running; it will keep watching.".to_string(),
        };
        let detail = stage.detail();
        assert!(detail.contains("Leave DIG running"), "{detail}");
        assert!(stage.is_settled());
    }

    /// **Money is shown as an amount AND a fee, and an unknown cost shows neither.**
    ///
    /// A spend surface that renders an unknown cost as `0 XCH` has told the person the transaction
    /// is free. `None` is the absence of a measurement, not a zero.
    #[test]
    fn a_cost_is_stated_in_full_or_not_at_all() {
        let money = Money {
            amount_mojos: 20_002,
            fee_mojos: 1,
        };
        let line = money.line();
        assert!(line.contains(&money.amount()), "{line}");
        assert!(line.contains(&money.fee()), "{line}");

        let unknown = Transaction::starting("Creating your profile", None);
        assert_eq!(unknown.money, None);
    }

    /// **A feed hands back exactly what was published, and one feed cannot read another.**
    ///
    /// The second half is what makes the shared app feed safe to test around: two detached feeds are
    /// genuinely separate, so a test can never see another's transaction.
    #[test]
    fn a_feed_reports_the_write_that_was_published_to_it() {
        let feed = Feed::detached();
        assert_eq!(feed.read(), None);

        let started = Transaction::starting("Creating your profile", None);
        feed.publish(started.clone());
        assert_eq!(feed.read(), Some(started));

        let other = Feed::detached();
        assert_eq!(other.read(), None, "two detached feeds share state");
    }

    /// **An unsettled write survives a dismissal; a settled one is cleared.**
    ///
    /// Dismissing the status surface must not cancel or hide an in-flight spend — the person can
    /// come back to it, which is the whole reason dismissing is allowed at all. Only a proved or
    /// failed write is forgotten.
    #[test]
    fn dismissing_cannot_forget_a_transaction_that_is_still_in_flight() {
        let feed = Feed::detached();
        let tx = Transaction::starting("Creating your profile", None);

        for still_going in [
            Stage::Building,
            Stage::Signing,
            Stage::Pushed {
                id: "0xabc".to_string(),
            },
        ] {
            feed.publish(tx.at(still_going.clone()));
            feed.clear_if_settled();
            assert_eq!(
                feed.read().map(|t| t.stage),
                Some(still_going.clone()),
                "an in-flight write at {still_going:?} was forgotten on dismissal"
            );
        }

        feed.publish(tx.at(Stage::Confirmed {
            height: 9_154_458,
            made: "a profile".to_string(),
        }));
        feed.clear_if_settled();
        assert_eq!(feed.read(), None, "a settled write was not cleared");
    }
}
