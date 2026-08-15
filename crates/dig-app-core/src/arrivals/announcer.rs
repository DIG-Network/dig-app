//! The single place that answers "may this arrival be announced?" (dig_ecosystem#2959).
//!
//! # Two instruments, two jobs
//!
//! [`ArrivalCursor`] is the right instrument for FETCHING and the wrong one for DECIDING. Its
//! position is a `seq`, and `seq` is `AUTOINCREMENT` in the node's `arrivals` table — a per-database
//! ordinal, not a property of the coin. It is stable only while that one `wallet.sqlite` survives.
//! Delete, restore or rebuild the node's database and every coin re-enters at a LOW `seq`: a machine
//! that adopted at `latest = 5` then asks for everything after 5, is handed the whole replayed
//! history, and toasts hundreds of times for money it already reported. **A notification that money
//! arrived is a claim about money**, so that is not a cosmetic annoyance.
//!
//! The coin id is a property of the coin, so it survives the database that indexed it. This module
//! therefore keeps the cursor for paging and makes the coin id decide announcing:
//! [`ArrivalAnnouncer::advance`] is the one decision site, and `watch::sweep` has no second opinion.
//!
//! # Why the set is bounded, and why pruning cannot resurrect a notification
//!
//! Remembering every coin id ever announced grows without limit on a long-lived wallet, so only the
//! most recent [`RETAINED_COINS`] are kept by insertion order. Eviction alone would let an old coin
//! look new again, so each eviction raises a horizon: `pruned_below_height` is the highest
//! `confirmed_height` ever evicted, and **an arrival is suppressed if its coin id is retained OR its
//! `confirmed_height` is at or below the horizon.** An evicted coin does not become new — it falls
//! under the horizon.
//!
//! # The asymmetry: an ABSENT set means "already announced", not "nothing announced"
//!
//! This looks like a bug on sight and is the whole point. An empty *set* read literally says nothing
//! has been announced, which on a corrupt or missing record would announce the node's entire ledger —
//! precisely the defect this module exists to prevent. So the persisted set is an `Option`, and
//! `None` is an ADOPT state rather than an empty set: the next page is suppressed ENTIRELY and its
//! highest `confirmed_height` becomes the horizon.
//!
//! That is the same fail-closed mechanic [`ArrivalCursor::unread`] is already trusted for — an unread
//! cursor announces NOTHING and jumps to `page.latest`. Reusing it keeps one concept here instead of
//! two. The cost is at most one page of missed toasts on a corrupted record; the cost of the opposite
//! is toasting a whole ledger.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::{Arrival, ArrivalCursor, ArrivalPage};

/// How many announced coin ids are retained, most recent first-out-last.
///
/// Large enough that ordinary use never evicts (a wallet receiving ten payments a day reaches it in
/// fourteen months), small enough that the record stays a few tens of kilobytes of JSON. Eviction is
/// safe rather than merely rare, because of the horizon — this number trades file size against how
/// far back a coin can be re-offered at a height ABOVE the horizon and still be recognised.
const RETAINED_COINS: usize = 512;

/// One announced coin, kept with the height that lets eviction raise the horizon honestly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AnnouncedCoin {
    coin_id: String,
    confirmed_height: u32,
}

/// The bounded record of coins already announced on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AnnouncedCoins {
    /// Insertion-ordered, oldest at the front. Bounded by [`RETAINED_COINS`].
    #[serde(default)]
    coins: VecDeque<AnnouncedCoin>,
    /// The highest `confirmed_height` ever evicted, or adopted. Anything at or below it is treated
    /// as already announced.
    #[serde(default)]
    pruned_below_height: u32,
}

impl AnnouncedCoins {
    /// The state a page ADOPTS into: nothing retained, and everything it carried under the horizon.
    fn adopting(page: &ArrivalPage) -> Self {
        Self {
            coins: VecDeque::new(),
            pruned_below_height: page
                .arrivals
                .iter()
                .map(|arrival| arrival.confirmed_height)
                .max()
                .unwrap_or(0),
        }
    }

    /// Whether `arrival` may be announced, recording it when it may.
    fn admit(&mut self, arrival: &Arrival) -> bool {
        if arrival.confirmed_height <= self.pruned_below_height {
            return false;
        }
        if self
            .coins
            .iter()
            .any(|announced| announced.coin_id == arrival.coin_id)
        {
            return false;
        }
        self.coins.push_back(AnnouncedCoin {
            coin_id: arrival.coin_id.clone(),
            confirmed_height: arrival.confirmed_height,
        });
        while self.coins.len() > RETAINED_COINS {
            let evicted = self.coins.pop_front().expect("len exceeds the bound");
            self.pruned_below_height = self.pruned_below_height.max(evicted.confirmed_height);
        }
        true
    }
}

/// What this machine has been told, and what it has said about it.
///
/// Persisted whole by [`super::store`]: the cursor and the coin record must fail together, because a
/// cursor that survived a lost coin record would page past arrivals the record could no longer
/// recognise.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrivalAnnouncer {
    #[serde(default)]
    cursor: ArrivalCursor,
    /// `None` is the ADOPT state — see the module docs. It is deliberately not an empty set.
    #[serde(default)]
    announced: Option<AnnouncedCoins>,
}

impl ArrivalAnnouncer {
    /// A machine that has never read the ledger. Its first [`advance`](Self::advance) adopts.
    pub fn unread() -> Self {
        Self::default()
    }

    /// The ledger position to resume paging from, or `None` before the first read.
    pub fn position(&self) -> Option<u64> {
        self.cursor.position()
    }

    /// Take `page` into account and report what may honestly be announced.
    ///
    /// The cursor decides what is NEW to this machine's paging; the coin record decides what has
    /// actually been SAID. Both must agree before a toast is drawn, and an adopt state overrides
    /// both by saying nothing at all.
    pub fn advance(&mut self, page: &ArrivalPage) -> Vec<Arrival> {
        let candidates = self.cursor.advance(page);
        let Some(announced) = self.announced.as_mut() else {
            self.announced = Some(AnnouncedCoins::adopting(page));
            return Vec::new();
        };
        candidates
            .into_iter()
            .filter(|arrival| announced.admit(arrival))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arrival(seq: u64, coin: u64, height: u32) -> Arrival {
        Arrival {
            seq,
            coin_id: format!("{coin:064x}"),
            asset_id: None,
            amount: 1_000,
            confirmed_height: height,
        }
    }

    fn page(arrivals: Vec<Arrival>, after_seq: u64, latest: u64) -> ArrivalPage {
        let cursor = arrivals.last().map_or(after_seq, |a| a.seq);
        ArrivalPage {
            arrivals,
            cursor,
            latest,
        }
    }

    /// **A coin announced once is not announced again after the node's table is rebuilt.**
    ///
    /// The fixture reproduces the real defect rather than a repeat poll: the machine adopts at a LOW
    /// `latest`, is told about coin `aaa` at seq 6, and then the node's `arrivals` table is rebuilt
    /// and replays the whole history — so `aaa` comes back at a DIFFERENT `seq`, which is exactly
    /// what a `seq`-keyed filter cannot see.
    ///
    /// `aaa` is deliberately renumbered ABOVE the cursor, because that is where the defect lives: a
    /// rebuild that renumbers BELOW it is swallowed by the cursor's floor and cannot exhibit this
    /// property at all, so a fixture built that way would prove nothing about the coin filter. The
    /// pages are built by hand because the helper derives `cursor` from the rows and cannot express a
    /// genuinely renumbered ledger.
    ///
    /// The second coin is the control: without it, "exactly one notification" is equally satisfied by
    /// a filter that suppresses everything.
    #[test]
    fn a_rebuilt_ledger_reissuing_low_seqs_does_not_re_announce_the_same_coin() {
        let mut announcer = ArrivalAnnouncer::unread();
        announcer.advance(&page(vec![], 0, 5));

        let first = announcer.advance(&ArrivalPage {
            arrivals: vec![arrival(6, 0xaaa, 5_412_100)],
            cursor: 6,
            latest: 6,
        });
        assert_eq!(
            first.iter().map(|a| a.coin_id.clone()).collect::<Vec<_>>(),
            vec![arrival(6, 0xaaa, 0).coin_id],
            "the arrival was never announced in the first place"
        );

        // The node's table is rebuilt and replays its history: the same coin returns at seq 300, and
        // a genuinely new coin follows it at seq 301.
        let replayed = announcer.advance(&ArrivalPage {
            arrivals: vec![
                arrival(300, 0xaaa, 5_412_100),
                arrival(301, 0xbbb, 5_412_400),
            ],
            cursor: 301,
            latest: 301,
        });
        assert_eq!(
            replayed
                .iter()
                .map(|a| a.coin_id.clone())
                .collect::<Vec<_>>(),
            vec![arrival(0, 0xbbb, 0).coin_id],
            "a rebuilt ledger re-announced money that had already been reported, \
             or suppressed a genuinely new coin"
        );
    }

    /// **Pruning cannot resurrect an old notification.**
    ///
    /// More coins are announced than the record retains, so the earliest are evicted; re-serving one
    /// of them at a seq above the cursor must still say nothing, because its height sits at or below
    /// the horizon eviction raised. The control at the end is a coin ABOVE the horizon, proving the
    /// horizon suppresses by height rather than suppressing everything.
    #[test]
    fn a_coin_evicted_from_the_record_is_not_announced_again() {
        let mut announcer = ArrivalAnnouncer::unread();
        announcer.advance(&page(vec![], 0, 0));

        let evicted = arrival(1, 1, 5_000_001);
        for seq in 1..=(RETAINED_COINS as u64 + 8) {
            let announced = announcer.advance(&page(
                vec![arrival(seq, seq, 5_000_000 + seq as u32)],
                seq - 1,
                seq,
            ));
            assert_eq!(announced.len(), 1, "arrival {seq} was not announced");
        }

        let resurrected = announcer.advance(&ArrivalPage {
            arrivals: vec![Arrival {
                seq: 9_000,
                ..evicted
            }],
            cursor: 9_000,
            latest: 9_000,
        });
        assert!(
            resurrected.is_empty(),
            "an evicted coin was announced a second time"
        );

        let fresh = announcer.advance(&ArrivalPage {
            arrivals: vec![arrival(9_001, 0xffff, 6_000_000)],
            cursor: 9_001,
            latest: 9_001,
        });
        assert_eq!(
            fresh.len(),
            1,
            "the horizon suppressed a coin above it, not merely the evicted one"
        );
    }

    /// **An absent coin record adopts in silence instead of announcing the ledger.**
    ///
    /// This is the in-memory half of the fail-closed rule; `store` covers the corrupt-file half.
    #[test]
    fn a_record_with_no_coin_set_suppresses_the_page_it_adopts() {
        let mut announcer = ArrivalAnnouncer::unread();
        let announced = announcer.advance(&page(
            vec![
                arrival(1, 1, 5_412_001),
                arrival(2, 2, 5_412_002),
                arrival(3, 3, 5_412_003),
            ],
            0,
            3,
        ));
        assert!(
            announced.is_empty(),
            "an adopting record announced {} historical arrivals",
            announced.len()
        );

        // And the adopted page is under the horizon afterwards, so a replay of it stays silent while
        // a later arrival is still announced.
        let replay = announcer.advance(&ArrivalPage {
            arrivals: vec![arrival(4, 2, 5_412_002)],
            cursor: 4,
            latest: 4,
        });
        assert!(replay.is_empty(), "an adopted arrival was announced later");
        let later = announcer.advance(&page(vec![arrival(5, 5, 5_412_010)], 4, 5));
        assert_eq!(later.len(), 1, "the horizon suppressed everything after it");
    }

    /// **The record survives its own JSON**, which is what makes a restart silent.
    ///
    /// This is the ONLY cover for the coin set's persistence, so its fixture has to be able to see
    /// the set. A coin replayed BELOW the persisted cursor proves nothing: `ArrivalCursor`'s floor
    /// filters that row before [`AnnouncedCoins::admit`] is ever consulted, so the assertion is
    /// answered by the cursor and a set that silently failed to serialize — a `#[serde(skip)]`, a
    /// renamed field — would leave this green while every restart re-announced the ledger. The coin
    /// therefore returns ABOVE the cursor, the same correction
    /// [`a_rebuilt_ledger_reissuing_low_seqs_does_not_re_announce_the_same_coin`] already carries.
    ///
    /// The second coin is the control: without it "suppressed" is equally satisfied by a reloaded
    /// record that announces nothing at all.
    #[test]
    fn a_reloaded_record_still_recognises_the_coins_it_announced() {
        let mut announcer = ArrivalAnnouncer::unread();
        announcer.advance(&page(vec![], 0, 4));
        assert_eq!(
            announcer
                .advance(&page(vec![arrival(5, 5, 5_412_500)], 4, 5))
                .len(),
            1
        );

        let json = serde_json::to_string(&announcer).expect("serializable");
        let mut restarted: ArrivalAnnouncer = serde_json::from_str(&json).expect("deserializable");
        let again = restarted.advance(&ArrivalPage {
            arrivals: vec![arrival(300, 5, 5_412_500), arrival(301, 0xbbb, 5_412_600)],
            cursor: 301,
            latest: 301,
        });
        assert_eq!(
            again.iter().map(|a| a.coin_id.clone()).collect::<Vec<_>>(),
            vec![arrival(0, 0xbbb, 0).coin_id],
            "a restart re-announced coin 5, or suppressed a genuinely new coin"
        );
    }
}
