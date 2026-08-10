//! Confirmed incoming-funds notifications (dig_ecosystem#2548) — the "you were paid" toast.
//!
//! # Where the judgement lives, and why it is not here
//!
//! **dig-node decides what an arrival is. This module only decides what to SAY and when to stop
//! saying it.** The node keeps a durable arrival ledger and serves it over
//! `control.wallet.arrivals`; everything below is a client of that cursor.
//!
//! That division is not stylistic. dig-app once ran its own detection on top of
//! `control.wallet.coins`, and the two implementations could not be equally correct, because
//! `.coins` is UNSPENT-ONLY. Deciding "is this the user's own change?" needs the coin's PARENT, and
//! a parent is spent by definition the moment it produces change — so an unspent-coin read
//! structurally cannot see it. The app's version papered over that by remembering coins it had
//! watched go by, which held only while the app happened to be running and polling: close dig-app,
//! send money from any client, reopen, and the change coin came back as a payment. A verifier ran
//! that code and it announced **"Received 8.999 XCH" for a transaction in which the user SENT
//! money** — nearly the whole balance, reported as income, out of a small payment.
//!
//! The node has the data the predicate needs (its `coins` table holds SPENT coins) and it has it
//! whether or not dig-app is running. So there is one implementation, on the side that can be
//! right, and this module cannot express the wrong answer because it never forms an opinion.
//!
//! # What this module is responsible for
//!
//! Exactly one thing: **each recorded arrival is announced at most once, on this machine.** That is
//! a durable [`ArrivalCursor`] — a single ledger position, persisted by [`store`] — plus the rule
//! for a machine that has never had one.
//!
//! | Failure | What stops it here |
//! |---|---|
//! | Installing dig-app on a node with a ledger toasts its whole history | a cursor with no position ADOPTS the node's `latest` in silence |
//! | A restart re-announces | the cursor is persisted before anything is drawn |
//! | The client resumes past an arrival it never saw | the cursor advances to the last row RECEIVED, never to `latest` |
//!
//! # A payment that lands while dig-app is CLOSED is announced when it next opens
//!
//! This is deliberate, and it is the behaviour the node ledger buys. The node records the arrival
//! whenever IT is running; dig-app is a reader of that record, so closing the app delays the toast
//! rather than losing it. A person who was paid overnight wants to be told, and telling them once,
//! late, is honest — the toast says money arrived, not that it arrived this second.
//!
//! What is genuinely not covered: an arrival that lands while **dig-node** is not running is
//! recorded by the catch-up that follows, but at or below the arrival baseline that catch-up arms
//! only if the wallet had never synced before. See dig-node's `sage::arrivals`.

pub mod store;
pub mod watch;

use dig_events_protocol::AssetId;
use serde::{Deserialize, Serialize};

/// One confirmed payment INTO the wallet, as dig-node's arrival ledger recorded it.
///
/// There is no `parent_coin_id` and no "is this change?" flag, because this type is downstream of
/// that question: the node answered it before the row existed. A field inviting a second opinion is
/// how the two divergent predicates got written in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {
    /// The ledger position this arrival occupies. Monotonic and never reused.
    pub seq: u64,
    /// The coin that arrived (lowercase hex).
    pub coin_id: String,
    /// The CAT asset id, or `None` for native XCH. Passed through verbatim from the node, which is
    /// what lets a toast name `$DIG` from the canonical id and any other CAT by its own id.
    pub asset_id: Option<AssetId>,
    /// The amount in that asset's base unit.
    pub amount: u64,
    /// The height the coin was confirmed at.
    pub confirmed_height: u32,
}

/// One page of the node's arrival ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrivalPage {
    /// The arrivals in this page, oldest first.
    pub arrivals: Vec<Arrival>,
    /// The position of the last row in this page, or the requested `after_seq` when it is empty.
    /// **The only value it is safe to resume from.**
    pub cursor: u64,
    /// Where the node's ledger had got to when the page was assembled — possibly AHEAD of
    /// [`cursor`](Self::cursor). Used only to adopt a starting position on a machine that has none.
    pub latest: u64,
}

/// A row of one of dig-node's money ledgers, identified by its position in it.
///
/// The one thing [`ArrivalCursor`] needs to know about a row, and therefore the whole of what makes
/// the cursor reusable by the outgoing ledger (dig_ecosystem#2565). The cursor's rules — adopt on
/// first read, advance to the last row HANDED OVER, never rewind, filter per row — are the same four
/// money-safety rules in both directions, and a second copy of them is a second place for one of
/// them to be dropped.
pub trait LedgerRow: Clone {
    /// This row's position in the node's ledger.
    fn seq(&self) -> u64;
}

impl LedgerRow for Arrival {
    fn seq(&self) -> u64 {
        self.seq
    }
}

/// How far through the node's arrival ledger this machine has been told.
///
/// `None` means this machine has never read the ledger, which is the one case that must not
/// announce: a person installing dig-app against a node that has been running for months would
/// otherwise get a toast per historical payment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrivalCursor {
    /// The last ledger position that has been announced on this machine.
    #[serde(default)]
    position: Option<u64>,
}

impl ArrivalCursor {
    /// A cursor that has never read the ledger. Its first [`advance`](Self::advance) adopts.
    pub fn unread() -> Self {
        Self::default()
    }

    /// The position to ask the node to resume from, or `None` before the first read.
    pub fn position(&self) -> Option<u64> {
        self.position
    }

    /// Take `page` into account and report what may honestly be announced.
    ///
    /// On a cursor with no position this ADOPTS: the position jumps to the node's `latest` and
    /// nothing is announced, because everything the node already holds predates this machine's
    /// knowledge of it.
    ///
    /// Afterwards the cursor advances to `page.cursor` — the last row actually HANDED OVER — and
    /// never to `latest`. The node reads `latest` after materializing the page, so an arrival
    /// recorded in between sits above the page and below `latest`; resuming from `latest` would
    /// step over it and lose a notification with nothing anywhere saying so.
    ///
    /// It also never moves BACKWARDS. A node whose ledger was rebuilt could answer a lower `cursor`
    /// than this machine has already announced from, and rewinding would replay those toasts.
    pub fn advance(&mut self, page: &ArrivalPage) -> Vec<Arrival> {
        self.advance_rows(&page.arrivals, page.cursor, page.latest)
    }

    /// [`advance`](Self::advance) over any node ledger's rows — the actual implementation, shared
    /// with the outgoing ledger (dig_ecosystem#2565) so both directions obey ONE copy of the four
    /// rules. Every test in this module exercises this code through the incoming path.
    pub fn advance_rows<R: LedgerRow>(&mut self, rows: &[R], cursor: u64, latest: u64) -> Vec<R> {
        let Some(position) = self.position else {
            self.position = Some(latest);
            return Vec::new();
        };
        self.position = Some(position.max(cursor));
        rows.iter()
            .filter(|row| row.seq() > position)
            .cloned()
            .collect()
    }
}

/// Why the node's arrival ledger could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArrivalSourceError {
    /// The read failed — no node, a refusal, a timeout. Ordinary, and reported by saying nothing.
    #[error("{0}")]
    Unavailable(String),
    /// The node answered with a row this client cannot read honestly (an amount outside `u64`).
    /// Distinguished from [`Unavailable`](Self::Unavailable) because it means the two sides of the
    /// contract disagree, which a retry does not fix.
    #[error("the node's answer could not be read: {0}")]
    Malformed(String),
}

/// The seam the node's arrival ledger arrives through.
///
/// Implemented by [`watch::ControlPlaneSource`] over `control.wallet.arrivals`. A future push
/// transport implements this same trait and nothing above it changes.
pub trait ArrivalSource {
    /// One page of arrivals strictly after `after_seq`.
    fn arrivals_since(&self, after_seq: u64) -> Result<ArrivalPage, ArrivalSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arrival(seq: u64, amount: u64) -> Arrival {
        Arrival {
            seq,
            coin_id: format!("{seq:064x}"),
            asset_id: None,
            amount,
            confirmed_height: 5_412_000 + seq as u32,
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

    /// **A machine reading the ledger for the first time announces nothing, however full it is.**
    ///
    /// The fixture is a node that has been running for months: nine recorded arrivals and a page
    /// full of them. A client that announced what it was handed would toast nine times on install.
    #[test]
    fn a_cursor_that_has_never_read_the_ledger_adopts_it_in_silence() {
        let mut cursor = ArrivalCursor::unread();
        let announced = cursor.advance(&page(
            vec![arrival(1, 100), arrival(2, 200), arrival(3, 300)],
            0,
            9,
        ));
        assert!(
            announced.is_empty(),
            "the first read announced {} historical arrivals",
            announced.len()
        );
        assert_eq!(
            cursor.position(),
            Some(9),
            "adoption must jump to the ledger head, or the next read replays the rest"
        );
    }

    /// **After adoption, an arrival above the cursor IS announced — exactly once.**
    #[test]
    fn an_arrival_above_the_cursor_is_announced_once() {
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(vec![], 0, 4));

        let announced = cursor.advance(&page(vec![arrival(5, 1_000)], 4, 5));
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].seq, 5);

        // The same page again, as a repeat poll against a node that has not moved.
        let repeat = cursor.advance(&page(vec![arrival(5, 1_000)], 4, 5));
        assert!(repeat.is_empty(), "a repeat poll re-announced the payment");
    }

    /// **A restart does not re-announce**, because the cursor round-trips through its own JSON.
    #[test]
    fn a_restart_resumes_from_the_stored_position() {
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(vec![], 0, 4));
        assert_eq!(cursor.advance(&page(vec![arrival(5, 1)], 4, 5)).len(), 1);

        let json = serde_json::to_string(&cursor).expect("serializable");
        let mut restarted: ArrivalCursor = serde_json::from_str(&json).expect("deserializable");
        let again = restarted.advance(&page(vec![arrival(5, 1)], 4, 5));
        assert!(again.is_empty(), "a restart re-announced arrival 5");
    }

    /// **The cursor advances to the last row RECEIVED, never to the ledger head.**
    ///
    /// The fixture is the race the node's own contract warns about: the page ends at 5 while the
    /// ledger has already reached 12. A client that stored `latest` would ask for everything after
    /// 12 next time and never learn about 6..=12 — a silent loss, which is worse than a late toast.
    /// The second read is what makes that observable: arrival 6 must still arrive.
    #[test]
    fn a_page_behind_the_ledger_head_does_not_skip_what_it_did_not_carry() {
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(vec![], 0, 4));

        let first = cursor.advance(&ArrivalPage {
            arrivals: vec![arrival(5, 1)],
            cursor: 5,
            latest: 12,
        });
        assert_eq!(first.len(), 1);
        assert_eq!(
            cursor.position(),
            Some(5),
            "the cursor jumped to the ledger head and skipped arrivals 6..=12"
        );

        let second = cursor.advance(&page(vec![arrival(6, 2)], 5, 12));
        assert_eq!(
            second.iter().map(|a| a.seq).collect::<Vec<_>>(),
            vec![6],
            "the arrival the first page did not carry was never announced"
        );
    }

    /// **A page carrying a row at or below the cursor does not re-announce it.**
    ///
    /// A node that re-serves an overlapping range — a rebuilt ledger, a client that asked from too
    /// far back — must not produce a second toast for money already reported. The row ABOVE the
    /// cursor in the same page is the control: it proves the filter is per-row, not per-page.
    #[test]
    fn an_overlapping_page_announces_only_the_rows_above_the_cursor() {
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(vec![], 0, 7));

        let announced = cursor.advance(&page(
            vec![arrival(6, 1), arrival(7, 2), arrival(8, 3)],
            5,
            8,
        ));
        assert_eq!(
            announced.iter().map(|a| a.seq).collect::<Vec<_>>(),
            vec![8],
            "an already-announced arrival was toasted again"
        );
    }

    /// **The cursor never moves backwards, even when the node hands it a lower position.**
    ///
    /// A node whose ledger was rebuilt renumbers from a low `seq` and answers a `cursor` BELOW what
    /// this machine has already announced from. Following it down would ask for everything after 3
    /// on the next poll and replay every toast between 4 and 100.
    ///
    /// The page is built by hand rather than through the helper, because the helper derives
    /// `cursor` from the rows and the caller's own `after_seq` and so cannot produce a cursor that
    /// has genuinely gone backwards — the exact fixture limitation that would make this test pass
    /// against a cursor with no floor at all. The second half is the control: a page whose cursor is
    /// AHEAD must still move it, or "never rewinds" would be satisfied by never moving.
    #[test]
    fn a_node_answering_a_lower_position_does_not_rewind_the_cursor() {
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(vec![], 0, 100));

        cursor.advance(&ArrivalPage {
            arrivals: Vec::new(),
            cursor: 3,
            latest: 3,
        });
        assert_eq!(cursor.position(), Some(100), "the cursor rewound");

        cursor.advance(&ArrivalPage {
            arrivals: vec![arrival(101, 1)],
            cursor: 101,
            latest: 101,
        });
        assert_eq!(
            cursor.position(),
            Some(101),
            "the floor froze the cursor instead of flooring it"
        );
    }
}
