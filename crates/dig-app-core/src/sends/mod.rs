//! Confirmed outgoing-funds notifications (dig_ecosystem#2565) — the "your payment went out" toast.
//!
//! The outgoing twin of [`crate::arrivals`], and it inherits that module's central rule verbatim:
//! **dig-node decides what a send is and how much left. This module only decides what to SAY and
//! when to stop saying it.**
//!
//! # Why dig-app forms no opinion here either, and why it matters MORE for sends
//!
//! A send is not the mirror of a receive. Spending a 9 XCH coin to pay 1 XCH creates ~8 XCH of
//! change back to the same wallet, so the figure a person needs is a DIFFERENCE — the wallet's own
//! inputs minus what came back — and computing it needs the whole of a confirmed block's coin
//! movement plus the knowledge of which puzzle hashes the wallet watches. dig-app has neither.
//!
//! It is also the exact shape of the #2548 defect that produced **"Received 8.999 XCH" for a
//! transaction in which the user SENT money**: a client that guesses about spent coins guesses
//! wrong. So this module holds no coin, no parent link and no amount arithmetic. It reads a figure
//! the node computed and renders it.
//!
//! # What this module is responsible for
//!
//! Exactly one thing, the same one: **each recorded send is announced at most once, on this
//! machine.** That is a durable cursor — the SAME [`crate::arrivals::ArrivalCursor`] type, because the four rules
//! (adopt on first read, advance to the last row handed over, never rewind, filter per row) are the
//! same four rules — persisted to its own file by [`store`], plus the rule for a machine that has
//! never had one.
//!
//! # The figure includes the fee, and the toast must not pretend otherwise
//!
//! [`SentPayment::net_outflow`] is what LEFT the wallet: payment plus any network fee. A node
//! observing only the chain never sees the recipient's output — it sits at a puzzle hash the node
//! does not watch — so nothing can split the two. The toast therefore says how much left, and never
//! offers a fee beside it.
//!
//! # A send made from ANOTHER client is announced here too
//!
//! Nothing on this path knows or cares what built the spend bundle. The node observed the chain, so
//! a payment made from a different wallet on the same seed reaches this toast identically. That is
//! a property of putting the detection in the node, not something this module implements.

pub mod store;
pub mod watch;

use dig_events_protocol::AssetId;

use crate::arrivals::LedgerRow;

/// One confirmed outflow from the wallet, as dig-node's send ledger recorded it.
///
/// There is no coin id, no input list and no fee, because this type is downstream of the questions
/// they would answer: the node settled them before the row existed. In particular there is no `fee`
/// — a node observing only chain cannot separate it from the payment, and a `0` in that slot would
/// be a fabricated number about somebody's money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentPayment {
    /// The ledger position this send occupies. Monotonic and never reused.
    pub seq: u64,
    /// What LEFT the wallet, in the asset's base unit: the wallet's own inputs minus the change
    /// that came back, INCLUSIVE of any network fee. Never a spent coin's amount.
    pub net_outflow: u64,
    /// The CAT asset id, or `None` for native XCH. Passed through verbatim from the node so a toast
    /// names `$DIG` from the canonical id and any other CAT by its own id — and so a future node
    /// that can score a CAT outflow is not rendered with XCH's divisor.
    pub asset_id: Option<AssetId>,
    /// The height the spend was confirmed at.
    pub confirmed_height: u32,
}

impl LedgerRow for SentPayment {
    fn seq(&self) -> u64 {
        self.seq
    }
}

/// One page of the node's send ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPage {
    /// The sends in this page, oldest first.
    pub sends: Vec<SentPayment>,
    /// The position of the last row in this page, or the requested `after_seq` when it is empty.
    /// **The only value it is safe to resume from.**
    pub cursor: u64,
    /// Where the node's ledger had got to when the page was assembled — possibly AHEAD of
    /// [`cursor`](Self::cursor). Used only to adopt a starting position on a machine that has none.
    pub latest: u64,
}

/// The seam the node's send ledger arrives through.
///
/// Implemented by [`watch::ControlPlaneSendSource`] over `control.wallet.sends`. Kept separate from
/// [`crate::arrivals::ArrivalSource`] on purpose: the two ledgers are different methods precisely so
/// that a client cannot be handed an outgoing row where it expects an incoming one, and collapsing
/// them into one trait here would put that confusion back on this side of the wire.
pub trait SendSource {
    /// One page of sends strictly after `after_seq`.
    fn sends_since(&self, after_seq: u64) -> Result<SendPage, crate::arrivals::ArrivalSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrivals::ArrivalCursor;

    fn sent(seq: u64, net_outflow: u64) -> SentPayment {
        SentPayment {
            seq,
            net_outflow,
            asset_id: None,
            confirmed_height: 5_412_000 + seq as u32,
        }
    }

    fn page(sends: Vec<SentPayment>, after_seq: u64, latest: u64) -> SendPage {
        let cursor = sends.last().map_or(after_seq, |s| s.seq);
        SendPage {
            sends,
            cursor,
            latest,
        }
    }

    fn advance(cursor: &mut ArrivalCursor, page: &SendPage) -> Vec<SentPayment> {
        cursor.advance_rows(&page.sends, page.cursor, page.latest)
    }

    /// **TRAP 4 — installing dig-app against a node with a send history announces nothing.**
    ///
    /// The fixture is a wallet that has been spending for months. A client that announced what it
    /// was handed would replay a lifetime of payments as toasts on first run.
    #[test]
    fn a_first_read_of_the_send_ledger_adopts_it_in_silence() {
        let mut cursor = ArrivalCursor::unread();
        let announced = advance(
            &mut cursor,
            &page(vec![sent(1, 100), sent(2, 200), sent(3, 300)], 0, 9),
        );
        assert!(
            announced.is_empty(),
            "the first read announced {} historical sends",
            announced.len()
        );
        assert_eq!(cursor.position(), Some(9));
    }

    /// **A send above the cursor is announced exactly once**, and a repeat poll says nothing. The
    /// positive half is what stops "announces nothing" being satisfied by announcing nothing ever.
    #[test]
    fn a_send_above_the_cursor_is_announced_once() {
        let mut cursor = ArrivalCursor::unread();
        advance(&mut cursor, &page(vec![], 0, 4));

        let announced = advance(&mut cursor, &page(vec![sent(5, 1_000)], 4, 5));
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].seq, 5);
        assert_eq!(announced[0].net_outflow, 1_000);

        let repeat = advance(&mut cursor, &page(vec![sent(5, 1_000)], 4, 5));
        assert!(repeat.is_empty(), "a repeat poll re-announced the payment");
    }

    /// **The two ledgers are independent positions.** They are separate `AUTOINCREMENT` sequences on
    /// the node, so one cursor covering both would either skip sends or replay arrivals.
    #[test]
    fn the_send_cursor_is_not_the_arrival_cursor() {
        let mut sends = ArrivalCursor::unread();
        advance(&mut sends, &page(vec![], 0, 900));

        let mut arrivals = ArrivalCursor::unread();
        arrivals.advance(&crate::arrivals::ArrivalPage {
            arrivals: Vec::new(),
            cursor: 0,
            latest: 4,
        });

        assert_eq!(sends.position(), Some(900));
        assert_eq!(arrivals.position(), Some(4));
    }
}
