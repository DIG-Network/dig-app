//! The wallet's two-way activity list — what came IN beside what went OUT (dig_ecosystem#3077).
//!
//! The wallet has kept an outbound log since it could spend ([`SpendRecord`]), and dig-node has kept
//! a confirmed-arrival ledger since dig_ecosystem#2548 ([`crate::arrivals`]). Until now they never
//! met: the tab could tell a person what they had sent, while every payment they received existed
//! only as a toast that had already gone. This module joins the two into the one list a wallet is
//! expected to have.
//!
//! # The two halves are NOT the same kind of claim, and this module refuses to pretend they are
//!
//! An arrival is a CONFIRMED coin. dig-node records it from its own chain replica, at a height, and
//! its contract forbids emitting a mempool sighting there — so [`Settlement::Confirmed`] is a chain
//! read, which is the only thing allowed to mean *settled*.
//!
//! An outbound [`SpendRecord`] is the opposite: it is written when this app BROADCAST a bundle, and
//! a broadcast is a submission. Whether it settled is [`InFlightSend::status`](crate::wallet::send::InFlightSend::status)'s
//! answer, from a chain read, and it is not knowable from the log. So an outbound entry carries
//! [`Settlement::Broadcast`] and [`ActivityEntry::is_settled`] answers `false` for it — permanently,
//! for every outbound row, including one from a year ago that plainly did settle.
//!
//! That looks like under-claiming and it is the point. The alternative — inferring settlement from
//! the existence of a broadcast record — is a surface reporting settled money from a submission,
//! which is the one class of defect this ecosystem does not defer. A row that says *sent* without
//! claiming *confirmed* is honest; a row that says *confirmed* because we once pressed send is not.
//!
//! # Why the list is ordered by when this APP learned of each entry
//!
//! The two sources carry incomparable clocks: a spend knows the unix second it was broadcast, and an
//! arrival knows a block HEIGHT and nothing else (`control.wallet.arrivals` serves no timestamp —
//! see `WalletArrivalRecord`). Sorting one list by a field that is seconds in half the rows and
//! blocks in the other half produces an order that is arithmetically confident and meaningless.
//!
//! Converting a height into a time would fix the sort by inventing the value it sorts on, so this
//! module does neither. Every entry carries [`ActivityEntry::learned_at`] — a monotonic position
//! this app assigns as it comes to know of the entry — and the list is newest-learned first. Each
//! row then STATES its own provenance ("at height 5 400 112" / "broadcast 3 minutes ago") rather
//! than borrowing a shared one it does not have.

use dig_events_protocol::AssetId;

use crate::arrivals::Arrival;

use super::state::{Asset, SpendRecord};

/// Which way the money moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Into this wallet — a confirmed coin from the node's arrival ledger.
    Received,
    /// Out of this wallet — a bundle this app broadcast.
    Sent,
}

/// What is KNOWN about an entry's place on chain. The two variants are two different kinds of
/// evidence, never two shades of one, and only one of them is a chain read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// Confirmed on chain at this height, per dig-node's arrival ledger.
    Confirmed {
        /// The height the coin was confirmed at.
        height: u32,
    },
    /// Broadcast by this app at this unix second. **Not a claim that it settled** — see the module
    /// header.
    Broadcast {
        /// Unix seconds when the bundle was handed to the node.
        at: u64,
    },
}

/// One row of the wallet's activity list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEntry {
    /// Which way the money moved.
    pub direction: Direction,
    /// The CAT asset id, or `None` for native XCH — carried verbatim so a CAT this build has never
    /// heard of is still named by its own id rather than mislabelled (see [`asset_label`]).
    pub asset_id: Option<AssetId>,
    /// The amount in that asset's base unit.
    pub amount: u64,
    /// What is known about this entry's place on chain.
    pub settlement: Settlement,
    /// The address this entry paid, for an outbound entry. `None` on an arrival: the node's ledger
    /// records the coin and the puzzle hash it landed on, and no sender — a wallet does not learn
    /// who paid it from a coin, and guessing one would name the wrong person.
    pub counterparty: Option<String>,
    /// The transaction id (outbound) or coin id (inbound), lowercase hex — the value a person takes
    /// to a block explorer.
    pub reference: String,
    /// Where this entry sits in the order THIS APP learned things. The list's sort key; see the
    /// module header for why it is not a timestamp.
    pub learned_at: u64,
}

impl ActivityEntry {
    /// Whether this entry is settled on chain, from evidence.
    ///
    /// `true` only for [`Settlement::Confirmed`], which comes from a chain read. An outbound entry
    /// answers `false` forever — the broadcast log cannot know, and answering from it is the money
    /// lie.
    pub fn is_settled(&self) -> bool {
        matches!(self.settlement, Settlement::Confirmed { .. })
    }
}

/// The $DIG CAT's asset id, or `None` for XCH — the asset a [`SpendRecord`] names, spelled the way
/// an arrival spells one, so both halves of the list carry one asset representation.
fn asset_id_of(asset: Asset) -> Option<AssetId> {
    match asset {
        Asset::Xch => None,
        Asset::Dig => Some(crate::notify::dig_asset_id()),
    }
}

/// The human label for an entry's asset: `XCH`, `$DIG`, or a short form of an unknown CAT's id.
///
/// Delegates to the notification path's renderer rather than repeating the mapping: a second copy of
/// "which id is $DIG" is how a surface comes to call somebody else's CAT $DIG.
pub fn asset_label(asset_id: Option<&AssetId>) -> String {
    crate::notify::render::asset_label(asset_id, Some(&crate::notify::dig_asset_id()))
}

/// Render an entry's amount with its asset's own decimals (XCH 12, CAT 3).
///
/// Delegates for the reason [`asset_label`] does — a divisor of its own on a money surface is
/// dig_ecosystem#2295.
pub fn format_entry_amount(entry: &ActivityEntry) -> String {
    crate::notify::render::format_amount(entry.asset_id.as_ref(), u128::from(entry.amount))
}

/// Join the outbound spend log with the arrivals this app has seen, newest-learned first.
///
/// `history` is oldest-first (as [`crate::wallet::state::WalletState::history`] keeps it) and
/// `arrivals` are ordered by the node's monotonic `seq`. Both orders are preserved WITHIN their
/// half; the interleave is by [`ActivityEntry::learned_at`], which this function assigns from the
/// caller's own ledger position for arrivals and from the spend's position in the log for outbound
/// rows — see [`ActivityLog`], which is what holds those positions in a running app.
pub fn merge(history: &[SpendRecord], arrivals: &[SeenArrival]) -> Vec<ActivityEntry> {
    let mut entries: Vec<ActivityEntry> = history
        .iter()
        .enumerate()
        .map(|(index, spend)| ActivityEntry {
            direction: Direction::Sent,
            asset_id: asset_id_of(spend.asset),
            amount: spend.amount,
            settlement: Settlement::Broadcast {
                at: spend.broadcast_at,
            },
            counterparty: Some(spend.recipient.clone()),
            reference: spend.transaction_id.clone(),
            learned_at: index as u64,
        })
        .chain(arrivals.iter().map(|seen| ActivityEntry {
            direction: Direction::Received,
            asset_id: seen.arrival.asset_id.clone(),
            amount: seen.arrival.amount,
            settlement: Settlement::Confirmed {
                height: seen.arrival.confirmed_height,
            },
            counterparty: None,
            reference: seen.arrival.coin_id.clone(),
            learned_at: seen.learned_at,
        }))
        .collect();

    // Newest-learned first. A stable sort, so two entries this app learned of in the same sweep keep
    // the order their own source gave them rather than swapping between repaints.
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.learned_at));
    entries
}

/// An arrival together with where it sits in this app's own learning order.
///
/// The position is not the node's `seq`: a client that has just adopted a node's ledger starts at a
/// large `seq` while its own spend log starts at zero, and interleaving those two would put every
/// arrival above every spend forever. [`ActivityLog`] assigns the position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenArrival {
    /// The arrival as the node's ledger recorded it.
    pub arrival: Arrival,
    /// Its position in this app's learning order.
    pub learned_at: u64,
}

/// How many arrivals the in-memory log keeps.
///
/// A bound rather than a preference: the log is a display cache, refilled from the node's durable
/// ledger, and an unbounded one grows for as long as a tray process lives. Sized so a busy wallet's
/// recent history is all present at the depth any list on the tab shows.
const MAX_REMEMBERED_ARRIVALS: usize = 256;

/// The arrivals this app has learned of, in learning order — the in-memory half of the activity
/// list.
///
/// **Not durable, and deliberately so.** dig-node's ledger is the durable record and this app is a
/// reader of it; a second persisted copy would be a second thing to keep correct across reorgs and
/// rebuilt databases, which is the divergence [`crate::arrivals`]'s header exists to prevent. What
/// is durable here is the CURSOR ([`crate::arrivals::store`]), which is a position rather than a
/// claim about money.
#[derive(Debug, Default)]
pub struct ActivityLog {
    seen: Vec<SeenArrival>,
    spends: Vec<SpendRecord>,
    next_position: u64,
}

impl ActivityLog {
    /// Record a sweep's worth of arrivals, oldest first, assigning each its learning position.
    ///
    /// Positions start above the largest a spend log could hand out, so an arrival learned after a
    /// spend sorts after it. The offset is the private `SPEND_POSITIONS`, whose own comment states
    /// what that ordering does and does not promise.
    pub fn record(&mut self, arrivals: &[Arrival]) {
        for arrival in arrivals {
            self.seen.push(SeenArrival {
                arrival: arrival.clone(),
                learned_at: SPEND_POSITIONS + self.next_position,
            });
            self.next_position += 1;
        }
        if self.seen.len() > MAX_REMEMBERED_ARRIVALS {
            self.seen.drain(..self.seen.len() - MAX_REMEMBERED_ARRIVALS);
        }
    }

    /// Record a spend this app broadcast in this session, oldest last.
    pub fn record_spend(&mut self, record: SpendRecord) {
        self.spends.push(record);
    }

    /// The arrivals this app has learned of, oldest first.
    pub fn seen(&self) -> &[SeenArrival] {
        &self.seen
    }

    /// The activity list for the persisted `history` joined with everything this session saw,
    /// newest-learned first.
    ///
    /// A spend appearing in BOTH — persisted and broadcast in this session — is listed once. The
    /// transaction id is what identifies it, because that is the value the chain and both logs agree
    /// on; deduplicating on amount-and-recipient would silently collapse two identical payments a
    /// person deliberately made twice.
    pub fn entries(&self, history: &[SpendRecord]) -> Vec<ActivityEntry> {
        let mut all = history.to_vec();
        for spend in &self.spends {
            if !all.iter().any(|s| s.transaction_id == spend.transaction_id) {
                all.push(spend.clone());
            }
        }
        merge(&all, &self.seen)
    }
}

/// The learning positions reserved for the outbound spend log.
///
/// [`merge`] gives a spend its INDEX in the log as its position, so the log's own append order is
/// its learning order. Arrivals are offset above that ceiling because the two sequences are
/// independent: without the offset the first arrival of a session would sort level with the first
/// spend ever made, and a payment received today would appear below a spend from last year.
///
/// The consequence is deliberate and worth stating plainly: **within one running session, every
/// arrival sorts above every previously-logged spend.** That is true of the order this app learned
/// them in, which is exactly what the list claims to show. A spend made after an arrival in the same
/// session is the one case this under-orders, and it is visible for seconds, next to a row that
/// states its own broadcast time.
const SPEND_POSITIONS: u64 = 1 << 32;

/// The process-wide activity log.
///
/// One instance for the reason the balance poller and the arrival watch are each one: the two
/// writers (the arrival sweep on its worker, the send path on its own) and the reader (the Wallet
/// pane, on the repaint thread) are in different places and must see the same list. A per-snapshot
/// log would show a payment that arrived and then lose it on the next repaint.
///
/// It holds only what [`ActivityLog`] holds — public metadata about money that has already moved.
/// No key, no bundle bytes, nothing that crosses the custody boundary (§908).
pub fn app_log() -> &'static std::sync::Mutex<ActivityLog> {
    static LOG: std::sync::OnceLock<std::sync::Mutex<ActivityLog>> = std::sync::OnceLock::new();
    LOG.get_or_init(Default::default)
}

/// Record `arrivals` in the process-wide log, ignoring a poisoned lock.
///
/// A poisoned lock is ignored rather than propagated because this is a display cache downstream of
/// dig-node's durable ledger: losing a row costs a list entry until the next sweep, while panicking
/// on the arrival worker would cost every future one.
pub fn remember_arrivals(arrivals: &[Arrival]) {
    match app_log().lock() {
        Ok(mut log) => log.record(arrivals),
        Err(_) => tracing::debug!("the activity log is poisoned; this sweep is not listed"),
    }
}

/// Record an outbound spend this app just broadcast in the process-wide log.
///
/// **What this row claims is exactly "we sent this".** It carries no height and answers `false` to
/// [`ActivityEntry::is_settled`], because a broadcast is a submission — settlement is
/// [`InFlightSend::status`](crate::wallet::send::InFlightSend::status)'s answer, from a chain read.
pub fn remember_spend(record: SpendRecord) {
    match app_log().lock() {
        Ok(mut log) => log.record_spend(record),
        Err(_) => tracing::debug!("the activity log is poisoned; this spend is not listed"),
    }
}

/// The activity list as the Wallet pane should draw it, newest-learned first.
pub fn entries() -> Vec<ActivityEntry> {
    match app_log().lock() {
        Ok(log) => log.entries(&[]),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spend(recipient: &str, amount: u64, broadcast_at: u64) -> SpendRecord {
        SpendRecord {
            recipient: recipient.into(),
            asset: Asset::Dig,
            amount,
            broadcast_at,
            transaction_id: format!("{broadcast_at:064x}"),
        }
    }

    fn arrival(seq: u64, amount: u64, height: u32) -> Arrival {
        Arrival {
            seq,
            coin_id: format!("{seq:064x}"),
            asset_id: None,
            amount,
            confirmed_height: height,
        }
    }

    /// **An outbound entry is never settled, however old it is.**
    ///
    /// The nearest wrong implementation reads the broadcast log as evidence of confirmation — which
    /// is right about most rows most of the time and is the money lie on the ones it is wrong about.
    /// The fixture is a spend broadcast long ago beside an arrival: if settlement came from "we have
    /// a record of it", both would answer `true`.
    #[test]
    fn a_broadcast_is_never_reported_as_settled_but_an_arrival_is() {
        let log = {
            let mut log = ActivityLog::default();
            log.record(&[arrival(1, 5, 5_400_112)]);
            log
        };
        let entries = log.entries(&[spend("xch1alice", 10, 1_600_000_000)]);

        let sent = entries
            .iter()
            .find(|e| e.direction == Direction::Sent)
            .expect("the spend is in the list");
        let received = entries
            .iter()
            .find(|e| e.direction == Direction::Received)
            .expect("the arrival is in the list");

        assert!(
            !sent.is_settled(),
            "a broadcast record must never claim settlement"
        );
        assert!(
            matches!(sent.settlement, Settlement::Broadcast { at: 1_600_000_000 }),
            "the outbound row carries its broadcast time, not a height"
        );
        assert!(
            received.is_settled(),
            "an arrival IS a chain read and settles"
        );
        assert_eq!(
            received.settlement,
            Settlement::Confirmed { height: 5_400_112 }
        );
    }

    /// **The list is ordered by what this app learned last, not by a number picked off each row.**
    ///
    /// The fixture is built so that the nearest wrong implementation — sorting on whatever numeric
    /// "time" each row carries — gives the opposite answer: the spend's unix second
    /// (1 600 000 000) dwarfs the arrival's height (100), so a mixed sort puts the spend newest.
    /// The arrival was nonetheless learned of afterwards and belongs on top.
    #[test]
    fn ordering_is_by_learning_and_not_by_mixing_heights_with_unix_seconds() {
        let mut log = ActivityLog::default();
        log.record(&[arrival(7, 5, 100)]);

        let entries = log.entries(&[spend("xch1alice", 10, 1_600_000_000)]);

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].direction,
            Direction::Received,
            "the arrival was learned of last, so it leads — a height-vs-seconds sort would not"
        );
        assert_eq!(entries[1].direction, Direction::Sent);
    }

    /// Within one half, source order is preserved and newest is first.
    #[test]
    fn each_half_keeps_its_own_order_newest_first() {
        let mut log = ActivityLog::default();
        log.record(&[arrival(1, 1, 10), arrival(2, 2, 11)]);
        let entries = log.entries(&[
            spend("xch1first", 10, 1_600_000_000),
            spend("xch1second", 20, 1_600_000_100),
        ]);

        let references: Vec<&str> = entries.iter().map(|e| e.reference.as_str()).collect();
        assert_eq!(
            references,
            vec![
                format!("{:064x}", 2),
                format!("{:064x}", 1),
                format!("{:064x}", 1_600_000_100u64),
                format!("{:064x}", 1_600_000_000u64),
            ],
            "arrivals newest first, then spends newest first"
        );
    }

    /// **An arrival names no counterparty.** A coin does not carry a sender, and a wallet that
    /// prints one has invented it.
    #[test]
    fn an_arrival_names_no_sender_while_a_spend_names_its_recipient() {
        let mut log = ActivityLog::default();
        log.record(&[arrival(1, 5, 10)]);
        let entries = log.entries(&[spend("xch1alice", 10, 1_600_000_000)]);

        assert_eq!(entries[0].counterparty, None);
        assert_eq!(entries[1].counterparty.as_deref(), Some("xch1alice"));
    }

    /// **A spend recorded in this session AND already persisted is listed once.**
    ///
    /// The nearest wrong implementation concatenates the two sources, which shows every payment
    /// twice the moment the persisted log gains a writer. Identity is the transaction id.
    #[test]
    fn a_spend_present_in_both_the_session_and_the_history_is_listed_once() {
        let persisted = spend("xch1alice", 10, 1_600_000_000);
        let mut log = ActivityLog::default();
        log.record_spend(persisted.clone());

        let entries = log.entries(std::slice::from_ref(&persisted));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].counterparty.as_deref(), Some("xch1alice"));
    }

    /// **Two identical payments deliberately made twice stay two rows.** Deduplicating on amount and
    /// recipient would hide one, which is a wrong claim about how much left the wallet.
    #[test]
    fn two_identical_payments_with_different_transaction_ids_are_two_rows() {
        let first = spend("xch1alice", 10, 1_600_000_000);
        let second = SpendRecord {
            transaction_id: "beef".into(),
            ..first.clone()
        };
        let mut log = ActivityLog::default();
        log.record_spend(second);

        assert_eq!(log.entries(std::slice::from_ref(&first)).len(), 2);
    }

    /// A spend broadcast in this session appears with no persisted history at all — which is the
    /// state every wallet is in today, since nothing writes the history yet.
    #[test]
    fn a_session_spend_appears_without_any_persisted_history() {
        let mut log = ActivityLog::default();
        log.record_spend(spend("xch1alice", 10, 1_600_000_000));
        let entries = log.entries(&[]);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].is_settled());
    }

    /// The empty case is an empty list, not a row saying so — the pane draws its own empty state.
    #[test]
    fn nothing_sent_and_nothing_received_is_an_empty_list() {
        assert!(ActivityLog::default().entries(&[]).is_empty());
    }

    /// A wallet that has only ever received still has a list.
    #[test]
    fn arrivals_alone_make_a_list() {
        let mut log = ActivityLog::default();
        log.record(&[arrival(1, 5, 10)]);
        assert_eq!(log.entries(&[]).len(), 1);
    }

    /// The in-memory log is bounded, keeping the most recently learned.
    #[test]
    fn the_log_is_bounded_and_drops_the_oldest() {
        let mut log = ActivityLog::default();
        let many: Vec<Arrival> = (0..MAX_REMEMBERED_ARRIVALS as u64 + 10)
            .map(|seq| arrival(seq, 1, 10))
            .collect();
        log.record(&many);

        assert_eq!(log.seen().len(), MAX_REMEMBERED_ARRIVALS);
        assert_eq!(
            log.seen()[0].arrival.seq,
            10,
            "the oldest ten were dropped, not the newest"
        );
    }

    /// **$DIG is named from the canonical id and an unknown CAT by its own id** — never a false
    /// ticker, and never XCH standing in for a CAT nobody recognised.
    #[test]
    fn assets_are_labelled_honestly() {
        assert_eq!(asset_label(None), "XCH");
        assert_eq!(asset_label(Some(&crate::notify::dig_asset_id())), "$DIG");
        let stranger = AssetId("0123456789abcdef0123".into());
        assert_eq!(asset_label(Some(&stranger)), "012345…0123");
    }

    /// A $DIG spend and a $DIG arrival carry the SAME asset id, so one list does not show the same
    /// token under two names depending on which way it moved.
    #[test]
    fn a_dig_spend_and_a_dig_arrival_agree_on_the_asset() {
        let mut log = ActivityLog::default();
        log.record(&[Arrival {
            asset_id: Some(crate::notify::dig_asset_id()),
            ..arrival(1, 5, 10)
        }]);
        let entries = log.entries(&[spend("xch1alice", 10, 1_600_000_000)]);
        assert_eq!(entries[0].asset_id, entries[1].asset_id);
        assert_eq!(asset_label(entries[0].asset_id.as_ref()), "$DIG");
    }

    /// Amounts carry each asset's own decimals — XCH twelve, a CAT three (dig_ecosystem#2295).
    #[test]
    fn amounts_use_the_assets_own_decimals() {
        let mut log = ActivityLog::default();
        log.record(&[arrival(1, 1_500_000_000_000, 10)]);
        let entries = log.entries(&[spend("xch1alice", 1_500, 1_600_000_000)]);
        assert_eq!(format_entry_amount(&entries[0]), "1.5", "XCH has 12 places");
        assert_eq!(format_entry_amount(&entries[1]), "1.5", "a CAT has 3");
    }
}
