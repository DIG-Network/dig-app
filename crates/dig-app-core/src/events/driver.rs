//! The event driver — turns the live [`EventFeed`] + [`CatchUp`] backfill into ordered
//! [`EventSink`] updates, with graceful recovery from a gap.
//!
//! The driver holds three things: the last delivered [`Cursor`] (start [`Cursor`]`(0)` — the
//! "seen-nothing" sentinel, cursors are 1-based per #1135), the subscriber's [`EventKind`] filter,
//! and the set of sinks. Its loop is thin; the decisions live in the pure, exhaustively-tested
//! [`accept_live`] and [`reconcile_backfill`] helpers so the recovery contract is verifiable
//! without any async plumbing.

use std::sync::Arc;

use dig_events_protocol::{filter_events, CatchUp, Cursor, EmittedEvent, EnumSet, EventKind};

use super::{EventFeed, EventSink, FeedItem};

/// The reactive driver: reads the [`EventFeed`], fans matching events to every [`EventSink`], and
/// backfills through [`CatchUp`] on a gap.
pub struct EventDriver {
    cursor: Cursor,
    filter: EnumSet<EventKind>,
    sinks: Vec<Arc<dyn EventSink>>,
}

impl EventDriver {
    /// Start a driver at `cursor` (pass [`Cursor`]`(0)` for a fresh subscriber) with `filter` and
    /// the `sinks` to fan every recognized event out to.
    pub fn new(cursor: Cursor, filter: EnumSet<EventKind>, sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self {
            cursor,
            filter,
            sinks,
        }
    }

    /// The last cursor the driver has delivered (its resume point).
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Fan one event out to every sink and advance the cursor.
    fn deliver(&mut self, event: &EmittedEvent) {
        for sink in &self.sinks {
            sink.apply(event);
        }
        self.cursor = event.cursor;
    }

    /// Broadcast the full-resync signal to every sink (an unrecoverable gap).
    fn broadcast_resync(&self) {
        for sink in &self.sinks {
            sink.resync();
        }
    }

    /// Handle one live item. Returns `false` when the stream closed (stop the loop).
    ///
    /// A [`FeedItem::Lagged`] triggers a single [`CatchUp::catch_up`] over ALL kinds (contiguous
    /// cursors are required to tell a real gap from ordinary kind-filtering), reconciled by
    /// [`reconcile_backfill`].
    async fn step<B: CatchUp + Sync>(&mut self, item: FeedItem, backfill: &B) -> bool {
        match item {
            FeedItem::Event(event) => {
                if let Some(accepted) = accept_live(self.cursor, event) {
                    self.deliver(&accepted);
                }
                true
            }
            FeedItem::Lagged => {
                // Request every kind so cursors are contiguous — the ONLY way to distinguish a
                // window-eviction gap from the normal cursor jumps a kind filter produces.
                if let Ok(backfilled) = backfill.catch_up(self.cursor, EnumSet::all()).await {
                    match reconcile_backfill(self.cursor, self.filter, backfilled) {
                        BackfillOutcome::Recovered {
                            dispatch,
                            new_cursor,
                        } => {
                            for event in &dispatch {
                                self.deliver(event);
                            }
                            // Advance past kept-but-filtered cursors so the next gap check is exact.
                            self.cursor = self.cursor.max(new_cursor);
                        }
                        BackfillOutcome::Unrecoverable { new_cursor } => {
                            self.broadcast_resync();
                            self.cursor = new_cursor;
                        }
                    }
                }
                // A transient catch_up error leaves the cursor put; the next Lagged retries.
                true
            }
            FeedItem::Closed => false,
        }
    }
}

/// Drive `feed` to completion, fanning events + backfill out to `driver`'s sinks.
///
/// Runs until the feed reports [`FeedItem::Closed`]. Intended to own a background task; the sinks
/// (the [`WalletView`](super::WalletView), the notification pipeline) are observed elsewhere.
pub async fn run<F, B>(mut driver: EventDriver, mut feed: F, backfill: B)
where
    F: EventFeed,
    B: CatchUp + Sync,
{
    loop {
        let item = feed.recv().await;
        if !driver.step(item, &backfill).await {
            break;
        }
    }
}

/// Whether a live event advances the stream, deduping anything at or before the cursor.
///
/// Live cursors are NOT contiguous under a kind filter, so acceptance is a pure dedup: an event
/// strictly beyond the cursor is new (backfill + live can overlap after a gap — the older copy is
/// dropped here). Returns the event to deliver, or `None` to skip.
pub fn accept_live(cursor: Cursor, event: EmittedEvent) -> Option<EmittedEvent> {
    (event.cursor > cursor).then_some(event)
}

/// The result of reconciling a backfill against the last delivered cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillOutcome {
    /// The missed range was fully within the engine's catch-up window. `dispatch` is the
    /// filter-matching subset to deliver, in cursor order; `new_cursor` is the head of the WHOLE
    /// (unfiltered) backfilled range, so the resume point clears kept-but-filtered cursors too.
    Recovered {
        /// The filter-matching events to deliver, in cursor order.
        dispatch: Vec<EmittedEvent>,
        /// The new resume cursor (head of the full backfilled range).
        new_cursor: Cursor,
    },
    /// The missed range began before the engine's bounded catch-up window (events were evicted):
    /// incremental recovery is impossible. The app must full-resync; `new_cursor` is the head of
    /// what the window still holds, so the driver resumes there without re-alarming.
    Unrecoverable {
        /// The head cursor to resume at after a full re-sync.
        new_cursor: Cursor,
    },
}

/// Reconcile a catch-up backfill (requested over ALL kinds) against `since`.
///
/// `backfilled` is every event the engine's window still holds with a cursor > `since`. If its
/// earliest cursor is beyond `since.next()`, the contiguous range from `since` was partly evicted
/// (a gap older than the bounded window, e.g. a long-offline app) → [`BackfillOutcome::Unrecoverable`].
/// Otherwise the range is intact → deliver the `filter`-matching subset (via the shared
/// [`filter_events`] rule) and resume at the range head.
pub fn reconcile_backfill(
    since: Cursor,
    filter: EnumSet<EventKind>,
    backfilled: Vec<EmittedEvent>,
) -> BackfillOutcome {
    let mut all: Vec<EmittedEvent> = backfilled
        .into_iter()
        .filter(|e| e.cursor > since)
        .collect();
    all.sort_by_key(|e| e.cursor);

    let Some(head) = all.last().map(|e| e.cursor) else {
        // Nothing missed (a spurious lag): resume exactly where we were.
        return BackfillOutcome::Recovered {
            dispatch: Vec::new(),
            new_cursor: since,
        };
    };

    // The earliest retained cursor must be the very next one after `since`; a jump means eviction.
    if all[0].cursor > since.next() {
        return BackfillOutcome::Unrecoverable { new_cursor: head };
    }

    BackfillOutcome::Recovered {
        dispatch: filter_events(all, filter),
        new_cursor: head,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_events_protocol::{Amount, WalletEvent, WalletId};
    use std::sync::Mutex;

    fn received(cursor: u64) -> EmittedEvent {
        EmittedEvent {
            cursor: Cursor(cursor),
            event: WalletEvent::FundsReceived {
                wallet_id: WalletId(1),
                asset: None,
                amount: Amount(cursor),
                coin_id: format!("{cursor:064x}"),
                confirmed_height: cursor as u32,
            },
        }
    }

    fn tip(cursor: u64) -> EmittedEvent {
        EmittedEvent {
            cursor: Cursor(cursor),
            event: WalletEvent::NewTip {
                height: cursor as u32,
                header_hash: "hh".into(),
            },
        }
    }

    // ---- accept_live: pure dedup ----

    #[test]
    fn accept_live_admits_a_cursor_beyond_the_last() {
        assert_eq!(accept_live(Cursor(2), received(3)), Some(received(3)));
    }

    #[test]
    fn accept_live_drops_a_duplicate_or_older_event() {
        assert_eq!(accept_live(Cursor(3), received(3)), None);
        assert_eq!(accept_live(Cursor(3), received(2)), None);
    }

    // ---- reconcile_backfill: the recovery contract ----

    #[test]
    fn contiguous_backfill_recovers_and_filters() {
        // From cursor 0: window holds 1(tip),2(received),3(received) — filter keeps only received.
        let outcome = reconcile_backfill(
            Cursor(0),
            EventKind::FundsReceived.into(),
            vec![tip(1), received(2), received(3)],
        );
        assert_eq!(
            outcome,
            BackfillOutcome::Recovered {
                dispatch: vec![received(2), received(3)],
                new_cursor: Cursor(3),
            }
        );
    }

    #[test]
    fn a_gap_older_than_the_window_is_unrecoverable() {
        // Last saw cursor 2; the window's earliest retained is 5 (3,4 evicted) -> unrecoverable,
        // resume at the window head so we do not re-alarm.
        let outcome = reconcile_backfill(Cursor(2), EnumSet::all(), vec![received(5), received(6)]);
        assert_eq!(
            outcome,
            BackfillOutcome::Unrecoverable {
                new_cursor: Cursor(6)
            }
        );
    }

    #[test]
    fn an_empty_backfill_is_a_no_op_resume() {
        let outcome = reconcile_backfill(Cursor(7), EnumSet::all(), vec![]);
        assert_eq!(
            outcome,
            BackfillOutcome::Recovered {
                dispatch: vec![],
                new_cursor: Cursor(7),
            }
        );
    }

    #[test]
    fn backfill_ignores_already_seen_cursors_in_the_overlap() {
        // A lag backfill can re-include cursor 3 we already delivered; it is dropped as <= since.
        let outcome = reconcile_backfill(Cursor(3), EnumSet::all(), vec![received(3), received(4)]);
        assert_eq!(
            outcome,
            BackfillOutcome::Recovered {
                dispatch: vec![received(4)],
                new_cursor: Cursor(4),
            }
        );
    }

    // ---- The async driver end-to-end over scripted seams ----

    /// A scripted feed yielding a canned list of items, then `Closed` forever.
    struct ScriptedFeed {
        items: std::collections::VecDeque<FeedItem>,
    }

    #[async_trait::async_trait]
    impl EventFeed for ScriptedFeed {
        async fn recv(&mut self) -> FeedItem {
            self.items.pop_front().unwrap_or(FeedItem::Closed)
        }
    }

    /// A catch-up double returning a preset backfill.
    struct FakeCatchUp(Vec<EmittedEvent>);

    #[async_trait::async_trait]
    impl CatchUp for FakeCatchUp {
        type Error = ();
        async fn catch_up(
            &self,
            since: Cursor,
            _filter: EnumSet<EventKind>,
        ) -> Result<Vec<EmittedEvent>, ()> {
            Ok(self
                .0
                .iter()
                .filter(|e| e.cursor > since)
                .cloned()
                .collect())
        }
    }

    /// A sink recording delivered events + resync calls.
    #[derive(Default)]
    struct RecordingSink {
        applied: Mutex<Vec<Cursor>>,
        resyncs: Mutex<usize>,
    }

    impl EventSink for RecordingSink {
        fn apply(&self, event: &EmittedEvent) {
            self.applied.lock().unwrap().push(event.cursor);
        }
        fn resync(&self) {
            *self.resyncs.lock().unwrap() += 1;
        }
    }

    #[tokio::test]
    async fn driver_delivers_live_events_in_order_and_dedups() {
        let sink = Arc::new(RecordingSink::default());
        let driver = EventDriver::new(Cursor(0), EnumSet::all(), vec![sink.clone()]);
        let feed = ScriptedFeed {
            items: [
                FeedItem::Event(received(1)),
                FeedItem::Event(received(1)), // duplicate — dropped
                FeedItem::Event(received(2)),
                FeedItem::Closed,
            ]
            .into(),
        };
        run(driver, feed, FakeCatchUp(vec![])).await;
        assert_eq!(*sink.applied.lock().unwrap(), vec![Cursor(1), Cursor(2)]);
        assert_eq!(*sink.resyncs.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn driver_backfills_on_lag_then_resumes_live() {
        let sink = Arc::new(RecordingSink::default());
        let driver = EventDriver::new(Cursor(0), EnumSet::all(), vec![sink.clone()]);
        let feed = ScriptedFeed {
            items: [
                FeedItem::Event(received(1)),
                FeedItem::Lagged, // missed 2,3 — backfilled below
                FeedItem::Event(received(4)),
                FeedItem::Closed,
            ]
            .into(),
        };
        let backfill = FakeCatchUp(vec![received(2), received(3)]);
        run(driver, feed, backfill).await;
        assert_eq!(
            *sink.applied.lock().unwrap(),
            vec![Cursor(1), Cursor(2), Cursor(3), Cursor(4)]
        );
        assert_eq!(*sink.resyncs.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn driver_resyncs_gracefully_on_an_unrecoverable_gap() {
        let sink = Arc::new(RecordingSink::default());
        // Saw cursor 1; window now only holds 8,9 (2..7 evicted).
        let driver = EventDriver::new(Cursor(1), EnumSet::all(), vec![sink.clone()]);
        let feed = ScriptedFeed {
            items: [
                FeedItem::Lagged,
                FeedItem::Event(received(10)),
                FeedItem::Closed,
            ]
            .into(),
        };
        let backfill = FakeCatchUp(vec![received(8), received(9)]);
        run(driver, feed, backfill).await;
        // One resync fired; the post-resync live event (10) still lands, no crash.
        assert_eq!(*sink.resyncs.lock().unwrap(), 1);
        assert_eq!(*sink.applied.lock().unwrap(), vec![Cursor(10)]);
    }
}
