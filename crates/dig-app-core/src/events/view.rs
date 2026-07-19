//! The reactive wallet view — the UI seam's observable state, driven purely by events.
//!
//! [`WalletView`] is an [`EventSink`] that folds the [`WalletEvent`] stream into a cheap, cloneable
//! [`WalletSnapshot`] the tray shell and `dign` CLI OBSERVE (the same shared-handle pattern as
//! [`crate::agent::SharedStatus`]) instead of polling. It tracks what events can tell it directly —
//! the sync lifecycle, the chain tip, and glanceable received/sent tallies — and flips a
//! [`WalletSnapshot::balances_dirty`] flag whenever money moved or an unrecoverable gap forced a
//! resync, signalling the observer to re-read the AUTHORITATIVE balance through the
//! [`crate::wallet`] read seam. Events say *when* to refresh; the read seam supplies the numbers.

use std::sync::{Arc, RwLock};

use dig_events_protocol::{EmittedEvent, SyncStatus, WalletEvent};

use super::EventSink;

/// A cheap, cloneable snapshot of wallet state the UI paints from.
///
/// Everything here is reconstructable from the event stream (or a resync), so an observer never
/// needs to reach into the driver — it reads this snapshot under the shared lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletSnapshot {
    /// The latest observed sync status, once a `SyncProgress` event has arrived.
    pub sync: Option<SyncStatus>,
    /// The height of the latest observed chain tip.
    pub tip_height: Option<u32>,
    /// How many inbound-funds events have been observed (glanceable activity count).
    pub received_count: u64,
    /// How many outbound-funds events have been observed.
    pub sent_count: u64,
    /// Set when money moved or a resync fired: the observer should re-read the authoritative
    /// balance from the wallet read seam and then [`WalletView::clear_balances_dirty`].
    pub balances_dirty: bool,
}

/// A shared, thread-safe handle to the [`WalletSnapshot`], for an observer (tray/CLI) to read while
/// the driver folds events in.
pub type SharedSnapshot = Arc<RwLock<WalletSnapshot>>;

/// The reactive wallet view: an [`EventSink`] that maintains a [`SharedSnapshot`].
#[derive(Default)]
pub struct WalletView {
    snapshot: SharedSnapshot,
}

impl WalletView {
    /// A fresh view with an empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// A cloneable handle for an observer to read the latest snapshot.
    pub fn handle(&self) -> SharedSnapshot {
        Arc::clone(&self.snapshot)
    }

    /// A copy of the current snapshot.
    pub fn snapshot(&self) -> WalletSnapshot {
        self.snapshot
            .read()
            .expect("snapshot lock poisoned")
            .clone()
    }

    /// Acknowledge an authoritative balance re-read: clear the dirty flag.
    pub fn clear_balances_dirty(&self) {
        self.write().balances_dirty = false;
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, WalletSnapshot> {
        self.snapshot.write().expect("snapshot lock poisoned")
    }
}

impl EventSink for WalletView {
    fn apply(&self, event: &EmittedEvent) {
        let mut snap = self.write();
        match &event.event {
            WalletEvent::FundsReceived { .. } => {
                snap.received_count += 1;
                snap.balances_dirty = true;
            }
            WalletEvent::FundsSent { .. } => {
                snap.sent_count += 1;
                snap.balances_dirty = true;
            }
            WalletEvent::NewTip { height, .. } => {
                snap.tip_height = Some(*height);
            }
            WalletEvent::SyncProgress {
                state,
                peak_height,
                target_height,
                ..
            } => {
                snap.sync = Some(SyncStatus {
                    state: *state,
                    peak_height: *peak_height,
                    target_height: *target_height,
                });
            }
            // Coin/tx/metadata events do not change the painted view directly; a confirmation or a
            // coin-state change is reflected via the authoritative balance re-read that any funds
            // event already requested.
            _ => {}
        }
    }

    fn resync(&self) {
        // The incremental tallies are no longer trustworthy after a lost range; reset them and
        // force an authoritative reload. Tip/sync will be repainted by the next live events.
        let mut snap = self.write();
        snap.received_count = 0;
        snap.sent_count = 0;
        snap.balances_dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_events_protocol::{Amount, Cursor, SyncLifecycle, WalletId};

    fn at(cursor: u64, event: WalletEvent) -> EmittedEvent {
        EmittedEvent {
            cursor: Cursor(cursor),
            event,
        }
    }

    fn received() -> WalletEvent {
        WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: None,
            amount: Amount(100),
            coin_id: "c".into(),
            confirmed_height: 5,
        }
    }

    #[test]
    fn funds_received_bumps_the_count_and_marks_balances_dirty() {
        let view = WalletView::new();
        view.apply(&at(1, received()));
        let snap = view.snapshot();
        assert_eq!(snap.received_count, 1);
        assert!(snap.balances_dirty);
    }

    #[test]
    fn funds_sent_bumps_the_sent_count() {
        let view = WalletView::new();
        view.apply(&at(
            1,
            WalletEvent::FundsSent {
                wallet_id: WalletId(1),
                asset: None,
                amount: Amount(10),
                tx_id: "t".into(),
                confirmed_height: 6,
            },
        ));
        assert_eq!(view.snapshot().sent_count, 1);
        assert!(view.snapshot().balances_dirty);
    }

    #[test]
    fn new_tip_and_sync_progress_paint_the_snapshot() {
        let view = WalletView::new();
        view.apply(&at(
            1,
            WalletEvent::NewTip {
                height: 42,
                header_hash: "hh".into(),
            },
        ));
        view.apply(&at(
            2,
            WalletEvent::SyncProgress {
                wallet_id: WalletId(1),
                state: SyncLifecycle::Syncing,
                peak_height: 40,
                target_height: 42,
            },
        ));
        let snap = view.snapshot();
        assert_eq!(snap.tip_height, Some(42));
        assert_eq!(
            snap.sync,
            Some(SyncStatus {
                state: SyncLifecycle::Syncing,
                peak_height: 40,
                target_height: 42,
            })
        );
    }

    #[test]
    fn clear_balances_dirty_acknowledges_a_reread() {
        let view = WalletView::new();
        view.apply(&at(1, received()));
        assert!(view.snapshot().balances_dirty);
        view.clear_balances_dirty();
        assert!(!view.snapshot().balances_dirty);
    }

    #[test]
    fn resync_resets_tallies_and_forces_a_reload() {
        let view = WalletView::new();
        view.apply(&at(1, received()));
        view.apply(&at(2, received()));
        assert_eq!(view.snapshot().received_count, 2);
        view.clear_balances_dirty();

        view.resync();
        let snap = view.snapshot();
        assert_eq!(snap.received_count, 0);
        assert_eq!(snap.sent_count, 0);
        assert!(snap.balances_dirty);
    }

    #[test]
    fn the_handle_observes_live_updates() {
        let view = WalletView::new();
        let handle = view.handle();
        view.apply(&at(1, received()));
        assert_eq!(handle.read().unwrap().received_count, 1);
    }
}
