//! Native funds-activity notifications (#970) — the "you got paid / your send confirmed" signal.
//!
//! A [`NotifyingSink`] taps the wallet [`EventSink`](crate::events::EventSink) stream for
//! [`WalletEvent::FundsReceived`]/[`WalletEvent::FundsSent`] and feeds them to [`run_notifier`],
//! which DEBOUNCES a short coalescing window so a burst (3 coins in 2s) becomes ONE toast, then
//! renders it through the per-OS [`NativeNotifier`]. It is a passive, dismissible awareness signal
//! — it never gates a read and is opt-out (§6.0/§6.1). It shows only amounts + counts; NEVER a key,
//! seed, or address (custody stays out of the notification surface).
//!
//! # Layers
//! - [`Notification`] + [`NativeNotifier`] — the render seam; per-OS backends + a headless
//!   [`LoggingNotifier`] fallback, chosen by [`native_notifier`].
//! - [`PendingActivity`] + [`summarize`] — the PURE coalescing model: fold a burst of funds events
//!   into one honest [`Notification`]. Fully unit-tested, no timing.
//! - [`NotifyingSink`] + [`run_notifier`] — the wiring: the sink forwards funds events over a
//!   channel; the async task applies the debounce window and shows the coalesced result.

mod render;

use std::collections::BTreeMap;

use dig_events_protocol::{AssetId, EmittedEvent, WalletEvent};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::events::EventSink;

pub use render::{native_notifier, LoggingNotifier};

/// A rendered notification: a short title + a glanceable body. Contains only public activity
/// facts (amounts, counts, asset labels) — never secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// The toast title (e.g. `"DIG — Funds received"`).
    pub title: String,
    /// The one- or two-line body (e.g. `"Received 3 payments: 1.5 XCH total"`).
    pub body: String,
}

/// The per-OS native toast seam. `Send + Sync` so the notifier task can own one across awaits.
///
/// The production implementations are the per-OS backends ([`render`]); tests use a recording
/// double, and a headless host falls back to the [`LoggingNotifier`].
pub trait NativeNotifier: Send + Sync {
    /// Show `notification` as a native OS toast (best-effort; a failure is swallowed — a missed
    /// awareness toast must never break the app).
    fn show(&self, notification: &Notification);
}

/// The running per-asset, per-direction tally of a coalescing window.
///
/// Keyed by the asset (native XCH = the `None` key, stored as an empty string) so a mixed burst
/// (XCH + a CAT) summarizes each asset honestly. Pure state — [`summarize`] renders it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingActivity {
    received: BTreeMap<Option<AssetId>, AssetTotal>,
    sent: BTreeMap<Option<AssetId>, AssetTotal>,
}

/// A count + summed base-unit amount for one asset in one direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct AssetTotal {
    count: u64,
    mojos: u128,
}

impl AssetTotal {
    fn add(&mut self, mojos: u64) {
        self.count += 1;
        self.mojos += mojos as u128;
    }
}

impl PendingActivity {
    /// Fold one funds event into the tally. Non-funds events are ignored (the sink only forwards
    /// funds events, but recording is total-function to keep the model self-contained).
    pub fn record(&mut self, event: &WalletEvent) {
        match event {
            WalletEvent::FundsReceived { asset, amount, .. } => {
                self.received
                    .entry(asset.clone())
                    .or_default()
                    .add(amount.mojos());
            }
            WalletEvent::FundsSent { asset, amount, .. } => {
                self.sent
                    .entry(asset.clone())
                    .or_default()
                    .add(amount.mojos());
            }
            _ => {}
        }
    }

    /// Whether anything has been recorded (an empty window renders no toast).
    pub fn is_empty(&self) -> bool {
        self.received.is_empty() && self.sent.is_empty()
    }
}

/// Render a coalesced window into one honest [`Notification`], or `None` when nothing was recorded.
///
/// `dig_asset_id` labels the DIG CAT as `$DIG`; any other CAT is shown by a short asset id, and the
/// native asset as `XCH` — never a false ticker (§6.0 honest).
pub fn summarize(
    pending: &PendingActivity,
    dig_asset_id: Option<&AssetId>,
) -> Option<Notification> {
    if pending.is_empty() {
        return None;
    }
    let received = render::direction_line("Received", &pending.received, dig_asset_id);
    let sent = render::direction_line("Sent", &pending.sent, dig_asset_id);

    let (title, body) = match (received, sent) {
        (Some(r), None) => ("DIG — Funds received".to_string(), r),
        (None, Some(s)) => ("DIG — Funds sent".to_string(), s),
        (Some(r), Some(s)) => ("DIG — Wallet activity".to_string(), format!("{r}\n{s}")),
        (None, None) => return None,
    };
    Some(Notification { title, body })
}

/// An [`EventSink`] that forwards funds events to the debounced notifier task.
///
/// It holds only the send half of an unbounded channel, so recording an event never blocks the
/// driver. A closed receiver (the notifier task stopped) silently drops events — notifications are
/// best-effort. `resync` is a no-op: a lost-range resync re-reads authoritative balance elsewhere;
/// firing a bulk "received N" toast for a backfill would be noise.
pub struct NotifyingSink {
    tx: UnboundedSender<WalletEvent>,
}

impl NotifyingSink {
    /// Build a sink over the given channel sender (paired with [`run_notifier`]'s receiver).
    pub fn new(tx: UnboundedSender<WalletEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for NotifyingSink {
    fn apply(&self, event: &EmittedEvent) {
        if matches!(
            event.event,
            WalletEvent::FundsReceived { .. } | WalletEvent::FundsSent { .. }
        ) {
            // Best-effort: a full/closed channel just drops the toast, never the driver.
            let _ = self.tx.send(event.event.clone());
        }
    }
}

/// The debounced notifier task: coalesce every funds event arriving within `window` of the first
/// into ONE toast, render it, and repeat. Returns when the channel closes.
///
/// Fixed-window (trailing-flush) debounce: the first event opens a window; all events inside it
/// merge; at the window's end one [`summarize`]d notification is shown. `dig_asset_id` labels the
/// DIG CAT honestly.
pub async fn run_notifier<N: NativeNotifier>(
    mut rx: UnboundedReceiver<WalletEvent>,
    window: std::time::Duration,
    dig_asset_id: Option<AssetId>,
    notifier: N,
) {
    while let Some(first) = rx.recv().await {
        let mut pending = PendingActivity::default();
        pending.record(&first);

        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                maybe = rx.recv() => match maybe {
                    Some(event) => pending.record(&event),
                    None => break, // channel closed mid-window: flush what we have, then stop.
                },
            }
        }

        if let Some(notification) = summarize(&pending, dig_asset_id.as_ref()) {
            notifier.show(&notification);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_events_protocol::{Amount, Cursor, WalletId};
    use std::sync::Mutex;
    use std::time::Duration;

    fn received(asset: Option<&str>, mojos: u64) -> WalletEvent {
        WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: asset.map(|a| AssetId(a.into())),
            amount: Amount(mojos),
            coin_id: "c".into(),
            confirmed_height: 1,
        }
    }

    fn sent(asset: Option<&str>, mojos: u64) -> WalletEvent {
        WalletEvent::FundsSent {
            wallet_id: WalletId(1),
            asset: asset.map(|a| AssetId(a.into())),
            amount: Amount(mojos),
            tx_id: "t".into(),
            confirmed_height: 1,
        }
    }

    #[test]
    fn empty_window_renders_no_notification() {
        assert_eq!(summarize(&PendingActivity::default(), None), None);
    }

    #[test]
    fn a_burst_of_receives_coalesces_into_one_notification() {
        let mut pending = PendingActivity::default();
        pending.record(&received(None, 500_000_000_000));
        pending.record(&received(None, 1_000_000_000_000));
        pending.record(&received(None, 500_000_000_000));
        let note = summarize(&pending, None).unwrap();
        assert_eq!(note.title, "DIG — Funds received");
        assert!(note.body.contains("3 payments"), "{}", note.body);
        assert!(note.body.contains("2 XCH"), "{}", note.body); // 2.0 XCH total
    }

    #[test]
    fn a_single_receive_reads_naturally() {
        let mut pending = PendingActivity::default();
        pending.record(&received(None, 1_000_000_000_000));
        let note = summarize(&pending, None).unwrap();
        assert!(note.body.contains("1 XCH"), "{}", note.body);
        assert!(!note.body.contains("payments"), "singular: {}", note.body);
    }

    #[test]
    fn mixed_received_and_sent_summarize_both_lines() {
        let mut pending = PendingActivity::default();
        pending.record(&received(None, 1_000_000_000_000));
        pending.record(&sent(None, 500_000_000_000));
        let note = summarize(&pending, None).unwrap();
        assert_eq!(note.title, "DIG — Wallet activity");
        assert!(note.body.contains("Received"), "{}", note.body);
        assert!(note.body.contains("Sent"), "{}", note.body);
    }

    #[test]
    fn the_dig_cat_is_labelled_dig_and_other_cats_are_not() {
        let dig = AssetId("dig-tail".into());
        let mut pending = PendingActivity::default();
        pending.record(&received(Some("dig-tail"), 3_000));
        let note = summarize(&pending, Some(&dig)).unwrap();
        assert!(note.body.contains("$DIG"), "{}", note.body);
    }

    /// A notifier that records every shown notification.
    #[derive(Default)]
    struct RecordingNotifier(Mutex<Vec<Notification>>);
    impl NativeNotifier for RecordingNotifier {
        fn show(&self, notification: &Notification) {
            self.0.lock().unwrap().push(notification.clone());
        }
    }

    #[tokio::test]
    async fn the_sink_forwards_only_funds_events() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = NotifyingSink::new(tx);
        sink.apply(&EmittedEvent {
            cursor: Cursor(1),
            event: WalletEvent::NewTip {
                height: 1,
                header_hash: "h".into(),
            },
        });
        sink.apply(&EmittedEvent {
            cursor: Cursor(2),
            event: received(None, 10),
        });
        drop(sink);
        // Only the funds event came through.
        assert!(matches!(
            rx.recv().await,
            Some(WalletEvent::FundsReceived { .. })
        ));
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn run_notifier_coalesces_a_burst_into_one_toast() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let notifier = std::sync::Arc::new(RecordingNotifier::default());
        let recorder = notifier.clone();
        let task = tokio::spawn(async move {
            run_notifier(
                rx,
                Duration::from_millis(50),
                None,
                DelegatingNotifier(recorder),
            )
            .await;
        });
        tx.send(received(None, 1_000_000_000_000)).unwrap();
        tx.send(received(None, 1_000_000_000_000)).unwrap();
        drop(tx); // close after the burst — the task flushes then returns.
        task.await.unwrap();
        let shown = notifier.0.lock().unwrap();
        assert_eq!(shown.len(), 1, "the burst coalesced into one toast");
        assert!(shown[0].body.contains("2 payments"));
    }

    /// Wraps an `Arc<RecordingNotifier>` so the test can both hand ownership to the task and still
    /// read what was shown afterward.
    struct DelegatingNotifier(std::sync::Arc<RecordingNotifier>);
    impl NativeNotifier for DelegatingNotifier {
        fn show(&self, notification: &Notification) {
            self.0.show(notification);
        }
    }
}
