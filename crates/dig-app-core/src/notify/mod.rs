//! Native funds-activity notifications (#970) — the "you got paid / your send confirmed" signal.
//!
//! A [`NotifyingSink`] taps the wallet [`EventSink`] stream for
//! [`WalletEvent::FundsReceived`]/[`WalletEvent::FundsSent`] and feeds them to [`run_notifier`],
//! which DEBOUNCES a short coalescing window so a burst (3 coins in 2s) becomes ONE toast, then
//! renders it through the per-OS [`NativeNotifier`]. It is a passive, dismissible awareness signal
//! — it never gates a read and is opt-out (§6.0/§6.1). It shows only amounts + counts; NEVER a key,
//! seed, or address (custody stays out of the notification surface).
//!
//! # Which debounce is the LIVE one (dig-app#292)
//!
//! There are two coalescing mechanisms here and only one of them runs in the shipped app. The
//! arrivals path — [`crate::arrivals::watch::sweep`] → [`announce_arrivals`] — is what a person
//! actually gets a toast from, and it debounces STRUCTURALLY: the batching window is the poll
//! interval, so one sweep is one toast with no timer to get wrong. The policy is stated in full on
//! [`crate::arrivals::watch::WATCH_INTERVAL`], including what happens to a coin that arrives
//! mid-window.
//!
//! [`run_notifier`]'s timed window is the event-stream half and currently has **no production
//! caller**; it is exercised by tests only. It is kept because the two feeds are genuinely
//! different — one is the node's persisted ledger, the other a live event stream — but a reader
//! looking for "how often does this fire?" must read `WATCH_INTERVAL`, not the timer below.
//!
//! # Layers
//! - [`Notification`] + [`NativeNotifier`] — the render seam; per-OS backends + a headless
//!   [`LoggingNotifier`] fallback, chosen by [`native_notifier`].
//! - [`PendingActivity`] + [`summarize`] — the PURE coalescing model: fold a burst of funds events
//!   into one honest [`Notification`]. Fully unit-tested, no timing.
//! - [`NotifyingSink`] + [`run_notifier`] — the wiring: the sink forwards funds events over a
//!   channel; the async task applies the debounce window and shows the coalesced result.

/// Crate-visible so the money surfaces that must render an asset the same way this one does — the
/// wallet's activity list ([`crate::wallet::activity`]) — reuse the mapping instead of copying it.
/// A second "which id is $DIG" is how a surface comes to call somebody else's CAT $DIG.
pub(crate) mod render;

/// The activity gate (dig-app#312): hold a notification until the person is at the machine, then
/// release it once, coalesced. Public because all three of its callers live outside this module.
pub mod gate;

/// Is anybody there — the one platform-specific half of the gate.
pub mod presence;

/// The one process-wide gate and the pump that drains it — what the app shell drives.
pub mod shared;

use std::collections::BTreeMap;

use dig_events_protocol::{AssetId, EmittedEvent, WalletEvent};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::events::EventSink;

pub use gate::{ActivityGate, HoldKey, HoldPolicy};
pub use presence::Presence;
pub use render::{native_notifier, LoggingNotifier};

/// This application's Windows AppUserModelID — the identity every DIG toast is filed under, and the
/// value the Start Menu shortcut must carry for a toast to appear at all. See
/// The Windows backend's application user-model id.
#[cfg(target_os = "windows")]
pub use render::AUMID;

/// Do whatever this host needs done BEFORE a notification can be drawn, and nothing else.
///
/// Called once at start-up by the app shell. On Windows it writes the Start Menu identity a toast is
/// attributed to, because that registration is not visible to the shell within the process that
/// makes it — see the Windows backend for the measurement. Everywhere else there is nothing to
/// prepare and this is a no-op, which is why it is a plain function rather than something a caller
/// has to branch on.
pub fn prepare_host() {
    #[cfg(target_os = "windows")]
    render::prepare();
}

/// A rendered notification: a short title + a glanceable body. Contains only public activity
/// facts (amounts, counts, asset labels) — never secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// The toast title (e.g. `"DIG — Funds received"`).
    pub title: String,
    /// The one- or two-line body (e.g. `"Received 3 payments: 1.5 XCH total"`).
    pub body: String,
    /// Where a click on this notification should land, when the host can deliver one.
    ///
    /// `None` for a notification that is purely an awareness signal — the funds-received toast has
    /// nowhere in particular to send anybody.
    ///
    /// **A route is a best-effort extra and never a promise.** See [`Route`] for which hosts can
    /// honour one; the load-bearing rule is that the title and body must stand alone on a host that
    /// cannot, which is why this is a separate field rather than a sentence in the copy.
    pub route: Option<Route>,
}

/// Where a click on a notification should take the user.
///
/// # Why an enum and not a URI string
///
/// A URI is the WIRE form on exactly one host (Windows protocol activation), and building the app's
/// navigation vocabulary out of strings means every consumer re-parses it and one of them eventually
/// parses it differently. This is the vocabulary; [`Route::uri`] is its serialization, and
/// [`Route::tab`] is what the window does with it once it arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The place a person adds funds — the Wallet tab, which is where the receive address lives.
    Deposit,
}

impl Route {
    /// The URI a host with protocol activation launches.
    ///
    /// Uses dig-app's own scheme rather than `dig://`, which is CONTENT addressing (see
    /// [`crate::link`]) and must not be overloaded with app navigation — a `dig://` that sometimes
    /// means "fetch this capsule" and sometimes "open this tab" is a scheme that cannot be routed.
    pub fn uri(self) -> &'static str {
        match self {
            Self::Deposit => "dig-app:deposit",
        }
    }

    /// Read a route back off an activation URI, or `None` for anything else.
    ///
    /// Total and refusing: an activation naming something this build does not know must open the
    /// window at whatever tab the user last had, never at a guess.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri.trim() {
            "dig-app:deposit" => Some(Self::Deposit),
            _ => None,
        }
    }

    /// The tab this route lands on.
    ///
    /// # Focus THEN navigate, and this is the navigate half
    ///
    /// Bringing the window forward without landing on the right tab is worse than ignoring the click
    /// entirely: the user is then looking at an app that appeared for no visible reason. So a caller
    /// handling an activation resolves this FIRST and shows the window already on that tab, rather
    /// than showing the window and navigating after.
    ///
    /// Because it is a pure function of the route, handling the same activation twice selects the
    /// same tab twice — which is what makes the hourly repeats idempotent. Several notifications can
    /// be live at once and clicking any of them reaches deposit once, not N stacked navigations.
    pub fn tab(self) -> crate::window_model::TabId {
        match self {
            // Wallet is where money arrives and where the receive address is copied from; dig-app
            // has no separate deposit destination, and inventing one would be a second surface for
            // the address that already lives there.
            Self::Deposit => crate::window_model::TabId::Wallet,
        }
    }
}

/// The per-OS native toast seam. `Send + Sync` so the notifier task can own one across awaits.
///
/// The production implementations are the per-OS backends (`render`); tests use a recording
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
    /// Fold one confirmed incoming amount into the tally, in the asset's own base unit.
    ///
    /// Separate from [`record`](Self::record) because the two callers hold different things: the
    /// event pipeline holds a whole [`WalletEvent`], while [`crate::arrivals`] holds a coin and an
    /// asset and would otherwise have to fabricate a wallet id and a cursor to reach this tally. A
    /// notification must not be built out of invented fields, so it takes the two that matter.
    pub fn received(&mut self, asset: Option<AssetId>, base_units: u64) {
        self.received.entry(asset).or_default().add(base_units);
    }

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
    // No route: a funds-activity toast is pure awareness and has nowhere in particular to send
    // anybody. Only the out-of-funds notification names a destination, because only it is asking for
    // something to be done.
    Some(Notification {
        title,
        body,
        route: None,
    })
}

/// The $DIG CAT's asset id, spelled the way the event contract spells an asset.
///
/// Taken from [`dig_constants::DIG_ASSET_ID`] — the ecosystem's single home for the value, declared
/// byte-identical to `chip35_dl_coin`'s, digstore-chain's and DataLayer-Driver's — rather than typed
/// out here. A second copy of a token id is how a notification comes to call somebody else's CAT
/// `$DIG`, which is a lie about which money arrived.
pub fn dig_asset_id() -> AssetId {
    AssetId(hex::encode(dig_constants::DIG_ASSET_ID))
}

/// One honest notification for a batch of confirmed arrivals, or `None` when the batch is empty.
///
/// The batch IS the coalescing window: [`crate::arrivals`] hands over everything one sweep of the
/// node's ledger newly reached, so three coins in one block become one toast without a timer.
/// Rendering goes through [`summarize`], so the amounts carry each asset's own decimals (XCH 12,
/// CAT 3) and $DIG is named from the canonical id rather than guessed.
///
/// The asset id is passed through from the node VERBATIM, which is why a CAT dig-app has never
/// heard of is still announced honestly — by its own short id rather than as XCH or not at all.
pub fn arrival_notification(arrivals: &[crate::arrivals::Arrival]) -> Option<Notification> {
    let dig = dig_asset_id();
    let mut pending = PendingActivity::default();
    for arrival in arrivals {
        pending.received(arrival.asset_id.clone(), arrival.amount);
    }
    summarize(&pending, Some(&dig))
}

/// Show `arrivals` as one notification — unless the user turned notifications off.
///
/// The switch is checked HERE, at the one place a toast is drawn, rather than at the detection site:
/// [`crate::arrivals`] must keep accounting for coins while notifications are off, or turning them
/// back on would announce everything received in between.
pub fn announce_arrivals(
    arrivals: &[crate::arrivals::Arrival],
    enabled: bool,
    notifier: &dyn NativeNotifier,
) {
    if !enabled {
        return;
    }
    if let Some(notification) = arrival_notification(arrivals) {
        notifier.show(&notification);
    }
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

    /// **A route round-trips through its URI**, so the string the OS hands back resolves to the same
    /// destination the toast asked for.
    #[test]
    fn a_route_survives_the_trip_through_the_os() {
        assert_eq!(Route::from_uri(Route::Deposit.uri()), Some(Route::Deposit));
        // Whitespace, because an activation argument arrives through a command line and a shell.
        assert_eq!(
            Route::from_uri("  dig-app:deposit \n"),
            Some(Route::Deposit)
        );
    }

    /// **An activation this build does not know opens nothing in particular**, rather than guessing
    /// at a tab — a window that appeared and landed somewhere arbitrary is the failure that makes a
    /// click worse than no click.
    #[test]
    fn an_unknown_activation_selects_no_tab() {
        for foreign in ["dig-app:something-else", "dig://store/abc", "", "deposit"] {
            assert_eq!(Route::from_uri(foreign), None, "{foreign:?}");
        }
    }

    /// **Resolving the same activation twice selects the same tab twice.**
    ///
    /// The hourly repeat means several notifications can be live at once, so clicking any of them
    /// must reach deposit ONCE rather than stacking navigations. That property rests on the route
    /// being a pure function with no accumulated state, which is what this pins.
    #[test]
    fn handling_an_activation_repeatedly_is_idempotent() {
        let tabs: Vec<_> = std::iter::repeat_with(|| {
            Route::from_uri(Route::Deposit.uri())
                .expect("a known activation")
                .tab()
        })
        .take(4)
        .collect();
        assert!(tabs.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(tabs[0], crate::window_model::TabId::Wallet);
    }

    /// **The app-navigation scheme is NOT the content scheme.**
    ///
    /// `dig://` addresses content ([`crate::link`]). A URI that sometimes means "fetch this capsule"
    /// and sometimes "open this tab" cannot be routed by a handler, so the two must stay apart.
    #[test]
    fn navigation_does_not_overload_the_content_scheme() {
        assert!(!Route::Deposit.uri().starts_with("dig://"));
        assert!(Route::Deposit.uri().starts_with("dig-app:"));
    }

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

    // ------------------------------------------------------------------------------------------
    // Arrival copy (dig_ecosystem#2548)
    // ------------------------------------------------------------------------------------------

    use crate::arrivals::Arrival;
    fn arrival(asset_id: Option<AssetId>, amount: u64) -> Arrival {
        Arrival {
            seq: amount,
            coin_id: format!("{amount:064x}"),
            asset_id,
            amount,
            confirmed_height: 5_412_000,
        }
    }

    /// An XCH arrival — the native asset carries no id at all.
    fn xch(amount: u64) -> Arrival {
        arrival(None, amount)
    }

    /// A $DIG arrival, named from the canonical id rather than a second copy of the token id.
    fn dig(amount: u64) -> Arrival {
        arrival(Some(dig_asset_id()), amount)
    }

    /// **The $DIG label comes from the canonical asset id, and the amount from the CAT divisor.**
    ///
    /// Two independent ways to lie about money in one sentence, so both are pinned: naming the CAT
    /// (a wrong id renders `$DIG` as a truncated hex string, or worse, calls a stranger's CAT
    /// `$DIG`), and dividing it ($DIG carries 3 decimals, so 2500 base units is 2.5 — rendering it
    /// with the XCH divisor would say `0.0000000025`).
    #[test]
    fn a_dig_arrival_is_named_and_divided_as_dig() {
        let note = arrival_notification(&[dig(2_500)]).expect("one arrival");
        assert_eq!(note.title, "DIG — Funds received");
        assert_eq!(note.body, "Received 2.5 $DIG");
        assert_eq!(
            dig_asset_id().0,
            "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81",
            "the label is only honest if the id is the canonical one"
        );
    }

    /// **An XCH arrival is divided by the XCH divisor, which is a different number.**
    #[test]
    fn an_xch_arrival_is_named_and_divided_as_xch() {
        let note = arrival_notification(&[xch(1_500_000_000_000)]).unwrap();
        assert_eq!(note.body, "Received 1.5 XCH");
    }

    /// **A batch of arrivals is ONE notification that totals each asset separately.**
    #[test]
    fn a_batch_of_arrivals_is_one_notification_per_asset() {
        let note =
            arrival_notification(&[xch(1_000_000_000_000), xch(500_000_000_000), dig(1_000)])
                .unwrap();
        assert!(note.body.contains("3 payments"), "{}", note.body);
        assert!(note.body.contains("1.5 XCH"), "{}", note.body);
        assert!(note.body.contains("1 $DIG"), "{}", note.body);
    }

    /// **An empty batch draws nothing** — a poll that found no arrivals must not toast.
    #[test]
    fn an_empty_batch_draws_nothing() {
        assert_eq!(arrival_notification(&[]), None);
    }

    /// **The off switch stops the toast, and the control proves the switch is what stopped it.**
    #[test]
    fn notifications_turned_off_draw_nothing() {
        let notifier = RecordingNotifier::default();
        announce_arrivals(&[xch(1_000_000_000_000)], false, &notifier);
        assert!(
            notifier.0.lock().unwrap().is_empty(),
            "a toast was drawn with notifications turned off"
        );

        announce_arrivals(&[xch(1_000_000_000_000)], true, &notifier);
        assert_eq!(
            notifier.0.lock().unwrap().len(),
            1,
            "with the switch ON nothing was drawn either, so the assertion above proves nothing"
        );
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
