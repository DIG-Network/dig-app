//! Reading dig-node's send ledger from the tray process.
//!
//! The mirror of [`crate::arrivals::watch`], and deliberately a separate throttle rather than a
//! second job inside that one: the two ledgers have separate cursors, separate files, separate
//! preferences and separate failure modes, and folding them into one sweep would mean a node that
//! is too old to serve `control.wallet.sends` silently costing the user their ARRIVAL toasts too.
//!
//! # The custody boundary (§908) and the token
//!
//! A read of the node's own replica. No key, seed, address or signature is involved and nothing here
//! can spend. It is TOKEN-GATED for a strictly stronger reason than the arrival cursor: the answer
//! names this node's own watched addresses AND says when this wallet is spending. A tray that cannot
//! read the control token therefore gets no send toasts, which is the correct trade.
//!
//! # A node that does not know the method is not an error
//!
//! `control.wallet.sends` arrived in dig-node 0.110.0. An older node answers a method-not-found,
//! which reaches [`sweep`] as an ordinary unavailable read: the cursor stays where it is, nothing is
//! announced, and nothing is logged above debug. The feature simply does not appear until the node
//! is new enough.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_events_protocol::AssetId;
use dig_node_control_interface::params::WalletSendsParams;
use dig_node_control_interface::results::{WalletSendRecord, WalletSendsResult};

use crate::arrivals::ArrivalSourceError;
use crate::control::{self, ControlFailure};
use crate::engine::EngineState;
use crate::notify::{self, NativeNotifier};

use super::{SendPage, SendSource, SentPayment};

/// How long between send reads. The arrival interval, for the same reason: the balance figure and
/// the toast that explains it describe one event.
pub const WATCH_INTERVAL: Duration = crate::arrivals::watch::WATCH_INTERVAL;

/// How long ONE send read may take before it is abandoned.
pub const WATCH_READ_TIMEOUT: Duration = crate::arrivals::watch::WATCH_READ_TIMEOUT;

/// How many pages one sweep will drain before leaving the rest for the next.
const MAX_PAGES_PER_SWEEP: usize = 20;

/// Reads dig-node's send ledger over the loopback control plane.
pub struct ControlPlaneSendSource {
    endpoint: String,
    token: Option<String>,
    timeout: Duration,
}

impl ControlPlaneSendSource {
    /// A source reading the send ledger of the node at `endpoint`, presenting `token` when there is
    /// one. `None` means the node will refuse — the read is gated, not open.
    pub fn new(endpoint: impl Into<String>, token: Option<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            token,
            timeout,
        }
    }
}

impl SendSource for ControlPlaneSendSource {
    fn sends_since(&self, after_seq: u64) -> Result<SendPage, ArrivalSourceError> {
        let params = WalletSendsParams {
            after_seq,
            limit: None,
        };
        let answer: WalletSendsResult = control::call_control_result(
            &self.endpoint,
            &params,
            self.token.as_deref(),
            self.timeout,
        )
        .map_err(|failure: ControlFailure| ArrivalSourceError::Unavailable(failure.to_string()))?;

        let sends = answer
            .sends
            .iter()
            .map(sent_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SendPage {
            sends,
            cursor: answer.cursor,
            latest: answer.latest,
        })
    }
}

/// One of the node's ledger rows as a [`SentPayment`].
///
/// The only thing that can fail is the figure, and it is REFUSED rather than defaulted. The contract
/// carries it as a decimal string because the ledger holds the full `u64` range; a zero or a
/// saturated maximum standing in for an unreadable value is a wrong claim about how much money left,
/// which is the one thing this feature must never make.
fn sent_from(record: &WalletSendRecord) -> Result<SentPayment, ArrivalSourceError> {
    let net_outflow = record.net_outflow.parse::<u64>().map_err(|e| {
        ArrivalSourceError::Malformed(format!(
            "send {} carries an unreadable net outflow: {e}",
            record.seq
        ))
    })?;
    Ok(SentPayment {
        seq: record.seq,
        net_outflow,
        asset_id: record.asset_id.clone().map(AssetId),
        confirmed_height: record.confirmed_height,
    })
}

/// The send watch: reads no more often than [`WATCH_INTERVAL`], never on the caller's thread, and
/// draws at most one toast per sweep.
pub struct SendWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    timeout: Duration,
    /// Where the durable cursor lives. `None` disables the watch: a cursor that cannot be persisted
    /// cannot promise that a restart will not re-announce, and an un-keepable promise about
    /// somebody's payments is worse than a missing toast.
    cursor_path: Option<std::path::PathBuf>,
    /// Where the user's preference lives, re-read per sweep so Settings takes effect within one
    /// interval rather than at the next restart.
    config_path: Option<std::path::PathBuf>,
    /// Reads the node's control token. Injected so a test presents its own fake node's token.
    read_token: fn() -> Option<String>,
}

/// What the watch knows between reads.
#[derive(Default)]
struct WatchState {
    last_read: Option<Instant>,
    in_flight: bool,
}

impl SendWatch {
    /// A watch that takes its control token from `read_token` rather than the on-disk install.
    #[cfg(test)]
    fn with_token_reader(
        refresh: Duration,
        cursor_path: Option<std::path::PathBuf>,
        read_token: fn() -> Option<String>,
    ) -> Self {
        Self {
            read_token,
            ..Self::new(refresh, Duration::from_secs(5), cursor_path, None)
        }
    }

    /// A watch reading at most every `refresh`, allowing `timeout` per read, persisting to
    /// `cursor_path` and honouring the preference in `config_path`.
    pub fn new(
        refresh: Duration,
        timeout: Duration,
        cursor_path: Option<std::path::PathBuf>,
        config_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchState::default())),
            refresh,
            timeout,
            cursor_path,
            config_path,
            read_token: control::load_control_token,
        }
    }

    /// The watch for this host, resolving its cursor beside `agent.json`.
    pub fn for_host() -> Self {
        let config_path = crate::environment::AppEnvironment::from_host()
            .config_path()
            .ok();
        let cursor_path = config_path
            .as_ref()
            .and_then(|config| config.parent().map(super::store::path_in));
        Self::new(WATCH_INTERVAL, WATCH_READ_TIMEOUT, cursor_path, config_path)
    }

    /// Notice, at most every `refresh`, whether the node has recorded money LEAVING — and toast if
    /// it has and the user wants to know. **Never blocks.**
    pub fn observe(&self, link: &EngineState) {
        let Some(cursor_path) = self.cursor_path.clone() else {
            return;
        };
        let EngineState::Connected { endpoint, .. } = link else {
            return;
        };

        let mut state = self.lock();
        if let Some(last) = state.last_read {
            if last.elapsed() < self.refresh {
                return;
            }
        }
        if state.in_flight {
            return;
        }
        state.in_flight = true;
        drop(state);

        let source =
            ControlPlaneSendSource::new(endpoint.clone(), (self.read_token)(), self.timeout);
        let shared = Arc::clone(&self.state);
        let config_path = self.config_path.clone();
        std::thread::spawn(move || {
            sweep(
                &source,
                &cursor_path,
                notifications_wanted(config_path.as_deref()),
                notify::native_notifier().as_ref(),
            );
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.last_read = Some(Instant::now());
            state.in_flight = false;
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Whether the user wants to be told about outgoing payments, as `agent.json` says right now.
///
/// Its OWN preference, not the arrival one: an arrival is news a person could not otherwise have,
/// while a send is usually confirmation of something they just did — and on a machine that publishes
/// or runs a dapp it is the noisier of the two. An unreadable config yields the DEFAULT (on), for the
/// reason the arrival watch gives: a read error is not evidence that anybody chose silence.
fn notifications_wanted(config_path: Option<&std::path::Path>) -> bool {
    let Some(path) = config_path else {
        return crate::notifications::Notifications::default().funds_sent;
    };
    match crate::config::AgentConfig::load(path) {
        Ok(config) => config.notifications.funds_sent,
        Err(e) => {
            tracing::debug!(error = %e, "the send-notification preference could not be read; using the default");
            crate::notifications::Notifications::default().funds_sent
        }
    }
}

/// One drain → account → announce cycle, with no threading and no clock.
///
/// The two orderings [`crate::arrivals::watch::sweep`] documents apply unchanged and for the same
/// reasons: the cursor is saved BEFORE anything is drawn, and a failed save abandons the whole sweep
/// rather than announcing payments whose position did not persist.
pub fn sweep(
    source: &dyn SendSource,
    cursor_path: &std::path::Path,
    notifications_enabled: bool,
    notifier: &dyn NativeNotifier,
) {
    let mut cursor = super::store::load(cursor_path);
    let mut announceable: Vec<SentPayment> = Vec::new();

    for _ in 0..MAX_PAGES_PER_SWEEP {
        let page = match source.sends_since(cursor.position().unwrap_or(0)) {
            Ok(page) => page,
            // A node that is briefly unreachable — or too old to know the method — is the ordinary
            // case, and the honest response is to say nothing about money.
            Err(e) => {
                tracing::debug!(reason = %e, "the node's send ledger could not be read");
                break;
            }
        };
        let empty = page.sends.is_empty();
        announceable.extend(cursor.advance_rows(&page.sends, page.cursor, page.latest));
        if empty {
            break;
        }
    }

    if let Err(e) = super::store::save(cursor_path, &cursor) {
        tracing::warn!(error = %e, "the send cursor could not be saved; nothing announced");
        return;
    }
    notify::announce_sends(&announceable, notifications_enabled, notifier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Notification;
    use std::sync::Mutex as StdMutex;

    /// A notifier that records what it was asked to show.
    #[derive(Default)]
    struct Recorder(StdMutex<Vec<Notification>>);
    impl NativeNotifier for Recorder {
        fn show(&self, notification: &Notification) {
            self.0.lock().unwrap().push(notification.clone());
        }
    }
    impl Recorder {
        fn shown(&self) -> Vec<Notification> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A source that serves scripted pages, one per call, then empties.
    struct Scripted {
        pages: StdMutex<std::collections::VecDeque<SendPage>>,
    }
    impl Scripted {
        fn of(pages: Vec<SendPage>) -> Self {
            Self {
                pages: StdMutex::new(pages.into()),
            }
        }
    }
    impl SendSource for Scripted {
        fn sends_since(&self, after_seq: u64) -> Result<SendPage, ArrivalSourceError> {
            Ok(self.pages.lock().unwrap().pop_front().unwrap_or(SendPage {
                sends: Vec::new(),
                cursor: after_seq,
                latest: after_seq,
            }))
        }
    }

    /// A source that always refuses, the way an older node refuses a method it does not know.
    struct Refusing;
    impl SendSource for Refusing {
        fn sends_since(&self, _after_seq: u64) -> Result<SendPage, ArrivalSourceError> {
            Err(ArrivalSourceError::Unavailable(
                "method not found: control.wallet.sends".into(),
            ))
        }
    }

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

    /// **TRAP 1 — the toast says what LEFT, because that is the only figure the row carries.**
    ///
    /// The node scored a 9 XCH coin spent to pay ~1 XCH. The fixture asserts the toast names the 1
    /// and, by name, that the 9 is nowhere in it — a client that had reached for a coin amount could
    /// not satisfy both.
    #[test]
    fn the_toast_announces_the_net_outflow_and_never_a_spent_coin_amount() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        // Adopt first, so the machine has a position and the next page is news.
        sweep(&Scripted::of(vec![]), &path, true, &notifier);
        sweep(
            &Scripted::of(vec![page(vec![sent(1, 1_000_005_000_000)], 0, 1)]),
            &path,
            true,
            &notifier,
        );

        let shown = notifier.shown();
        assert_eq!(shown.len(), 1, "one send is one toast");
        assert_eq!(shown[0].title, "DIG — Funds sent");
        assert!(
            shown[0].body.contains("1.000005"),
            "the toast must state what left: {}",
            shown[0].body
        );
        assert!(
            !shown[0].body.contains('9'),
            "the spent coin's amount must appear nowhere: {}",
            shown[0].body
        );
    }

    /// **TRAP 4 — a machine meeting a node with a send history announces nothing on first run.**
    #[test]
    fn a_first_sweep_against_a_full_ledger_announces_nothing() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(
            &Scripted::of(vec![page(
                vec![sent(1, 100), sent(2, 200), sent(3, 300)],
                0,
                9,
            )]),
            &path,
            true,
            &notifier,
        );
        assert!(
            notifier.shown().is_empty(),
            "history was toasted on install"
        );
        assert_eq!(super::super::store::load(&path).position(), Some(9));
    }

    /// **A restart does not re-announce**, because the cursor is on disk before the toast is drawn.
    #[test]
    fn a_second_sweep_over_the_same_page_says_nothing_again() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Scripted::of(vec![]), &path, true, &notifier);
        sweep(
            &Scripted::of(vec![page(vec![sent(5, 42)], 0, 5)]),
            &path,
            true,
            &notifier,
        );
        assert_eq!(notifier.shown().len(), 1);

        sweep(
            &Scripted::of(vec![page(vec![sent(5, 42)], 0, 5)]),
            &path,
            true,
            &notifier,
        );
        assert_eq!(notifier.shown().len(), 1, "a restart re-announced send 5");
    }

    /// **Turning the switch off silences the toast but NOT the accounting.**
    ///
    /// The cursor must keep advancing while notifications are off, or turning them back on floods.
    /// The second sweep, with the switch back on, is what proves the row was accounted for rather
    /// than merely swallowed.
    #[test]
    fn the_off_switch_silences_the_toast_without_replaying_it_later() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Scripted::of(vec![]), &path, false, &notifier);
        sweep(
            &Scripted::of(vec![page(vec![sent(5, 42)], 0, 5)]),
            &path,
            false,
            &notifier,
        );
        assert!(notifier.shown().is_empty());

        sweep(
            &Scripted::of(vec![page(vec![sent(5, 42)], 0, 5)]),
            &path,
            true,
            &notifier,
        );
        assert!(
            notifier.shown().is_empty(),
            "a send accounted for while the switch was off came back when it was turned on"
        );
    }

    /// **An older node that does not know the method costs nothing.** Nothing is announced, and the
    /// cursor stays unread so the first page a NEW node serves is still adopted rather than replayed.
    #[test]
    fn a_node_that_refuses_the_method_announces_nothing_and_leaves_the_cursor_unread() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Refusing, &path, true, &notifier);
        assert!(notifier.shown().is_empty());
        assert_eq!(
            super::super::store::load(&path).position(),
            None,
            "a refused read must not adopt a position the node never gave"
        );
    }

    /// **A whole burst is ONE toast.** Three sends drained in one sweep coalesce, because the sweep
    /// is the window.
    #[test]
    fn several_sends_in_one_sweep_are_one_toast() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Scripted::of(vec![]), &path, true, &notifier);
        sweep(
            &Scripted::of(vec![page(
                vec![sent(1, 10), sent(2, 20), sent(3, 30)],
                0,
                3,
            )]),
            &path,
            true,
            &notifier,
        );
        let shown = notifier.shown();
        assert_eq!(shown.len(), 1);
        assert!(shown[0].body.contains('3'), "{}", shown[0].body);
    }

    /// **A watch with nowhere to persist its cursor does nothing at all**, rather than announcing
    /// from a position it cannot keep.
    #[test]
    fn a_watch_without_a_cursor_path_never_reads() {
        let watch = SendWatch::with_token_reader(Duration::from_millis(0), None, || {
            panic!("a watch with no cursor path must not read a token")
        });
        watch.observe(&EngineState::Connected {
            endpoint: "http://127.0.0.1:1".into(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        });
    }

    /// **An unreadable figure is refused, never defaulted.** A row the client cannot read honestly
    /// is a contract disagreement, and a zero standing in for it would understate a payment to nil.
    #[test]
    fn an_unreadable_net_outflow_is_refused_rather_than_read_as_zero() {
        let record = WalletSendRecord {
            seq: 1,
            net_outflow: "not-a-number".into(),
            asset_id: None,
            confirmed_height: 10,
        };
        assert!(matches!(
            sent_from(&record),
            Err(ArrivalSourceError::Malformed(_))
        ));

        // The control: the same row with a readable figure is accepted, so "refuses" is not
        // satisfied by refusing everything.
        let good = WalletSendRecord {
            net_outflow: "18446744073709551615".into(),
            ..record
        };
        assert_eq!(sent_from(&good).expect("readable").net_outflow, u64::MAX);
    }
}
