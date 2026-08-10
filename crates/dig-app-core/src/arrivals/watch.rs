//! Reading dig-node's arrival ledger from the tray process.
//!
//! Two pieces, mirroring [`crate::wallet::node`]:
//!
//! - [`ControlPlaneSource`] — the [`ArrivalSource`] over `control.wallet.arrivals`, a TOKEN-GATED
//!   read of the node's own local ledger.
//! - [`ArrivalWatch`] — the throttle that owns *when* that read happens, so the tray's
//!   twice-a-second repaint does not become twice-a-second node calls, and so the read never runs
//!   on the caller's thread.
//!
//! # Why this is a poll and not a subscription
//!
//! The control plane is strictly request→response; it has no server-initiated frame. dig-node does
//! push a `coin_state` doorbell over `/ws`, but that frame carries no coin id, amount, asset or
//! height — notifying from it would be announcing something whose amount we do not know. The node's
//! cursor is monotonic and persisted, so polling it loses nothing: whatever was recorded between two
//! polls is still there at the next one.
//!
//! # The custody boundary (§908)
//!
//! Everything here is a READ of the node's own replica. No key, seed, address or signature is
//! involved, nothing on this path can spend, and there is no oracle leg — polling it discloses
//! nothing off-machine.
//!
//! It is nonetheless the one wallet READ that needs the control token, and the reason is worth
//! keeping in view: the other reads answer about an address the CALLER named, while this one takes
//! a cursor and answers with the node's own watched puzzle hashes and the receive history behind
//! them. The chain facts are public; the association between this machine and those addresses is
//! not. So a tray that cannot read the control token gets no arrival toasts, and that is the
//! correct trade — the alternative is any local process enumerating the user's addresses.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_events_protocol::AssetId;
use dig_node_control_interface::params::WalletArrivalsParams;
use dig_node_control_interface::results::{WalletArrivalRecord, WalletArrivalsResult};

use crate::control::{self, ControlFailure};
use crate::engine::EngineState;
use crate::notify::{self, NativeNotifier};

use super::{Arrival, ArrivalPage, ArrivalSource, ArrivalSourceError};

/// How long between arrival reads.
///
/// Matched to [`crate::wallet::node::REFRESH_INTERVAL`] on purpose: the balance figure and the
/// "you were paid" toast describe the same event, and a slower notification than the number it
/// explains reads as the app noticing twice.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// How long ONE arrival read may take before it is abandoned.
///
/// Shorter than the balance budget because this read cannot go to chain: it is a bounded query
/// against a local SQLite ledger, so a node taking seconds over it is a node in trouble, not a node
/// waiting on a public HTTPS source.
pub const WATCH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How many pages one sweep will drain before leaving the rest for the next.
///
/// A bound rather than a tuned number: the node clamps its own page size, so this only decides how
/// long a single sweep may hold its worker thread when a machine reconnects to a node that recorded
/// a great deal while it was away. What is left over is not lost — the cursor advanced over exactly
/// what was read, so the next sweep continues from there.
const MAX_PAGES_PER_SWEEP: usize = 20;

/// Reads dig-node's arrival ledger over the loopback control plane.
pub struct ControlPlaneSource {
    endpoint: String,
    token: Option<String>,
    timeout: Duration,
}

impl ControlPlaneSource {
    /// A source reading the ledger of the node at `endpoint`, presenting `token` when there is one.
    ///
    /// `token` is an `Option` because the tray cannot always read one — an install whose token
    /// file is unreadable has none to present. The read is TOKEN-GATED, so a `None` here means the
    /// node will refuse and the watch stays quiet; it does NOT mean the read is open.
    pub fn new(endpoint: impl Into<String>, token: Option<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            token,
            timeout,
        }
    }
}

impl ArrivalSource for ControlPlaneSource {
    fn arrivals_since(&self, after_seq: u64) -> Result<ArrivalPage, ArrivalSourceError> {
        let params = WalletArrivalsParams {
            after_seq,
            limit: None,
        };
        let answer: WalletArrivalsResult = control::call_control_result(
            &self.endpoint,
            &params,
            self.token.as_deref(),
            self.timeout,
        )
        .map_err(|failure: ControlFailure| ArrivalSourceError::Unavailable(failure.to_string()))?;

        let arrivals = answer
            .arrivals
            .iter()
            .map(arrival_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ArrivalPage {
            arrivals,
            cursor: answer.cursor,
            latest: answer.latest,
        })
    }
}

/// One of the node's ledger rows as an [`Arrival`].
///
/// The only thing that can fail is the amount. The contract carries it as a DECIMAL STRING because
/// the ledger holds the full `u64` range and a JSON number would round it, so a client has to parse
/// it — and a value it cannot parse is refused rather than defaulted. A zero or a saturated maximum
/// standing in for an unreadable figure is a wrong claim about how much money arrived, which is
/// exactly what this feature must never make.
fn arrival_from(record: &WalletArrivalRecord) -> Result<Arrival, ArrivalSourceError> {
    let amount = record.amount.parse::<u64>().map_err(|e| {
        ArrivalSourceError::Malformed(format!(
            "arrival {} carries an unreadable amount: {e}",
            record.seq
        ))
    })?;
    Ok(Arrival {
        seq: record.seq,
        coin_id: record.coin_id.clone(),
        asset_id: record.asset_id.clone().map(AssetId),
        amount,
        confirmed_height: record.confirmed_height,
    })
}

/// The arrival watch: reads no more often than [`WATCH_INTERVAL`], never on the caller's thread, and
/// draws at most one toast per sweep.
///
/// Lives beside the tray's status handle and is poked on every repaint, exactly like
/// [`crate::wallet::node::NodeBalance`] — and for the same reason: a node call takes time and a
/// repaint happens twice a second.
pub struct ArrivalWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    timeout: Duration,
    /// Where the durable cursor lives. `None` on a host whose brand directory cannot be resolved,
    /// which disables the watch entirely — a cursor that cannot be persisted cannot promise that a
    /// restart will not re-announce, and an un-keepable promise is worse than a missing toast.
    cursor_path: Option<std::path::PathBuf>,
    /// Where the user's preference lives. Read on the worker thread at read time, not per repaint,
    /// and not cached: turning notifications off in Settings takes effect on the next read rather
    /// than at the next restart, and this file is touched six times a minute at most.
    config_path: Option<std::path::PathBuf>,
    /// Reads the node's control token. Injected so a test presents its own fake node's token.
    read_token: fn() -> Option<String>,
}

/// What the watch knows between reads.
#[derive(Default)]
struct WatchState {
    /// When the last read finished.
    last_read: Option<Instant>,
    /// Whether a worker is currently reading — the de-duplication that keeps a repaint during a
    /// read from starting a second one.
    in_flight: bool,
}

impl ArrivalWatch {
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

    /// Notice, at most every `refresh`, whether the node has recorded money arriving — and toast if
    /// it has and the user wants to know. **Never blocks.**
    ///
    /// Takes no address: the node's ledger already covers every address the wallet watches, which is
    /// strictly more than the one address the tray happens to be displaying.
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

        let source = ControlPlaneSource::new(endpoint.clone(), (self.read_token)(), self.timeout);
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

/// Whether the user wants to be told, as `agent.json` says right now.
///
/// A config that cannot be read yields the DEFAULT (on) rather than silence: the setting is a
/// deliberate choice, and an unreadable file is not evidence that anybody made it. The alternative —
/// failing closed here — would turn a transient read error into a feature that quietly stopped
/// working, with nothing anywhere saying why.
fn notifications_wanted(config_path: Option<&std::path::Path>) -> bool {
    let Some(path) = config_path else {
        return crate::notifications::Notifications::default().funds_received;
    };
    match crate::config::AgentConfig::load(path) {
        Ok(config) => config.notifications.funds_received,
        Err(e) => {
            tracing::debug!(error = %e, "the notification preference could not be read; using the default");
            crate::notifications::Notifications::default().funds_received
        }
    }
}

/// One drain → account → announce cycle, with no threading and no clock.
///
/// Split out so the whole behaviour is testable against a scripted source and a recording notifier.
/// The cursor is loaded, pages are drained until the node has nothing more (or the per-sweep page cap
/// is reached), the cursor is written back, and only then is anything shown.
///
/// # Two orderings that are deliberate
///
/// **The cursor is saved BEFORE the toast is drawn.** A crash between the two costs a toast; the
/// other order costs a duplicate announcement on the next run, and a duplicate claim about money is
/// worse than a missing one.
///
/// **A failed save abandons the whole sweep.** Announcing arrivals whose cursor did not persist
/// means announcing them again next time, so nothing is said at all.
pub fn sweep(
    source: &dyn ArrivalSource,
    cursor_path: &std::path::Path,
    notifications_enabled: bool,
    notifier: &dyn NativeNotifier,
) {
    let mut cursor = super::store::load(cursor_path);
    let mut announceable: Vec<Arrival> = Vec::new();

    for _ in 0..MAX_PAGES_PER_SWEEP {
        let page = match source.arrivals_since(cursor.position().unwrap_or(0)) {
            Ok(page) => page,
            // Not an error a surface reports: a node that is briefly unreachable is the ordinary
            // case, and the honest response is to say nothing about money. Whatever was already
            // drained stays in hand — its cursor is saved below, so it is neither lost nor repeated.
            Err(e) => {
                tracing::debug!(reason = %e, "the node's arrival ledger could not be read");
                break;
            }
        };
        let empty = page.arrivals.is_empty();
        announceable.extend(cursor.advance(&page));
        if empty {
            break;
        }
    }

    if let Err(e) = super::store::save(cursor_path, &cursor) {
        tracing::warn!(error = %e, "the arrival cursor could not be saved; nothing announced");
        return;
    }
    notify::announce_arrivals(&announceable, notifications_enabled, notifier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Notification;
    use crate::test_support::node::{ArrivalsReply, FakeArrivalPage, FakeNode};
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

    /// A source that answers from a scripted ledger, honouring `after_seq` the way the node does.
    ///
    /// Deliberately NOT a list of canned pages: the property under test is what the client ASKS
    /// for next, and a source that ignored `after_seq` would answer identically to a correct node
    /// however wrongly the client resumed.
    struct Ledger {
        rows: Vec<Arrival>,
        page_size: usize,
        asked: StdMutex<Vec<u64>>,
    }

    impl Ledger {
        fn of(seqs: &[u64], page_size: usize) -> Self {
            Self {
                rows: seqs
                    .iter()
                    .map(|seq| Arrival {
                        seq: *seq,
                        coin_id: format!("{seq:064x}"),
                        asset_id: None,
                        amount: 1_000_000_000_000,
                        confirmed_height: 5_412_000 + *seq as u32,
                    })
                    .collect(),
                page_size,
                asked: StdMutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<u64> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl ArrivalSource for Ledger {
        fn arrivals_since(&self, after_seq: u64) -> Result<ArrivalPage, ArrivalSourceError> {
            self.asked.lock().unwrap().push(after_seq);
            let arrivals: Vec<Arrival> = self
                .rows
                .iter()
                .filter(|a| a.seq > after_seq)
                .take(self.page_size)
                .cloned()
                .collect();
            Ok(ArrivalPage {
                cursor: arrivals.last().map_or(after_seq, |a| a.seq),
                latest: self.rows.last().map_or(0, |a| a.seq),
                arrivals,
            })
        }
    }

    /// A source that always refuses.
    struct Unreachable;
    impl ArrivalSource for Unreachable {
        fn arrivals_since(&self, _after_seq: u64) -> Result<ArrivalPage, ArrivalSourceError> {
            Err(ArrivalSourceError::Unavailable("no node".into()))
        }
    }

    // ----------------------------------------------------------------------------------------
    // THE DEFECT THIS ARCHITECTURE REMOVES (dig_ecosystem#2548)
    // ----------------------------------------------------------------------------------------

    /// **dig-app has no change predicate of its own, so a change coin whose parent it never saw
    /// cannot be announced.**
    ///
    /// The defect: the app used to decide "is this the user's own change?" from
    /// `control.wallet.coins`, which lists UNSPENT coins only. A parent is spent the instant it
    /// produces change, so the only way the app could recognise one was to have watched it go by
    /// while running. Close the app, send money from any client, reopen — and the change coin came
    /// back with a parent nobody here had ever recorded. A verifier drove the real ledger through
    /// that sequence and got `Received 8.999 XCH` for a transaction in which the user SENT money.
    ///
    /// The fixture is that sequence with the app's memory made deliberately empty, which is the
    /// state a fresh process is in and the state the old implementation could not survive: the node
    /// reports one arrival (the stranger's payment) and does NOT report the change coin, because the
    /// node answered the question from a table that holds spent coins. The app announces exactly
    /// what it was given. There is no code path here that could announce anything else, which is
    /// the point — a test cannot catch a predicate that no longer exists, so what it pins is that
    /// the client is a pass-through and never inflates the node's answer.
    #[test]
    fn a_change_coin_the_node_did_not_report_is_never_announced() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        // A fresh process: no cursor, no memory of any coin. It adopts the node's head in silence.
        let before = Ledger::of(&[1], 50);
        sweep(&before, &path, true, &notifier);
        assert!(notifier.shown().is_empty(), "the adoption announced");

        // The user now SENDS 1 XCH out of a 9 XCH coin from another client, and a stranger pays
        // them 0.5 XCH. The node records ONE arrival: the stranger's. The 8.999 XCH of change is
        // absent, because the node recognised the spent parent as its own.
        let after = Ledger {
            rows: vec![
                Arrival {
                    seq: 1,
                    coin_id: "01".repeat(32),
                    asset_id: None,
                    amount: 9_000_000_000_000,
                    confirmed_height: 5_412_001,
                },
                Arrival {
                    seq: 2,
                    coin_id: "02".repeat(32),
                    asset_id: None,
                    amount: 500_000_000_000,
                    confirmed_height: 5_412_100,
                },
            ],
            page_size: 50,
            asked: StdMutex::new(Vec::new()),
        };
        sweep(&after, &path, true, &notifier);

        let shown = notifier.shown();
        assert_eq!(shown.len(), 1, "expected one toast, got {shown:?}");
        assert_eq!(
            shown[0].body, "Received 0.5 XCH",
            "the user's own change was reported as money received"
        );
    }

    // ----------------------------------------------------------------------------------------
    // The sweep
    // ----------------------------------------------------------------------------------------

    /// **The first sweep adopts the node's ledger in silence; the next payment is announced once.**
    ///
    /// The fixture is a node that has been running long before dig-app was installed — three
    /// recorded arrivals — so a client that announced what it was handed would toast three times on
    /// first launch.
    #[test]
    fn the_first_sweep_adopts_then_the_next_payment_is_announced_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Ledger::of(&[1, 2, 3], 50), &path, true, &notifier);
        assert!(
            notifier.shown().is_empty(),
            "the first sweep announced history: {:?}",
            notifier.shown()
        );

        let paid = Ledger::of(&[1, 2, 3, 4], 50);
        sweep(&paid, &path, true, &notifier);
        assert_eq!(notifier.shown().len(), 1, "the payment was not announced");
        assert_eq!(
            paid.asked(),
            vec![3, 4],
            "the client must resume from its cursor, then confirm the ledger is drained"
        );

        // A repeat poll against an unchanged ledger.
        sweep(&Ledger::of(&[1, 2, 3, 4], 50), &path, true, &notifier);
        assert_eq!(
            notifier.shown().len(),
            1,
            "a repeat poll re-announced the same payment"
        );
    }

    /// **A backlog spanning several pages is drained, and every arrival in it is announced once.**
    ///
    /// The page size is deliberately smaller than the backlog, because a single-page fixture cannot
    /// tell a client that drains from one that reads one page and forgets the rest — both would
    /// look correct. Each page must ALSO be asked for from the previous page's last row, which is
    /// what `asked` pins: a client resuming from `latest` would ask `[0, 9, 9, …]` and skip rows.
    #[test]
    fn a_backlog_larger_than_one_page_is_drained_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Ledger::of(&[1], 2), &path, true, &notifier);

        let backlog = Ledger::of(&[1, 2, 3, 4, 5, 6, 7], 2);
        sweep(&backlog, &path, true, &notifier);
        assert_eq!(
            backlog.asked(),
            vec![1, 3, 5, 7],
            "the pages were not walked from the last row of the previous one"
        );
        let shown = notifier.shown();
        assert_eq!(shown.len(), 1, "one sweep is one toast");
        assert!(
            shown[0].body.contains("6 payments"),
            "the backlog was not fully drained: {}",
            shown[0].body
        );
    }

    /// **With notifications off nothing is drawn, and the cursor still advances.**
    ///
    /// The second half is the one a naive off-switch gets wrong: gating the READ rather than the
    /// toast means turning notifications back on announces everything received in between. The
    /// control at the end proves the switch, and not the fixture, is what kept it quiet.
    #[test]
    fn turning_notifications_off_silences_the_toast_without_stalling_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Ledger::of(&[1], 50), &path, true, &notifier); // adopt
        sweep(&Ledger::of(&[1, 2], 50), &path, false, &notifier); // arrives while off
        assert!(
            notifier.shown().is_empty(),
            "a toast was drawn with the switch off"
        );

        sweep(&Ledger::of(&[1, 2, 3], 50), &path, true, &notifier);
        let shown = notifier.shown();
        assert_eq!(
            shown.len(),
            1,
            "turning notifications back on replayed what happened while they were off"
        );
        assert!(
            !shown[0].body.contains("2 payments"),
            "the arrival from the silent window was replayed: {}",
            shown[0].body
        );
    }

    /// **A node that cannot answer changes nothing** — no toast, and no adopted cursor that would
    /// swallow the next real arrival.
    #[test]
    fn a_node_that_cannot_answer_leaves_no_trace() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        sweep(&Unreachable, &path, true, &notifier);
        assert!(notifier.shown().is_empty());
        assert_eq!(
            super::super::store::load(&path).position(),
            None,
            "an unanswerable read adopted a position nobody measured"
        );
    }

    /// **The preference is read from the file, both ways, and an absent file means ON.**
    #[test]
    fn the_preference_comes_from_the_config_file() {
        use crate::config::AgentConfig;
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());

        assert!(
            notifications_wanted(Some(&path)),
            "an install with no config yet must still notify"
        );
        assert!(notifications_wanted(None));

        AgentConfig {
            notifications: crate::notifications::Notifications {
                funds_received: false,
                funds_sent: false,
            },
            ..AgentConfig::default()
        }
        .save(&path)
        .unwrap();
        assert!(
            !notifications_wanted(Some(&path)),
            "the stored choice to turn notifications off was ignored"
        );
    }

    // ----------------------------------------------------------------------------------------
    // The source, over a real socket
    // ----------------------------------------------------------------------------------------

    fn source_for(node: &FakeNode) -> ControlPlaneSource {
        ControlPlaneSource::new(
            node.endpoint(),
            Some(FakeNode::TOKEN.to_string()),
            Duration::from_secs(5),
        )
    }

    /// **A ledger row survives the real wire with its position, amount and asset intact.**
    ///
    /// Over a loopback socket in the node's own envelope. The amount is beyond `f64`'s exact-integer
    /// range on purpose: it is carried as a decimal string precisely because a JSON number would
    /// round it, and a client that parsed it as a float would report a different figure than the one
    /// that arrived.
    #[test]
    fn an_arrival_crosses_the_wire_with_its_full_amount_and_asset() {
        let node = FakeNode::serving_arrivals(ArrivalsReply::Pages(vec![FakeArrivalPage {
            rows: vec![(7, u64::MAX, None), (8, 2_500, Some("a406d3".to_string()))],
            latest: 9,
        }]));
        let page = source_for(&node).arrivals_since(6).expect("a page");

        assert_eq!(page.cursor, 8, "the cursor is the last row served");
        assert_eq!(page.latest, 9, "the ledger head must not be the cursor");
        assert_eq!(page.arrivals[0].amount, u64::MAX);
        assert_eq!(page.arrivals[0].asset_id, None);
        assert_eq!(
            page.arrivals[1].asset_id,
            Some(AssetId("a406d3".to_string()))
        );
        assert_eq!(page.arrivals[1].confirmed_height, 5_412_008);
    }

    /// **The client asks for exactly the position it holds, on the wire.**
    ///
    /// Read from the request the fake actually received, so a client that sent a hard-coded `0` —
    /// which would replay the ledger on every poll — fails here rather than being rescued by a
    /// tolerant fixture.
    #[test]
    fn the_requested_cursor_position_travels_in_the_request() {
        let node = FakeNode::serving_arrivals(ArrivalsReply::Pages(vec![FakeArrivalPage::of(&[])]));
        let _ = source_for(&node).arrivals_since(41);
        assert!(
            node.received().contains("\"after_seq\":41"),
            "the cursor did not reach the wire: {}",
            node.received()
        );
    }

    /// **An UNAUTHENTICATED arrivals read is refused, and the same read WITH the token succeeds.**
    ///
    /// The cursor is token-gated (dig_ecosystem#2548): it names the node's own watched puzzle
    /// hashes to a caller that supplied nothing but a position. This is the behavioural half of
    /// that gate — the contract-level membership test in `dig-node-control-interface` pins the
    /// constant, and this pins what a caller actually experiences.
    ///
    /// The fixture varies exactly ONE thing, the token, against ONE fake node, and the tokened leg
    /// is the control. Without it the refusal could equally be a fake that serves nothing, a
    /// mis-typed method name, or a client that never dialled — every one of which produces the same
    /// `Unavailable`. The token is also asserted to have reached the WIRE, because a client that
    /// held a token and failed to send it would still pass a test that only read its own return
    /// value.
    #[test]
    fn an_untokened_arrivals_read_is_refused_and_the_tokened_one_is_served() {
        let node = FakeNode::serving_arrivals(ArrivalsReply::Pages(vec![FakeArrivalPage {
            rows: vec![(7, 2_500, None)],
            latest: 7,
        }]));

        let untokened = ControlPlaneSource::new(node.endpoint(), None, Duration::from_secs(5))
            .arrivals_since(6);
        assert!(
            matches!(untokened, Err(ArrivalSourceError::Unavailable(_))),
            "an untokened arrivals read must be refused, got {untokened:?}"
        );

        let page = source_for(&node)
            .arrivals_since(6)
            .expect("the tokened read must be served");
        assert_eq!(page.cursor, 7, "the tokened read reached the ledger");

        // The fake hands back the requests in the order it received them, so the first is the
        // untokened attempt and the second is the tokened one. Reading BOTH is what proves the
        // token is the only difference between them.
        let (first, second) = (node.received(), node.received());
        assert!(
            !first
                .to_lowercase()
                .contains(&FakeNode::TOKEN.to_lowercase()),
            "the untokened leg must not have sent a token: {first}"
        );
        assert!(
            second
                .to_lowercase()
                .contains(&FakeNode::TOKEN.to_lowercase()),
            "the control token never reached the wire: {second}"
        );
    }

    /// **A refused read is an error, never an empty page** — an empty page would adopt a position
    /// nobody measured and silently swallow the next real arrival.
    #[test]
    fn a_refused_read_is_an_error_not_an_empty_page() {
        let node =
            FakeNode::serving_arrivals(ArrivalsReply::rejected(-32004, "WALLET_READ_FAILED"));
        assert!(matches!(
            source_for(&node).arrivals_since(0),
            Err(ArrivalSourceError::Unavailable(_))
        ));
    }

    /// **An amount this client cannot read is refused, not defaulted.**
    ///
    /// A `0` or a saturated maximum standing in for an unparseable figure would be a wrong claim
    /// about how much money arrived — the one thing this feature must never make.
    #[test]
    fn an_unreadable_amount_is_refused_rather_than_defaulted() {
        let broken = WalletArrivalRecord {
            seq: 3,
            coin_id: "ab".repeat(32),
            puzzle_hash: "cc".repeat(32),
            amount: "not-a-number".into(),
            asset_id: None,
            confirmed_height: 5_412_000,
        };
        assert!(matches!(
            arrival_from(&broken),
            Err(ArrivalSourceError::Malformed(_))
        ));

        // The control: the same record with a readable amount crosses fine, so the assertion above
        // is about the amount and not about the mapper refusing everything.
        let good = WalletArrivalRecord {
            amount: "42".into(),
            ..broken
        };
        assert_eq!(arrival_from(&good).expect("readable").amount, 42);
    }

    // ----------------------------------------------------------------------------------------
    // The throttle
    // ----------------------------------------------------------------------------------------

    fn connected_to(node: &FakeNode) -> EngineState {
        EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    fn no_token() -> Option<String> {
        None
    }

    /// Wait for the watch's worker to finish, or give up. Returns whether it finished.
    fn settled(path: &std::path::Path) -> bool {
        for _ in 0..100 {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// **A repaint does not become a node call**: the cadence is the watch's, not the caller's.
    ///
    /// Counted at the SERVER, so this is what actually went out on the wire rather than the client's
    /// account of it.
    #[test]
    fn a_second_observe_inside_the_interval_does_not_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let cursor = super::super::store::path_in(dir.path());
        let node = FakeNode::serving_arrivals(ArrivalsReply::Pages(vec![FakeArrivalPage::of(&[])]));
        let link = connected_to(&node);
        let watch = ArrivalWatch::with_token_reader(
            Duration::from_secs(600),
            Some(cursor.clone()),
            no_token,
        );

        watch.observe(&link);
        assert!(settled(&cursor), "the first sweep never finished");
        let after_first = node.request_count();
        assert_eq!(after_first, 1, "an empty ledger is one call");

        for _ in 0..5 {
            watch.observe(&link);
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            node.request_count(),
            after_first,
            "repaints inside the interval turned into node calls"
        );
    }

    /// **Nothing is read without a node.** A stopped node has no endpoint, and asking anyway would
    /// be a call against something that is not there.
    #[test]
    fn a_watch_with_no_node_reads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cursor = super::super::store::path_in(dir.path());
        let watch = ArrivalWatch::with_token_reader(
            Duration::from_millis(1),
            Some(cursor.clone()),
            no_token,
        );

        watch.observe(&EngineState::Disconnected {
            reason: "no node".to_string(),
        });
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !cursor.exists(),
            "a cursor was written without any node call"
        );
    }

    /// **A watch with nowhere to persist reads nothing at all.**
    ///
    /// A cursor that cannot be written cannot promise a restart will not re-announce, and an
    /// un-keepable promise about somebody's money is worse than a missing toast.
    #[test]
    fn a_watch_that_cannot_persist_does_not_read() {
        let node = FakeNode::serving_arrivals(ArrivalsReply::Pages(vec![FakeArrivalPage::of(&[])]));
        let watch = ArrivalWatch::with_token_reader(Duration::from_millis(1), None, no_token);
        watch.observe(&connected_to(&node));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(node.request_count(), 0);
    }
}
