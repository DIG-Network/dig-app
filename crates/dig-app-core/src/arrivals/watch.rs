//! Driving [`super::ArrivalLedger`] off the node the app is already talking to.
//!
//! Two pieces, mirroring [`crate::wallet::node`]:
//!
//! - [`ControlPlaneSource`] — the [`ArrivalSource`] over `control.wallet.coins`, an OPEN read of a
//!   PUBLIC address. It asks for every asset the wallet holds and refuses to build a
//!   [`ChainView`] out of an answer that did not prove it was caught up.
//! - [`ArrivalWatch`] — the throttle that owns *when* that read happens, so the tray's
//!   twice-a-second repaint does not become twice-a-second chain reads, and so the seconds-long read
//!   never runs on the caller's thread.
//!
//! # The custody boundary (§908)
//!
//! Everything here is a chain read of a bech32m address the node already serves without a token. No
//! key, seed or signature is involved, and nothing on this path can spend.
//!
//! # Why the node's push stream is not used yet
//!
//! dig-node already pushes a `coin_state` frame over its `/ws` surface when it applies a coin-state
//! update, but that frame carries no coin id, amount, asset or height — it is a doorbell, not a
//! claim about money. Notifying from it directly would be announcing something whose amount we do
//! not know. When dig-node grows a real confirmed funds event, it implements [`ArrivalSource`] (or
//! feeds one) and nothing above this module changes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_node_control_interface::params::{Asset as WireAsset, WalletCoinsParams};
use dig_node_control_interface::results::{WalletCoinRecord, WalletCoinsResult};

use crate::control::{self, ControlFailure};
use crate::engine::EngineState;
use crate::notify::{self, NativeNotifier};
use crate::wallet::state::Asset;

use super::{ArrivalSource, ArrivalSourceError, ChainView, ConfirmedCoin};

/// How long between confirmed-arrival reads.
///
/// Matched to [`crate::wallet::node::REFRESH_INTERVAL`] on purpose: the balance figure and the
/// "you were paid" toast describe the same event, and a slower notification than the number it
/// explains reads as the app noticing twice.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// How long ONE arrival read may take before it is abandoned.
///
/// The same budget as a balance read, for the same measured reason: the node may serve a wallet read
/// from a public HTTPS chain source, and dig_ecosystem#2325 measured that taking six seconds.
pub const WATCH_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Every asset the wallet surface knows about, which is the set an arrival can be denominated in.
const WATCHED_ASSETS: [Asset; 2] = [Asset::Xch, Asset::Dig];

/// Reads confirmed coins for one address from a running dig-node over the loopback control plane.
pub struct ControlPlaneSource {
    endpoint: String,
    token: Option<String>,
    timeout: Duration,
    address: String,
}

impl ControlPlaneSource {
    /// A source reading `address` from the node at `endpoint`, presenting `token` when there is one.
    ///
    /// `token` is optional because `control.wallet.coins` is an OPEN read: a machine whose control
    /// token this user cannot read still learns when it was paid.
    pub fn new(
        endpoint: impl Into<String>,
        token: Option<String>,
        timeout: Duration,
        address: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            token,
            timeout,
            address: address.into(),
        }
    }

    /// One `control.wallet.coins` call, for one asset.
    fn read(&self, asset: Asset) -> Result<WalletCoinsResult, ControlFailure> {
        let params = WalletCoinsParams {
            address: self.address.clone(),
            asset: match asset {
                Asset::Xch => WireAsset::Xch,
                Asset::Dig => WireAsset::Dig,
            },
        };
        control::call_control_result(&self.endpoint, &params, self.token.as_deref(), self.timeout)
    }
}

impl ArrivalSource for ControlPlaneSource {
    /// The confirmed coins at this address across every watched asset.
    ///
    /// The per-asset answers are combined at the LOWEST peak either of them reported, because the
    /// view can only honestly claim to reflect the height BOTH reads had reached. A single asset
    /// answering from a staler view would otherwise raise the whole view's baseline over coins the
    /// other read has not seen yet.
    fn view(&self) -> Result<ChainView, ArrivalSourceError> {
        let mut coins = Vec::new();
        let mut peak: Option<u32> = None;
        let mut synced = true;
        for asset in WATCHED_ASSETS {
            let answer = self
                .read(asset)
                .map_err(|failure| ArrivalSourceError::Unavailable(failure.to_string()))?;
            synced &= answer.synced;
            peak = match (peak, answer.peak_height) {
                (Some(current), Some(reported)) => Some(current.min(reported)),
                (None, reported) => reported,
                (current, None) => {
                    // A missing peak on ANY leg makes the combined view unheighted: null is
                    // unknown, never zero, and `ChainView::of_read` will refuse it.
                    let _ = current;
                    None
                }
            };
            coins.extend(
                answer
                    .coins
                    .iter()
                    .filter_map(|record| confirmed(record, asset)),
            );
        }
        ChainView::of_read(synced, peak, coins).ok_or(ArrivalSourceError::NotConfirmable)
    }
}

/// One of the node's coin records as a [`ConfirmedCoin`], or `None` when this read may not carry it.
///
/// Three refusals, and each drops a different kind of untrue claim:
///
/// - **no `created_height`** — a coin the node has only SEEN. This is the mempool guard in its
///   structural form: a sighting that later reorgs away must never have been announced as money.
/// - **a `spent_height`** — money that has already left again, which is not something to tell
///   somebody they received.
/// - **an asset other than the one asked for** — the request named ONE asset, so a record under any
///   other is not an answer to the question that was put. Taking the asset from the RECORD rather
///   than from the call is what makes that checkable at all; assuming the request's asset would
///   silently relabel whatever came back, and a $DIG figure rendered with the XCH divisor is wrong
///   by a factor of a billion.
fn confirmed(record: &WalletCoinRecord, asked: Asset) -> Option<ConfirmedCoin> {
    let asset = match record.asset {
        WireAsset::Xch => Asset::Xch,
        WireAsset::Dig => Asset::Dig,
    };
    match (asset == asked, record.created_height, record.spent_height) {
        (true, Some(confirmed_height), None) => Some(ConfirmedCoin {
            coin_id: record.coin_id.clone(),
            parent_coin_id: record.parent_coin_info.clone(),
            asset,
            amount: record.amount,
            confirmed_height,
        }),
        _ => None,
    }
}

/// The confirmed-arrival watch: reads no more often than [`WATCH_INTERVAL`], never on the caller's
/// thread, and draws at most one toast per read.
///
/// Lives beside the tray's status handle and is poked on every repaint, exactly like
/// [`crate::wallet::node::NodeBalance`] — and for the same reason: a chain read takes seconds and a
/// repaint happens twice a second.
pub struct ArrivalWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    timeout: Duration,
    /// Where the durable ledger lives. `None` on a host whose brand directory cannot be resolved,
    /// which disables the watch entirely — a ledger that cannot be persisted cannot promise that a
    /// restart will not re-announce, and an un-keepable promise is worse than a missing toast.
    ledger_path: Option<std::path::PathBuf>,
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
    /// When the last read finished, whichever address it was for.
    last_read: Option<Instant>,
    /// The address a worker is currently reading for, if any — the de-duplication that keeps a
    /// repaint during a multi-second read from starting a second one.
    in_flight: Option<String>,
}

impl ArrivalWatch {
    /// A watch that takes its control token from `read_token` rather than the on-disk install.
    #[cfg(test)]
    fn with_token_reader(
        refresh: Duration,
        ledger_path: Option<std::path::PathBuf>,
        read_token: fn() -> Option<String>,
    ) -> Self {
        Self {
            read_token,
            ..Self::new(refresh, Duration::from_secs(5), ledger_path, None)
        }
    }

    /// A watch reading at most every `refresh`, allowing `timeout` per read, persisting to
    /// `ledger_path` and honouring the preference in `config_path`.
    pub fn new(
        refresh: Duration,
        timeout: Duration,
        ledger_path: Option<std::path::PathBuf>,
        config_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchState::default())),
            refresh,
            timeout,
            ledger_path,
            config_path,
            read_token: control::load_control_token,
        }
    }

    /// The watch for this host, resolving its ledger beside `agent.json`.
    pub fn for_host() -> Self {
        let config_path = crate::environment::AppEnvironment::from_host()
            .config_path()
            .ok();
        let ledger_path = config_path
            .as_ref()
            .and_then(|config| config.parent().map(super::store::path_in));
        Self::new(WATCH_INTERVAL, WATCH_READ_TIMEOUT, ledger_path, config_path)
    }

    /// Notice, at most every `refresh`, whether money has arrived at `address` — and toast if it
    /// has and the user wants to know. **Never blocks.**
    pub fn observe(&self, link: &EngineState, address: Option<&str>) {
        let (Some(address), Some(ledger_path)) = (address, self.ledger_path.clone()) else {
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
        if state.in_flight.is_some() {
            return;
        }
        state.in_flight = Some(address.to_string());
        drop(state);

        let source =
            ControlPlaneSource::new(endpoint.clone(), (self.read_token)(), self.timeout, address);
        let shared = Arc::clone(&self.state);
        let config_path = self.config_path.clone();
        std::thread::spawn(move || {
            sweep(
                &source,
                &ledger_path,
                notifications_wanted(config_path.as_deref()),
                notify::native_notifier().as_ref(),
            );
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.last_read = Some(Instant::now());
            state.in_flight = None;
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

/// One read → account → announce cycle, with no threading and no clock.
///
/// Split out so the whole behaviour is testable against a scripted source and a recording notifier:
/// the ledger is loaded, the view is accounted for, the ledger is written back, and only then is
/// anything shown. Writing BEFORE showing is deliberate — a crash between the two costs a toast,
/// while the other order costs a duplicate announcement on the next run.
pub fn sweep(
    source: &dyn ArrivalSource,
    ledger_path: &std::path::Path,
    notifications_enabled: bool,
    notifier: &dyn NativeNotifier,
) {
    let view = match source.view() {
        Ok(view) => view,
        // Not an error a surface reports: a node that is still catching up, or briefly unreachable,
        // is the ordinary case, and the honest response is to say nothing about money.
        Err(e) => {
            tracing::debug!(reason = %e, "no confirmed chain view; nothing announced");
            return;
        }
    };

    let mut ledger = super::store::load(ledger_path);
    let arrivals = ledger.observe(&view);
    if let Err(e) = super::store::save(ledger_path, &ledger) {
        // The ledger did not persist, so the next run may re-announce. Say nothing NOW rather than
        // risk saying it twice: a duplicate claim about money is worse than a missing one.
        tracing::warn!(error = %e, "the arrival ledger could not be saved; nothing announced");
        return;
    }
    notify::announce_arrivals(&arrivals, notifications_enabled, notifier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Notification;
    use crate::test_support::node::{CoinsReply, FakeCoin, FakeNode};
    use std::sync::Mutex as StdMutex;

    const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

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

    /// A source that hands out a scripted sequence of answers, one per call.
    struct Scripted(StdMutex<std::collections::VecDeque<Result<ChainView, ArrivalSourceError>>>);
    impl Scripted {
        fn of(answers: Vec<Result<ChainView, ArrivalSourceError>>) -> Self {
            Self(StdMutex::new(answers.into()))
        }
    }
    impl ArrivalSource for Scripted {
        fn view(&self) -> Result<ChainView, ArrivalSourceError> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(ArrivalSourceError::NotConfirmable))
        }
    }

    fn coin(id: &str, parent: &str, height: u32, asset: Asset, amount: u64) -> ConfirmedCoin {
        ConfirmedCoin {
            coin_id: id.to_string(),
            parent_coin_id: parent.to_string(),
            asset,
            amount,
            confirmed_height: height,
        }
    }

    fn view(peak: u32, coins: Vec<ConfirmedCoin>) -> ChainView {
        ChainView::of_read(true, Some(peak), coins).expect("synced with a peak")
    }

    fn source_for(node: &FakeNode) -> ControlPlaneSource {
        ControlPlaneSource::new(
            node.endpoint(),
            Some(FakeNode::TOKEN.to_string()),
            Duration::from_secs(5),
            ADDRESS,
        )
    }

    // ------------------------------------------------------------------------------------------
    // The source, over a real socket
    // ------------------------------------------------------------------------------------------

    /// **A confirmed, unspent coin becomes a `ConfirmedCoin` carrying its parent and its height.**
    ///
    /// Over a real loopback socket in the real 0.6.0 wire shape, so a client that dropped the parent
    /// (the only thing separating a payment from change) fails here.
    #[test]
    fn a_confirmed_coin_arrives_with_its_parent_and_height() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![FakeCoin::confirmed("xch", 7)]));
        let view = source_for(&node).view().expect("a confirmed view");
        let coin = view
            .coins()
            .iter()
            .find(|c| c.amount == 7)
            .expect("the coin travelled");
        assert_eq!(coin.coin_id, format!("{:064x}", 7));
        assert_eq!(coin.parent_coin_id, format!("{:064x}", 8));
        assert_eq!(coin.confirmed_height, 5_412_000);
    }

    /// **A coin the node has only SEEN is not in the view, and neither is one already spent.**
    ///
    /// The mempool guard at the wire boundary. The confirmed coin alongside them is the control: it
    /// proves the read worked and that the two were dropped by their heights rather than by the
    /// whole answer failing.
    #[test]
    fn an_unconfirmed_or_spent_coin_never_reaches_the_view() {
        let mempool = FakeCoin {
            created_height: None,
            ..FakeCoin::confirmed("xch", 11)
        };
        let spent = FakeCoin {
            spent_height: Some(5_412_005),
            ..FakeCoin::confirmed("xch", 12)
        };
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![
            mempool,
            spent,
            FakeCoin::confirmed("xch", 13),
        ]));
        let view = source_for(&node).view().expect("a confirmed view");
        let amounts: Vec<u64> = view.coins().iter().map(|c| c.amount).collect();
        assert_eq!(
            amounts,
            vec![13],
            "a mempool sighting or a spent coin reached the notification path"
        );
    }

    /// **A coin listed under an asset this call did not ask for is not taken.**
    ///
    /// The fixture answers every asset leg with the same body, which is exactly the shape that
    /// catches a client labelling coins by the asset it REQUESTED: such a client would take the XCH
    /// coin twice, once relabelled `Dig`, and render one of the two with the wrong divisor.
    #[test]
    fn a_coin_of_another_asset_is_not_relabelled_as_the_one_that_was_asked_for() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![FakeCoin::confirmed("xch", 31)]));
        let view = source_for(&node).view().expect("a confirmed view");
        assert_eq!(
            view.coins().len(),
            1,
            "the XCH coin was counted under both assets"
        );
        assert_eq!(view.coins()[0].asset, Asset::Xch);
    }

    /// **A node that says its answer is stale produces no view at all.**
    #[test]
    fn an_unsynced_answer_is_not_confirmable() {
        let node = FakeNode::serving_coins(CoinsReply::CoinsAt {
            coins: vec![FakeCoin::confirmed("xch", 21)],
            synced: false,
            peak_height: Some(5_412_009),
        });
        assert_eq!(
            source_for(&node).view(),
            Err(ArrivalSourceError::NotConfirmable)
        );
    }

    /// **A node reporting no peak height produces no view — null is unknown, never zero.**
    #[test]
    fn an_answer_with_no_peak_height_is_not_confirmable() {
        let node = FakeNode::serving_coins(CoinsReply::CoinsAt {
            coins: vec![FakeCoin::confirmed("xch", 22)],
            synced: true,
            peak_height: None,
        });
        assert_eq!(
            source_for(&node).view(),
            Err(ArrivalSourceError::NotConfirmable)
        );
    }

    /// **A refusal is an error, never an empty view** — an empty view would raise a baseline over
    /// coins nobody read, and silently swallow the next real arrival.
    #[test]
    fn a_refused_read_is_an_error_not_an_empty_view() {
        let node = FakeNode::serving_coins(CoinsReply::rejected(-32004, "WALLET_READ_FAILED"));
        assert!(matches!(
            source_for(&node).view(),
            Err(ArrivalSourceError::Unavailable(_))
        ));
    }

    // ------------------------------------------------------------------------------------------
    // The sweep — the whole cycle, end to end
    // ------------------------------------------------------------------------------------------

    /// **The whole cycle: adopt in silence, then announce the next payment, once.**
    ///
    /// This is the four traps composed, driven through the same function the tray runs: the first
    /// sweep adopts a wallet with history and shows nothing; the second announces exactly the new
    /// coin, with its own amount and asset; the third — the same view again, as a repeat poll or a
    /// re-scan would present it — shows nothing more.
    #[test]
    fn the_sweep_adopts_in_silence_then_announces_the_next_payment_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        let history = view(
            100,
            vec![
                coin("old-a", "s", 10, Asset::Xch, 1_000_000_000_000),
                coin("old-b", "s", 20, Asset::Xch, 2_000_000_000_000),
            ],
        );
        let paid = view(
            200,
            vec![
                coin("old-a", "s", 10, Asset::Xch, 1_000_000_000_000),
                coin("old-b", "s", 20, Asset::Xch, 2_000_000_000_000),
                coin("paid", "stranger", 150, Asset::Dig, 2_500),
            ],
        );
        let source = Scripted::of(vec![Ok(history), Ok(paid.clone()), Ok(paid)]);

        sweep(&source, &path, true, &notifier);
        assert!(
            notifier.shown().is_empty(),
            "the first sweep announced history: {:?}",
            notifier.shown()
        );

        sweep(&source, &path, true, &notifier);
        assert_eq!(
            notifier.shown().len(),
            1,
            "the payment was not announced once"
        );
        assert_eq!(notifier.shown()[0].body, "Received 2.5 $DIG");

        sweep(&source, &path, true, &notifier);
        assert_eq!(
            notifier.shown().len(),
            1,
            "a repeat poll re-announced the same payment"
        );
    }

    /// **With notifications off nothing is drawn, and the ledger still advances.**
    ///
    /// The second half is the one a naive off-switch gets wrong: gating the DETECTION rather than
    /// the toast means turning notifications back on announces everything received in between. The
    /// control at the end proves the switch, and not the fixture, is what kept it quiet.
    #[test]
    fn turning_notifications_off_silences_the_toast_without_stalling_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();

        let empty = view(100, vec![]);
        let while_off = view(200, vec![coin("quiet", "stranger", 150, Asset::Xch, 1)]);
        let after_on = view(
            300,
            vec![
                coin("quiet", "stranger", 150, Asset::Xch, 1),
                coin("loud", "stranger", 250, Asset::Xch, 1_000_000_000_000),
            ],
        );
        let source = Scripted::of(vec![Ok(empty), Ok(while_off), Ok(after_on)]);

        sweep(&source, &path, true, &notifier); // adopt
        sweep(&source, &path, false, &notifier); // arrives while the switch is off
        assert!(
            notifier.shown().is_empty(),
            "a toast was drawn with the switch off"
        );

        sweep(&source, &path, true, &notifier); // switch back on
        let shown = notifier.shown();
        assert_eq!(
            shown.len(),
            1,
            "turning notifications back on replayed what happened while they were off"
        );
        assert_eq!(
            shown[0].body, "Received 1 XCH",
            "the wrong coin was announced"
        );
    }

    /// **The preference is read from the file, both ways, and an absent file means ON.**
    ///
    /// The default matters as much as the read: a machine with no `agent.json` yet is a fresh
    /// install, and a fresh install must get the feature rather than silently not have it.
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

    // ------------------------------------------------------------------------------------------
    // The throttle
    // ------------------------------------------------------------------------------------------

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

    /// **A repaint does not become a chain read**: the cadence is the watch's, not the caller's.
    ///
    /// Counted at the SERVER, so this is what actually went out on the wire rather than the client's
    /// account of it. The wallet holds two assets, so ONE sweep is two calls — the property is that a
    /// second `observe` inside the interval adds none.
    #[test]
    fn a_second_observe_inside_the_interval_does_not_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = super::super::store::path_in(dir.path());
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![FakeCoin::confirmed("xch", 41)]));
        let link = connected_to(&node);
        let watch = ArrivalWatch::with_token_reader(
            Duration::from_secs(600),
            Some(ledger.clone()),
            no_token,
        );

        watch.observe(&link, Some(ADDRESS));
        assert!(settled(&ledger), "the first sweep never finished");
        let after_first = node.request_count();
        assert_eq!(
            after_first,
            WATCHED_ASSETS.len(),
            "one sweep asks once per asset"
        );

        for _ in 0..5 {
            watch.observe(&link, Some(ADDRESS));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            node.request_count(),
            after_first,
            "repaints inside the interval turned into chain reads"
        );
    }

    /// **Nothing is read without a node or without an address.**
    ///
    /// Both are states the tray is routinely in — a locked account has no address, and a stopped node
    /// has no endpoint — and asking anyway would be a read against a node that is not there.
    #[test]
    fn a_watch_with_no_node_or_no_address_reads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = super::super::store::path_in(dir.path());
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![]));
        let watch = ArrivalWatch::with_token_reader(
            Duration::from_millis(1),
            Some(ledger.clone()),
            no_token,
        );

        watch.observe(
            &EngineState::Disconnected {
                reason: "no node".to_string(),
            },
            Some(ADDRESS),
        );
        watch.observe(&connected_to(&node), None);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            node.request_count(),
            0,
            "a read went out with nothing to read"
        );
        assert!(
            !ledger.exists(),
            "a ledger was written without any chain read"
        );
    }

    /// **A watch with nowhere to persist reads nothing at all.**
    ///
    /// A ledger that cannot be written cannot promise a restart will not re-announce, and an
    /// un-keepable promise about somebody's money is worse than a missing toast.
    #[test]
    fn a_watch_that_cannot_persist_does_not_read() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![]));
        let watch = ArrivalWatch::with_token_reader(Duration::from_millis(1), None, no_token);
        watch.observe(&connected_to(&node), Some(ADDRESS));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(node.request_count(), 0);
    }

    /// **A source that cannot answer changes nothing** — no toast, and no baseline written that
    /// would swallow the next real arrival.
    #[test]
    fn a_source_that_cannot_answer_leaves_no_trace() {
        let dir = tempfile::tempdir().unwrap();
        let path = super::super::store::path_in(dir.path());
        let notifier = Recorder::default();
        let source = Scripted::of(vec![Err(ArrivalSourceError::NotConfirmable)]);

        sweep(&source, &path, true, &notifier);
        assert!(notifier.shown().is_empty());
        assert!(
            !path.exists(),
            "an unanswerable read wrote a ledger, which would adopt a baseline nobody measured"
        );
    }
}
