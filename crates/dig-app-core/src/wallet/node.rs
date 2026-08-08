//! The PRODUCTION balance source — `control.wallet.balance` against the local dig-node
//! (dig_ecosystem#2206).
//!
//! [`super::overview`] describes what the Wallet surface may honestly say; this module is what makes
//! it say a number. Two pieces:
//!
//! - [`NodeWalletEngine`] — a [`WalletEngine`] whose `balance` is one
//!   `control.wallet.balance` call over the loopback control plane ([`crate::control`]).
//! - [`NodeBalance`] — the throttle that owns *when* that call happens, so the tray's twice-a-second
//!   repaint does not become twice-a-second chain reads.
//!
//! # The capability is asked, never assumed
//!
//! A node either answers the call or refuses it, and its refusal says which kind it is: an older
//! build resolves no such method (`METHOD_NOT_FOUND` / `NOT_SUPPORTED`), a busy one reports
//! `WALLET_NOT_SYNCED`, a broken one `WALLET_READ_FAILED`. This module turns those stable symbols
//! into typed [`WalletError`]s, and the overview turns those into the sentence a person reads. No
//! version sniffing and no local table of what nodes can do: both would be a fresh copy of the
//! hardcode this module exists to delete.
//!
//! # The custody boundary
//!
//! Reading a balance is a chain read of a PUBLIC address. No key material crosses into the node —
//! the request carries only a bech32m address and an asset name, and dig-node serves the method as
//! an OPEN read for exactly that reason. Sending (which does involve custody) is #2207's, and this
//! engine deliberately refuses it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::method::ControlMethod;
use dig_node_control_interface::params::{
    Asset as WireAsset, WalletBalanceParams, WalletBroadcastParams, WalletCoinsParams,
};
use dig_node_control_interface::results::WalletCoinRecord;

use crate::control::{self, ControlCallError, ControlFailure};
use crate::engine::EngineState;

use super::engine::{
    BalanceRequest, BalanceResponse, BroadcastRequest, BroadcastResponse, CoinsRequest,
    CoinsResponse, WalletEngine,
};
use super::overview::{AddressReading, BalanceReading, ChainSource, WalletOverview};
use super::state::{Asset, CoinRecord};
use super::WalletError;

/// How long a balance reading is reused before the node is asked again.
///
/// The tray repaints twice a second and a balance is a chain read the node rate-limits, so the poll
/// cadence has to be its own decision rather than the repaint's. Ten seconds is short enough that a
/// received payment shows up while the user is still looking, and long enough that an idle tray
/// costs the node six reads a minute.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// How long ONE balance read may take before it is abandoned.
///
/// Deliberately not [`control::DEFAULT_PROBE_TIMEOUT`]. That constant answers a different question
/// — how long a §5.3 tier may take to prove it is alive before the ladder falls through — and it is
/// sized (1500 ms) so a stalled tier cannot hold the run loop. A balance is not a liveness probe: it
/// is a chain read the node may serve from a public HTTPS chain source, and dig_ecosystem#2325
/// measured the live node taking 2534 ms and 6014 ms to answer one. Under the probe budget that read
/// failed 100% of the time on a healthy machine.
///
/// Twenty seconds is a little over three times the slowest reading ever measured — headroom for a
/// tail this small a sample cannot have seen, rather than a value fitted to it. Past that the read is
/// abandoned and the surface says the node did not answer in time; because the poller never runs two
/// reads for one address at once, a run of slow reads cannot pile up, and the next observation simply
/// starts a fresh one.
///
/// Nothing waits on this budget: the read runs on its own thread (see [`NodeBalance`]), so a long
/// tail costs a late figure, never a frozen tray.
pub const BALANCE_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Reads balances from a running dig-node over the loopback control plane.
///
/// One instance is bound to one endpoint — the tier of the §5.3 ladder that actually answered — so
/// it never re-resolves and never silently talks to a different node than the status surface names.
pub struct NodeWalletEngine {
    endpoint: String,
    token: Option<String>,
    timeout: Duration,
}

impl NodeWalletEngine {
    /// An engine that reads from the node at `endpoint`, presenting `token` when there is one.
    ///
    /// `token` is optional because `control.wallet.balance` is an OPEN read on every node build that
    /// has it: a machine whose control-token file this user cannot read still gets its balance.
    pub fn new(endpoint: impl Into<String>, token: Option<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            token,
            timeout,
        }
    }
}

impl WalletEngine for NodeWalletEngine {
    /// Push an ALREADY-SIGNED bundle through the node's `control.wallet.broadcast`.
    ///
    /// The node never sees a key: this carries signed bytes and nothing else (§908). A mempool that
    /// judged the bundle comes back as a [`BroadcastResponse`] carrying its verdict — including a
    /// refusal — and only a failure to REACH a mempool is an error here.
    fn broadcast(&self, request: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
        let params = WalletBroadcastParams {
            signed_bundle_hex: request.signed_bundle_hex,
        };
        let result = self.call(&params, ControlMethod::WalletBroadcast)?;
        Ok(BroadcastResponse {
            accepted: result.accepted,
            transaction_id: result.transaction_id,
            rejection: result.rejection,
        })
    }

    /// Read an address's spendable coins through the node's `control.wallet.coins`.
    ///
    /// An empty list is the node's ANSWER — this address holds nothing — and every way of failing
    /// to consult a chain is an error instead. Collapsing the two would report "you hold nothing"
    /// to somebody who holds funds, and a spend built on that answer refuses with a shortfall that
    /// is not true.
    fn coins(&self, request: CoinsRequest) -> Result<CoinsResponse, WalletError> {
        let params = WalletCoinsParams {
            address: request.address,
            asset: wire_asset(request.asset),
        };
        let result = self.call(&params, ControlMethod::WalletCoins)?;
        Ok(CoinsResponse {
            coins: result.coins.iter().map(app_coin).collect(),
        })
    }

    fn balance(&self, request: BalanceRequest) -> Result<BalanceResponse, WalletError> {
        let params = WalletBalanceParams {
            address: request.address,
            asset: wire_asset(request.asset),
        };
        let result = control::call_control_result(
            &self.endpoint,
            &params,
            self.token.as_deref(),
            self.timeout,
        )
        .map_err(|failure| classify(ControlMethod::WalletBalance, failure))?;

        // The node answered with figures AND told us they are stale. A stale number still reads as
        // the truth on a menu row, so it is reported as an unknown rather than shown with a caveat.
        if !result.synced {
            return Err(WalletError::EngineNotSynced);
        }
        Ok(BalanceResponse {
            balance: result.balance,
        })
    }
}

impl NodeWalletEngine {
    /// One control call to this engine's node, with `method`'s refusals classified for `method`.
    ///
    /// The method travels alongside the call because the SAME refusal symbol means different things
    /// on different methods — see [`classify`] — and deriving it from the call's own type is what
    /// keeps the two from drifting apart.
    fn call<C>(&self, call: &C, method: ControlMethod) -> Result<C::Output, WalletError>
    where
        C: dig_node_control_interface::traits::ControlCall,
    {
        control::call_control_result(&self.endpoint, call, self.token.as_deref(), self.timeout)
            .map_err(|failure| classify(method, failure))
    }
}

/// One of the node's coin records as dig-app's own [`CoinRecord`].
///
/// The node's record is a SUPERSET: it also carries the parent, the puzzle hash and the two
/// heights, which is what a spend needs to reconstruct a `Coin`. dig-app's wallet surface needs
/// only the identity and the amount, so the rest is dropped HERE, visibly, rather than by a
/// tolerant deserializer — a reader should be able to see that the drop is a decision.
fn app_coin(record: &WalletCoinRecord) -> CoinRecord {
    CoinRecord {
        coin_id: record.coin_id.clone(),
        asset: app_asset(record.asset),
        amount: record.amount,
    }
}

/// The contract's wire enum as dig-app's [`Asset`] — the inverse of [`wire_asset`].
fn app_asset(asset: WireAsset) -> Asset {
    match asset {
        WireAsset::Xch => Asset::Xch,
        WireAsset::Dig => Asset::Dig,
    }
}

/// dig-app's [`Asset`] as the control contract's wire enum. Both serialize to the same lowercase
/// token; this conversion is what keeps that a compile-time fact rather than a coincidence.
fn wire_asset(asset: Asset) -> WireAsset {
    match asset {
        Asset::Xch => WireAsset::Xch,
        Asset::Dig => WireAsset::Dig,
    }
}

/// The stable `data.code` symbols that mean "this build cannot serve the method at all".
///
/// `METHOD_NOT_FOUND` is a build predating the method; `NOT_SUPPORTED` is a build that has it but
/// cannot offer it. Both name an upgrade as the remedy.
///
/// `UNAUTHORIZED` is deliberately NOT here — it belongs to [`classify`], which decides what it means
/// from the METHOD it was raised on.
const CANNOT_SERVE: &[&str] = &[
    // Taken from the contract crate rather than retyped. A client must key on the stable contract
    // symbol and never on a locally re-derived one -- hand-typing these was doing exactly what that
    // rule warns against, and no test could have caught a divergence because the fixtures would
    // have retyped the same literal (dig-app#109 review).
    ControlErrorCode::MethodNotFound.name(),
    ControlErrorCode::NotSupported.name(),
];

/// Turn a control-plane failure into the typed wallet error the overview renders from.
///
/// Keyed on the stable UPPER_SNAKE `data.code`, never on the human message — the message is
/// explicitly not contract-stable, so matching on its words would break on a reword.
///
/// # Why the method is an argument
///
/// An authorization refusal means opposite things on the two kinds of wallet method, and only the
/// method can tell them apart:
///
/// - On an **open read** (`balance`, `coins`, `peak`) no token is ever required, so a refusal on
///   authorization grounds can only come from a build that gates the method behind the control
///   plane — that is, one that does not really have it. The remedy is an upgrade.
/// - On a **token-gated** method (`broadcast`) it means exactly what it says: this app did not
///   present a usable control token. The remedy is to make the node's token readable, and telling
///   the user to upgrade a node that already serves the push would send them nowhere.
///
/// The same fork covers the transport-level `401` a real node answers a tokenless gated call with,
/// which never reaches the JSON-RPC error layer at all.
fn classify(method: ControlMethod, failure: ControlFailure) -> WalletError {
    /// What an authorization refusal on `method` means.
    fn unauthorized(method: ControlMethod) -> WalletError {
        match method.is_open_read() {
            true => WalletError::EngineUnsupported,
            false => WalletError::EngineUnauthorized,
        }
    }

    match failure {
        ControlFailure::Transport(ControlCallError::HttpRefused { code: 401, .. }) => {
            unauthorized(method)
        }
        ControlFailure::Rejected(ref e)
            if e.data.code == ControlErrorCode::Unauthorized.name() =>
        {
            unauthorized(method)
        }
        other => classify_read_failure(other),
    }
}

/// The stable symbol for "answered, but still catching up".
const NOT_SYNCED: &str = ControlErrorCode::WalletNotSynced.name();

/// The stable symbol for "the method is here, but there is no chain to read from".
///
/// This is what a DEFAULT dig-node install answers today: the method is served, unauthenticated, and
/// its chain source is absent. It is neither a missing capability nor an ordinary lag, so it gets its
/// own reason all the way to the sentence the user reads.
const NO_CHAIN_SOURCE: &str = ControlErrorCode::WalletNoChainSource.name();

/// Every failure whose meaning does NOT depend on which method raised it.
fn classify_read_failure(failure: ControlFailure) -> WalletError {
    match failure {
        ControlFailure::Transport(ControlCallError::Unreachable(detail)) => {
            WalletError::EngineUnreachable(detail)
        }
        // The socket connected and the read overran. Kept separate from `Unreachable` all the way to
        // the sentence a person reads, because only `Unreachable` is evidence about whether a node
        // exists (dig_ecosystem#2325).
        ControlFailure::Transport(ControlCallError::TimedOut(detail)) => {
            WalletError::EngineTimedOut(detail)
        }
        ControlFailure::Transport(e) => WalletError::Engine(e.to_string()),
        ControlFailure::Rejected(e) if CANNOT_SERVE.contains(&e.data.code.as_str()) => {
            WalletError::EngineUnsupported
        }
        ControlFailure::Rejected(e) if e.data.code == NOT_SYNCED => WalletError::EngineNotSynced,
        ControlFailure::Rejected(e) if e.data.code == NO_CHAIN_SOURCE => {
            WalletError::EngineNoChainSource
        }
        ControlFailure::Rejected(e) => WalletError::Engine(e.message),
    }
}

/// The account's balance, polled from the node no more often than [`REFRESH_INTERVAL`].
///
/// Lives beside the tray's status handle and is asked for a reading on every repaint. It answers
/// from its cache and does the real read on a WORKER THREAD, so a caller never waits on the node:
/// the tray repaints twice a second and a chain read takes seconds (dig_ecosystem#2325), so a
/// blocking read would either freeze the tray or force a budget too small for the read it makes.
/// While a read is in flight the answer is [`BalanceReading::Pending`] — or, if this address already
/// has a reading, that reading, so a routine refresh does not flicker the figure away.
///
/// Holding all of this HERE rather than in the shell is deliberate: the shell is a binary, and a
/// binary is a test-free zone.
pub struct NodeBalance {
    /// Shared with the worker threads, which is why it is an [`Arc`] rather than a plain field.
    state: Arc<Mutex<PollState>>,
    refresh: Duration,
    timeout: Duration,
    /// Reads the node's control token. Injected so a test presents its own fake node's token
    /// instead of whatever this machine's real install holds.
    read_token: fn() -> Option<String>,
}

/// What the poller knows between reads.
#[derive(Default)]
struct PollState {
    /// The last reading taken, whichever address it was for.
    cached: Option<Cached>,
    /// The address a worker is currently reading for, if any.
    ///
    /// This is the de-duplication: without it every repaint during a multi-second read would start
    /// another pair of chain reads on a node that is already busy answering the first.
    in_flight: Option<String>,
}

impl PollState {
    /// The reading held for `address` and how long ago it was taken — `None` when the last reading
    /// was for a different account, because that is a different question with a different answer.
    fn reading_for(&self, address: &str) -> Option<(BalanceReading, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.address == address)
            .map(|c| (c.reading.clone(), c.taken.elapsed()))
    }
}

/// A reading and the address + instant it was taken for.
struct Cached {
    address: String,
    reading: BalanceReading,
    taken: Instant,
}

impl Default for NodeBalance {
    fn default() -> Self {
        Self::new(REFRESH_INTERVAL, BALANCE_READ_TIMEOUT)
    }
}

impl NodeBalance {
    /// A poller refreshing at most every `refresh`, allowing `timeout` per read.
    pub fn new(refresh: Duration, timeout: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(PollState::default())),
            refresh,
            timeout,
            read_token: control::load_control_token,
        }
    }

    /// A poller that obtains its control token from `read_token` rather than the on-disk install.
    #[cfg(test)]
    fn with_token_reader(
        refresh: Duration,
        timeout: Duration,
        read_token: fn() -> Option<String>,
    ) -> Self {
        Self {
            read_token,
            ..Self::new(refresh, timeout)
        }
    }

    /// The freshest reading for `address`, given the current link to the node. **Never blocks.**
    ///
    /// Starts a background read when the cache is stale, when the address changed (a different
    /// account's balance is a different question), or when nothing has been read yet — and answers
    /// straight away from what it already has. With no address there is nothing to ask about, so the
    /// cache is dropped and the caller — [`WalletOverview::of_tray`] — states the address's own
    /// reason instead.
    pub fn observe(&self, link: &EngineState, address: Option<&str>) -> BalanceReading {
        let Some(address) = address else {
            self.lock().cached = None;
            return BalanceReading::default();
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.reading_for(address) {
            if age < self.refresh {
                return fresh;
            }
        }

        self.start_read(&mut state, link, address);
        // Whatever is there now: the reading a link with no node produced without any I/O, or the
        // previous figure for this address while its refresh runs — showing that beats blanking a
        // known balance to "checking" every ten seconds. Only a first read for an address has
        // genuinely nothing to state.
        state
            .reading_for(address)
            .map(|(reading, _)| reading)
            .unwrap_or(BalanceReading::Pending)
    }

    /// Begin a read for `address` unless one is already under way for it.
    ///
    /// A disconnected link needs no thread: the answer involves no I/O and is recorded immediately,
    /// so "DIG could not reach a node" is never left waiting behind a `Pending`.
    fn start_read(&self, state: &mut PollState, link: &EngineState, address: &str) {
        let endpoint = match link {
            EngineState::Disconnected { .. } => {
                state.cached = Some(Cached {
                    address: address.to_string(),
                    reading: WalletOverview::read(
                        AddressReading::Known(address.to_string()),
                        &ChainSource::Absent,
                    )
                    .balance,
                    taken: Instant::now(),
                });
                return;
            }
            // The endpoint the status probe ALREADY resolved off the §5.3 ladder, so the balance and
            // the status line can never describe two different nodes.
            EngineState::Connected { endpoint, .. } => endpoint.clone(),
        };
        if state.in_flight.as_deref() == Some(address) {
            return;
        }
        state.in_flight = Some(address.to_string());

        let shared = Arc::clone(&self.state);
        let address = address.to_string();
        let engine = NodeWalletEngine::new(endpoint, (self.read_token)(), self.timeout);
        std::thread::spawn(move || {
            let reading = WalletOverview::read(
                AddressReading::Known(address.clone()),
                &ChainSource::Ready(&engine),
            )
            .balance;
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.cached = Some(Cached {
                address: address.clone(),
                reading,
                taken: Instant::now(),
            });
            // Cleared only if it is still OUR read: the account may have changed while we waited,
            // in which case a later worker owns the slot and must not be cancelled by this one.
            if state.in_flight.as_deref() == Some(address.as_str()) {
                state.in_flight = None;
            }
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PollState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node::{BroadcastReply, CoinsReply, FakeCoin, FakeNode, WalletReply};
    use crate::wallet::overview::{balance_line, BalanceUnknown, Balances};

    const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    /// Two whole coins of DIG and one of XCH, in each asset's OWN base unit — $DIG carries 3 decimals
    /// and XCH 12, so the two integers differ by more than their rendered figures do. Chosen so a
    /// swapped-asset implementation cannot pass, and so a single-divisor formatter renders one of
    /// them absurdly (dig_ecosystem#2295).
    const DIG_UNITS: u64 = 2_000;
    const XCH_MOJOS: u64 = 1_000_000_000_000;

    fn fake_token() -> Option<String> {
        Some(FakeNode::TOKEN.to_string())
    }

    fn no_token() -> Option<String> {
        None
    }

    fn engine_for(node: &FakeNode) -> NodeWalletEngine {
        NodeWalletEngine::new(node.endpoint(), fake_token(), Duration::from_secs(5))
    }

    fn ask(engine: &NodeWalletEngine, asset: Asset) -> Result<u64, WalletError> {
        engine
            .balance(BalanceRequest {
                address: ADDRESS.to_string(),
                asset,
            })
            .map(|r| r.balance)
    }

    /// **The headline property.** Against a node that serves `control.wallet.balance`, the overview
    /// reports a real number — over a real socket, in the real wire shape.
    ///
    /// The two assets carry DIFFERENT amounts, so an implementation that read one and reused it for
    /// both (or swapped them) fails here rather than passing on a symmetric fixture.
    #[test]
    fn a_node_that_serves_the_method_yields_a_known_balance() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let engine = engine_for(&node);
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine),
        );

        assert_eq!(
            overview.balance,
            BalanceReading::Known(Balances {
                xch_mojos: XCH_MOJOS,
                dig_units: DIG_UNITS,
            }),
            "a node that answered must produce a KNOWN balance"
        );
        assert_eq!(
            balance_line(&overview.balance),
            "Balance: 2 $DIG and 1 XCH."
        );
        // Asserted from the SERVER's copy of the bytes: the contract method name must have gone out
        // on the wire, not merely been named in a constant the client also owns.
        assert!(node.received().contains("control.wallet.balance"));
    }

    /// A node that resolves no such method still yields "this node cannot read balances yet" — the
    /// state that must stay reachable, now produced by the node's ANSWER rather than by a constant.
    #[test]
    fn an_older_node_that_does_not_serve_the_method_says_so() {
        let node = FakeNode::serving_wallet(WalletReply::rejected(-32601, "METHOD_NOT_FOUND"));
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine_for(&node)),
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NodeCannotRead)
        );
    }

    /// An old build gates the method behind the control token, so an authorization refusal on THIS
    /// method means "no such method here" — never a fault in the user's account.
    #[test]
    fn an_authorization_refusal_on_this_open_read_reads_as_an_older_node() {
        let node = FakeNode::serving_wallet(WalletReply::rejected(-32030, "UNAUTHORIZED"));
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine_for(&node)),
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NodeCannotRead)
        );
    }

    /// A syncing node's own refusal reaches the user as "still catching up".
    #[test]
    fn a_syncing_node_is_reported_as_syncing_not_as_a_failure() {
        let node = FakeNode::serving_wallet(WalletReply::rejected(-32041, "WALLET_NOT_SYNCED"));
        assert!(matches!(
            ask(&engine_for(&node), Asset::Xch),
            Err(WalletError::EngineNotSynced)
        ));
    }

    /// **A node that answers with figures AND `synced: false` is still an unknown.** The nearest
    /// wrong implementation reads `balance` and ignores `synced`; this fixture is the only one that
    /// can catch it, because the read SUCCEEDS at the transport layer.
    #[test]
    fn figures_the_node_calls_stale_are_not_a_balance() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: false,
        });
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine_for(&node)),
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NotSynced)
        );
        assert!(
            !balance_line(&overview.balance).contains('2'),
            "a stale figure must not reach the user: {}",
            balance_line(&overview.balance)
        );
    }

    /// **The answer a DEFAULT dig-node install actually gives today.** Measured against a live
    /// 0.98.0 node: the method is served, no token is needed, and it refuses with
    /// `-32040 WALLET_NO_CHAIN_SOURCE` because the node has nothing to look the address up in.
    ///
    /// It must reach the user as its OWN reason. Folding it into `ReadFailed` would show them the
    /// node's internal wording; folding it into `NodeCannotRead` would tell them to upgrade a node
    /// that is already new enough.
    #[test]
    fn a_node_with_no_chain_source_says_exactly_that() {
        let node =
            FakeNode::serving_wallet(WalletReply::rejected(-32040, "WALLET_NO_CHAIN_SOURCE"));
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine_for(&node)),
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NoChainSource)
        );
        let line = balance_line(&overview.balance);
        assert!(line.contains("no live connection to the"), "{line}");
        assert!(
            !line.contains("money sent to it still arrives") || !line.contains("upgrade"),
            "a capable node must not be described as one needing an upgrade: {line}"
        );
    }

    /// A read that fails for a reason we cannot classify carries the node's words — and never
    /// becomes a zero.
    #[test]
    fn a_failed_read_is_unknown_never_zero() {
        let node = FakeNode::serving_wallet(WalletReply::rejected(-32042, "WALLET_READ_FAILED"));
        let overview = WalletOverview::read(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&engine_for(&node)),
        );
        assert!(
            matches!(
                overview.balance,
                BalanceReading::Unknown(BalanceUnknown::ReadFailed(_))
            ),
            "got {:?}",
            overview.balance
        );
        assert_ne!(
            overview.balance,
            BalanceReading::Known(Balances {
                xch_mojos: 0,
                dig_units: 0
            })
        );
    }

    /// **The method is served WITHOUT a control token**, which is what lets a user whose node runs
    /// as an unreadable-token service still see their balance.
    ///
    /// The fake gates every other method on the token exactly as the node does, so this passing
    /// means the open-read exemption was genuinely exercised — not that the gate was absent.
    #[test]
    fn a_balance_is_readable_with_no_control_token_at_all() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let engine = NodeWalletEngine::new(node.endpoint(), None, Duration::from_secs(5));
        assert_eq!(ask(&engine, Asset::Xch).ok(), Some(XCH_MOJOS));
    }

    /// **The defect dig_ecosystem#2325 reported, at the engine seam.** A node that is up, connected
    /// and simply slower than the budget must not be classified as an absent one.
    ///
    /// The delay is 20× the budget so the outcome cannot turn on scheduling noise, and
    /// [`a_read_slower_than_a_probe_budget_still_yields_a_balance`] is the control that keeps this
    /// from passing for a trivial reason: the SAME slow fixture, given a chain-read budget, must
    /// produce the figure.
    #[test]
    fn a_node_that_answers_late_times_out_rather_than_looking_absent() {
        let node = FakeNode::serving_wallet_slowly(
            WalletReply::Balance {
                xch: XCH_MOJOS,
                dig: DIG_UNITS,
                synced: true,
            },
            Duration::from_secs(4),
        );
        let engine =
            NodeWalletEngine::new(node.endpoint(), fake_token(), Duration::from_millis(200));
        let error = ask(&engine, Asset::Xch).expect_err("the answer arrives after the budget");
        assert!(
            matches!(error, WalletError::EngineTimedOut(_)),
            "a late node is not an absent one; got {error:?}"
        );
        assert!(
            !error.to_string().contains("no DIG node"),
            "the error may not claim the node is missing: {error}"
        );
    }

    /// **The regression itself**: a read that takes longer than the LADDER PROBE budget, but well
    /// inside the balance budget, yields a real figure.
    ///
    /// The fixture's delay is deliberately chosen from the constants rather than picked: it is past
    /// [`control::DEFAULT_PROBE_TIMEOUT`] — the budget the shipped app wrongly used — and far inside
    /// [`BALANCE_READ_TIMEOUT`]. Against the shipped code this fixture produced
    /// [`WalletError::EngineUnreachable`] and the user was told no node was running.
    #[test]
    fn a_read_slower_than_a_probe_budget_still_yields_a_balance() {
        let node = FakeNode::serving_wallet_slowly(
            WalletReply::Balance {
                xch: XCH_MOJOS,
                dig: DIG_UNITS,
                synced: true,
            },
            control::DEFAULT_PROBE_TIMEOUT + Duration::from_millis(250),
        );
        let engine = NodeWalletEngine::new(node.endpoint(), fake_token(), BALANCE_READ_TIMEOUT);
        assert_eq!(ask(&engine, Asset::Xch).ok(), Some(XCH_MOJOS));
    }

    /// **The budget is pinned from both sides against the measurement that produced it.**
    ///
    /// dig_ecosystem#2325 measured the live node answering an authenticated, valid-address balance
    /// read in 6014 ms and 2534 ms. A bound asserted only from below could be satisfied by any
    /// value at all; the lower assertion is what says the SHIPPED budget was provably too small, and
    /// the upper one keeps this from being "raise it until the test passes".
    #[test]
    fn the_balance_budget_covers_the_slowest_read_ever_measured() {
        const SLOWEST_MEASURED: Duration = Duration::from_millis(6014);

        assert!(
            control::DEFAULT_PROBE_TIMEOUT < SLOWEST_MEASURED,
            "the probe budget must remain a probe budget — if it grew past a chain read, the \
             fall-through this constant exists for has been slowed to fix the wrong problem"
        );
        assert!(
            BALANCE_READ_TIMEOUT >= SLOWEST_MEASURED * 3,
            "a chain read seen at {SLOWEST_MEASURED:?} needs tail headroom, not a hairline pass"
        );
        assert!(
            BALANCE_READ_TIMEOUT <= Duration::from_secs(30),
            "a budget this large stops being a budget"
        );
    }

    /// Nothing listening is "no node is running", not "the read failed" — different remedies.
    #[test]
    fn nothing_listening_reads_as_no_node() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        drop(listener);
        let engine = NodeWalletEngine::new(endpoint, fake_token(), Duration::from_millis(300));
        assert!(matches!(
            ask(&engine, Asset::Xch),
            Err(WalletError::EngineUnreachable(_))
        ));
    }

    /// Nothing listening is "no node is running" for a PUSH too — and a push that never reached a
    /// mempool must never look like one the mempool refused.
    #[test]
    fn a_push_with_no_node_listening_is_unreachable_not_a_refusal() {
        let engine = NodeWalletEngine::new("http://localhost:1", None, Duration::from_millis(50));
        assert!(matches!(
            engine.broadcast(push()),
            Err(WalletError::EngineUnreachable(_))
        ));
    }

    /// A bundle to push. The bytes are arbitrary; what matters is that they arrive unchanged.
    fn push() -> BroadcastRequest {
        BroadcastRequest {
            signed_bundle_hex: SIGNED_BUNDLE.to_string(),
        }
    }

    /// The hex the fixtures push. Distinctive enough that finding it in the server's copy of the
    /// request proves THESE bytes travelled, rather than some bytes.
    const SIGNED_BUNDLE: &str = "ff01c0ffee";

    /// **The headline coin read.** A node that serves `control.wallet.coins` yields the real
    /// records, over a real socket, in the real wire shape.
    ///
    /// The two coins carry different amounts and, through [`FakeCoin::confirmed`], three ids that
    /// differ from one another — so a client that read the puzzle hash where it meant the coin id,
    /// or reported one coin twice, fails here rather than passing on a uniform fixture.
    #[test]
    fn a_node_that_serves_coins_yields_the_real_records() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![
            FakeCoin::confirmed("dig", 1_500),
            FakeCoin::confirmed("dig", 2_500),
        ]));
        let read = read_coins(&engine_for(&node), Asset::Dig).expect("the node answered");

        assert_eq!(
            read.coins.iter().map(|c| c.amount).collect::<Vec<_>>(),
            [1_500, 2_500]
        );
        assert_eq!(
            read.coins.iter().map(|c| c.coin_id.as_str()).collect::<Vec<_>>(),
            [format!("{:064x}", 1_500), format!("{:064x}", 2_500)]
        );
        assert!(read.coins.iter().all(|c| c.asset == Asset::Dig));
        assert!(node.received().contains("control.wallet.coins"));
    }

    /// **An empty list is an ANSWER**: the node consulted a chain and this address holds nothing.
    #[test]
    fn an_address_holding_nothing_reads_as_an_empty_list() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(Vec::new()));
        assert_eq!(
            read_coins(&engine_for(&node), Asset::Xch)
                .expect("an empty address is a successful read")
                .coins,
            Vec::new()
        );
    }

    /// **...and an unreachable chain is an ERROR, never that same empty list.**
    ///
    /// This is the pair that makes the previous test mean something. The nearest wrong
    /// implementation maps every refusal to `Ok(no coins)`, which would tell somebody who holds
    /// funds that they hold nothing — and would then refuse their mint with a shortfall that is not
    /// true. Both fixtures are needed: either alone is satisfied by a constant.
    #[test]
    fn a_chain_that_could_not_be_read_is_an_error_never_an_empty_list() {
        for (code, symbol) in [
            (-32040, "WALLET_NO_CHAIN_SOURCE"),
            (-32041, "WALLET_NOT_SYNCED"),
            (-32042, "WALLET_READ_FAILED"),
        ] {
            let node = FakeNode::serving_coins(CoinsReply::rejected(code, symbol));
            let outcome = read_coins(&engine_for(&node), Asset::Xch);
            assert!(
                outcome.is_err(),
                "{symbol} became a successful read: {outcome:?}"
            );
        }
    }

    /// The coin read is OPEN, exactly as the contract declares it — a machine whose control-token
    /// file this user cannot read still gets its coins.
    #[test]
    fn coins_are_readable_with_no_control_token_at_all() {
        let node = FakeNode::serving_coins(CoinsReply::Coins(vec![FakeCoin::confirmed("xch", 42)]));
        let engine = NodeWalletEngine::new(node.endpoint(), None, Duration::from_secs(5));
        assert_eq!(
            read_coins(&engine, Asset::Xch).expect("an open read needs no token").coins.len(),
            1
        );
    }

    /// A node predating the method says so, and the remedy is an upgrade.
    #[test]
    fn an_older_node_that_cannot_read_coins_says_so() {
        let node = FakeNode::serving_coins(CoinsReply::rejected(-32601, "METHOD_NOT_FOUND"));
        assert!(matches!(
            read_coins(&engine_for(&node), Asset::Xch),
            Err(WalletError::EngineUnsupported)
        ));
    }

    /// **A push the mempool accepted comes back as an acceptance carrying the transaction id** —
    /// and the SIGNED BYTES are what went out, asserted from the server's own copy.
    #[test]
    fn an_accepted_push_reports_the_transaction_id() {
        let node = FakeNode::serving_broadcast(BroadcastReply::Accepted {
            transaction_id: "abc123".to_string(),
        });
        let outcome = engine_for(&node).broadcast(push()).expect("the node answered");

        assert!(outcome.accepted);
        assert_eq!(outcome.transaction_id.as_deref(), Some("abc123"));
        assert_eq!(outcome.rejection, None);
        let sent = node.received();
        assert!(sent.contains("control.wallet.broadcast"));
        assert!(sent.contains(SIGNED_BUNDLE), "the signed bytes must travel");
    }

    /// **A mempool that looked at the bundle and said no is a VALUE, not an error** — and it
    /// carries the reason, because "retry the same bundle" and "build a new one" are opposite
    /// remedies.
    ///
    /// The nearest wrong implementation turns any non-acceptance into an `Err`, which would make a
    /// double-spend indistinguishable from a dropped network connection.
    #[test]
    fn a_mempool_refusal_is_an_answer_carrying_its_reason() {
        let node = FakeNode::serving_broadcast(BroadcastReply::RefusedByMempool {
            reason: "DOUBLE_SPEND".to_string(),
        });
        let outcome = engine_for(&node)
            .broadcast(push())
            .expect("a judged bundle is a successful call");

        assert!(!outcome.accepted);
        assert_eq!(outcome.rejection.as_deref(), Some("DOUBLE_SPEND"));
        assert_eq!(outcome.transaction_id, None);
    }

    /// **An authorization refusal on the PUSH means the token is missing — never "this node is too
    /// old".**
    ///
    /// The two reads are open, so a refusal on them can only come from a build that lacks them, and
    /// [`an_authorization_refusal_on_this_open_read_reads_as_an_older_node`] pins that. The push is
    /// token-gated, so the same symbol means the opposite thing, and telling this user to upgrade a
    /// node that already serves the method would send them after the wrong remedy entirely.
    ///
    /// The fixture varies ONE actor: the SAME node, serving the SAME method, asked once without a
    /// token and once with one. The control is what keeps this from passing because the fake is
    /// broken — a node that refused everybody would satisfy the first assertion on its own.
    #[test]
    fn an_authorization_refusal_on_the_push_names_the_token_not_the_node() {
        let node = FakeNode::serving_broadcast(BroadcastReply::Accepted {
            transaction_id: "abc123".to_string(),
        });

        let tokenless = NodeWalletEngine::new(node.endpoint(), None, Duration::from_secs(5));
        let refusal = tokenless
            .broadcast(push())
            .expect_err("a token-gated method refuses a tokenless caller");
        assert!(
            matches!(refusal, WalletError::EngineUnauthorized),
            "a gated method's refusal is about the token, not the build; got {refusal:?}"
        );

        assert!(
            engine_for(&node).broadcast(push()).is_ok(),
            "the control: the same node accepts the same push WITH a token"
        );
    }

    /// A build predating the push genuinely is too old, and that stays distinguishable from the
    /// token case above.
    #[test]
    fn an_older_node_that_cannot_push_reads_as_an_older_node() {
        let node = FakeNode::serving_broadcast(BroadcastReply::rejected(-32601, "METHOD_NOT_FOUND"));
        assert!(matches!(
            engine_for(&node).broadcast(push()),
            Err(WalletError::EngineUnsupported)
        ));
    }

    /// Read `asset`'s coins at the fixture address.
    fn read_coins(engine: &NodeWalletEngine, asset: Asset) -> Result<CoinsResponse, WalletError> {
        engine.coins(CoinsRequest {
            address: ADDRESS.to_string(),
            asset,
        })
    }

    /// **The poller reaches a real node end to end** — the path the shipped app takes: an
    /// `EngineState::Connected` from the status probe, an address, and a number out.
    #[test]
    fn the_poller_reads_a_real_balance_from_a_connected_node() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let poller =
            NodeBalance::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        assert_eq!(
            settle(&poller, &connected_to(&node)),
            BalanceReading::Known(Balances {
                xch_mojos: XCH_MOJOS,
                dig_units: DIG_UNITS,
            })
        );
    }

    /// **A read in flight must not hold the caller** (dig_ecosystem#2325).
    ///
    /// `observe` is called from the tray's twice-a-second repaint, so a chain read given a
    /// chain-sized budget can only be honest if nobody waits on it. The fixture's node is slow but
    /// perfectly healthy; the assertion is on ELAPSED TIME, which is the one thing a synchronous
    /// implementation cannot fake — it would return `Known` here, after the full delay.
    #[test]
    fn an_unfinished_read_returns_at_once_as_pending_and_lands_later() {
        const DELAY: Duration = Duration::from_millis(1_500);
        let node = FakeNode::serving_wallet_slowly(
            WalletReply::Balance {
                xch: XCH_MOJOS,
                dig: DIG_UNITS,
                synced: true,
            },
            DELAY,
        );
        let poller =
            NodeBalance::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        let link = connected_to(&node);

        let started = Instant::now();
        let immediate = poller.observe(&link, Some(ADDRESS));
        let waited = started.elapsed();

        assert_eq!(
            immediate,
            BalanceReading::Pending,
            "an unfinished read is neither a figure nor a fault"
        );
        assert!(
            waited < DELAY / 2,
            "the repaint waited {waited:?} on a read that takes {DELAY:?}"
        );
        assert_eq!(
            settle(&poller, &link),
            BalanceReading::Known(Balances {
                xch_mojos: XCH_MOJOS,
                dig_units: DIG_UNITS,
            }),
            "the figure must arrive once the node answers"
        );
    }

    /// **A refresh does not blank the figure it is refreshing** (dig-app#123 review).
    ///
    /// `SPEC.md` requires the caller receive the pending state *or the reading already held for
    /// that address*, and the whole point of the second half is a figure the user is looking at
    /// surviving its own ten-second re-read. The nearest wrong implementation returns `Pending` the
    /// moment a reading goes stale, so the balance blinks to "checking…" on every refresh cycle —
    /// and no other test can see it, because [`settle`] loops until the answer is not pending and is
    /// therefore blind to an intermediate blank by construction.
    ///
    /// The fixture is built to make that blink unavoidable if it exists: a refresh window shorter
    /// than the read it triggers, so there is a window in which a read IS in flight for an address
    /// that already has a figure. The final request count is what keeps the test from passing for
    /// the wrong reason — a poller that never refreshed at all would return the same stale figure.
    #[test]
    fn a_refresh_in_flight_keeps_showing_the_figure_it_is_refreshing() {
        const READ_TAKES: Duration = Duration::from_millis(600);
        let node = FakeNode::serving_wallet_slowly(
            WalletReply::Balance {
                xch: XCH_MOJOS,
                dig: DIG_UNITS,
                synced: true,
            },
            READ_TAKES,
        );
        // Shorter than one read, so the reading is due a refresh before the refresh can finish.
        let poller = NodeBalance::with_token_reader(
            Duration::from_millis(50),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        let held = BalanceReading::Known(Balances {
            xch_mojos: XCH_MOJOS,
            dig_units: DIG_UNITS,
        });
        assert_eq!(settle(&poller, &link), held, "the first read must land");

        // Now stale. This observation starts the re-read and must answer with the figure on screen.
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            poller.observe(&link, Some(ADDRESS)),
            held,
            "a balance the user is looking at must not blink to 'checking' while it is re-read"
        );
        // ...and stays that way for the WHOLE of the re-read, not merely on its first instant.
        //
        // Waiting on the server's own count rather than on [`settle`] is the load-bearing choice
        // here: `settle` returns the moment the answer is not pending, which a stale-but-known
        // reading already is, so it would return instantly and this loop would never observe the
        // re-read it is supposed to be watching. Two calls per read, so a completed second read is
        // four — and the assertion inside the loop is what proves the figure never blinked while it
        // was happening.
        let deadline = Instant::now() + Duration::from_secs(30);
        while node.request_count() < 4 && Instant::now() < deadline {
            assert_eq!(
                poller.observe(&link, Some(ADDRESS)),
                held,
                "the figure blinked away mid-refresh"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            node.request_count() >= 4,
            "no re-read ever completed, so nothing above was actually exercised: {} calls",
            node.request_count()
        );
    }

    /// **A slow node is asked ONCE**, however many repaints happen while it thinks.
    ///
    /// Without in-flight de-duplication the twice-a-second repaint would stack a fresh pair of chain
    /// reads on top of every unfinished one — the pile-up the generous
    /// [`BALANCE_READ_TIMEOUT`] would otherwise make possible. Counted at the SERVER.
    #[test]
    fn repaints_during_a_slow_read_do_not_stack_more_reads_on_the_node() {
        let node = FakeNode::serving_wallet_slowly(
            WalletReply::Balance {
                xch: XCH_MOJOS,
                dig: DIG_UNITS,
                synced: true,
            },
            Duration::from_millis(800),
        );
        let poller =
            NodeBalance::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        let link = connected_to(&node);

        for _ in 0..12 {
            assert_eq!(
                poller.observe(&link, Some(ADDRESS)),
                BalanceReading::Pending
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(matches!(settle(&poller, &link), BalanceReading::Known(_)));
        assert_eq!(
            node.request_count(),
            2,
            "one read means two calls — one per asset — no matter how often the tray repainted"
        );
    }

    /// Observe until the poller has something other than a pending read, or give up.
    ///
    /// The deadline is generous because it only bounds a HANG: a test that is going to pass does so
    /// as soon as the fake node answers.
    fn settle(poller: &NodeBalance, link: &EngineState) -> BalanceReading {
        settle_for(poller, link, ADDRESS)
    }

    /// [`settle`], for an account other than the fixture's usual one.
    fn settle_for(poller: &NodeBalance, link: &EngineState, address: &str) -> BalanceReading {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match poller.observe(link, Some(address)) {
                BalanceReading::Pending if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                settled => return settled,
            }
        }
    }

    /// With no node, the poller says so without inventing a read failure.
    #[test]
    fn the_poller_reports_no_node_when_disconnected() {
        let poller = NodeBalance::default();
        let link = EngineState::Disconnected {
            reason: "nothing answered".to_string(),
        };
        assert_eq!(
            poller.observe(&link, Some(ADDRESS)),
            BalanceReading::Unknown(BalanceUnknown::NoNode)
        );
    }

    /// **The throttle actually throttles.** Two observations inside one refresh window must reach
    /// the node ONCE — otherwise the tray's twice-a-second repaint becomes twice-a-second chain
    /// reads, which the node rate-limits.
    ///
    /// Counted at the SERVER, because a client-side count would only prove the client's own idea of
    /// what it sent.
    #[test]
    fn a_second_observation_inside_the_window_does_not_ask_the_node_again() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let poller = NodeBalance::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        let first = settle(&poller, &link);
        let second = poller.observe(&link, Some(ADDRESS));

        assert_eq!(first, second);
        // Two assets = two calls for the ONE read that happened. A second read would make it four.
        assert_eq!(
            node.request_count(),
            2,
            "the second observation must be served from cache"
        );
    }

    /// **A different address is a different question.** Without this, switching accounts would show
    /// the previous account's money — the fixture varies ONE thing (the address) against a cache
    /// that is otherwise still fresh.
    #[test]
    fn a_changed_address_invalidates_the_cache() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let poller = NodeBalance::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        settle(&poller, &link);
        settle_for(&poller, &link, "xch1someoneelse");
        assert_eq!(
            node.request_count(),
            4,
            "a balance cached for one address must not be reported for another"
        );
    }

    /// A stale cache from a previous account must not survive into a state with no address at all.
    #[test]
    fn losing_the_address_drops_the_cached_reading() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let poller = NodeBalance::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        assert!(matches!(settle(&poller, &link), BalanceReading::Known(_)));
        assert_eq!(
            poller.observe(&link, None),
            BalanceReading::Pending,
            "with no address nothing is being asked, which is neither a figure nor a fault"
        );
        // And the dropped cache is genuinely gone: the next observation asks again.
        settle(&poller, &link);
        assert_eq!(node.request_count(), 4);
    }

    /// The poller presents no token when the install has none — the open-read path, end to end.
    #[test]
    fn the_poller_works_without_a_control_token() {
        let node = FakeNode::serving_wallet(WalletReply::Balance {
            xch: XCH_MOJOS,
            dig: DIG_UNITS,
            synced: true,
        });
        let poller =
            NodeBalance::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), no_token);
        assert!(matches!(
            settle(&poller, &connected_to(&node)),
            BalanceReading::Known(_)
        ));
    }

    /// An `EngineState` naming `node` as the endpoint that answered the §5.3 status probe.
    fn connected_to(node: &FakeNode) -> EngineState {
        EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }
}
