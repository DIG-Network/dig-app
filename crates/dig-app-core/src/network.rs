//! Where this node STANDS on the two networks it belongs to — the header strip's chain-sync badge
//! and its two peer counts (dig_ecosystem#2569).
//!
//! # Two networks, never one number
//!
//! dig-node participates in two entirely separate networks, and a single *peers: N* would be a lie
//! about both:
//!
//! - the **DIG** content network — the peers this node exchanges capsules with
//!   ([`NetworkStanding::dig_peers`], from `control.peerCounts`);
//! - the **Chia** network — the full nodes the wallet reads the blockchain through
//!   ([`NetworkStanding::chia_peers`], the same observation `control.wallet.syncStatus` reports).
//!
//! A person told *1 peer* cannot tell which of the two is healthy, and on a default install the
//! honest answer is that one is at zero and the other at one — two different problems with two
//! different remedies. So both are read, both are labelled, and they are NEVER added together.
//!
//! The Chia count and the sync badge are one story, which is why they are read together here: a
//! count below the node's peer-trust quorum is not *one peer, fine*, it is the REASON nothing is
//! syncing (dig_ecosystem#2568). No threshold is compared against in this crate — the node owns
//! that number — so the count is rendered as a count and the verdict is left to the badge.
//!
//! # The state the node cannot name, and why this module exists
//!
//! `control.wallet.syncStatus` reports one of three phases. On a DEFAULT install the honest answer
//! is a fourth thing it has no word for: peers discovered by the node are denied write authority, so
//! the replica's initial catch-up never completes and its peak height stays `null` **forever**
//! (dig-node `crates/dig-wallet/src/sage/service.rs:173-180`; filed as dig_ecosystem#2568). The node
//! therefore reports `phase: "syncing"` for a machine on which nothing will ever finish syncing, and
//! a client that renders that phase as a spinner is asserting progress that cannot happen.
//!
//! **This module does not invent the missing state.** It derives only what the wire honestly
//! supports, and the derivation turns on a fact the phase does not carry: whether the replica has
//! reached ANY height at all.
//!
//! - a height, and a completed catch-up → [`ChainSync::Synced`];
//! - a height, and a sync still running → [`ChainSync::Syncing`] — genuinely progressing, because
//!   there is a block behind the claim;
//! - **no height at all** → [`ChainSync::NoProgress`], which never says *syncing*. It is the state
//!   a default install is permanently in, and it is also, briefly, the state of a sync in its first
//!   seconds. Those two are not distinguishable from the wire, so the word chosen is true of BOTH
//!   and asserts neither: it reports that the replica has no chain height, which is a fact, rather
//!   than guessing at a cause, which would be the client inventing the state #2568 has to add.
//!
//! The real fix is node-side: until #2568 lands, no client can tell *cannot sync here* from *has not
//! got anywhere yet*, and any client that claims to is guessing.
//!
//! # Why a poller and not a read at paint time
//!
//! The window snapshot is taken twice a second and this is a node round trip. [`NodeChainSync`] owns
//! the cadence exactly as [`NodeHostedStores`](crate::hosted_stores::NodeHostedStores) does: it
//! answers from cache immediately, refreshes on a worker thread, and de-duplicates so a slow node is
//! asked once however many repaints happen while it thinks.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::{PeerCountsParams, WalletSyncStatusParams};
use dig_node_control_interface::results::{
    PeerCountsResult, WalletSyncPhase, WalletSyncStatusResult,
};

use crate::control::{self, ControlCallError, ControlFailure};
use crate::engine::EngineState;

/// How long a sync reading is reused before the node is asked again.
///
/// Five seconds, which is the shortest cadence of the three pollers. It is deliberately shorter than
/// the balance's ten: this is the reading a person watches to see whether anything is HAPPENING, and
/// a progress indication that updates every ten seconds reads as frozen. The call itself is a local
/// answer from the node's own replica state rather than a chain round trip, so the cost of asking
/// more often is a loopback request.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// How long ONE sync read may take before it is abandoned.
///
/// The node answers this from state it already holds — no chain read, no disk walk — so a healthy
/// node is quick. Five seconds is a bound on a node that has wedged, not a budget fitted to a
/// measurement; nothing waits on it, because the read runs on its own thread.
pub const SYNC_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What the app can honestly say about the node's wallet chain replica.
///
/// See the module docs for why [`NoProgress`](Self::NoProgress) is worded the way it is, and why
/// there is no variant meaning *this machine can never sync*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSync {
    /// Nobody has asked a node yet. Not a fault, and not a claim about the chain.
    Pending,
    /// The catch-up completed, a Chia peer is attached, and the replica has a height.
    ///
    /// Carries the height because the contract forbids a `Synced` with no height: a node records its
    /// peak BEFORE it marks catch-up complete, so a heightless `Synced` describes a state no
    /// conforming node can be in — and this type declines to be able to express it.
    Synced {
        /// The replica's own peak height.
        peak_height: u32,
    },
    /// A sync is running AND has reached a block, so there is something behind the claim.
    Syncing {
        /// The replica's own peak height so far.
        peak_height: u32,
    },
    /// The replica has reached NO height. Never rendered as progress — see the module docs.
    NoProgress(NoProgress),
    /// No sync is running in this process, though the wallet database remembers a height.
    ///
    /// Explicitly legitimate per the contract: a node that synced yesterday and has just restarted
    /// reports exactly this, and reports it truthfully.
    Idle {
        /// The height the replica reached before the sync stopped running.
        peak_height: u32,
    },
    /// No reading could be taken, and which thing was missing.
    Unknown(SyncUnknown),
}

impl Default for ChainSync {
    /// Before anything has been asked the answer is [`Pending`](Self::Pending) — not a fault, and
    /// certainly not "synced".
    fn default() -> Self {
        Self::Pending
    }
}

/// Why the replica has no height to show. **One variant per remedy.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoProgress {
    /// A sync is nominally running and the node is connected to NO Chia peers, so nothing can be
    /// fetched. The contract names this case itself: `chia_peer_count: 0` beside `Syncing` is the
    /// honest "syncing — no peers" state, and a bare "syncing" over it implies progress that is not
    /// happening.
    NoPeers,
    /// A sync is nominally running, at least one peer is attached, and the replica has still reached
    /// no block. This is the state a default install is permanently in (dig_ecosystem#2568).
    NoHeight,
    /// No sync is running and the wallet database remembers no height either — a wallet that has
    /// never synced at all.
    NeverStarted,
}

/// Why no sync reading is available. **One variant per remedy**, never per rough category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncUnknown {
    /// No node is connected at all, so there is nothing to ask.
    NoNode,
    /// A node answered and does not serve this method — a build older than dig-node 0.109.0. The
    /// remedy is an upgrade.
    NodeCannotRead,
    /// The socket opened and the read overran its budget. Kept apart from
    /// [`Unreachable`](Self::Unreachable) because only that one is evidence about whether a node
    /// exists (dig_ecosystem#2325).
    TimedOut(String),
    /// The node could not be reached for this read — it stopped between the status probe and now.
    Unreachable(String),
    /// The node refused for a reason we cannot classify; its own words are carried.
    ReadFailed(String),
}

impl SyncUnknown {
    /// Every reason, for the tests that must cover all of them.
    ///
    /// Hand-listed because the variants carry payloads, and asserted complete by
    /// `every_reason_is_in_all` — without which a sixth reason would ship with no coverage while
    /// every test stayed green. Same device and same reason as
    /// [`HostedStoresUnknown::all`](crate::hosted_stores::HostedStoresUnknown::all).
    #[cfg(test)]
    pub(crate) fn all() -> Vec<Self> {
        vec![
            Self::NoNode,
            Self::NodeCannotRead,
            Self::TimedOut("the read took longer than 5s".to_string()),
            Self::Unreachable("connection refused".to_string()),
            Self::ReadFailed("the node fell over".to_string()),
        ]
    }
}

impl ChainSync {
    /// Read the node's answer as the honest state it supports.
    ///
    /// # The one judgement made here
    ///
    /// A `Syncing` phase is split on whether the replica has a HEIGHT, and a heightless one is
    /// reported as [`NoProgress`](Self::NoProgress) rather than as progress. That is not a guess
    /// about the node's configuration — it is the wire's own two facts read together, and it is what
    /// keeps a permanently-stuck default install (dig_ecosystem#2568) from being drawn as a machine
    /// that is getting somewhere.
    ///
    /// A `Synced` with no height is a state the contract says a conforming node MUST NOT emit. It is
    /// still handled, and handled as [`NoProgress::NoHeight`] rather than as `Synced`: a claim of
    /// being caught up with no block behind it is the one reading this surface must never render.
    pub fn of_status(status: &WalletSyncStatusResult) -> Self {
        let no_peers = status.chia_peer_count == Some(0);
        match (status.phase, status.peak_height) {
            (WalletSyncPhase::Synced, Some(peak_height)) => Self::Synced { peak_height },
            (WalletSyncPhase::NotStarted, Some(peak_height)) => Self::Idle { peak_height },
            (WalletSyncPhase::NotStarted, None) => Self::NoProgress(NoProgress::NeverStarted),
            (_, Some(peak_height)) => Self::Syncing { peak_height },
            (_, None) if no_peers => Self::NoProgress(NoProgress::NoPeers),
            (_, None) => Self::NoProgress(NoProgress::NoHeight),
        }
    }

    /// The badge word for this reading, or `None` for a state the strip must stay silent about.
    ///
    /// Silence is a real answer here. A node nobody has reached, or one too old to serve the method,
    /// licenses no claim about syncing at all — and a badge reading "Unknown" beside two badges that
    /// carry real facts costs a person a glance to learn nothing.
    pub fn badge(&self) -> Option<(&'static str, ChainSyncTone)> {
        match self {
            Self::Synced { .. } => Some((SYNC_SYNCED, ChainSyncTone::Good)),
            Self::Syncing { .. } => Some((SYNC_SYNCING, ChainSyncTone::Neutral)),
            Self::NoProgress(NoProgress::NoPeers) => Some((SYNC_NO_PEERS, ChainSyncTone::Warn)),
            Self::NoProgress(NoProgress::NoHeight) => Some((SYNC_NO_HEIGHT, ChainSyncTone::Warn)),
            Self::NoProgress(NoProgress::NeverStarted) => {
                Some((SYNC_NOT_RUNNING, ChainSyncTone::Warn))
            }
            Self::Idle { .. } => Some((SYNC_NOT_RUNNING, ChainSyncTone::Warn)),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// How worried to be about a sync reading.
///
/// A tiny mirror of the pane layer's own `Tone`, declared here rather than imported because this
/// module is above the GUI and must not depend on it. [`crate::confirm::gui`] maps one to the other
/// in one place, and a test pins the two enums to the same shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSyncTone {
    /// Nothing to do.
    Good,
    /// Working, and not a fault.
    Neutral,
    /// Something a person may need to act on.
    Warn,
}

/// How many peers this node holds on ONE network, or why that is not known.
///
/// The four states are [`BalanceReading`](crate::wallet::overview::BalanceReading)'s split applied
/// to connectivity, and for the same reason: **an unknown count is not zero.** Drawing `0 peers`
/// because a node could not be asked is the money-lie pattern pointed at the network — it reports a
/// fault that may not exist, and it reports it in exactly the shape of a real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCount {
    /// Nobody has asked yet.
    Pending,
    /// The node answered with a count. `0` is an OBSERVED zero — a real finding, and usually the
    /// interesting one.
    Known(u32),
    /// The node answered and cannot observe this count at all. A fact about the node, not about the
    /// network, and it licenses no claim about connectivity either way.
    Unobservable,
    /// Nobody could be asked, and why.
    Unknown(SyncUnknown),
}

impl Default for PeerCount {
    fn default() -> Self {
        Self::Pending
    }
}

impl PeerCount {
    /// Read one nullable wire count: `null` is [`Unobservable`](Self::Unobservable), never zero.
    fn of_wire(count: Option<u32>) -> Self {
        match count {
            Some(count) => Self::Known(count),
            None => Self::Unobservable,
        }
    }

    /// The badge word for this count, or `None` for a state the strip must stay silent about.
    ///
    /// Silence rather than a placeholder, exactly as [`ChainSync::badge`] is silent: a badge reading
    /// an em dash beside badges carrying real facts costs a glance and teaches nothing, and any
    /// digit at all would be a number nobody measured.
    ///
    /// A zero is drawn as [`ChainSyncTone::Warn`]. It is a working network's failure state on both
    /// networks — no capsules can be exchanged, and no chain can be read — so colouring it as
    /// ordinary would be the surface disagreeing with the sync badge sitting next to it.
    pub fn badge(&self) -> Option<(String, ChainSyncTone)> {
        match self {
            Self::Known(0) => Some(("0".to_string(), ChainSyncTone::Warn)),
            Self::Known(count) => Some((count.to_string(), ChainSyncTone::Good)),
            Self::Unobservable => Some((PEERS_UNOBSERVABLE.to_string(), ChainSyncTone::Neutral)),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// Everything this node can say about its standing on both networks, from one refresh.
///
/// Read together rather than as three independent pollers because they are read from one node at one
/// instant, and a strip whose badges came from three different moments could show a peer count that
/// contradicts the sync state beside it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkStanding {
    /// How the wallet's chain replica is doing.
    pub sync: ChainSync,
    /// Peers on the DIG content network.
    pub dig_peers: PeerCount,
    /// Chia full nodes the wallet reads the chain through.
    pub chia_peers: PeerCount,
}

impl NetworkStanding {
    /// The standing of a node nobody could reach, with `reason` given for all three readings.
    fn unavailable(reason: SyncUnknown) -> Self {
        Self {
            sync: ChainSync::Unknown(reason.clone()),
            dig_peers: PeerCount::Unknown(reason.clone()),
            chia_peers: PeerCount::Unknown(reason),
        }
    }
}

/// The label the strip puts before the DIG peer count.
///
/// Names the NETWORK, not merely "peers". The two counts are meaningless — actively misleading —
/// without knowing which network each one is about.
pub const DIG_PEERS_LABEL: &str = "DIG peers";
/// The label the strip puts before the Chia peer count.
pub const CHIA_PEERS_LABEL: &str = "Chia peers";
/// The badge word for a count the node cannot observe.
pub const PEERS_UNOBSERVABLE: &str = "Not reported";

/// The badge word for a replica that is caught up and connected.
pub const SYNC_SYNCED: &str = "Chain synced";
/// The badge word for a sync that is running and has reached a block.
pub const SYNC_SYNCING: &str = "Chain syncing";
/// The badge word for a sync running with no Chia peer to fetch from.
pub const SYNC_NO_PEERS: &str = "No chain peers";
/// The badge word for a replica that has reached no block at all.
///
/// Deliberately a statement of FACT rather than of cause. It is true of a permanently-stuck default
/// install (dig_ecosystem#2568) and of a sync in its first seconds alike, and the wire cannot tell
/// those apart — so it says the thing that is true of both, and never the word "syncing", which is
/// true of only one.
pub const SYNC_NO_HEIGHT: &str = "No chain height";
/// The badge word for a replica with no sync running.
pub const SYNC_NOT_RUNNING: &str = "Chain sync idle";

/// The `data.code` symbols meaning "this build does not serve the method at all".
///
/// Taken from the contract crate rather than retyped, so a rename upstream is a compile error here
/// instead of a silently unmatched string.
const CANNOT_SERVE: &[&str] = &[
    ControlErrorCode::MethodNotFound.name(),
    ControlErrorCode::NotSupported.name(),
];

/// Turn a control-plane failure into the typed reason the surface renders from.
///
/// Keyed on the stable UPPER_SNAKE `data.code`, never on the human message — the message is
/// explicitly not contract-stable, so matching on its words would break on a reword.
///
/// `control.wallet.syncStatus` is an OPEN read
/// ([`ControlMethod::is_open_read`](dig_node_control_interface::method::ControlMethod::is_open_read)),
/// so an `UNAUTHORIZED` here cannot mean *present the token*: only a node build that predates the
/// method and gates it generically can produce it, and the remedy is an upgrade. It is therefore
/// classified as [`SyncUnknown::NodeCannotRead`], not as a permission fault — pointing a person at a
/// token they do not need is worse than saying nothing.
fn classify(failure: ControlFailure) -> SyncUnknown {
    match failure {
        ControlFailure::Transport(ControlCallError::Unreachable(detail)) => {
            SyncUnknown::Unreachable(detail)
        }
        ControlFailure::Transport(ControlCallError::TimedOut(detail)) => {
            SyncUnknown::TimedOut(detail)
        }
        ControlFailure::Transport(ControlCallError::HttpRefused {
            code: 401 | 403, ..
        }) => SyncUnknown::NodeCannotRead,
        ControlFailure::Transport(e) => SyncUnknown::ReadFailed(e.to_string()),
        ControlFailure::Rejected(e)
            if CANNOT_SERVE.contains(&e.data.code.as_str())
                || e.data.code == ControlErrorCode::Unauthorized.name() =>
        {
            SyncUnknown::NodeCannotRead
        }
        ControlFailure::Rejected(e) => SyncUnknown::ReadFailed(e.message),
    }
}

/// Read this node's standing on both networks, once.
///
/// Two calls, because the two networks are two facts and the contract answers them separately. The
/// Chia count is taken from `control.peerCounts` rather than from the sync reading, even though both
/// carry it: the contract requires a conforming node to serve them from ONE source, so reading it in
/// one place here means the two cannot come to disagree inside this app.
///
/// Separated from the poller so the derivation and the classification above are testable against a
/// real socket without a cadence in the way.
fn read_once(endpoint: &str, token: Option<&str>, timeout: Duration) -> NetworkStanding {
    let sync = match control::call_control_result(endpoint, &WalletSyncStatusParams {}, token, timeout)
    {
        Ok(result) => ChainSync::of_status(&result),
        Err(failure) => ChainSync::Unknown(classify(failure)),
    };
    let (dig_peers, chia_peers) =
        match control::call_control_result(endpoint, &PeerCountsParams {}, token, timeout) {
            Ok(PeerCountsResult {
                dig_peer_count,
                chia_peer_count,
            }) => (
                PeerCount::of_wire(dig_peer_count),
                PeerCount::of_wire(chia_peer_count),
            ),
            Err(failure) => {
                let reason = classify(failure);
                (
                    PeerCount::Unknown(reason.clone()),
                    PeerCount::Unknown(reason),
                )
            }
        };
    NetworkStanding {
        sync,
        dig_peers,
        chia_peers,
    }
}

/// This node's standing on both networks, polled no more often than [`REFRESH_INTERVAL`].
///
/// Lives beside the tray's status handle and is asked for a reading on every snapshot. It answers
/// from its cache and does the real read on a WORKER THREAD, so a caller never waits on the node.
///
/// Holding this here rather than in the shell is deliberate: the shell is a binary, and a binary is
/// a test-free zone.
pub struct NodeNetworkStanding {
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
    /// The last reading taken, and the endpoint + instant it was taken at.
    cached: Option<Cached>,
    /// The endpoint a worker is currently reading from, if any — the de-duplication that keeps a
    /// twice-a-second snapshot from stacking reads on a node already answering one.
    in_flight: Option<String>,
}

impl PollState {
    /// The reading held for `endpoint` and how long ago it was taken.
    ///
    /// `None` when the last reading came from a DIFFERENT node: a chain replica belongs to one node,
    /// so carrying one node's progress over to another would report a height the new node never
    /// reached.
    fn reading_for(&self, endpoint: &str) -> Option<(NetworkStanding, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.endpoint == endpoint)
            .map(|c| (c.reading.clone(), c.taken.elapsed()))
    }
}

/// A reading and the endpoint + instant it was taken for.
struct Cached {
    endpoint: String,
    reading: NetworkStanding,
    taken: Instant,
}

impl Default for NodeNetworkStanding {
    fn default() -> Self {
        Self::new(REFRESH_INTERVAL, SYNC_READ_TIMEOUT)
    }
}

impl NodeNetworkStanding {
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

    /// The freshest reading for the currently linked node. **Never blocks.**
    ///
    /// With no node there is nothing to ask, so the held reading is dropped — a height from a node
    /// that has since gone away must not outlive it — and the answer names the absent node.
    pub fn observe(&self, link: &EngineState) -> NetworkStanding {
        let EngineState::Connected { endpoint, .. } = link else {
            let mut state = self.lock();
            state.cached = None;
            return NetworkStanding::unavailable(SyncUnknown::NoNode);
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.reading_for(endpoint) {
            if age < self.refresh {
                return fresh;
            }
        }

        self.start_read(&mut state, endpoint);
        // The reading already held for this node while its refresh runs — showing it beats blanking
        // the badge every five seconds. Only a first read has genuinely nothing to state.
        state
            .reading_for(endpoint)
            .map(|(reading, _)| reading)
            .unwrap_or_default()
    }

    /// Begin a read from `endpoint` unless one is already under way for it.
    fn start_read(&self, state: &mut PollState, endpoint: &str) {
        if state.in_flight.as_deref() == Some(endpoint) {
            return;
        }
        state.in_flight = Some(endpoint.to_string());

        let shared = Arc::clone(&self.state);
        let endpoint = endpoint.to_string();
        let token = (self.read_token)();
        let timeout = self.timeout;
        std::thread::spawn(move || {
            let reading = read_once(&endpoint, token.as_deref(), timeout);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.cached = Some(Cached {
                endpoint: endpoint.clone(),
                reading,
                taken: Instant::now(),
            });
            // Cleared only if it is still OUR read: the link may have moved to a different node
            // while we waited, in which case a later worker owns the slot.
            if state.in_flight.as_deref() == Some(endpoint.as_str()) {
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
    use crate::test_support::node::{FakeNode, SyncReply};

    /// The node's answer, with every field named so a fixture cannot silently reuse a default.
    fn wire(
        phase: WalletSyncPhase,
        peak_height: Option<u32>,
        chia_peer_count: Option<u32>,
    ) -> WalletSyncStatusResult {
        WalletSyncStatusResult {
            phase,
            peak_height,
            chia_peer_count,
        }
    }

    /// **The machine every user actually has is NOT drawn as progress** (dig_ecosystem#2569, #2568).
    ///
    /// The fixture is the reading measured on a real default install: `phase: syncing`,
    /// `peak_height: null`, `chia_peer_count: 1`. On such a machine the replica never completes,
    /// because discovered peers are denied write authority — so the phase describes a PERMANENT
    /// state, and a client that renders it as a spinner asserts progress that will never occur.
    ///
    /// The control is the same phase WITH a height. It varies one field, and it is what makes this
    /// test able to see the defect: a derivation that read the phase alone would give both fixtures
    /// the same word, and a test driven only by the stuck case would be satisfied by a client that
    /// says "no progress" about every sync there has ever been.
    #[test]
    fn a_syncing_node_with_no_height_is_never_reported_as_syncing() {
        let stuck = ChainSync::of_status(&wire(WalletSyncPhase::Syncing, None, Some(1)));
        assert_eq!(stuck, ChainSync::NoProgress(NoProgress::NoHeight));
        let (stuck_word, stuck_tone) = stuck.badge().expect("the strip must say something");
        assert_eq!(stuck_word, SYNC_NO_HEIGHT);
        assert_eq!(stuck_tone, ChainSyncTone::Warn);
        assert_ne!(
            stuck_word, SYNC_SYNCING,
            "a replica that has reached no block is being told it is making progress"
        );

        let moving = ChainSync::of_status(&wire(WalletSyncPhase::Syncing, Some(6_000_123), Some(1)));
        assert_eq!(
            moving,
            ChainSync::Syncing {
                peak_height: 6_000_123
            }
        );
        assert_eq!(moving.badge().map(|(word, _)| word), Some(SYNC_SYNCING));
        assert_ne!(
            moving.badge(),
            stuck.badge(),
            "a sync that has reached a block reads the same as one that has not, so the badge \
             cannot distinguish progress from a permanently stuck replica"
        );
    }

    /// **Every phase gets its own reading, and no two states share a word.**
    ///
    /// The exhaustive control for the test above. A derivation that collapsed two states would leave
    /// a person unable to tell "nothing is running" from "running and getting nowhere", which are
    /// different problems with different remedies.
    #[test]
    fn no_two_sync_states_are_shown_the_same_word() {
        let states = [
            ChainSync::of_status(&wire(WalletSyncPhase::Synced, Some(6_000_000), Some(4))),
            ChainSync::of_status(&wire(WalletSyncPhase::Syncing, Some(5_999_000), Some(4))),
            ChainSync::of_status(&wire(WalletSyncPhase::Syncing, None, Some(0))),
            ChainSync::of_status(&wire(WalletSyncPhase::Syncing, None, Some(2))),
            ChainSync::of_status(&wire(WalletSyncPhase::NotStarted, Some(4_000_000), Some(0))),
        ];
        let expected = [
            ChainSync::Synced {
                peak_height: 6_000_000,
            },
            ChainSync::Syncing {
                peak_height: 5_999_000,
            },
            ChainSync::NoProgress(NoProgress::NoPeers),
            ChainSync::NoProgress(NoProgress::NoHeight),
            ChainSync::Idle {
                peak_height: 4_000_000,
            },
        ];
        assert_eq!(states.to_vec(), expected.to_vec());

        let mut words: Vec<&str> = states
            .iter()
            .map(|state| state.badge().expect("every real reading has a word").0)
            .collect();
        let total = words.len();
        words.sort_unstable();
        words.dedup();
        assert_eq!(
            words.len(),
            total,
            "two sync states are shown the same word: {words:?}"
        );
    }

    /// **A node that claims to be synced with no height is not believed.**
    ///
    /// The contract says a conforming node MUST NOT emit this pair, which is exactly why it is worth
    /// pinning: an unreachable state is where a client quietly renders the most reassuring word it
    /// has. "Caught up" with no block behind it is the one claim this surface must never make.
    #[test]
    fn a_synced_phase_with_no_height_is_not_reported_as_synced() {
        let impossible = ChainSync::of_status(&wire(WalletSyncPhase::Synced, None, Some(3)));
        assert_ne!(impossible.badge().map(|(word, _)| word), Some(SYNC_SYNCED));
        assert_eq!(impossible, ChainSync::NoProgress(NoProgress::NoHeight));
    }

    /// **A state nothing is known about says nothing at all.**
    ///
    /// Both halves are the honesty rule: an unasked node is not a synced one, and a badge reading
    /// "Unknown" beside two badges carrying real facts costs a glance and teaches nothing.
    #[test]
    fn an_unread_state_draws_no_badge() {
        assert_eq!(ChainSync::default(), ChainSync::Pending);
        assert_eq!(ChainSync::Pending.badge(), None);
        for reason in SyncUnknown::all() {
            assert_eq!(
                ChainSync::Unknown(reason.clone()).badge(),
                None,
                "{reason:?} was drawn as a badge, which claims a fact nobody has"
            );
        }
    }

    /// **Every reason is in `all()`**, so the test above really covers the enum.
    #[test]
    fn every_reason_is_in_all() {
        let all = SyncUnknown::all();
        // Matched exhaustively so a new variant is a COMPILE error here rather than an untested one.
        for reason in [
            SyncUnknown::NoNode,
            SyncUnknown::NodeCannotRead,
            SyncUnknown::TimedOut(String::new()),
            SyncUnknown::Unreachable(String::new()),
            SyncUnknown::ReadFailed(String::new()),
        ] {
            let named = |candidate: &SyncUnknown| {
                std::mem::discriminant(candidate) == std::mem::discriminant(&reason)
            };
            assert!(all.iter().any(named), "{reason:?} is missing from all()");
        }
        assert_eq!(all.len(), 5, "all() has grown a duplicate or lost a variant");
    }

    /// **An older node's refusal points at an upgrade, never at a token.**
    ///
    /// `control.wallet.syncStatus` is an OPEN read, so `UNAUTHORIZED` can only come from a build that
    /// predates the method and gates everything generically. Classifying it as a permission fault
    /// would send a person to fix a token that was never the problem.
    #[test]
    fn an_unauthorized_refusal_on_an_open_read_reads_as_an_old_node() {
        use dig_node_control_interface::error::{ControlError, ControlErrorData};
        let refusal = |code: &str| {
            classify(ControlFailure::Rejected(ControlError {
                code: -32601,
                message: "no".to_string(),
                data: ControlErrorData {
                    code: code.to_string(),
                    origin: "node".to_string(),
                },
            }))
        };
        assert_eq!(
            refusal(ControlErrorCode::Unauthorized.name()),
            SyncUnknown::NodeCannotRead
        );
        assert_eq!(
            refusal(ControlErrorCode::MethodNotFound.name()),
            SyncUnknown::NodeCannotRead
        );
        assert_eq!(
            classify(ControlFailure::Transport(ControlCallError::TimedOut(
                "slow".to_string()
            ))),
            SyncUnknown::TimedOut("slow".to_string()),
            "a slow node must stay distinguishable from an absent one"
        );
    }

    /// **The poller reads the whole standing off a real socket, tokenless, and keeps the two
    /// networks apart.**
    ///
    /// Both methods are OPEN reads, so the fixture presents NO token: a client that only worked
    /// while holding one would fail here, which is the shape of the drift this asserts against.
    ///
    /// The fixture is this machine's real reading — a stuck sync, ZERO DIG peers and ONE Chia peer.
    /// The two counts differ, deliberately: a client that read one count and rendered it for both
    /// networks would pass on any fixture where they happened to agree, and would be telling a
    /// person their content network is healthy on the strength of a chain connection.
    #[test]
    fn the_poller_reads_both_networks_off_a_real_socket_without_a_token() {
        let node = FakeNode::serving_sync(SyncReply::Status {
            phase: "syncing".to_string(),
            peak_height: None,
            dig_peer_count: Some(0),
            chia_peer_count: Some(1),
        });
        let link = EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        };
        let poller = NodeNetworkStanding::with_token_reader(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || None,
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut reading = poller.observe(&link);
        while reading == NetworkStanding::default() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            reading = poller.observe(&link);
        }
        assert_eq!(reading.sync, ChainSync::NoProgress(NoProgress::NoHeight));
        assert_eq!(reading.dig_peers, PeerCount::Known(0));
        assert_eq!(reading.chia_peers, PeerCount::Known(1));
        assert_ne!(
            reading.dig_peers, reading.chia_peers,
            "the two networks were read as one number, so a healthy chain connection would be \
             reported as a healthy content network"
        );
    }

    /// **A null count is `Not reported`, and never a zero.**
    ///
    /// The whole point of the four-state reading. A node that cannot observe a count has made no
    /// claim about connectivity, and rendering that as `0` invents a fault — one shaped exactly like
    /// a real outage, which is what makes it expensive.
    #[test]
    fn a_count_the_node_cannot_observe_is_never_drawn_as_zero() {
        assert_eq!(PeerCount::of_wire(None), PeerCount::Unobservable);
        assert_eq!(PeerCount::of_wire(Some(0)), PeerCount::Known(0));

        let unobservable = PeerCount::Unobservable
            .badge()
            .expect("the node answered, so the strip has something to say");
        assert_eq!(unobservable.0, PEERS_UNOBSERVABLE);
        assert_ne!(
            unobservable.0, "0",
            "a count nobody could observe was drawn as an observed zero"
        );
        assert_eq!(
            unobservable.1,
            ChainSyncTone::Neutral,
            "a count the node cannot report is not a fault of the network"
        );

        let observed_zero = PeerCount::Known(0)
            .badge()
            .expect("an observed zero is a real finding");
        assert_eq!(observed_zero, ("0".to_string(), ChainSyncTone::Warn));
        assert_eq!(
            PeerCount::Known(6).badge(),
            Some(("6".to_string(), ChainSyncTone::Good))
        );
    }

    /// **A count nobody could ask for draws nothing at all.**
    ///
    /// The counterpart of [`ChainSync::badge`]'s silence, and the reason the reading has four states
    /// rather than three: `Pending` and `Unknown` are both "we have no number", and neither may be
    /// rendered as one.
    #[test]
    fn an_unasked_count_draws_no_badge() {
        assert_eq!(PeerCount::default(), PeerCount::Pending);
        assert_eq!(PeerCount::Pending.badge(), None);
        for reason in SyncUnknown::all() {
            assert_eq!(
                PeerCount::Unknown(reason.clone()).badge(),
                None,
                "{reason:?} was drawn as a peer count, which claims a number nobody has"
            );
        }
        let lost = NetworkStanding::unavailable(SyncUnknown::NoNode);
        assert_eq!(lost.dig_peers, PeerCount::Unknown(SyncUnknown::NoNode));
        assert_eq!(lost.chia_peers, PeerCount::Unknown(SyncUnknown::NoNode));
        assert_eq!(lost.sync, ChainSync::Unknown(SyncUnknown::NoNode));
    }

    /// **A node that refuses the reads reports UNKNOWN counts, never zeros** (dig_ecosystem#2569).
    ///
    /// Driven over the real socket, because the property is about what a refusal turns into on the
    /// way through the transport — the layer a pure-function test cannot see. A client that mapped a
    /// refusal onto `0` would put a red `0` beside both networks on a perfectly healthy machine
    /// whose control plane simply said no, which is a fault report about something that is not
    /// broken.
    #[test]
    fn a_refused_read_yields_unknown_counts_rather_than_zeros() {
        let node = FakeNode::serving_sync(SyncReply::Rejected {
            code: -32601,
            symbol: ControlErrorCode::MethodNotFound.name().to_string(),
        });
        let link = EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        };
        let poller = NodeNetworkStanding::with_token_reader(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || None,
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut reading = poller.observe(&link);
        while reading == NetworkStanding::default() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            reading = poller.observe(&link);
        }
        assert_eq!(
            reading.dig_peers,
            PeerCount::Unknown(SyncUnknown::NodeCannotRead)
        );
        assert_eq!(
            reading.chia_peers,
            PeerCount::Unknown(SyncUnknown::NodeCannotRead)
        );
        assert_eq!(reading.dig_peers.badge(), None, "a refusal was drawn as a count");
        assert_eq!(reading.sync.badge(), None);
    }

    /// **The two labels name their networks, and they are not the same string.**
    ///
    /// The whole ask: a person seeing `1` must be able to tell WHICH network it is about.
    #[test]
    fn each_count_is_labelled_with_the_network_it_is_about() {
        assert!(DIG_PEERS_LABEL.contains("DIG"));
        assert!(CHIA_PEERS_LABEL.contains("Chia"));
        assert_ne!(DIG_PEERS_LABEL, CHIA_PEERS_LABEL);
    }

    /// **A link with no node drops the held reading rather than carrying it forward.**
    ///
    /// A height belongs to one node. Reporting the last node's progress after it has gone away is
    /// the same class of lie as reporting a cached balance for a different account.
    #[test]
    fn losing_the_node_takes_the_reading_with_it() {
        let poller = NodeNetworkStanding::default();
        assert_eq!(
            poller.observe(&EngineState::Disconnected {
                reason: "no node".to_string()
            }),
            NetworkStanding::unavailable(SyncUnknown::NoNode)
        );
    }
}
