//! The stores this node holds — the Cache pane's list, read from `control.hostedStores.list`
//! (dig_ecosystem#2330).
//!
//! # Three states, never collapsed
//!
//! The counterpart of [`BalanceReading`](crate::wallet::overview::BalanceReading), for the same
//! reason and after the same defect. **A store list that could not be read is not an empty store
//! list.** Rendering "you are hosting nothing" because a read timed out is dig_ecosystem#2325 in a
//! different pane: a slow node reported as an absent one. So [`HostedStoresReading`] separates
//!
//! - [`Pending`](HostedStoresReading::Pending) — a read is under way and nothing has failed;
//! - [`Known(vec![])`](HostedStoresReading::Known) — the node ANSWERED, and it holds nothing;
//! - [`Unknown(reason)`](HostedStoresReading::Unknown) — nobody answered, and which thing was missing.
//!
//! A renderer has no path that turns an unknown into "0 stores", because they are different variants
//! and the empty one can only be built from a node's actual answer.
//!
//! # Why it is polled rather than read while the pane is drawn
//!
//! The window snapshot is taken twice a second and this is a node round trip. [`NodeHostedStores`]
//! owns the cadence exactly as [`NodeBalance`](crate::wallet::node::NodeBalance) does: it answers
//! from cache immediately, refreshes on a worker thread, and de-duplicates so a slow node is asked
//! once however many repaints happen while it thinks.
//!
//! # This read IS token-gated, unlike the balance
//!
//! `control.wallet.balance` is served as an open read; `control.hostedStores.list` is not. So an
//! `UNAUTHORIZED` refusal here means something real and fixable — this app cannot read the node's
//! control token — and it gets its own [`HostedStoresUnknown::Unauthorized`] rather than being folded
//! into "this node cannot answer", which would point the user at an upgrade that changes nothing.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::HostedStoresListParams;
use dig_node_control_interface::results::HostedStore as WireHostedStore;

use crate::control::{self, ControlCallError, ControlFailure};
use crate::engine::EngineState;

/// How long a hosted-store reading is reused before the node is asked again.
///
/// Longer than the balance's ten seconds because the answer moves far more slowly: a store joins or
/// leaves the cache when content is fetched or evicted, not on a chain's schedule. Thirty seconds
/// keeps an idle window at two reads a minute while still showing a newly cached store while the
/// person who fetched it is still looking.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How long ONE hosted-store read may take before it is abandoned.
///
/// Deliberately not [`control::DEFAULT_PROBE_TIMEOUT`] (1500 ms), which answers a different question
/// — how long a §5.3 tier may take to prove it is alive before the ladder falls through. This is not
/// a liveness probe: the node walks its on-disk cache index to build the list, so a machine with a
/// large cache on slow storage can legitimately take seconds.
///
/// Ten seconds is a deliberately generous bound rather than one fitted to a measurement — no timing
/// of this call on a large real cache exists yet, so the honest choice is a budget that cannot
/// plausibly be exceeded by a healthy node, with the read abandoned (and SAID to have been abandoned)
/// past it. Nothing waits on it: the read runs on its own thread, so a long tail costs a late list,
/// never a frozen window.
pub const STORES_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// One store this node holds, as a surface renders it.
///
/// A distillation of the contract crate's `HostedStore`, not a re-export, for the reason
/// [`NodeFacts`](crate::node_facts::NodeFacts) gives: this lands in
/// [`TrayView`](crate::tray_menu::TrayView), which is compared field by field on every tick, and the
/// upstream type carries a `capsules: Vec<CapsuleEntry>` — every cached capsule of every store, each
/// with a `last_used_unix_ms` that moves whenever content is served. Comparing that on every repaint
/// would make a busy node repaint the window continuously to show a list that did not visibly change.
///
/// The per-capsule detail is therefore DROPPED here rather than carried and ignored. A pane that ever
/// needs it should ask `control.hostedStores.status` for the one store a person opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedStore {
    /// The canonical lowercase 64-hex store id.
    pub store_id: String,
    /// Whether the operator has pinned this store, so it survives eviction.
    pub pinned: bool,
    /// How many capsules of this store are cached.
    pub capsule_count: u64,
    /// The total cached bytes across this store's capsules.
    pub total_bytes: u64,
}

impl HostedStore {
    /// Distil one wire entry into what a surface renders.
    fn of_wire(store: &WireHostedStore) -> Self {
        Self {
            store_id: store.store_id.clone(),
            pinned: store.pinned,
            capsule_count: store.capsule_count,
            total_bytes: store.total_bytes,
        }
    }
}

/// What the app knows about the stores this node holds. See the module docs for why these three are
/// separate types rather than one list that is sometimes empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedStoresReading {
    /// A read is under way and has not answered yet. Nothing has failed, so naming a reason would
    /// invent one.
    Pending,
    /// The node answered. An EMPTY vector is a real answer: this node holds nothing.
    Known(Vec<HostedStore>),
    /// No list could be read, and which thing was missing.
    Unknown(HostedStoresUnknown),
}

impl Default for HostedStoresReading {
    /// Before anything has been asked the list is [`Pending`](Self::Pending) — not empty, and not a
    /// fault either.
    fn default() -> Self {
        Self::Pending
    }
}

/// Why no hosted-store list is available. **One variant per REMEDY**, never per rough category — the
/// reason is the only thing that tells a person whether to start their node, wait, or fix a
/// permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedStoresUnknown {
    /// No node is connected at all, so there is nothing to ask.
    NoNode,
    /// A node answered and does not serve this method — an older build. The remedy is an upgrade.
    NodeCannotRead,
    /// A node answered and refused this app. The remedy is the control token, NOT an upgrade: this
    /// method is token-gated, so a refusal here is a permission fault on a perfectly capable node.
    Unauthorized,
    /// The socket opened and the read overran its budget. Kept apart from [`Unreachable`](Self::Unreachable)
    /// all the way to the sentence a person reads, because only `Unreachable` is evidence about
    /// whether a node exists (dig_ecosystem#2325).
    TimedOut(String),
    /// The node could not be reached for this read — it stopped between the status probe and now.
    Unreachable(String),
    /// The node refused for a reason we cannot classify; its own words are carried.
    ReadFailed(String),
}

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
fn classify(failure: ControlFailure) -> HostedStoresUnknown {
    match failure {
        ControlFailure::Transport(ControlCallError::Unreachable(detail)) => {
            HostedStoresUnknown::Unreachable(detail)
        }
        ControlFailure::Transport(ControlCallError::TimedOut(detail)) => {
            HostedStoresUnknown::TimedOut(detail)
        }
        // dig-node gates this method, and it refuses at the HTTP layer — before any JSON-RPC error
        // exists to carry a `data.code`. That is a permission fault with a real remedy, so it must
        // not fall through to "the read failed", which names none.
        ControlFailure::Transport(ControlCallError::HttpRefused {
            code: 401 | 403, ..
        }) => HostedStoresUnknown::Unauthorized,
        ControlFailure::Transport(e) => HostedStoresUnknown::ReadFailed(e.to_string()),
        ControlFailure::Rejected(e) if CANNOT_SERVE.contains(&e.data.code.as_str()) => {
            HostedStoresUnknown::NodeCannotRead
        }
        ControlFailure::Rejected(e) if e.data.code == ControlErrorCode::Unauthorized.name() => {
            HostedStoresUnknown::Unauthorized
        }
        ControlFailure::Rejected(e) => HostedStoresUnknown::ReadFailed(e.message),
    }
}

/// Read the hosted-store list from the node at `endpoint`, once.
///
/// Separated from the poller so the classification above is testable against a real socket without a
/// cadence in the way.
fn read_once(endpoint: &str, token: Option<&str>, timeout: Duration) -> HostedStoresReading {
    match control::call_control_result(endpoint, &HostedStoresListParams {}, token, timeout) {
        Ok(result) => {
            HostedStoresReading::Known(result.stores.iter().map(HostedStore::of_wire).collect())
        }
        Err(failure) => HostedStoresReading::Unknown(classify(failure)),
    }
}

/// The stores this node holds, polled no more often than [`REFRESH_INTERVAL`].
///
/// Lives beside the tray's status handle and is asked for a reading on every snapshot. It answers
/// from its cache and does the real read on a WORKER THREAD, so a caller never waits on the node.
/// While a first read is in flight the answer is [`HostedStoresReading::Pending`]; a REFRESH of a
/// list already held answers with that list, so a routine refresh does not blank a list the person
/// is reading.
///
/// Holding this here rather than in the shell is deliberate: the shell is a binary, and a binary is
/// a test-free zone.
pub struct NodeHostedStores {
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
    /// `None` when the last reading came from a DIFFERENT node: a store list is a property of one
    /// node, so carrying one node's answer over to another would report stores the new node does not
    /// hold.
    fn reading_for(&self, endpoint: &str) -> Option<(HostedStoresReading, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.endpoint == endpoint)
            .map(|c| (c.reading.clone(), c.taken.elapsed()))
    }
}

/// A reading and the endpoint + instant it was taken for.
struct Cached {
    endpoint: String,
    reading: HostedStoresReading,
    taken: Instant,
}

impl Default for NodeHostedStores {
    fn default() -> Self {
        Self::new(REFRESH_INTERVAL, STORES_READ_TIMEOUT)
    }
}

impl NodeHostedStores {
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
    /// With no node there is nothing to ask, so the held reading is dropped — a list from a node
    /// that has since gone away must not outlive it — and the answer names the absent node.
    pub fn observe(&self, link: &EngineState) -> HostedStoresReading {
        let EngineState::Connected { endpoint, .. } = link else {
            let mut state = self.lock();
            state.cached = None;
            return HostedStoresReading::Unknown(HostedStoresUnknown::NoNode);
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.reading_for(endpoint) {
            if age < self.refresh {
                return fresh;
            }
        }

        self.start_read(&mut state, endpoint);
        // The list already held for this node while its refresh runs — showing it beats blanking a
        // list to "checking" every half minute. Only a first read has genuinely nothing to state.
        state
            .reading_for(endpoint)
            .map(|(reading, _)| reading)
            .unwrap_or(HostedStoresReading::Pending)
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
    use crate::test_support::node::{FakeNode, FakeStore, StoresReply};

    /// Two stores that differ in EVERY field, so an implementation that read one entry and reused it
    /// — or that swapped two fields of the same type — cannot pass on a symmetric fixture.
    fn two_stores() -> Vec<FakeStore> {
        vec![
            FakeStore {
                store_id: "aa".repeat(32),
                pinned: true,
                capsule_count: 3,
                total_bytes: 7_000,
            },
            FakeStore {
                store_id: "bb".repeat(32),
                pinned: false,
                capsule_count: 1,
                total_bytes: 250,
            },
        ]
    }

    fn fake_token() -> Option<String> {
        Some(FakeNode::TOKEN.to_string())
    }

    fn no_token() -> Option<String> {
        None
    }

    /// An `EngineState` naming `node` as the endpoint the §5.3 status probe answered from.
    fn connected_to(node: &FakeNode) -> EngineState {
        EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// Observe until the poller has something other than a pending read, or give up. The deadline
    /// only bounds a HANG — a test that will pass does so as soon as the fake answers.
    fn settle(poller: &NodeHostedStores, link: &EngineState) -> HostedStoresReading {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match poller.observe(link) {
                HostedStoresReading::Pending if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                settled => return settled,
            }
        }
    }

    /// **The headline property.** Against a node that serves the method, every field of every store
    /// arrives — over a real socket, in the real wire shape, in the node's own order.
    #[test]
    fn a_node_that_serves_the_method_yields_its_real_store_list() {
        let node = FakeNode::serving_stores(StoresReply::Stores(two_stores()));
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );

        assert_eq!(
            settle(&poller, &connected_to(&node)),
            HostedStoresReading::Known(vec![
                HostedStore {
                    store_id: "aa".repeat(32),
                    pinned: true,
                    capsule_count: 3,
                    total_bytes: 7_000,
                },
                HostedStore {
                    store_id: "bb".repeat(32),
                    pinned: false,
                    capsule_count: 1,
                    total_bytes: 250,
                },
            ])
        );
        // Asserted from the SERVER's copy of the bytes: the contract method name must have gone out
        // on the wire, not merely been named in a constant the client also owns.
        assert!(node.received().contains("control.hostedStores.list"));
    }

    /// **A node holding nothing is a KNOWN empty list**, not an unknown — the success state of a
    /// brand-new install, which a pane must be able to render as "you are not hosting anything yet"
    /// rather than as a fault.
    #[test]
    fn a_node_that_holds_nothing_answers_with_a_known_empty_list() {
        let node = FakeNode::serving_stores(StoresReply::Stores(vec![]));
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );
        assert_eq!(
            settle(&poller, &connected_to(&node)),
            HostedStoresReading::Known(vec![])
        );
    }

    /// **The defect this type exists to prevent.** Each way of failing to read produces a DIFFERENT
    /// unknown, and none of them produces `Known(vec![])` — which is what "you are hosting nothing"
    /// would be rendered from.
    ///
    /// Driven through the whole transport rather than `classify` alone, so the node's real error
    /// envelope is what is being classified.
    #[test]
    fn every_way_of_failing_is_its_own_reason_and_none_of_them_is_an_empty_list() {
        let cases: Vec<(StoresReply, HostedStoresUnknown)> = vec![
            (
                StoresReply::rejected(-32601, "METHOD_NOT_FOUND"),
                HostedStoresUnknown::NodeCannotRead,
            ),
            (
                StoresReply::rejected(-32030, "UNAUTHORIZED"),
                HostedStoresUnknown::Unauthorized,
            ),
        ];
        for (reply, expected) in cases {
            let node = FakeNode::serving_stores(reply.clone());
            let poller = NodeHostedStores::with_token_reader(
                REFRESH_INTERVAL,
                Duration::from_secs(5),
                fake_token,
            );
            let reading = settle(&poller, &connected_to(&node));
            assert_eq!(
                reading,
                HostedStoresReading::Unknown(expected),
                "{reply:?} must reach the surface as its own reason"
            );
        }

        // An unclassifiable refusal carries the node's own words rather than becoming a list.
        let node = FakeNode::serving_stores(StoresReply::rejected(-32099, "SOMETHING_ELSE"));
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );
        assert!(
            matches!(
                settle(&poller, &connected_to(&node)),
                HostedStoresReading::Unknown(HostedStoresUnknown::ReadFailed(_))
            ),
            "an unclassified refusal must stay an unknown"
        );
    }

    /// **An UNAUTHORIZED refusal is not an old node.** This method is token-gated, so the remedy is
    /// the control token — telling this user to upgrade would send them after a fault that is not
    /// there.
    ///
    /// The fixture varies ONE actor: the same healthy node, asked WITHOUT a token, against the
    /// token-bearing control above.
    #[test]
    fn a_read_without_the_control_token_is_a_permission_fault_not_a_missing_method() {
        let node = FakeNode::serving_stores(StoresReply::Stores(two_stores()));
        let refused =
            NodeHostedStores::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), no_token);
        assert!(
            matches!(
                settle(&refused, &connected_to(&node)),
                HostedStoresReading::Unknown(HostedStoresUnknown::Unauthorized)
            ),
            "the node gates this method, so a tokenless read is refused — and refused is not empty"
        );
        // The control: the SAME node, asked with the token, answers. Without this the test above
        // would pass against a fake that simply never served anything.
        let allowed = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );
        assert!(matches!(
            settle(&allowed, &connected_to(&node)),
            HostedStoresReading::Known(_)
        ));
    }

    /// **A node that is up and simply slow is not an absent one** (dig_ecosystem#2325's shape).
    ///
    /// The delay is many times the budget so the outcome cannot turn on scheduling noise, and the
    /// assertion is that the reason is a TIMEOUT — not `NoNode`, and above all not an empty list.
    #[test]
    fn a_node_that_answers_late_times_out_rather_than_looking_empty() {
        let node = FakeNode::serving_stores_slowly(
            StoresReply::Stores(two_stores()),
            Duration::from_secs(4),
        );
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_millis(200),
            fake_token,
        );
        let reading = settle(&poller, &connected_to(&node));
        assert!(
            matches!(
                reading,
                HostedStoresReading::Unknown(HostedStoresUnknown::TimedOut(_))
            ),
            "a late node is not an absent or empty one; got {reading:?}"
        );
    }

    /// The control for the timeout above, and the regression the generous budget exists for: the
    /// SAME slow fixture, given a read budget instead of a probe budget, produces the real list.
    ///
    /// The delay is chosen FROM the constants — past [`control::DEFAULT_PROBE_TIMEOUT`], far inside
    /// [`STORES_READ_TIMEOUT`] — rather than picked, so it pins the gap between them.
    #[test]
    fn a_read_slower_than_a_probe_budget_still_yields_the_list() {
        let node = FakeNode::serving_stores_slowly(
            StoresReply::Stores(two_stores()),
            control::DEFAULT_PROBE_TIMEOUT + Duration::from_millis(250),
        );
        let poller =
            NodeHostedStores::with_token_reader(REFRESH_INTERVAL, STORES_READ_TIMEOUT, fake_token);
        assert!(matches!(
            settle(&poller, &connected_to(&node)),
            HostedStoresReading::Known(_)
        ));
    }

    /// The budget is pinned from BOTH sides: large enough that a probe budget would not do, and
    /// small enough to remain a budget.
    #[test]
    fn the_read_budget_is_a_read_budget_and_not_a_probe_budget() {
        assert!(
            STORES_READ_TIMEOUT > control::DEFAULT_PROBE_TIMEOUT * 4,
            "a cache-index walk is not a liveness probe and must not share its budget"
        );
        assert!(
            STORES_READ_TIMEOUT <= Duration::from_secs(30),
            "a budget this large stops being a budget"
        );
        assert!(
            REFRESH_INTERVAL > STORES_READ_TIMEOUT,
            "a refresh window shorter than one read would ask again before the answer arrived"
        );
    }

    /// **A read in flight must not hold the caller.** `observe` is called from the window's
    /// twice-a-second snapshot, so the assertion is on ELAPSED TIME — the one thing a synchronous
    /// implementation cannot fake, since it would return `Known` here after the full delay.
    #[test]
    fn an_unfinished_read_returns_at_once_as_pending_and_lands_later() {
        const DELAY: Duration = Duration::from_millis(1_500);
        let node = FakeNode::serving_stores_slowly(StoresReply::Stores(two_stores()), DELAY);
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);

        let started = Instant::now();
        let immediate = poller.observe(&link);
        let waited = started.elapsed();

        assert_eq!(
            immediate,
            HostedStoresReading::Pending,
            "an unfinished read is neither a list nor a fault"
        );
        assert!(
            waited < DELAY / 2,
            "the snapshot waited {waited:?} on a read that takes {DELAY:?}"
        );
        assert!(matches!(
            settle(&poller, &link),
            HostedStoresReading::Known(_)
        ));
    }

    /// **A slow node is asked ONCE**, however many snapshots happen while it thinks. Counted at the
    /// SERVER, because a client-side count would only prove the client's own idea of what it sent.
    #[test]
    fn repaints_during_a_slow_read_do_not_stack_more_reads_on_the_node() {
        let node = FakeNode::serving_stores_slowly(
            StoresReply::Stores(two_stores()),
            Duration::from_millis(800),
        );
        let poller = NodeHostedStores::with_token_reader(
            REFRESH_INTERVAL,
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);

        for _ in 0..12 {
            assert_eq!(poller.observe(&link), HostedStoresReading::Pending);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(matches!(
            settle(&poller, &link),
            HostedStoresReading::Known(_)
        ));
        assert_eq!(
            node.request_count(),
            1,
            "one read, no matter how often the window snapshotted"
        );
    }

    /// **The throttle actually throttles.** Two observations inside one refresh window reach the
    /// node once. Counted at the SERVER.
    #[test]
    fn a_second_observation_inside_the_window_does_not_ask_the_node_again() {
        let node = FakeNode::serving_stores(StoresReply::Stores(two_stores()));
        let poller = NodeHostedStores::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        let first = settle(&poller, &link);
        let second = poller.observe(&link);

        assert_eq!(first, second);
        assert_eq!(
            node.request_count(),
            1,
            "the second observation must be served from cache"
        );
    }

    /// **A refresh does not blank the list it is refreshing.** The nearest wrong implementation
    /// returns `Pending` the moment a reading goes stale, so the pane blinks to "checking…" every
    /// refresh cycle — and [`settle`] is blind to that by construction, because it returns as soon
    /// as the answer is not pending.
    ///
    /// The fixture makes the blink unavoidable if it exists: a refresh window shorter than the read
    /// it triggers. The final request count keeps the test from passing for the wrong reason — a
    /// poller that never refreshed at all would return the same stale list.
    #[test]
    fn a_refresh_in_flight_keeps_showing_the_list_it_is_refreshing() {
        let node = FakeNode::serving_stores_slowly(
            StoresReply::Stores(two_stores()),
            Duration::from_millis(600),
        );
        let poller = NodeHostedStores::with_token_reader(
            Duration::from_millis(50),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        let held = settle(&poller, &link);
        assert!(matches!(held, HostedStoresReading::Known(_)));

        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            poller.observe(&link),
            held,
            "a list the user is reading must not blink away while it is re-read"
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while node.request_count() < 2 && Instant::now() < deadline {
            assert_eq!(poller.observe(&link), held, "the list blinked mid-refresh");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            node.request_count() >= 2,
            "no re-read ever completed, so nothing above was actually exercised: {} calls",
            node.request_count()
        );
    }

    /// With no node the answer names the absent node — never an empty list, and never a read failure
    /// that did not happen.
    #[test]
    fn a_disconnected_link_reports_no_node_without_asking_anything() {
        let poller = NodeHostedStores::default();
        assert_eq!(
            poller.observe(&EngineState::Disconnected {
                reason: "nothing answered".to_string(),
            }),
            HostedStoresReading::Unknown(HostedStoresUnknown::NoNode)
        );
    }

    /// **A list read from one node must not be reported for another.** The fixture varies ONE actor
    /// — which node the link names — against a cache that is otherwise still fresh, and counts at
    /// each server so the re-read is proven rather than assumed.
    #[test]
    fn a_changed_node_invalidates_the_cache() {
        let first = FakeNode::serving_stores(StoresReply::Stores(two_stores()));
        let second = FakeNode::serving_stores(StoresReply::Stores(vec![]));
        let poller = NodeHostedStores::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );

        assert!(matches!(
            settle(&poller, &connected_to(&first)),
            HostedStoresReading::Known(ref stores) if stores.len() == 2
        ));
        assert_eq!(
            settle(&poller, &connected_to(&second)),
            HostedStoresReading::Known(vec![]),
            "the second node holds nothing, and its answer must not be the first node's list"
        );
        assert_eq!(first.request_count(), 1);
        assert_eq!(second.request_count(), 1);
    }

    /// Losing the node drops the held list: a list from a node that has since gone away must not
    /// outlive it on screen.
    #[test]
    fn losing_the_node_drops_the_cached_list() {
        let node = FakeNode::serving_stores(StoresReply::Stores(two_stores()));
        let poller = NodeHostedStores::with_token_reader(
            Duration::from_secs(600),
            Duration::from_secs(5),
            fake_token,
        );
        let link = connected_to(&node);
        assert!(matches!(
            settle(&poller, &link),
            HostedStoresReading::Known(_)
        ));

        assert_eq!(
            poller.observe(&EngineState::Disconnected {
                reason: "the node stopped".to_string(),
            }),
            HostedStoresReading::Unknown(HostedStoresUnknown::NoNode)
        );
        // And the dropped cache is genuinely gone: the next observation asks again.
        settle(&poller, &link);
        assert_eq!(node.request_count(), 2);
    }

    /// A refusal that is NOT an authorization one keeps its own words rather than being reported as
    /// a permission fault — the control for the `401`/`403` arm in [`classify`], without which every
    /// transport refusal could be mapped to `Unauthorized` and the test above would still pass.
    #[test]
    fn a_server_side_http_refusal_is_not_reported_as_a_permission_fault() {
        let node = FakeNode::with_behaviour(crate::test_support::node::Behaviour::Http(
            500,
            "the node fell over".to_string(),
        ));
        assert!(
            matches!(
                read_once(
                    &node.endpoint(),
                    fake_token().as_deref(),
                    Duration::from_secs(5)
                ),
                HostedStoresReading::Unknown(HostedStoresUnknown::ReadFailed(_))
            ),
            "a 500 is not a permission fault, and telling the user to fix their token would send \
             them after a fault that is not there"
        );
    }

    /// Nothing listening is "the node could not be reached", not a read failure and not an empty
    /// list — different remedies.
    #[test]
    fn nothing_listening_reads_as_unreachable() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        drop(listener);
        assert!(matches!(
            read_once(&endpoint, None, Duration::from_millis(300)),
            HostedStoresReading::Unknown(HostedStoresUnknown::Unreachable(_))
        ));
    }
}
