//! The audit record's cadence — how the Activity tab gets a reading without blocking the repaint.
//!
//! The window snapshots about twice a second and the record is a node round trip, so the read cannot
//! happen inline. This is the same shape as [`crate::hosted_stores::NodeHostedStores`] and the
//! sibling balance and network pollers, and it shares their claim-keeping through `crate::probe`
//! so a correction to the spawn/de-duplication logic reaches all of them at once rather than three
//! times.
//!
//! # What it may NOT do, and why that is the whole point
//!
//! **Carry one node's record over to another, and answer an unasked question with an empty list.**
//! Both are the same failure in different clothes: a person looking at an audit record of their own
//! money being spent, and being shown something that is not a measurement of it. So the cache is
//! keyed on the endpoint it was taken from, a disconnect DROPS it, and the very first read reports
//! [`ActivityReading::Pending`] rather than an empty ledger.
//!
//! A REFRESH is different from a first read: while one is running the record already held for that
//! same node keeps being shown, because blanking a list of spends to "checking…" every thirty
//! seconds is worse than showing one that is thirty seconds old.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::control;
use crate::engine::EngineState;
use crate::probe::{self, HasProbeSlots, ProbeSlots};

use super::bonds::{self, LockedReading, LockedUnknown};
use super::control::{read, ACTIVITY_READ_TIMEOUT};
use super::{ActivityReading, ActivityUnknown};

/// How stale a held record may get before another read is started.
///
/// Slower than the balance's cadence on purpose: an automated spend happens on a WEEKLY epoch, so a
/// record that is half a minute old is not meaningfully less true than one taken this instant, and
/// asking more often would spend node round trips to change nothing on screen.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Reads dig-node's automated-spend record on its own cadence.
pub struct NodeActivity {
    state: Arc<Mutex<PollState>>,
    refresh: Duration,
    timeout: Duration,
    /// Reads the node's control token. Injected so a test presents its own fake node's token rather
    /// than whatever this machine's real install holds.
    read_token: fn() -> Option<String>,
}

/// What the poller knows between reads.
#[derive(Default)]
struct PollState {
    cached: Option<Cached>,
    /// The endpoints a worker is currently reading from — the de-duplication that stops a
    /// twice-a-second snapshot stacking reads on a node already answering one. A SET rather than one
    /// slot, because an alternating ladder defeats a single-slot claim (see [`crate::probe`]).
    in_flight: ProbeSlots,
}

impl HasProbeSlots for PollState {
    fn probe_slots(&mut self) -> &mut ProbeSlots {
        &mut self.in_flight
    }
}

impl PollState {
    /// The record held for `endpoint` and how long ago it was taken.
    ///
    /// `None` when the last reading came from a DIFFERENT node. An audit record is one node's
    /// bookkeeping, so showing node A's spends while pointed at node B would be a list of money
    /// movements attributed to the wrong machine.
    fn reading_for(&self, endpoint: &str) -> Option<(ActivityReading, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.endpoint == endpoint)
            .map(|c| (c.reading.clone(), c.taken.elapsed()))
    }

    /// The locked-collateral figure held for `endpoint` and how long ago it was taken.
    ///
    /// Keyed on the endpoint on the same terms as [`reading_for`](Self::reading_for), and for a
    /// sharper reason: a locked total attributed to the wrong machine is a figure about money the
    /// person looking at it does not have.
    fn locked_for(&self, endpoint: &str) -> Option<(LockedReading, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.endpoint == endpoint)
            .map(|c| (c.locked.clone(), c.taken.elapsed()))
    }
}

/// A reading and the endpoint + instant it was taken for.
struct Cached {
    endpoint: String,
    reading: ActivityReading,
    /// The locked-collateral total, taken in the SAME pass as `reading`.
    ///
    /// Held beside the record rather than in its own poller because the two are read together and
    /// shown together: two cadences would let the tab state a total from one instant beside a spend
    /// list from another, and a person checking the figure against the entries would be comparing
    /// two different moments.
    locked: LockedReading,
    taken: Instant,
}

impl Default for NodeActivity {
    fn default() -> Self {
        Self::new(REFRESH_INTERVAL, ACTIVITY_READ_TIMEOUT)
    }
}

impl NodeActivity {
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

    /// The freshest record for the currently linked node. **Never blocks.**
    pub fn observe(&self, link: &EngineState) -> ActivityReading {
        let EngineState::Connected { endpoint, .. } = link else {
            // A record from a node that has since gone away must not outlive it: a person would be
            // reading spends attributed to a machine this app is no longer talking to.
            let mut state = self.lock();
            state.cached = None;
            return ActivityReading::Unknown(ActivityUnknown::NoNode);
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.reading_for(endpoint) {
            if age < self.refresh {
                return fresh;
            }
        }

        self.start_read(&mut state, endpoint);
        state
            .reading_for(endpoint)
            .map(|(reading, _)| reading)
            .unwrap_or(ActivityReading::Pending)
    }

    /// The freshest locked-collateral total for the currently linked node. **Never blocks.**
    ///
    /// Shares one cache entry and one worker with [`observe`](Self::observe), so calling both in a
    /// snapshot costs the same round trips as calling either — and guarantees the two figures
    /// describe the same node at the same instant.
    pub fn observe_locked(&self, link: &EngineState) -> LockedReading {
        let EngineState::Connected { endpoint, .. } = link else {
            let mut state = self.lock();
            state.cached = None;
            return LockedReading::Unknown(LockedUnknown::NoNode);
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.locked_for(endpoint) {
            if age < self.refresh {
                return fresh;
            }
        }

        self.start_read(&mut state, endpoint);
        state
            .locked_for(endpoint)
            .map(|(locked, _)| locked)
            .unwrap_or(LockedReading::Pending)
    }

    /// Begin a read from `endpoint` unless one is already under way for it.
    fn start_read(&self, state: &mut PollState, endpoint: &str) {
        let shared = Arc::clone(&self.state);
        let owned = endpoint.to_string();
        let token = (self.read_token)();
        let timeout = self.timeout;
        probe::start(&self.state, state, endpoint, move || {
            let reading = read(Some(&owned), token.as_deref(), timeout);
            // The two reads happen back to back in ONE worker so the pair is always from the same
            // node and the same moment. Splitting them across pollers would let the tab show a
            // total and a list taken seconds apart with no way for a reader to tell.
            let locked = bonds::read(Some(&owned), token.as_deref(), bonds::BONDS_READ_TIMEOUT);
            let mut state = probe::lock(&shared);
            state.cached = Some(Cached {
                endpoint: owned,
                reading,
                locked,
                taken: Instant::now(),
            });
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PollState> {
        probe::lock(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_token() -> Option<String> {
        None
    }

    fn fake_token() -> Option<String> {
        Some(crate::test_support::node::FakeNode::TOKEN.to_string())
    }

    /// An engine that has no node, however it came to have none.
    fn disconnected() -> EngineState {
        EngineState::Disconnected {
            reason: "no node".to_string(),
        }
    }

    /// An `EngineState` naming `node` as the endpoint the §5.3 status probe answered from.
    fn connected_to(node: &crate::test_support::node::FakeNode) -> EngineState {
        EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// Observe until the poller has something other than a pending read, or give up. The deadline
    /// only bounds a HANG — a test that will pass does so as soon as the fake answers.
    fn settle(poller: &NodeActivity, link: &EngineState) -> ActivityReading {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match poller.observe(link) {
                ActivityReading::Pending if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                settled => return settled,
            }
        }
    }

    fn poller() -> NodeActivity {
        NodeActivity::with_token_reader(REFRESH_INTERVAL, Duration::from_millis(50), no_token)
    }

    /// **With no node there is nothing to ask, and the answer says so** rather than reporting an
    /// empty record.
    #[test]
    fn a_disconnected_engine_reports_no_node() {
        assert_eq!(
            poller().observe(&disconnected()),
            ActivityReading::Unknown(ActivityUnknown::NoNode)
        );
    }

    /// **A record does not survive the node it came from.**
    ///
    /// The fixture seeds a cached record for one endpoint, then disconnects — which is the sequence
    /// a node restart actually produces. An implementation that only cleared on a DIFFERENT endpoint
    /// would keep showing the old node's spends across the gap, and the person would be reading a
    /// list of money movements attributed to a machine this app is no longer talking to.
    #[test]
    fn a_disconnect_drops_the_record_rather_than_carrying_it() {
        let poller = poller();
        {
            let mut state = poller.lock();
            state.cached = Some(Cached {
                endpoint: "http://127.0.0.1:9778".to_string(),
                reading: ActivityReading::Known(Default::default()),
                locked: LockedReading::default(),
                taken: Instant::now(),
            });
        }
        assert_eq!(
            poller.observe(&disconnected()),
            ActivityReading::Unknown(ActivityUnknown::NoNode)
        );
        assert!(
            poller.lock().cached.is_none(),
            "the held record was carried past the node that produced it"
        );
    }

    /// A node that answers every call with the JSON-RPC rejection `body`.
    ///
    /// Written as a raw HTTP body rather than through a typed helper because the bytes ARE the
    /// contract here: what is being tested is that a real wire rejection decodes into the right
    /// absence, and a helper that constructed the error from the same enum the reader matches on
    /// would be testing the enum against itself.
    fn node_rejecting(symbol: &str, code: i64) -> crate::test_support::node::FakeNode {
        use crate::test_support::node::{Behaviour, FakeNode};
        FakeNode::with_behaviour(Behaviour::Http(
            200,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": code,
                    "message": "the node refused this method",
                    "data": { "code": symbol, "origin": "node" },
                },
            })
            .to_string(),
        ))
    }

    /// **A node that does not serve the method reports NotSupported, over a real socket.**
    ///
    /// The whole stack end to end — poller, control transport, HTTP, JSON-RPC, error decode —
    /// against the rejection a node too old to keep the record actually sends. That is EXACTLY the
    /// node every user has today, because dig-node#376 has not shipped, so this is the path that
    /// runs in production right now.
    ///
    /// The assertion is on the REASON rather than on "not Known", because "not Known" is also
    /// satisfied by `NoNode` — which would send somebody to start a node that is already running.
    #[test]
    fn a_node_without_the_method_reports_an_old_node_and_not_an_empty_record() {
        let node = node_rejecting("METHOD_NOT_FOUND", -32601);
        let poller =
            NodeActivity::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        let reading = settle(&poller, &connected_to(&node));

        assert_eq!(
            reading,
            ActivityReading::Unknown(ActivityUnknown::NotSupported),
            "the node answered, and what it said was 'I do not keep that record'"
        );
        assert!(
            !reading.is_known_empty(),
            "an unsupported node must never read as a measured zero"
        );
    }

    /// **A refusal and an unsupported method reach DIFFERENT remedies over the same socket.**
    ///
    /// The truthful control for the test above. Both are rejections carried identically on the wire
    /// and differing only in the symbol, so an implementation that branched on the numeric code, on
    /// the error band, or simply on "there was an error" would collapse them — and would tell a
    /// person to update a perfectly current node when the real problem is a control token.
    #[test]
    fn an_authorization_refusal_is_not_an_out_of_date_node() {
        let node = node_rejecting("UNAUTHORIZED", -32030);
        let poller =
            NodeActivity::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        assert_eq!(
            settle(&poller, &connected_to(&node)),
            ActivityReading::Unknown(ActivityUnknown::Refused)
        );
    }

    /// **A node answering the wrong SHAPE is unreadable, never empty.**
    ///
    /// `serving_status` replies `200` with a healthy status body to whatever it is asked, which is a
    /// good model of a node that resolves the method and answers something this app cannot use. The
    /// tempting decode drops what it cannot parse and yields an empty ledger — a person would be
    /// told their node has spent nothing on the strength of a reply that never contained the answer.
    #[test]
    fn a_reply_of_the_wrong_shape_is_unreadable_rather_than_empty() {
        use crate::test_support::node::FakeNode;

        let node = FakeNode::serving_status();
        let poller =
            NodeActivity::with_token_reader(REFRESH_INTERVAL, Duration::from_secs(5), fake_token);
        let reading = settle(&poller, &connected_to(&node));

        assert_eq!(
            reading,
            ActivityReading::Unknown(ActivityUnknown::Unreadable)
        );
        assert!(!reading.is_known_empty());
    }

    /// **One node's record is never shown for another.**
    ///
    /// Two endpoints, one cached record, and the assertion is that asking about the OTHER endpoint
    /// does not return it. A single-endpoint fixture cannot distinguish a correctly-keyed cache from
    /// one that ignores the key entirely.
    #[test]
    fn a_record_is_keyed_on_the_node_that_produced_it() {
        let poller = poller();
        let held = ActivityReading::Known(Default::default());
        {
            let mut state = poller.lock();
            state.cached = Some(Cached {
                endpoint: "http://127.0.0.1:9778".to_string(),
                reading: held.clone(),
                locked: LockedReading::default(),
                taken: Instant::now(),
            });
        }
        let state = poller.lock();
        assert_eq!(
            state.reading_for("http://127.0.0.1:9778").map(|(r, _)| r),
            Some(held)
        );
        assert!(
            state.reading_for("http://127.0.0.2:80").is_none(),
            "a different node's record was offered as this one's"
        );
    }
}
