//! Whether the connected node can service a profile mint, measured off the painting thread
//! (dig_ecosystem#2398).
//!
//! # Why a poller and not a read at paint time
//!
//! [`ChainReadiness::probe`] asks the node two questions, and the window snapshot is taken about
//! twice a second. Probing in the frame would put two node round trips on the paint path and stall
//! the tray for as long as an unhealthy node took to answer — the same reason
//! [`NodeNetworkStanding`](crate::network::NodeNetworkStanding) and
//! [`NodeHostedStores`](crate::hosted_stores::NodeHostedStores) own their cadence rather than the
//! surfaces that read them.
//!
//! # What this deliberately does NOT decide
//!
//! It measures the CHAIN, and stops there. It has no `availability()` and produces no
//! [`ProfileCreation`](crate::profiles::ProfileCreation): a mint's availability is read off
//! [`ProfileMintSeams`](crate::account::profile_mint::ProfileMintSeams), which needs a door this
//! poller cannot hold — the door borrows a live account session and cannot leave the thread that
//! owns it. A second route to an availability is precisely the drift dig_ecosystem#2377 measured, so
//! the caller attaches the door and asks the seams.
//!
//! # An unmeasured node is not a measured absence
//!
//! Before the first probe returns, [`observe`](NodeChainReadiness::observe) answers `None` — *not
//! asked yet* — rather than a transport failure. The two are different facts, and reporting one as
//! the other would put a diagnostic on screen that names a cause nobody observed. Both withhold the
//! mint offer, which is the safe direction either way.

use std::sync::{Arc, Mutex};

use crate::probe::{self, HasProbeSlots, ProbeSlots};
use std::time::{Duration, Instant};

use crate::account::profile_mint::ChainReadiness;
use crate::chain::{ControlChainSource, READ_TIMEOUT};
use crate::engine::EngineState;

/// How long a reading stays fresh.
///
/// Long, because the answer changes only when a node is restarted or upgraded — not with the chain.
/// Re-probing faster would spend two round trips a minute to re-learn a constant.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Measures [`ChainReadiness`] against the connected node, at most once per [`REFRESH_INTERVAL`].
pub struct NodeChainReadiness {
    /// Shared with the worker threads, which is why it is an [`Arc`] rather than a plain field.
    state: Arc<Mutex<PollState>>,
    refresh: Duration,
    /// The per-read budget handed to the chain source.
    timeout: Duration,
    /// Takes one reading from an endpoint. Injected so a test probes its own fake chain instead of
    /// whatever node this machine happens to be running.
    probe: fn(&str, Duration) -> ChainReadiness,
}

/// What the poller knows between reads.
#[derive(Default)]
struct PollState {
    /// The last reading taken, and the endpoint + instant it was taken at.
    cached: Option<Cached>,
    /// The endpoints a worker is currently probing — the de-duplication that keeps a
    /// twice-a-second snapshot from stacking probes on a node already answering one.
    ///
    /// A SET rather than one endpoint: an alternating ladder defeats a single-slot claim entirely
    /// (see [`crate::probe`]).
    in_flight: ProbeSlots,
}

impl HasProbeSlots for PollState {
    fn probe_slots(&mut self) -> &mut ProbeSlots {
        &mut self.in_flight
    }
}

impl PollState {
    /// The reading held for `endpoint` and how long ago it was taken.
    ///
    /// `None` when the last reading came from a DIFFERENT node: readiness is a property of the node
    /// that answered, so carrying one node's answer over to another would report a capability the
    /// new node was never asked about.
    fn reading_for(&self, endpoint: &str) -> Option<(ChainReadiness, Duration)> {
        self.cached
            .as_ref()
            .filter(|c| c.endpoint == endpoint)
            .map(|c| (c.reading.clone(), c.taken.elapsed()))
    }
}

/// A reading and the endpoint + instant it was taken for.
struct Cached {
    endpoint: String,
    reading: ChainReadiness,
    taken: Instant,
}

impl Default for NodeChainReadiness {
    fn default() -> Self {
        Self::new(REFRESH_INTERVAL, READ_TIMEOUT)
    }
}

impl NodeChainReadiness {
    /// A poller refreshing at most every `refresh`, allowing `timeout` per read.
    pub fn new(refresh: Duration, timeout: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(PollState::default())),
            refresh,
            timeout,
            probe: probe_endpoint,
        }
    }

    /// A poller that probes through `probe` rather than a real node.
    #[cfg(test)]
    fn with_probe(refresh: Duration, probe: fn(&str, Duration) -> ChainReadiness) -> Self {
        Self {
            probe,
            ..Self::new(refresh, READ_TIMEOUT)
        }
    }

    /// The readiness of the node `link` names, refreshing in the background when stale.
    ///
    /// `None` means no reading applies: either nothing is connected, or the first probe of this node
    /// has not come back yet. A disconnected link DROPS the cached reading rather than keeping it,
    /// because a reading describes a node that is answering and this one is not.
    pub fn observe(&self, link: &EngineState) -> Option<ChainReadiness> {
        let EngineState::Connected { endpoint, .. } = link else {
            self.lock().cached = None;
            return None;
        };

        let mut state = self.lock();
        if let Some((fresh, age)) = state.reading_for(endpoint) {
            if age < self.refresh {
                return Some(fresh);
            }
        }

        self.start_probe(&mut state, endpoint);
        // The reading already held for this node while its refresh runs. Only a first probe has
        // genuinely nothing to report.
        state.reading_for(endpoint).map(|(reading, _)| reading)
    }

    /// Begin a probe of `endpoint` unless one is already under way for it.
    ///
    /// The claim-keeping and the non-panicking spawn live in [`crate::probe`], shared with the two
    /// sibling pollers so one correction reaches all three (dig-app#261).
    fn start_probe(&self, state: &mut PollState, endpoint: &str) {
        let shared = Arc::clone(&self.state);
        let owned = endpoint.to_string();
        let timeout = self.timeout;
        let probe = self.probe;
        probe::start(&self.state, state, endpoint, move || {
            let reading = probe(&owned, timeout);
            let mut state = probe::lock(&shared);
            state.cached = Some(Cached {
                endpoint: owned,
                reading,
                taken: Instant::now(),
            });
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PollState> {
        probe::lock(&self.state)
    }
}

/// One reading, taken through a real control-plane chain source.
fn probe_endpoint(endpoint: &str, timeout: Duration) -> ChainReadiness {
    ChainReadiness::probe(&ControlChainSource::with_timeout(endpoint, timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link connected to `endpoint`, with the status fields a reading never consults.
    fn connected(endpoint: &str) -> EngineState {
        EngineState::Connected {
            endpoint: endpoint.to_owned(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// Every probe answers `WalksLineages`, and records nothing — the cadence is what is under test.
    fn walks(_endpoint: &str, _timeout: Duration) -> ChainReadiness {
        ChainReadiness::WalksLineages
    }

    /// Spin until `f` answers `Some`, so a test never asserts against a worker that has not landed.
    ///
    /// # The ceiling is generous ON PURPOSE, and generosity costs nothing here
    ///
    /// The property every caller is testing is whether a reading EVER lands — a stranded endpoint
    /// never answers, however long anybody waits — so the budget is not part of any assertion. It is
    /// only an upper bound on how long a genuine failure takes to report, and it is paid solely when
    /// a test is already failing.
    ///
    /// It was two seconds, which made these tests WALL-CLOCK gates rather than logic gates: on a
    /// contended windows-latest runner the same suite takes ~290 s against ~36 s locally, and
    /// `a_probe_that_panics_does_not_strand_the_endpoint_as_permanently_unmeasured` — whose second
    /// probe must be scheduled, run and stored inside the budget — went red there while passing on
    /// ubuntu and macOS in the very same run. A red that tracks runner load says nothing about the
    /// code, and a flaky gate is a gate people learn to re-run instead of read.
    const SETTLE_POLLS: usize = 2_000;

    fn settled(poller: &NodeChainReadiness, link: &EngineState) -> ChainReadiness {
        for _ in 0..SETTLE_POLLS {
            if let Some(reading) = poller.observe(link) {
                return reading;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the probe never landed");
    }

    /// dig-app#261 §1 — **endpoint churn costs one probe per ENDPOINT, never one per snapshot.**
    ///
    /// Makes impossible: the steady state of tens of live threads and sockets that an alternating
    /// ladder used to produce. `endpoint_ladder` prefers `dig.local` and falls back to `localhost`,
    /// and `dig.local` resolves over mDNS/LLMNR, which answers intermittently — so a snapshot taken
    /// twice a second alternates between the two names. Against the single-slot claim this replaced,
    /// EVERY alternation passed `in_flight != endpoint` and spawned a fresh detached thread.
    ///
    /// # Why the fixture alternates rather than repeating one endpoint
    ///
    /// Repeating ONE endpoint is the blind fixture here: the single-slot claim deduplicates that case
    /// perfectly, so a test built on it passes identically before and after the fix. The defect is
    /// only expressible when a SECOND endpoint displaces the first, which is why there are two and
    /// why they alternate. Ten rounds rather than the two that would strictly suffice, so the failure
    /// reports the SHAPE — a count that tracks snapshots — instead of an off-by-one.
    ///
    /// # Why this cannot pass on a bound that is really the test's own duration
    ///
    /// Nothing here is timed. Every probe blocks until the test releases it, so no claim can be
    /// returned early and quietly re-taken; the assertion runs only after every claim has been given
    /// back, which means every worker that was EVER spawned has finished and `ENTRIES` is final. A
    /// leak would therefore be counted, not outrun.
    #[test]
    fn churn_between_two_endpoints_costs_one_probe_per_endpoint_not_one_per_snapshot() {
        let poller = NodeChainReadiness::with_probe(REFRESH_INTERVAL, churn::blocking_probe);
        let dig_local = connected("http://dig.local");
        let loopback = connected("http://localhost:9778");

        for _ in 0..10 {
            poller.observe(&dig_local);
            poller.observe(&loopback);
        }

        churn::release();
        for _ in 0..SETTLE_POLLS {
            if poller.lock().in_flight.live_count() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            poller.lock().in_flight.live_count(),
            0,
            "every claim should have been given back once the probes were released"
        );

        assert_eq!(
            churn::entries(),
            2,
            "twenty alternating snapshots over two endpoints must cost two probes, one per endpoint"
        );
    }

    /// The blocking probe and its gate for the churn test above.
    ///
    /// Free functions over statics because [`NodeChainReadiness::with_probe`] takes a `fn` pointer,
    /// which cannot close over a test's locals. Owned by that one test, so no other test observes
    /// this state.
    mod churn {
        use super::{ChainReadiness, Duration};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};

        static ENTRIES: AtomicUsize = AtomicUsize::new(0);
        static GATE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

        /// Counts its own entry, then blocks until [`release`] — so a claim taken during the churn
        /// loop is still held when the next snapshot asks for it.
        pub(super) fn blocking_probe(_endpoint: &str, _timeout: Duration) -> ChainReadiness {
            ENTRIES.fetch_add(1, Ordering::SeqCst);
            let (open, waiters) = &GATE;
            let mut open = open.lock().unwrap_or_else(|e| e.into_inner());
            while !*open {
                open = waiters.wait(open).unwrap_or_else(|e| e.into_inner());
            }
            ChainReadiness::WalksLineages
        }

        pub(super) fn release() {
            let (open, waiters) = &GATE;
            *open.lock().unwrap_or_else(|e| e.into_inner()) = true;
            waiters.notify_all();
        }

        pub(super) fn entries() -> usize {
            ENTRIES.load(Ordering::SeqCst)
        }
    }

    /// **A node that has not been probed yet reads as `None`, never as a transport failure.**
    ///
    /// Makes impossible: a first frame that names a cause nobody measured. The second leg is what
    /// keeps this from passing on a poller that answers `None` forever.
    #[test]
    fn an_unprobed_node_is_unmeasured_rather_than_unreachable() {
        let poller = NodeChainReadiness::with_probe(REFRESH_INTERVAL, walks);
        let link = connected("http://dig.local:4801");

        assert_eq!(poller.observe(&link), None, "no probe has landed yet");
        assert_eq!(settled(&poller, &link), ChainReadiness::WalksLineages);
    }

    /// **A reading is never carried from one node to another.**
    ///
    /// Makes impossible: a cache keyed on nothing, which would report the previous node's capability
    /// for a machine that has just been pointed at a different one — including reporting a mint as
    /// possible against a node that cannot walk a lineage.
    ///
    /// The fixture switches to a SECOND endpoint whose probe answers differently, so a poller that
    /// ignored the endpoint would return the first answer and fail here. A single-endpoint fixture
    /// could not tell the two apart.
    #[test]
    fn a_reading_belongs_to_the_node_that_answered_it() {
        fn by_endpoint(endpoint: &str, _timeout: Duration) -> ChainReadiness {
            match endpoint.contains("second") {
                true => ChainReadiness::NoLineageWalk {
                    why: "no walk here".into(),
                },
                false => ChainReadiness::WalksLineages,
            }
        }

        let poller = NodeChainReadiness::with_probe(REFRESH_INTERVAL, by_endpoint);
        assert_eq!(
            settled(&poller, &connected("http://first.local:4801")),
            ChainReadiness::WalksLineages
        );

        let second = connected("http://second.local:4801");
        // The first observation of a new node reports nothing rather than the old node's answer.
        assert_eq!(poller.observe(&second), None);
        assert_eq!(
            settled(&poller, &second),
            ChainReadiness::NoLineageWalk {
                why: "no walk here".into()
            }
        );
    }

    /// **A probe that falls over releases the endpoint, so the node can be measured again**
    /// (dig_ecosystem#2686 §3).
    ///
    /// Makes impossible: permanent silent unavailability from ONE transient panic. The in-flight
    /// slot was released on the worker's last line, so an unwinding probe skipped it — and because
    /// the same unwind also skipped the write to `cached`, [`observe`] then found no reading AND
    /// found the slot still taken, so [`start_probe`](NodeChainReadiness::start_probe) returned
    /// early on every subsequent call. That endpoint answered `None` for the life of the process
    /// with no path back, which the surface renders as *still checking* forever
    /// (dig_ecosystem#2690): an ongoing activity that is not ongoing, and no action the person can
    /// take. Fail-closed must not mean permanently denied.
    ///
    /// # Why the fixture needs a probe that recovers rather than one that always panics
    ///
    /// A probe that panicked every time would leave `observe` answering `None` under both the fixed
    /// and the broken body, so it could not tell them apart. Only the SECOND attempt distinguishes
    /// them, and the second attempt happens only if the slot was released — so `settled` landing at
    /// all IS the property. Against the pre-fix body this fails on `settled`'s own
    /// *"the probe never landed"*, having spun the full two seconds.
    ///
    /// The attempt count is asserted separately so a poller that somehow answered without probing
    /// twice could not satisfy this either.
    #[test]
    fn a_probe_that_panics_does_not_strand_the_endpoint_as_permanently_unmeasured() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

        /// Falls over on its first call and answers honestly on every one after.
        fn panics_once(_endpoint: &str, _timeout: Duration) -> ChainReadiness {
            match ATTEMPTS.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("a transient probe failure"),
                _ => ChainReadiness::WalksLineages,
            }
        }

        let poller = NodeChainReadiness::with_probe(REFRESH_INTERVAL, panics_once);
        let link = connected("http://dig.local:4801");

        assert_eq!(poller.observe(&link), None, "no probe has landed yet");
        assert_eq!(
            settled(&poller, &link),
            ChainReadiness::WalksLineages,
            "one panicking probe left the endpoint unmeasurable for the life of the process"
        );
        assert!(
            ATTEMPTS.load(Ordering::SeqCst) >= 2,
            "the reading arrived without a second probe, so it says nothing about the slot"
        );
    }

    /// **A disconnected link drops the reading rather than keeping the last good one.**
    ///
    /// Makes impossible: a tray that goes on offering a mint after its node has gone away, because
    /// the last thing the node said was that it could.
    #[test]
    fn a_disconnected_link_has_no_reading_at_all() {
        let poller = NodeChainReadiness::with_probe(REFRESH_INTERVAL, walks);
        let link = connected("http://dig.local:4801");
        assert_eq!(settled(&poller, &link), ChainReadiness::WalksLineages);

        assert_eq!(
            poller.observe(&EngineState::Disconnected {
                reason: "the node stopped".into()
            }),
            None
        );
        // And the drop is real: reconnecting reports nothing until a fresh probe lands.
        assert_eq!(poller.observe(&link), None);
    }
}
