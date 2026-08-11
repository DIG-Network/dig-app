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
    /// The endpoint a worker is currently probing, if any — the de-duplication that keeps a
    /// twice-a-second snapshot from stacking probes on a node already answering one.
    in_flight: Option<String>,
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

/// The worker's claim on [`PollState::in_flight`], released when the worker's stack unwinds as well
/// as when it returns.
///
/// # Why an RAII guard rather than a line at the end of the worker
///
/// The release used to be the worker's last statement, which a panicking probe skips — and the same
/// unwind skips the write to [`PollState::cached`], so the endpoint was left holding the slot with
/// nothing to show for it. [`observe`](NodeChainReadiness::observe) then found no reading and
/// [`start_probe`](NodeChainReadiness::start_probe) found the slot taken, so it declined to probe;
/// that endpoint answered `None` for the life of the process with no path back. ONE transient panic
/// bought permanent silent unavailability, and a surface that says *still checking* about an
/// activity nobody is performing (dig_ecosystem#2686 §3, dig_ecosystem#2690).
///
/// A `Drop` releases on both paths by construction, so the failure cannot come back by someone
/// adding an early return above the release.
struct InFlight {
    state: Arc<Mutex<PollState>>,
    endpoint: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Cleared only if it is still OUR probe: the link may have moved to a different node while
        // we waited, in which case a later worker owns the slot.
        if state.in_flight.as_deref() == Some(self.endpoint.as_str()) {
            state.in_flight = None;
        }
    }
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
    fn start_probe(&self, state: &mut PollState, endpoint: &str) {
        if state.in_flight.as_deref() == Some(endpoint) {
            return;
        }
        state.in_flight = Some(endpoint.to_string());

        let shared = Arc::clone(&self.state);
        let endpoint = endpoint.to_string();
        let timeout = self.timeout;
        let probe = self.probe;
        std::thread::spawn(move || {
            // Declared FIRST so it drops LAST — after the guard below — because releasing the slot
            // takes the same lock. Held for the whole worker so a probe that panics releases it too.
            let _slot = InFlight {
                state: Arc::clone(&shared),
                endpoint: endpoint.clone(),
            };

            let reading = probe(&endpoint, timeout);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.cached = Some(Cached {
                endpoint: endpoint.clone(),
                reading,
                taken: Instant::now(),
            });
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PollState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
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
    fn settled(poller: &NodeChainReadiness, link: &EngineState) -> ChainReadiness {
        for _ in 0..200 {
            if let Some(reading) = poller.observe(link) {
                return reading;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the probe never landed");
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
