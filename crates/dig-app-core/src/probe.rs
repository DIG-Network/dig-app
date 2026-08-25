//! The one background-probe seam the endpoint pollers share (dig-app#261).
//!
//! Three modules poll the connected node on a cadence and cache what it answered:
//! [`chain::readiness`](crate::chain::readiness), [`hosted_stores`](crate::hosted_stores) and
//! [`network`](crate::network). Each of them needs the same three things, and each of them used to
//! carry its own copy:
//!
//! 1. **Do not stack probes** on a node that is already answering one.
//! 2. **Release the claim on every path**, including the one a panicking probe takes.
//! 3. **Never panic the caller**, which is the tray's paint thread.
//!
//! Three copies of one rule is three chances to fix it once and leave it broken twice, which is
//! what happened: the RAII release landed in `chain::readiness` alone and the other two kept
//! releasing on the return path only. This module is the single home, so a correction here reaches
//! all three by construction.
//!
//! # Why the claim is a SET and not one endpoint
//!
//! Each poller used to hold `in_flight: Option<String>` — the endpoint of the single probe believed
//! to be running. That is a dedup keyed on *the last endpoint asked about*, not on *what is
//! actually running*, and the two diverge the moment the endpoint alternates.
//!
//! The alternation is not hypothetical. `endpoint_ladder` prefers `http://dig.local` and falls back
//! to `http://localhost:9778`, and `dig.local` resolves over mDNS/LLMNR, which answers
//! intermittently on a busy or roaming network. A snapshot taken twice a second that alternates
//! between the two names passes `in_flight != endpoint` on EVERY snapshot, so every snapshot spawned
//! a fresh detached thread holding a socket for up to two read timeouts. The dedup was not merely
//! weak under churn; it was fully defeated by it, and steady state was tens of live threads.
//!
//! Keyed as a set, an alternating ladder costs one probe per DISTINCT endpoint — two — no matter how
//! fast the name flips, because the claim now describes the work in flight rather than the last
//! question asked.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

/// The endpoints a background probe is currently running for.
///
/// Embedded in each poller's own state struct rather than wrapping it, so a poller keeps ownership
/// of its cache shape and shares only the claim-keeping.
#[derive(Default)]
pub(crate) struct ProbeSlots {
    live: HashSet<String>,
}

impl ProbeSlots {
    /// Claim `endpoint`, answering whether the claim was granted.
    ///
    /// `false` means a probe is already running for it, which is the whole dedup.
    fn claim(&mut self, endpoint: &str) -> bool {
        self.live.insert(endpoint.to_string())
    }

    /// Give up the claim on `endpoint`.
    fn release(&mut self, endpoint: &str) {
        self.live.remove(endpoint);
    }

    /// How many probes are running. Test-facing: the bound under churn is the property at issue.
    #[cfg(test)]
    pub(crate) fn live_count(&self) -> usize {
        self.live.len()
    }
}

/// A poller state that keeps its in-flight claims in a [`ProbeSlots`].
pub(crate) trait HasProbeSlots {
    fn probe_slots(&mut self) -> &mut ProbeSlots;
}

/// A worker's claim on one endpoint, released when its stack unwinds as well as when it returns.
///
/// # Why an RAII guard rather than a line at the end of the worker
///
/// The release used to be the worker's last statement, which a panicking probe skips — and the same
/// unwind skips the write to the cache, so the endpoint was left holding the claim with nothing to
/// show for it. The poller then found no reading AND found the slot taken, so it declined to probe
/// again: that endpoint answered "still checking" for the life of the process with no path back. ONE
/// transient panic bought permanent silent unavailability (dig-app#261 §3).
///
/// A `Drop` releases on both paths by construction, so the failure cannot return by way of someone
/// adding an early return above the release.
struct ProbeClaim<S: HasProbeSlots> {
    state: Arc<Mutex<S>>,
    endpoint: String,
}

impl<S: HasProbeSlots> Drop for ProbeClaim<S> {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        state.probe_slots().release(&self.endpoint);
    }
}

/// Lock `state`, taking a poisoned lock's contents rather than panicking.
///
/// A poisoned poller mutex means some probe panicked; the cache it guards is a set of independent
/// per-endpoint readings, so the panic cannot have left a half-written invariant, and refusing to
/// read it would turn one dead probe into a dead surface.
pub(crate) fn lock<S>(state: &Arc<Mutex<S>>) -> MutexGuard<'_, S> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `work` on a background thread unless a probe is already running for `endpoint`.
///
/// `state` is the caller's ALREADY-HELD guard: claiming and spawning happen under the one lock the
/// caller took, so two snapshots cannot both find the slot free.
///
/// # Why the thread is spawned through a [`Builder`](std::thread::Builder)
///
/// [`std::thread::spawn`] PANICS when the OS refuses a thread, and this is called from the tray's
/// paint thread while that lock is held. Thread exhaustion — which the un-keyed claim above used to
/// cause — therefore surfaced as a panicked UI rather than as a dropped probe. A `Builder` returns
/// the refusal as a value, so the poller loses one reading and the app keeps painting.
///
/// A refused spawn releases the claim through the guard we already hold, NOT through a
/// [`ProbeClaim`]: that guard takes the same lock the caller is standing on, and `std`'s mutex is
/// not reentrant, so dropping one here would deadlock the paint thread. The claim is built INSIDE
/// the worker for the same reason.
pub(crate) fn start<S, F>(shared: &Arc<Mutex<S>>, state: &mut S, endpoint: &str, work: F)
where
    S: HasProbeSlots + Send + 'static,
    F: FnOnce() + Send + 'static,
{
    if !state.probe_slots().claim(endpoint) {
        return;
    }

    let worker_state = Arc::clone(shared);
    let worker_endpoint = endpoint.to_string();
    let spawned = std::thread::Builder::new()
        .name("dig-endpoint-probe".to_string())
        .spawn(move || {
            // Constructed HERE, and bound to a name so it lives for the whole worker and drops LAST
            // — after any guard `work` takes on the same mutex — because releasing the claim takes
            // that lock too.
            let _claim = ProbeClaim {
                state: worker_state,
                endpoint: worker_endpoint,
            };
            work();
        });

    if spawned.is_err() {
        // The closure never ran, so no `ProbeClaim` was ever constructed and nothing will release
        // the slot on its own. Release through the guard already in hand — which is also why the
        // claim could not be built above: dropping one here would take a lock we are standing on.
        state.probe_slots().release(endpoint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A poller state carrying nothing but the claims, which is all this seam touches.
    #[derive(Default)]
    struct Slots {
        in_flight: ProbeSlots,
    }

    impl HasProbeSlots for Slots {
        fn probe_slots(&mut self) -> &mut ProbeSlots {
            &mut self.in_flight
        }
    }

    /// Spin until `f` holds, so no assertion races a worker that has not landed.
    ///
    /// The ceiling only bounds how long a genuine failure takes to REPORT — the properties below are
    /// counts and set contents, never durations — so a slow machine cannot turn a pass into a fail
    /// or the reverse.
    fn until(f: impl Fn() -> bool) {
        for _ in 0..2_000 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the condition never held");
    }

    /// **A probe that panics gives its claim back.**
    ///
    /// Makes impossible: one transient panic buying PERMANENT silent unavailability for an endpoint.
    /// Without the RAII claim the unwind skips the release, the slot stays taken, and every later
    /// snapshot declines to probe — so the surface says "still checking" about an activity nobody is
    /// performing. `hosted_stores` and `network` released on the return path only until this seam
    /// became their shared home, so this is the property they GAINED.
    #[test]
    fn a_panicking_probe_gives_its_claim_back() {
        let shared = Arc::new(Mutex::new(Slots::default()));

        {
            let mut state = lock(&shared);
            start(&shared, &mut state, "http://dig.local", || {
                panic!("probe blew up")
            });
        }

        until(|| lock(&shared).in_flight.live_count() == 0);
    }

    /// **A second snapshot does not stack a probe on an endpoint already being probed.**
    ///
    /// The dedup itself — the property the churn keying must not cost. Both claims are asked for
    /// while the first is still held, so a granted second claim would be a stacked probe.
    #[test]
    fn one_endpoint_is_claimed_once_while_its_probe_runs() {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let shared = Arc::new(Mutex::new(Slots::default()));

        for _ in 0..5 {
            let gate = Arc::clone(&gate);
            let mut state = lock(&shared);
            start(&shared, &mut state, "http://dig.local", move || {
                RUNS.fetch_add(1, Ordering::SeqCst);
                let (open, waiters) = &*gate;
                let mut open = open.lock().unwrap_or_else(|e| e.into_inner());
                while !*open {
                    open = waiters.wait(open).unwrap_or_else(|e| e.into_inner());
                }
            });
        }

        let (open, waiters) = &*gate;
        *open.lock().unwrap_or_else(|e| e.into_inner()) = true;
        waiters.notify_all();

        until(|| lock(&shared).in_flight.live_count() == 0);
        assert_eq!(RUNS.load(Ordering::SeqCst), 1, "five snapshots, one probe");
    }

    /// **Distinct endpoints are claimed independently.**
    ///
    /// The control for the test above: a dedup that refused a SECOND endpoint would satisfy
    /// "one probe" while breaking the ladder it exists to serve, and this is what tells the two
    /// apart. Both claims are asserted while both probes are still blocked, so this cannot pass on a
    /// seam that merely serialises them.
    #[test]
    fn two_endpoints_are_claimed_independently() {
        let shared = Arc::new(Mutex::new(Slots::default()));
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));

        for endpoint in ["http://dig.local", "http://localhost:9778"] {
            let gate = Arc::clone(&gate);
            let mut state = lock(&shared);
            start(&shared, &mut state, endpoint, move || {
                let (open, waiters) = &*gate;
                let mut open = open.lock().unwrap_or_else(|e| e.into_inner());
                while !*open {
                    open = waiters.wait(open).unwrap_or_else(|e| e.into_inner());
                }
            });
        }

        assert_eq!(
            lock(&shared).in_flight.live_count(),
            2,
            "each endpoint holds its own claim while its probe runs"
        );

        let (open, waiters) = &*gate;
        *open.lock().unwrap_or_else(|e| e.into_inner()) = true;
        waiters.notify_all();
        until(|| lock(&shared).in_flight.live_count() == 0);
    }
}
