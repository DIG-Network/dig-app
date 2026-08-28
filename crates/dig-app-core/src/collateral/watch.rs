//! The first caller of the activity gate: notify when the node is short of $DIG (dig-app#306).
//!
//! [`runway`](crate::activity::runway) already decides WHETHER a collateral reading is worth
//! interrupting somebody over, and already renders the copy. Until now nothing showed it — a correct
//! reader with no call site, which is indistinguishable from a missing feature. This is the call
//! site.
//!
//! # Two throttles, and they answer different questions
//!
//! - [`WATCH_INTERVAL`](crate::collateral::watch::WATCH_INTERVAL) is how often the NODE is asked. The collateral cycle turns on a weekly
//!   epoch, so asking every few minutes is already far more often than the answer can change.
//! - The activity gate ([`crate::notify::shared`]) owns how often a person is TOLD, and it is the
//!   only thing that decides when. This module never consults a clock.
//!
//! # What it must not do
//!
//! Notify on `below_recommended_buffer`. That state is a readout — the ordinary condition of a
//! funded-but-not-over-funded wallet — and toasting it would teach an operator to dismiss the two
//! states above it, which are the ones that cost them money. The decision is not restated here:
//! this module calls [`runway::notification`](crate::activity::runway::notification), which returns
//! `None` for it. **This module holds no opinion of its own about which warnings matter** — that is
//! the property under test, asserted against the contract's own `is_shortfall` over every state it
//! defines. (The rule is enforced twice INSIDE `runway`, by `title` and `body` together; that is
//! belt-and-braces there, not a second opinion here.)
//!
//! # The custody boundary (§908)
//!
//! A token-gated READ of the node's own collateral position. No key, seed or signature is involved
//! and nothing on this path can spend.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::activity::runway;
use crate::collateral::node::{read_buffer, BufferReading};
use crate::engine::EngineState;
use crate::notify::gate::HoldKey;

/// How long between collateral reads.
///
/// Slow on purpose: the requirement is re-derived once a weekly epoch, so a reading five minutes
/// old is not meaningfully less true than one taken this instant, and a faster cadence would spend
/// node round trips to change nothing.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How long one collateral read may take before it is abandoned.
pub const WATCH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Watches the node's collateral position and offers the resulting notification to the gate.
pub struct CollateralWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    /// Reads the node's buffer. Injected so a test answers with its own reading instead of needing
    /// a node, and so the whole decide-and-offer path is exercised rather than mocked around.
    read: fn(&str) -> BufferReading,
    /// Offers a notification to the gate, returning whether it was taken. Injected for the same
    /// reason — a test must be able to see WHAT was offered, not just that nothing crashed.
    offer: fn(HoldKey, crate::notify::Notification) -> bool,
}

#[derive(Default)]
struct WatchState {
    last_read: Option<Instant>,
    in_flight: bool,
}

impl Default for CollateralWatch {
    fn default() -> Self {
        Self::new(
            WATCH_INTERVAL,
            read_over_ladder,
            crate::notify::shared::hold,
        )
    }
}

impl CollateralWatch {
    /// A watch with its cadence and both seams stated.
    #[must_use]
    pub fn new(
        refresh: Duration,
        read: fn(&str) -> BufferReading,
        offer: fn(HoldKey, crate::notify::Notification) -> bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchState::default())),
            refresh,
            read,
            offer,
        }
    }

    /// Ask the node — at most every [`WATCH_INTERVAL`] — whether it is short, and offer the
    /// notification if it is. **Never blocks**: the read runs on a worker.
    ///
    /// A disconnected engine reads nothing. That is not a silent failure: an unasked question has
    /// no answer, and inventing "funded" from silence would be the direction that costs money.
    pub fn observe(&self, link: &EngineState) {
        let EngineState::Connected { endpoint, .. } = link else {
            return;
        };

        {
            let mut state = self.lock();
            if state.in_flight {
                return;
            }
            if state
                .last_read
                .is_some_and(|last| last.elapsed() < self.refresh)
            {
                return;
            }
            state.in_flight = true;
        }

        let endpoint = endpoint.clone();
        let shared = Arc::clone(&self.state);
        let (read, offer) = (self.read, self.offer);
        std::thread::spawn(move || {
            sweep(&read(&endpoint), offer);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.last_read = Some(Instant::now());
            state.in_flight = false;
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Offer the notification this reading warrants, if any.
///
/// Separate from the threading so the decision is testable as a pure step: a reading in, at most one
/// offer out.
fn sweep(reading: &BufferReading, offer: fn(HoldKey, crate::notify::Notification) -> bool) -> bool {
    let Some(notification) = runway::notification(reading) else {
        return false;
    };
    offer(HoldKey::Collateral, notification)
}

/// Read the buffer over the node ladder, using this machine's control token.
fn read_over_ladder(endpoint: &str) -> BufferReading {
    let token = crate::control::load_control_token();
    read_buffer(endpoint, token.as_deref(), WATCH_READ_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::node::{
        BufferUnknown, CollateralFundingState, CollateralUnknown, NodeBuffer,
    };
    use crate::collateral::SafetyMargin;
    use crate::notify::Notification;
    use std::sync::OnceLock;

    /// What the last `sweep` offered, so a `fn` pointer (which cannot capture) can still report.
    fn offered() -> &'static Mutex<Vec<Notification>> {
        static OFFERED: OnceLock<Mutex<Vec<Notification>>> = OnceLock::new();
        OFFERED.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// The recorder is a `static`, because a `fn` pointer cannot capture. Two cases writing to it
    /// at once would each see the other's offers, so they take turns.
    fn exclusively() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record(_key: HoldKey, notification: Notification) -> bool {
        offered().lock().unwrap().push(notification);
        true
    }

    /// A complete node answer in `state`, with a real gap between the recommendation and the
    /// balance so every state carries a figure — including the one that must stay silent, whose
    /// silence would otherwise be explained by having nothing to say.
    fn buffer(state: CollateralFundingState) -> BufferReading {
        BufferReading::Known(NodeBuffer {
            epoch: 7,
            protocol_version: 1,
            funding_state: state,
            recommended_buffer_dig_base_units: 32_400,
            spendable_dig_base_units: 14_050,
            pairs_served_by_this_node: 12,
            required_per_store_dig_base_units: 1_036,
            margin: SafetyMargin::of_basis_points(100),
            overlap_dig_base_units: 3_108,
            escalation_headroom_dig_base_units: 7_468,
            horizon_epochs: 4,
            escalation_ceiling_micros: 1_601_806,
        })
    }

    /// **Every funding state, swept: only the two shortfalls are offered to the gate.**
    ///
    /// Driven off `CollateralFundingState::ALL` rather than a hand-written pair, so a state added
    /// upstream is covered the day it lands. The offered/withheld verdict is compared against the
    /// contract's own `is_shortfall`, which is the point — this module must hold no second opinion
    /// about which warnings matter, and `below_recommended_buffer` in particular must never reach
    /// the gate at all.
    #[test]
    fn only_a_real_shortfall_is_offered_to_the_gate() {
        let _exclusive = exclusively();
        for &state in CollateralFundingState::ALL {
            offered().lock().unwrap().clear();
            let taken = sweep(&buffer(state), record);
            assert_eq!(
                taken,
                state.is_shortfall(),
                "{state:?} must be offered exactly when the node calls it a shortfall"
            );
            assert_eq!(offered().lock().unwrap().len(), usize::from(taken));
        }
    }

    /// **An unreadable node offers nothing, and it is not because the code path is dead.**
    ///
    /// The control is the shortfall case in the same test: a `sweep` that returned `false`
    /// unconditionally would satisfy the unknown assertion perfectly.
    #[test]
    fn an_unreadable_node_says_nothing_but_a_readable_short_one_speaks() {
        let _exclusive = exclusively();
        offered().lock().unwrap().clear();
        let unknown = BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NoNode));
        assert!(
            !sweep(&unknown, record),
            "an unasked question has no answer"
        );
        assert!(!sweep(&BufferReading::Pending, record));
        assert!(offered().lock().unwrap().is_empty());

        assert!(sweep(&buffer(CollateralFundingState::ShortNow), record));
        let offers = offered().lock().unwrap();
        assert_eq!(offers.len(), 1);
        assert!(
            offers[0].body.contains("$DIG"),
            "the offer carries the node's own figure: {}",
            offers[0].body
        );
    }

    /// How many times the throttle let a read through.
    fn reads() -> &'static std::sync::atomic::AtomicUsize {
        static READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        &READS
    }

    fn counting_read(_endpoint: &str) -> BufferReading {
        reads().fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        buffer(CollateralFundingState::Funded)
    }

    /// A link connected to a node, with the status fields this watch never consults.
    fn connected() -> EngineState {
        EngineState::Connected {
            endpoint: "http://127.0.0.1:4161".to_owned(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// **The node is asked once per interval, not once per repaint.**
    ///
    /// The tray ticks twice a second; the collateral answer changes once a weekly epoch. The second
    /// burst of observations happens with the SAME reading available, so the only thing that can
    /// explain one read instead of twenty is the throttle. The waited-out call afterwards is the
    /// control: without it, a watch that never read again after the first would pass.
    #[test]
    fn the_node_is_asked_on_its_own_cadence_and_not_on_every_tick() {
        let _exclusive = exclusively();
        reads().store(0, std::sync::atomic::Ordering::SeqCst);
        let watch = CollateralWatch::new(Duration::from_secs(3600), counting_read, record);

        for _ in 0..20 {
            watch.observe(&connected());
        }
        // The read runs on a worker; wait for the first one to land rather than racing it.
        for _ in 0..100 {
            if watch.lock().last_read.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            reads().load(std::sync::atomic::Ordering::SeqCst),
            1,
            "twenty ticks, one node round trip"
        );

        // A watch whose interval has elapsed asks again — the same twenty ticks against a zero
        // interval must NOT be silent, or the assertion above would be proving inertia.
        reads().store(0, std::sync::atomic::Ordering::SeqCst);
        let eager = CollateralWatch::new(Duration::ZERO, counting_read, record);
        eager.observe(&connected());
        for _ in 0..100 {
            if eager.lock().last_read.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            reads().load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an elapsed interval reads"
        );
    }

    /// **A disconnected engine reads nothing at all** — the throttle is never even consulted, so a
    /// tray that has lost its node cannot spend threads asking it questions.
    #[test]
    fn a_disconnected_engine_starts_no_read() {
        fn never_read(_: &str) -> BufferReading {
            panic!("a disconnected engine must not be read");
        }
        let watch = CollateralWatch::new(Duration::from_secs(1), never_read, record);
        watch.observe(&EngineState::initial());
        assert!(watch.lock().last_read.is_none());
    }
}
