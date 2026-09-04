//! Keeping [`super::machine`]'s reading current from the running node (dig-app#341).
//!
//! [`super::machine`] holds the reading and [`super::machine_address`] performs one read. This is
//! the thing that runs them on a cadence from the app's paint loop, so the Machine wallet tab shows
//! the node's real address, balance and coins instead of the fixture the preview binary seeds.
//!
//! # The whole reading is written at once, never field by field
//!
//! [`MachineWalletReading`] carries an address, a balance and a coin listing, and its own docs say
//! the three are only meaningful together: a balance without the address it was read for is exactly
//! the ambiguity this tab exists to remove. So this module reads all three on one worker and calls
//! [`super::machine::remember`] once. A per-field write would let the pane paint a balance from the
//! previous address next to the address just discovered — a true figure about the wrong wallet,
//! which is the defect verbatim.
//!
//! # It does not borrow the user wallet's poller, and that is not an oversight
//!
//! [`super::node::NodeBalance`] already polls a balance for an address, and reusing it here would
//! have been one line. Two things make it wrong:
//!
//! * Its cache holds ONE address. Alternating the user's address and the machine's on every tick
//!   would invalidate it twice a second, so both wallets would read `Pending` forever while the
//!   node was asked continuously.
//! * Its worker calls [`super::coin_list::refresh`], which writes the process-global listing the
//!   USER's Coins card draws. Pointed at the machine address it would render the node's own coins
//!   under the user's address — the two-wallets confusion, arriving from the opposite direction.
//!
//! So this watch reads through the same primitives ([`WalletOverview::read`],
//! [`NodeWalletEngine::walk_coins`], [`super::coin_list::listing_for`]) on its own cadence into its
//! own reading. Shared reads, separate destinations.
//!
//! # Nothing here signs, and nothing here moves money (§908)
//!
//! Three reads. The user's key is not involved in any direction, and knowing where the node's
//! wallet receives authorises nobody to spend from it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::engine::EngineState;

use super::machine::{MachineAddressReading, MachineAddressUnknown, MachineWalletReading};
use super::machine_address;
use super::node::NodeWalletEngine;
use super::overview::{AddressReading, BalanceReading, ChainSource, WalletOverview};

/// How often the machine wallet is re-read.
///
/// Slower than the user's wallet on purpose. A person watches their own balance while they spend;
/// the machine wallet changes when a weekly collateral pass runs, and the question this tab answers
/// -- *where do I send $DIG, and has it arrived* -- is not one a faster cadence answers better.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(30);

/// How long the whole three-read pass may take before it is abandoned.
pub const WATCH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Watches the node's own wallet and records what it finds.
pub struct MachineWalletWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    /// Reads the whole machine wallet from an endpoint. Injected so a test answers with its own
    /// reading rather than needing a node, and so the cadence and de-duplication are exercised for
    /// real instead of mocked around.
    read: fn(&str) -> MachineWalletReading,
    /// Records the reading. Injected for the same reason -- a test must be able to see WHAT was
    /// recorded, not merely that nothing panicked.
    record: fn(MachineWalletReading),
}

#[derive(Default)]
struct WatchState {
    last_read: Option<Instant>,
    in_flight: bool,
}

impl Default for MachineWalletWatch {
    fn default() -> Self {
        Self::new(WATCH_INTERVAL, read_over_ladder, super::machine::remember)
    }
}

impl MachineWalletWatch {
    /// A watch with its cadence and both seams stated.
    #[must_use]
    pub fn new(
        refresh: Duration,
        read: fn(&str) -> MachineWalletReading,
        record: fn(MachineWalletReading),
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchState::default())),
            refresh,
            read,
            record,
        }
    }

    /// Ask the node -- at most every [`WATCH_INTERVAL`] -- what its own wallet holds.
    /// **Never blocks**: the read runs on a worker.
    ///
    /// A disconnected engine records [`MachineAddressUnknown::NoNode`] immediately and without a
    /// thread, because that answer involves no I/O. Leaving the previous reading in place instead
    /// would keep a stale address and its balance on screen after the node went away — a figure
    /// about a wallet nothing is currently reading, presented as current.
    pub fn observe(&self, link: &EngineState) {
        let EngineState::Connected { endpoint, .. } = link else {
            (self.record)(MachineWalletReading {
                address: MachineAddressReading::Unknown(MachineAddressUnknown::NoNode),
                balance: BalanceReading::Pending,
                coins: super::coin_list::CoinListing::default(),
            });
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
        let (read, record) = (self.read, self.record);
        std::thread::spawn(move || {
            record(read(&endpoint));
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.last_read = Some(Instant::now());
            state.in_flight = false;
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Read the address, then what it holds, over the node ladder using this machine's control token.
///
/// # The balance and coins are read ONLY for a `Known` address
///
/// Every other address state leaves the balance [`BalanceReading::Pending`] and the coin listing
/// empty, because with no address there is nothing to read them FOR. This is the same rule
/// [`MachineWalletReading::not_published`] encodes: a figure beside an address this app cannot name
/// is the defect, not a partial fix of it.
fn read_over_ladder(endpoint: &str) -> MachineWalletReading {
    let token = crate::control::load_control_token();
    let address = machine_address::read(Some(endpoint), token.as_deref(), WATCH_READ_TIMEOUT);
    let Some(known) = address.address().map(str::to_owned) else {
        return MachineWalletReading {
            address,
            balance: BalanceReading::Pending,
            coins: super::coin_list::CoinListing::default(),
        };
    };

    let engine = NodeWalletEngine::new(endpoint.to_string(), token, WATCH_READ_TIMEOUT);
    let balance = WalletOverview::read(
        AddressReading::Known(known.clone()),
        &ChainSource::Ready(&engine),
    )
    .balance;
    // Reservations are deliberately NOT read, matching the user wallet's poller: the held-coin
    // method is token-gated beyond what this worker carries, and a refusal mapped to "nothing is
    // held" is the one reading that licenses a spend (dig_ecosystem#3170).
    let coins =
        super::coin_list::listing_for(&known, |addr, asset| engine.walk_coins(addr, asset), None);
    MachineWalletReading {
        address,
        balance,
        coins,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serialises the tests, because both seams below are process-global statics.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn recorded() -> &'static Mutex<Vec<MachineWalletReading>> {
        static RECORDED: std::sync::OnceLock<Mutex<Vec<MachineWalletReading>>> =
            std::sync::OnceLock::new();
        RECORDED.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn reads() -> &'static AtomicUsize {
        static READS: AtomicUsize = AtomicUsize::new(0);
        &READS
    }

    fn record(reading: MachineWalletReading) {
        recorded()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(reading);
    }

    fn read_one(_endpoint: &str) -> MachineWalletReading {
        reads().fetch_add(1, Ordering::SeqCst);
        MachineWalletReading {
            address: MachineAddressReading::Known("xch1machinewallet".to_string()),
            ..Default::default()
        }
    }

    fn reset() {
        recorded().lock().unwrap_or_else(|e| e.into_inner()).clear();
        reads().store(0, Ordering::SeqCst);
    }

    fn taken() -> Vec<MachineWalletReading> {
        recorded()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn connected() -> EngineState {
        EngineState::Connected {
            endpoint: "http://127.0.0.1:1/rpc".to_string(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// Wait for the worker to land its record, so the test asserts on a finished read rather than
    /// on a race. Bounded, so a wedged worker fails the test instead of hanging the suite.
    fn settle(expected: usize) {
        for _ in 0..200 {
            if taken().len() >= expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A connected node is read, and the whole reading is recorded.
    #[test]
    fn a_connected_node_is_asked_and_its_answer_recorded() {
        let _guard = test_lock();
        reset();
        let watch = MachineWalletWatch::new(Duration::from_secs(60), read_one, record);
        watch.observe(&connected());
        settle(1);
        assert_eq!(
            taken().first().map(|r| r.address.clone()),
            Some(MachineAddressReading::Known("xch1machinewallet".to_string()))
        );
    }

    /// A second look inside the interval asks nothing.
    ///
    /// The cadence is the whole reason this type exists rather than a call in the paint loop: that
    /// loop runs twice a second, and an unthrottled read would be sixty node round trips a minute
    /// for a figure that changes weekly.
    #[test]
    fn a_second_look_inside_the_interval_asks_nothing() {
        let _guard = test_lock();
        reset();
        let watch = MachineWalletWatch::new(Duration::from_secs(60), read_one, record);
        watch.observe(&connected());
        settle(1);
        watch.observe(&connected());
        watch.observe(&connected());
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            reads().load(Ordering::SeqCst),
            1,
            "the interval was not honoured"
        );
    }

    /// A lapsed interval asks again.
    ///
    /// The pair to the test above, and it is what stops that one from passing on a watch that never
    /// reads at all. A throttle test alone is satisfied by a broken watch.
    #[test]
    fn a_lapsed_interval_asks_again() {
        let _guard = test_lock();
        reset();
        let watch = MachineWalletWatch::new(Duration::from_millis(1), read_one, record);
        watch.observe(&connected());
        settle(1);
        std::thread::sleep(Duration::from_millis(10));
        watch.observe(&connected());
        settle(2);
        assert_eq!(reads().load(Ordering::SeqCst), 2);
    }

    /// The DEFAULT watch — the one the app builds — writes into the REAL reading.
    ///
    /// Every other test here injects both seams, so all of them would keep passing if
    /// [`Default`] were wired to a sink nothing draws from. That is not a hypothetical: for the
    /// whole life of [`super::machine`] before this module, [`super::machine::remember`] was called
    /// only by the preview binary and the pane's own fixtures, so a complete and fully-tested data
    /// model showed a real machine nothing at all. This asserts the one link that gap was made of.
    ///
    /// Driven through the DISCONNECTED arm because it is the one that needs no node and no worker,
    /// so the assertion is about the wiring rather than about a race.
    #[test]
    fn the_default_watch_records_into_the_reading_the_pane_draws() {
        let _guard = test_lock();
        let _reading = crate::wallet::machine::test_lock();
        crate::wallet::machine::remember(MachineWalletReading {
            address: MachineAddressReading::Known("xch1stalefixture".to_string()),
            ..Default::default()
        });

        MachineWalletWatch::default().observe(&EngineState::Disconnected {
            reason: "no node".to_string(),
        });

        assert_eq!(
            crate::wallet::machine::reading().address,
            MachineAddressReading::Unknown(MachineAddressUnknown::NoNode),
            "the default watch does not reach the reading the pane draws"
        );
        crate::wallet::machine::remember(MachineWalletReading::not_published());
    }

    /// A node that went away takes its address with it.
    ///
    /// Asserted as a RECORD rather than as an absence of one: leaving the previous reading in place
    /// would keep a stale address and its balance on screen, presented as current, which is the
    /// exact class of claim this tab exists to stop making.
    #[test]
    fn a_disconnected_node_records_no_node_rather_than_the_previous_address() {
        let _guard = test_lock();
        reset();
        let watch = MachineWalletWatch::new(Duration::from_secs(60), read_one, record);
        watch.observe(&connected());
        settle(1);
        watch.observe(&EngineState::Disconnected {
            reason: "no node".to_string(),
        });
        assert_eq!(
            taken().last().map(|r| r.address.clone()),
            Some(MachineAddressReading::Unknown(MachineAddressUnknown::NoNode)),
            "a disconnected node must not leave the previous address standing"
        );
        assert_eq!(
            reads().load(Ordering::SeqCst),
            1,
            "a disconnected node needs no worker"
        );
    }
}
