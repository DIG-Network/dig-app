//! The MACHINE wallet: the node's own operator wallet, which is not the user's (dig-app#339).
//!
//! # Two wallets, and only one of them was ever on screen
//!
//! This computer holds money in two places and they are not interchangeable:
//!
//! | wallet | whose key | what it pays for |
//! |---|---|---|
//! | **user** | the person's own, and it never enters the node (§908) | what the person chooses to spend |
//! | **machine** | the node's own autoseed, sealed under the device key (`SPEC.md` §16.4) | **mirror-coin collateral**, signed without asking |
//!
//! The Wallet tab showed the first one. The node spends the second one. That gap is not cosmetic: a
//! node reporting its mirror bonds `unfunded, short 1010` is making a true statement about a wallet
//! the person has never seen and has no reason to believe exists, while the tab in front of them
//! shows a funded balance. Both readings are correct and together they are misleading, which is the
//! money-honesty defect this module exists to close.
//!
//! The nameable cause was that **`Unfunded` names a figure and no address.** So the rule this module
//! and the pane above it hold is the inverse: **every figure names its wallet**, and the machine
//! wallet's address is a first-class value a person can read and copy, because funding it is the
//! remedy and an address is what funding needs.
//!
//! # This module reads. It never signs, and it never asks the user to
//!
//! §908 is untouched here. The machine wallet is machine custody, and making it *visible* grants
//! nobody a new power over it — there is no verb on this surface. The user's key does not enter the
//! node to make this work, and nothing here moves money between the two wallets: an app-driven
//! sweep from the user wallet to the machine wallet would be a spend of the user's money on a
//! schedule, which is precisely what §908 forbids.
//!
//! # The address is not published yet, and that is stated rather than guessed
//!
//! The node derives this address — `dig_wallet::operator_wallet::operator_puzzle_hash` — but **no
//! control method exposes it.** dig-node's own CLI says so in as many words at
//! `control_cli.rs:956`: *"This node cannot know which address holds an operator's $DIG, and a
//! balance read of the wrong address returns a confident number about the wrong money"* — so
//! `dign collateral buffer` takes the balance as an OPERAND rather than looking it up.
//!
//! dig-app is in the same position, and the honest response to it is
//! [`MachineAddressUnknown::NotPublished`](crate::wallet::machine::MachineAddressUnknown::NotPublished), not a derivation invented here. A second, independent
//! derivation of a money address is the rival-implementation defect in its most expensive form: the
//! two copies would agree until the day they did not, and the day they did not a person would fund
//! an address nothing watches.
//!
//! Everything downstream of the address is already built and address-keyed —
//! [`crate::wallet::node::NodeBalance::observe`] takes an address, and
//! [`crate::wallet::coin_list::refresh`] takes an address — so adopting the method when it publishes
//! is a wiring step and not a second implementation.
//!
//! # Nothing here divides an amount
//!
//! Every figure this reading carries is in its asset's BASE UNIT, exactly as the node reported it.
//! The one place that knows $DIG has three decimals and XCH twelve is
//! [`crate::amount::format_asset_amount`]. A local divisor is what rendered $DIG a billion times too
//! small in dig_ecosystem#2295.

use super::coin_list::CoinListing;
use super::overview::BalanceReading;

/// What the app can honestly say about the machine wallet's address.
///
/// Three states and not two, for the reason [`BalanceReading`] has three: a read in flight is not a
/// fault, and a fault is not an absence. Collapsing `Pending` into an unknown would name a reason
/// during the seconds a node takes to answer, and collapsing it into `Known` is not expressible —
/// which is the point of carrying the address as a reading rather than as an `Option<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineAddressReading {
    /// The node named the address its operator wallet receives at.
    Known(String),
    /// A read is under way and has not answered. Not a fault, so it names no reason.
    Pending,
    /// No address could be read, and which thing was missing.
    Unknown(MachineAddressUnknown),
}

impl Default for MachineAddressReading {
    /// Before anything has been asked, the address is [`Pending`](Self::Pending).
    ///
    /// Deliberately not [`MachineAddressUnknown::NotPublished`]: that is a conclusion about the
    /// node's contract, and a default that states it would have every not-yet-populated snapshot
    /// assert a fault nobody measured.
    fn default() -> Self {
        Self::Pending
    }
}

impl MachineAddressReading {
    /// The address string, when there is one.
    pub fn address(&self) -> Option<&str> {
        match self {
            Self::Known(address) => Some(address),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// Why the machine wallet's address is not known.
///
/// **One variant per REMEDY, never per rough category** — the rule
/// [`AddressUnavailable`](super::overview::AddressUnavailable) records, for the same reason: a
/// surface that names a remedy the reader cannot perform is the dead end dig_ecosystem#1800 removed
/// once already. "Start your node" is right for [`NoNode`](Self::NoNode), useless for
/// [`NotPublished`](Self::NotPublished), and actively wrong for [`ReadFailed`](Self::ReadFailed),
/// where the node answered and said something this app could not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineAddressUnknown {
    /// Nothing answered the §5.3 endpoint ladder, so there is no node to ask.
    ///
    /// Stated as *DIG could not reach one*, never as *none is running*: the ladder's silence is
    /// equally consistent with a node that is starting up.
    NoNode,
    /// A node answered, but its control interface publishes no method that names its operator
    /// wallet's address.
    ///
    /// The state every node is in today, and **not a fault on this machine** — so the sentence for
    /// it must not read as one. It is a contract gap in `dig-node-control-interface`, tracked so the
    /// person reading this surface knows the absence is expected rather than broken.
    NotPublished,
    /// The node was asked and the answer could not be used — quoted, because a node's own words are
    /// more use to whoever debugs this than a category chosen here.
    ReadFailed(String),
}

/// Everything the Machine wallet tab draws, as one reading.
///
/// Carried as a whole rather than as an address plus two loose fields, because the three parts are
/// only meaningful together: a balance without the address it was read for is the exact ambiguity
/// dig-app#339 exists to remove, and a figure that cannot name its wallet is worse than no figure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineWalletReading {
    /// Where the node's operator wallet receives, or why that is not known.
    pub address: MachineAddressReading,
    /// What it holds. [`BalanceReading::Pending`] until an address exists to read for.
    pub balance: BalanceReading,
    /// The coins behind that balance, per asset.
    pub coins: CoinListing,
}

impl MachineWalletReading {
    /// The reading for a machine whose node has not published its operator address.
    ///
    /// The whole reading and not just its address field: with no address there is nothing to read a
    /// balance FOR, so a `Known` balance beside a `NotPublished` address would be a figure about an
    /// address this app cannot name — which is the defect, not a partial fix of it.
    pub fn not_published() -> Self {
        Self {
            address: MachineAddressReading::Unknown(MachineAddressUnknown::NotPublished),
            balance: BalanceReading::Pending,
            coins: CoinListing::default(),
        }
    }
}

/// This process's machine-wallet reading.
///
/// A process-global for the same reason [`crate::wallet::coin_list`]'s listing is one: the pane
/// repaints from a snapshot it does not own, and threading a second reading through `TrayView`
/// would add a field to a struct whose equality check destructures without a rest pattern — the
/// single-writer hazard that makes two lanes touching `TrayView` conflict by construction.
fn app_reading() -> &'static std::sync::Mutex<MachineWalletReading> {
    static READING: std::sync::OnceLock<std::sync::Mutex<MachineWalletReading>> =
        std::sync::OnceLock::new();
    READING.get_or_init(|| std::sync::Mutex::new(MachineWalletReading::not_published()))
}

/// Record what a read of the machine wallet found.
pub fn remember(reading: MachineWalletReading) {
    let mut held = app_reading().lock().unwrap_or_else(|e| e.into_inner());
    *held = reading;
}

/// What the app currently knows about the machine wallet.
pub fn reading() -> MachineWalletReading {
    app_reading()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Serialises the tests that write [`remember`], because the reading is a PROCESS global.
///
/// Cargo runs tests in parallel threads within one process, so two tests that each seed the reading
/// and restore it afterwards interleave: one restores the default while the other is still painting
/// against a known address, and the second reads an absence it did not ask for. That failure is
/// order-dependent and therefore intermittent, which is worse than a red test — it reads as flake.
///
/// Every test that calls [`remember`] takes this first, including the pane tests in
/// `confirm::gui::window::pane::wallet`, and holds it across seed-paint-restore so the three are one
/// step.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::overview::Balances;

    /// The default is not a zero and not a fault — it is the contract gap, named.
    #[test]
    fn the_default_reading_names_the_gap_and_shows_no_figure() {
        let reading = MachineWalletReading::not_published();
        assert_eq!(
            reading.address,
            MachineAddressReading::Unknown(MachineAddressUnknown::NotPublished)
        );
        assert_eq!(reading.balance, BalanceReading::Pending);
        assert_eq!(reading.address.address(), None);
    }

    /// `Pending` is not an unknown, and an unknown is not an address.
    ///
    /// Written against all three states rather than against the default alone, because the failure
    /// this guards is a two-state collapse and a test that only ever sees one state cannot see it.
    #[test]
    fn only_a_known_reading_yields_an_address() {
        assert_eq!(
            MachineAddressReading::Known("xch1machine".into()).address(),
            Some("xch1machine")
        );
        assert_eq!(MachineAddressReading::Pending.address(), None);
        assert_eq!(
            MachineAddressReading::Unknown(MachineAddressUnknown::NoNode).address(),
            None
        );
    }

    /// Each unknown reason is its own value, so a surface can say a different sentence for each.
    ///
    /// The nearest wrong implementation is one enum variant covering "no address" — which reads as
    /// correct until a person with a running node is told to start one. Distinguishing the two
    /// reasons is the property; a fixture holding only one of them could not show it.
    #[test]
    fn the_unknown_reasons_are_distinguishable_from_each_other() {
        assert_ne!(
            MachineAddressUnknown::NoNode,
            MachineAddressUnknown::NotPublished
        );
        assert_ne!(
            MachineAddressUnknown::NotPublished,
            MachineAddressUnknown::ReadFailed("rpc error 500".into())
        );
    }

    /// The global round-trips, so the pane reads what the reader wrote rather than a default.
    ///
    /// Uses a `Known` reading with a real balance, because the state this must carry correctly is
    /// the one that does not exist yet — a round-trip proved only on the default would pass under
    /// an implementation that ignored its argument entirely.
    #[test]
    fn a_recorded_reading_is_what_the_pane_reads_back() {
        let _held = test_lock();
        remember(MachineWalletReading {
            address: MachineAddressReading::Known("xch1machinewallet".into()),
            balance: BalanceReading::Known {
                balances: Balances::of_xch_and_dig(0, 1_015_000),
                as_of: crate::wallet::engine::BalanceAsOf::Undisclosed,
            },
            coins: CoinListing::default(),
        });
        let read = reading();
        assert_eq!(read.address.address(), Some("xch1machinewallet"));
        match read.balance {
            BalanceReading::Known { balances, .. } => assert_eq!(
                balances
                    .holdings
                    .iter()
                    .find(|h| h.asset == crate::wallet::state::Asset::DIG)
                    .map(|h| h.base_units),
                Some(1_015_000)
            ),
            other => panic!("the recorded balance came back as {other:?}"),
        }
        // Left as it was found: this global outlives the test, and a later test reading a fixture
        // address would be reading this one's leftovers.
        remember(MachineWalletReading::not_published());
    }
}
