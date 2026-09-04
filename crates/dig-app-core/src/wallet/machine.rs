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
    /// A node answered, but it is too old to serve the method that names its operator wallet's
    /// address.
    ///
    /// **Not a fault on this machine** — so the sentence for it must not read as one. The method
    /// (`control.wallet.operatorAddress`) exists in the contract from 0.28.0 and is served, so the
    /// remedy is a node update and the copy says so. Before that it was the state EVERY node was
    /// in, which is why the wording it carried named no remedy at all; a sentence that still said
    /// *no version of it publishes this yet* would now be false on every machine that can read it.
    NotPublished,
    /// The node serves the method and says it has no operator wallet yet.
    ///
    /// **Nothing is wrong**, and the contract says so in as many words: a node that has not run its
    /// autoseed setup has no operator wallet and therefore no address, and it will have one. It is
    /// a fourth state rather than a reuse of a neighbour because both neighbours would misinform —
    /// [`NotPublished`](Self::NotPublished) tells a person to update a node that is already new
    /// enough to have answered, and [`ReadFailed`](Self::ReadFailed) tells them their machine
    /// custody is broken when it is merely unbuilt.
    NotInitialized,
    /// The node was asked and the answer could not be used — quoted, because a node's own words are
    /// more use to whoever debugs this than a category chosen here.
    ReadFailed(String),
}

impl From<crate::activity::absence::ControlAbsence> for MachineAddressUnknown {
    /// The shared control-failure taxonomy, said in this surface's words.
    ///
    /// Exhaustive with **no wildcard arm**, deliberately: a fifth absence must be a build error
    /// here rather than folding into whichever neighbour a `_ =>` happened to point at.
    ///
    /// [`NotInitialized`](Self::NotInitialized) is unreachable from here BY CONSTRUCTION and that
    /// is correct — it is not a failed call at all, but a node that answered and named its own
    /// state, so it can only come from a successful decode in
    /// [`super::machine_address`](crate::wallet::machine_address).
    fn from(absence: crate::activity::absence::ControlAbsence) -> Self {
        use crate::activity::absence::ControlAbsence as Absence;
        match absence {
            Absence::NoNode => Self::NoNode,
            Absence::NotSupported => Self::NotPublished,
            // A node that refused the caller is not a node without the method, and telling somebody
            // to update it would send them after the wrong thing. Quoted as a fault because it is
            // one: this app holds a token the node would not accept.
            Absence::Refused => Self::ReadFailed(
                "Your node refused DIG's request for its own wallet address.".to_string(),
            ),
            Absence::Unreadable => Self::ReadFailed(
                "Your node answered with something DIG could not read.".to_string(),
            ),
        }
    }
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

/// Why the machine address is unknown, in the words a reader sees.
///
/// The ONE place these sentences are chosen, because two surfaces now show them -- the Wallet pane
/// and the sidebar switcher -- and a reason worded twice is a reason that drifts. The pane has room
/// for the whole sentence; the switcher shows the same string in a narrower column.
pub fn unknown_address_reason(why: &MachineAddressUnknown) -> String {
    match why {
        MachineAddressUnknown::NoNode => NO_NODE.to_string(),
        MachineAddressUnknown::NotPublished => NOT_PUBLISHED.to_string(),
        MachineAddressUnknown::NotInitialized => NOT_INITIALIZED.to_string(),
        // The node's own words, quoted whole. A category chosen here would throw away the only
        // detail that helps whoever debugs it.
        MachineAddressUnknown::ReadFailed(said) => said.clone(),
    }
}

/// The same reason, short enough for the sidebar switcher.
///
/// A SECOND wording rather than a truncation of the first, because the sidebar has room for about
/// four words and a sentence cut at that width loses its verb. Each of these says the same thing as
/// its long form in the space available; the Wallet pane, which has room, shows the long one.
///
/// The pairing is deliberate and is asserted: a short form that said something DIFFERENT from its
/// long form would be two answers to one question, which is the drift this crate words its reasons
/// in one place to avoid.
pub fn short_address_reason(why: &MachineAddressUnknown) -> String {
    match why {
        MachineAddressUnknown::NoNode => "Node not reachable".to_string(),
        MachineAddressUnknown::NotPublished => "Node too old to say".to_string(),
        MachineAddressUnknown::NotInitialized => "No wallet on your node yet".to_string(),
        // Not the node's own words here: they are arbitrarily long and this surface has four words.
        // The pane quotes them in full, which is where somebody debugging will look.
        MachineAddressUnknown::ReadFailed(_) => "Address could not be read".to_string(),
    }
}

/// Said when nothing answered the §5.3 endpoint ladder.
///
/// *Could not reach* rather than *is not running*: the ladder's silence is equally consistent with a
/// node that is still starting up, and telling somebody to start a node they already started is the
/// dead end this app removed once already.
const NO_NODE: &str =
    "DIG could not reach your node, so it cannot ask where your node's own wallet receives.";

/// Said when the node is too old to serve the method naming its operator address.
///
/// Deliberately NOT phrased as a fault on this computer, because it is not one. It names the remedy
/// -- an update -- which the sentence this replaced could not: while NO node published the method,
/// the honest wording was *no version of it publishes this yet*, and that claim became false in the
/// same commit that taught this app to ask. A sentence that still said it would tell a person with
/// a current node to go looking for a setting that does not exist.
const NOT_PUBLISHED: &str = concat!(
    "Your node is too old to tell DIG where its own wallet receives, so this address cannot be ",
    "shown. Nothing is wrong with it — updating your node will let DIG ask.",
);

/// Said when the node serves the method and has no operator wallet yet.
///
/// The one absence on this surface that asks for NOTHING. A person reading it has a working, current
/// node that has simply not built its own wallet yet, and the contract states outright that a client
/// must not present this as a fault -- so the sentence neither blames the machine nor offers a
/// remedy for a problem that does not exist.
const NOT_INITIALIZED: &str = concat!(
    "Your node has not set up its own wallet yet, so it has no address to receive at. Nothing is ",
    "wrong: it will have one once it finishes setting itself up.",
);

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

    /// **Every reason has a short form that FITS the switcher and still says something.**
    ///
    /// The sidebar has room for about four words at XS. A reason that overruns renders truncated —
    /// losing its verb, which is how a custody badge came to read *"Your node spends this witho…"* —
    /// and an empty one leaves a wallet with nothing under its name, which reads as a wallet with no
    /// address at all.
    ///
    /// # Why the bound is on WIDTH and not on "shorter than the long form"
    ///
    /// That was this test's first shape and it was wrong, which the test itself caught.
    /// [`MachineAddressUnknown::ReadFailed`] carries **the node's own words**, and a node is free to
    /// say something very short — `rpc error 500 after 30s` is already shorter than any fixed
    /// sentence written here. So "the short form is shorter" is not a property of that variant at
    /// all, and asserting it would have forced the short form to be worded around a fixture rather
    /// than around the column it has to fit in.
    ///
    /// The width bound is the real requirement and it holds for every variant. The shorter-than
    /// relation is asserted only for the two whose long form is a constant this crate controls.
    #[test]
    fn every_reason_has_a_short_form_that_fits_the_switcher() {
        /// What the 208 px sidebar renders without truncating at XS.
        const FITS: usize = 28;

        for why in [
            MachineAddressUnknown::NoNode,
            MachineAddressUnknown::NotPublished,
            MachineAddressUnknown::ReadFailed("rpc error 500 after 30s".into()),
        ] {
            let short = short_address_reason(&why);
            assert!(
                !short.trim().is_empty(),
                "{why:?} has an empty short reason, which reads as no address at all"
            );
            assert!(
                short.chars().count() <= FITS,
                "{why:?}'s short reason will truncate in the switcher: {short:?}"
            );
        }

        // The two whose long form this crate writes are genuinely condensed rather than merely
        // different. Asserted separately, because the third variant's long form is not ours.
        for why in [
            MachineAddressUnknown::NoNode,
            MachineAddressUnknown::NotPublished,
        ] {
            assert!(
                short_address_reason(&why).chars().count()
                    < unknown_address_reason(&why).chars().count(),
                "{why:?}'s short reason is not a condensation of its long one"
            );
        }

        // The bound from the other side, so it cannot be satisfied by a short form that says
        // nothing: the LONG form of a reason this crate writes must genuinely overrun the column,
        // or there was no reason to have two wordings.
        assert!(
            unknown_address_reason(&MachineAddressUnknown::NotPublished)
                .chars()
                .count()
                > FITS,
            "the long reason now fits the switcher, so the short form is redundant"
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
