//! What the app can HONESTLY say about the account's money right now (dig_ecosystem#1850).
//!
//! The Wallet surface answers two questions — *where do I receive?* and *what do I hold?* — and the
//! second one has a trap in it. A balance the app could not read is not zero; it is unknown. Rendering
//! it as `0` is how a person concludes their money is gone, so the two are DIFFERENT TYPES here
//! ([`BalanceReading::Known`] vs [`BalanceReading::Unknown`]) and the renderer has no path that turns
//! an unknown into a numeral.
//!
//! Every unknown carries WHICH thing is missing ([`BalanceUnknown`]), because "we cannot show your
//! balance" with no reason is a dead end in the sense dig_ecosystem#1800 removed from the tray: the
//! reason is what tells a person whether to start their node, wait, or unlock.
//!
//! # Where the numbers come from
//!
//! Balances are chain state, which dig-app deliberately cannot read for itself — the node holds the
//! peer connections and the coinset access (the `control.wallet.*` seam, [`super::engine`]). So the
//! source is an input ([`ChainSource`]) rather than something this module reaches for; the production
//! source is [`super::node::NodeWalletEngine`], which speaks `control.wallet.balance` to whichever
//! node the §5.3 ladder found.
//!
//! # Why the reasons are not decided here
//!
//! There are two honest sources — no node at all, or a node to ask — and this module never guesses
//! which of the *further* reasons applies. Whether a node can serve a wallet read, and whether its
//! chain view is caught up, are answers only the node can give: they arrive as
//! [`WalletError::EngineUnsupported`] / [`WalletError::EngineNotSynced`] from the read itself and are
//! translated where the read happens. A constant in this file claiming to know them is exactly the
//! defect dig_ecosystem#2206 removed.

use crate::amount::amount_with_unit;

use super::engine::{BalanceAsOf, BalanceRequest, WalletEngine};
use super::state::Asset;
use super::WalletError;

/// The account's receive address, or the reason there is not one to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressReading {
    /// The derived `xch1…` address this account receives at.
    Known(String),
    /// No address can be shown, and why.
    Unavailable(AddressUnavailable),
}

/// Why no receive address is available.
///
/// **One variant per REMEDY, never per rough category.** The account has six user-visible states and
/// they do not share a way forward: unlocking is right for a locked account, useless to someone who has
/// never set a password, and actively wrong for an account that cannot be opened *because unlocking is
/// what already failed*. Collapsing them — as this enum's first three variants did — produces a surface
/// that names a remedy the user cannot perform, which is the dead end dig_ecosystem#1800 removed from
/// the tray menu (dig_ecosystem#1841).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressUnavailable {
    /// There is no account on this computer yet, so there is no key to derive an address from.
    NoAccount,
    /// This host has no per-application credential store, so it cannot hold an account at all. NOT
    /// [`NoAccount`](Self::NoAccount): "set one up" is advice that cannot be followed here.
    HostUnsupported,
    /// The account exists but is still sealed under the machine-generated password. NOT
    /// [`Locked`](Self::Locked): there is no password to type yet, so the way forward is to CHOOSE one.
    NoPasswordYet,
    /// The account is locked. An address is public, but deriving one needs the key material a lock
    /// deliberately drops — so the address is *withheld*, never guessed.
    Locked,
    /// The account will not open at all. NOT [`Locked`](Self::Locked): unlocking is the thing that
    /// already failed, so offering it again names a remedy guaranteed not to work.
    Unopenable,
    /// The account is unlocked but the address could not be encoded — a genuine defect, surfaced
    /// rather than swallowed, because the alternative is showing something wrong.
    DerivationFailed,
    /// The account is unlocked, but its wallet was opened at a different profile than the one now
    /// active, so the only address it can derive belongs to the profile the user just left
    /// (dig_ecosystem#2496). NOT [`Locked`](Self::Locked) and NOT
    /// [`DerivationFailed`](Self::DerivationFailed): nothing is broken and unlocking is not the
    /// remedy — re-opening the account is.
    WalletBehindActiveProfile,
}

impl AddressReading {
    /// The address string, when there is one.
    pub fn address(&self) -> Option<&str> {
        match self {
            Self::Known(address) => Some(address),
            Self::Unavailable(_) => None,
        }
    }
}

/// One asset's spendable amount, in that asset's own base unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holding {
    /// Which token this is an amount of.
    pub asset: Asset,
    /// How much is held, in [`asset`](Self::asset)'s base unit. Only meaningful WITH the asset —
    /// see [`crate::amount::amount_with_unit`], which is why the two are one
    /// struct and never two parallel lists.
    pub base_units: u64,
}

/// What this wallet holds, one entry per asset it reads (dig_ecosystem#3077).
///
/// # Why this stopped being a pair of named fields
///
/// It was `{ xch_mojos, dig_units }` — two fields, two assets, and no way to express a third. A
/// wallet that holds a CAT could not say so, so the token was simply absent from the surface with
/// nothing to indicate anything was missing. Widening it to a LIST is what lets a person see the
/// tokens they hold; [`xch_mojos`](Self::xch_mojos) and [`dig_units`](Self::dig_units) remain as
/// accessors because the two assets dig-app knows by name are still special — they are the two the
/// send form weighs an amount and a fee against.
///
/// An asset that was not READ is ABSENT from this list, and [`of`](Self::of) answers `0` for it.
/// That is deliberate but narrow: this type is only ever built from a completed read of a KNOWN
/// list of assets (see `read_balances`), and a read that failed for any asset produces
/// [`BalanceReading::Unknown`] for the whole reading rather than a `Balances` with a gap in it. So
/// a zero here always means a read that came back empty, never a read that did not happen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Balances {
    /// Every asset read, in the order it was asked for — XCH first, then $DIG, then watched CATs.
    pub holdings: Vec<Holding>,
}

impl Balances {
    /// A reading of exactly the two assets dig-app knows by name.
    ///
    /// The shape this type used to have, kept as a CONSTRUCTOR because it is still the common case
    /// — a wallet nobody has added a token to holds exactly these two — and because a fixture that
    /// says `of_xch_and_dig(1, 2)` reads better than one that assembles a vector of structs. What it
    /// is no longer is the only shape expressible.
    pub fn of_xch_and_dig(xch_mojos: u64, dig_units: u64) -> Self {
        Self {
            holdings: vec![
                Holding {
                    asset: Asset::Xch,
                    base_units: xch_mojos,
                },
                Holding {
                    asset: Asset::DIG,
                    base_units: dig_units,
                },
            ],
        }
    }

    /// The amount held of `asset`, or `0` when this reading did not cover it.
    pub fn of(&self, asset: Asset) -> u64 {
        self.holdings
            .iter()
            .find(|holding| holding.asset == asset)
            .map_or(0, |holding| holding.base_units)
    }

    /// Native Chia held, in mojos — the currency every network fee is paid in.
    pub fn xch_mojos(&self) -> u64 {
        self.of(Asset::Xch)
    }

    /// $DIG held, in base units.
    pub fn dig_units(&self) -> u64 {
        self.of(Asset::DIG)
    }
}

/// What the app knows about the balance. **Two states, never collapsed**: an unknown balance is not a
/// zero balance, and this type is what keeps a renderer from pretending otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalanceReading {
    /// A balance actually read from a chain source. `0` here means genuinely nothing held.
    ///
    /// Carries its [`BalanceAsOf`] because a figure from a light client is a statement about a
    /// MOMENT, not about now: the replica trails the tip permanently, so "wait until it is caught
    /// up" shows no balance at all (dig_ecosystem#2824). Shown with its as-of, a behind figure is
    /// true; shown bare, it is a claim about the present that nothing supports.
    Known {
        /// What is held, as of `as_of`.
        balances: Balances,
        /// What those figures are true as of.
        as_of: BalanceAsOf,
    },
    /// A read is under way and has not answered yet.
    ///
    /// The third state, and the honest one for the several seconds a chain read takes
    /// (dig_ecosystem#2325): nothing has failed, so naming a *reason* would invent one. It is not an
    /// [`Unknown`](Self::Unknown) for that reason — every unknown carries a fault, and "still
    /// fetching" is not a fault.
    Pending,
    /// No balance could be read, and which thing was missing.
    Unknown(BalanceUnknown),
}

impl Default for BalanceReading {
    /// Before anything has been asked, the balance is [`Pending`](Self::Pending) — not a zero, and
    /// not a fault either.
    ///
    /// It used to default to [`BalanceUnknown::NoNode`], which stated a conclusion about the user's
    /// computer that no read had been made to support (dig_ecosystem#2325). A `Default` of
    /// `Known(0)` would be worse still: it would hand every not-yet-populated snapshot a balance it
    /// never read.
    fn default() -> Self {
        BalanceReading::Pending
    }
}

/// Why a balance could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalanceUnknown {
    /// There is no address to read a balance for — the address's own reason applies first, because
    /// "start your node" is useless advice to someone with no account.
    NoAddress(AddressUnavailable),
    /// Nothing answered the §5.3 endpoint ladder, so DIG has no node to ask.
    ///
    /// Stated as *DIG could not reach one*, never as *none is running*: the ladder's silence is
    /// evidence about this app's reach, and a node listening somewhere DIG does not look would make
    /// the stronger claim false (dig_ecosystem#2325).
    NoNode,
    /// A node accepted the connection and did not finish the read in time.
    ///
    /// Deliberately NOT [`NoNode`](Self::NoNode): the socket connected, so a node is demonstrably
    /// there and the surface must not send its owner off to start one. This is the state a live user
    /// was shown as "no DIG node is running" while the Status tab, on the same screen, showed the
    /// node healthy (dig_ecosystem#2325).
    NodeTimedOut,
    /// A node answered, but this build of it does not serve wallet chain reads.
    NodeCannotRead,
    /// A node answered and DOES serve wallet reads, but has no live view of the chain to read from.
    ///
    /// Deliberately NOT folded into [`NodeCannotRead`](Self::NodeCannotRead) or
    /// [`NotSynced`](Self::NotSynced): the build is capable, and the node is not merely behind — it
    /// has no chain source at all. Those three call for different things (upgrade / wait / the
    /// node's own connection), and a surface that names the wrong one sends a person after a fault
    /// they do not have. This is the state a default dig-node install is in today.
    NoChainSource,
    /// The NODE ITSELF refused the read as not caught up (`WALLET_NOT_SYNCED`).
    ///
    /// This is the node declining to answer, not this app declining to show a behind figure — dig-app
    /// no longer does the latter, because a light client is never caught up and that rule hid the
    /// balance permanently (dig_ecosystem#2824). A figure the node DOES give while behind is shown
    /// with its as-of height instead.
    ///
    /// It is ONE of at least three situations that used to render as it — see
    /// [`AddressesNotFollowed`](Self::AddressesNotFollowed) and
    /// [`AwaitingNodeRestart`](Self::AwaitingNodeRestart), which it must no longer speak for.
    NotSynced,
    /// The node's own replica answered and has synced nothing, so there is no figure to show.
    ///
    /// Its `balance: 0` is *no data*, not *no money*, and this variant is what keeps the two apart:
    /// a zero rendered here would tell somebody who holds funds that they hold none. Absent, not
    /// stale, and never a numeral.
    ReplicaHasNoData,
    /// The node is following NO addresses of this account, measured, so it holds no record of this
    /// account's coins to read (dig_ecosystem#2848).
    ///
    /// It claims nothing about the node's chain position, because the reading that produces it —
    /// [`SyncProgress::NothingToSync`](crate::network::SyncProgress::NothingToSync) — is answered
    /// from the watched count BEFORE either height is consulted, so this is reached on a first run
    /// that is genuinely still syncing as well as on a caught-up one.
    ///
    /// Distinct from [`NotSynced`](Self::NotSynced) because the remedy is the opposite one: waiting
    /// achieves nothing here, since a replica with an empty subscription does not sync by design.
    /// This is the state a live user was shown as "your node is still catching up with the
    /// blockchain" while the same window reported the chain synced — the contradiction that opened
    /// dig_ecosystem#2848.
    AddressesNotFollowed,
    /// The node has ACCEPTED this account's keys and has not begun following them yet, because
    /// enrolment reaches the live subscription only at the node's next start
    /// (dig_ecosystem#2826).
    ///
    /// A known interval with a known cause, so it is neither a fault nor a silent wait: it is
    /// reported as itself. Distinct from [`AddressesNotFollowed`](Self::AddressesNotFollowed)
    /// because nothing more is asked of anyone — the registration already happened.
    AwaitingNodeRestart,
    /// The read reached a source and failed. Carries the source's own words so the window can say
    /// what went wrong.
    ReadFailed(String),
}

/// What there is to ask about a balance right now.
///
/// Exactly two states, because there are only two things the caller can know without asking: either
/// the §5.3 ladder found nothing, or it found a node. Everything else — whether that node serves
/// wallet reads at all, whether it is caught up, whether the read failed — is the NODE's answer, and
/// arrives as a typed [`WalletError`] from the engine rather than as a variant guessed here.
pub enum ChainSource<'a> {
    /// Nothing answered the §5.3 endpoint ladder, so there is nobody to ask.
    Absent,
    /// A node to ask. Its answer decides the rest.
    Ready(&'a dyn WalletEngine),
}

/// Everything the Wallet surface renders: where money arrives, and what is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletOverview {
    /// The receive address, or why there is none.
    pub address: AddressReading,
    /// The balance, or why it is unknown.
    pub balance: BalanceReading,
    /// Whether this host could not READ its profile registry, in which case the address above is the
    /// account's root address rather than the active profile's (dig_ecosystem#2398).
    ///
    /// An unreadable registry boots the app unprofiled, and unprofiled derives at
    /// [`ProfileIx::ROOT`](dig_account::ProfileIx::ROOT). Everything is then internally consistent —
    /// the wallet and the active profile agree, so no money accessor refuses — and the address on
    /// screen is nonetheless a DIFFERENT address from the one a person on profile 3 was handing out.
    /// That is the silent address move this whole area exists to prevent, so it is stated rather
    /// than left to be inferred from the profile list.
    pub profiles_unreadable: bool,
    /// The peak this node's own Chia peers announced, or `None` when none has.
    ///
    /// Carried beside the balance because a height alone cannot say whether a figure is CURRENT —
    /// only a comparison can, and this is the only chain tip the app knows. Without it the surface
    /// can state what a figure is true as of, and can never state that it is up to date.
    ///
    /// `None` fails closed to the as-of wording, which is true whether or not the replica has caught
    /// up. That is why this is an `Option` rather than a height defaulted to zero: a zero would make
    /// every figure trivially "up to date", which is the money-currency version of the
    /// absent-rendered-as-zero mistake this module exists to prevent.
    pub peers_peak: Option<u32>,
}

impl WalletOverview {
    /// Read the overview for `address` against `source`.
    ///
    /// The address's availability is checked FIRST: with no address there is nothing to read a balance
    /// for, and the address's reason is the actionable one.
    pub fn read(address: AddressReading, source: &ChainSource<'_>) -> Self {
        Self::read_assets(address, source, &[Asset::Xch, Asset::DIG])
    }

    /// Read the overview for `address` against `source`, covering exactly `assets`.
    ///
    /// [`read`](Self::read) is this method pinned to the two assets dig-app knows by name. A caller
    /// that knows the wallet's watch list passes it here so the person sees the tokens they added;
    /// a caller that does not gets the two, which is what this surface has always shown.
    ///
    /// The asset list is a PARAMETER and not something this module reaches for, because dig-app
    /// cannot discover which CATs an address holds: the node's wallet seam answers one named asset
    /// at a time and has no enumeration method (dig_ecosystem#3115). A token is read because
    /// somebody named it.
    pub fn read_assets(
        address: AddressReading,
        source: &ChainSource<'_>,
        assets: &[Asset],
    ) -> Self {
        let balance = match (&address, source) {
            (AddressReading::Unavailable(why), _) => {
                BalanceReading::Unknown(BalanceUnknown::NoAddress(*why))
            }
            (_, ChainSource::Absent) => BalanceReading::Unknown(BalanceUnknown::NoNode),
            (AddressReading::Known(address), ChainSource::Ready(engine)) => {
                read_balances(address, *engine, assets)
            }
        };
        // `read` is the direct-address path (the shell has an address in hand and wants a balance),
        // which never consults a registry. The caveat belongs to `of_tray`, which does.
        Self {
            address,
            balance,
            profiles_unreadable: false,
            // This path reads a balance for an address handed to it; it has no view of the network
            // and therefore no chain tip to compare against. `None` is the honest answer, and it
            // fails closed to the as-of wording — a figure from this constructor is never claimed to
            // be up to date, because nothing here could check that.
            peers_peak: None,
        }
    }

    /// The overview the tray's Wallet window renders, derived from the snapshot the menu was built from.
    ///
    /// Lives here rather than in the `dig-app` shell because a binary is a test-free zone and this
    /// mapping is exactly where an unknown could quietly become a zero: it decides which reason the
    /// window states.
    pub fn of_tray(view: &crate::tray_menu::TrayView) -> Self {
        use crate::tray_menu::{AccountState, AddressFault};

        // One arm per account state, because each has a different way forward and the surface states it
        // verbatim. The three that used to fall through to `Locked` were each told to unlock: a host that
        // cannot hold an account, an account with no password to type, and an account whose unlock is
        // exactly what failed.
        let address = match (&view.receive_address, view.account.as_ref()) {
            (Some(address), _) => AddressReading::Known(address.clone()),
            // No account, or none reported yet: there is no key to derive from and nothing to wait for.
            (None, None | Some(AccountState::Absent)) => {
                AddressReading::Unavailable(AddressUnavailable::NoAccount)
            }
            (None, Some(AccountState::Unsupported)) => {
                AddressReading::Unavailable(AddressUnavailable::HostUnsupported)
            }
            (None, Some(AccountState::NeedsPassword)) => {
                AddressReading::Unavailable(AddressUnavailable::NoPasswordYet)
            }
            (None, Some(AccountState::Unopenable)) => {
                AddressReading::Unavailable(AddressUnavailable::Unopenable)
            }
            // Unlocked at the moment of observation, yet the derivation itself failed: unlocking is NOT
            // the way back, because unlocking is not what is missing (dig_ecosystem#2059). Checked
            // before the plain `Locked` arm below so this — the narrower, rarer case — wins.
            (None, Some(AccountState::Unlocked { .. }))
                if view.address_fault == Some(AddressFault::DerivationFailed) =>
            {
                AddressReading::Unavailable(AddressUnavailable::DerivationFailed)
            }
            // Unlocked, and the wallet is pinned behind the profile now active. Checked beside the
            // arm above and before the plain `Locked` one, for the same reason: unlocking is a remedy
            // that cannot work here, and the address that DOES exist is the wrong profile's.
            (None, Some(AccountState::Unlocked { .. }))
                if view.address_fault == Some(AddressFault::WalletBehindActiveProfile) =>
            {
                AddressReading::Unavailable(AddressUnavailable::WalletBehindActiveProfile)
            }
            // Locked, or unlocked-but-address-not-yet-derived for an ordinary reason (e.g. the shell
            // simply hasn't read it this repaint): the key material is sealed and unlocking is genuinely
            // the route back.
            (None, Some(AccountState::Locked | AccountState::Unlocked { .. })) => {
                AddressReading::Unavailable(AddressUnavailable::Locked)
            }
        };

        // The balance is NOT read here. A tray snapshot is taken on every repaint (twice a second),
        // and a chain read is a network round trip the node rate-limits — so the reading is polled on
        // its own cadence by `super::node::NodeBalance` and carried in the view. This mapping only
        // decides whether that reading is the one to show: with no address there is nothing the
        // figure could be ABOUT, and the address's reason is the actionable one.
        let balance = match &address {
            AddressReading::Unavailable(why) => {
                BalanceReading::Unknown(BalanceUnknown::NoAddress(*why))
            }
            // The node's refusal arrives with the balance; what that refusal MEANS needs two more
            // readings from the same snapshot, so the naming happens here rather than in the
            // engine (dig_ecosystem#2848).
            AddressReading::Known(_) => match &view.balance {
                BalanceReading::Unknown(BalanceUnknown::NotSynced) => {
                    BalanceReading::Unknown(refine_unsynced(&view.network, &view.enrolment))
                }
                other => other.clone(),
            },
        };
        Self {
            address,
            balance,
            profiles_unreadable: view.profiles.is_unreadable(),
            // The one figure that can say whether the balance above is CURRENT. Taken from the same
            // snapshot as the balance so the two describe one moment; a pane that read it separately
            // could call a figure up to date on the strength of a later reading than the figure.
            peers_peak: view.network.chia_peer_peak_height,
        }
    }
}

/// Which of the three "no figure yet" situations the node is actually in
/// (dig_ecosystem#2848).
///
/// The node declines a read with one symbol, `WALLET_NOT_SYNCED`, for situations whose remedies have
/// nothing in common: one is waited out, one is fixed by enrolling addresses, and one is a known
/// interval that resolves itself. Telling them apart needs two readings the engine's error does not
/// carry — the node's own catch-up [`progress`](crate::network::NetworkStanding::progress) and what
/// this app knows about [`Enrolment`] — which is why this is a function over a SNAPSHOT rather than
/// a mapping in `why_unread`.
///
/// # A measured distance keeps the original reason
///
/// [`SyncProgress::Behind`] means the replica trails the peak its peers announced, and there waiting
/// IS the remedy — any other explanation would distract from a wait that is working.
///
/// # What the enrolment reasons may NOT claim, and why
///
/// [`NetworkStanding::progress`](crate::network::NetworkStanding::progress) answers
/// [`NothingToSync`](SyncProgress::NothingToSync) from the measured `watched_addresses` alone,
/// **before it looks at either height** — deliberately, because a replica with an empty subscription
/// is frozen rather than lagging and a distance computed over it is arithmetically correct and false
/// (dig_ecosystem#2820).
///
/// So this arm is ALSO reached on a first run that is genuinely still syncing with nothing enrolled,
/// and neither enrolment sentence may assert that the node is caught up. An earlier draft opened
/// with *"your node is caught up with the blockchain"* — the mirror of the defect this whole feature
/// exists to remove, an app asserting a sync state nobody measured, merely inverted. The sentences
/// therefore say only what the enrolment fact supports: which addresses the node follows, and what
/// happens next.
///
/// # Silence where nothing is known
///
/// [`SyncProgress::CaughtUp`] and [`SyncProgress::CannotTell`] fall back to
/// [`BalanceUnknown::NotSynced`] unchanged. Both are states where the node has declined for a reason
/// this app cannot name, and naming one anyway — "your addresses are not followed" over a node that
/// has simply not resolved its subscription yet — would trade a vague truth for a confident guess.
fn refine_unsynced(
    standing: &crate::network::NetworkStanding,
    enrolment: &crate::wallet::enrol::Enrolment,
) -> BalanceUnknown {
    use crate::network::SyncProgress;
    use crate::wallet::enrol::Enrolment;

    match standing.progress() {
        SyncProgress::Behind { .. } => BalanceUnknown::NotSynced,
        // A MEASURED empty subscription: whatever this node's chain position is, it holds no record
        // of THIS account, so a catch-up is not what stands between the user and their figure — see
        // the doc above for why no claim about that position may ride along. Which of the two
        // enrolment reasons it is turns on whether
        // this app has got its keys ACCEPTED — the node takes them into its live set only when it
        // next starts (dig_ecosystem#2826), so "registered" and "followed" are different facts and
        // the wait between them is its own state.
        SyncProgress::NothingToSync => match enrolment {
            Enrolment::Registered => BalanceUnknown::AwaitingNodeRestart,
            Enrolment::Unasked | Enrolment::Refused(_) => BalanceUnknown::AddressesNotFollowed,
        },
        SyncProgress::CaughtUp | SyncProgress::CannotTell => BalanceUnknown::NotSynced,
    }
}

/// The Wallet window's whole text: where money arrives, what is held, and where sending lives.
///
/// # Why this window names the Wallet tab rather than denying sending
///
/// This is the TRAY's read-only wallet notice, and it long said *"sending is not available yet — DIG
/// will not offer a button that moves money until the path behind it is finished"*. That was true
/// while the money path was parked, and dig-app#167/#174 shipped a real Send verb in the window's
/// Wallet tab — so a released build told a person in one window that a control they can press in
/// another does not exist (dig_ecosystem#2988). An app that denies a capability it ships is lying
/// about money in the direction that costs it every other claim it makes.
///
/// What is true of THIS window is unchanged: it is a notification body assembled by `explain_wallet`,
/// with no control and no row that emits an action. So it says that, and points at the surface
/// that can, instead of speaking for the whole app.
pub fn window_body(overview: &WalletOverview) -> String {
    format!(
        "{}{}\n\n{}\n\nThis window shows what you hold; it does not send. Sending is in the DIG \
         window's Wallet tab, which states its own reason underneath when it cannot go ahead. \
         Receiving works now: anything sent to the address above \
         arrives in this account, and your recovery phrase restores it.\n\n\
         Reading DIG content never needs an account or a wallet.",
        address_line(&overview.address),
        unreadable_registry_caveat(overview.profiles_unreadable),
        balance_line(&overview.balance, overview.peers_peak),
    )
}

/// The sentence appended to the address line when this host could not READ its profile registry.
///
/// A caveat on an address that derived perfectly well, not a fault instead of one: the app is running
/// at the account root, so nothing refuses and nothing looks wrong — which is exactly why somebody
/// who was using another profile has to be told, rather than left to notice that their address
/// changed.
fn unreadable_registry_caveat(unreadable: bool) -> &'static str {
    match unreadable {
        false => "",
        true => {
            "\n\nDIG could not read your list of profiles on this computer, so it is using your \
             account's main address. If you were using a different profile, this is NOT that \
             profile's address — the Account tab explains what could not be read."
        }
    }
}

/// Read every asset in `assets` for `address`.
///
/// A failure in ANY of them makes the WHOLE reading unknown — a window showing one asset's balance
/// beside a silently-missing other is a half-truth about someone's money, and that stays true when
/// the missing one is the third token rather than the second. The alternative, a partial list, would
/// render a held token as absent, which is the absent-shown-as-zero mistake wearing a different hat.
fn read_balances(address: &str, engine: &dyn WalletEngine, assets: &[Asset]) -> BalanceReading {
    let mut holdings = Vec::with_capacity(assets.len());
    // Seeded from the FIRST read rather than from a constant, because `BalanceAsOf` deliberately has
    // no `Default`: every provenance is a claim, and there is no claim to make before a read.
    let mut as_of: Option<BalanceAsOf> = None;

    for asset in assets {
        match engine.balance(BalanceRequest {
            address: address.to_string(),
            asset: *asset,
        }) {
            Ok(answer) => {
                holdings.push(Holding {
                    asset: *asset,
                    base_units: answer.balance,
                });
                // Each asset is read separately and they are shown as one holding, so the set takes
                // the weakest provenance among them — see `BalanceAsOf::weaker`.
                as_of = Some(match as_of {
                    Some(so_far) => so_far.weaker(answer.as_of),
                    None => answer.as_of,
                });
            }
            Err(e) => return BalanceReading::Unknown(why_unread(e)),
        }
    }

    match as_of {
        Some(as_of) => BalanceReading::Known {
            balances: Balances { holdings },
            as_of,
        },
        // Nothing was asked for, so nothing was learned. Not a `Known` empty holding: that would
        // state that this wallet holds nothing, on the strength of no read at all.
        None => BalanceReading::Pending,
    }
}

/// Translate the engine's typed failure into the reason a person is shown.
///
/// The three named variants exist so that the node's own answer — not a constant in this file —
/// decides which remedy the window offers. Anything else is a genuine read failure and carries the
/// source's words, because a fault we cannot classify must not be dressed up as one we can.
///
/// Public because the coin list ([`crate::wallet::coin_list`]) reads the SAME node over the same
/// transport and must name the same fault in the same words. A second mapping there would be a
/// rival that drifts, and the way it would drift is a coin list saying "no node" on the frame the
/// balance beside it says "still syncing".
pub fn why_unread(error: WalletError) -> BalanceUnknown {
    match error {
        WalletError::EngineUnreachable(_) => BalanceUnknown::NoNode,
        WalletError::EngineTimedOut(_) => BalanceUnknown::NodeTimedOut,
        WalletError::EngineUnsupported => BalanceUnknown::NodeCannotRead,
        WalletError::EngineNotSynced => BalanceUnknown::NotSynced,
        WalletError::EngineNoReplicaData => BalanceUnknown::ReplicaHasNoData,
        WalletError::EngineNoChainSource => BalanceUnknown::NoChainSource,
        other => BalanceUnknown::ReadFailed(other.to_string()),
    }
}

/// Render a held amount WITH its unit, the way a person reads it — see
/// [`crate::amount::amount_with_unit`], which this delegates to so that the
/// Wallet surface cannot acquire a divisor of its own (dig_ecosystem#2295).
///
/// The unit travels with the figure because for a CAT dig-app has only been told the id of, the
/// figure is in BASE UNITS and saying so is the whole difference between a true statement and a
/// whole-coin claim nothing measured.
pub fn format_amount(asset: Asset, base_units: u64) -> String {
    amount_with_unit(asset, base_units)
}

/// Every held amount as one sentence clause: `1.5 $DIG, 2 XCH and 1500 base units of a1b2c3…f80912`.
///
/// $DIG leads, because it is the network's own token and the reason most people have this wallet;
/// the rest follow in the order they were read. Each amount carries its own unit, so a reader never
/// has to work out which figure belongs to which token — and a token whose precision is unknown
/// says so in place rather than borrowing a neighbour's decimal point.
fn holdings_phrase(balances: &Balances) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(balances.holdings.len());
    parts.extend(dig_first(balances).map(|held| format_amount(held.asset, held.base_units)));
    match parts.split_last() {
        None => "nothing".to_string(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// The same holdings at menu width: `·`-separated, $DIG first, no conjunction.
///
/// A native menu row cannot wrap, so this trades the sentence's readability for width. It is still
/// the same figures from the same renderer — a menu that formatted its own amounts is exactly how a
/// second divisor gets into the codebase.
fn menu_holdings(balances: &Balances) -> String {
    dig_first(balances)
        .map(|held| format_amount(held.asset, held.base_units))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The holdings with $DIG moved to the front, everything else keeping its read order.
///
/// One ordering used by both renderers, so the window and the menu can never disagree about which
/// token a person sees first.
fn dig_first(balances: &Balances) -> impl Iterator<Item = &Holding> {
    let (dig, others): (Vec<_>, Vec<_>) = balances
        .holdings
        .iter()
        .partition(|held| held.asset.is_dig());
    dig.into_iter().chain(others)
}

/// The address line for the Wallet window.
pub fn address_line(address: &AddressReading) -> String {
    match address {
        AddressReading::Known(address) => format!("Your receive address:\n{address}"),
        AddressReading::Unavailable(AddressUnavailable::NoAccount) => {
            "You do not have a DIG Account on this computer yet, so there is no address to receive at. \
             Set one up from the tray menu and your address appears here."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::HostUnsupported) => {
            "This computer cannot hold a DIG Account, so there is no address to receive at. Status \
             explains what this system is missing."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::NoPasswordYet) => {
            "Your address is not shown because your account has no password yet. Choose one from the \
             tray menu and your address appears here — DIG will not derive an address from keys that \
             nothing is protecting."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::Locked) => {
            "Your address is not shown because your account is locked. Unlock it and it appears here — \
             an address is public, but DIG will not guess one while the keys it comes from are sealed."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::Unopenable) => {
            "Your address cannot be shown because this account will not open, so the key it is derived \
             from is out of reach. Unlocking is not the way back — the tray menu's \
             \"This account cannot be opened\" row explains what to do."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::DerivationFailed) => {
            "Your address could not be derived on this computer. This is a fault, not a normal state — \
             please report it from the tray's log folder rather than using any address shown elsewhere."
                .to_string()
        }
        AddressReading::Unavailable(AddressUnavailable::WalletBehindActiveProfile) => {
            "Your address is not shown because your wallet is still on the profile you switched \
             away from, and DIG will not show you an address belonging to a different profile. \
             Close DIG and open it again to move your wallet to the profile you are now using."
                .to_string()
        }
    }
}

/// The balance line for the Wallet window.
///
/// The whole point of this function: an [`BalanceReading::Unknown`] renders WORDS, never a numeral, so
/// no unknown can be read as "you hold nothing".
pub fn balance_line(balance: &BalanceReading, peers_peak: Option<u32>) -> String {
    match balance {
        BalanceReading::Pending => "Balance: checking with your node…".to_string(),
        BalanceReading::Known { balances, as_of } => format!(
            "Balance: {}. {}",
            holdings_phrase(balances),
            as_of_sentence(*as_of, peers_peak)
        ),
        BalanceReading::Unknown(why) => format!("Balance: not known — {}", unknown_reason(why)),
    }
}

/// The sentence stating what a shown figure is true AS OF.
///
/// Every branch says a fact and implies no fault: being behind the tip is how a light client works,
/// and an oracle answer is somebody else's reading rather than a failure of this one. The height is
/// stated because it is the whole difference between a stale figure and a true statement about a
/// moment (dig_ecosystem#2824).
///
/// The oracle branch names the third party deliberately, and carries no height: an oracle answer has
/// none by contract, so writing one would invent it.
///
/// # `peers_peak` is what separates *current* from *behind*
///
/// A height alone cannot say whether a figure is current — only a comparison can, and the only chain
/// tip this app knows is the peak this node's own Chia peers announced
/// ([`NetworkStanding::chia_peer_peak_height`](crate::network::NetworkStanding::chia_peer_peak_height)).
/// The BALANCE's own height is compared against it, rather than reusing the header's
/// [`SyncProgress`](crate::network::SyncProgress): that reading is about the replica at the moment
/// the sync was polled, and this claim is about the figure on screen. A pane that borrowed the
/// header's verdict could call a balance current on the strength of a different, later reading.
///
/// `None` — no peer has announced a peak — can never produce the current claim. There is nothing to
/// have reached, so the fail-closed reading is the as-of one, which is true either way.
pub fn as_of_sentence(as_of: BalanceAsOf, peers_peak: Option<u32>) -> String {
    match as_of {
        // LEVEL with the peak this node's own peers announced: the figure is current, and saying so
        // is the point. A replica genuinely does reach its peers' peak and track it — measured on an
        // enrolled 0.116.0 node following peaks 9,141,738 → 9,141,739 → 9,141,741 — so this is an
        // ordinary state, not a theoretical one.
        //
        // Wording it as a caveat here would be the same defect as putting the provenance suffix on
        // every menu row (see `menu_provenance`): a permanent apology attached to a figure that is
        // actually current teaches a person to stop reading it, exactly when the day it means
        // something is the day it changes. The height stays, because it is what makes the claim
        // checkable rather than a reassurance.
        BalanceAsOf::Replica { height, caught_up } if is_level(height, caught_up, peers_peak) => {
            format!(
                "Up to date with the chain, at block {}.",
                grouped_height(height)
            )
        }
        // BEHIND, and the sentence says both halves. The as-of alone was true but incomplete: a
        // reader can take "the last your node has read" for a node that has finished and simply
        // reads that block, which is the one reading of it that would stop them waiting
        // (dig_ecosystem#2869). The figure is not called stale — it is correct as of that height —
        // and the node is named as still working.
        BalanceAsOf::Replica { height, .. } => {
            format!(
                "Still syncing — correct as of block {}, the last your node has read.",
                grouped_height(height)
            )
        }
        // Current, and NOT the user's own node: the oracle answered because the replica has not
        // caught up to this address yet. So the syncing signal belongs here too, on a figure that
        // must not itself be described as out of date.
        BalanceAsOf::Oracle => {
            "Still syncing — read from a public chain service, not from your own node.".to_string()
        }
        BalanceAsOf::Undisclosed => "Your node did not say where this came from.".to_string(),
    }
}

/// The same reading as [`balance_line`], rendered for a MENU ROW (dig_ecosystem#1841).
///
/// A row in a native menu cannot wrap or scroll, so this is the short form: one line, both assets, and
/// for an unknown a clause naming the missing thing — with the full explanation one click away in the
/// window [`window_body`] renders.
///
/// # Two things it deliberately does not do
///
/// It never renders a numeral for an [`BalanceReading::Unknown`], for the reason this whole module
/// exists: a `0` glanced at in a menu is how a person concludes their money is gone.
///
/// And it never interpolates the upstream error of a [`BalanceUnknown::ReadFailed`]. That string comes
/// from outside this crate and has neither a length bound nor a guarantee about its contents, so on a
/// menu row it could be arbitrarily wide — and could itself carry digits, defeating the rule above. The
/// row says the read failed; the window says what the source said.
pub fn menu_balance_label(balance: &BalanceReading, peers_peak: Option<u32>) -> String {
    match balance {
        BalanceReading::Pending => "Balance: checking…".to_string(),
        BalanceReading::Known { balances, as_of } => format!(
            "Balance: {}{}",
            menu_holdings(balances),
            menu_provenance(*as_of, peers_peak)
        ),
        BalanceReading::Unknown(why) => format!("Balance not known — {}…", menu_reason(why)),
    }
}

/// The parenthetical a menu row carries after the figures, or `""` when a replica is level with
/// the chain.
///
/// # Why the row cannot stay silent about provenance
///
/// The window explains the provenance in a sentence; this row had no room for one and therefore
/// said nothing — which is not neutral. A bare `Balance: … XCH` on a menu is read as *your wallet's
/// balance*, so an oracle figure shown that way is the app presenting a third party's number as its
/// own view of the user's money. That is the money-provenance claim the whole `as_of` split exists
/// to keep honest, and it was being dropped at exactly the surface a person glances at most.
///
/// It is not hypothetical: until the replica completes initial sync (dig_ecosystem#2871) EVERY live read
/// returns the fallback tier, so on a real install today this row is the oracle case, always.
///
/// [`Replica`](BalanceAsOf::Replica) takes no suffix only when it is LEVEL with the chain per
/// [`is_level`]: then it IS the wallet's own current reading, so the default reading of the row is
/// already true. A replica still behind renders ` (syncing)` instead. Its as-of height belongs in
/// the window, where there is room to state a height without crowding the figures.
///
/// Digit-free, like [`menu_reason`], so the no-numeral rule stays mechanical — the only numerals a
/// row may carry are the figures themselves.
///
/// # Why these are so short
///
/// The window's wording is a sentence; these are the same facts at menu width. The row's budget is
/// what is left of 80 characters after two figures, and two `u64` amounts spend 61 of them on their
/// own — so the first draft (`(public chain service)`) made the widest row 86 characters wide.
/// `every_menu_label_stays_short_including_a_hostile_upstream_error` now measures the widest figures
/// against EVERY provenance, so a longer rewording fails loudly rather than silently overflowing an
/// OS menu.
///
/// `(older node)` is the contract's own reading of an absent `source`, not an inference from one:
/// `dig-node-control-interface`'s `WalletBalanceResult` states that absent "means the answering node
/// predates tier disclosure". So it names the fact AND the remedy, in the shortest form that does
/// both.
/// # Why the oracle clause is written so tightly
///
/// A row cannot wrap, and the widest a `u64` pair of figures can render is 63 characters against a
/// bound of 80 — so every suffix has 17 characters to say what it needs, and the oracle case has
/// the most to say: the node is still syncing AND this figure is not the node's own. `·` rather
/// than a spaced separator is what fits both facts; the window's sentence is where either is
/// explained (dig_ecosystem#2869).
fn menu_provenance(as_of: BalanceAsOf, peers_peak: Option<u32>) -> &'static str {
    match as_of {
        BalanceAsOf::Replica { height, caught_up } if is_level(height, caught_up, peers_peak) => "",
        BalanceAsOf::Replica { .. } => " (syncing)",
        BalanceAsOf::Oracle => " (syncing·public)",
        BalanceAsOf::Undisclosed => " (older node)",
    }
}

/// A block height with thousands separators — seven bare digits are a number nobody reads.
///
/// Crate-visible so every surface that prints a height prints it the same way: the balance card's
/// as-of line and the activity list's confirmed rows sit inches apart, and one of them showing
/// `5400112` beside the other's `7,000,000` reads as two different kinds of number.
pub fn grouped_height(height: u32) -> String {
    let digits = height.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Whether a replica reading is LEVEL with the chain — the node's own claim, corroborated by the
/// peak its peers announced.
///
/// Two sources because the two read paths have different evidence. The node's `synced` flag travels
/// with every reading; the peers' peak exists only on a tray snapshot. Either alone is incomplete:
/// the comparison alone marks a caught-up node as syncing wherever no peak is known, and a node
/// that has advanced past the peak recorded in the snapshot is level even before it says so.
///
/// Where NEITHER is available the answer is *not level*, which is the direction this feature must
/// fail in: silence about the chain tip is not evidence of being at it (dig_ecosystem#2869).
fn is_level(height: u32, caught_up: bool, peers_peak: Option<u32>) -> bool {
    caught_up || peers_peak.is_some_and(|peak| height >= peak)
}

/// Whether this reading needs a SYNCING indicator beside the figure.
///
/// One predicate for every surface that shows a balance, because the tray row and the Wallet pane
/// disagreeing about whether the same figure is current is the drift this returns a `bool` to
/// prevent. `true` means the figure is real and shown, and something must say so beside it.
///
/// # Beside, not beneath (dig_ecosystem#2869)
///
/// The user asked for *"an indicator that its still syncing next to the balance"*, and the
/// distinction is not cosmetic: an as-of sentence a scroll away from the number qualifies the
/// number only for somebody who reads on. The indicator travels WITH the figure so the qualified
/// claim is the one a glance takes away.
///
/// An [`Oracle`](BalanceAsOf::Oracle) reading is included even though the figure itself is current:
/// the oracle answered *because* the user's own replica has not got there yet, so the node is
/// demonstrably still syncing. What that indicator must not do is call the FIGURE stale — see
/// `menu_provenance` and [`as_of_sentence`], which both name the public source.
pub fn is_syncing(balance: &BalanceReading, peers_peak: Option<u32>) -> bool {
    match balance {
        BalanceReading::Known { as_of, .. } => match as_of {
            BalanceAsOf::Replica { height, caught_up } => {
                !is_level(*height, *caught_up, peers_peak)
            }
            BalanceAsOf::Oracle => true,
            // An older node disclosed nothing, so "still syncing" is a claim about it that nothing
            // measured. Its own row already says `older node`.
            BalanceAsOf::Undisclosed => false,
        },
        BalanceReading::Pending | BalanceReading::Unknown(_) => false,
    }
}

/// The menu-length clause completing "Balance not known — …", naming the missing thing or the remedy.
///
/// Deliberately separate wording from [`unknown_reason`] rather than a truncation of it: the window's
/// sentences explain, and a row this size can only point. Each is digit-free, which is what keeps the
/// no-numeral rule above mechanical rather than a matter of care.
fn menu_reason(why: &BalanceUnknown) -> &'static str {
    match why {
        BalanceUnknown::NoAddress(AddressUnavailable::NoAccount) => {
            "no account on this computer yet"
        }
        BalanceUnknown::NoAddress(AddressUnavailable::HostUnsupported) => {
            "this computer cannot hold an account"
        }
        BalanceUnknown::NoAddress(AddressUnavailable::NoPasswordYet) => {
            "set a password for your account first"
        }
        BalanceUnknown::NoAddress(AddressUnavailable::Locked) => "unlock your account first",
        BalanceUnknown::NoAddress(AddressUnavailable::Unopenable) => {
            "your account cannot be opened"
        }
        BalanceUnknown::NoAddress(AddressUnavailable::DerivationFailed) => {
            "your address could not be derived"
        }
        BalanceUnknown::NoAddress(AddressUnavailable::WalletBehindActiveProfile) => {
            "your wallet is still on the profile you switched away from"
        }
        BalanceUnknown::NoNode => "DIG could not reach a node",
        BalanceUnknown::NodeTimedOut => "your node did not answer in time",
        BalanceUnknown::NodeCannotRead => "this node cannot read balances yet",
        BalanceUnknown::NoChainSource => "your node has no chain connection yet",
        BalanceUnknown::NotSynced => "your node is still syncing",
        BalanceUnknown::ReplicaHasNoData => "your node has not synced your wallet yet",
        BalanceUnknown::AddressesNotFollowed => "your node is not following your addresses yet",
        BalanceUnknown::AwaitingNodeRestart => {
            "your node follows your addresses from its next start"
        }
        BalanceUnknown::ReadFailed(_) => "the read failed",
    }
}

/// The clause that completes "not known — …". Each one names the missing thing and, where there is
/// one, the way to fix it.
///
/// `pub` because the Wallet content pane shows the same reason on its own, under a "Balance" label
/// that supplies the words this clause completes. One set of sentences for both surfaces: two would
/// drift, and the reason a balance is missing is exactly the copy that must not.
pub fn unknown_reason(why: &BalanceUnknown) -> String {
    match why {
        BalanceUnknown::NoAddress(AddressUnavailable::NoAccount) => {
            "there is no account on this computer to hold one.".to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::HostUnsupported) => {
            "this computer cannot hold a DIG Account, so there is no address to read a balance for."
                .to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::NoPasswordYet) => {
            "your account has no password yet, so DIG cannot tell which address to read. Choose a \
             password to see your balance."
                .to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::Locked) => {
            "your account is locked, so DIG cannot tell which address to read. Unlock it to see your \
             balance."
                .to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::Unopenable) => {
            "this account will not open, so the address its balance would be read for is out of reach."
                .to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::DerivationFailed) => {
            "your address could not be derived, so there is nothing to read a balance for.".to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::WalletBehindActiveProfile) => {
            "your wallet is still on the profile you switched away from, and DIG will not read a \
             balance for an address belonging to a different profile. Close DIG and open it again to \
             move your wallet across."
                .to_string()
        }
        BalanceUnknown::NoNode => {
            "DIG could not reach a node on this computer, and reading a balance needs one. Status \
             shows where DIG looked; if your node is running somewhere else, name it there."
                .to_string()
        }
        BalanceUnknown::NodeTimedOut => {
            "your node did not answer in time. Nothing is wrong with your account, and the figure \
             appears on its own once a read finishes — a balance is a chain lookup, and a busy node \
             can take longer than DIG waits."
                .to_string()
        }
        BalanceUnknown::NodeCannotRead => {
            "your DIG node is running but this version of it does not read wallet balances yet. \
             Nothing is wrong with your account — the figure simply is not available."
                .to_string()
        }
        BalanceUnknown::NoChainSource => {
            "your DIG node is running and can read balances, but it has no live connection to the \
             Chia blockchain to read one from. Nothing is wrong with your account or your address — \
             money sent to it still arrives, and the figure appears once your node has a chain \
             connection."
                .to_string()
        }
        BalanceUnknown::NotSynced => {
            "your node is still catching up with the blockchain. A figure now would be out of date, so \
             DIG waits rather than showing one."
                .to_string()
        }
        BalanceUnknown::ReplicaHasNoData => {
            "your node has not synced your wallet yet, so there is no balance for it to report. The \
             figure appears once the node has synced the address."
                .to_string()
        }
        BalanceUnknown::AddressesNotFollowed => {
            "your node is not following your addresses yet, so it holds no record of your coins to \
             read. Nothing is wrong with your account, and money sent to your address still \
             arrives. DIG registers your addresses with your node while your account is \
             unlocked."
                .to_string()
        }
        BalanceUnknown::AwaitingNodeRestart => {
            "your addresses are registered with your node, and it starts following them the next \
             time it restarts. Nothing is wrong and there is nothing to do — the figure \
             appears once it has read them."
                .to_string()
        }
        BalanceUnknown::ReadFailed(detail) => format!("the read failed ({detail})."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray_menu::AddressFault;
    use crate::wallet::engine::test_support::FakeWalletEngine;
    use crate::wallet::engine::{BroadcastRequest, BroadcastResponse, CoinsRequest, CoinsResponse};
    use crate::wallet::state::CoinRecord;
    use crate::wallet::WalletError;

    const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    fn known() -> AddressReading {
        AddressReading::Known(ADDRESS.to_string())
    }

    fn coin(asset: Asset, amount: u64) -> CoinRecord {
        CoinRecord {
            coin_id: format!("{amount:064x}"),
            asset,
            amount,
        }
    }

    /// A source that REFUSES every chain read with a chosen error — the "reachable but not
    /// answering" case, parameterised because WHICH refusal a node gives is now what decides the
    /// reason the user is shown (dig_ecosystem#2206).
    struct RefusingEngine(fn() -> WalletError);

    impl WalletEngine for RefusingEngine {
        fn broadcast(&self, _: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
            unreachable!("the overview never broadcasts")
        }
        fn coins(&self, _: CoinsRequest) -> Result<CoinsResponse, WalletError> {
            Err((self.0)())
        }
        fn balance(
            &self,
            _: BalanceRequest,
        ) -> Result<super::super::engine::BalanceResponse, WalletError> {
            Err((self.0)())
        }
    }

    /// The engine every "the read reached a source and failed" fixture uses.
    fn failing_engine() -> RefusingEngine {
        RefusingEngine(|| WalletError::Engine("upstream refused".to_string()))
    }

    /// **The headline property.** A wallet holding genuinely nothing and a wallet whose balance could
    /// not be read must not render the same way — and only the first may show a number.
    ///
    /// Both fixtures carry the SAME (valid, funded-capable) address, so the only difference is whether
    /// a source answered. An implementation that defaulted an unreadable balance to zero would produce
    /// identical text here and fail.
    #[test]
    fn an_empty_wallet_and_an_unreadable_one_never_read_the_same() {
        let empty =
            WalletOverview::read(known(), &ChainSource::Ready(&FakeWalletEngine::default()));
        let unreadable = WalletOverview::read(known(), &ChainSource::Absent);

        assert_eq!(
            empty.balance,
            BalanceReading::Known {
                balances: Balances::of_xch_and_dig(0, 0),
                as_of: BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true
                }
            },
            "a source that answered zero IS a zero balance"
        );
        let empty_line = balance_line(&empty.balance, None);
        let unreadable_line = balance_line(&unreadable.balance, None);
        assert_ne!(empty_line, unreadable_line);
        assert!(empty_line.contains('0'), "{empty_line}");
        assert!(
            !unreadable_line.contains('0'),
            "an unknown balance must never render a numeral: {unreadable_line}"
        );
        assert!(unreadable_line.contains("could not reach a node"));
    }

    /// A real balance is reported per asset, in whole coins, from the source's base units.
    #[test]
    fn a_real_balance_is_read_per_asset_and_shown_in_whole_coins() {
        let engine = FakeWalletEngine {
            coins: vec![
                coin(Asset::DIG, 2_500),
                coin(Asset::Xch, 1_000_000_000_000),
                coin(Asset::Xch, 250_000_000_000),
            ],
            ..FakeWalletEngine::default()
        };
        let overview = WalletOverview::read(known(), &ChainSource::Ready(&engine));

        assert_eq!(
            overview.balance,
            BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: crate::wallet::engine::test_support::FAKE_AS_OF
            }
        );
        assert!(
            balance_line(&overview.balance, None).starts_with("Balance: 2.5 $DIG and 1.25 XCH."),
            "{}",
            balance_line(&overview.balance, None)
        );
    }

    /// Each way of not knowing says something DIFFERENT, because the remedies differ: start a node,
    /// wait for a sync, unlock, or set up an account.
    #[test]
    fn every_unknown_names_its_own_missing_thing() {
        let cases = [
            (
                WalletOverview::read(known(), &ChainSource::Absent).balance,
                "could not reach a node",
            ),
            (
                WalletOverview::read(
                    known(),
                    &ChainSource::Ready(&RefusingEngine(|| WalletError::EngineUnsupported)),
                )
                .balance,
                "does not read wallet balances yet",
            ),
            (
                WalletOverview::read(
                    known(),
                    &ChainSource::Ready(&RefusingEngine(|| WalletError::EngineNotSynced)),
                )
                .balance,
                "catching up with the blockchain",
            ),
            (
                WalletOverview::read(
                    AddressReading::Unavailable(AddressUnavailable::Locked),
                    &ChainSource::Ready(&FakeWalletEngine::default()),
                )
                .balance,
                "your account is locked",
            ),
            (
                WalletOverview::read(
                    AddressReading::Unavailable(AddressUnavailable::NoAccount),
                    &ChainSource::Absent,
                )
                .balance,
                "no account on this computer",
            ),
            (
                WalletOverview::read(known(), &ChainSource::Ready(&failing_engine())).balance,
                "upstream refused",
            ),
        ];

        let mut seen = std::collections::HashSet::new();
        for (reading, expected) in cases {
            let line = balance_line(&reading, None);
            assert!(line.contains(expected), "{line}");
            assert!(
                matches!(reading, BalanceReading::Unknown(_)),
                "none of these read a balance"
            );
            assert!(seen.insert(line.clone()), "reasons must differ: {line}");
        }
    }

    /// Every `BalanceUnknown` there is, so the menu-label tests below cover the whole enum rather than
    /// the two states production happens to produce today.
    fn every_unknown() -> Vec<BalanceUnknown> {
        vec![
            BalanceUnknown::NoAddress(AddressUnavailable::NoAccount),
            BalanceUnknown::NoAddress(AddressUnavailable::HostUnsupported),
            BalanceUnknown::NoAddress(AddressUnavailable::NoPasswordYet),
            BalanceUnknown::NoAddress(AddressUnavailable::Locked),
            BalanceUnknown::NoAddress(AddressUnavailable::Unopenable),
            BalanceUnknown::NoAddress(AddressUnavailable::DerivationFailed),
            BalanceUnknown::NoNode,
            BalanceUnknown::NodeTimedOut,
            BalanceUnknown::NodeCannotRead,
            BalanceUnknown::NoChainSource,
            BalanceUnknown::NotSynced,
            BalanceUnknown::ReplicaHasNoData,
            // A detail full of digits — the case that would smuggle a numeral into a menu label if the
            // renderer passed the upstream string through.
            BalanceUnknown::ReadFailed("HTTP 503 after 30s".to_string()),
        ]
    }

    /// **The headline property, at the MENU layer.** A menu row is where a glanced-at numeral does the
    /// most damage, so the no-numeral-for-an-unknown rule has to hold here too — not only in the
    /// window, where [`balance_line`] proves it.
    ///
    /// Asserted over EVERY unknown, including a `ReadFailed` whose upstream detail is full of digits:
    /// an implementation that reused `balance_line`, or that interpolated the detail, fails on that one.
    #[test]
    fn an_unknown_balance_never_renders_a_numeral_on_a_menu_row() {
        for why in every_unknown() {
            let label = menu_balance_label(&BalanceReading::Unknown(why.clone()), None);
            assert!(
                !label.chars().any(|c| c.is_ascii_digit()),
                "{why:?}: an unknown balance must never show a figure: {label}"
            );
            assert!(
                label.contains("not known"),
                "{why:?}: the row must say the balance is not known: {label}"
            );
        }
    }

    /// Each unknown names its OWN missing thing on the menu row, and no two read alike — the same
    /// property [`balance_line`] holds, at menu length.
    ///
    /// Without the distinctness assertion a renderer could collapse all seven to
    /// "Balance not known…" and still pass the no-numeral test above.
    #[test]
    fn each_unknown_names_its_own_reason_on_the_menu_row() {
        let expected = [
            "no account on this computer yet",
            "this computer cannot hold an account",
            "set a password for your account first",
            "unlock your account first",
            "your account cannot be opened",
            "your address could not be derived",
            "DIG could not reach a node",
            "your node did not answer in time",
            "this node cannot read balances yet",
            "your node has no chain connection yet",
            "your node is still syncing",
            "has not synced your wallet yet",
            "the read failed",
        ];
        let mut seen = std::collections::HashSet::new();
        for (why, clause) in every_unknown().into_iter().zip(expected) {
            let reason = unknown_reason(&why);
            assert!(
                !reason.contains("  "),
                "{why:?}: rendered reason must not contain double spaces: {reason}"
            );
            let label = menu_balance_label(&BalanceReading::Unknown(why.clone()), None);
            assert!(label.contains(clause), "{why:?}: {label}");
            assert!(seen.insert(label.clone()), "reasons must differ: {label}");
        }
    }

    /// A KNOWN balance shows both assets, in whole coins, on one row — including a genuine zero, which
    /// is the one case where a numeral is the truth.
    #[test]
    fn a_known_balance_shows_both_assets_on_the_menu_row() {
        let held = menu_balance_label(
            &BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
            None,
        );
        assert!(held.contains("2.5 $DIG"), "{held}");
        assert!(held.contains("1.25 XCH"), "{held}");

        let empty = menu_balance_label(
            &BalanceReading::Known {
                balances: Balances::of_xch_and_dig(0, 0),
                as_of: BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
            None,
        );
        assert!(
            empty.contains("0 $DIG") && empty.contains("0 XCH"),
            "{empty}"
        );
        assert!(
            !empty.contains("not known"),
            "a source that answered zero KNOWS the balance: {empty}"
        );
    }

    /// **A balance level with the chain says so, instead of apologising** (dig_ecosystem#2824).
    ///
    /// A replica genuinely reaches its peers' peak and tracks it — measured on an enrolled 0.116.0
    /// node following 9,141,738 → 9,141,739 → 9,141,741 — so this is the ordinary state, not a
    /// theoretical one. Wording it as a caveat would be the same defect as putting the provenance
    /// suffix on every menu row: a permanent apology on a figure that is actually current teaches a
    /// person to stop reading it, and the day it means something is the day it changes.
    ///
    /// Every fixture here sets `caught_up: false` deliberately. The node's own claim is the OTHER
    /// route to "level" (dig_ecosystem#2869), and it short-circuits the comparison — so a fixture
    /// that set it would pass whatever the comparison did, and this test would stop being about
    /// the peak at all.
    #[test]
    fn a_balance_level_with_the_chain_says_so_rather_than_apologising() {
        const PEAK: u32 = 9_141_741;

        // LEVEL with the peers' peak. A replica genuinely reaches this and tracks it — measured on
        // an enrolled 0.116.0 node following 9,141,738 → 9,141,739 → 9,141,741 — so this is the
        // ordinary state, not a theoretical one.
        let current = as_of_sentence(
            BalanceAsOf::Replica {
                height: PEAK,
                caught_up: false,
            },
            Some(PEAK),
        );
        assert!(
            current.contains("Up to date"),
            "a figure level with the chain must not be worded as a caveat: {current}"
        );
        assert!(
            current.contains("9,141,741"),
            "the height stays, because it is what makes the claim checkable: {current}"
        );

        // A block PAST the announced peak is still up to date: the replica copied another block
        // between the sync poll and the balance read.
        assert!(as_of_sentence(
            BalanceAsOf::Replica {
                height: PEAK + 1,
                caught_up: false
            },
            Some(PEAK)
        )
        .contains("Up to date"),);

        // THE CONTROL, and the reason this is a distinction rather than a decoration: a replica that
        // is genuinely behind must NOT claim to be current. Without this, a sentence that always
        // said "Up to date" would satisfy every assertion above — which is the money-currency
        // version of the mistake the provenance suffix test guards against.
        let behind = as_of_sentence(
            BalanceAsOf::Replica {
                height: PEAK - 1_709,
                caught_up: false,
            },
            Some(PEAK),
        );
        assert!(
            !behind.contains("Up to date"),
            "a trailing replica must not be presented as current: {behind}"
        );
        assert!(
            behind.contains("as of block") && behind.contains("9,140,032"),
            "a trailing figure states the moment it IS true of: {behind}"
        );

        // FAIL CLOSED: no peer has announced a peak, so there is nothing to have reached. The as-of
        // wording is true either way; the current claim is not checkable and is not made. A `0`
        // default for the peak would make EVERY figure trivially up to date.
        let unknowable = as_of_sentence(
            BalanceAsOf::Replica {
                height: PEAK,
                caught_up: false,
            },
            None,
        );
        assert!(
            !unknowable.contains("Up to date"),
            "an unobservable chain tip licenses no claim that anything reached it: {unknowable}"
        );
        assert!(unknowable.contains("as of block"), "{unknowable}");
    }

    /// **The peers' peak reaches the balance sentence from the SAME snapshot as the balance.**
    ///
    /// `of_tray` takes both off one `TrayView`. A pane that read the tip separately could call a
    /// figure up to date on the strength of a reading taken after the figure — which is the money
    /// claim this whole module is careful about, made by accident through a plumbing choice.
    #[test]
    fn the_chain_tip_used_to_judge_a_balance_comes_from_the_balances_own_snapshot() {
        let view = crate::tray_menu::TrayView {
            receive_address: Some("xch1example".to_string()),
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            balance: BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: BalanceAsOf::Replica {
                    height: 9_141_741,
                    caught_up: true,
                },
            },
            network: crate::network::NetworkStanding {
                chia_peer_peak_height: Some(9_141_741),
                ..crate::network::NetworkStanding::default()
            },
            ..crate::tray_menu::TrayView::default()
        };

        let overview = WalletOverview::of_tray(&view);
        assert_eq!(
            overview.peers_peak,
            Some(9_141_741),
            "the tip must be carried off the same snapshot as the balance"
        );
        let body = window_body(&overview);
        assert!(
            body.contains("Up to date"),
            "a caught-up balance reads as current on the window too: {body}"
        );
    }

    /// **A figure that is NOT the wallet's own says so on the menu row too** (dig_ecosystem#2824).
    ///
    /// The window explains provenance in a sentence and this row had no room for one, so it said
    /// nothing — which is not neutral. A bare `Balance: … XCH` on a menu is read as *your wallet's
    /// balance*, so an oracle figure rendered that way is a third party's number presented as the
    /// app's own view of the user's money.
    ///
    /// Not hypothetical: until node-side enrolment lands (#2823) every live read returns the
    /// fallback tier, so on a real install today this row is the oracle case, always.
    ///
    /// The `Replica` control is the half that makes this a distinction rather than a decoration. A
    /// suffix on every reading would satisfy the two assertions below and be wrong — the wallet's
    /// own node needs no disclaimer, and one there would teach a person to ignore the parenthetical
    /// exactly when it starts carrying information.
    #[test]
    fn a_figure_that_is_not_the_wallets_own_is_labelled_on_the_menu_row() {
        let row = |as_of| {
            menu_balance_label(
                &BalanceReading::Known {
                    balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                    as_of,
                },
                None,
            )
        };

        let oracle = row(BalanceAsOf::Oracle);
        assert!(
            oracle.contains("public"),
            "an oracle figure must not read as the wallet's own: {oracle}"
        );
        let undisclosed = row(BalanceAsOf::Undisclosed);
        assert!(
            undisclosed.contains("older node"),
            "an undisclosed tier must not read as the wallet's own: {undisclosed}"
        );
        assert_ne!(
            oracle, undisclosed,
            "a third party's number and an unstated source are different claims"
        );

        // THE CONTROL: the wallet's own node carries no disclaimer, because the row's default
        // reading is already true of it.
        let replica = row(BalanceAsOf::Replica {
            height: 7_000_000,
            caught_up: true,
        });
        assert_eq!(
            replica, "Balance: 2.5 $DIG · 1.25 XCH",
            "a replica reading IS the wallet's own and must not be qualified: {replica}"
        );

        // The figures survive the suffix — a label that dropped them would satisfy every
        // `contains` above.
        for labelled in [&oracle, &undisclosed] {
            assert!(
                labelled.contains("2.5 $DIG") && labelled.contains("1.25 XCH"),
                "the provenance must be added to the figures, not instead of them: {labelled}"
            );
        }
    }

    /// A menu row cannot wrap or scroll, so EVERY label this function can emit is bounded — not just
    /// the ones someone remembered to measure.
    ///
    /// The bound is 80 characters: comfortably inside what a native menu renders on the narrowest
    /// platform, and loose enough that a clause can be reworded without a spurious failure. The
    /// interesting fixture is the hostile upstream error — a renderer that interpolated a
    /// `ReadFailed` detail would emit a label thousands of characters wide, carrying whatever the
    /// source sent, straight into an OS menu.
    #[test]
    fn every_menu_label_stays_short_including_a_hostile_upstream_error() {
        let mut labels: Vec<String> = every_unknown()
            .into_iter()
            .map(|why| menu_balance_label(&BalanceReading::Unknown(why), None))
            .collect();
        labels.push(menu_balance_label(
            &BalanceReading::Unknown(BalanceUnknown::ReadFailed("x".repeat(4000))),
            None,
        ));
        // The widest KNOWN reading a u64 pair can produce, so the bound covers the figures too —
        // and once for EVERY provenance, because the suffix is part of the row's width and the
        // longest one lands on the case that is universal today (dig_ecosystem#2824). Measured with
        // only the unsuffixed `Replica` here, this bound would have been checked against the one
        // reading no real install can currently produce.
        for as_of in [
            BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
            BalanceAsOf::Oracle,
            BalanceAsOf::Undisclosed,
        ] {
            // BOTH sides of the level/behind split, because they render DIFFERENT suffixes and
            // the wider one is the syncing form this feature added. A sweep pinned only at
            // `None` would measure the row that says least.
            for peers_peak in [None, Some(1), Some(u32::MAX)] {
                labels.push(menu_balance_label(
                    &BalanceReading::Known {
                        balances: Balances::of_xch_and_dig(u64::MAX, u64::MAX),
                        as_of,
                    },
                    peers_peak,
                ));
            }
        }

        for label in &labels {
            assert!(
                label.chars().count() <= 80,
                "{} chars is wider than a menu row: {label}",
                label.chars().count()
            );
        }
        assert!(
            !labels.iter().any(|label| label.contains("xxxx")),
            "the upstream detail belongs in the window, not the menu: {labels:?}"
        );
    }

    /// **The three states dig_ecosystem#2325 collapsed into one wrong sentence.**
    ///
    /// A read that overran its budget, a node that is behind the chain, and nothing reachable at all
    /// are three different facts with three different remedies, and the app was stating the third
    /// for all of them. Asserted on the produced REASON as well as the words (dig_ecosystem#2320),
    /// so a future reword cannot quietly re-merge them.
    #[test]
    fn a_timeout_a_sync_and_an_unreachable_node_are_three_distinguishable_states() {
        let reason = |error: fn() -> WalletError| {
            WalletOverview::read(known(), &ChainSource::Ready(&RefusingEngine(error))).balance
        };
        let timed_out = reason(|| WalletError::EngineTimedOut("after 20s".to_string()));
        let syncing = reason(|| WalletError::EngineNotSynced);
        let unreachable = WalletOverview::read(known(), &ChainSource::Absent).balance;

        assert_eq!(
            timed_out,
            BalanceReading::Unknown(BalanceUnknown::NodeTimedOut)
        );
        assert_eq!(syncing, BalanceReading::Unknown(BalanceUnknown::NotSynced));
        assert_eq!(unreachable, BalanceReading::Unknown(BalanceUnknown::NoNode));

        let lines = [&timed_out, &syncing, &unreachable].map(|r| balance_line(r, None));
        let rows = [&timed_out, &syncing, &unreachable].map(|r| menu_balance_label(r, None));
        assert_eq!(
            std::collections::HashSet::from(lines.clone()).len(),
            3,
            "three facts, three sentences: {lines:?}"
        );
        assert_eq!(
            std::collections::HashSet::from(rows.clone()).len(),
            3,
            "three facts, three rows: {rows:?}"
        );
    }

    /// **A read that ran out of time says nothing about whether a node is running** — the defect a
    /// live user hit while the Status tab, on the same screen, showed a healthy node.
    ///
    /// The claim is checked over the whole surface (window body AND menu row), because the row is
    /// what the user saw. The forbidden phrases are the ones that assert node presence either way;
    /// the timeout knows only that OUR call did not finish.
    #[test]
    fn a_timed_out_read_never_claims_the_node_is_missing() {
        let timed_out = BalanceReading::Unknown(BalanceUnknown::NodeTimedOut);
        let surfaces = [
            balance_line(&timed_out, None),
            menu_balance_label(&timed_out, None),
            window_body(&WalletOverview {
                address: known(),
                balance: timed_out.clone(),
                profiles_unreadable: false,
                peers_peak: None,
            }),
        ];
        for text in surfaces {
            for forbidden in [
                "no DIG node is running",
                "no DIG node",
                "is not running",
                "Start the DIG node",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "a call that overran its budget cannot know this: {text}"
                );
            }
            assert!(
                text.contains("did not answer in time") || text.contains("did not answer"),
                "the surface must name what actually happened: {text}"
            );
        }
    }

    /// **A read still in flight is a PENDING state, not a failure.** During the 2.5–6 s a real chain
    /// read takes, the truthful thing to say is "checking" — and, critically, not a numeral and not
    /// a reason that sends the user after a fault they do not have.
    #[test]
    fn a_read_in_flight_reads_as_checking_rather_than_as_a_failure() {
        let pending = BalanceReading::Pending;
        for text in [
            balance_line(&pending, None),
            menu_balance_label(&pending, None),
        ] {
            assert!(text.to_lowercase().contains("checking"), "{text}");
            assert!(
                !text.chars().any(|c| c.is_ascii_digit()),
                "a balance not yet read must never show a figure: {text}"
            );
            assert!(
                !text.contains("no DIG node"),
                "nothing has failed yet: {text}"
            );
        }
        assert_ne!(
            balance_line(&pending, None),
            balance_line(&BalanceReading::Unknown(BalanceUnknown::NoNode), None)
        );
    }

    /// With no address, the ADDRESS's reason wins over the source's — telling someone with no account
    /// to start their node answers a question they did not ask.
    #[test]
    fn a_missing_address_outranks_a_missing_source() {
        let overview = WalletOverview::read(
            AddressReading::Unavailable(AddressUnavailable::NoAccount),
            &ChainSource::Absent,
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NoAddress(AddressUnavailable::NoAccount))
        );
    }

    /// One asset failing makes the WHOLE reading unknown: showing the half that worked would state a
    /// balance the wallet does not have.
    #[test]
    fn a_partial_read_is_not_a_balance() {
        /// Answers XCH and refuses DIG — the asymmetric failure a "sum what we got" implementation
        /// would happily render as a complete balance.
        struct HalfEngine;
        impl WalletEngine for HalfEngine {
            fn broadcast(&self, _: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
                unreachable!()
            }
            fn coins(&self, _: CoinsRequest) -> Result<CoinsResponse, WalletError> {
                unreachable!()
            }
            fn balance(
                &self,
                request: BalanceRequest,
            ) -> Result<super::super::engine::BalanceResponse, WalletError> {
                match request.asset {
                    Asset::Xch => Ok(super::super::engine::BalanceResponse {
                        as_of: crate::wallet::engine::test_support::FAKE_AS_OF,
                        balance: 7_000_000_000_000,
                    }),
                    // Every CAT fails, so the fixture varies exactly one thing — whether the asset
                    // is native — and the assertion cannot be satisfied by an implementation that
                    // happened to skip the second read.
                    Asset::Cat(_) => Err(WalletError::Engine("cat read failed".to_string())),
                }
            }
        }

        let overview = WalletOverview::read(known(), &ChainSource::Ready(&HalfEngine));
        assert!(matches!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::ReadFailed(_))
        ));
        assert!(!balance_line(&overview.balance, None).contains('7'));
    }

    /// The read is made for THIS address, not a hardcoded or empty one — a source keyed on the wrong
    /// address would report someone else's money.
    #[test]
    fn the_balance_is_read_for_the_account_s_own_address() {
        /// Records the address it was asked about.
        struct RecordingEngine(std::cell::RefCell<Vec<String>>);
        impl WalletEngine for RecordingEngine {
            fn broadcast(&self, _: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
                unreachable!()
            }
            fn coins(&self, _: CoinsRequest) -> Result<CoinsResponse, WalletError> {
                unreachable!()
            }
            fn balance(
                &self,
                request: BalanceRequest,
            ) -> Result<super::super::engine::BalanceResponse, WalletError> {
                self.0.borrow_mut().push(request.address);
                Ok(super::super::engine::BalanceResponse {
                    balance: 0,
                    as_of: crate::wallet::engine::test_support::FAKE_AS_OF,
                })
            }
        }

        let engine = RecordingEngine(std::cell::RefCell::new(Vec::new()));
        WalletOverview::read(known(), &ChainSource::Ready(&engine));
        assert_eq!(engine.0.borrow().as_slice(), [ADDRESS, ADDRESS]);
    }

    /// The address line shows the address in full — an address truncated for looks is an address a
    /// person cannot use.
    #[test]
    fn the_address_line_carries_the_whole_address() {
        assert!(address_line(&known()).contains(ADDRESS));
    }

    /// A locked account still gets an explanation rather than a blank — and the explanation is not the
    /// no-account one, because those are different situations with different remedies.
    #[test]
    fn each_missing_address_explains_itself_distinctly() {
        let locked = address_line(&AddressReading::Unavailable(AddressUnavailable::Locked));
        let absent = address_line(&AddressReading::Unavailable(AddressUnavailable::NoAccount));
        let broken = address_line(&AddressReading::Unavailable(
            AddressUnavailable::DerivationFailed,
        ));
        assert!(locked.contains("locked"));
        assert!(absent.contains("do not have a DIG Account"));
        assert!(broken.contains("could not be derived"));
        assert_ne!(locked, absent);
        assert_ne!(locked, broken);
    }

    /// **The Wallet surface renders each asset at ITS OWN scale** (dig_ecosystem#2295).
    ///
    /// One whole coin is `10^decimals` base units, so each expectation is derived from the asset's
    /// declared decimals rather than typed as a magic number — the test this replaces asserted a
    /// single asset-agnostic divisor and was therefore perfectly self-consistent with rendering a
    /// whole $DIG as `0.000000001`.
    /// A CAT dig-app knows nothing about but its id — deliberately not $DIG's, so an implementation
    /// that fell back to $DIG produces a visibly different value.
    const SPACEBUCKS_HEX: &str = "a628c1c2c6fcb74d53746157e438e108eab5c0bb3e5c80ff9b1910b3e4832913";

    /// [`SPACEBUCKS_HEX`] as an [`Asset`].
    fn spacebucks() -> Asset {
        Asset::Cat(
            crate::wallet::state::AssetId::from_hex(SPACEBUCKS_HEX).expect("a 64-hex asset id"),
        )
    }

    /// **A token with an unknown precision is stated in BASE UNITS, with the words.**
    ///
    /// Two actors in one fixture, and that is the point: $DIG renders as a whole-coin `2.5` in the
    /// same sentence where the unknown CAT renders as `4200 base units`. A renderer that showed
    /// everything as base units, or that applied the CAT convention's three decimals to every token,
    /// fails on one half or the other. A single-asset fixture could not tell them apart.
    #[test]
    fn an_unknown_precision_reads_as_base_units_beside_a_token_that_reads_whole_coin() {
        let balances = Balances {
            holdings: vec![
                Holding {
                    asset: Asset::DIG,
                    base_units: 2_500,
                },
                Holding {
                    asset: spacebucks(),
                    base_units: 4_200,
                },
            ],
        };
        let line = balance_line(
            &BalanceReading::Known {
                balances,
                as_of: BalanceAsOf::Replica {
                    height: 6_000_000,
                    caught_up: true,
                },
            },
            None,
        );
        assert!(
            line.contains("2.5 $DIG"),
            "$DIG keeps its own decimals: {line}"
        );
        assert!(
            line.contains("4200 base units of"),
            "an unknown precision states the unit it is true in: {line}"
        );
        assert!(
            !line.contains("4.2"),
            "the CAT convention's three decimals must not be applied to a token nobody stated the \
             precision of: {line}"
        );
    }

    /// **A read that fails for ONE asset makes the WHOLE reading unknown.**
    ///
    /// The fixture varies exactly one actor: XCH answers, every CAT fails. A partial list would show
    /// the XCH figure beside a silently-missing $DIG, which reads as a wallet holding no $DIG.
    ///
    /// This pins the behaviour at the read layer specifically: the failing asset is the SECOND one
    /// asked for, so an implementation that returned early with what it had would produce a `Known`
    /// reading with one holding, and that is what fails here.
    #[test]
    fn one_assets_failure_makes_the_whole_reading_unknown() {
        struct HalfBrokenEngine;
        impl WalletEngine for HalfBrokenEngine {
            fn broadcast(
                &self,
                _: super::super::engine::BroadcastRequest,
            ) -> Result<super::super::engine::BroadcastResponse, WalletError> {
                unreachable!()
            }
            fn coins(
                &self,
                _: super::super::engine::CoinsRequest,
            ) -> Result<super::super::engine::CoinsResponse, WalletError> {
                unreachable!()
            }
            fn balance(
                &self,
                request: BalanceRequest,
            ) -> Result<super::super::engine::BalanceResponse, WalletError> {
                match request.asset {
                    Asset::Xch => Ok(super::super::engine::BalanceResponse {
                        as_of: crate::wallet::engine::test_support::FAKE_AS_OF,
                        balance: 7_000_000_000_000,
                    }),
                    Asset::Cat(_) => Err(WalletError::EngineNotSynced),
                }
            }
        }
        let overview = WalletOverview::read_assets(
            AddressReading::Known(ADDRESS.to_string()),
            &ChainSource::Ready(&HalfBrokenEngine),
            &[Asset::Xch, Asset::DIG],
        );
        assert_eq!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::NotSynced),
            "a half-read must never be displayed as a whole one"
        );
    }

    #[test]
    fn amounts_render_at_each_assets_own_scale() {
        let one_dig = 10u64.pow(crate::amount::decimals(Asset::DIG).expect("$DIG is known"));
        let one_xch = 10u64.pow(crate::amount::decimals(Asset::Xch).expect("XCH is known"));

        assert_eq!(format_amount(Asset::DIG, one_dig), "1 $DIG");
        assert_eq!(format_amount(Asset::Xch, one_xch), "1 XCH");
        assert_eq!(format_amount(Asset::DIG, one_dig * 3 / 2), "1.5 $DIG");
        assert_eq!(format_amount(Asset::Xch, one_xch * 3 / 2), "1.5 XCH");
        assert_eq!(format_amount(Asset::DIG, 0), "0 $DIG");
        assert_eq!(format_amount(Asset::Xch, 0), "0 XCH");
    }

    /// A sub-unit holding is never rounded away to a zero that would read as "nothing".
    #[test]
    fn a_sub_coin_holding_is_never_rendered_as_nothing() {
        assert_ne!(format_amount(Asset::DIG, 1), "0 $DIG");
        assert_ne!(format_amount(Asset::Xch, 1), "0 XCH");
        assert_eq!(format_amount(Asset::DIG, 1), "0.001 $DIG");
        assert_eq!(format_amount(Asset::Xch, 1), "0.000000000001 XCH");
    }

    /// **A real user with a real reading sees the number.** This is the whole of dig_ecosystem#2206
    /// at the surface a person looks at: the window renders the balance the node reported, rather
    /// than a constant claiming no node could ever answer.
    ///
    /// It fails against the previous mapping, which derived the reading from `node_connected` alone
    /// and could only ever produce "not known".
    #[test]
    fn the_window_states_the_balance_the_node_reported() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            node_connected: true,
            balance: BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
            ..Default::default()
        }));
        assert!(body.contains("Balance: 2.5 $DIG and 1.25 XCH."), "{body}");
        assert!(!body.contains("not known"), "{body}");
    }

    /// **The window a user actually reads must not turn an unknown balance into a zero either.**
    ///
    /// Asserted on the rendered BODY rather than the `BalanceReading`, because the mapping from the
    /// tray snapshot to that reading is itself a place the distinction could be lost — and the body
    /// is what a person acts on. Every reason the poller can carry reaches the window as its own
    /// words, and none of them as a numeral.
    #[test]
    fn the_wallet_window_never_states_a_balance_it_could_not_read() {
        let body_for = |balance| {
            window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
                account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
                receive_address: Some(ADDRESS.to_string()),
                node_connected: true,
                balance,
                ..Default::default()
            }))
        };
        let cases = [
            (BalanceUnknown::NoNode, "could not reach a node"),
            (BalanceUnknown::NodeTimedOut, "did not answer in time"),
            (
                BalanceUnknown::NodeCannotRead,
                "does not read wallet balances yet",
            ),
            (BalanceUnknown::NotSynced, "catching up with the blockchain"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (why, expected) in cases {
            let body = body_for(BalanceReading::Unknown(why));
            assert!(body.contains(ADDRESS), "the address is readable regardless");
            assert!(body.contains("Balance: not known"), "{body}");
            assert!(body.contains(expected), "{body}");
            assert!(
                !body.contains("0 $DIG"),
                "an unread balance must never appear as zero: {body}"
            );
            assert!(seen.insert(body), "each reason is a different fact");
        }
    }

    /// **An unavailable address outranks even a balance that WAS read.** A locked account must not
    /// keep showing the figure its last unlocked poll captured — the address is withheld, and the
    /// money it describes goes with it.
    #[test]
    fn a_withheld_address_suppresses_a_reading_already_taken() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Locked),
            receive_address: None,
            node_connected: true,
            balance: BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
            ..Default::default()
        }));
        assert!(body.contains("account is locked"), "{body}");
        // Both figures are named, because a negative assertion only discriminates while the string it
        // looks for is the one the fixture would actually render. A rescaled fixture silently vacated
        // the $DIG half of this test once already (dig_ecosystem#2295).
        assert!(
            !body.contains("2.5 $DIG"),
            "a locked account must not still show its last figure: {body}"
        );
        assert!(
            !body.contains("1.25 XCH"),
            "a locked account must not still show its last figure: {body}"
        );
    }

    /// A locked account and an account that does not exist reach DIFFERENT windows — the remedies are
    /// unlocking and setting one up, and telling either user the other's story is a dead end.
    #[test]
    fn the_window_tells_a_locked_user_and_a_new_user_different_things() {
        let locked = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Locked),
            receive_address: None,
            ..Default::default()
        }));
        let brand_new = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Absent),
            receive_address: None,
            ..Default::default()
        }));

        assert!(locked.contains("account is locked"), "{locked}");
        assert!(
            brand_new.contains("do not have a DIG Account"),
            "{brand_new}"
        );
        assert_ne!(locked, brand_new);
    }

    /// **Every account state reaches a DIFFERENT window, and none is told to unlock unless unlocking
    /// is the way back** (dig_ecosystem#1841).
    ///
    /// Before this, three states fell through to `Locked` and every one of them read "Unlock it and it
    /// appears here": a host that cannot hold an account at all, an account that has no password to
    /// type, and an account whose unlock is exactly what failed. The distinctness assertion is what
    /// makes a future re-collapse fail — a shared arm would produce two identical bodies.
    #[test]
    fn each_account_state_reaches_its_own_window_naming_a_remedy_it_can_perform() {
        use crate::tray_menu::AccountState;

        let body = |account: AccountState| {
            window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
                account: Some(account),
                receive_address: None,
                ..Default::default()
            }))
        };
        let cases = [
            (AccountState::Unsupported, "cannot hold a DIG Account"),
            (AccountState::Absent, "do not have a DIG Account"),
            (AccountState::NeedsPassword, "no password yet"),
            (AccountState::Locked, "account is locked"),
            (AccountState::Unopenable, "will not open"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (account, expected) in cases {
            let text = body(account.clone());
            assert!(text.contains(expected), "{account:?}: {text}");
            assert!(
                seen.insert(text),
                "{account:?}: states must not share a window"
            );
        }

        // The one that would be wrong to say, said only where it is true.
        assert!(
            !body(AccountState::Unopenable).contains("Unlock it and it appears here"),
            "unlocking is what already failed for this account"
        );
        assert!(
            !body(AccountState::NeedsPassword).contains("Unlock it and it appears here"),
            "there is no password to type yet"
        );
    }

    /// **An unlocked account whose wallet is behind the active profile is told THAT, not told to
    /// unlock** (dig_ecosystem#2496).
    ///
    /// The nearest wrong mapping is the `Locked` arm this would otherwise fall through to, which
    /// names a remedy the person has already performed. The second assertion is what makes it more
    /// than a "some words appear" test: the sentence must not send them to unlock, and it must not
    /// call a normal consequence of switching a fault.
    #[test]
    fn an_unlocked_account_whose_wallet_is_behind_is_told_that_rather_than_to_unlock() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: None,
            address_fault: Some(AddressFault::WalletBehindActiveProfile),
            ..Default::default()
        }));

        assert!(
            body.contains("still on the profile you switched away from"),
            "the reason must name the switch: {body}"
        );
        assert!(
            body.contains("open it again"),
            "and it must name the remedy that works: {body}"
        );
        for wrong in [
            "Unlock it to see",
            "unlock your account first",
            "This is a fault",
        ] {
            assert!(
                !body.contains(wrong),
                "a wallet behind the active profile is neither locked nor broken, yet the body says \
                 {wrong:?}: {body}"
            );
        }
    }

    /// **A host that could not read its profile registry says so on the WALLET surface.**
    ///
    /// This is the one address move that produces no fault anywhere: an unreadable registry boots the
    /// app unprofiled, so the wallet and the active profile are both ROOT, they agree, every accessor
    /// answers happily, and a person who was on another profile is shown a different address with
    /// nothing said (dig_ecosystem#2398).
    ///
    /// The control is the SAME view with a readable registry: without it, a caveat printed
    /// unconditionally would satisfy the first assertion while telling every user their address might
    /// be wrong.
    #[test]
    fn an_unreadable_profile_registry_is_disclosed_beside_the_address_it_changed() {
        let view = |profiles| crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: Some("xch1example".to_string()),
            profiles,
            ..Default::default()
        };

        let unreadable = window_body(&WalletOverview::of_tray(&view(
            crate::profiles::ProfilesReading::Unknown(
                crate::profiles::ProfilesUnknown::Unreadable("the file is not JSON".to_string()),
            ),
        )));
        assert!(
            unreadable.contains("could not read your list of profiles"),
            "an address silently derived at the account root must be disclosed: {unreadable}"
        );
        assert!(
            unreadable.contains("NOT that profile's address"),
            "and the disclosure must say what the address is not: {unreadable}"
        );

        let readable = window_body(&WalletOverview::of_tray(&view(
            crate::profiles::ProfilesReading::Known(vec![]),
        )));
        assert!(
            !readable.contains("could not read your list of profiles"),
            "control: a host that CAN read its registry must not be warned about one: {readable}"
        );
        assert!(
            readable.contains("xch1example"),
            "control: the address itself still renders either way: {readable}"
        );
    }

    /// **An unlocked account whose address derivation genuinely fails is told the truth, never
    /// "unlock your account first"** (dig_ecosystem#2059).
    ///
    /// Before this fix, `Unlocked { .. }` + `receive_address: None` fell through to the SAME `Locked`
    /// arm as an ordinary lock — naming a remedy ("unlock it") the user is not in a position to need,
    /// because they are already unlocked. This is the load-bearing assertion: it fails against the old
    /// collapse-to-`Locked` mapping and passes only once the address FAULT is threaded through
    /// to a distinct `DerivationFailed` reading.
    #[test]
    fn an_unlocked_account_with_a_failed_derivation_is_told_the_truth_not_told_to_unlock() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: None,
            address_fault: Some(AddressFault::DerivationFailed),
            ..Default::default()
        }));

        assert!(
            body.contains("could not be derived"),
            "the honest fault text must appear: {body}"
        );
        assert!(
            !body.contains("Unlock it and it appears here"),
            "the account is ALREADY unlocked — this remedy cannot apply: {body}"
        );
    }

    /// **The control: a plain locked account (never unlocked) still gets the ordinary "unlock it"
    /// wording**, proving the arm above did not swallow the everyday case — only a residency observed
    /// unlocked-yet-failing routes to `DerivationFailed`.
    #[test]
    fn a_plain_locked_account_still_says_unlock_it() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Locked),
            receive_address: None,
            address_fault: None,
            ..Default::default()
        }));

        assert!(body.contains("Unlock it and it appears here"), "{body}");
        assert!(!body.contains("could not be derived"), "{body}");
    }

    /// **The race the atomic read closes:** an account observed unlocked this repaint but with NO
    /// derivation-failure signal (the ordinary in-between state — e.g. a lock landed between the tray's
    /// last read and this one) must NOT be alarmed into `DerivationFailed`. Only the atomic
    /// address fault — set from ONE observation, never from `Unlocked` alone — may
    /// route there.
    #[test]
    fn unlocked_with_no_address_and_no_failure_signal_reads_as_an_ordinary_lock() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: None,
            address_fault: None,
            ..Default::default()
        }));

        assert!(
            body.contains("Unlock it and it appears here"),
            "a merely-locked-mid-observation account must read as an ordinary lock, not a fault: {body}"
        );
        assert!(!body.contains("could not be derived"), "{body}");
    }

    /// The Wallet tab's source, read at compile time so the guard below asks what the app SHIPS
    /// rather than what this test module remembers about it.
    const WALLET_PANE_SOURCE: &str = include_str!("../confirm/gui/window/pane/wallet.rs");

    /// **This window never denies a Send the app ships (dig_ecosystem#2988).**
    ///
    /// # Why the pane's source is read instead of asserted about
    ///
    /// The nearest wrong fix to the shipped defect is deleting the false sentence and asserting the
    /// deletion — which stays green if Send is later withdrawn and the window then says nothing
    /// about a verb that no longer exists, and equally green if a future edit reintroduces a denial
    /// in different words. So the test is a COUPLING: it establishes from the pane's own source that
    /// a `Send` verb ships, and only then requires this window to be free of denial. Withdraw Send
    /// and the control fails first, naming the real reason rather than the copy.
    ///
    /// The anchor is `id: Verb::Send` — the field assignment that BUILDS the button — rather than the
    /// bare name, which also occurs in that file's prose and its tests. Anchoring on the bare name
    /// would let the shipped row be deleted while a doc mention kept this control green, which is the
    /// vacuity a coupling test exists to avoid.
    #[test]
    fn the_window_never_denies_a_send_the_app_ships() {
        assert!(
            WALLET_PANE_SOURCE.contains("enum Verb")
                && WALLET_PANE_SOURCE.contains("id: Verb::Send"),
            "the Wallet tab no longer ships a Send verb — this window's copy must be revisited \
             before this guard is relaxed"
        );

        let body = window_body(&WalletOverview::read(known(), &ChainSource::Absent));
        for denial in [
            "Sending is not available",
            "not offer a button that moves money",
            "sending is not available",
        ] {
            assert!(
                !body.contains(denial),
                "the app ships Send, so this window may not say {denial:?}: {body}"
            );
        }
    }

    /// Saying only "this window does not send" would leave a person with a capability they cannot
    /// find, so the window names where Send is — the never-trap rule applied to copy.
    #[test]
    fn the_window_says_where_sending_lives() {
        let body = window_body(&WalletOverview::read(known(), &ChainSource::Absent));
        assert!(
            body.contains("Sending is in the DIG window's Wallet tab"),
            "{body}"
        );
        assert!(body.contains("it does not send"), "{body}");
        // A wrapped literal that lost its trailing `\` renders the source's own indentation as a
        // run of spaces mid-sentence; this copy is wrapped, so it is checked for that here.
        assert!(
            !body.contains("  "),
            "a space run reached the window: {body}"
        );
    }

    /// `address()` reads through only when there IS one.
    #[test]
    fn the_address_accessor_is_none_without_an_address() {
        assert_eq!(known().address(), Some(ADDRESS));
        assert_eq!(
            AddressReading::Unavailable(AddressUnavailable::Locked).address(),
            None
        );
    }

    /// The three situations that used to render as one sentence must now render as three
    /// (dig_ecosystem#2848).
    ///
    /// This is a TABLE rather than three separate tests for one reason: a test that asserts a single
    /// reason in isolation passes against an implementation that returns that reason for
    /// everything. The discriminating structure is that every row varies only what it names — the
    /// pair of heights, the measured watched count, the enrolment — and every row must produce a
    /// DIFFERENT reason from its neighbours, which the final uniqueness assertion pins.
    #[test]
    fn a_declined_read_names_which_of_the_three_situations_the_node_is_in() {
        use crate::network::{ChainSync, NetworkStanding};
        use crate::wallet::enrol::Enrolment;

        /// A node standing: how far the replica has copied, what its peers announced, and how many
        /// addresses it is measurably following.
        fn standing(replica: u32, peers: u32, watched: Option<u32>) -> NetworkStanding {
            NetworkStanding {
                sync: ChainSync::Syncing {
                    peak_height: replica,
                },
                chia_peer_peak_height: Some(peers),
                watched_addresses: watched,
                ..Default::default()
            }
        }
        let reason = |standing, enrolment| {
            let overview = WalletOverview::of_tray(&crate::tray_menu::TrayView {
                account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
                receive_address: Some(ADDRESS.to_string()),
                node_connected: true,
                balance: BalanceReading::Unknown(BalanceUnknown::NotSynced),
                network: standing,
                enrolment,
                ..Default::default()
            });
            match overview.balance {
                BalanceReading::Unknown(why) => why,
                other => panic!("a declined read is never a figure: {other:?}"),
            }
        };

        // Genuinely behind: waiting IS the remedy, so the original sentence stands. The watched
        // count is deliberately non-zero here — a replica with an empty subscription would not be
        // behind, it would be frozen.
        let behind = reason(standing(9_140_000, 9_142_585, Some(1)), Enrolment::Unasked);
        // Level with the chain, following nothing, nothing registered: the measured state on the
        // user's machine. Note it shares its ENROLMENT with the row above, so a reason derived from
        // enrolment alone cannot tell them apart.
        let unfollowed = reason(standing(9_142_585, 9_142_585, Some(0)), Enrolment::Unasked);
        // The same node, the same heights, the same empty live set — and the keys accepted. Varies
        // ONE field against the row above, so it discriminates the enrolment leg exactly.
        let awaiting = reason(
            standing(9_142_585, 9_142_585, Some(0)),
            Enrolment::Registered,
        );
        // An UNRESOLVED subscription (`None`, not a measured zero) is not evidence of anything, so
        // the vague-but-true sentence is kept rather than a confident guess made.
        let unresolved = reason(standing(9_142_585, 9_142_585, None), Enrolment::Registered);

        assert_eq!(behind, BalanceUnknown::NotSynced);
        assert_eq!(unfollowed, BalanceUnknown::AddressesNotFollowed);
        assert_eq!(awaiting, BalanceUnknown::AwaitingNodeRestart);
        assert_eq!(unresolved, BalanceUnknown::NotSynced);

        // The sentences a person reads must differ too, not only the variants: three names for one
        // paragraph would leave the defect exactly where it was.
        let sentences = [&behind, &unfollowed, &awaiting].map(unknown_reason);
        assert_ne!(sentences[0], sentences[1]);
        assert_ne!(sentences[1], sentences[2]);
        assert_ne!(sentences[0], sentences[2]);
        assert!(
            !unknown_reason(&unfollowed).contains("catching up")
                && !unknown_reason(&awaiting).contains("catching up"),
            "neither enrolment reason may blame the chain: {sentences:?}"
        );

        // And neither may assert the OPPOSITE chain state either — the mirror of the same defect.
        // `progress()` answers `NothingToSync` from the watched count alone, before it consults
        // either height (`network.rs`, dig_ecosystem#2820), so both enrolment reasons are reached on
        // a first run that is genuinely still syncing. An earlier draft opened with "your node is
        // caught up with the blockchain" and was, on that machine, false.
        //
        // The control is the `behind` row: it is the ONE reason licensed to talk about the chain,
        // and it must still do so — otherwise a version that stripped every chain word everywhere
        // would pass this.
        for chain_claim in ["caught up", "up to date", "in sync", "synced"] {
            for (name, sentence) in [("unfollowed", &unfollowed), ("awaiting", &awaiting)] {
                assert!(
                    !unknown_reason(sentence).contains(chain_claim),
                    "{name} asserts a chain position nothing measured ({chain_claim:?}): {}",
                    unknown_reason(sentence)
                );
            }
        }
        assert!(
            unknown_reason(&behind).contains("catching up with the blockchain"),
            "control: the one reason that IS about the chain must still say so: {}",
            unknown_reason(&behind)
        );
    }

    /// **A measured zero is a FACT and stays a zero.** The refinement above must never reach a
    /// balance the node actually served: an account that holds nothing is entitled to be told so.
    ///
    /// The discriminating fixture is the one under which the refinement WOULD fire — a caught-up
    /// node following no addresses — so an implementation that refined every reading rather than
    /// only a declined one fails here.
    #[test]
    fn a_real_zero_survives_a_node_that_follows_no_addresses() {
        use crate::network::{ChainSync, NetworkStanding};

        let overview = WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            node_connected: true,
            balance: BalanceReading::Known {
                balances: Balances::of_xch_and_dig(0, 0),
                as_of: BalanceAsOf::Replica {
                    height: 9_142_585,
                    caught_up: true,
                },
            },
            network: NetworkStanding {
                sync: ChainSync::Synced {
                    peak_height: 9_142_585,
                },
                chia_peer_peak_height: Some(9_142_585),
                watched_addresses: Some(0),
                ..Default::default()
            },
            ..Default::default()
        });
        assert_eq!(
            overview.balance,
            BalanceReading::Known {
                balances: Balances::of_xch_and_dig(0, 0),
                as_of: BalanceAsOf::Replica {
                    height: 9_142_585,
                    caught_up: true,
                },
            },
            "a figure the node served is never re-explained away"
        );
    }
}
