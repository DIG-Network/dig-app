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

use crate::amount::format_asset_amount;

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

/// A spendable balance, in each asset's base unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balances {
    /// Native Chia, in mojos.
    pub xch_mojos: u64,
    /// The DIG CAT, in base units.
    pub dig_units: u64,
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
    NotSynced,
    /// The node's own replica answered and has synced nothing, so there is no figure to show.
    ///
    /// Its `balance: 0` is *no data*, not *no money*, and this variant is what keeps the two apart:
    /// a zero rendered here would tell somebody who holds funds that they hold none. Absent, not
    /// stale, and never a numeral.
    ReplicaHasNoData,
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
}

impl WalletOverview {
    /// Read the overview for `address` against `source`.
    ///
    /// The address's availability is checked FIRST: with no address there is nothing to read a balance
    /// for, and the address's reason is the actionable one.
    pub fn read(address: AddressReading, source: &ChainSource<'_>) -> Self {
        let balance = match (&address, source) {
            (AddressReading::Unavailable(why), _) => {
                BalanceReading::Unknown(BalanceUnknown::NoAddress(*why))
            }
            (_, ChainSource::Absent) => BalanceReading::Unknown(BalanceUnknown::NoNode),
            (AddressReading::Known(address), ChainSource::Ready(engine)) => {
                read_balances(address, *engine)
            }
        };
        // `read` is the direct-address path (the shell has an address in hand and wants a balance),
        // which never consults a registry. The caveat belongs to `of_tray`, which does.
        Self {
            address,
            balance,
            profiles_unreadable: false,
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
            AddressReading::Known(_) => view.balance.clone(),
        };
        Self {
            address,
            balance,
            profiles_unreadable: view.profiles.is_unreadable(),
        }
    }
}

/// The Wallet window's whole text: where money arrives, what is held, and what the wallet still cannot
/// do.
pub fn window_body(overview: &WalletOverview) -> String {
    format!(
        "{}{}\n\n{}\n\nSending is not available yet — DIG will not offer a button that moves money until \
         the path behind it is finished. Receiving works now: anything sent to the address above \
         arrives in this account, and your recovery phrase restores it.\n\n\
         Reading DIG content never needs an account or a wallet.",
        address_line(&overview.address),
        unreadable_registry_caveat(overview.profiles_unreadable),
        balance_line(&overview.balance),
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

/// Read both assets for `address`. A failure in EITHER makes the whole reading unknown — a window
/// showing one asset's balance beside a silently-missing other is a half-truth about someone's money.
fn read_balances(address: &str, engine: &dyn WalletEngine) -> BalanceReading {
    let read = |asset| {
        engine.balance(BalanceRequest {
            address: address.to_string(),
            asset,
        })
    };
    match (read(Asset::Xch), read(Asset::Dig)) {
        (Ok(xch), Ok(dig)) => BalanceReading::Known {
            balances: Balances {
                xch_mojos: xch.balance,
                dig_units: dig.balance,
            },
            // The two assets are read separately and shown as one holding, so the pair takes the
            // weaker of the two provenances — see `BalanceAsOf::weaker`.
            as_of: xch.as_of.weaker(dig.as_of),
        },
        (Err(e), _) | (_, Err(e)) => BalanceReading::Unknown(why_unread(e)),
    }
}

/// Translate the engine's typed failure into the reason a person is shown.
///
/// The three named variants exist so that the node's own answer — not a constant in this file —
/// decides which remedy the window offers. Anything else is a genuine read failure and carries the
/// source's words, because a fault we cannot classify must not be dressed up as one we can.
fn why_unread(error: WalletError) -> BalanceUnknown {
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

/// Render a held amount the way a person reads it — see [`format_asset_amount`], which this delegates
/// to so that the Wallet surface cannot acquire a divisor of its own (dig_ecosystem#2295).
pub fn format_amount(asset: Asset, base_units: u64) -> String {
    format_asset_amount(asset, base_units)
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
pub fn balance_line(balance: &BalanceReading) -> String {
    match balance {
        BalanceReading::Pending => "Balance: checking with your node…".to_string(),
        BalanceReading::Known { balances, as_of } => format!(
            "Balance: {} $DIG and {} XCH. {}",
            format_amount(Asset::Dig, balances.dig_units),
            format_amount(Asset::Xch, balances.xch_mojos),
            as_of_sentence(*as_of)
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
pub fn as_of_sentence(as_of: BalanceAsOf) -> String {
    /// A block height with thousands separators — seven bare digits are a number nobody reads.
    fn grouped(height: u32) -> String {
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

    match as_of {
        BalanceAsOf::Replica { height } => {
            format!(
                "Correct as of block {}, the last your node has read.",
                grouped(height)
            )
        }
        BalanceAsOf::Oracle => {
            "Read from a public chain service, not from your own node.".to_string()
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
pub fn menu_balance_label(balance: &BalanceReading) -> String {
    match balance {
        BalanceReading::Pending => "Balance: checking…".to_string(),
        BalanceReading::Known { balances, .. } => format!(
            "Balance: {} $DIG · {} XCH",
            format_amount(Asset::Dig, balances.dig_units),
            format_amount(Asset::Xch, balances.xch_mojos)
        ),
        BalanceReading::Unknown(why) => format!("Balance not known — {}…", menu_reason(why)),
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
                balances: Balances {
                    xch_mojos: 0,
                    dig_units: 0
                },
                as_of: BalanceAsOf::Replica { height: 7_000_000 }
            },
            "a source that answered zero IS a zero balance"
        );
        let empty_line = balance_line(&empty.balance);
        let unreadable_line = balance_line(&unreadable.balance);
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
                coin(Asset::Dig, 2_500),
                coin(Asset::Xch, 1_000_000_000_000),
                coin(Asset::Xch, 250_000_000_000),
            ],
            ..FakeWalletEngine::default()
        };
        let overview = WalletOverview::read(known(), &ChainSource::Ready(&engine));

        assert_eq!(
            overview.balance,
            BalanceReading::Known {
                balances: Balances {
                    xch_mojos: 1_250_000_000_000,
                    dig_units: 2_500,
                },
                as_of: crate::wallet::engine::test_support::FAKE_AS_OF
            }
        );
        assert!(
            balance_line(&overview.balance).starts_with("Balance: 2.5 $DIG and 1.25 XCH."),
            "{}",
            balance_line(&overview.balance)
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
            let line = balance_line(&reading);
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
            let label = menu_balance_label(&BalanceReading::Unknown(why.clone()));
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
            let label = menu_balance_label(&BalanceReading::Unknown(why.clone()));
            assert!(label.contains(clause), "{why:?}: {label}");
            assert!(seen.insert(label.clone()), "reasons must differ: {label}");
        }
    }

    /// A KNOWN balance shows both assets, in whole coins, on one row — including a genuine zero, which
    /// is the one case where a numeral is the truth.
    #[test]
    fn a_known_balance_shows_both_assets_on_the_menu_row() {
        let held = menu_balance_label(&BalanceReading::Known {
            balances: Balances {
                xch_mojos: 1_250_000_000_000,
                dig_units: 2_500,
            },
            as_of: BalanceAsOf::Replica { height: 7_000_000 },
        });
        assert!(held.contains("2.5 $DIG"), "{held}");
        assert!(held.contains("1.25 XCH"), "{held}");

        let empty = menu_balance_label(&BalanceReading::Known {
            balances: Balances {
                xch_mojos: 0,
                dig_units: 0,
            },
            as_of: BalanceAsOf::Replica { height: 7_000_000 },
        });
        assert!(
            empty.contains("0 $DIG") && empty.contains("0 XCH"),
            "{empty}"
        );
        assert!(
            !empty.contains("not known"),
            "a source that answered zero KNOWS the balance: {empty}"
        );
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
            .map(|why| menu_balance_label(&BalanceReading::Unknown(why)))
            .collect();
        labels.push(menu_balance_label(&BalanceReading::Unknown(
            BalanceUnknown::ReadFailed("x".repeat(4000)),
        )));
        // The widest KNOWN reading a u64 pair can produce, so the bound covers the figures too.
        labels.push(menu_balance_label(&BalanceReading::Known {
            balances: Balances {
                xch_mojos: u64::MAX,
                dig_units: u64::MAX,
            },
            as_of: BalanceAsOf::Replica { height: 7_000_000 },
        }));

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

        let lines = [&timed_out, &syncing, &unreachable].map(balance_line);
        let rows = [&timed_out, &syncing, &unreachable].map(menu_balance_label);
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
            balance_line(&timed_out),
            menu_balance_label(&timed_out),
            window_body(&WalletOverview {
                address: known(),
                balance: timed_out.clone(),
                profiles_unreadable: false,
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
        for text in [balance_line(&pending), menu_balance_label(&pending)] {
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
            balance_line(&pending),
            balance_line(&BalanceReading::Unknown(BalanceUnknown::NoNode))
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
                    Asset::Dig => Err(WalletError::Engine("cat read failed".to_string())),
                }
            }
        }

        let overview = WalletOverview::read(known(), &ChainSource::Ready(&HalfEngine));
        assert!(matches!(
            overview.balance,
            BalanceReading::Unknown(BalanceUnknown::ReadFailed(_))
        ));
        assert!(!balance_line(&overview.balance).contains('7'));
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
    #[test]
    fn amounts_render_at_each_assets_own_scale() {
        let one_dig = 10u64.pow(Asset::Dig.decimals());
        let one_xch = 10u64.pow(Asset::Xch.decimals());

        assert_eq!(format_amount(Asset::Dig, one_dig), "1");
        assert_eq!(format_amount(Asset::Xch, one_xch), "1");
        assert_eq!(format_amount(Asset::Dig, one_dig * 3 / 2), "1.5");
        assert_eq!(format_amount(Asset::Xch, one_xch * 3 / 2), "1.5");
        assert_eq!(format_amount(Asset::Dig, 0), "0");
        assert_eq!(format_amount(Asset::Xch, 0), "0");
    }

    /// A sub-unit holding is never rounded away to a zero that would read as "nothing".
    #[test]
    fn a_sub_coin_holding_is_never_rendered_as_nothing() {
        assert_ne!(format_amount(Asset::Dig, 1), "0");
        assert_ne!(format_amount(Asset::Xch, 1), "0");
        assert_eq!(format_amount(Asset::Dig, 1), "0.001");
        assert_eq!(format_amount(Asset::Xch, 1), "0.000000000001");
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
                balances: Balances {
                    xch_mojos: 1_250_000_000_000,
                    dig_units: 2_500,
                },
                as_of: BalanceAsOf::Replica { height: 7_000_000 },
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
                balances: Balances {
                    xch_mojos: 1_250_000_000_000,
                    dig_units: 2_500,
                },
                as_of: BalanceAsOf::Replica { height: 7_000_000 },
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

    /// The window never advertises a verb the app cannot perform — sending is parked (#1702), so it is
    /// named as absent rather than implied.
    #[test]
    fn the_window_says_sending_is_not_available() {
        let body = window_body(&WalletOverview::read(known(), &ChainSource::Absent));
        assert!(body.contains("Sending is not available yet"), "{body}");
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
}
