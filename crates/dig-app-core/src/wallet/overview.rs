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
//! # Where the numbers would come from
//!
//! Balances are chain state, which dig-app deliberately cannot read for itself — the engine holds the
//! peer connections and the coinset access (the `control.wallet.*` seam, [`super::engine`]). So the
//! source is an input ([`ChainSource`]) rather than something this module reaches for, and today's
//! production value is [`ChainSource::WithoutWalletReads`] or [`ChainSource::Absent`]: dig-node's
//! published control catalog carries no wallet method yet, so nothing can answer. That is a fact to
//! state, not a zero to show.

use super::engine::{BalanceRequest, WalletEngine};
use super::state::Asset;

/// Mojos in one XCH, and base units in one $DIG — both assets carry 12 decimal places on Chia.
const UNITS_PER_COIN: u64 = 1_000_000_000_000;

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
    Known(Balances),
    /// No balance could be read, and which thing was missing.
    Unknown(BalanceUnknown),
}

/// Why a balance could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalanceUnknown {
    /// There is no address to read a balance for — the address's own reason applies first, because
    /// "start your node" is useless advice to someone with no account.
    NoAddress(AddressUnavailable),
    /// Nothing answered the §5.3 endpoint ladder: no local node is running.
    NoNode,
    /// A node answered, but this build of it does not serve wallet chain reads.
    NodeCannotRead,
    /// A source is there and still catching up to the chain tip, so any figure it gave would be
    /// stale. Reported as unknown rather than shown with a caveat: a stale number still reads as
    /// the truth.
    NotSynced,
    /// The read reached a source and failed. Carries the source's own words so the window can say
    /// what went wrong.
    ReadFailed(String),
}

/// What can answer a balance read right now. The caller decides — this module never probes.
pub enum ChainSource<'a> {
    /// No node is reachable.
    Absent,
    /// A node is reachable but serves no wallet chain reads.
    WithoutWalletReads,
    /// A source is reachable and still syncing.
    NotSynced,
    /// A source ready to answer.
    Ready(&'a dyn WalletEngine),
}

/// Everything the Wallet surface renders: where money arrives, and what is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletOverview {
    /// The receive address, or why there is none.
    pub address: AddressReading,
    /// The balance, or why it is unknown.
    pub balance: BalanceReading,
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
            (_, ChainSource::WithoutWalletReads) => {
                BalanceReading::Unknown(BalanceUnknown::NodeCannotRead)
            }
            (_, ChainSource::NotSynced) => BalanceReading::Unknown(BalanceUnknown::NotSynced),
            (AddressReading::Known(address), ChainSource::Ready(engine)) => {
                read_balances(address, *engine)
            }
        };
        Self { address, balance }
    }

    /// The overview the tray's Wallet window renders, derived from the snapshot the menu was built from.
    ///
    /// Lives here rather than in the `dig-app` shell because a binary is a test-free zone and this
    /// mapping is exactly where an unknown could quietly become a zero: it decides which reason the
    /// window states.
    pub fn of_tray(view: &crate::tray_menu::TrayView) -> Self {
        use crate::tray_menu::AccountState;

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
            (None, Some(AccountState::Unlocked { .. })) if view.address_derivation_failed => {
                AddressReading::Unavailable(AddressUnavailable::DerivationFailed)
            }
            // Locked, or unlocked-but-address-not-yet-derived for an ordinary reason (e.g. the shell
            // simply hasn't read it this repaint): the key material is sealed and unlocking is genuinely
            // the route back.
            (None, Some(AccountState::Locked | AccountState::Unlocked { .. })) => {
                AddressReading::Unavailable(AddressUnavailable::Locked)
            }
        };

        // dig-node's published control catalog carries no wallet method, so even a reachable node
        // cannot answer a balance read today. Which of the two applies matters: "start your node" and
        // "your node cannot do this yet" ask different things of the user.
        let source = if view.node_connected {
            ChainSource::WithoutWalletReads
        } else {
            ChainSource::Absent
        };
        Self::read(address, &source)
    }
}

/// The Wallet window's whole text: where money arrives, what is held, and what the wallet still cannot
/// do.
pub fn window_body(overview: &WalletOverview) -> String {
    format!(
        "{}\n\n{}\n\nSending is not available yet — DIG will not offer a button that moves money until \
         the path behind it is finished. Receiving works now: anything sent to the address above \
         arrives in this account, and your recovery phrase restores it.\n\n\
         Reading DIG content never needs an account or a wallet.",
        address_line(&overview.address),
        balance_line(&overview.balance),
    )
}

/// Read both assets for `address`. A failure in EITHER makes the whole reading unknown — a window
/// showing one asset's balance beside a silently-missing other is a half-truth about someone's money.
fn read_balances(address: &str, engine: &dyn WalletEngine) -> BalanceReading {
    let read = |asset| {
        engine
            .balance(BalanceRequest {
                address: address.to_string(),
                asset,
            })
            .map(|response| response.balance)
    };
    match (read(Asset::Xch), read(Asset::Dig)) {
        (Ok(xch_mojos), Ok(dig_units)) => BalanceReading::Known(Balances {
            xch_mojos,
            dig_units,
        }),
        (Err(e), _) | (_, Err(e)) => {
            BalanceReading::Unknown(BalanceUnknown::ReadFailed(e.to_string()))
        }
    }
}

/// Render a base-unit amount as a whole-coin decimal with its trailing zeros trimmed (`1.5`, `0`,
/// `0.000000000001`) — the form a person reads, without pretending to a precision the number does not
/// have.
pub fn format_amount(base_units: u64) -> String {
    let whole = base_units / UNITS_PER_COIN;
    let fraction = base_units % UNITS_PER_COIN;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:012}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
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
    }
}

/// The balance line for the Wallet window.
///
/// The whole point of this function: an [`BalanceReading::Unknown`] renders WORDS, never a numeral, so
/// no unknown can be read as "you hold nothing".
pub fn balance_line(balance: &BalanceReading) -> String {
    match balance {
        BalanceReading::Known(held) => format!(
            "Balance: {} $DIG and {} XCH.",
            format_amount(held.dig_units),
            format_amount(held.xch_mojos)
        ),
        BalanceReading::Unknown(why) => format!("Balance: not known — {}", unknown_reason(why)),
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
        BalanceReading::Known(held) => format!(
            "Balance: {} $DIG · {} XCH",
            format_amount(held.dig_units),
            format_amount(held.xch_mojos)
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
        BalanceUnknown::NoNode => "no DIG node is running",
        BalanceUnknown::NodeCannotRead => "this node cannot read balances yet",
        BalanceUnknown::NotSynced => "your node is still syncing",
        BalanceUnknown::ReadFailed(_) => "the read failed",
    }
}

/// The clause that completes "not known — …". Each one names the missing thing and, where there is
/// one, the way to fix it.
fn unknown_reason(why: &BalanceUnknown) -> String {
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
        BalanceUnknown::NoNode => {
            "no DIG node is running on this computer, and reading a balance needs one. Start the DIG \
             node and check again."
                .to_string()
        }
        BalanceUnknown::NodeCannotRead => {
            "your DIG node is running but this version of it does not read wallet balances yet. \
             Nothing is wrong with your account — the figure simply is not available."
                .to_string()
        }
        BalanceUnknown::NotSynced => {
            "your node is still catching up with the blockchain. A figure now would be out of date, so \
             DIG waits rather than showing one."
                .to_string()
        }
        BalanceUnknown::ReadFailed(detail) => format!("the read failed ({detail})."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// A source that FAILS every chain read — the "reachable but broken" case.
    struct FailingEngine;

    impl WalletEngine for FailingEngine {
        fn broadcast(&self, _: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
            unreachable!("the overview never broadcasts")
        }
        fn coins(&self, _: CoinsRequest) -> Result<CoinsResponse, WalletError> {
            Err(WalletError::Engine("upstream refused".to_string()))
        }
        fn balance(
            &self,
            _: BalanceRequest,
        ) -> Result<super::super::engine::BalanceResponse, WalletError> {
            Err(WalletError::Engine("upstream refused".to_string()))
        }
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
            BalanceReading::Known(Balances {
                xch_mojos: 0,
                dig_units: 0
            }),
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
        assert!(unreadable_line.contains("no DIG node is running"));
    }

    /// A real balance is reported per asset, in whole coins, from the source's base units.
    #[test]
    fn a_real_balance_is_read_per_asset_and_shown_in_whole_coins() {
        let engine = FakeWalletEngine {
            coins: vec![
                coin(Asset::Dig, 2_500_000_000_000),
                coin(Asset::Xch, 1_000_000_000_000),
                coin(Asset::Xch, 250_000_000_000),
            ],
            ..FakeWalletEngine::default()
        };
        let overview = WalletOverview::read(known(), &ChainSource::Ready(&engine));

        assert_eq!(
            overview.balance,
            BalanceReading::Known(Balances {
                xch_mojos: 1_250_000_000_000,
                dig_units: 2_500_000_000_000,
            })
        );
        assert_eq!(
            balance_line(&overview.balance),
            "Balance: 2.5 $DIG and 1.25 XCH."
        );
    }

    /// Each way of not knowing says something DIFFERENT, because the remedies differ: start a node,
    /// wait for a sync, unlock, or set up an account.
    #[test]
    fn every_unknown_names_its_own_missing_thing() {
        let cases = [
            (
                WalletOverview::read(known(), &ChainSource::Absent).balance,
                "no DIG node is running",
            ),
            (
                WalletOverview::read(known(), &ChainSource::WithoutWalletReads).balance,
                "does not read wallet balances yet",
            ),
            (
                WalletOverview::read(known(), &ChainSource::NotSynced).balance,
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
                WalletOverview::read(known(), &ChainSource::Ready(&FailingEngine)).balance,
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
            BalanceUnknown::NodeCannotRead,
            BalanceUnknown::NotSynced,
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
            "no DIG node is running",
            "this node cannot read balances yet",
            "your node is still syncing",
            "the read failed",
        ];
        let mut seen = std::collections::HashSet::new();
        for (why, clause) in every_unknown().into_iter().zip(expected) {
            let label = menu_balance_label(&BalanceReading::Unknown(why.clone()));
            assert!(label.contains(clause), "{why:?}: {label}");
            assert!(seen.insert(label.clone()), "reasons must differ: {label}");
        }
    }

    /// A KNOWN balance shows both assets, in whole coins, on one row — including a genuine zero, which
    /// is the one case where a numeral is the truth.
    #[test]
    fn a_known_balance_shows_both_assets_on_the_menu_row() {
        let held = menu_balance_label(&BalanceReading::Known(Balances {
            xch_mojos: 1_250_000_000_000,
            dig_units: 2_500_000_000_000,
        }));
        assert!(held.contains("2.5 $DIG"), "{held}");
        assert!(held.contains("1.25 XCH"), "{held}");

        let empty = menu_balance_label(&BalanceReading::Known(Balances {
            xch_mojos: 0,
            dig_units: 0,
        }));
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
        labels.push(menu_balance_label(&BalanceReading::Known(Balances {
            xch_mojos: u64::MAX,
            dig_units: u64::MAX,
        })));

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
                Ok(super::super::engine::BalanceResponse { balance: 0 })
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

    /// Amounts round-trip the way a person reads them — and a sub-unit amount is never rounded away to
    /// a zero that would read as "nothing".
    #[test]
    fn amounts_render_as_trimmed_whole_coins() {
        assert_eq!(format_amount(0), "0");
        assert_eq!(format_amount(UNITS_PER_COIN), "1");
        assert_eq!(format_amount(UNITS_PER_COIN * 3 / 2), "1.5");
        assert_eq!(format_amount(1), "0.000000000001");
        assert_eq!(format_amount(u64::MAX), "18446744.073709551615");
    }

    /// **The window a user actually reads must not turn an unknown balance into a zero either.**
    ///
    /// Asserted on the rendered BODY rather than the `BalanceReading`, because the mapping from the tray
    /// snapshot to that reading is itself a place the distinction could be lost — and the body is what a
    /// person acts on. Two views differing ONLY in whether a node is connected must both say "not known",
    /// each for its own reason.
    #[test]
    fn the_wallet_window_never_states_a_balance_it_could_not_read() {
        let mut view = crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            node_connected: false,
            ..Default::default()
        };

        let offline = window_body(&WalletOverview::of_tray(&view));
        view.node_connected = true;
        let online = window_body(&WalletOverview::of_tray(&view));

        for body in [&offline, &online] {
            assert!(body.contains(ADDRESS), "the address is readable in both");
            assert!(body.contains("Balance: not known"), "{body}");
            assert!(
                !body.contains("0 $DIG"),
                "an unread balance must never appear as zero: {body}"
            );
        }
        assert!(offline.contains("no DIG node is running"));
        assert!(online.contains("does not read wallet balances yet"));
        assert_ne!(offline, online, "the two reasons are different facts");
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

    /// **An unlocked account whose address derivation genuinely fails is told the truth, never
    /// "unlock your account first"** (dig_ecosystem#2059).
    ///
    /// Before this fix, `Unlocked { .. }` + `receive_address: None` fell through to the SAME `Locked`
    /// arm as an ordinary lock — naming a remedy ("unlock it") the user is not in a position to need,
    /// because they are already unlocked. This is the load-bearing assertion: it fails against the old
    /// collapse-to-`Locked` mapping and passes only once `address_derivation_failed` is threaded through
    /// to a distinct `DerivationFailed` reading.
    #[test]
    fn an_unlocked_account_with_a_failed_derivation_is_told_the_truth_not_told_to_unlock() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: None,
            address_derivation_failed: true,
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
            address_derivation_failed: false,
            ..Default::default()
        }));

        assert!(body.contains("Unlock it and it appears here"), "{body}");
        assert!(!body.contains("could not be derived"), "{body}");
    }

    /// **The race the atomic read closes:** an account observed unlocked this repaint but with NO
    /// derivation-failure signal (the ordinary in-between state — e.g. a lock landed between the tray's
    /// last read and this one) must NOT be alarmed into `DerivationFailed`. Only the atomic
    /// `address_derivation_failed` flag — set from ONE observation, never from `Unlocked` alone — may
    /// route there.
    #[test]
    fn unlocked_with_no_address_and_no_failure_signal_reads_as_an_ordinary_lock() {
        let body = window_body(&WalletOverview::of_tray(&crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: None,
            address_derivation_failed: false,
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
