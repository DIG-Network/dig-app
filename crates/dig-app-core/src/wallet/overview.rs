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

/// Why no receive address is available. Each variant is a different thing for the user to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressUnavailable {
    /// There is no account on this computer yet, so there is no key to derive an address from.
    NoAccount,
    /// The account is locked. An address is public, but deriving one needs the key material a lock
    /// deliberately drops — so the address is *withheld*, never guessed.
    Locked,
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
            (AddressReading::Unavailable(why), _) => BalanceReading::Unknown(
                BalanceUnknown::NoAddress(*why),
            ),
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
        (Err(e), _) | (_, Err(e)) => BalanceReading::Unknown(BalanceUnknown::ReadFailed(
            e.to_string(),
        )),
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
        AddressReading::Unavailable(AddressUnavailable::Locked) => {
            "Your address is not shown because your account is locked. Unlock it and it appears here — \
             an address is public, but DIG will not guess one while the keys it comes from are sealed."
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

/// The clause that completes "not known — …". Each one names the missing thing and, where there is
/// one, the way to fix it.
fn unknown_reason(why: &BalanceUnknown) -> String {
    match why {
        BalanceUnknown::NoAddress(AddressUnavailable::NoAccount) => {
            "there is no account on this computer to hold one.".to_string()
        }
        BalanceUnknown::NoAddress(AddressUnavailable::Locked) => {
            "your account is locked, so DIG cannot tell which address to read. Unlock it to see your \
             balance."
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
    use crate::wallet::engine::{
        BroadcastRequest, BroadcastResponse, CoinsRequest, CoinsResponse,
    };
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
        fn balance(&self, _: BalanceRequest) -> Result<super::super::engine::BalanceResponse, WalletError> {
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
        let empty = WalletOverview::read(
            known(),
            &ChainSource::Ready(&FakeWalletEngine::default()),
        );
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
