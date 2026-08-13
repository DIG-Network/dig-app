//! The engine-facing wallet seam — the `control.wallet.*` method set (contract-first).
//!
//! The wallet builds and signs locally (custody stays in dig-app), but the two things it CANNOT do
//! itself — broadcasting a signed bundle to the network and reading chain state — belong to the
//! identity-agnostic engine (it holds the peer connections + the chia-query coinset access). Those
//! cross the §5.3 IPC session as a small, explicit method set:
//!
//! | Method | Request | Response |
//! |---|---|---|
//! | [`METHOD_BROADCAST`] | [`BroadcastRequest`] | [`BroadcastResponse`] |
//! | [`METHOD_COINS`]     | [`CoinsRequest`]     | [`CoinsResponse`]     |
//! | [`METHOD_BALANCE`]   | [`BalanceRequest`]   | [`BalanceResponse`]   |
//!
//! This is the **byte-identical cross-repo contract NODE-1 (dig_ecosystem#910) implements the engine
//! side of** — the same contract-first pattern as the §5.3 session methods. dig-app depends only on
//! the [`WalletEngine`] trait, so it compiles + tests standalone; APP-1's real `SessionClient`
//! transport drops in as the production implementation without touching the wallet logic.

use serde::{Deserialize, Serialize};

use super::state::{Asset, CoinRecord};
use super::WalletError;

/// `control.wallet.broadcast` — submit a locally-signed spend bundle to the network via the engine.
pub const METHOD_BROADCAST: &str = "control.wallet.broadcast";
/// `control.wallet.coins` — read an address's spendable coins for an asset via the engine.
pub const METHOD_COINS: &str = "control.wallet.coins";
/// `control.wallet.balance` — read an address's spendable balance for an asset via the engine.
pub const METHOD_BALANCE: &str = "control.wallet.balance";

/// `control.wallet.broadcast` request: the fully-signed spend bundle, hex-encoded (the chia
/// `Streamable` serialization of the `SpendBundle`). The engine receives ONLY signed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastRequest {
    /// The signed spend bundle, lowercase hex of its streamable bytes.
    pub signed_bundle_hex: String,
}

/// `control.wallet.broadcast` response: the mempool acceptance outcome.
///
/// # Accepted is not confirmed
///
/// `accepted` says the mempool took the bundle. It is not evidence that anything reached a block,
/// and no caller may record an outcome from it — only a buried confirmation of the created coin is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastResponse {
    /// Whether the network accepted the bundle into the mempool.
    pub accepted: bool,
    /// The transaction id (spend-bundle name), lowercase hex, when accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Why the mempool refused, when it refused; `None` on acceptance.
    ///
    /// A refusal is a VALUE and not an error — the bundle was seen and judged — so the reason has
    /// to travel with it. Without this field the caller could tell that a push did not land and not
    /// which of the two opposite remedies applies: retry the same bundle, or build a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<String>,
}

/// `control.wallet.coins` / `control.wallet.balance` request: which address + asset to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinsRequest {
    /// The `xch1…` address to read.
    pub address: String,
    /// The asset to read coins/balance for.
    pub asset: Asset,
}

/// [`CoinsRequest`] doubles as the balance request — a balance is a coins read reduced to a sum, so
/// the wire shape is identical.
pub type BalanceRequest = CoinsRequest;

/// `control.wallet.coins` response: the address's spendable coins for the requested asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinsResponse {
    /// The spendable coins the engine's chain read found.
    pub coins: Vec<CoinRecord>,
}

/// What a balance figure is true AS OF — the provenance that travels with every reading.
///
/// A light client trails the chain permanently, so "caught up" is a moment it passes through rather
/// than a state it sits in. Refusing every figure that is not caught up therefore shows no figure at
/// all. The honest alternative is not to hide the number but to say what it is a statement ABOUT:
/// a replica balance at height N is true of height N, and becomes a lie only when presented as
/// current without saying so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BalanceAsOf {
    /// The node's OWN replica answered, and its figures are true as of this peak height.
    Replica {
        /// The peak height the figures reflect.
        height: u32,
    },
    /// A third party's coinset answer, not the wallet's own view of the chain.
    ///
    /// Carries no height by contract — the figures came from the oracle's chain view, not the
    /// node's — so a surface may not invent an as-of for it.
    Oracle,
    /// The answering node predates tier disclosure, so which tier produced the figures is unknown.
    ///
    /// A THIRD state and not a default tier: naming a tier that was never reported would state
    /// something about the reading that nothing measured.
    Undisclosed,
}

impl BalanceAsOf {
    /// The weaker of two provenances — the one that claims less.
    ///
    /// Two assets are read separately and shown as one holding, so the pair needs a single as-of.
    /// Taking the weaker claim is the only choice that cannot overstate either read: an
    /// [`Undisclosed`](Self::Undisclosed) answer cannot be presented as an [`Oracle`](Self::Oracle)
    /// one, an oracle figure cannot be presented as the wallet's own, and two replica heights
    /// resolve to the earlier one — the later figure is also true of the earlier height, so the
    /// pair is true as of the earlier.
    pub fn weaker(self, other: Self) -> Self {
        match (self, other) {
            (Self::Undisclosed, _) | (_, Self::Undisclosed) => Self::Undisclosed,
            (Self::Oracle, _) | (_, Self::Oracle) => Self::Oracle,
            (Self::Replica { height: a }, Self::Replica { height: b }) => Self::Replica {
                height: a.min(b),
            },
        }
    }
}

/// `control.wallet.balance` response: the address's spendable balance in the asset's base units,
/// with the provenance that makes the figure readable as a claim about a moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceResponse {
    /// The spendable balance, in the asset's base unit (mojos for XCH, base units for DIG).
    pub balance: u64,
    /// What this figure is true as of.
    pub as_of: BalanceAsOf,
}

/// The engine operations the wallet delegates: broadcast a signed bundle, and read chain state for
/// an address. Implemented by the real IPC-session transport in production (APP-1's `SessionClient`)
/// and by fakes in tests — the wallet logic depends only on this trait.
pub trait WalletEngine {
    /// Broadcast a locally-signed bundle. The engine forwards it to the network and reports mempool
    /// acceptance; it never sees the wallet key, only the signed bytes.
    fn broadcast(&self, request: BroadcastRequest) -> Result<BroadcastResponse, WalletError>;

    /// Read the spendable coins for `address` + asset (chia-query-backed, coinset layer).
    fn coins(&self, request: CoinsRequest) -> Result<CoinsResponse, WalletError>;

    /// Read the spendable balance for `address` + asset.
    fn balance(&self, request: BalanceRequest) -> Result<BalanceResponse, WalletError>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A [`WalletEngine`] fake: records broadcasts and returns preloaded coins. Stands in for the
    /// real IPC transport so the seam is driven end-to-end without an engine.
    #[derive(Default)]
    pub struct FakeWalletEngine {
        /// Every bundle handed to [`WalletEngine::broadcast`], in order.
        pub broadcasts: std::cell::RefCell<Vec<String>>,
        /// The coins [`WalletEngine::coins`] / [`WalletEngine::balance`] report.
        pub coins: Vec<CoinRecord>,
        /// The provenance [`WalletEngine::balance`] reports, or [`FAKE_AS_OF`] when unset.
        ///
        /// An [`Option`] rather than a plain field because [`BalanceAsOf`] deliberately has no
        /// `Default` — a default provenance would be a claim nothing measured — while this fake
        /// wants one so the many tests that do not care about provenance need not state one.
        pub as_of: Option<BalanceAsOf>,
    }

    /// The provenance a [`FakeWalletEngine`] reports when a test does not choose one.
    pub const FAKE_AS_OF: BalanceAsOf = BalanceAsOf::Replica { height: 7_000_000 };

    impl WalletEngine for FakeWalletEngine {
        fn broadcast(&self, request: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
            self.broadcasts.borrow_mut().push(request.signed_bundle_hex);
            Ok(BroadcastResponse {
                accepted: true,
                transaction_id: Some("fake-txid".to_string()),
                rejection: None,
            })
        }

        fn coins(&self, request: CoinsRequest) -> Result<CoinsResponse, WalletError> {
            let coins = self
                .coins
                .iter()
                .filter(|c| c.asset == request.asset)
                .cloned()
                .collect();
            Ok(CoinsResponse { coins })
        }

        fn balance(&self, request: BalanceRequest) -> Result<BalanceResponse, WalletError> {
            let balance = self
                .coins
                .iter()
                .filter(|c| c.asset == request.asset)
                .map(|c| c.amount)
                .sum();
            Ok(BalanceResponse {
                balance,
                as_of: self.as_of.unwrap_or(FAKE_AS_OF),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeWalletEngine;
    use super::*;

    fn dig_coin(amount: u64) -> CoinRecord {
        CoinRecord {
            coin_id: format!("{amount:064x}"),
            asset: Asset::Dig,
            amount,
        }
    }

    #[test]
    fn broadcast_records_the_signed_bytes_and_reports_acceptance() {
        let engine = FakeWalletEngine::default();
        let response = engine
            .broadcast(BroadcastRequest {
                signed_bundle_hex: "deadbeef".to_string(),
            })
            .unwrap();
        assert!(response.accepted);
        assert_eq!(engine.broadcasts.borrow().as_slice(), ["deadbeef"]);
    }

    #[test]
    fn coins_and_balance_filter_by_asset() {
        let engine = FakeWalletEngine {
            coins: vec![dig_coin(100), dig_coin(50)],
            ..FakeWalletEngine::default()
        };
        let request = CoinsRequest {
            address: "xch1example".to_string(),
            asset: Asset::Dig,
        };
        assert_eq!(engine.coins(request.clone()).unwrap().coins.len(), 2);
        assert_eq!(engine.balance(request).unwrap().balance, 150);

        let none = CoinsRequest {
            address: "xch1example".to_string(),
            asset: Asset::Xch,
        };
        assert_eq!(engine.balance(none).unwrap().balance, 0);
    }

    #[test]
    fn the_method_names_are_the_frozen_wire_contract() {
        // These strings are the byte-identical contract NODE-1 (#910) dispatches on — pin them.
        assert_eq!(METHOD_BROADCAST, "control.wallet.broadcast");
        assert_eq!(METHOD_COINS, "control.wallet.coins");
        assert_eq!(METHOD_BALANCE, "control.wallet.balance");
    }

    #[test]
    fn requests_round_trip_through_json() {
        let request = CoinsRequest {
            address: "xch1abc".to_string(),
            asset: Asset::Dig,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<CoinsRequest>(&json).unwrap(),
            request
        );
        // Asset serializes lowercase for a stable, language-neutral wire form.
        assert!(json.contains("\"dig\""));
    }
}
