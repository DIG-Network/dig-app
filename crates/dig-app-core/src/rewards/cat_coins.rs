//! The reward-distributor mint's $DIG reserve coin: list candidates, then resolve ONE chosen coin's
//! CAT lineage -- dig-account 0.28.0 has no public CAT selector to call instead (measured against
//! `dig-account-0.28.0/src/wallet/cat_transfer.rs`: `select_cat_coins` at `:472` and
//! `resolve_lineage` at `:649` are both private `fn`; the only public entry point is
//! [`dig_account::dig_curried_puzzle_hash`]). This module mirrors `resolve_lineage`'s SHAPE exactly
//! (same two-step read: list by curried puzzle hash, then read+parse each candidate's PARENT spend
//! for its lineage proof) rather than inventing a different one, and is deleted the day dig-account
//! exposes a public equivalent -- tracked as DIG-Network/dig-account#59.
//!
//! # Why this is not a hand-rolled CAT parser
//!
//! Parsing is entirely [`Cat::parse_children`] -- the chia-wallet-sdk driver's own parser. Nothing
//! here decodes a CLVM puzzle or a CAT layer by hand; this module only does the two chain reads and
//! the coin-id match dig-account's own `resolve_lineage` does, using the SDK's parser exactly as it
//! does. A wrong lineage FAILS CLOSED -- `MintError::Refused` inside
//! `begin_reward_distributor_mint`'s own ownership re-check (`reward_distributor.rs`'s
//! `request.reward_cat.info.p2_puzzle_hash != wallet_puzzle_hash` guard) -- never a lost coin.
//!
//! # Reserve amount (dig-account#59's sibling decision)
//!
//! [`dig_account::mint::reward_distributor::RewardDistributorMintRequest::reward_cat`] is ONE
//! [`Cat`] whose WHOLE amount becomes the distributor's reserve -- there is no amount parameter.
//! This module therefore lists candidate coins for a person to pick ONE from (see
//! [`dig_candidates`]); it does not split, merge or partially spend a coin to reach an exact amount.
//! Follow-up: DIG-Network/dig-app#412.

use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::{Cat, Puzzle};
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;
use dig_account::dig_curried_puzzle_hash;
use dig_chainsource_interface::ChainSource;
use dig_constants::DIG_ASSET_ID;

/// Why a chosen $DIG coin could not be turned into a spendable [`Cat`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigLineageError {
    /// The chain source itself could not answer.
    ChainUnavailable(String),
    /// The coin's parent spend is not known to this source -- its lineage cannot be proven, so it
    /// must not be spent.
    ParentSpendUnknown,
    /// The parent's puzzle reveal or solution did not decode.
    Undecodable(String),
    /// The parent spend decoded but is not a CAT spend at all.
    ParentNotCat,
    /// The parent CAT spend decoded, but none of its children is the coin that was asked for -- a
    /// mismatch between what was selected and what the lineage actually creates.
    ChildNotFound,
}

impl std::fmt::Display for DigLineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainUnavailable(why) => write!(f, "chain source unavailable: {why}"),
            Self::ParentSpendUnknown => {
                write!(f, "the coin's parent spend is unknown to this source")
            }
            Self::Undecodable(why) => write!(f, "the parent spend does not decode: {why}"),
            Self::ParentNotCat => write!(f, "the parent coin is not a CAT"),
            Self::ChildNotFound => write!(
                f,
                "the parent CAT spend does not create the coin that was selected"
            ),
        }
    }
}

impl std::error::Error for DigLineageError {}

/// Every confirmed, unspent $DIG coin at `p2_puzzle_hash` -- candidates for the create card's
/// reserve-coin picker. Never merges or totals them: `RewardDistributorMintRequest::reward_cat`
/// takes exactly one coin, whole.
pub fn dig_candidates<C>(chain: &C, p2_puzzle_hash: Bytes32) -> Result<Vec<Coin>, String>
where
    C: ChainSource + ?Sized,
{
    let cat_puzzle_hash = dig_curried_puzzle_hash(p2_puzzle_hash);
    let records = chain
        .coin_records_by_puzzle_hash(cat_puzzle_hash, false)
        .map_err(|e| e.to_string())?;
    Ok(records
        .into_iter()
        .filter(|record| !record.is_spent() && record.confirmed_height.is_some())
        .map(|record| record.coin)
        .collect())
}

/// Turns one selected $DIG coin into a spendable [`Cat`] by reading and parsing its PARENT spend --
/// the lineage proof the CAT puzzle demands, unobtainable from a coin record alone. Mirrors
/// dig-account's private `resolve_lineage` (`wallet/cat_transfer.rs:649`) exactly. See this
/// module's doc comment for why this is the sanctioned interim route rather than a second parser.
pub fn resolve_dig_lineage<C>(chain: &C, coin: Coin) -> Result<Cat, DigLineageError>
where
    C: ChainSource + ?Sized,
{
    let coin_id = coin.coin_id();
    let parent = chain
        .parent_spend(coin_id)
        .map_err(|e| DigLineageError::ChainUnavailable(e.to_string()))?
        .ok_or(DigLineageError::ParentSpendUnknown)?;

    let mut allocator = Allocator::new();
    let puzzle_ptr = node_from_bytes(&mut allocator, &parent.puzzle_reveal)
        .map_err(|e| DigLineageError::Undecodable(format!("puzzle reveal: {e}")))?;
    let solution_ptr = node_from_bytes(&mut allocator, &parent.solution)
        .map_err(|e| DigLineageError::Undecodable(format!("solution: {e}")))?;
    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    let children = Cat::parse_children(&mut allocator, parent.coin, puzzle, solution_ptr)
        .map_err(|e| DigLineageError::Undecodable(e.to_string()))?
        .ok_or(DigLineageError::ParentNotCat)?;

    children
        .into_iter()
        .find(|child| child.coin.coin_id() == coin_id)
        .ok_or(DigLineageError::ChildNotFound)
}

/// $DIG's own asset id, re-exported here so a test building a [`Cat`] fixture by hand does not have
/// to depend on `dig-constants` directly.
pub const DIG_ASSET_ID_HASH: Bytes32 = DIG_ASSET_ID;

/// Fixture-only CAT lineage building, `pub(crate)` so [`super::mint`]'s door tests can drive
/// `begin_reward_distributor_mint` over a reward CAT with the same proven lineage shape, under a
/// caller-supplied wallet key, rather than each duplicating this CLVM construction.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use chia_bls::PublicKey;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::driver::{CatSpend, SpendContext, StandardLayer};
    use chia_wallet_sdk::prelude::{Conditions, SpendWithConditions};
    use dig_chainsource_interface::record::CoinRecord;
    use dig_chainsource_interface::MockChainSource;

    /// Builds one real CAT coin lineage (a parent CAT coin spent into one child of the same
    /// amount, both curried to `p2_public_key`) and loads it into a [`MockChainSource`], so
    /// `resolve_dig_lineage` runs the real SDK parser over real CLVM bytes rather than a stub.
    ///
    /// Takes the actual public key, not a puzzle hash: [`Cat::parse_children`] derives the
    /// child's `p2_puzzle_hash` STRUCTURALLY from the parent's real inner puzzle reveal, so the
    /// puzzle built here (`StandardLayer::new(p2_public_key)`) must be the SAME key the caller
    /// will treat the resulting coin as belonging to -- a puzzle hash passed independently could
    /// silently mismatch the puzzle actually spent.
    pub(crate) fn fixture_cat_lineage(p2_public_key: PublicKey, amount: u64) -> (Coin, MockChainSource) {
        let p2_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(p2_public_key).into();
        let asset_id = DIG_ASSET_ID_HASH;
        let cat_puzzle_hash = dig_curried_puzzle_hash(p2_puzzle_hash);

        let grandparent_id = Bytes32::from([1u8; 32]);
        let parent_coin = Coin::new(grandparent_id, cat_puzzle_hash, amount);
        let child_puzzle_hash = cat_puzzle_hash;

        let mut ctx = SpendContext::new();
        let p2 = StandardLayer::new(p2_public_key);
        let inner_spend = p2
            .spend_with_conditions(
                &mut ctx,
                Conditions::new().create_coin(
                    child_puzzle_hash,
                    amount,
                    chia_puzzle_types::Memos::None,
                ),
            )
            .expect("build inner spend");
        let cat = Cat::new(
            parent_coin,
            None,
            chia_wallet_sdk::driver::CatInfo::new(asset_id, None, p2_puzzle_hash),
        );
        let cat_spend = CatSpend::new(cat, inner_spend);
        Cat::spend_all(&mut ctx, &[cat_spend]).expect("build CAT spend");
        let coin_spends = ctx.take();
        let parent_spend = coin_spends
            .into_iter()
            .find(|cs| cs.coin.coin_id() == parent_coin.coin_id())
            .expect("parent CAT spend present");

        let child_coin = Coin::new(parent_coin.coin_id(), child_puzzle_hash, amount);

        // `ChainSource::parent_spend(child_id)` resolves `coin_record(child_id)` then
        // `coin_spend(record.coin.parent_coin_info)` -- so the stored spend is keyed by the
        // PARENT coin's own id, not the child's.
        let chain = MockChainSource::new()
            .with_coin(
                child_coin.coin_id(),
                CoinRecord {
                    coin: child_coin,
                    confirmed_height: Some(10),
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            )
            .with_spend(parent_coin.coin_id(), parent_spend);
        (child_coin, chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_chainsource_interface::record::CoinRecord;
    use dig_chainsource_interface::MockChainSource;

    /// A synthetic key + its standard p2 puzzle hash, for the tests below that need only a
    /// puzzle hash (no real CAT spend).
    fn fixture_key() -> (chia_bls::SecretKey, Bytes32) {
        let sk = chia_bls::SecretKey::from_seed(&[7u8; 32]);
        let pk = sk.public_key();
        let ph: Bytes32 = chia_puzzle_types::standard::StandardArgs::curry_tree_hash(pk).into();
        (sk, ph)
    }

    #[test]
    fn a_real_cat_lineage_resolves_to_a_cat_of_the_same_coin() {
        let (sk, _p2) = fixture_key();
        let (child_coin, chain) = fixtures::fixture_cat_lineage(sk.public_key(), 1_000);

        let cat = resolve_dig_lineage(&chain, child_coin).expect("lineage resolves");
        assert_eq!(cat.coin, child_coin);
    }

    #[test]
    fn an_unknown_parent_spend_is_refused_not_skipped() {
        let (_sk, p2) = fixture_key();
        let cat_puzzle_hash = dig_curried_puzzle_hash(p2);
        let orphan_coin = Coin::new(Bytes32::from([9u8; 32]), cat_puzzle_hash, 500);
        let chain = MockChainSource::new().with_coin(
            orphan_coin.coin_id(),
            CoinRecord {
                coin: orphan_coin,
                confirmed_height: Some(10),
                spent_height: None,
                timestamp: None,
                coinbase: false,
            },
        );

        let err = resolve_dig_lineage(&chain, orphan_coin).expect_err("no parent spend loaded");
        assert_eq!(err, DigLineageError::ParentSpendUnknown);
    }

    #[test]
    fn dig_candidates_excludes_spent_and_unconfirmed_coins() {
        let (_sk, p2) = fixture_key();
        let cat_puzzle_hash = dig_curried_puzzle_hash(p2);
        let confirmed = Coin::new(Bytes32::from([1u8; 32]), cat_puzzle_hash, 100);
        let spent = Coin::new(Bytes32::from([2u8; 32]), cat_puzzle_hash, 200);
        let unconfirmed = Coin::new(Bytes32::from([3u8; 32]), cat_puzzle_hash, 300);
        let chain = MockChainSource::new()
            .with_coin(
                confirmed.coin_id(),
                CoinRecord {
                    coin: confirmed,
                    confirmed_height: Some(5),
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            )
            .with_coin(
                spent.coin_id(),
                CoinRecord {
                    coin: spent,
                    confirmed_height: Some(5),
                    spent_height: Some(6),
                    timestamp: None,
                    coinbase: false,
                },
            )
            .with_coin(
                unconfirmed.coin_id(),
                CoinRecord {
                    coin: unconfirmed,
                    confirmed_height: None,
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            );

        let candidates = dig_candidates(&chain, p2).expect("read succeeds");
        assert_eq!(candidates, vec![confirmed]);
    }
}
