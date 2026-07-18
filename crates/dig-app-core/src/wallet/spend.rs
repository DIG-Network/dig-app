//! Spend construction — the $DIG per-capsule payment, built via the canonical chip35 spend builder.
//!
//! dig-app NEVER hand-rolls a spend bundle (SPEC §4.1 / the `canonical` skill): every $DIG spend is
//! constructed by [`chip35_dl_coin`], the ecosystem's canonical CHIP-0035 spend builder, and the DIG
//! treasury constant reused from it (byte-identical to the digstore-chain mirror). This module is a
//! thin, typed adapter: it hands the wallet's buyer key + selected DIG coins to chip35, returns the
//! UNSIGNED coin spends, and leaves signing to [`super::signing::WalletKey::sign_bundle`].

use chia_protocol::{Bytes32, CoinSpend};
use chia_sdk_driver::Cat;
use chip35_dl_coin::build_dig_store_payment;

use super::signing::WalletKey;
use super::WalletError;

/// The canonical DIG treasury recipient of every per-capsule payment, re-exported from the chip35
/// builder so consumers never hardcode a placeholder (see the `canonical` skill → DIG treasury).
pub use chip35_dl_coin::{DIG_ASSET_ID, DIG_TREASURY_INNER_PUZZLE_HASH};

/// Build the UNSIGNED $DIG coin spends that pay `amount` base units to the DIG treasury for the
/// capsule (commit) identified by `store_id`, spending `wallet`'s selected DIG [`Cat`] coins.
///
/// The `amount` is the dynamic, USD-pegged per-capsule price in DIG base units — an input the caller
/// computes from the live DIG price, never a hardcoded constant (chip35's pricing contract). The
/// returned spends are unsigned; the caller signs them locally with
/// [`WalletKey::sign_bundle`](super::signing::WalletKey::sign_bundle) and hands the finished bundle
/// to the engine to broadcast.
///
/// # Errors
///
/// [`WalletError::Spend`] if chip35 rejects the inputs (empty/mixed/non-DIG coins, or a total below
/// `amount`) or fails to construct the spend.
pub fn build_dig_capsule_payment(
    wallet: &WalletKey,
    dig_coins: Vec<Cat>,
    store_id: Bytes32,
    amount: u64,
) -> Result<Vec<CoinSpend>, WalletError> {
    build_dig_store_payment(wallet.public_key(), dig_coins, store_id, amount)
        .map_err(|e| WalletError::Spend(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::encode_signed_bundle;
    use crate::wallet::engine::{test_support::FakeWalletEngine, BroadcastRequest, WalletEngine};
    use chia_bls::Signature;
    use chia_protocol::{Coin, SpendBundle};
    use chia_puzzle_types::standard::StandardArgs;
    use chia_sdk_driver::CatInfo;

    /// A buyer-owned DIG [`Cat`] of `amount` base units, owned by `wallet`'s standard puzzle — the
    /// keyless test analogue of a real reconstructed DIG CAT (mirrors chip35's own `dig_cat` helper).
    fn dig_cat(wallet: &WalletKey, amount: u64) -> Cat {
        let p2: Bytes32 = StandardArgs::curry_tree_hash(wallet.public_key()).into();
        Cat::new(
            Coin {
                parent_coin_info: Bytes32::new([5u8; 32]),
                puzzle_hash: Bytes32::new([6u8; 32]),
                amount,
            },
            None,
            CatInfo::new(DIG_ASSET_ID, None, p2),
        )
    }

    /// Whether any spend commits to the DIG treasury inner puzzle hash (its 32 bytes appear in the
    /// spend's `puzzle_reveal || solution`) — the keyless "this bundle pays the treasury" signal.
    fn pays_treasury(coin_spends: &[CoinSpend]) -> bool {
        let needle = DIG_TREASURY_INNER_PUZZLE_HASH.to_bytes();
        coin_spends.iter().any(|cs| {
            let mut bytes = cs.puzzle_reveal.as_ref().to_vec();
            bytes.extend_from_slice(cs.solution.as_ref());
            bytes.windows(needle.len()).any(|w| w == needle)
        })
    }

    #[test]
    fn a_capsule_payment_builds_valid_unsigned_spends_paying_the_treasury() {
        let wallet = WalletKey::from_seed([3u8; 32]);
        let store_id = Bytes32::new([0x11u8; 32]);
        let spends = build_dig_capsule_payment(
            &wallet,
            vec![dig_cat(&wallet, 1_000_000)],
            store_id,
            100_000,
        )
        .unwrap();

        assert!(!spends.is_empty(), "a payment must produce coin spends");
        assert!(
            pays_treasury(&spends),
            "the payment must pay the DIG treasury"
        );
    }

    #[test]
    fn a_built_payment_encodes_and_broadcasts_via_the_engine() {
        // The build → encode → broadcast half of the custody flow (local signing of a real spend is
        // covered in `signing`, since a fabricated CAT has no on-chain lineage for the signer to
        // execute). The engine receives ONLY the encoded bundle bytes — never the wallet key.
        let wallet = WalletKey::from_seed([4u8; 32]);
        let store_id = Bytes32::new([0x22u8; 32]);
        let spends =
            build_dig_capsule_payment(&wallet, vec![dig_cat(&wallet, 500_000)], store_id, 250_000)
                .unwrap();

        let bundle = SpendBundle::new(spends, Signature::default());
        let hex = encode_signed_bundle(&bundle).unwrap();
        assert!(!hex.is_empty());

        let engine = FakeWalletEngine::default();
        let response = engine
            .broadcast(BroadcastRequest {
                signed_bundle_hex: hex.clone(),
            })
            .unwrap();
        assert!(response.accepted);
        assert_eq!(engine.broadcasts.borrow().as_slice(), [hex]);
    }

    #[test]
    fn an_empty_coin_set_is_rejected_by_chip35() {
        let wallet = WalletKey::from_seed([5u8; 32]);
        let err =
            build_dig_capsule_payment(&wallet, vec![], Bytes32::new([0u8; 32]), 1).unwrap_err();
        assert!(matches!(err, WalletError::Spend(_)));
    }

    #[test]
    fn insufficient_dig_is_rejected() {
        let wallet = WalletKey::from_seed([6u8; 32]);
        let err = build_dig_capsule_payment(
            &wallet,
            vec![dig_cat(&wallet, 10)],
            Bytes32::new([0u8; 32]),
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Spend(_)));
    }
}
