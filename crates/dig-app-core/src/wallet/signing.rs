//! The wallet's BLS key and the **local** spend-bundle signer (SECURITY-CRITICAL custody boundary).
//!
//! A profile's wallet key is a Chia BLS key held **only in memory** while the profile is unlocked;
//! its 32-byte seed is DIGOP1-sealed at rest ([`super::state`]). Signing happens in-process and the
//! finished [`SpendBundle`] — signed bytes only — is what leaves for the engine to broadcast. The
//! engine **never** receives the private key (the same custody boundary as the session `sign`
//! callback, §2.3 of `SPEC.md`).
//!
//! # Key derivation (canonical Chia wallet path)
//!
//! The seed roots a Chia BLS master key; the on-chain spending key is the standard unhardened wallet
//! child at index 0, made synthetic — `master_to_wallet_unhardened(master, 0).derive_synthetic()`
//! (the canonical chip35-re-exported derivation, identical whether applied to the secret or public
//! key). Its public half curries the standard puzzle whose tree hash is the wallet's XCH address.
//!
//! # Signing (the proven ecosystem pattern)
//!
//! Each coin spend's required BLS signatures are extracted with the `chia-wallet-sdk` signer against
//! the network AGG_SIG constants, then signed with the synthetic secret key and aggregated — the
//! same construction the node-side `dig-wallet` uses. We never hand-roll the CLVM or the signature.

use chia_bls::{sign, PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
use chia_sdk_signer::{AggSigConstants, RequiredSignature};
use chia_sdk_utils::Address;
use chip35_dl_coin::master_to_wallet_unhardened;
use clvmr::Allocator;
use hex_literal::hex;
use zeroize::Zeroizing;

use super::WalletError;

/// The Chia **mainnet** `AGG_SIG_ME` additional data — the mainnet genesis challenge every standard
/// spend signature is bound to. A public Chia L1 network constant (not a secret, not DIG-specific):
/// a signature made against it is only valid on mainnet, which is the only network dig-app spends on.
pub const CHIA_MAINNET_AGG_SIG_DATA: Bytes32 = Bytes32::new(hex!(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
));

/// The unhardened wallet-child index the standard receive key derives at (Chia's canonical index 0).
const WALLET_CHILD_INDEX: u32 = 0;

/// The unlocked wallet key of one profile — the sole holder of the wallet's private BLS material
/// while the profile is unlocked. Built from the sealed seed on unlock and dropped (secrets
/// zeroized) on lock. Exposes public identifiers and a signing operation, but **never** the private
/// key itself.
pub struct WalletKey {
    /// The 32-byte seed, retained (zeroizing) so the wallet state can be re-sealed without a fresh
    /// unlock. It is the ONLY serialized form of the key and is always sealed before it touches disk.
    seed: Zeroizing<[u8; 32]>,
    /// The synthetic standard-layer secret key, held as its 32 raw bytes in a zeroizing buffer so the
    /// private material is scrubbed from memory on drop. `chia_bls::SecretKey` (0.26) implements no
    /// `Zeroize`/`Drop` scrub, so storing the live `SecretKey` would leave the key lingering in freed
    /// heap; we keep the bytes zeroizing and reconstruct the transient `SecretKey` only inside a
    /// signing operation ([`WalletKey::synthetic`]).
    synthetic_sk_bytes: Zeroizing<[u8; 32]>,
    /// The synthetic standard-layer public key — public material, cached for cheap address/lookup.
    synthetic_pk: PublicKey,
}

impl WalletKey {
    /// Derive the wallet key from its 32-byte `seed` (the canonical Chia wallet path).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        // `master` and `synthetic` are transient `chia_bls::SecretKey` locals; chia-bls 0.26 does not
        // scrub them on drop, so we immediately capture the synthetic key's bytes into a zeroizing
        // buffer (the persisted form) and let the locals fall out of scope. Scrubbing the transient
        // SecretKey locals would need a chia-bls Zeroize impl (upstream limitation, tracked follow-up).
        let master = SecretKey::from_seed(&*seed);
        let synthetic = master_to_wallet_unhardened(&master, WALLET_CHILD_INDEX).derive_synthetic();
        let synthetic_sk_bytes = Zeroizing::new(synthetic.to_bytes());
        let synthetic_pk = synthetic.public_key();
        Self {
            seed,
            synthetic_sk_bytes,
            synthetic_pk,
        }
    }

    /// Reconstruct the transient synthetic signing key from its zeroizing bytes, for the duration of
    /// one signing operation. Crate-internal; the key is never handed to a caller.
    fn synthetic(&self) -> SecretKey {
        SecretKey::from_bytes(&self.synthetic_sk_bytes)
            .expect("32 stored bytes are a valid SecretKey")
    }

    /// Generate a fresh wallet key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        Self::from_seed(seed)
    }

    /// The synthetic standard-layer **public** key — what curries the on-chain standard puzzle and
    /// what a [`chip35_dl_coin::build_dig_store_payment`] buyer key must be.
    pub fn public_key(&self) -> PublicKey {
        self.synthetic_pk
    }

    /// The wallet's standard p2 puzzle hash (the on-chain home of its coins).
    pub fn puzzle_hash(&self) -> Bytes32 {
        StandardArgs::curry_tree_hash(self.public_key()).into()
    }

    /// The wallet's canonical XCH receive address (`xch1…` bech32m of the puzzle hash).
    pub fn address(&self) -> Result<String, WalletError> {
        Address::new(self.puzzle_hash(), "xch".to_string())
            .encode()
            .map_err(|e| WalletError::Address(e.to_string()))
    }

    /// The seed, for sealing at rest ONLY. Crate-internal so no public caller can extract the key;
    /// the returned buffer zeroizes on drop.
    pub(crate) fn sealed_seed(&self) -> Zeroizing<[u8; 32]> {
        self.seed.clone()
    }

    /// Sign `coin_spends` locally and return the finished [`SpendBundle`] ready for the engine to
    /// broadcast. Every required standard-puzzle signature is matched to the wallet's synthetic key,
    /// signed, and aggregated; a required signature for a key this wallet does not hold is skipped —
    /// the resulting bundle is then incomplete and the network rejects it (fail-closed, never a
    /// silent forge).
    pub fn sign_bundle(&self, coin_spends: Vec<CoinSpend>) -> Result<SpendBundle, WalletError> {
        let signature = self.sign(&coin_spends)?;
        Ok(SpendBundle::new(coin_spends, signature))
    }

    /// Produce the aggregated BLS signature for `coin_spends` against the Chia mainnet AGG_SIG
    /// constants. The private key never leaves this method.
    ///
    /// # Custody: refuse (fail-closed) any non-coin-bound signature
    ///
    /// The wallet signs a required signature **only** when it is coin- and network-bound — i.e. its
    /// `domain_string` is `Some` (an `AGG_SIG_ME`/parent/puzzle/amount/… whose message carries the
    /// coin identity plus the mainnet genesis domain). It **rejects the whole bundle** the moment it
    /// sees an `AGG_SIG_UNSAFE` required signature (`domain_string == None` && empty `appended_info`),
    /// whose message is the raw, caller-supplied bytes with no coin or network binding. Signing an
    /// unsafe condition would make the wallet a **signing oracle**: a caller could feed a fabricated
    /// spend `(q . ((49 <wallet_pk> <arbitrary M>)))` and extract a valid BLS signature by the user's
    /// key over ANY message `M`, reusable in any `AGG_SIG_UNSAFE(wallet_pk, M)` context, cross-coin
    /// and cross-network. Failing CLOSED (rather than silently skipping the unsafe entry and signing
    /// the rest) both surfaces the attack and guarantees no partially-signed bundle escapes. Because
    /// `sign_bundle` is the public seam the `control.wallet.*` / dapp-signing path wires into, this is
    /// the one place every signature funnels through.
    fn sign(&self, coin_spends: &[CoinSpend]) -> Result<Signature, WalletError> {
        let mut allocator = Allocator::new();
        let constants = AggSigConstants::new(CHIA_MAINNET_AGG_SIG_DATA);
        let required = RequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)
            .map_err(|e| WalletError::Sign(format!("required-signature extraction: {e:?}")))?;

        let synthetic_pk = self.public_key();
        let synthetic_sk = self.synthetic();
        let mut aggregate = Signature::default();
        for req in required {
            let RequiredSignature::Bls(bls) = req else {
                continue;
            };
            // Fail CLOSED on AGG_SIG_UNSAFE (no coin/network binding) — see the custody note above.
            if bls.domain_string.is_none() && bls.appended_info.is_empty() {
                return Err(WalletError::Sign(
                    "refusing to sign a non-coin-bound AGG_SIG_UNSAFE message (signing-oracle guard)"
                        .to_string(),
                ));
            }
            if bls.public_key == synthetic_pk {
                aggregate += &sign(&synthetic_sk, bls.message());
            }
        }
        Ok(aggregate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Bytes, Coin, CoinSpend};
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_types::conditions::{AggSig, AggSigKind};
    use chia_sdk_types::Conditions;

    /// A deterministic wallet key for reproducible assertions.
    fn wallet(seed: u8) -> WalletKey {
        WalletKey::from_seed([seed; 32])
    }

    /// A real standard-layer coin spend of a coin `key` owns. The standard puzzle always emits an
    /// `AGG_SIG_ME` for the synthetic key, so the signer can execute it and extract exactly the
    /// signature this wallet must produce — unlike a fabricated CAT, whose puzzle needs a real
    /// on-chain lineage to run.
    fn standard_spend(key: &WalletKey) -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        let coin = Coin {
            parent_coin_info: Bytes32::new([1u8; 32]),
            puzzle_hash: key.puzzle_hash(),
            amount: 1_000,
        };
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, Conditions::new())
            .expect("a standard-layer spend of an owned coin");
        ctx.take()
    }

    #[test]
    fn the_mainnet_agg_sig_constant_is_32_bytes() {
        assert_eq!(CHIA_MAINNET_AGG_SIG_DATA.to_bytes().len(), 32);
    }

    #[test]
    fn a_seed_deterministically_derives_the_same_key() {
        assert_eq!(wallet(7).public_key(), wallet(7).public_key());
        assert_eq!(wallet(7).puzzle_hash(), wallet(7).puzzle_hash());
    }

    #[test]
    fn distinct_seeds_derive_distinct_keys() {
        assert_ne!(wallet(1).public_key(), wallet(2).public_key());
    }

    #[test]
    fn generated_keys_are_random() {
        assert_ne!(
            WalletKey::generate().public_key(),
            WalletKey::generate().public_key()
        );
    }

    #[test]
    fn the_derivation_matches_the_canonical_public_only_path() {
        // The public-only wallet path (what a watch-only caller derives from the master public key)
        // must equal our secret-derived public key — proving `sign_bundle` signs for the exact key
        // that owns the wallet's coins.
        let key = wallet(3);
        let master = SecretKey::from_seed(&[3u8; 32]);
        let public_path = master_to_wallet_unhardened(&master.public_key(), WALLET_CHILD_INDEX)
            .derive_synthetic();
        assert_eq!(key.public_key(), public_path);
    }

    #[test]
    fn the_address_is_a_bech32m_xch_string() {
        let address = wallet(4).address().unwrap();
        assert!(address.starts_with("xch1"), "got {address}");
    }

    #[test]
    fn signing_no_spends_yields_the_identity_signature() {
        // No required signatures ⇒ the aggregate is the default (empty) signature — a well-defined,
        // safe base case, never an error.
        let bundle = wallet(5).sign_bundle(vec![]).unwrap();
        assert!(bundle.coin_spends.is_empty());
        assert_eq!(bundle.aggregated_signature, Signature::default());
    }

    #[test]
    fn signing_a_standard_spend_produces_a_real_local_signature() {
        // The custody-critical positive path: the wallet signs a spend of its own coin locally and
        // the finished bundle carries a real (non-empty) aggregated signature — no key exposed.
        let key = wallet(8);
        let spends = standard_spend(&key);
        let bundle = key.sign_bundle(spends.clone()).unwrap();

        assert_eq!(
            bundle.coin_spends, spends,
            "the spends are preserved verbatim"
        );
        assert_ne!(
            bundle.aggregated_signature,
            Signature::default(),
            "a real spend must produce a real signature"
        );
    }

    /// A fabricated coin spend whose puzzle unconditionally emits `AGG_SIG_UNSAFE(pk, message)` —
    /// the signing-oracle attack input. The "identity" puzzle (CLVM `1`, which returns its solution)
    /// outputs the condition list carried in the solution, so `from_coin_spends` extracts exactly one
    /// raw, non-coin-bound required signature for `pk` over `message`.
    fn agg_sig_unsafe_spend(pk: PublicKey, message: &[u8]) -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        let identity_puzzle = ctx.alloc(&1).expect("alloc identity puzzle");
        let conditions = vec![AggSig::new(
            AggSigKind::Unsafe,
            pk,
            Bytes::from(message.to_vec()),
        )];
        let solution = ctx.alloc(&conditions).expect("alloc unsafe condition");
        let puzzle_reveal = ctx.serialize(&identity_puzzle).expect("serialize puzzle");
        let solution = ctx.serialize(&solution).expect("serialize solution");
        let coin = Coin {
            parent_coin_info: Bytes32::new([2u8; 32]),
            puzzle_hash: Bytes32::new([3u8; 32]),
            amount: 1,
        };
        vec![CoinSpend::new(coin, puzzle_reveal, solution)]
    }

    #[test]
    fn an_agg_sig_unsafe_spend_is_refused_closing_the_signing_oracle() {
        // The custody regression (adversarial gate): a caller-fabricated AGG_SIG_UNSAFE over
        // attacker-chosen bytes, addressed to the wallet's own key, MUST fail CLOSED — the wallet
        // errors on the whole bundle rather than emitting any signature over uncontrolled bytes.
        let key = wallet(11);
        let spends = agg_sig_unsafe_spend(key.public_key(), b"transfer all funds to mallory");
        assert!(
            matches!(key.sign_bundle(spends), Err(WalletError::Sign(_))),
            "the wallet must reject an AGG_SIG_UNSAFE bundle (signing-oracle guard)"
        );
    }

    #[test]
    fn a_foreign_wallet_cannot_sign_anothers_spend() {
        // Signing another key's spend yields the identity signature (no required sig matches this
        // wallet's key) — the bundle is then incomplete and the network rejects it (fail-closed).
        let owner = wallet(9);
        let stranger = wallet(10);
        let spends = standard_spend(&owner);
        let bundle = stranger.sign_bundle(spends).unwrap();
        assert_eq!(bundle.aggregated_signature, Signature::default());
    }
}
