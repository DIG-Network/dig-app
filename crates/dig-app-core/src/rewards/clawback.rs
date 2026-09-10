//! The clawback authority gate (dig_ecosystem#3281): a [`ClawbackAuthority`] witness constructible
//! only from a wallet-key-derived [`ViewerPuzzleHash`] that is byte-equal to a commitment's
//! `clawback_puzzle_hash`, and the SOLE producer of the four finished `rewards-clawback-*`
//! sentences.
//!
//! # The defect class this closes
//!
//! [`super::pane::WarningsShown`] (`pane.rs:646-682`) is proven by comparing `REQUIRED_WARNING_KEYS`
//! (`pub`) against a caller-supplied list -- the caller supplies BOTH sides of that equality, so the
//! witness proves only that the caller named the right keys, never that anything was actually
//! painted; its own doc comment had to retract a stronger claim in the same file. That shape is out
//! of scope here and its warning strings ship unchanged, but the same mistake over
//! `clawback_puzzle_hash` would be worse: a per-user custody boundary, not a UI paint-order
//! convention. A `prove(viewer_ph: [u8; 32], commitment_ph: [u8; 32])` signature is forged in one
//! line -- `prove(c.clawback_puzzle_hash, c.clawback_puzzle_hash)` -- because the caller can name
//! both compared values.
//!
//! [`ClawbackAuthority::prove`] closes it by taking the CAPABILITY ([`ViewerPuzzleHash`],
//! constructible only from a real wallet key this process holds) and reading the OTHER side of the
//! comparison out of the record itself. A caller can supply neither compared value directly -- only
//! the wallet key `viewer` was derived from, and the commitment `prove` reads
//! `clawback_puzzle_hash` out of.
//!
//! # What this does NOT prove
//!
//! [`ViewerPuzzleHash::from_wallet_key`] derives at [`dig_account::ProfileIx::ROOT`] only.
//! `wallet/state.rs:262-270`'s `derivation_index_of` returns `Option<u32>` where `None` means
//! *unknown*, never index zero -- a range scan here would have to invent the bound that type
//! deliberately refuses to state, and the false-positive surface (a stranger's slot read as this
//! viewer's) would grow with the scan width. A profile spending from a non-root wallet index sees
//! every commitment as a stranger's; that is a real coverage gap, not a forgeable one.
//!
//! And `copy::CLAWBACK_*` dropping to `pub(super)` narrows reach to the `rewards` module, not to
//! this file alone: `pane.rs`, `reading.rs`, `cadence.rs`, `client.rs` and `tab_placement.rs` sit in
//! the SAME module and could still name a clawback key or fluent id. That last hop is covered by
//! [`tests::no_module_outside_clawback_names_a_clawback_key`], a source scan, NOT the compiler --
//! writing "unreachable outside the gate" here would be exactly the retraction `pane.rs:646-658`
//! already had to publish once.

use chia_protocol::Bytes32;
use dig_account::WalletKey;

use crate::amount::{amount_with_unit, short_asset_id_str};
use crate::i18n::Args;
use crate::wallet::state::Asset;

use super::copy;
use super::wire::RewardDistributorCommitment;

/// A wallet's own standard puzzle hash, derived ONLY from a real wallet-spending key.
///
/// # Why there is no `from_bytes`
///
/// The entire point of this type is that a caller cannot mint one from an arbitrary 32 bytes -- if
/// it could, [`ClawbackAuthority::prove`] would reduce to comparing two caller-supplied values,
/// exactly the forge the module doc above describes. The only legal input is a [`WalletKey`] this
/// process actually holds and controls; a second member (a non-root index) is added later by
/// extending this constructor, never by adding a `from_bytes`.
#[derive(Debug)]
pub struct ViewerPuzzleHash(Bytes32);

impl ViewerPuzzleHash {
    /// The ONLY constructor. `key.puzzle_hash()` already curries `StandardArgs` over the
    /// `master_to_wallet_unhardened(master, ProfileIx::ROOT).derive_synthetic()` public key --
    /// `dig-account`'s own derivation, byte-identical to the longhand
    /// `account/residency.rs:970-983` re-derives independently for its own test, and reused here
    /// rather than re-derived (proven equal, not merely assumed, by
    /// [`tests::from_wallet_key_matches_the_independently_derived_curry_tree_hash`]). ROOT index
    /// only -- see the module doc.
    pub fn from_wallet_key(key: &WalletKey) -> Self {
        ViewerPuzzleHash(key.puzzle_hash())
    }
}

/// Proof that the viewer who produced a [`ViewerPuzzleHash`] controls a commitment's
/// `clawback_puzzle_hash`. See the module doc for the defect class this closes.
///
/// # Why not `Copy`/`Clone`/`Default`
///
/// A copyable witness could be spent against two different commitments' worth of confirm text
/// without a second [`Self::prove`] -- [`ProvenClawback::open`] consumes this type by value for
/// exactly that reason: one proof, one confirm window.
///
/// # Two compile-time properties a comment cannot hold
///
/// `CLAWBACK_CONFIRM_BODY` is `pub(super)` inside `rewards` -- unreachable from outside the crate,
/// where this doctest runs:
///
/// ```compile_fail
/// let _ = dig_app_core::rewards::copy::CLAWBACK_CONFIRM_BODY;
/// ```
///
/// A consumed witness cannot be reused -- `authority` is moved into the first [`ProvenClawback::open`]
/// call, so a second call with the same binding does not compile:
///
/// ```compile_fail
/// # fn fixture() -> (dig_app_core::rewards::clawback::ClawbackAuthority,
/// #                  dig_app_core::rewards::wire::RewardDistributorCommitment) {
/// #     todo!()
/// # }
/// use dig_app_core::rewards::clawback::ProvenClawback;
///
/// let (authority, commitment) = fixture();
/// let _first = ProvenClawback::open(authority, &commitment);
/// let _second = ProvenClawback::open(authority, &commitment); // moved -- does not compile
/// ```
#[derive(Debug)]
pub struct ClawbackAuthority {
    /// The matched hash, carried so [`ProvenClawback::open`] can render it without reading the
    /// commitment's own `clawback_puzzle_hash` a second time -- see the module doc's
    /// `clawback_ph_short` rule.
    matched: Bytes32,
}

impl ClawbackAuthority {
    /// The ONLY constructor. Takes the CAPABILITY (`viewer`) and reads the comparand out of
    /// `commitment` itself -- see the module doc for the one-line forge this shape closes. `None`
    /// when the two hashes differ by even one bit: this is a per-user custody boundary, not a
    /// display convenience, so there is no partial or "close enough" match.
    pub fn prove(
        viewer: &ViewerPuzzleHash,
        commitment: &RewardDistributorCommitment,
    ) -> Option<Self> {
        let commitment_ph = Bytes32::new(commitment.clawback_puzzle_hash);
        (viewer.0 == commitment_ph).then_some(ClawbackAuthority { matched: viewer.0 })
    }
}

/// The four already-formatted `rewards-clawback-*` sentences, produced ONLY by [`Self::open`] from
/// a consumed [`ClawbackAuthority`]. `Clone` is fine here -- this is finished, post-proof text, not
/// a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenClawback {
    /// [`copy::CLAWBACK_CONFIRM_TITLE`], rendered.
    pub confirm_title: String,
    /// [`copy::CLAWBACK_CONFIRM_BODY`], rendered.
    pub confirm_body: String,
    /// [`copy::CLAWBACK_WITHDRAW_BUTTON`], rendered.
    pub withdraw_button: String,
    /// [`copy::CLAWBACK_KEEP_BUTTON`], rendered.
    pub keep_button: String,
}

impl ProvenClawback {
    /// Consumes `authority` BY VALUE -- one proof, one confirm window, four strings; a second
    /// confirm window needs a second [`ClawbackAuthority::prove`].
    ///
    /// `None` when `commitment.rewards_base_units` is less than its `recoverable_base_units`: an
    /// underflow means the record is internally inconsistent, and the WHOLE window is refused
    /// rather than shown with a stand-in zero forfeited figure (the #402 wrapper trap reappearing
    /// under a different name).
    pub fn open(
        authority: ClawbackAuthority,
        commitment: &RewardDistributorCommitment,
    ) -> Option<Self> {
        let forfeited_base_units = commitment
            .rewards_base_units
            .checked_sub(commitment.recoverable_base_units)?;

        // The witness's OWN field, never `commitment.clawback_puzzle_hash` -- see the module doc.
        // Post-proof the two are equal, so this is not about today's value; it is about the
        // direction a later loosening of `prove`'s equality drifts. Reading the record here would
        // silently start printing a stranger's hash while this doc comment kept claiming otherwise.
        let clawback_ph_short = short_asset_id_str(&authority.matched.to_string());

        // dig-app-core has no date-formatting helper yet (`copy.rs`'s own `ENTRY_SET_KNOWN` doc
        // names the same caveat), and the four-field wire commitment carries no per-slot ordinal --
        // only the raw Unix `epoch_start`. Rendered as-is for both `epoch_index` and
        // `epoch_start_date` until a real ordinal/date formatter lands; a known display gap, not a
        // security one -- the security-relevant field is `clawback_ph_short` above.
        let epoch = commitment.epoch_start.to_string();

        let slot_amount = amount_with_unit(Asset::DIG, commitment.rewards_base_units);
        let returned_amount = amount_with_unit(Asset::DIG, commitment.recoverable_base_units);
        let forfeited_amount = amount_with_unit(Asset::DIG, forfeited_base_units);

        let confirm_title =
            copy::CLAWBACK_CONFIRM_TITLE.with(&Args::new().text("epoch_index", epoch.clone()));
        let confirm_body = copy::CLAWBACK_CONFIRM_BODY.with(
            &Args::new()
                .text("slot_amount", slot_amount)
                .text("epoch_index", epoch.clone())
                .text("epoch_start_date", epoch)
                .text("returned_amount", returned_amount.clone())
                .text("forfeited_amount", forfeited_amount)
                .text("clawback_ph_short", clawback_ph_short),
        );
        let withdraw_button = copy::CLAWBACK_WITHDRAW_BUTTON
            .with(&Args::new().text("returned_amount", returned_amount));
        let keep_button = copy::CLAWBACK_KEEP_BUTTON.text();

        Some(ProvenClawback {
            confirm_title,
            confirm_body,
            withdraw_button,
            keep_button,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::test_scan::string_literals;

    /// A fixed, arbitrary 32-byte BIP-39 entropy -- distinct from dig-account's own golden-vector
    /// seed (`0x42` repeated) so this test module is not silently re-deriving that pinned value.
    /// Expanded through a real mnemonic, never fed to `WalletKey::from_seed` raw, so the fixture
    /// starts from a state production actually reaches (a recovery phrase), per the module doc's
    /// "no `from_bytes`, no forge fixture" rule.
    const ENTROPY: [u8; 32] = [0x7c; 32];

    fn test_wallet_key() -> WalletKey {
        let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &ENTROPY)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("");
        WalletKey::from_seed(&expanded)
    }

    /// The same longhand `account/residency.rs:970-983` uses, stopped one step short of the
    /// bech32m address: BIP-39-expand -> `master_to_wallet_unhardened(master, ROOT).derive_synthetic()`
    /// -> `StandardArgs::curry_tree_hash`. A SECOND implementation, so the provenance test below is
    /// not the code under test agreeing with itself.
    fn independently_derived_root_puzzle_hash() -> Bytes32 {
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
        use dig_account::ProfileIx;

        let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &ENTROPY)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("");
        let master = SecretKey::from_seed(&expanded);
        let synthetic = master_to_wallet_unhardened(&master, ProfileIx::ROOT.0).derive_synthetic();
        StandardArgs::curry_tree_hash(synthetic.public_key()).into()
    }

    fn commitment_with_clawback_ph(clawback_puzzle_hash: [u8; 32]) -> RewardDistributorCommitment {
        RewardDistributorCommitment {
            epoch_start: 1_767_225_600,
            clawback_puzzle_hash,
            rewards_base_units: 10_000,
            recoverable_base_units: 9_000,
        }
    }

    /// Step 6 -- ACCEPTANCE 1: no sibling module in `rewards` may name a clawback fluent key or
    /// constant. Reuses [`string_literals`] (moved to `test_scan` so more than one test module can
    /// share it, per the plan's "reuse it, do not write a second") rather than a second extractor.
    #[test]
    fn no_module_outside_clawback_names_a_clawback_key() {
        let forbidden_keys = [
            "rewards-clawback-confirm-title",
            "rewards-clawback-confirm-body",
            "rewards-clawback-withdraw-button",
            "rewards-clawback-keep-button",
        ];
        let forbidden_consts = [
            "CLAWBACK_CONFIRM_TITLE",
            "CLAWBACK_CONFIRM_BODY",
            "CLAWBACK_WITHDRAW_BUTTON",
            "CLAWBACK_KEEP_BUTTON",
        ];
        let siblings: [(&str, &str); 5] = [
            ("pane.rs", include_str!("pane.rs")),
            ("reading.rs", include_str!("reading.rs")),
            ("cadence.rs", include_str!("cadence.rs")),
            ("client.rs", include_str!("client.rs")),
            ("tab_placement.rs", include_str!("tab_placement.rs")),
        ];
        for (name, src) in siblings {
            for literal in string_literals(src) {
                for key in forbidden_keys {
                    assert_ne!(literal, key, "{name} names clawback key {key:?}");
                }
            }
            for constant in forbidden_consts {
                assert!(
                    !src.contains(constant),
                    "{name} names clawback constant {constant}"
                );
            }
        }
    }

    /// A sibling module that DOES name a clawback key must trip the guard above -- proves the scan
    /// is not vacuously passing over its own fixture text.
    #[test]
    fn the_guard_itself_trips_on_a_planted_key() {
        let planted = "let _bad = \"rewards-clawback-confirm-title\";";
        assert!(string_literals(planted).contains(&"rewards-clawback-confirm-title".to_string()));
    }

    /// Step 8 -- provenance: [`ViewerPuzzleHash::from_wallet_key`] equals the longhand computed
    /// independently in this test module.
    #[test]
    fn from_wallet_key_matches_the_independently_derived_curry_tree_hash() {
        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        assert_eq!(viewer.0, independently_derived_root_puzzle_hash());
    }

    /// Step 9 -- a one-bit-flipped hash (not a random one) proves nothing.
    #[test]
    fn a_one_bit_flipped_commitment_hash_proves_nothing() {
        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        let mut flipped = viewer.0.to_bytes();
        flipped[0] ^= 0b0000_0001;
        let commitment = commitment_with_clawback_ph(flipped);
        assert!(ClawbackAuthority::prove(&viewer, &commitment).is_none());
    }

    /// Step 10 -- ACCEPTANCE 3, THE NON-VACUOUS SUBJECT TEST. Delete the `==` in
    /// `ClawbackAuthority::prove` and this test MUST go red (verified by hand per the RETURN
    /// section; not automatable from inside the suite it would falsify).
    #[test]
    fn rendered_body_names_the_viewers_own_hash_and_a_strangers_commitment_renders_nothing() {
        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        let own_hash = independently_derived_root_puzzle_hash();
        let own_commitment = commitment_with_clawback_ph(own_hash.to_bytes());

        // (a) the viewer's own hash: proves, opens, and the body names the INDEPENDENTLY derived
        // short hash -- never a hash borrowed back from the type under test.
        let authority = ClawbackAuthority::prove(&viewer, &own_commitment)
            .expect("viewer controls this commitment's clawback_puzzle_hash");
        let proven = ProvenClawback::open(authority, &own_commitment)
            .expect("rewards_base_units >= recoverable_base_units in this fixture");
        let expected_short = short_asset_id_str(&own_hash.to_string());
        assert!(
            proven.confirm_body.contains(&expected_short),
            "confirm body {:?} does not name the viewer's own hash {expected_short:?}",
            proven.confirm_body
        );
        // (c) asserted on an owned `String` field of `proven`, never a `&str` borrowed from a
        // dropped local (dig_ecosystem#3253 finding 2's undefined-behaviour shape).
        assert!(!proven.confirm_title.is_empty());
        assert!(!proven.withdraw_button.is_empty());
        assert!(!proven.keep_button.is_empty());

        // (b) a stranger's commitment (one bit flipped): `prove` is `None`, and -- structurally,
        // not just in this assertion -- no `ProvenClawback` can exist without a `ClawbackAuthority`
        // to consume, so no string is produced at all.
        let mut strangers_ph = own_hash.to_bytes();
        strangers_ph[0] ^= 0b0000_0001;
        let strangers_commitment = commitment_with_clawback_ph(strangers_ph);
        assert!(ClawbackAuthority::prove(&viewer, &strangers_commitment).is_none());
    }

    /// [`ProvenClawback::open`] refuses the whole window on an internally inconsistent commitment
    /// rather than showing a stand-in zero forfeited figure.
    #[test]
    fn checked_sub_underflow_refuses_the_whole_window() {
        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        let own_hash = independently_derived_root_puzzle_hash();
        let inconsistent = RewardDistributorCommitment {
            epoch_start: 1_767_225_600,
            clawback_puzzle_hash: own_hash.to_bytes(),
            rewards_base_units: 100,
            recoverable_base_units: 101, // more recoverable than was ever committed
        };
        let authority = ClawbackAuthority::prove(&viewer, &inconsistent).unwrap();
        assert!(ProvenClawback::open(authority, &inconsistent).is_none());
    }
}
