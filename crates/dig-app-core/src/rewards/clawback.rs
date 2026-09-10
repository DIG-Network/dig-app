//! The clawback authority gate (dig_ecosystem#3281): a [`ClawbackAuthority`] witness constructible
//! only from a wallet-key-derived [`ViewerPuzzleHash`] that is byte-equal to a commitment's
//! `clawback_puzzle_hash`, and the only producer of a [`ProvenClawback`] -- the only value in this
//! crate that carries the four finished `rewards-clawback-*` sentences bound to a commitment's
//! real amounts and hash.
//!
//! That is narrower than "the sole producer of those sentences", and the difference matters.
//! [`crate::i18n::Msg::new`] is a public `const fn` and the fluent key is a plain `&'static str`
//! literal (`copy::ALL_KEYS`, the one place that used to re-export it by value, is now private --
//! dig_ecosystem#3281 S2), so any crate that writes the literal key still renders the same
//! 14-locale sentence with any amounts and any hash it likes. What this module holds is that no
//! code outside it can produce or mutate a [`ProvenClawback`], and that a [`ProvenClawback`]'s
//! text is always bound to a commitment whose `clawback_puzzle_hash` a wallet key this process
//! holds actually controls. Reach-narrowing, not unreachability -- see "What this does NOT prove"
//! below.
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
//! `tests::no_module_outside_clawback_names_a_clawback_key`, a source scan, NOT the compiler --
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
    /// `tests::from_wallet_key_matches_the_independently_derived_curry_tree_hash`). ROOT index
    /// only -- see the module doc.
    pub fn from_wallet_key(key: &WalletKey) -> Self {
        ViewerPuzzleHash(key.puzzle_hash())
    }
}

/// Proof that the viewer who produced a [`ViewerPuzzleHash`] controls a commitment's
/// `clawback_puzzle_hash`. See the module doc for the defect class this closes.
///
/// # Why the proved commitment travels INSIDE the witness
///
/// An earlier revision carried only `matched` and let [`ProvenClawback::open`] take a SECOND,
/// independent commitment, which it never re-checked. That made
/// `open(prove(&viewer, &mine).unwrap(), &strangers_slot)` render a stranger's amounts under
/// en.ftl's "You committed ..." and "... returns to this wallet" -- beside the viewer's own
/// genuine hash, which made the forgery more convincing rather than less (dig_ecosystem#3281
/// security gate, S1). It is the predecessor PR's subject defect: correctly typed, correctly
/// formatted, and false about whose money it is.
///
/// The fix is not a re-check inside `open` -- a re-check leaves the splice expressible and relies
/// on a future maintainer remembering it. The witness carries the commitment it was proved against
/// by value, and `open` takes exactly one argument, so there is no second commitment to pass and
/// the splice is unrepresentable. Same principle as [`Self::prove`] taking the capability instead
/// of a compared value.
///
/// # Why not `Copy`/`Clone`/`Default`
///
/// A copyable witness could be spent for two confirm windows' worth of text from one
/// [`Self::prove`] -- [`ProvenClawback::open`] consumes this type by value for exactly that
/// reason: one proof, one confirm window. Note this is a REPLAY property only; it never protected
/// the subject, which is what carrying the commitment above does.
///
/// # Three compile-time properties a comment cannot hold
///
/// [`ProvenClawback::open`] takes EXACTLY ONE argument, so passing a second, independent
/// commitment -- the S1 splice, `open(prove(&viewer, &mine).unwrap(), &strangers_slot)` -- is not
/// merely re-checked away, it is a wrong-number-of-arguments error (`E0061`) and does not compile:
///
/// ```compile_fail,E0061
/// # fn fixture() -> dig_app_core::rewards::clawback::ClawbackAuthority {
/// #     todo!()
/// # }
/// # fn strangers_commitment() -> dig_app_core::rewards::wire::RewardDistributorCommitment {
/// #     todo!()
/// # }
/// use dig_app_core::rewards::clawback::ProvenClawback;
///
/// let authority = fixture();
/// let _ = ProvenClawback::open(authority, &strangers_commitment()); // too many args -- does not compile
/// ```
///
/// `CLAWBACK_CONFIRM_BODY`'s PATH is `pub(super)` inside `rewards`, so naming the constant from
/// outside the crate -- where this doctest runs -- is a private-path error (`E0603`), asserted by
/// the error code rather than by "it failed to build somehow". That narrows REACH to the `rewards`
/// module; it does not make the sentence unrenderable, because the fluent key is a `&'static str`
/// any crate can hand to the public [`crate::i18n::Msg::new`]:
///
/// ```compile_fail,E0603
/// let _ = dig_app_core::rewards::copy::CLAWBACK_CONFIRM_BODY;
/// ```
///
/// A consumed witness cannot be reused -- `authority` is moved into the first [`ProvenClawback::open`]
/// call, so a second call with the same binding is a use-of-moved-value error (`E0382`):
///
/// ```compile_fail,E0382
/// # fn fixture() -> dig_app_core::rewards::clawback::ClawbackAuthority {
/// #     todo!()
/// # }
/// use dig_app_core::rewards::clawback::ProvenClawback;
///
/// let authority = fixture();
/// let _first = ProvenClawback::open(authority);
/// let _second = ProvenClawback::open(authority); // moved -- does not compile
/// ```
#[derive(Debug)]
pub struct ClawbackAuthority {
    /// The matched hash, carried so [`ProvenClawback::open`] can render it without reading the
    /// commitment's own `clawback_puzzle_hash` a second time -- see the module doc's
    /// `clawback_ph_short` rule.
    matched: Bytes32,
    /// The commitment `matched` was proved against, by value -- the ONLY record
    /// [`ProvenClawback::open`] may read a figure from. See "Why the proved commitment travels
    /// INSIDE the witness" above.
    commitment: RewardDistributorCommitment,
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
        (viewer.0 == commitment_ph).then_some(ClawbackAuthority {
            matched: viewer.0,
            commitment: *commitment,
        })
    }
}

/// The four already-formatted `rewards-clawback-*` sentences, produced ONLY by [`Self::open`] from
/// a consumed [`ClawbackAuthority`].
///
/// # Fields are PRIVATE, not `pub`
///
/// An earlier revision left these four fields `pub`, so a struct literal built anywhere in the
/// crate -- with no [`ClawbackAuthority`] involved at all -- produced a value indistinguishable
/// from one this module actually proved, and a legitimately obtained one was mutable in place
/// (overwrite `withdraw_button` after the honest "returns to this wallet" body was rendered
/// beside it). `#[non_exhaustive]` would not have closed this: it blocks a struct literal from a
/// foreign crate but leaves every field publicly writable to anyone who already has a value, which
/// is the exact mutation this doc used to (wrongly) claim was impossible. Private fields plus the
/// accessors below are the only shape that makes both "constructed only by `open`" and "not
/// mutable after" true at once.
///
/// `Clone`/`PartialEq`/`Eq` stay: this is finished, post-proof text, not a capability, so copying
/// or comparing it carries no custody meaning -- unlike [`ClawbackAuthority`], which is
/// deliberately not `Clone` (see its own doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenClawback {
    /// `copy::CLAWBACK_CONFIRM_TITLE` (`pub(super)`), rendered.
    confirm_title: String,
    /// `copy::CLAWBACK_CONFIRM_BODY` (`pub(super)`), rendered.
    confirm_body: String,
    /// `copy::CLAWBACK_WITHDRAW_BUTTON` (`pub(super)`), rendered.
    withdraw_button: String,
    /// `copy::CLAWBACK_KEEP_BUTTON` (`pub(super)`), rendered.
    keep_button: String,
}

impl ProvenClawback {
    /// The rendered `rewards-clawback-confirm-title` sentence.
    pub fn confirm_title(&self) -> &str {
        &self.confirm_title
    }

    /// The rendered `rewards-clawback-confirm-body` sentence -- the one that names amounts and the
    /// viewer's own hash; see the module doc's S1 fix for why it can only ever name the commitment
    /// [`ClawbackAuthority::prove`] matched.
    pub fn confirm_body(&self) -> &str {
        &self.confirm_body
    }

    /// The rendered `rewards-clawback-withdraw-button` sentence.
    pub fn withdraw_button(&self) -> &str {
        &self.withdraw_button
    }

    /// The rendered `rewards-clawback-keep-button` sentence.
    pub fn keep_button(&self) -> &str {
        &self.keep_button
    }

    /// Consumes `authority` BY VALUE -- one proof, one confirm window, four strings; a second
    /// confirm window needs a second [`ClawbackAuthority::prove`].
    ///
    /// `None` when the held commitment's `rewards_base_units` is less than its
    /// `recoverable_base_units`: an underflow means the record is internally inconsistent, and the
    /// WHOLE window is refused rather than shown with a stand-in zero forfeited figure (the #402
    /// wrapper trap reappearing under a different name).
    ///
    /// Takes EXACTLY ONE argument -- see "Why the proved commitment travels INSIDE the witness"
    /// above. There is no second `commitment` parameter to pass a stranger's record through, so
    /// S1's splice (`open(prove(&viewer, &mine).unwrap(), &strangers_slot)`) is not merely
    /// re-checked, it is unrepresentable: every figure below is read from `authority.commitment`,
    /// the same record `prove` matched `authority.matched` against.
    pub fn open(authority: ClawbackAuthority) -> Option<Self> {
        let commitment = &authority.commitment;
        let forfeited_base_units = commitment
            .rewards_base_units
            .checked_sub(commitment.recoverable_base_units)?;

        // The witness's OWN field, never a second, independently-supplied commitment -- see the
        // module doc and this method's doc above. Post-proof the two are equal by construction
        // (there is no other `commitment` in scope to diverge from), so this is not a defensive
        // re-check; it is the only record this method can read from at all.
        let clawback_ph_short = short_asset_id_str(&authority.matched.to_string());

        // dig-app-core has no date-formatting helper yet (`copy.rs`'s own `ENTRY_SET_KNOWN` doc
        // names the same caveat), and the four-field wire commitment carries no per-slot ordinal --
        // only the raw Unix `epoch_start`. Rendered as-is for both `epoch_index` and
        // `epoch_start_date` until a real ordinal/date formatter lands (dig_ecosystem#3281 F3).
        // This is NOT merely a display gap: `epoch_index` is the only identifier in this sentence
        // naming WHICH commitment is being withdrawn, and this raw timestamp is not it. Until the
        // wire carries a real per-slot ordinal, the value rendered here is not a trustworthy epoch
        // identifier and no future renderer should treat it as one, or key logic off it, the same
        // way the `checked_sub` refusal two lines above treats an inconsistent commitment as
        // unshowable rather than "close enough". The wire field this needs does not exist yet
        // (four fields: `epoch_start`, `clawback_puzzle_hash`, `rewards_base_units`,
        // `recoverable_base_units`) -- adding one, or deriving an index from a compiled-in epoch
        // length, is the shape SPEC §2.6 clause 2 already rejected once; this stays a known-false
        // display until the wire changes, tracked as a follow-up ticket rather than fixed here.
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
    ///
    /// ENUMERATES `src/rewards/` at test time (`std::fs::read_dir`, not a hardcoded file list) so
    /// a tenth file added to this directory is covered automatically rather than silently
    /// outside the scan -- dig_ecosystem#3281 F2 found the previous hardcoded five-file list had
    /// already drifted behind `mod.rs`, `wire.rs` and `test_scan.rs` (`mod.rs` is the material
    /// gap: a `pub use` there widens reach past both this scan and the compiler). Only two `.rs`
    /// files are deliberately excluded, both self-evidently: `clawback.rs` (this file -- the gate
    /// itself legitimately names every key and constant in its own doc comments) and `copy.rs`
    /// (the module that OWNS and defines every `CLAWBACK_*` constant and fluent key -- the thing
    /// this scan exists to keep OTHER modules from naming). `the_guard_itself_trips_on_a_planted_key`
    /// below keeps this non-vacuous.
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
        const EXCLUDED: &[&str] = &["clawback.rs", "copy.rs"];

        let rewards_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rewards");
        let entries = std::fs::read_dir(&rewards_dir)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", rewards_dir.display()));

        let mut scanned = Vec::new();
        for entry in entries {
            let path = entry.expect("directory entry readable").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 file name")
                .to_string();
            if EXCLUDED.contains(&name.as_str()) {
                continue;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));

            for literal in string_literals(&src) {
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
            scanned.push(name);
        }

        // Non-vacuity of the ENUMERATION itself: if the directory read silently returned nothing
        // (a moved crate root, a bad `CARGO_MANIFEST_DIR`), every assertion above would trivially
        // pass over zero files. `wire.rs`, `mod.rs` and `test_scan.rs` are the three the previous
        // hardcoded list was missing; require them by name so this scan cannot quietly narrow back
        // to the old five without a test failure naming which one dropped out.
        for must_be_scanned in ["mod.rs", "wire.rs", "test_scan.rs", "pane.rs"] {
            assert!(
                scanned.iter().any(|n| n == must_be_scanned),
                "{must_be_scanned} was not scanned -- directory enumeration under-covered \
                 (scanned: {scanned:?})"
            );
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
        let proven = ProvenClawback::open(authority)
            .expect("rewards_base_units >= recoverable_base_units in this fixture");
        let expected_short = short_asset_id_str(&own_hash.to_string());
        assert!(
            proven.confirm_body().contains(&expected_short),
            "confirm body {:?} does not name the viewer's own hash {expected_short:?}",
            proven.confirm_body()
        );
        // (c) asserted on an owned `String` field of `proven`, never a `&str` borrowed from a
        // dropped local (dig_ecosystem#3253 finding 2's undefined-behaviour shape).
        assert!(!proven.confirm_title().is_empty());
        assert!(!proven.withdraw_button().is_empty());
        assert!(!proven.keep_button().is_empty());

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
        assert!(ProvenClawback::open(authority).is_none());
    }
}
