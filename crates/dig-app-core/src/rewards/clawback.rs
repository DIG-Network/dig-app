//! The clawback authority gate (dig_ecosystem#3281): a [`ClawbackAuthority`] witness constructible
//! only from a wallet-key-derived [`ViewerPuzzleHash`] that is byte-equal to a commitment's
//! `clawback_puzzle_hash`, and the only producer of a [`ProvenClawback`] -- the only value in this
//! crate that carries the four finished `rewards-clawback-*` sentences bound to the amounts carried
//! by the commitment [`ClawbackAuthority::prove`] was called against, and to the hash it matched.
//! "Bound to the commitment" is a binding to whatever fields that commitment value holds -- it is
//! NOT a claim that those fields' PROVENANCE (that the commitment came from a parsed chain read
//! rather than an in-crate construction) is established; see "What this does NOT prove" below.
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
//! [`super::pane::WarningsShown`] is proven by comparing `REQUIRED_WARNING_KEYS`
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
//! writing "unreachable outside the gate" here would be exactly the retraction [`super::pane::WarningsShown`]
//! already had to publish once.
//!
//! [`ClawbackAuthority::prove`] binds key control over `clawback_puzzle_hash`, and only that --
//! it does not prove a commitment's ORIGIN by itself. `super::wire`'s private `commitment`
//! submodule closes the struct-literal and type-alias forging route via `E0451` (see
//! `super::wire`'s `RewardDistributorCommitment` doc for the full attempt and why it now fails --
//! code span, not a `[link]`: the type is `pub(crate)`, and rustdoc refuses a public doc linking a
//! private item; restoring the brackets here re-breaks `Doc-link hygiene` and both Native
//! confirmers, as it already has once), but that is narrower than record provenance: PROVENANCE
//! IS NOT BOUND, and
//! dig_ecosystem#3294 stays open, blocked on dig_ecosystem#3342 landing a real transport for
//! `parse_from_rpc` to parse. See that type's doc for the exact DOES/DOES-NOT split -- restated
//! here would go stale the next time that split changes, as it already has once.

use chia_protocol::Bytes32;
use dig_account::WalletKey;

use crate::amount::{amount_with_unit, short_asset_id_str};
use crate::i18n::Args;
use crate::wallet::state::Asset;

use super::copy;
use super::humanize;
use super::wire::{CommitmentsReading, RewardDistributorCommitment};

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
/// [`ProvenClawback::open`] takes EXACTLY ONE witness argument (plus the caller's own clock), so
/// passing a second, independent commitment -- the S1 splice,
/// `open(prove(&viewer, &mine).unwrap(), now, &strangers_slot)` -- is not merely re-checked away,
/// it is a wrong-number-of-arguments error (`E0061`) and does not compile:
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
/// let _ = ProvenClawback::open(authority, 0, &strangers_commitment()); // too many args -- does not compile
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
/// let _first = ProvenClawback::open(authority, 0);
/// let _second = ProvenClawback::open(authority, 0); // moved -- does not compile
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
        let commitment_ph = Bytes32::new(commitment.clawback_puzzle_hash());
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
    /// Refuses the whole window, with a distinct reason each, rather than showing a stand-in zero:
    /// - [`ClawbackRefusal::NotRecoverable`] when the held commitment carries no recoverable figure
    ///   (`None`: the chain refuses this clawback), OR when `epoch_start <= now`: the figure was
    ///   filtered once at parse time against the reply's clock, and a record parsed before its
    ///   epoch but confirmed after it would otherwise promise a return the chain refuses. `now`
    ///   can only ADD a refusal (fail-closed), never remove one; an absent figure is refused
    ///   whatever `now` is and is never read as 0 (dig_ecosystem#3446).
    /// - [`ClawbackRefusal::InconsistentRecord`] when `rewards_base_units` is less than the
    ///   recoverable figure: an underflow means the record is internally inconsistent (the #402
    ///   wrapper trap reappearing under a different name).
    ///
    /// Takes EXACTLY ONE argument -- see "Why the proved commitment travels INSIDE the witness"
    /// above. There is no second `commitment` parameter to pass a stranger's record through, so
    /// S1's splice (`open(prove(&viewer, &mine).unwrap(), &strangers_slot)`) is not merely
    /// re-checked, it is unrepresentable: every figure below is read from `authority.commitment`,
    /// the same record `prove` matched `authority.matched` against.
    pub fn open(authority: ClawbackAuthority, now: u64) -> Result<Self, ClawbackRefusal> {
        let commitment = &authority.commitment;
        // Checked before the figure is read: an epoch that has started is unrecoverable on chain.
        if commitment.epoch_start() <= now {
            return Err(ClawbackRefusal::NotRecoverable);
        }
        let recoverable_base_units = commitment
            .recoverable_base_units()
            .ok_or(ClawbackRefusal::NotRecoverable)?;
        let forfeited_base_units = commitment
            .rewards_base_units()
            .checked_sub(recoverable_base_units)
            .ok_or(ClawbackRefusal::InconsistentRecord)?;

        // The witness's OWN field, never a second, independently-supplied commitment -- see the
        // module doc and this method's doc above. Post-proof the two are equal by construction
        // (there is no other `commitment` in scope to diverge from), so this is not a defensive
        // re-check; it is the only record this method can read from at all.
        let clawback_ph_short = short_asset_id_str(&authority.matched.to_string());

        // `epoch_index` stays the RAW `epoch_start` integer, rendered as-is: the four-field wire
        // commitment carries no per-slot ordinal, only the raw Unix `epoch_start`, and this is NOT
        // merely a display gap -- `epoch_index` is the only identifier in this sentence naming
        // WHICH commitment is being withdrawn, so inventing a humanized substitute for it would
        // hide the very identifier a reader needs to match against the chain, not merely make it
        // prettier. Tracked as dig_ecosystem#3289; unaffected by dig_ecosystem#3297, which is
        // about DATE placeables, not identifiers.
        //
        // `epoch_start_date`, by contrast, IS a date placeable (dig_ecosystem#3297). `epoch_start`
        // is a fixed calendar instant, not one this function may assume is future OR past: a
        // clawback confirmation commonly targets an already-SETTLED epoch (the epoch has started,
        // even finished, and this is exactly the leftover it left behind), but nothing forbids
        // confirming against a commitment for an epoch that has not started yet either.
        // `super::humanize::until` is the one function in this crate built for that -- it renders
        // the honest past form ("N ago") when the epoch has already started and the honest future
        // form ("in N") when it has not, rather than assuming either (see its module doc).
        let epoch_index = commitment.epoch_start().to_string();
        let epoch_start_date = humanize::until(now, commitment.epoch_start());

        // A related but distinct gap, tracked separately as dig_ecosystem#3290: SPEC §2.6 clause 5
        // distinguishes "nothing committed" from "could not be read" (a distributor with zero
        // commitments vs. a read this process failed to perform), and none of the types in this
        // module or `wire.rs` can represent that distinction -- an empty commitment set and a
        // failed read are not separable here. Not this function's defect (`open` never sees an
        // empty set, only a single already-obtained commitment), but the same wire gap this
        // sentence's `epoch_index` caveat sits next to, so it is named here rather than left for
        // the next reader to rediscover.

        let slot_amount = amount_with_unit(Asset::DIG, commitment.rewards_base_units());
        let returned_amount = amount_with_unit(Asset::DIG, recoverable_base_units);
        let forfeited_amount = amount_with_unit(Asset::DIG, forfeited_base_units);

        let confirm_title = copy::CLAWBACK_CONFIRM_TITLE
            .with(&Args::new().text("epoch_index", epoch_index.clone()));
        let confirm_body = copy::CLAWBACK_CONFIRM_BODY.with(
            &Args::new()
                .text("slot_amount", slot_amount)
                .text("epoch_index", epoch_index)
                .text("epoch_start_date", epoch_start_date)
                .text("returned_amount", returned_amount.clone())
                .text("forfeited_amount", forfeited_amount)
                .text("clawback_ph_short", clawback_ph_short),
        );
        let withdraw_button = copy::CLAWBACK_WITHDRAW_BUTTON
            .with(&Args::new().text("returned_amount", returned_amount));
        let keep_button = copy::CLAWBACK_KEEP_BUTTON.text();

        Ok(ProvenClawback {
            confirm_title,
            confirm_body,
            withdraw_button,
            keep_button,
        })
    }
}

/// Why [`ProvenClawback::open`] refused to build a confirm window. The two kinds stay distinct:
/// folding them would tell a viewer whose slot the chain simply refuses that their record is
/// corrupt, or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawbackRefusal {
    /// The commitment carries no recoverable figure: the chain refuses this clawback (its epoch
    /// has started). Not a zero share and not a failed read.
    NotRecoverable,
    /// `rewards_base_units` is less than the recoverable figure -- the record contradicts itself.
    InconsistentRecord,
}

impl ClawbackRefusal {
    /// The rendered sentence for this refusal, in the active language. Carries no amount, so an
    /// absent figure can never read as a zero.
    pub fn sentence(&self) -> String {
        self.sentence_in(crate::i18n::current_language())
    }

    /// [`Self::sentence`] in an explicit language, independent of the process-wide one.
    pub fn sentence_in(&self, lang: crate::i18n::Language) -> String {
        match self {
            ClawbackRefusal::NotRecoverable => copy::CLAWBACK_NOT_RECOVERABLE.text_in(lang),
            ClawbackRefusal::InconsistentRecord => copy::CLAWBACK_INCONSISTENT_RECORD.text_in(lang),
        }
    }
}

/// Renders a [`CommitmentsReading`] (dig_ecosystem#3290, SPEC §2.6 clause 5) into one sentence,
/// naming the current gap: a chain-read failure MUST read as "could not be read", never as a bare
/// zero (dig_ecosystem#3427), and "nothing committed" MUST read distinctly from either. This is a
/// read-only report, not a custody gate -- unlike [`ProvenClawback`], nothing here proves control
/// over a `clawback_puzzle_hash`, so it carries no capability and needs none.
pub fn commitments_reading_sentence(reading: &CommitmentsReading, now: u64) -> String {
    match reading {
        CommitmentsReading::Unreadable(reason) => {
            copy::COMMITMENTS_UNREADABLE.with(&Args::new().text("reason", *reason))
        }
        CommitmentsReading::NothingCommitted { observed_at } => copy::COMMITMENTS_NOTHING_COMMITTED
            .with(&Args::new().text("observed_ago", humanize::ago(now, *observed_at))),
        CommitmentsReading::Committed {
            slots,
            observed_at,
            epoch_seconds: _,
        } => copy::COMMITMENTS_COMMITTED_SUMMARY.with(
            &Args::new()
                .text("slot_count", slots.len().to_string())
                .text("observed_ago", humanize::ago(now, *observed_at)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Language;
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
        RewardDistributorCommitment::new_for_test(
            1_767_225_600,
            clawback_puzzle_hash,
            10_000,
            Some(9_000),
        )
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
        let proven = ProvenClawback::open(authority, 0)
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
        // more recoverable than was ever committed
        let inconsistent = RewardDistributorCommitment::new_for_test(
            1_767_225_600,
            own_hash.to_bytes(),
            100,
            Some(101),
        );
        let authority = ClawbackAuthority::prove(&viewer, &inconsistent).unwrap();
        assert_eq!(
            ProvenClawback::open(authority, 0).err(),
            Some(ClawbackRefusal::InconsistentRecord)
        );
    }

    fn proved(commitment: &RewardDistributorCommitment) -> ClawbackAuthority {
        let viewer = ViewerPuzzleHash::from_wallet_key(&test_wallet_key());
        ClawbackAuthority::prove(&viewer, commitment).unwrap()
    }

    /// dig_ecosystem#3446: an absent figure is refused as NotRecoverable -- whatever `now` is, and
    /// never opened as a zero-amount window.
    #[test]
    fn absent_figure_is_refused_not_recoverable_whatever_the_clock() {
        let own_hash = independently_derived_root_puzzle_hash().to_bytes();
        let none = RewardDistributorCommitment::new_for_test(1_767_225_600, own_hash, 100, None);
        for now in [0, 1_767_225_600, u64::MAX] {
            assert_eq!(
                ProvenClawback::open(proved(&none), now).err(),
                Some(ClawbackRefusal::NotRecoverable)
            );
        }
    }

    /// dig_ecosystem#3446: `Some(0)` is a real zero payout -- the window opens and the button
    /// names a zero amount rather than refusing as "not recoverable".
    #[test]
    fn real_zero_figure_opens_and_names_a_zero_amount() {
        let own_hash = independently_derived_root_puzzle_hash().to_bytes();
        let zero = RewardDistributorCommitment::new_for_test(1_767_225_600, own_hash, 100, Some(0));
        let proven = ProvenClawback::open(proved(&zero), 0).expect("Some(0) is a real zero");
        let zero_amount = amount_with_unit(Asset::DIG, 0);
        assert!(
            proven.withdraw_button().contains(&zero_amount),
            "{:?} must name {zero_amount:?}",
            proven.withdraw_button()
        );

        // Contrast: a real 50 must NOT render the zero amount, so the assertion above can fail.
        let fifty =
            RewardDistributorCommitment::new_for_test(1_767_225_600, own_hash, 100, Some(50));
        let other = ProvenClawback::open(proved(&fifty), 0).unwrap();
        assert!(
            !other.withdraw_button().contains(&zero_amount),
            "{:?} must not render {zero_amount:?}",
            other.withdraw_button()
        );
    }

    /// dig_ecosystem#3446 (gate): `parse_from_rpc` filters on the reply's clock ONCE. A record
    /// parsed one second BEFORE its epoch (figure kept) and confirmed AT/AFTER the epoch start must
    /// be refused by `open` -- the chain refuses that slot, so "would return X" would be false.
    #[test]
    fn open_refuses_once_the_epoch_has_started_even_if_parsed_before() {
        const PEAK: u64 = 1_767_225_000;
        let own_hash = independently_derived_root_puzzle_hash().to_bytes();
        let parsed =
            RewardDistributorCommitment::parse_from_rpc(PEAK + 1, own_hash, 100, Some(50), PEAK);
        assert_eq!(
            parsed.recoverable_base_units(),
            Some(50),
            "figure kept at parse"
        );

        // Still before the epoch: opens.
        assert!(ProvenClawback::open(proved(&parsed), PEAK).is_ok());
        // Epoch started (== counts as started) or long past: refused.
        for now in [PEAK + 1, PEAK + 2, u64::MAX] {
            assert_eq!(
                ProvenClawback::open(proved(&parsed), now).err(),
                Some(ClawbackRefusal::NotRecoverable),
                "now={now}"
            );
        }
    }

    /// dig_ecosystem#3451 end to end: a node reply with `null` for a not-yet-started slot decodes to
    /// an absent figure, proves, and `open` refuses it as NotRecoverable -- a sentence with no
    /// digit in it. A reply `0` is a real zero and opens.
    #[test]
    fn a_decoded_null_reply_refuses_and_a_decoded_zero_reply_opens() {
        use crate::rewards::commitments::decode;
        const PEAK: u64 = 1_767_225_000;
        const FUTURE: u64 = PEAK + 1_000_000;
        let launcher = [0xab_u8; 32];
        let own_hash = independently_derived_root_puzzle_hash().to_bytes();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let row = |recoverable: serde_json::Value| {
            serde_json::json!({
                "epoch_start": FUTURE,
                "clawback_puzzle_hash": hex(&own_hash),
                "rewards_base_units": 100u64,
                "recoverable_base_units": recoverable,
            })
        };
        let reply = serde_json::json!({
            "launcher_id": hex(&launcher),
            "withdrawal_share_bps": 9000,
            "epoch_seconds": 604_800u64,
            "commitments": [row(serde_json::Value::Null), row(serde_json::json!(0))],
            "observed_at": PEAK,
            "chain_peak_height": 7u64,
            "chain_peak_timestamp": PEAK,
        });
        let decoded = decode(&reply, &launcher).expect("decodes");
        assert_eq!(decoded.commitments.len(), 2);

        let refusal = ProvenClawback::open(proved(&decoded.commitments[0]), PEAK)
            .err()
            .expect("an absent figure must refuse");
        assert_eq!(refusal, ClawbackRefusal::NotRecoverable);
        let sentence = refusal.sentence_in(Language::En);
        assert!(
            !sentence.chars().any(|c| c.is_ascii_digit()),
            "{sentence:?}"
        );

        let opened = ProvenClawback::open(proved(&decoded.commitments[1]), PEAK)
            .expect("Some(0) is a real zero, not a refusal");
        assert!(opened
            .withdraw_button()
            .contains(&amount_with_unit(Asset::DIG, 0)));
    }

    /// dig_ecosystem#3446: the NotRecoverable sentence says so and carries no digit; the two
    /// refusals render distinct sentences. Pinned to English: the process-wide language is ambient.
    #[test]
    fn not_recoverable_sentence_says_so_without_a_figure() {
        let en = Language::En;
        let text = ClawbackRefusal::NotRecoverable.sentence_in(en);
        assert!(text.contains("not recoverable"), "{text:?}");
        assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text:?}");
        let other = ClawbackRefusal::InconsistentRecord.sentence_in(en);
        assert!(!other.is_empty());
        assert_ne!(text, other);
    }

    /// dig_ecosystem#3446 clause 4: the present-figure copy is a projection, not a guarantee.
    /// The OLD copy said "returns to this wallet" as a fact; the catalog line must no longer.
    /// Reads the English catalog directly (ambient language cannot skew it) and also checks the
    /// window `open` builds is figure-bearing.
    #[test]
    fn confirm_body_does_not_guarantee_the_return() {
        let body = copy::CLAWBACK_CONFIRM_BODY.text_in(Language::En);
        assert!(!body.contains("returns to this wallet"), "{body:?}");
        assert!(body.contains("would return"), "{body:?}");

        let own_hash = independently_derived_root_puzzle_hash().to_bytes();
        let some =
            RewardDistributorCommitment::new_for_test(1_767_225_600, own_hash, 100, Some(50));
        let proven = ProvenClawback::open(proved(&some), 0).unwrap();
        let returned = amount_with_unit(Asset::DIG, 50);
        assert!(
            proven.confirm_body().contains(&returned),
            "{:?} must name the returned amount {returned:?}",
            proven.confirm_body()
        );
    }

    /// dig_ecosystem#3297: WHEN `epoch_start` is still ahead of the confirming clock (this
    /// fixture's case -- an epoch that has not started yet), `confirm_body` must say so with the
    /// future form, never "ago" -- that would claim a promise already kept. `epoch_start` is not
    /// always future (see `open`'s own doc comment: a clawback commonly targets an already-settled
    /// epoch), so this test pins only the future-input case; the past-input case is
    /// `humanize::tests::until_never_renders_a_false_future_for_a_past_or_present_instant`.
    #[test]
    fn epoch_start_date_is_a_future_form_never_an_ago_form() {
        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        let own_hash = independently_derived_root_puzzle_hash();
        // one hour after `now` below
        let commitment = RewardDistributorCommitment::new_for_test(
            1_700_003_600,
            own_hash.to_bytes(),
            100,
            Some(50),
        );
        let authority = ClawbackAuthority::prove(&viewer, &commitment).unwrap();
        let now = 1_700_000_000;
        let proven = ProvenClawback::open(authority, now).unwrap();
        assert!(
            proven.confirm_body().contains("in 1 hour"),
            "confirm body {:?} does not render the future form",
            proven.confirm_body()
        );
        assert!(
            !proven.confirm_body().contains("ago"),
            "confirm body {:?} claims a future epoch already started",
            proven.confirm_body()
        );
    }

    /// dig_ecosystem#3297's acceptance bar, over `clawback.rs`'s own render path -- the guard
    /// `pane.rs`'s own digit-run test's doc comment used to (falsely) claim to cover. Every
    /// rendered `rewards-clawback-*` sentence must not contain a raw 9-11 digit epoch-shaped run,
    /// with exactly ONE documented exemption: `epoch_index` (`confirm_title`/`confirm_body`) is
    /// deliberately the RAW `epoch_start` integer, per `open`'s own doc comment -- it is the only
    /// identifier in the sentence naming which commitment is being withdrawn, tracked separately
    /// as dig_ecosystem#3289, and unaffected by this ticket, which is about DATE placeables. This
    /// exemption is checked by VALUE (the exact known raw string), not by narrowing the digit-run
    /// pattern or by skipping a whole sentence, so a second, undocumented raw timestamp appearing
    /// anywhere else in these four strings still trips the guard.
    #[test]
    fn no_rendered_clawback_sentence_contains_an_undocumented_epoch_shaped_digit_run() {
        use crate::rewards::test_scan::longest_ascii_digit_run;

        const NOW: u64 = 1_700_000_000; // 10 digits -- itself epoch-shaped, never rendered raw
        const EPOCH_START: u64 = 1_700_003_600; // one hour after NOW; also epoch-shaped

        let key = test_wallet_key();
        let viewer = ViewerPuzzleHash::from_wallet_key(&key);
        let own_hash = independently_derived_root_puzzle_hash();
        let commitment = RewardDistributorCommitment::new_for_test(
            EPOCH_START,
            own_hash.to_bytes(),
            100,
            Some(50),
        );
        let authority = ClawbackAuthority::prove(&viewer, &commitment).unwrap();
        let proven = ProvenClawback::open(authority, NOW).unwrap();

        let documented_epoch_index = EPOCH_START.to_string();
        let rendered = [
            proven.confirm_title(),
            proven.confirm_body(),
            proven.withdraw_button(),
            proven.keep_button(),
        ];
        for text in rendered {
            // The one documented exemption: strip the exact known `epoch_index` value before
            // scanning, rather than skipping the whole string or loosening the digit-run length.
            let scanned = text.replace(&documented_epoch_index, "");
            if let Some(run) = longest_ascii_digit_run(&scanned) {
                assert!(
                    !(9..=11).contains(&run),
                    "{text:?} contains a {run}-digit run outside the documented epoch_index \
                     exemption, which reads as a raw epoch second"
                );
            }
        }
    }

    /// dig_ecosystem#3290, SPEC §2.6 clause 5: a chain-read failure must render distinctly from
    /// "nothing committed" -- never the same sentence, and never a bare zero.
    #[test]
    fn unreadable_never_renders_the_same_as_nothing_committed() {
        let unreadable =
            commitments_reading_sentence(&CommitmentsReading::Unreadable("no peer"), 0);
        let nothing_committed = commitments_reading_sentence(
            &CommitmentsReading::NothingCommitted { observed_at: 0 },
            0,
        );

        assert_ne!(unreadable, nothing_committed);
        assert!(
            !unreadable.contains('0'),
            "an unreadable result must not render as a zero: {unreadable:?}"
        );
    }

    /// Every one of the three states renders non-empty text and no two states collapse into the
    /// same sentence.
    #[test]
    fn every_commitments_reading_variant_renders_distinct_nonempty_text() {
        let now = 1_767_225_600;
        let readings = [
            CommitmentsReading::Unreadable("no peer"),
            CommitmentsReading::NothingCommitted {
                observed_at: now - 60,
            },
            CommitmentsReading::Committed {
                slots: vec![],
                observed_at: now - 60,
                epoch_seconds: 604_800,
            },
        ];

        let rendered: Vec<String> = readings
            .iter()
            .map(|reading| commitments_reading_sentence(reading, now))
            .collect();

        for text in &rendered {
            assert!(!text.is_empty(), "every variant must render non-empty text");
        }
        for i in 0..rendered.len() {
            for j in (i + 1)..rendered.len() {
                assert_ne!(
                    rendered[i], rendered[j],
                    "variants {i} and {j} must not render the same sentence"
                );
            }
        }
    }
}
