//! Typed shapes mirroring dig-rewards-coin SPEC §2.3 and §2.6 verbatim.
//!
//! Nothing here is invented: every field name and every state traces to a SPEC clause named in its
//! doc comment. The four `Tier::Control` reward methods shipped in dig-rpc-protocol v0.11.0;
//! these types mirror SPEC §2.3 and §2.6 until dig-app's transport is wired. [`crate::rewards::client::RewardsClient`]
//! (sibling module) is the seam that will be re-pointed at them without reshaping this module.

/// The closed set of prover states (SPEC §2.3). An implementation MUST use exactly this set, MUST
/// NOT add a state without adding it here, and MUST NOT collapse two into one message —
/// `LocalCopyMissing` and `Stopped` especially, because only one names the operator's own mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProverState {
    Idle,
    Running,
    LocalCopyMissing,
    ChainSourceUnavailable,
    Unfunded,
    FeeBudgetExhausted,
    EntrySetFull,
    Paused,
    Stopped,
}

/// One distributor's counters (SPEC §2.3 `counters`).
///
/// # Fields are `pub(crate)`, not `pub`
///
/// A money figure reaches a person only through `amount::format_asset_amount`, and
/// `entry_count`/`total_paid_out_base_units` reach a person only through
/// [`super::reading::entry_set_reading`]/[`super::reading::payout_reading`] — both rules that a
/// `pub` field lets any caller bypass by convention rather than by the compiler. Narrowed to
/// `pub(crate)` rather than given a constructor: a constructor over nine positional fields would
/// only re-expose the same fields as call-site arguments, and the real transport that will decode
/// `dig.getRewardProverStatus` into this type is not wired yet (see [`crate::rewards`]'s module
/// doc) — a constructor with no caller is dead code today. `pub(crate)` still closes the gap that
/// matters now: no crate OUTSIDE dig-app-core can read a raw counter and bypass `reading`'s typed
/// wrappers, and the struct-literal route stays open for this crate's own fixtures and the future
/// transport code, which is where the derive-through-`reading` contract is documented for the
/// next reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewardCounters {
    pub(crate) mirrors_seen: u64,
    pub(crate) challenges_issued: u64,
    pub(crate) challenges_passed: u64,
    pub(crate) challenges_failed: u64,
    pub(crate) entries_added: u64,
    pub(crate) entries_removed: u64,
    pub(crate) entry_count: u32,
    pub(crate) reserve_base_units: u64,
    pub(crate) total_paid_out_base_units: u64,
}

/// The per-distributor status record (SPEC §2.3), field for field. Every `Option<Unix seconds>`
/// field here is `None` for exactly the reason the spec names, never a stand-in zero — see
/// [`crate::rewards::reading`], which is the ONLY place this record is turned into what a person
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardDistributorStatusRecord {
    pub launcher_id: [u8; 32],
    pub store_id: [u8; 32],
    pub root: [u8; 32],
    pub prover_state: ProverState,
    pub prover_state_since: u64,
    pub last_cycle_started_at: Option<u64>,
    pub last_cycle_completed_at: Option<u64>,
    pub next_cycle_due_at: Option<u64>,
    pub last_entry_write_at: Option<u64>,
    pub consecutive_cycle_failures: u32,
    pub pending_entry_writes: u32,
    /// The chain view this record reflects — NOT "now". Staleness (§2.4) is derived by the reader
    /// from this against its own clock; it is never precomputed by the writer.
    pub observed_at: u64,
    pub counters: RewardCounters,
}

/// One committed-incentive slot (SPEC §2.6 `dig.listRewardDistributorCommitments`), mirroring
/// dig-rpc-protocol v0.11.0's `RewardDistributorCommitment` shape verbatim: all four fields, or
/// none.
///
/// # Why `recoverable_base_units` is a wire field, never a computed one
///
/// SPEC §2.6 clause 2 forbids BY NAME recomputing a share from a compiled-in constant —
/// `committed * 9000 / 10_000` or `committed * withdrawal_share_bps / 10_000` run in this crate is
/// exactly the banned defect, because the real split is decided on-chain and can differ from
/// whatever bps this crate happens to have compiled in. This type carries the chain's own already-
/// computed answer instead, so there is nothing here to recompute.
///
/// This type is no longer inert: [`super::clawback::ClawbackAuthority::prove`] (dig_ecosystem#3281)
/// constructs it into the witness it proves against, and [`super::clawback::ProvenClawback::open`]
/// reads `rewards_base_units`, `recoverable_base_units` and their difference through
/// `amount_with_unit` and paints all three as `$DIG`. The next reader must not assume no custody
/// gate reads this type — the clawback authority gate does, today. What is still true: no
/// constructor here takes a `dig.listRewardDistributorCommitments` RPC response —
/// [`super::client::RewardsClient`] does not adopt that method (deleted per the dig_ecosystem#3253
/// adversarial gate's finding 2 — the trait method wrapped only this type's `Vec`, dropping three
/// of the SPEC §2.6 result's five fields), and no constructor of this type anywhere in this crate
/// sits outside `#[cfg(test)]` code. So this type has no production value at this head, only
/// test fixtures — see dig_ecosystem#3294 for why that gap matters to [`super::clawback`]'s proof,
/// and where closing it lands once the transport is wired.
///
/// # Fields are PRIVATE, not `pub(crate)` (dig_ecosystem#3294)
///
/// `pub(crate)` narrowed WHO could read a field, never WHO could FORGE the whole record: any
/// module inside `dig-app-core` could still write a struct literal with any
/// `rewards_base_units`/`recoverable_base_units` it liked, and [`super::clawback`]'s custody gate
/// (`ClawbackAuthority::prove`) trusts this record's numbers completely once a hash matches --
/// binding key control over `clawback_puzzle_hash`, never that the NUMBERS came from a parsed
/// chain/RPC read rather than an in-crate literal.
///
/// **The forging attempt tried, and why it now fails:** the precedent this doc follows is
/// `pub struct Acknowledged;` (forgeable in one line by any caller who could name the type). The
/// analogous one-liner here would be
/// `RewardDistributorCommitment { epoch_start: 0, clawback_puzzle_hash: victim_hash, rewards_base_units: u64::MAX, recoverable_base_units: 0 }`
/// from ANY function in this crate that can name the four field values -- no RPC call, no chain
/// read, just four numbers a caller already has. With `pub(crate)` fields this compiled; with
/// private fields it is `E0451` (field is private) from every module except this one, so the only
/// way to produce a value is through `RewardDistributorCommitment::parse_from_rpc` below, or the
/// `#[cfg(test)]`-gated `RewardDistributorCommitment::new_for_test` fixture constructor.
///
/// **Is the producer guarded?** Yes: `RewardDistributorCommitment::parse_from_rpc` is the ONLY
/// non-test constructor, and it exists in this same module rather than being callable generically
/// -- a caller cannot construct one from values it invented without going through the function
/// named for the transport read it stands in for. **Can the guard be forged?** Not from outside
/// this module: the fields are private, so no struct literal compiles anywhere else, and there is
/// no second `pub`/`pub(crate)` constructor to route around this one.
///
/// # Accessors read the fields, never a raw field access
///
/// [`super::clawback`] and this module's own tests read every field through
/// `Self::epoch_start`/`Self::clawback_puzzle_hash`/`Self::rewards_base_units`/
/// `Self::recoverable_base_units` -- narrow, read-only, and unable to construct a new value the
/// way a `pub(crate)` field could be used to (a caller with a `&mut` reference to a field could
/// mutate a legitimately-obtained record in place; there is no `&mut` accessor here, so a
/// [`RewardDistributorCommitment`] is immutable for its whole life once produced).
///
/// # `RewardDistributorStatusRecord` is NOT narrowed the same way
///
/// Considered and decided against, for now: unlike this type, `RewardDistributorStatusRecord` has
/// no custody gate reading it -- [`super::clawback::ClawbackAuthority::prove`] is the one function
/// in this crate that turns a wire record's numbers into a security decision, and it only ever
/// takes a [`RewardDistributorCommitment`]. Narrowing the status record too would be pure
/// defense-in-depth with no forging attempt to point to yet; tracked as a follow-up if a future
/// custody-adjacent reader of `RewardDistributorStatusRecord` appears, rather than done
/// speculatively here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDistributorCommitment {
    epoch_start: u64,
    clawback_puzzle_hash: [u8; 32],
    rewards_base_units: u64,
    recoverable_base_units: u64,
}

impl RewardDistributorCommitment {
    /// The ONLY non-test constructor (dig_ecosystem#3294): stands in for parsing
    /// `dig.listRewardDistributorCommitments`' RPC/chain response shape. Takes the already-decoded
    /// primitives rather than a transport response TYPE because no such type is wired into this
    /// crate yet -- but it is still the single named seam a future transport wiring replaces the
    /// BODY of, never a second constructor added beside it.
    ///
    /// # No production caller yet, and that is deliberate (dig_ecosystem#3342)
    ///
    /// [`super::client::RewardsClient`] does NOT adopt `dig.listRewardDistributorCommitments` in
    /// this change, and must not until dig_ecosystem#3342 closes: a released v0.259.0 node's live
    /// RPC does not usefully answer that method, and `REWARD_CHAIN_UNAVAILABLE` conflates "no such
    /// distributor" with "the chain is unreachable" -- exactly this epic's own defect class,
    /// landing on the wire surface a clawback decision would then trust. Wiring the transport now
    /// would pull that ambiguity into a money surface; a prior adoption of this same method was
    /// already deleted once by the dig_ecosystem#3253 gate for a different reason (dropping three
    /// of the SPEC §2.6 result's five fields). So this function has no caller in this crate today,
    /// on purpose -- the `#[allow(dead_code)]` below is that decision made explicit, not a
    /// suppression of an unrelated warning; a caller was deliberately NOT invented to silence it
    /// the wrong way. `tests::no_construction_site_of_the_commitment_sits_outside_cfg_test`
    /// still holds with zero callers: it proves no OTHER construction route exists, which needs no
    /// caller of this one to be true.
    #[allow(dead_code)]
    pub(crate) fn parse_from_rpc(
        epoch_start: u64,
        clawback_puzzle_hash: [u8; 32],
        rewards_base_units: u64,
        recoverable_base_units: u64,
    ) -> Self {
        Self {
            epoch_start,
            clawback_puzzle_hash,
            rewards_base_units,
            recoverable_base_units,
        }
    }

    /// Test-only fixture constructor. Exists so this crate's own tests can build a record without
    /// a real RPC call, without adding a second production constructor -- see the module doc's
    /// "forging attempt" paragraph for why a second constructor is exactly the gap #3294 closes.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        epoch_start: u64,
        clawback_puzzle_hash: [u8; 32],
        rewards_base_units: u64,
        recoverable_base_units: u64,
    ) -> Self {
        Self {
            epoch_start,
            clawback_puzzle_hash,
            rewards_base_units,
            recoverable_base_units,
        }
    }

    /// SPEC §2.6: when the committed epoch started.
    pub(crate) fn epoch_start(&self) -> u64 {
        self.epoch_start
    }

    /// SPEC §2.6: the puzzle hash key control over which [`super::clawback::ClawbackAuthority`]
    /// binds against.
    pub(crate) fn clawback_puzzle_hash(&self) -> [u8; 32] {
        self.clawback_puzzle_hash
    }

    /// SPEC §2.6: the slot's total committed reward, base units.
    pub(crate) fn rewards_base_units(&self) -> u64 {
        self.rewards_base_units
    }

    /// SPEC §2.6: the chain's own already-computed recoverable share, base units -- never
    /// recomputed from a compiled-in bps constant (see the module doc's clause-2 paragraph).
    pub(crate) fn recoverable_base_units(&self) -> u64 {
        self.recoverable_base_units
    }
}

/// The ONE legal source of a reward distributor's reserve asset id (SPEC §9.1): every distributor
/// reserves `$DIG` and nothing else, so this MUST never be a typed hex literal, a runtime
/// parameter, or re-exported under a new name — it is always exactly
/// [`dig_constants::DIG_ASSET_ID`], read through this function so a caller never has to know that.
pub fn reserve_asset_id() -> chia_protocol::Bytes32 {
    dig_constants::DIG_ASSET_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC §9.1: the reserve asset id is always `dig_constants::DIG_ASSET_ID` — never a second
    /// source that could quietly drift from it.
    #[test]
    fn reserve_asset_id_is_the_dig_constants_source() {
        assert_eq!(reserve_asset_id(), dig_constants::DIG_ASSET_ID);
    }

    /// Compile-level proof that [`RewardDistributorStatusRecord`] carries exactly these fields —
    /// no more, no less. A `let Struct { a, b, .. } = x` pattern with `..` would still compile if a
    /// `healthy`/`ok`/`up`/`running` boolean were added later (SPEC §2.4's forbidden shape); this
    /// pattern has NO `..`, so it fails to compile the moment any field is added, renamed or
    /// removed, and a reviewer sees exactly which one broke it.
    #[test]
    fn status_record_has_no_extra_field_and_therefore_no_health_boolean() {
        let record = RewardDistributorStatusRecord {
            launcher_id: [0; 32],
            store_id: [0; 32],
            root: [0; 32],
            prover_state: ProverState::Idle,
            prover_state_since: 0,
            last_cycle_started_at: None,
            last_cycle_completed_at: None,
            next_cycle_due_at: None,
            last_entry_write_at: None,
            consecutive_cycle_failures: 0,
            pending_entry_writes: 0,
            observed_at: 0,
            counters: RewardCounters::default(),
        };
        let RewardDistributorStatusRecord {
            launcher_id: _,
            store_id: _,
            root: _,
            prover_state: _,
            prover_state_since: _,
            last_cycle_started_at: _,
            last_cycle_completed_at: _,
            next_cycle_due_at: _,
            last_entry_write_at: _,
            consecutive_cycle_failures: _,
            pending_entry_writes: _,
            observed_at: _,
            counters: _,
        } = record;
    }

    /// Compile-level proof [`RewardDistributorCommitment`] carries exactly these four fields --
    /// all four or none, per SPEC §2.6 clause 2. A `..` pattern would still compile if a fifth
    /// field silently reintroduced a pre-computed share; this pattern has no `..`.
    #[test]
    fn commitment_has_exactly_the_four_spec_fields_and_no_more() {
        let commitment = RewardDistributorCommitment {
            epoch_start: 0,
            clawback_puzzle_hash: [0; 32],
            rewards_base_units: 0,
            recoverable_base_units: 0,
        };
        let RewardDistributorCommitment {
            epoch_start: _,
            clawback_puzzle_hash: _,
            rewards_base_units: _,
            recoverable_base_units: _,
        } = commitment;
    }

    /// Step -- ACCEPTANCE (dig_ecosystem#3294): no `RewardDistributorCommitment { .. }` struct
    /// literal exists anywhere in `src/rewards/` OUTSIDE `#[cfg(test)]`-gated code. Private fields
    /// already make a literal outside this file an `E0451` compile error, so this scan's live
    /// finding is narrower and still real: a literal INSIDE this file but OUTSIDE its own
    /// `#[cfg(test)] mod tests` block (i.e. a second production constructor added beside
    /// `parse_from_rpc` without going through this doc's "forging attempt" reasoning again).
    ///
    /// ENUMERATES `src/rewards/` (`std::fs::read_dir`, same idiom as
    /// `clawback.rs::no_module_outside_clawback_names_a_clawback_key`) rather than a hardcoded file
    /// list, for the same reason that test gives: a tenth file added to this directory is covered
    /// automatically.
    #[test]
    fn no_construction_site_of_the_commitment_sits_outside_cfg_test() {
        const NEEDLE: &str = "RewardDistributorCommitment {";
        const CFG_TEST: &str = "#[cfg(test)]";
        const MOD_TESTS: &str = "mod tests";

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
            let raw_src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));

            // CODE lines only, same convention as `super::test_scan::string_literals`: a doc
            // comment (`//!`/`///`) is allowed to QUOTE the forging-attempt struct literal as
            // prose (both `wire.rs` and `clawback.rs`'s module docs do exactly that, to name the
            // attempt and its compile error) without that quotation being mistaken for a second
            // construction site. Only a line that is not a comment can actually construct the
            // type at compile time.
            //
            // The TYPE DEFINITION (`pub struct RewardDistributorCommitment {`) also contains the
            // literal substring `NEEDLE` and is not a construction site -- it is the declaration
            // the constructors build.
            //
            // A FUNCTION SIGNATURE returning this type (`fn f(..) -> RewardDistributorCommitment
            // {`) trips it too, for the same reason: the brace opens the function BODY, not a
            // struct literal. `clawback.rs`'s own `commitment_with_clawback_ph` test fixture is
            // exactly this shape -- it calls the real `new_for_test` constructor inside its body
            // and would otherwise be misread as a second forging site.
            //
            // The `impl RewardDistributorCommitment {` block header trips it a third way: the
            // brace opens the impl block, not a struct literal, and it sits BEFORE `mod tests`
            // (it has to -- `parse_from_rpc`/`new_for_test` live in it), so it would otherwise
            // read as a production-code forging site every time.
            //
            // All three are stripped by the same "skip this whole line" convention as comments,
            // rather than a second detection mechanism, so the one filter chain above stays the
            // single place that decides what counts as scannable code.
            let src: String = raw_src
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| !line.contains("struct RewardDistributorCommitment"))
                .filter(|line| !line.contains("-> RewardDistributorCommitment {"))
                .filter(|line| !line.trim_start().starts_with("impl RewardDistributorCommitment"))
                .collect::<Vec<_>>()
                .join("\n");

            // The one place a literal is legitimate: this file's own `#[cfg(test)] mod tests`
            // block (the compile-level shape proofs above, and any future test fixture). Everywhere
            // a literal appears BEFORE that block's start is production code.
            let test_mod_start = if name == "wire.rs" {
                src.find(CFG_TEST)
                    .and_then(|cfg_at| src[cfg_at..].find(MOD_TESTS).map(|at| cfg_at + at))
                    .unwrap_or(src.len())
            } else {
                // No sibling file may name the literal at all -- private fields already forbid it
                // from compiling, but a scan should not depend on that compiler error to notice.
                // `usize::MAX` makes every real occurrence trip the `occurrence >= test_mod_start`
                // check below (a wrong-direction threshold of `0` would instead pass every one).
                usize::MAX
            };

            for (occurrence, _) in src.match_indices(NEEDLE) {
                assert!(
                    occurrence >= test_mod_start,
                    "{name} constructs RewardDistributorCommitment outside #[cfg(test)] code                      at byte {occurrence} -- only parse_from_rpc/new_for_test may produce one"
                );
            }
            scanned.push(name);
        }

        for must_be_scanned in ["wire.rs", "clawback.rs", "mod.rs"] {
            assert!(
                scanned.iter().any(|n| n == must_be_scanned),
                "{must_be_scanned} was not scanned -- directory enumeration under-covered                  (scanned: {scanned:?})"
            );
        }
    }
}
