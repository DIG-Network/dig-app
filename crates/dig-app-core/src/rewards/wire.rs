//! Typed shapes mirroring dig-rewards-coin SPEC §2.3 and §2.6 verbatim.
//!
//! Nothing here is invented: every field name and every state traces to a SPEC clause named in its
//! doc comment. The four `Tier::Control` reward methods shipped in dig-rpc-protocol v0.11.0;
//! these types mirror SPEC §2.3 and §2.6 until dig-app's transport is wired. [`super::client::RewardsClient`]
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
/// none. The type itself, its fields and its two constructors live in the private `commitment`
/// submodule below; this re-export is the only path to it from the rest of the crate.
///
/// # Why `recoverable_base_units` is a wire field, never a computed one
///
/// SPEC §2.6 clause 2 forbids a **compiled-in** share — `committed * 9000 / 10_000`, or any
/// `committed * withdrawal_share_bps / 10_000` where `withdrawal_share_bps` is a literal or a
/// crate constant this crate invented, is exactly the banned defect, because the real split is
/// decided on-chain and can differ from whatever bps this crate happens to have hardcoded.
///
/// It does **not** ban computing the same formula over an **observed, curried** bps read fresh off
/// this chain read (dig_ecosystem#3290 correction — an earlier revision of this doc conflated the
/// two). `client.rs`'s `current_distributor_epoch_start` already sets this precedent for
/// `epoch_seconds` (dig_ecosystem#3262): deriving a value from a chain-observed curried constant is
/// the compliant shape SPEC §2.6 clause 2 asks for, in principle, not the violation it bans.
///
/// That said, **this crate currently derives no recoverable-share figure anywhere, on purpose**
/// (dig_ecosystem#3439, priority:1-high, confirmed at the admitted rung against a real validator):
/// `rewards_base_units * observed withdrawal_share_bps / 10_000` — the formula an earlier revision
/// of [`commitments_reading_from_slots`] used — reports a nonzero recoverable amount
/// for a commitment the chain will still refuse, because it takes no account of the puzzle's own
/// compiled-in `ASSERT_BEFORE_SECONDS_ABSOLUTE(epoch_start)`, which rejects a clawback against an
/// epoch that has already started. An observed-and-curried bps is not automatically safe to
/// render just because it is not compiled-in; #3439 must close (the puzzle's own epoch-start
/// refusal must be accounted for) before any recoverable figure is derived here again. This type's
/// own `parse_from_rpc` constructor still takes an already-computed `recoverable_base_units`
/// because its input is (eventually) a `dig.listRewardDistributorCommitments` RPC reply that
/// carries the chain's own already-validated answer directly — a different source than an in-app
/// derivation, and not affected by #3439.
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
/// # Fields are PRIVATE to `commitment`, not merely `pub(crate)` (dig_ecosystem#3294, #410)
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
/// read, just four numbers a caller already has. Fields private to a MODULE (not merely a file)
/// make that `E0451` from every module except `commitment` itself, however the type is spelled
/// at the call site: a local `type Alias = RewardDistributorCommitment;` outside `commitment` is
/// still outside the module the fields are private to, so `Alias { .. }` is exactly as rejected as
/// the fully-qualified name -- this is the fix for the loop-security PoC on PR #410 that defeated
/// the prior text-scanning test (a `type Alias = ...` construction site was invisible to a scan for
/// the literal type name or `Self {`, because neither needle is what the compiler actually checks;
/// module-private fields ARE what the compiler checks, so there is no second spelling left to miss).
/// The only way to produce a value is through `RewardDistributorCommitment::parse_from_rpc`, or the
/// `#[cfg(test)]`-gated `RewardDistributorCommitment::new_for_test` fixture constructor -- both
/// defined inside `commitment`, nowhere else.
///
/// **What this DOES establish:** no module outside `commitment` can write a struct literal or
/// route around the field privacy with a type alias -- `E0451` from every other module in this
/// crate, regardless of what name or alias the type is reached through, and there is no second
/// `pub`/`pub(crate)` constructor beside `parse_from_rpc` to route around this one. That closes
/// the ONE-LINER forging attempt named above.
///
/// **What this does NOT establish (dig_ecosystem#3294 stays open):** `parse_from_rpc` is
/// `pub(crate)` and validates nothing -- it takes four already-decoded primitives and returns
/// `Self { .. }` unconditionally. Inherent-method resolution does not require its defining module
/// to be reachable, so any module in this crate can still call
/// `RewardDistributorCommitment::parse_from_rpc(0, victim_hash, u64::MAX, 0)` and get a value with
/// fabricated amounts -- the same forging attempt under the constructor's name instead of a struct
/// literal's. Closing that gap needs `parse_from_rpc` to take a real parsed wire response rather
/// than four numbers, and no such transport type exists in this crate yet:
/// `dig.listRewardDistributorCommitments` returns `-32032 REWARD_CHAIN_UNAVAILABLE` on a released
/// v0.259.0 node against live mainnet (dig_ecosystem#3342). Inventing a wire type with no
/// transport behind it would be fabricating the input this constructor is supposed to gate on, so
/// that is deliberately left for when #3342 lands the real transport, not simulated here.
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
pub(crate) use commitment::RewardDistributorCommitment;

/// Private home of [`RewardDistributorCommitment`] and its two sanctioned constructors
/// (dig_ecosystem#3294, PR #410 structural fix). This is the whole audit surface: a struct and two
/// functions, private-fields-to-module rather than a text scan, so `rustc`'s own `E0451` is the
/// enforcement -- it cannot be defeated by a comment, a doc-quoted literal, an aliased type name, a
/// macro, or a spelling of the construction site nobody has thought of yet, because none of those
/// change which MODULE a field is private to. Everything a removed text scan
/// (`no_construction_site_of_the_commitment_sits_outside_cfg_test`, deleted on this same change
/// after a `type Alias = RewardDistributorCommitment;` PoC defeated it) tried to approximate is now
/// a property of the module boundary itself; the replacement test below checks the boundary's
/// SHAPE (exactly these two constructors, nothing else `pub(crate)`), not the source text.
mod commitment {
    /// One committed-incentive slot (SPEC §2.6) -- see the re-export's doc comment in the parent
    /// module for the full custody-boundary reasoning; this doc only covers the shape.
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
        /// [`super::super::super::client::RewardsClient`] does NOT adopt `dig.listRewardDistributorCommitments`
        /// in this change, and must not until dig_ecosystem#3342 closes: a released v0.259.0 node's
        /// live RPC does not usefully answer that method, and `REWARD_CHAIN_UNAVAILABLE` conflates "no
        /// such distributor" with "the chain is unreachable" -- exactly this epic's own defect class,
        /// landing on the wire surface a clawback decision would then trust. Wiring the transport now
        /// would pull that ambiguity into a money surface; a prior adoption of this same method was
        /// already deleted once by the dig_ecosystem#3253 gate for a different reason (dropping three
        /// of the SPEC §2.6 result's five fields). So this function has no caller in this crate today,
        /// on purpose -- the `#[allow(dead_code)]` below is that decision made explicit, not a
        /// suppression of an unrelated warning; a caller was deliberately NOT invented to silence it
        /// the wrong way. `commitment::tests::surface_is_exactly_two_constructors_and_four_accessors`
        /// still holds with zero callers: it proves the module's SHAPE, which needs no caller of this
        /// one to be true.
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
        /// a real RPC call, without adding a second production constructor -- see the parent module's
        /// re-export doc for why a second constructor is exactly the gap #3294 closes.
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

        /// SPEC §2.6: the puzzle hash key control over which
        /// [`super::super::super::clawback::ClawbackAuthority`] binds against.
        pub(crate) fn clawback_puzzle_hash(&self) -> [u8; 32] {
            self.clawback_puzzle_hash
        }

        /// SPEC §2.6: the slot's total committed reward, base units.
        pub(crate) fn rewards_base_units(&self) -> u64 {
            self.rewards_base_units
        }

        /// SPEC §2.6: the chain's own already-computed recoverable share, base units -- never
        /// recomputed from a compiled-in bps constant (see the parent module's re-export doc,
        /// clause-2 paragraph).
        pub(crate) fn recoverable_base_units(&self) -> u64 {
            self.recoverable_base_units
        }
    }

    #[cfg(test)]
    mod tests {
        use super::RewardDistributorCommitment;

        /// Compile-level proof [`RewardDistributorCommitment`] carries exactly these four fields --
        /// all four or none, per SPEC §2.6 clause 2. A `..` pattern would still compile if a fifth
        /// field silently reintroduced a pre-computed share; this pattern has no `..`. Runs INSIDE
        /// `commitment`, the only place a struct literal is legal at all.
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

        /// Replaces `no_construction_site_of_the_commitment_sits_outside_cfg_test` (dig_ecosystem#3294,
        /// deleted on PR #410 after a `type Alias = RewardDistributorCommitment;` PoC defeated its
        /// text scan): rather than searching source text for spellings of a construction site, this
        /// checks the module's SHAPE compiles with EXACTLY the two sanctioned constructors and no
        /// third. A future `pub(crate) fn forge(..) -> Self` added anywhere in this `impl` block would
        /// not change what this test asserts -- it would still compile -- which is why the real
        /// enforcement is `rustc`'s `E0451` on every OTHER module (proven by `parse_from_rpc` and
        /// `new_for_test` being reachable only through this module, and by every non-test caller in
        /// the crate going through `parse_from_rpc` alone, which `cargo doc`/a reviewer reading this
        /// ~90-line module can confirm directly). This test's job is narrower and still worth having:
        /// naming both constructors here means a third one added beside them is a diff a reviewer
        /// sees, not a fact only the compiler enforces silently.
        #[test]
        fn surface_is_exactly_two_constructors_and_four_accessors() {
            let value = RewardDistributorCommitment::new_for_test(0, [0; 32], 0, 0);
            let _: u64 = value.epoch_start();
            let _: [u8; 32] = value.clawback_puzzle_hash();
            let _: u64 = value.rewards_base_units();
            let _: u64 = value.recoverable_base_units();
        }
    }
}

/// One committed-incentive slot as read directly off a live chain walk (SPEC §2.6), distinct from
/// `RewardDistributorCommitment`: that type mirrors an RPC reply this crate cannot call yet
/// (dig_ecosystem#3342); this one is built straight from
/// `dig_rewards_coin::state::DistributorSnapshot::slots().commitments` by
/// [`commitments_reading_from_slots`].
///
/// # This deliberately carries NO recoverable-share figure (dig_ecosystem#3439)
///
/// An earlier revision of this type computed `recoverable_base_units` in-app as
/// `rewards_base_units * observed withdrawal_share_bps / 10_000` via
/// `dig_rewards_coin::recoverable_base_units`. dig_ecosystem#3439 (priority:1-high, confirmed at
/// the admitted rung against a real validator) found that formula reports a nonzero recoverable
/// amount for a commitment the chain will still refuse: a clawback against an epoch that has
/// already started is rejected by the puzzle's own compiled-in
/// `ASSERT_BEFORE_SECONDS_ABSOLUTE(epoch_start)`, which the bare bps arithmetic takes no account
/// of. Quoting a recoverable figure the chain will not actually pay is worse than quoting nothing —
/// it offers the user money they cannot accept, at the moment they are deciding about money (same
/// rule as dig_ecosystem#3427). This type therefore carries only the raw, chain-observed fields;
/// no derived recoverable amount is computed, carried or rendered until #3439 closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedSlot {
    /// SPEC §2.6: when the committed epoch started.
    pub epoch_start: u64,
    /// SPEC §2.6: the puzzle hash key control over the clawback.
    pub clawback_puzzle_hash: [u8; 32],
    /// SPEC §2.6: the slot's total committed reward, base units.
    pub rewards_base_units: u64,
}

/// The closed set of outcomes reading a distributor's committed-incentive slots can reach
/// (dig_ecosystem#3290, SPEC §2.6 clause 5): *"The surface MUST distinguish 'nothing is
/// recoverable, because nothing was committed' from 'the commitments could not be read.'"* Before
/// this type, dig-app had no representation of either state — [`super::clawback::ProvenClawback::open`]
/// had no production caller, and no commitment-collection type existed anywhere in this crate.
///
/// # Why this is its own four-variant enum, not `super::node_status::PaneReading<Vec<CommittedSlot>>`
///
/// `PaneReading<T>`'s `Answered(Option<T>)` shape would collapse "read the distributor, it exists,
/// it has zero commitments" and "no distributor exists to read commitments from" into the same
/// `Answered(None)` — exactly the distinction clause 5 requires. This enum keeps them apart:
/// [`Self::NoDistributor`] and [`Self::NothingCommitted`] are different variants, never the same
/// `Option::None` read two ways.
///
/// # Why this does NOT collapse the way `EntrySetReading::Empty` does (SPEC §12.5 clause 7)
///
/// [`super::reading::EntrySetReading::Empty`] collapses "zero entries" against "the historical
/// count that emptied it" because clause 7 forbids reconstructing per-item history from present
/// state — a different axis than this type's split. Clause 5 asks the opposite of clause 7 here:
/// it forbids collapsing "the read succeeded and found nothing" against "the read did not
/// succeed," which is not a history question at all, only a question about THIS read's own
/// outcome. Nothing in this type reconstructs which past events emptied a set; it never even
/// establishes that one is empty out of a formerly non-empty history — clause 7 is not in tension
/// with clause 5 here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentsReading {
    /// The chain source could not answer the read at all (transport, timeout, malformed) — never
    /// rendered as though nothing were committed. Carries a static reason from a closed set, never the
    /// chain source's own text (a peer's words; see `chain_read.rs`).
    Unreadable(&'static str),
    /// The distributor itself does not exist per this chain source. Distinct from
    /// [`Self::NothingCommitted`]: there is no distributor to have committed anything.
    NoDistributor,
    /// The distributor exists and was read successfully, and currently has zero outstanding
    /// commitment slots. Distinct from [`Self::Unreadable`]: this is a real, successful answer,
    /// not a failure to answer.
    NothingCommitted {
        /// The chain view this answer reflects — never "now" (SPEC §2.4's staleness rule).
        observed_at: u64,
    },
    /// The distributor exists, was read successfully, and has at least one outstanding commitment
    /// slot.
    Committed {
        /// Every outstanding commitment slot, in the order the chain walk returned them. Carries
        /// no recoverable-share figure — see [`CommittedSlot`]'s doc, dig_ecosystem#3439.
        slots: Vec<CommittedSlot>,
        /// The chain view this answer reflects — never "now" (SPEC §2.4's staleness rule).
        observed_at: u64,
        /// The distributor's current epoch length in seconds, as read off this same chain walk.
        epoch_seconds: u64,
    },
}

/// Maps a chain-read distributor's commitment slots to a [`CommitmentsReading`] — the pure part of
/// the #3290 read, split out from the chain walk itself so it is directly unit-testable against
/// hand-built [`chia_sdk_types::puzzles::RewardDistributorCommitmentSlotValue`] values, with no
/// `ChainSource` or live chain walk required. [`super::chain_read::commitments_reading`] is the
/// thin glue that calls this after `dig_rewards_coin::state::read_distributor` answers `Ok(Some(_))`.
///
/// Computes no recoverable-share figure — see [`CommittedSlot`]'s doc, dig_ecosystem#3439.
pub fn commitments_reading_from_slots(
    slots: &[chia_sdk_types::puzzles::RewardDistributorCommitmentSlotValue],
    observed_at: u64,
    epoch_seconds: u64,
) -> CommitmentsReading {
    if slots.is_empty() {
        return CommitmentsReading::NothingCommitted { observed_at };
    }
    let committed_slots = slots
        .iter()
        .map(|slot| CommittedSlot {
            epoch_start: slot.epoch_start,
            clawback_puzzle_hash: slot.clawback_ph.into(),
            rewards_base_units: slot.rewards,
        })
        .collect();
    CommitmentsReading::Committed {
        slots: committed_slots,
        observed_at,
        epoch_seconds,
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

    fn commitment_slot(
        epoch_start: u64,
        rewards: u64,
    ) -> chia_sdk_types::puzzles::RewardDistributorCommitmentSlotValue {
        chia_sdk_types::puzzles::RewardDistributorCommitmentSlotValue {
            epoch_start,
            clawback_ph: chia_protocol::Bytes32::from([7u8; 32]),
            rewards,
        }
    }

    /// dig_ecosystem#3290, SPEC §2.6 clause 5: zero commitment slots on a real, successfully-read
    /// distributor is `NothingCommitted`, never collapsed into `Unreadable` or a bare zero.
    #[test]
    fn empty_slots_read_as_nothing_committed_not_unreadable() {
        let reading = commitments_reading_from_slots(&[], 42, 600);
        assert_eq!(
            reading,
            CommitmentsReading::NothingCommitted { observed_at: 42 }
        );
    }

    /// One or more outstanding slots read as `Committed`, carrying every slot's raw fields and no
    /// derived recoverable figure (dig_ecosystem#3439).
    #[test]
    fn nonempty_slots_read_as_committed_with_no_recoverable_figure() {
        let slots = [commitment_slot(100, 5_000), commitment_slot(200, 7_500)];

        let reading = commitments_reading_from_slots(&slots, 42, 600);

        match reading {
            CommitmentsReading::Committed {
                slots: committed,
                observed_at,
                epoch_seconds,
            } => {
                assert_eq!(observed_at, 42);
                assert_eq!(epoch_seconds, 600);
                assert_eq!(committed.len(), 2);
                assert_eq!(committed[0].epoch_start, 100);
                assert_eq!(committed[0].rewards_base_units, 5_000);
                assert_eq!(committed[0].clawback_puzzle_hash, [7u8; 32]);
                assert_eq!(committed[1].epoch_start, 200);
                assert_eq!(committed[1].rewards_base_units, 7_500);
            }
            other => panic!("expected Committed, got {other:?}"),
        }
    }

    /// `Unreadable` and `NothingCommitted` must render as distinct variants, never equal to each
    /// other — the exact distinction SPEC §2.6 clause 5 requires dig-app to carry.
    #[test]
    fn unreadable_and_nothing_committed_are_never_equal() {
        let unreadable = CommitmentsReading::Unreadable("no peer");
        let nothing_committed = CommitmentsReading::NothingCommitted { observed_at: 1 };
        assert_ne!(unreadable, nothing_committed);
    }
}
