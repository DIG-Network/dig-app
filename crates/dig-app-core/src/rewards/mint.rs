//! The reward-distributor MINT seam (dig_ecosystem#3253) — and why this file has no concrete
//! [`DistributorMintDoor`] yet.
//!
//! # This mirrors `account::profile_mint`'s shape, deliberately
//!
//! [`DistributorMintDoor`] and [`DistributorMintAvailability`] follow
//! `crate::account::profile_mint::{ProfileMintDoor, ProfileMintAvailability}` exactly: a trait a
//! surface can hold and test against a double that cannot spend, and an availability enum with a
//! named arm for every reason a mint cannot be offered — never a bare bool, because a bool cannot
//! tell a card WHY to refuse, and a card that cannot say why renders a dead control instead of a
//! reason (`ProfileMintAvailability::NoLineageWalk`'s own doc: *"Offering a mint here spends real
//! XCH on a profile that can never finish."*).
//!
//! # Why there is no concrete implementation, and no card that uses one (dig_ecosystem#3253)
//!
//! A distributor launch is a TWO-CALL chain, not one. [`super::create::Launchable`]'s
//! `into_manager_inner_puzzle` output (a `ManagerInnerPuzzle`) is consumed by
//! `dig_rewards_coin::manager::launch_manager_singleton(ctx, parent_coin_id, inner_puzzle)`
//! (`manager.rs:154-158`), which returns a `LaunchedManagerSingleton` whose `launcher_id()`
//! (`manager.rs:62-74`) feeds a `DistributorLaunchTerms`, which `constants::dig_distributor_constants`
//! (`constants.rs:114-117`) curries into a `RewardDistributorConstants`. THAT is what
//! `dig_rewards_coin::launch::launch_dig_distributor` (0.6.0) actually takes — `&mut SpendContext`,
//! `&Offer`, `first_epoch_start`, the curried `RewardDistributorConstants`, `&ConsensusConstants`,
//! a `LaunchComment` and `now_unix_seconds` (`launch.rs:77-85`) — no `ManagerInnerPuzzle` reaches
//! it directly; the manager singleton and its epoch seconds are already curried into `constants`
//! before this call, per `launch.rs:63-65`. It returns a `LaunchedDistributor` carrying
//! `signature` + `security_coin_secret_key` — an aggregate signature over the SECURITY coin the
//! launch itself creates, plus the ephemeral key the caller must sign with and discard. That
//! covers only the security coin. The `Offer`'s own underlying coin spends — the funder's real
//! XCH/CAT — still need this wallet's ordinary money-path signature before the bundle is
//! complete.
//!
//! **What is actually known, at the exact versions this crate resolves** (per THIS workspace's
//! `Cargo.lock` — `dig-account` pins to `0.27.0`, and `dig-account` 0.27.0 itself resolves
//! `dig-wallet-backend` to `0.31.1`; a claim about either crate that does not name the resolved
//! version is a claim that gets re-litigated against the wrong one, as this module's own doc
//! already has been once):
//!
//! - `dig_account::wallet::enforcer::PolicyAuthorizer::authorize_op` and
//!   `dig_account::wallet::money_signer::{LocalMoneySigner, MoneySigner}::sign_approved` are both
//!   re-exported at `dig-account`'s crate root (`lib.rs`), so both are reachable from
//!   `dig-app-core` with what is already pinned — this is NOT a missing-export gap.
//! - `LocalMoneySigner::required_signatures` (`money_signer.rs`) is key-agnostic: it re-derives
//!   AGG_SIG_ME requirements from `coin_spends` via chia-wallet-sdk's
//!   `SdkRequiredSignature::from_coin_spends`, with no check on the SPENT PUZZLE's type. The
//!   fail-closed guarantee this module previously described as "decodes only standard and CAT
//!   spends" is real, but lives one layer down, in `dig-wallet-backend` 0.31.1's `analyze`
//!   (`client/verify.rs`) — and it is a per-coin-spend dispatch, not a blanket refusal: a CAT send
//!   (`Cat::parse`) and a standard XCH send (`StandardLayer::parse_puzzle`) both decode cleanly,
//!   and `is_protocol_sink_hash` (`verify.rs:224-234`) recognizes `SINGLETON_LAUNCHER_HASH`
//!   itself as a SANCTIONED egress (the same allow-list entry a `SETTLEMENT_PAYMENT_HASH` offer
//!   payment gets) — not a refusal. A distributor launch's FUNDER spends (the `Offer`'s own
//!   CAT/XCH sends) are therefore plausibly ordinary, analyzable shapes.
//! - The precise per-spend dispatch and refusal mechanism in `dig-wallet-backend` 0.31.1's
//!   `client/verify.rs` for either leg of the two-call chain above has **not** been established
//!   by this module. What is known is stated above: a candidate seam exists and is reachable,
//!   and it is unproven for this shape. Establishing which arm of `client/verify.rs` receives
//!   each spend of the two-call chain, and what refuses it, is the first task of the unit that
//!   builds the mint — tracked as dig_ecosystem#3340, **not something to be inherited from this
//!   comment.**
//!
//! **What is genuinely unproven, not merely undocumented:**
//!
//! - Whether `PolicyAuthorizer::authorize_op` + `LocalMoneySigner::sign_approved` can be called
//!   over ONLY the `Offer`'s funder coin spends — excluding the launch's own singleton-creation
//!   spends, which `launch_dig_distributor` already signs itself via the returned `signature` /
//!   `security_coin_secret_key` — and produce a signature that aggregates correctly with that
//!   returned signature into one broadcastable `SpendBundle`. Nothing in this crate has attempted
//!   that split, and nothing in `dig-account` or `dig-wallet-backend`'s docs states it is
//!   supported or forbidden.
//! - Whether `enforce_bundle_nft_mint_binding` / `enforce_bundle_settlement_binding` (both run
//!   unconditionally inside `analyze`) impose any additional cross-coin requirement on a
//!   partial-bundle call (funder spends only, launch spends withheld) that a full-bundle call
//!   would not hit — this has not been read closely enough to rule in or out.
//!
//! This module therefore does **not** claim dig-account has no seam. It claims a candidate seam
//! exists, is reachable, and is unproven for this exact shape — and that hand-rolling a signer
//! here instead of finishing that proof is the custody violation `crate::chain::publish` and
//! dig-account's own `money_signer` module doc both forbid by name: *"There is deliberately NO
//! bespoke signer path: a hand-rolled spend signer is how custody bugs ship."* This module does
//! not do that, and no card in this crate is wired to a handler that discards a built value
//! instead of pushing it — see dig_ecosystem#3253's own bar: **either the flow signs and pushes,
//! or there is no button.** There is no button.
//!
//! Proving or disproving the candidate seam — and, if it holds, wiring `authorize_op` +
//! `sign_approved` over the funder spends and aggregating with `launch_dig_distributor`'s own
//! signature into a `SpendBundle` for [`crate::chain::publish::ControlSpendPublisher`] — is next
//! unit's work, not this one's. This module states the shape the seam will hold either way.

/// The one door a distributor mint may be driven through, once the candidate signing seam this
/// module's doc describes is proven (or a dig-account-side seam replaces it) — mirrors
/// `ProfileMintDoor`'s `begin` / `status` / `liveness` shape; `advance` and `record` have no
/// distributor analogue: a distributor launch is ONE bundle, not a two-phase ceremony, so there
/// is no second push to advance and no confirmed-evidence type to record beyond what `status`
/// already reports.
///
/// **No concrete implementor exists in this crate.** See this module's doc comment for why: the
/// funder-spend signing half of `begin` has not been proven reachable yet. Sealed
/// (`private::Sealed`) so that remains true by construction, not by convention — an external
/// crate cannot supply a fake implementor that reports `Possible` with nothing behind it, the
/// same shape of defect dig_ecosystem#3253 withdrew a whole PR over. A surface may hold
/// `Option<&dyn DistributorMintDoor>` and get `None` on every build, exactly as
/// `ProfileMintSeams::door` returns `None` on a build that cannot finish phase B.
pub trait DistributorMintDoor: private::Sealed {
    /// Consume a proven [`Launchable`](super::create::Launchable) choice, build the launch spend,
    /// sign it, and push it. Spends real XCH the moment this returns `Ok`, or a partial amount if
    /// the push itself is refused before broadcast (see `crate::chain::publish::PublishFailure`,
    /// which this seam's concrete implementation must route any push failure through unchanged).
    ///
    /// Takes `self` by value, not `&self`: a distributor launch is a single irreversible action,
    /// and a door that survived `begin` would invite a second call reusing the same
    /// `Launchable` — which `Launchable::into_manager_inner_puzzle` already makes impossible to
    /// construct twice from one witness chain, but a reusable `&self` door would still invite a
    /// caller to try. Consuming the door too closes that at the type level, not by convention.
    fn begin(
        self,
        launchable: super::create::Launchable,
    ) -> Result<DistributorMintStatus, DistributorMintError>;

    /// Where a previously begun mint stands, without spending, pushing or writing.
    fn status(&self) -> Result<DistributorMintStatus, DistributorMintError>;

    /// How alive an in-flight launch bundle looks, or `None` when nothing is in flight.
    fn liveness(&self) -> Option<DistributorMintLiveness>;
}

/// The sealing boundary for [`DistributorMintDoor`] — `private` is not `pub`, so
/// `private::Sealed` cannot be named, let alone implemented, outside this crate. This is what
/// makes "no external implementor" a fact the compiler enforces rather than a claim this module's
/// prose makes on its own; a `pub trait` with no such supertrait can be implemented by anyone who
/// can name it, no matter what its doc comment asserts.
mod private {
    /// No public constructor, no public methods, no external path to `impl` this trait's only
    /// implementors: this crate's own future concrete `DistributorMintDoor`s.
    pub trait Sealed {}
}

/// Placeholder outcome shape — narrowed to the real evidence type once a concrete
/// [`DistributorMintDoor`] exists to produce one.
///
/// `#[non_exhaustive]` here blocks external EXHAUSTIVE MATCHING only — it forces any downstream
/// `match` to carry a wildcard arm, so adding the real evidence variant later cannot break a
/// caller outside this crate. It does **not** block construction: `NotYetImplemented` is a public
/// unit variant, and `#[non_exhaustive]` has no effect on a unit variant's constructibility (only
/// struct-like variants with fields gain a construction restriction from it). Nothing in this
/// crate needs `DistributorMintStatus` to be unconstructible from outside — the type this module
/// actually needs unconstructible is [`DistributorMintDoor`] itself, sealed above by
/// `private::Sealed`, which real sealing (not an enum attribute) is required to achieve.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintStatus {
    /// Reserved for the concrete implementation this module cannot yet provide.
    NotYetImplemented,
}

/// Reserved for the concrete implementation this module cannot yet provide — mirrors
/// `account::profile_mint::MintLiveness`'s no-threshold discipline: an unbuilt door reports no
/// liveness at all rather than inventing one. See [`DistributorMintStatus`]'s doc comment for
/// exactly what `#[non_exhaustive]` does and does not guarantee here.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintLiveness {
    /// Reserved for the concrete implementation this module cannot yet provide.
    NotYetImplemented,
}

/// Reserved for the concrete implementation this module cannot yet provide. See
/// [`DistributorMintStatus`]'s doc comment for exactly what `#[non_exhaustive]` does and does not
/// guarantee here.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintError {
    /// No concrete [`DistributorMintDoor`] exists in this crate yet to route through. Not a
    /// network fault, not an account-state refusal — a capability this BUILD does not have, of
    /// the same kind `ProfileMintAvailability::NoLineageWalk` reports for phase B of a profile
    /// mint.
    NoSigningSeam,
}

/// Whether this build can mint a reward distributor, and when it cannot, why — mirrors
/// `ProfileMintAvailability` exactly: a named arm per refusal, never a bare bool, so a card can
/// render the REASON instead of a dead control.
///
/// Every build today reports [`Self::NoSigningSeam`]. There is no code path in this crate that
/// can produce [`Self::Possible`] until a concrete [`DistributorMintDoor`] exists, and no
/// concrete `DistributorMintDoor` can exist until this module's doc comment's candidate seam is
/// proven (or a dig-account-side seam replaces it).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorMintAvailability {
    /// A distributor mint may be attempted.
    ///
    /// Unreachable today
    /// (`current_availability_is_never_possible_while_no_door_exists` below pins that). Kept as a
    /// named arm so a future concrete `DistributorMintDoor` slots into the SAME enum this module
    /// already defines, rather than a card growing a second, drifted copy of this decision the
    /// way dig_ecosystem#2377 measured for the profile gate.
    Possible,
    /// No concrete [`DistributorMintDoor`] exists in this crate. See this module's doc comment.
    /// **This is the only value this build can currently report.**
    NoSigningSeam,
}

impl DistributorMintAvailability {
    /// The only answer this build can give until a concrete [`DistributorMintDoor`] exists.
    ///
    /// A free function rather than tied to any door, because there is no door to ask: unlike
    /// `ProfileMintSeams::probe`, which reads the CHAIN, this reads a CAPABILITY GAP in this
    /// crate, which is fixed at compile time, not at runtime. A future revision that adds a
    /// concrete `DistributorMintDoor` replaces this function's caller, not this function — the
    /// pinned unavailability stays correct describing the builds before that door lands.
    pub const fn current() -> Self {
        Self::NoSigningSeam
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this whole module exists to prevent: a build that reports `Possible`
    /// with no door to back it, which is exactly the shape of a card whose Sign handler
    /// discards its result (the defect dig_ecosystem#3253 withdrew a whole PR over).
    #[test]
    fn current_availability_is_never_possible_while_no_door_exists() {
        assert_eq!(
            DistributorMintAvailability::current(),
            DistributorMintAvailability::NoSigningSeam,
            "no concrete DistributorMintDoor exists in this crate; Possible must never be \
             reachable until one does"
        );
    }
}
