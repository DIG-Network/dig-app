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
//! A distributor launch is `dig_rewards_coin::launch::launch_dig_distributor` (0.6.0): given a
//! `SpendContext`, an `Offer` and a `ManagerInnerPuzzle` (obtainable ONLY from
//! [`super::create::Launchable::into_manager_inner_puzzle`]), it returns a `LaunchedDistributor`
//! carrying `signature` + `security_coin_secret_key` — an aggregate signature over the SECURITY
//! coin the launch itself creates, plus the ephemeral key the caller must sign with and discard.
//! That covers only the security coin. The `Offer`'s own underlying coin spends — the funder's
//! real XCH/CAT — still need this wallet's ordinary money-path signature before the bundle is
//! complete, and **dig-account 0.27.0 (the exact version this crate depends on) has no seam that
//! provides one**:
//!
//! - `dig_account::wallet::money_signer::LocalMoneySigner` — the general money path — is
//!   documented to **fail closed on a singleton launch by design**: its vetted verifier decodes
//!   only standard and CAT spends (`money_signer.rs`'s own module doc). It refuses a distributor
//!   launch's coin spends outright, correctly.
//! - `ProfileMinter::begin_did_mint` / the private `build_and_sign_store_launch` (`mint/did.rs`,
//!   `mint/store_launch.rs`) are the only OTHER signers dig-account exposes, and both are narrow,
//!   `pub(super)` gates hand-built for `dig-did`'s create spends specifically — not exported, not
//!   generic, and refuse any bundle that is not that exact shape.
//! - `ProfileSigner` (`signer.rs`) is the IDENTITY path only (session-attach, `dign sign`),
//!   explicitly documented as **not** the money path.
//! - Nothing in dig-account 0.27.0 mentions a reward or a distributor at all.
//!
//! Hand-rolling a signer here — pulling a raw wallet key out of the session and signing the
//! `Offer`'s coin spends directly in dig-app-core — is the custody violation
//! `crate::chain::publish` and dig-account's own `money_signer` module doc both forbid by name:
//! *"There is deliberately NO bespoke signer path: a hand-rolled spend signer is how custody bugs
//! ship."* This module does not do that, and no card in this crate is wired to a handler that
//! discards a built value instead of pushing it — see dig_ecosystem#3253's own bar, restated in
//! the ticket that opened this file: **either the flow signs and pushes, or there is no button.**
//! There is no button.
//!
//! What CAN be stated today, without spending anything, is the shape the seam will hold once
//! dig-account grows a `begin_reward_distributor_mint`-style signer mirroring
//! `build_and_sign_store_launch`: build the launch's coin spends, extract
//! `chia_wallet_sdk::signer::RequiredSignature`s, gate to this wallet's own `AGG_SIG_ME`
//! signatures over spends it already owns or the bundle itself creates, sign, aggregate with the
//! `signature`/`security_coin_secret_key` the launch call already returns for the security coin,
//! and hand back a `SpendBundle` for [`crate::chain::publish::ControlSpendPublisher`]. That is a
//! dig-account change, not a dig-app one, and is out of scope for this crate until it lands.

/// The one door a distributor mint may be driven through, once dig-account exposes a launch
/// signer — mirrors `ProfileMintDoor` exactly (`begin` / `status` / `liveness`; `advance` and
/// `record` have no distributor analogue: a distributor launch is ONE bundle, not a two-phase
/// ceremony, so there is no second push to advance and no confirmed-evidence type to record
/// beyond what `status` already reports).
///
/// **No concrete implementor exists in this crate.** See this module's doc comment for why: the
/// signing half of `begin` has nowhere to route to yet. A surface may hold `Option<&dyn
/// DistributorMintDoor>` and get `None` on every build, exactly as
/// `ProfileMintSeams::door` returns `None` on a build that cannot finish phase B.
pub trait DistributorMintDoor {
    /// Build the launch spend, sign it, and push it. Spends real XCH the moment this returns
    /// `Ok`, or a partial amount if the push itself is refused before broadcast (see
    /// `crate::chain::publish::PublishFailure`, which this seam's concrete implementation must
    /// route any push failure through unchanged).
    fn begin(&self) -> Result<DistributorMintStatus, DistributorMintError>;

    /// Where a previously begun mint stands, without spending, pushing or writing.
    fn status(&self) -> Result<DistributorMintStatus, DistributorMintError>;

    /// How alive an in-flight launch bundle looks, or `None` when nothing is in flight.
    fn liveness(&self) -> Option<DistributorMintLiveness>;
}

/// Placeholder outcome shape — narrowed to the real evidence type once a concrete
/// [`DistributorMintDoor`] exists to produce one. Left deliberately unconstructible outside this
/// module (`#[non_exhaustive]`, no variant public constructor beyond the enum itself) so nothing
/// downstream can manufacture a false "confirmed" without the door that would have proven it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintStatus {
    /// Reserved for the concrete implementation this module cannot yet provide.
    NotYetImplemented,
}

/// Reserved for the concrete implementation this module cannot yet provide — mirrors
/// `account::profile_mint::MintLiveness`'s no-threshold discipline: an unbuilt door reports no
/// liveness at all rather than inventing one.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintLiveness {
    /// Reserved for the concrete implementation this module cannot yet provide.
    NotYetImplemented,
}

/// Reserved for the concrete implementation this module cannot yet provide.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintError {
    /// dig-account exposes no seam to sign a reward-distributor launch bundle. See this module's
    /// doc comment for the exact gap. Not a network fault, not an account-state refusal — a
    /// capability this BUILD does not have, of the same kind `ProfileMintAvailability::
    /// NoLineageWalk` reports for phase B of a profile mint.
    NoSigningSeam,
}

/// Whether this build can mint a reward distributor, and when it cannot, why — mirrors
/// `ProfileMintAvailability` exactly: a named arm per refusal, never a bare bool, so a card can
/// render the REASON instead of a dead control.
///
/// Every build today reports [`Self::NoSigningSeam`]. There is no code path in this crate that
/// can produce [`Self::Possible`] until a concrete [`DistributorMintDoor`] exists, and no
/// concrete `DistributorMintDoor` can exist until dig-account grows the seam this module's doc
/// comment describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorMintAvailability {
    /// A distributor mint may be attempted.
    ///
    /// Unreachable today (`always_reports_no_signing_seam` below pins that). Kept as a named arm
    /// so a future concrete `DistributorMintDoor` slots into the SAME enum this module already
    /// defines, rather than a card growing a second, drifted copy of this decision the way
    /// dig_ecosystem#2377 measured for the profile gate.
    Possible,
    /// dig-account has no seam to sign a reward-distributor launch. See this module's doc
    /// comment. **This is the only value this build can currently report.**
    NoSigningSeam,
}

impl DistributorMintAvailability {
    /// The only answer this build can give until dig-account grows a launch signer.
    ///
    /// A free function rather than tied to any door, because there is no door to ask: unlike
    /// `ProfileMintSeams::probe`, which reads the CHAIN, this reads a CAPABILITY GAP in a
    /// dependency version, which is fixed at compile time, not at runtime. A future revision
    /// that adds a concrete `DistributorMintDoor` replaces this function's caller, not this
    /// function — the pinned unavailability stays correct describing the versions before that
    /// dig-account release.
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
