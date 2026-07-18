//! The onboarding gate — the ORDERED `wallet → profile → ready` wizard that governs whether the
//! dig-peer is usable yet (SG-0 of epic [dig_ecosystem#986]).
//!
//! A fresh dig-app has no identity: it holds no wallet and no profile. The social surfaces the epic
//! builds on — requesting a peer's profile, exchanging profiles, being "connected" — are meaningless
//! until the user has both a wallet (to fund/anchor an identity) and at least one profile (the
//! [`IdentityProfile`] a peer would exchange). This module models that as one small state machine and
//! a gate the downstream peer operations consult, so "is the peer usable yet?" has exactly one answer
//! in exactly one place.
//!
//! # The ordering is the point
//!
//! The two prerequisites are strictly ordered — a wallet FIRST, then a profile:
//!
//! - [`OnboardingState::NeedsWallet`] — nothing yet; the user must import or create a wallet.
//! - [`OnboardingState::NeedsProfile`] — a wallet exists but no profile does; the user must create
//!   one. (Creating a profile mints a `did:chia:` DID, which is gated on the on-chain mint spend —
//!   the [`DidMinter`](crate::profiles::DidMinter) seam, held on dig-identity #771 via
//!   [`HeldDidMinter`](crate::profiles::HeldDidMinter). The wizard step exists now; the mint itself
//!   returns an explicit held error until #771 lands, so the flow is wired but cannot fake a mint.)
//! - [`OnboardingState::Ready`] — a wallet and ≥1 profile exist; the dig-peer is usable.
//!
//! The state is a pure function of two observed facts ([`OnboardingState::evaluate`]), so it is fully
//! testable without a wallet, a keystore, or the network. The app observes the wallet fact through the
//! [`WalletPresence`] seam and the profile count from the [`ProfileManager`](crate::profiles::ProfileManager),
//! then gates each peer operation on [`OnboardingState::require_ready`].
//!
//! [dig_ecosystem#986]: https://github.com/DIG-Network/dig_ecosystem/issues/986
//! [`IdentityProfile`]: dig_identity

/// Where the user is in the ordered onboarding wizard — the single source of truth for whether the
/// dig-peer (social / profile-exchange surfaces) is usable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingState {
    /// No wallet has been imported or created yet — the first, blocking step. The peer is unusable
    /// and every downstream social operation is refused until a wallet exists.
    NeedsWallet,
    /// A wallet exists but no profile (identity) does yet — the second, blocking step. The peer is
    /// still unusable: there is no profile to present to, or exchange with, another peer.
    NeedsProfile,
    /// A wallet and at least one profile exist — the dig-peer is usable.
    Ready,
}

impl OnboardingState {
    /// Derives the onboarding state from the two observed prerequisites: whether a wallet exists and
    /// how many profiles exist. This is the whole gate logic as a pure function — a wallet is required
    /// first, then a profile — so it can be exhaustively unit-tested without any I/O.
    pub fn evaluate(has_wallet: bool, profile_count: usize) -> Self {
        match (has_wallet, profile_count) {
            (false, _) => OnboardingState::NeedsWallet,
            (true, 0) => OnboardingState::NeedsProfile,
            (true, _) => OnboardingState::Ready,
        }
    }

    /// Derives the onboarding state from a live [`WalletPresence`] seam and an observed profile count
    /// — the wiring the app uses at run time. Thin sugar over [`evaluate`](Self::evaluate).
    pub fn resolve(wallet: &dyn WalletPresence, profile_count: usize) -> Self {
        Self::evaluate(wallet.wallet_present(), profile_count)
    }

    /// Whether the dig-peer is usable (a wallet and ≥1 profile exist).
    pub fn is_ready(&self) -> bool {
        matches!(self, OnboardingState::Ready)
    }

    /// The gate every downstream peer/social operation consults: `Ok(())` when the peer is usable, or
    /// the specific [`OnboardingError`] naming the next required step so the caller (or UI) can route
    /// the user to it.
    pub fn require_ready(self) -> Result<(), OnboardingError> {
        match self {
            OnboardingState::Ready => Ok(()),
            OnboardingState::NeedsWallet => Err(OnboardingError::WalletRequired),
            OnboardingState::NeedsProfile => Err(OnboardingError::ProfileRequired),
        }
    }
}

/// The reason the dig-peer is not yet usable — one variant per blocking onboarding step, so a caller
/// reacts precisely and a UI can deep-link to the exact next step rather than a generic "not ready".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OnboardingError {
    /// A wallet must be imported or created before the dig-peer can be used.
    #[error("a wallet must be imported or created before the dig-peer can be used")]
    WalletRequired,
    /// A wallet exists, but a profile must be created before the dig-peer can be used.
    #[error("a profile must be created before the dig-peer can be used")]
    ProfileRequired,
}

/// Observes whether the user has a wallet — the first onboarding prerequisite.
///
/// A seam (rather than a concrete check) so the onboarding logic stays pure and testable: the app
/// supplies the real detection (the presence of a sealed wallet key), while tests supply a fixed
/// answer. Keeping this abstract also means the gate does not couple to how wallet custody is stored.
pub trait WalletPresence {
    /// Whether a wallet exists for this dig-app (import-or-create has completed at least once).
    fn wallet_present(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double whose wallet-presence answer is fixed at construction.
    struct FixedWallet(bool);
    impl WalletPresence for FixedWallet {
        fn wallet_present(&self) -> bool {
            self.0
        }
    }

    // --- the ordered gate transitions ------------------------------------------------------------

    #[test]
    fn no_wallet_needs_a_wallet_regardless_of_profile_count() {
        // A wallet is the FIRST prerequisite: without it the state is NeedsWallet even if (somehow)
        // profiles are reported — the ordering is strict.
        assert_eq!(
            OnboardingState::evaluate(false, 0),
            OnboardingState::NeedsWallet
        );
        assert_eq!(
            OnboardingState::evaluate(false, 3),
            OnboardingState::NeedsWallet
        );
    }

    #[test]
    fn wallet_but_no_profile_needs_a_profile() {
        assert_eq!(
            OnboardingState::evaluate(true, 0),
            OnboardingState::NeedsProfile
        );
    }

    #[test]
    fn wallet_and_at_least_one_profile_is_ready() {
        assert_eq!(OnboardingState::evaluate(true, 1), OnboardingState::Ready);
        assert_eq!(OnboardingState::evaluate(true, 5), OnboardingState::Ready);
    }

    // --- the gate blocks/permits downstream peer use ---------------------------------------------

    #[test]
    fn require_ready_blocks_peer_use_before_a_wallet() {
        assert_eq!(
            OnboardingState::NeedsWallet.require_ready(),
            Err(OnboardingError::WalletRequired)
        );
    }

    #[test]
    fn require_ready_blocks_peer_use_before_a_profile() {
        assert_eq!(
            OnboardingState::NeedsProfile.require_ready(),
            Err(OnboardingError::ProfileRequired)
        );
    }

    #[test]
    fn require_ready_permits_peer_use_when_ready() {
        assert_eq!(OnboardingState::Ready.require_ready(), Ok(()));
        assert!(OnboardingState::Ready.is_ready());
        assert!(!OnboardingState::NeedsWallet.is_ready());
        assert!(!OnboardingState::NeedsProfile.is_ready());
    }

    // --- resolution through the live seam --------------------------------------------------------

    #[test]
    fn resolve_walks_the_full_journey_through_the_seam() {
        // No wallet → NeedsWallet, whatever the profile count.
        assert_eq!(
            OnboardingState::resolve(&FixedWallet(false), 0),
            OnboardingState::NeedsWallet
        );
        // Wallet, no profile → NeedsProfile.
        assert_eq!(
            OnboardingState::resolve(&FixedWallet(true), 0),
            OnboardingState::NeedsProfile
        );
        // Wallet + a profile → Ready.
        assert_eq!(
            OnboardingState::resolve(&FixedWallet(true), 1),
            OnboardingState::Ready
        );
    }
}
