//! The onboarding gate — the ORDERED wallet → profile → ready wizard that governs whether the
//! dig-peer (social / profile-exchange surfaces, epic dig_ecosystem#986) is usable yet.
//!
//! WIP (SG-0, #986): the [`OnboardingState`] model + gate land here.

/// Where the user is in the ordered onboarding wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingState {
    /// No wallet has been imported or created yet — the first, blocking step.
    NeedsWallet,
    /// A wallet exists but no profile (identity) does yet — the second, blocking step.
    NeedsProfile,
    /// A wallet and at least one profile exist — the dig-peer is usable.
    Ready,
}
