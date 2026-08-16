//! Whether the app may OFFER to edit a profile, and — when it may not — which piece is missing.
//!
//! # Why this is a reading and not a boolean
//!
//! `ProfileCreation` (`crate::profiles`) records the lesson this type inherits: an unmeasured
//! capability and a measured blocker are different facts, and drawing the first as the second names
//! a cause nobody observed. A person whose node is merely still starting would be told *this version
//! of DIG cannot edit profiles*, which is false and leaves them without the one action that helps.
//!
//! So [`Unknown`](ProfileEditing::Unknown) withholds the offer exactly as a blocker does — the safe
//! direction is identical — and differs only in what the surface SAYS while it waits.

use super::commit::EditSeams;

/// What is in the way of editing a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditBlocked {
    /// This build cannot read chain or push a bundle, so no profile can be edited on this machine.
    NoChainTransport,
    /// This account holds no profile, so there is nothing to edit. Creating one is the remedy, and
    /// it lives one card up.
    NoProfile,
    /// The account is locked, so nothing can be signed.
    Locked,
}

impl EditBlocked {
    /// Every blocker, so a sweep over them cannot fall behind the enum.
    ///
    /// `CreationBlocked::EVERY`'s reason: the Account pane's one-sentence-set guard walks this
    /// list, and a hand-listed version there drifted the moment a third arm arrived.
    pub const EVERY: [Self; 3] = [Self::NoChainTransport, Self::NoProfile, Self::Locked];

    /// The sentence a surface shows, which always names the remedy — a statement that something
    /// cannot be done, with no door named, is the dead end dig_ecosystem#1800 removed.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::NoChainTransport => {
                "This version of DIG cannot reach the blockchain to change a profile. Install a \
                 newer DIG and a newer node, and this becomes available."
            }
            Self::NoProfile => {
                "You do not have a profile yet. Set up a profile in the card above, and you can \
                 fill it in here."
            }
            Self::Locked => {
                "Your account is locked, so DIG cannot sign a change. Unlock it to edit your \
                 profile."
            }
        }
    }
}

/// Whether a profile can be edited here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileEditing {
    /// **Nobody has measured this yet.** Not a failure and not a capability.
    #[default]
    Unknown,
    /// A seam, a profile and an unlocked account: an edit can really be attempted.
    ///
    /// Reachable only through [`of_seams`](Self::of_seams), so this arm cannot be asserted beside
    /// the capability — it can only be read off it.
    Possible,
    /// Editing cannot be attempted, and this is the piece that is missing.
    Blocked(EditBlocked),
}

impl ProfileEditing {
    /// Read the offer off the seams that exist, plus the two facts the seams cannot know.
    ///
    /// `has_profile` and `unlocked` are the caller's, because a seam is about this BUILD while both
    /// of those are about this MOMENT: an account locks and unlocks under a seam that never changes.
    pub fn of_seams(seams: &EditSeams, has_profile: bool, unlocked: bool) -> Self {
        match (seams.is_possible(), has_profile, unlocked) {
            (false, _, _) => Self::Blocked(EditBlocked::NoChainTransport),
            (true, false, _) => Self::Blocked(EditBlocked::NoProfile),
            (true, true, false) => Self::Blocked(EditBlocked::Locked),
            (true, true, true) => Self::Possible,
        }
    }

    /// Whether the editor's verbs may be offered. Keyed on the ARM: an `Unknown` reading must
    /// withhold the offer exactly as a blocker does.
    pub fn is_possible(self) -> bool {
        matches!(self, Self::Possible)
    }

    /// What is in the way, when something measured is.
    pub fn blocked(self) -> Option<EditBlocked> {
        match self {
            Self::Blocked(why) => Some(why),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wired() -> EditSeams {
        EditSeams::Wired {
            seam: std::sync::Arc::new(super::super::commit::tests_support::NeverSeam),
            bodies: std::sync::Arc::new(super::super::commit::tests_support::NeverBodies),
        }
    }

    /// The default has measured nothing, and withholds the offer as firmly as a blocker.
    #[test]
    fn an_unmeasured_offer_says_nothing_and_offers_nothing() {
        let unknown = ProfileEditing::default();
        assert_eq!(unknown, ProfileEditing::Unknown);
        assert!(!unknown.is_possible());
        assert!(
            unknown.blocked().is_none(),
            "an unmeasured reading named a cause nobody observed"
        );
    }

    /// The three blockers, each read off the state that actually causes it — and in the order a
    /// person can act on them: a build that cannot reach chain is not helped by being told to
    /// unlock.
    #[test]
    fn each_missing_piece_is_named_by_the_state_that_causes_it() {
        assert_eq!(
            ProfileEditing::of_seams(&EditSeams::NoChainTransport, true, true).blocked(),
            Some(EditBlocked::NoChainTransport)
        );
        assert_eq!(
            ProfileEditing::of_seams(&wired(), false, true).blocked(),
            Some(EditBlocked::NoProfile)
        );
        assert_eq!(
            ProfileEditing::of_seams(&wired(), true, false).blocked(),
            Some(EditBlocked::Locked)
        );
        assert!(ProfileEditing::of_seams(&wired(), true, true).is_possible());
    }

    /// A transport-less build is told about its transport even while it is also locked: naming the
    /// unlock would send a person to do something that changes nothing.
    #[test]
    fn the_deepest_blocker_is_the_one_reported() {
        assert_eq!(
            ProfileEditing::of_seams(&EditSeams::NoChainTransport, false, false).blocked(),
            Some(EditBlocked::NoChainTransport)
        );
    }

    /// Every blocker names a door.
    #[test]
    fn every_blocker_names_a_remedy() {
        for blocked in EditBlocked::EVERY {
            assert!(
                crate::window_model::label_names_a_remedy(blocked.sentence()),
                "{blocked:?} names no remedy: {}",
                blocked.sentence()
            );
        }
    }
}
