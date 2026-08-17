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
    /// # Why the lock is reported FIRST, ahead of a missing transport
    ///
    /// While the account is locked, the other two facts are not measurements — they are consequences
    /// of the lock. The shell derives both from the ACTIVE profile, and a locked account has no
    /// active profile to derive them from, so the seams stay uninstalled and `has_profile` reads
    /// false on a machine that holds a profile and a working node alike.
    ///
    /// Reporting the transport there is a fabrication about the BUILD: it told a person whose only
    /// problem was a locked account to *install a newer DIG and a newer node*
    /// (dig_ecosystem#3057). Naming the unlock first is honest at every step — it is true right now,
    /// it is the one act that helps, and a genuinely missing transport is still named the moment the
    /// unlock has made that a thing anybody has measured.
    pub fn of_seams(seams: &EditSeams, has_profile: bool, unlocked: bool) -> Self {
        match (unlocked, seams.is_possible(), has_profile) {
            (false, _, _) => Self::Blocked(EditBlocked::Locked),
            (true, false, _) => Self::Blocked(EditBlocked::NoChainTransport),
            (true, _, false) => Self::Blocked(EditBlocked::NoProfile),
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

    /// **A locked account is told to unlock, never that its build cannot reach the chain**
    /// (dig_ecosystem#3057).
    ///
    /// The fixture is the state a real locked machine is actually in, and that is the whole point:
    /// the shell installs the edit seams from the ACTIVE profile, and a locked account has none — so
    /// `EditSeams::NoChainTransport` with `has_profile: false` is what a perfectly healthy machine
    /// reports while its account is locked, NOT a measurement of the build. Reading the transport off
    /// it told those people to *install a newer DIG and a newer node*.
    ///
    /// # Why the unlocked control is load-bearing
    ///
    /// "Locked always wins" and "the transport blocker was deleted" are indistinguishable from the
    /// locked leg alone. The control is the SAME seams, unlocked: there the missing transport is a
    /// real measurement and must still be named, because that person genuinely does need a newer
    /// build and telling them to unlock an already-open account helps nobody.
    #[test]
    fn a_locked_account_is_told_to_unlock_and_an_unlocked_one_still_hears_about_its_transport() {
        assert_eq!(
            ProfileEditing::of_seams(&EditSeams::NoChainTransport, false, false).blocked(),
            Some(EditBlocked::Locked),
            "a locked account was told its build cannot reach the blockchain"
        );

        assert_eq!(
            ProfileEditing::of_seams(&EditSeams::NoChainTransport, false, true).blocked(),
            Some(EditBlocked::NoChainTransport),
            "an unlocked build with no transport lost the sentence that names its real cause"
        );
    }

    /// The sentence a locked account reads names the unlock, and does not send anybody to install
    /// anything — the words the defect actually put on screen.
    #[test]
    fn the_locked_sentence_names_the_unlock_and_no_installation() {
        let said = EditBlocked::Locked.sentence().to_lowercase();
        assert!(said.contains("unlock"), "the locked sentence: {said}");
        assert!(
            !said.contains("install") && !said.contains("newer"),
            "the locked sentence tells a person to install a newer build: {said}"
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
