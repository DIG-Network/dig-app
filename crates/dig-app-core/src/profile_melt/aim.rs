//! Which profile a delete press names — and, when none, WHICH of the several different reasons
//! that is (dig_ecosystem#3067).
//!
//! # Why aiming is a value here rather than an `Option` in the shell
//!
//! A deletion is the one irreversible act in this app, so the profile it destroys must be decided
//! by the press and by nothing else. The shell used to decide that inline and answer `Option`: no
//! account, no such profile, and an already-ended profile all collapsed into `None`, and the shell
//! then painted the ONE sentence it had — *"DIG could not reach your node"* — over all three. Two
//! of those are not node faults, and for an already-deleted profile every clause of that sentence
//! is false and its remedy can never work.
//!
//! So the answers are separate values, each with its own sentence and its own next step, decided
//! here where a test can reach them. The shell's remaining job is to hand over the index the person
//! pressed.

use dig_account::registry::{ProfileAnchor, ProfileRegistry};
use dig_account::ProfileIx;

/// Why a deletion cannot be aimed at anything, in the terms a person can act on.
///
/// **One variant per REMEDY**, the rule the rest of this crate's reading types follow: the reason is
/// the only thing that tells a person what to do, and a wrong one sends them to fix something that
/// is not broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeltUnaimed {
    /// No unlocked account, so there is no registry to look a profile up in.
    NoAccount,
    /// No node endpoint to read the chain through or push a spend to.
    NoNode,
    /// This account holds no confirmed profile at that index.
    NotOnThisAccount,
    /// The profile at that index has already ended on chain.
    ///
    /// Reachable because a list drawn a moment ago can outlive the profile it lists — a second
    /// window, or a melt this app itself confirmed between the draw and the press.
    AlreadyEnded,
}

impl MeltUnaimed {
    /// What is true, said without claiming anything about the chain that is not.
    pub fn says(self) -> &'static str {
        match self {
            Self::NoAccount => "DIG could not open this account to delete a profile.",
            Self::NoNode => "DIG could not reach your node to delete this profile.",
            Self::NotOnThisAccount => "That profile is no longer on this account's list.",
            Self::AlreadyEnded => {
                "That profile has already been deleted from the blockchain, so there is nothing \
                 left to delete."
            }
        }
    }

    /// What to do about it. Every arm names a door — a sentence naming none is the dead end
    /// dig_ecosystem#1800 removed once already.
    pub fn next(self) -> &'static str {
        match self {
            Self::NoAccount => {
                "Nothing was deleted and nothing was spent. Unlock DIG and try again."
            }
            Self::NoNode => {
                "Nothing was deleted and nothing was spent. Start your DIG node and try again."
            }
            Self::NotOnThisAccount => {
                "Nothing was deleted. Close and reopen this window to see the current list."
            }
            Self::AlreadyEnded => super::copy::ALREADY_GONE_NEXT,
        }
    }
}

/// The on-chain anchor of the profile at `ix`, or why nothing can be aimed at it.
///
/// The anchor is read from the entry at the index the CONTROL carried, never off the active slot: a
/// deletion aimed by the active slot melts the wrong profile's singletons, and there is no layer
/// below this one that could notice.
///
/// The account being LOCKED is deliberately not tested here — the seam derives its melter per call
/// and answers [`ProfileMeltError::Locked`](super::ProfileMeltError::Locked) itself, so there is one
/// predicate for it rather than a second one that can drift from it.
pub fn aim_at(registry: &ProfileRegistry, ix: ProfileIx) -> Result<ProfileAnchor, MeltUnaimed> {
    let Some(entry) = registry.get(ix) else {
        return Err(MeltUnaimed::NotOnThisAccount);
    };
    match entry.is_live() {
        true => Ok(entry.anchor().clone()),
        false => Err(MeltUnaimed::AlreadyEnded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{expected_store_id, registry_with};
    use dig_account::registry::ProfileEndOutcome;

    /// The store id `aim_at` returned, in the form a surface prints — the value that says WHICH
    /// profile the seam would have melted.
    fn aimed_store_id(registry: &ProfileRegistry, ix: ProfileIx) -> String {
        let anchor = aim_at(registry, ix).expect("a live profile can be aimed at");
        format!("0x{}", hex::encode(anchor.store_launcher_id()))
    }

    /// **A press on a NON-active profile aims at that profile, not at the active one.**
    ///
    /// The fixture is active on `ROOT` and presses index 2, so an implementation that read the
    /// active slot instead of the pressed index returns `ROOT`'s anchor and fails here. A
    /// single-profile fixture — or one whose press happened to land on the active profile — cannot
    /// tell the two apart, which is why there are two profiles and why the pressed one is the
    /// second.
    ///
    /// What it pins is irreversible: the anchor decides which two singletons are melted, and
    /// nothing below this layer can notice that they belonged to a profile the person did not name.
    #[test]
    fn a_press_on_a_non_active_profile_aims_at_the_profile_that_was_pressed() {
        let registry = registry_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(2), Some("work")),
        ]);
        assert_eq!(
            registry.active().map(|active| active.ix()),
            Some(ProfileIx::ROOT),
            "the fixture must be active on a DIFFERENT profile from the one pressed"
        );

        assert_eq!(
            aimed_store_id(&registry, ProfileIx(2)),
            expected_store_id(ProfileIx(2)),
            "deleting profile 2 was aimed at another profile's store — the wrong singletons would \
             have been melted, irreversibly"
        );
        // The control: aiming at the active profile still answers the active profile, so the
        // assertion above is passing on the aim and not on a function that returns a fixed row.
        assert_eq!(
            aimed_store_id(&registry, ProfileIx::ROOT),
            expected_store_id(ProfileIx::ROOT)
        );
    }

    /// **An already-deleted profile, an unknown index, and a live one are three different answers.**
    ///
    /// The defect this replaces collapsed the first two into the third's absence, and the shell
    /// painted a node fault over both.
    #[test]
    fn an_ended_profile_and_an_unknown_index_are_not_the_same_answer() {
        let mut registry = registry_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(2), Some("work")),
        ]);
        // Asserted rather than discarded: melting a NON-active profile must not move the active
        // slot, and this is where a change of that would first show.
        assert_eq!(
            registry
                .record_melted(ProfileIx(2), 4_200)
                .expect("a confirmed melt of a live profile"),
            ProfileEndOutcome::Recorded
        );

        assert_eq!(
            aim_at(&registry, ProfileIx(2)),
            Err(MeltUnaimed::AlreadyEnded)
        );
        assert_eq!(
            aim_at(&registry, ProfileIx(9)),
            Err(MeltUnaimed::NotOnThisAccount)
        );
        assert!(
            aim_at(&registry, ProfileIx::ROOT).is_ok(),
            "the surviving profile stopped being deletable when its sibling was deleted"
        );
    }

    /// **No unaimed answer blames the node for something the node did not cause, and every one
    /// names a next step.**
    #[test]
    fn every_unaimed_answer_is_honest_about_the_node_and_names_a_next_step() {
        for why in [
            MeltUnaimed::NoAccount,
            MeltUnaimed::NotOnThisAccount,
            MeltUnaimed::AlreadyEnded,
        ] {
            let said = format!("{} {}", why.says(), why.next()).to_lowercase();
            assert!(
                !said.contains("node"),
                "{why:?} tells a person to fix their node for something the node did not cause: \
                 {said}"
            );
        }
        for why in [
            MeltUnaimed::NoAccount,
            MeltUnaimed::NoNode,
            MeltUnaimed::NotOnThisAccount,
            MeltUnaimed::AlreadyEnded,
        ] {
            assert!(!why.says().trim().is_empty(), "{why:?} says nothing");
            assert!(!why.next().trim().is_empty(), "{why:?} names no next step");
        }
        // The control: the one answer that IS a node fault does name the node, so the sweep above
        // is passing on copy that distinguishes rather than on copy that never mentions a node.
        assert!(MeltUnaimed::NoNode.says().to_lowercase().contains("node"));
    }
}
