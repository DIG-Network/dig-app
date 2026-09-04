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

use super::MeltTarget;

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

/// Both halves of a deletion press: what the confirmation names, and what the melt spends.
///
/// One [`ProfileRegistry::get`] read produces both (dig_ecosystem#217/dig-app#217). Before this
/// type existed, the caller who draws the confirmation and the caller who builds the melt each read
/// the registry separately — the same `ix`, but never provably the same ENTRY, with an unbounded
/// human decision sitting between the two reads. A registry that moved in that gap (a concurrent
/// edit, another window, a melt this app itself just confirmed) let the seam melt whatever `ix`
/// resolved to at the second read, which the confirmation had never actually described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aimed {
    /// What the confirmation names — the profile a person is being asked to destroy.
    pub target: MeltTarget,
    /// What the melt spends — the same entry's on-chain anchor.
    pub anchor: ProfileAnchor,
}

/// Aim a deletion at the profile at `ix`, or say why nothing can be aimed at it.
///
/// The entry is read from the registry ONCE: both [`Aimed::target`] (what the confirmation will
/// name) and [`Aimed::anchor`] (what the melt will spend) are derived from that single read, never
/// from two separate lookups a caller might otherwise take on either side of a confirmation. The
/// entry is read at the index the CONTROL carried, never off the active slot — a deletion aimed by
/// the active slot melts the wrong profile's singletons, and there is no layer below this one that
/// could notice.
///
/// The account being LOCKED is deliberately not tested here — the seam derives its melter per call
/// and answers [`ProfileMeltError::Locked`](super::ProfileMeltError::Locked) itself, so there is one
/// predicate for it rather than a second one that can drift from it.
pub fn aim_at(registry: &ProfileRegistry, ix: ProfileIx) -> Result<Aimed, MeltUnaimed> {
    let Some(entry) = registry.get(ix) else {
        return Err(MeltUnaimed::NotOnThisAccount);
    };
    if !entry.is_live() {
        return Err(MeltUnaimed::AlreadyEnded);
    }
    let anchor = entry.anchor().clone();
    // The SAME derivation `ProfileRow::of_entry` (crate::profiles) uses for a list row, so the
    // sentence a delete confirmation shows can never read differently from the row the person
    // pressed delete on.
    let name = match entry.label() {
        Some(label) => format!("\u{201c}{label}\u{201d}"),
        None => format!("profile {}", ix.0.saturating_add(1)),
    };
    let target = MeltTarget {
        ix: ix.0,
        name,
        did: anchor.did().to_string(),
        store_id: format!("0x{}", hex::encode(anchor.store_launcher_id())),
    };
    Ok(Aimed { target, anchor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{
        expected_did, expected_store_id, registry_with,
    };
    use dig_account::registry::ProfileEndOutcome;

    /// The three-profile fixture every test below aims into, active on `ROOT`.
    ///
    /// Three, and the press lands on the MIDDLE one, because each smaller fixture agrees with a
    /// different wrong implementation: one profile agrees with every one of them, a press on the
    /// active profile agrees with reading the active slot, a press on the first entry agrees with
    /// reading `entries[0]`, and a press on the last agrees with reading the most recent mint.
    fn three_profiles() -> ProfileRegistry {
        registry_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(2), Some("work")),
            (ProfileIx(4), Some("archive")),
        ])
    }

    /// The store id an aim's ANCHOR would melt, in the form a surface prints — the value that says
    /// WHICH profile's singletons the seam is built to spend.
    fn aimed_store_id(registry: &ProfileRegistry, ix: ProfileIx) -> String {
        let aim = aim_at(registry, ix).expect("a live profile can be aimed at");
        store_id_of(&aim.anchor)
    }

    /// The store id an aim's TARGET names — what the confirmation prints, and the only description
    /// of the profile a person ever reads before agreeing to destroy it.
    fn named_store_id(registry: &ProfileRegistry, ix: ProfileIx) -> String {
        aim_at(registry, ix)
            .expect("a live profile can be aimed at")
            .target
            .store_id
    }

    /// An anchor's store launcher id in the `0x...` form [`MeltTarget::store_id`] carries, so the
    /// two halves are compared as the same kind of value rather than through a conversion that
    /// could itself be the thing under test.
    fn store_id_of(anchor: &ProfileAnchor) -> String {
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
    ///
    /// Both halves of the aim are asserted, not just the anchor. The target is what the
    /// confirmation prints, so an aim whose target came off the active slot describes the wrong
    /// profile to the person deciding -- and an assertion on the anchor alone passes anyway.
    #[test]
    fn a_press_on_a_non_active_profile_aims_at_the_profile_that_was_pressed() {
        let registry = three_profiles();
        assert_eq!(
            registry.active().map(|active| active.ix()),
            Some(ProfileIx::ROOT),
            "the fixture must be active on a DIFFERENT profile from the one pressed"
        );

        assert_eq!(
            aimed_store_id(&registry, ProfileIx(2)),
            expected_store_id(ProfileIx(2)),
            "deleting profile 2 was aimed at another profile's store -- the wrong singletons would \
             have been melted, irreversibly"
        );
        assert_eq!(
            named_store_id(&registry, ProfileIx(2)),
            expected_store_id(ProfileIx(2)),
            "the confirmation would have named a profile the person did not press, and the press \
             is the only thing that decides an irreversible deletion"
        );
        // The control: aiming at the active profile still answers the active profile, so the
        // assertions above are passing on the aim and not on a function that returns a fixed row.
        assert_eq!(
            aimed_store_id(&registry, ProfileIx::ROOT),
            expected_store_id(ProfileIx::ROOT)
        );
        assert_eq!(
            named_store_id(&registry, ProfileIx::ROOT),
            expected_store_id(ProfileIx::ROOT)
        );
    }

    /// **The profile a person is SHOWN and the profile whose singletons are SPENT are one entry.**
    ///
    /// The defect this pins (dig-app#217) was not a wrong lookup: both reads used the same index
    /// and each was individually correct. It was that there were TWO of them -- the confirmation's
    /// description came from one read of the registry and the melt's anchor from a second, taken
    /// after an unbounded pause for thought -- so nothing made them the same entry. One call
    /// returning both halves is what removes the gap, and this asserts the halves agree.
    ///
    /// # Why the fixture holds three DISTINGUISHABLE profiles
    ///
    /// "The two halves agree" is satisfied by every implementation on a fixture whose profiles
    /// share a store id, including one that pairs two different entries. So the ids are asserted
    /// pairwise distinct FIRST: without that control this test proves nothing, and it would still
    /// be green.
    #[test]
    fn the_profile_a_person_is_shown_and_the_singletons_that_are_spent_are_one_entry() {
        let registry = three_profiles();
        let ids: Vec<String> = [ProfileIx::ROOT, ProfileIx(2), ProfileIx(4)]
            .iter()
            .map(|ix| expected_store_id(*ix))
            .collect();
        for (a, id) in ids.iter().enumerate() {
            for other in ids.iter().skip(a + 1) {
                assert_ne!(
                    id, other,
                    "the fixture cannot tell its own profiles apart, so an aim that paired two \
                     different entries would satisfy every assertion below"
                );
            }
        }

        let aim = aim_at(&registry, ProfileIx(2)).expect("a live profile can be aimed at");

        // Each half names profile 2 on its own terms...
        assert_eq!(aim.target.ix, 2);
        assert_eq!(aim.target.did, expected_did(ProfileIx(2)));
        assert_eq!(aim.target.store_id, expected_store_id(ProfileIx(2)));
        assert!(
            aim.target.name.contains("work"),
            "the confirmation would name a profile by someone else's label: {}",
            aim.target.name
        );
        // ...and, the part a two-read shape could never promise, they name the SAME one.
        assert_eq!(
            aim.anchor.did(),
            aim.target.did,
            "the identity named in the confirmation is not the identity the melt would end"
        );
        assert_eq!(
            store_id_of(&aim.anchor),
            aim.target.store_id,
            "the content store named in the confirmation is not the store the melt would end"
        );
    }

    /// **An aim is a snapshot: the registry moving afterwards cannot change what was agreed to.**
    ///
    /// The confirmation refuses by default and has no attention timeout, so the pause between
    /// drawing it and answering it is unbounded -- long enough for a second window to rename,
    /// re-activate or end a profile. The old shape re-read the registry AFTER the answer and built
    /// the seam from that second read, so what was destroyed was decided by the list as it stood
    /// afterwards rather than by the sentence the person agreed to.
    ///
    /// # What this fixture can and cannot move
    ///
    /// Within one account an index's ANCHOR is fixed at mint and never changes, so the drift a
    /// registry can exhibit here is the label and the active slot -- both of which the target
    /// carries and the person reads. The anchor half of the same straddle needs two registries
    /// disagreeing at one index, which is only reachable across ACCOUNTS and which
    /// `test_support`'s builder cannot express today; it is stated rather than silently implied.
    #[test]
    fn an_aim_taken_before_the_question_is_not_re_read_after_the_answer() {
        let mut registry = three_profiles();

        // The aim behind the confirmation now on screen.
        let agreed = aim_at(&registry, ProfileIx(2)).expect("a live profile can be aimed at");

        // The person is deciding. Another window renames that profile and switches away from the
        // one they were on.
        registry
            .set_label(ProfileIx(2), Some("banking".to_owned()))
            .expect("renaming a confirmed profile");
        // The fixture is not a real host with a receive-address surface to disclose to, so the
        // switch's must-use return is deliberately dropped here.
        let _ = registry
            .set_active(ProfileIx(4))
            .expect("activating a confirmed profile");

        // The control, and the reason this test is not vacuous: a SECOND read -- the one the old
        // shape took after the answer -- genuinely answers something else now.
        let re_read = aim_at(&registry, ProfileIx(2)).expect("the profile is still live");
        assert_ne!(
            re_read.target.name, agreed.target.name,
            "the registry did not move between the two reads, so this test cannot see a melt \
             aimed by the second one"
        );

        // What was agreed to still describes one profile, and it is the one that was described.
        assert!(
            agreed.target.name.contains("work") && !agreed.target.name.contains("banking"),
            "the aim was re-read after the answer: {}",
            agreed.target.name
        );
        assert_eq!(
            store_id_of(&agreed.anchor),
            agreed.target.store_id,
            "the held aim's two halves came apart"
        );
        assert_eq!(
            agreed.target.store_id,
            expected_store_id(ProfileIx(2)),
            "the aim stopped naming the profile that was pressed when the active slot moved"
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
