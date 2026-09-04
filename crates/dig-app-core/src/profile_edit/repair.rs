//! Putting a profile's published content back on this computer, as a control a person can find.
//!
//! # The hole this fills (dig-app#207, over dig_ecosystem#3036)
//!
//! The repair itself has existed since #3036: a read that finds nothing rebuilds the body from the
//! seed the profile was minted with, verifies it against the root the chain anchors, and hands it
//! to the node ([`NodeProfileContent::rebuilt`](super::adapter)). What it has never had is a DOOR.
//! It happens as a side effect of reading, so a person whose profile will not render has no way to
//! ask for it — they reach the remedy only by already having opened the broken profile's editor.
//! A capability nobody can invoke is, from where they stand, a capability the app does not have.
//!
//! # The two fallback paths, and why this module is only ONE of them
//!
//! A profile with no readable content has two remedies and they cost different things. When the
//! anchored root matches a deterministic rebuild, the body is republished LOCALLY: no chain write,
//! no signature, no spend — that is this module. When nothing this app can produce matches it, the
//! only honest fix is a real edit writing a new root, which IS a spend and goes through the editor
//! and the transaction sheet with its cost stated. Collapsing the two would hide a cost from
//! somebody choosing between them, so nothing here ever escalates into the second.
//!
//! # §908, and why this is free of the money path entirely
//!
//! Nothing here signs, pushes, or reads a chain. It rebuilds bytes from a seed, compares a hash,
//! and writes to the node's body store. No key is taken, and there is nowhere to put one.
//!
//! # The rule that outranks repairing anything
//!
//! **The bytes are only ever produced by [`recovery::seed_body_for`]**, which returns them only
//! after `VerifiedBody::open` has accepted them against the root the chain anchors. A body that
//! does not verify is not a worse rebuild — it is a body for a DIFFERENT profile, and publishing it
//! would make this app serve content the chain contradicts. That check is not repeated or relaxed
//! here, and this module has no other source of bytes.

use super::bodies::{BodyRead, BodyStore, BodyStoreError};
use super::commit::{ProfileEditError, ProfileSnapshot};
use super::recovery;

/// Whether a profile's published content can be put back on this computer WITHOUT a chain write.
///
/// # Three states, because "we have not looked" is not "there is nothing to do"
///
/// A bool would have to answer one of them for both, and either answer is wrong in one direction:
/// reported as *no*, an unmeasured profile silently withholds a free remedy from somebody who has
/// one; reported as *yes*, the app offers a control it has not established can do anything. The
/// same reason `BalanceReading` keeps pending, known and unknown apart.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BodyRepair {
    /// Nobody has established whether a repair is possible. Never drawn as *no*.
    ///
    /// The state every row starts in, and the state a row whose chain read failed STAYS in: a node
    /// that could not answer says nothing about whether a rebuild would verify.
    #[default]
    Unmeasured,
    /// Measured, and there is nothing to put back — the content reads, or nothing this app can
    /// rebuild commits to the root the chain anchors.
    NotOffered,
    /// The chain-anchored root has a preimage this app can rebuild and hand to the node.
    ///
    /// **No chain write and no spend.** Carries the root the rebuild commits to, so the act and the
    /// measurement can never be about different values.
    Rebuildable {
        /// The root the rebuild commits to, lowercase 64-hex, as the chain read returned it.
        root: String,
    },
}

impl BodyRepair {
    /// What a completed profile read says about repairing this profile's content for free.
    ///
    /// # Why only `BodyLost` can answer yes
    ///
    /// It is the one state that means *the chain anchors a root and this computer does not hold its
    /// preimage*, which is exactly what a rebuild would supply. A profile that READS has nothing to
    /// put back. A store that never committed content has no preimage to restore at all — its
    /// remedy is a first publish, which is a spend and belongs to the editor. And a body that
    /// contradicts the chain is a refusal with no repair a person can perform, which is what its own
    /// sentence says.
    ///
    /// # Why every other failure stays `Unmeasured`
    ///
    /// They did not establish what the chain anchors, so they establish nothing about whether it can
    /// be rebuilt. Answering `NotOffered` there would withdraw a free remedy on the strength of a
    /// node hiccup.
    pub fn of_read(read: Result<&ProfileSnapshot, &ProfileEditError>) -> Self {
        match read {
            Ok(_) => Self::NotOffered,
            Err(ProfileEditError::BodyLost { root }) => match root_bytes(root) {
                Some(bytes) if recovery::seed_body_for(bytes).is_some() => {
                    Self::Rebuildable { root: root.clone() }
                }
                _ => Self::NotOffered,
            },
            Err(ProfileEditError::Unpublished | ProfileEditError::Inconsistent) => Self::NotOffered,
            Err(_) => Self::Unmeasured,
        }
    }

    /// The root a repair would restore, when one has been measured as restorable.
    pub fn root(&self) -> Option<&str> {
        match self {
            Self::Rebuildable { root } => Some(root),
            _ => None,
        }
    }
}

/// What a repair attempt did.
///
/// Every variant is a statement about the NODE's storage and none is a statement about the chain,
/// because nothing here touches one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairOutcome {
    /// The body was rebuilt, given to the node, and read back from it.
    Restored {
        /// The root it was stored under — the value the chain already anchors.
        root: String,
    },
    /// Nothing this app can rebuild commits to that root, so there is nothing legitimate to store.
    NotRebuildable {
        /// The root that could not be answered for.
        root: String,
    },
    /// The node would not keep the bytes, in its own words.
    NotKept {
        /// What the store said.
        why: BodyStoreError,
    },
    /// The node reported success and does not hold it.
    ///
    /// Its own variant, and the reason the read-back exists: a store that accepts everything and
    /// keeps nothing answers `Ok(())`, and the profile is then exactly as unreadable as before with
    /// every layer reporting success. The same discipline
    /// [`commit_and_persist`](super::commit::commit_and_persist) applies to a committed body.
    NotHeld {
        /// The root the bytes were offered under.
        root: String,
    },
    /// There is nothing measured to repair, or nothing to repair it through.
    ///
    /// Reached only by a control that should not have been drawn, so it is worded as an app fault
    /// rather than as a claim about the person's profile.
    NotOffered,
}

/// Rebuild the body `root` commits to and give it to the node, verifying it is kept.
///
/// Spends nothing, signs nothing, and reads no chain. `root` must be the value a chain read
/// returned: it is what the rebuild is accepted against, so a caller passing a root from anywhere
/// else gets `NotRebuildable` rather than a body stored under a root nobody anchored.
pub fn restore(bodies: &dyn BodyStore, store_id: &str, root: &str) -> RepairOutcome {
    let Some(bytes) = root_bytes(root).and_then(recovery::seed_body_for) else {
        return RepairOutcome::NotRebuildable {
            root: root.to_string(),
        };
    };
    if let Err(why) = bodies.put(store_id, root, &bytes) {
        return RepairOutcome::NotKept { why };
    }
    // The read-back, for `commit_and_persist`'s reason: a store that accepts everything and keeps
    // nothing returns `Ok(())`, and reporting that as a repair leaves the profile exactly as
    // unreadable as it was with every layer claiming success.
    match bodies.get(store_id, root) {
        Ok(BodyRead::Held(_)) => RepairOutcome::Restored {
            root: root.to_string(),
        },
        Ok(BodyRead::Nothing) => RepairOutcome::NotHeld {
            root: root.to_string(),
        },
        Err(why) => RepairOutcome::NotKept { why },
    }
}

/// A 64-hex root as the bytes [`recovery::seed_body_for`] takes, tolerating the `0x` form every DIG
/// surface prints.
///
/// `None` for anything that is not 32 bytes of hex. That is a refusal and never a fallback: a root
/// this cannot parse is a root nothing may be stored under.
fn root_bytes(root: &str) -> Option<[u8; 32]> {
    let hex = root.strip_prefix("0x").unwrap_or(root);
    hex::decode(hex).ok()?.try_into().ok()
}

/// The words the repair control and its confirmation are drawn from.
///
/// Kept here rather than in the shell so the one thing a person is told about cost is written once.
/// It is the whole difference between this remedy and the other one, and a second copy of it is a
/// second chance to say the wrong one.
pub mod copy {
    /// The per-profile menu row. Names the act and where it happens; the disclosure is the prompt's.
    pub fn label(profile: &str) -> String {
        format!("Restore the details of {profile} on this computer…")
    }

    /// The confirmation window's title.
    pub const TITLE: &str = "Restore profile details";

    /// The question being put to the user.
    pub const HEADING: &str = "Put this profile's published details back on this computer?";

    /// What the answer does, in the user's words.
    ///
    /// It states the absence of a cost explicitly. The other remedy for an unreadable profile is a
    /// real publish that spends XCH and replaces what the chain records, and a person choosing
    /// between them cannot do so unless each says which it is.
    pub const BODY: &str =
        "DIG can rebuild this profile's published details from what was recorded \
                            when it was created, and give them back to your node. Nothing is \
                            written to the blockchain and no XCH is spent. The details are only \
                            accepted if they match what the blockchain already records for this \
                            profile.";

    /// The affirming choice's label — a verb naming the action, never a bare OK.
    pub const AFFIRM: &str = "Restore the details";
}

/// Render one [`RepairOutcome`] as a follow-up notice: `(heading, body)`.
///
/// A pure function, so the words are testable without a native confirmer — the same split [`copy`]
/// exists for.
///
/// Every failing arm says what is still true (nothing was spent) and what the remaining route is,
/// because a statement of failure with no next action is the dead end `professional-ui`'s first rule
/// forbids. None of them offers a RETRY of this control where retrying cannot help: a rebuild that
/// did not verify will not verify on the second press.
pub fn describe(outcome: &RepairOutcome) -> (&'static str, String) {
    match outcome {
        RepairOutcome::Restored { root } => (
            "Details restored",
            format!(
                "Your node now holds this profile's published details for {root}. Nothing was \
                 written to the blockchain and no XCH was spent."
            ),
        ),
        RepairOutcome::NotRebuildable { root } => (
            "Nothing here matches that profile",
            format!(
                "DIG could not rebuild details matching what the blockchain records for this \
                 profile ({root}), so it stored nothing. Nothing was written to the blockchain and \
                 no XCH was spent. Your profile itself is safe and still yours. To use it again, \
                 open its editor and publish the details — that writes to the blockchain and costs \
                 a small amount of XCH."
            ),
        ),
        RepairOutcome::NotKept { why } => (
            "Your node would not keep them",
            format!(
                "The rebuilt details are correct and your node did not store them: {why}. Nothing \
                 was written to the blockchain and no XCH was spent. Check that your node is \
                 running, then try again."
            ),
        ),
        RepairOutcome::NotHeld { root } => (
            "Your node did not keep them",
            format!(
                "Your node accepted this profile's details for {root} and does not hold them. \
                 Nothing was written to the blockchain and no XCH was spent. Check your node's \
                 storage before trying again."
            ),
        ),
        RepairOutcome::NotOffered => (
            "Nothing to restore",
            "DIG has not established that this profile's details can be rebuilt, so it did not \
             try. Nothing was written to the blockchain and no XCH was spent."
                .to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use dig_account::mint::ProfileSeed;

    use super::super::bodies::doubles::InMemoryBodies;
    use super::*;

    const STORE: &str = "11";

    /// The root every profile this app has minted anchors — rebuildable from the empty seed alone.
    fn minted_root() -> String {
        hex::encode(ProfileSeed::new().root().expect("the seed builds"))
    }

    /// A root that belongs to some other profile, which this app recorded no seed for.
    fn foreign_root() -> String {
        "77".repeat(32)
    }

    /// The repair, end to end: a root this app minted is rebuilt, stored, and READ BACK.
    ///
    /// # Why the store is asserted afterwards
    ///
    /// The nearest wrong implementation rebuilds the body, reports success, and never puts it —
    /// indistinguishable from the caller's side, and it leaves every reader as stuck as before. So
    /// the observable is the store's contents, not the return value alone.
    #[test]
    fn a_root_this_app_minted_is_rebuilt_stored_and_read_back() {
        let bodies = InMemoryBodies::default();
        let root = minted_root();

        assert_eq!(
            restore(&bodies, STORE, &root),
            RepairOutcome::Restored { root: root.clone() }
        );
        assert!(
            matches!(bodies.get(STORE, &root), Ok(BodyRead::Held(_))),
            "the repair reported success and the node holds nothing, so nothing can read it"
        );
    }

    /// A root this app cannot rebuild stores NOTHING, and says so.
    ///
    /// This is the guard, and the whole reason the module is safe: a version that stored its nearest
    /// candidate would make the app serve content the chain contradicts, under somebody's identity.
    /// The store is asserted empty afterwards for exactly that reason, and the control below keeps
    /// the refusal about the ROOT rather than about a store that refuses everything.
    #[test]
    fn a_root_this_app_cannot_rebuild_stores_nothing() {
        let bodies = InMemoryBodies::default();
        let root = foreign_root();

        assert_eq!(
            restore(&bodies, STORE, &root),
            RepairOutcome::NotRebuildable { root: root.clone() }
        );
        assert!(
            matches!(bodies.get(STORE, &root), Ok(BodyRead::Nothing)),
            "a body was stored under a root it does not commit to"
        );
        assert!(matches!(
            restore(&bodies, STORE, &minted_root()),
            RepairOutcome::Restored { .. }
        ));
    }

    /// A root that is not 32 bytes of hex is refused rather than parsed loosely, and the `0x` form
    /// every DIG surface prints is still accepted.
    #[test]
    fn a_root_that_is_not_a_root_is_refused_and_the_printed_form_is_not() {
        let bodies = InMemoryBodies::default();
        for wrong in ["", "0xzz", &"aa".repeat(31)] {
            assert!(
                matches!(
                    restore(&bodies, STORE, wrong),
                    RepairOutcome::NotRebuildable { .. }
                ),
                "a root of {wrong:?} was treated as something a body could be stored under"
            );
        }
        assert!(matches!(
            restore(&bodies, STORE, &format!("0x{}", minted_root())),
            RepairOutcome::Restored { .. }
        ));
    }

    /// The offer is measured from the READ, and each state answers for itself.
    ///
    /// # Why all five are asserted together
    ///
    /// Any one of them passes against a version that answers the same thing for everything, and the
    /// two damaging versions are exactly that: *always `NotOffered`* silently withholds a free
    /// remedy, *always `Rebuildable`* draws a control with nothing to put back. The property is that
    /// the five are told APART.
    #[test]
    fn the_repair_offer_is_measured_per_state_and_only_a_lost_body_can_answer_yes() {
        let read = ProfileSnapshot {
            store_id: STORE.to_string(),
            root: minted_root(),
            values: BTreeMap::new(),
            body: Vec::new(),
        };
        assert_eq!(BodyRepair::of_read(Ok(&read)), BodyRepair::NotOffered);

        assert_eq!(
            BodyRepair::of_read(Err(&ProfileEditError::BodyLost {
                root: minted_root()
            })),
            BodyRepair::Rebuildable {
                root: minted_root()
            },
            "a body this app can rebuild was not offered the free repair"
        );
        assert_eq!(
            BodyRepair::of_read(Err(&ProfileEditError::BodyLost {
                root: foreign_root()
            })),
            BodyRepair::NotOffered,
            "a repair was offered for a root nothing this app produces commits to"
        );

        // The store that never published has no preimage to restore. Its remedy is a first publish,
        // which is a SPEND — offering this control there would hide that cost behind a free one.
        assert_eq!(
            BodyRepair::of_read(Err(&ProfileEditError::Unpublished)),
            BodyRepair::NotOffered
        );
        // A read that failed measured nothing, so it must not report "no" either.
        assert_eq!(
            BodyRepair::of_read(Err(&ProfileEditError::ChainUnreachable("no node".into()))),
            BodyRepair::Unmeasured,
            "a node hiccup withdrew a free remedy the app never established was unavailable"
        );
    }

    /// Every outcome says whether money moved, and the prompt says it BEFORE the press.
    ///
    /// The money clause is the one a person actually needs: this control sits a row away from a
    /// remedy that DOES spend, so a repair silent about cost invites the assumption that it behaved
    /// like the other one.
    #[test]
    fn every_outcome_says_that_nothing_was_spent() {
        for outcome in [
            RepairOutcome::Restored {
                root: minted_root(),
            },
            RepairOutcome::NotRebuildable {
                root: foreign_root(),
            },
            RepairOutcome::NotKept {
                why: BodyStoreError::Refused("no node".into()),
            },
            RepairOutcome::NotHeld {
                root: minted_root(),
            },
            RepairOutcome::NotOffered,
        ] {
            let (heading, body) = describe(&outcome);
            assert!(!heading.is_empty(), "{outcome:?} has no heading");
            assert!(
                body.contains("no XCH was spent"),
                "{outcome:?} left a person unable to tell whether this remedy cost them money: \
                 {body}"
            );
        }

        assert!(copy::BODY.contains("no XCH is spent"), "{}", copy::BODY);
        assert!(
            copy::BODY.contains("Nothing is written to the blockchain"),
            "{}",
            copy::BODY
        );
    }
}
