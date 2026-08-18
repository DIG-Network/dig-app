//! Editing a dig-profile: what it holds now, what a person changed, and committing that on chain.
//!
//! # The shape (dig_ecosystem#2993, W7 of #3008)
//!
//! A profile's values live in an SMT whose ROOT is on chain and whose BODY is not. So an edit is
//! three things that must all happen, in order, or the profile is worse off than before it started:
//!
//! 1. **Read** the current body and verify it against the root the chain anchors. dig-account's
//!    `read_profile` does this; a body that does not rebuild to the anchored root is refused, so
//!    nothing here has to decide whether to trust it.
//! 2. **Commit** the change: build the update spend, sign it in THIS process, push the signed bundle
//!    through the node. §908 — the node never sees a key.
//! 3. **Persist the bytes the commit returns.** This is the step with no error to warn you: the new
//!    root is on chain the moment the spend confirms, and if nobody holds its preimage the profile
//!    becomes unreadable to everyone, permanently, with every layer reporting success. See
//!    [`bodies`].
//!
//! # What this module decides, and what it does not
//!
//! It decides the MODEL: which fields exist ([`field`]), what a person has changed and whether it
//! can fit ([`draft`]), where bytes are kept ([`bodies`]), and how a commit is run off the painting
//! thread ([`commit`]). It decides no pixel and no verb — the editor's one model verb is built in
//! [`crate::tray_menu`] like every other, and the pane draws what it is given.
//!
//! # Why the crate seam is a trait rather than a direct call
//!
//! [`commit::ProfileEditSeam`] names exactly what this app needs of dig-account: read a profile,
//! commit an edit, hand back the bytes. Two things fall out of that. A test can drive the whole
//! editor — including the failure where the bytes come back and are dropped — against a double,
//! with no chain and no money. And the concrete adapter is one small file that names the crate,
//! which is what lets the rest of the editor be written and reviewed against an API that is
//! published rather than one that is in a gate.

pub mod adapter;
pub mod bodies;
pub mod commit;
pub mod draft;
pub mod field;
pub mod mint_seed;
pub mod offer;
pub mod pending;
pub mod picture;
pub mod predict;
pub mod recovery;
pub mod seed;
pub mod service;

use std::collections::BTreeMap;

/// The sentences for the two profile states that are NOT faults, kept where both the model and the
/// pane can reach one definition.
///
/// # Why these live in the model and not the pane's copy table
///
/// Both are returned by [`ProfileEditError::sentence`], which is what a commit failure is reported
/// through, AND drawn by the editor card. Two tables would let the same state be described two ways
/// depending on which surface a person happened to be looking at — which is how *your node refused
/// you* came to be shown for a profile that had simply never published anything (dig_ecosystem#3036).
pub mod copy {
    /// Said over a store that exists on chain with nothing published under it.
    ///
    /// Names all three facts a person needs: the profile is real, nothing is broken, and what is
    /// missing is content. It does not offer a retry, because there is nothing to ask again.
    pub const UNPUBLISHED: &str = "This profile has no published information yet. Nothing has gone \
                                   wrong — the profile is on the blockchain and its details have \
                                   never been written. Publishing them writes to the blockchain and \
                                   costs a small amount of XCH.";

    /// Said over a profile whose content is anchored on chain and exists nowhere
    /// (dig_ecosystem#3041).
    ///
    /// # Every clause is load-bearing
    ///
    /// It states the loss without hedging, because the preceding version of this sentence told those
    /// people *"nothing has gone wrong"* and they went looking for a setting that would bring their
    /// profile back. It does not offer a retry, because a hash has no preimage to find. It names the
    /// root, so the claim is checkable rather than taken on trust. And it ends on the door — typing
    /// the details in again — because a statement of loss with no next action is the dead end
    /// `professional-ui`'s first rule exists to forbid.
    ///
    /// # What it deliberately does NOT claim
    ///
    /// Three MEASURED facts — not on your node, not found anywhere else, not rebuildable — rather
    /// than a universal *this can never be recovered*. The rebuild candidate list is complete only
    /// once [`install_recorded_seeds`](super::recovery::install_recorded_seeds) has run, and what
    /// guarantees that before a person reaches this card is an ORDERING rather than an invariant. So
    /// the sentence says what this app looked for and did not find, and stops there.
    ///
    /// # Why the remedy is worded as *add the details*
    ///
    /// [`label_names_a_remedy`](crate::window_model::label_names_a_remedy) checks for a remedy VERB,
    /// and an earlier draft of this sentence cleared it only because the phrase *not by waiting,
    /// retrying, or reinstalling* contains "install" — a verb inside a NEGATION, telling the person
    /// the one thing that would not help. The check was passing on a coincidence. The remedy is
    /// named with a listed verb deliberately now, so the guard is measuring the door rather than a
    /// substring of the sentence that says there isn't one.
    pub fn body_lost(root: &str) -> String {
        format!(
            "This profile's details are gone. The blockchain still records that they existed \
             (as {root}), but the details themselves are not on your node, could not be found \
             anywhere else, and cannot be rebuilt. Your profile itself is safe and still yours. To \
             use it again, add the details below and publish them; that writes to the blockchain \
             and costs a small amount of XCH."
        )
    }

    /// Said beneath any failure that PROVES nothing reached a mempool.
    ///
    /// # Why this is copy and not a sentence written into each arm
    ///
    /// Every control that publishes a profile spends real XCH, so the first question a person has
    /// when one refuses them is whether it spent any. Before this, the reassurance existed only as a
    /// constant no code path could reach ([`ProfileEditError`](super::ProfileEditError) built it for
    /// a refusal that the fresh-body publish removed the need for), while the sentence a person
    /// actually saw said only that their profile was unchanged — true, and silent on the money.
    ///
    /// It is attached to [`ProfileEditError::profile_is_unchanged`](super::ProfileEditError::profile_is_unchanged),
    /// which is deliberately conservative: only outcomes that provably never reached a mempool
    /// answer yes, so an attempt whose fate is UNKNOWN can never be told that nothing was spent.
    pub const NOTHING_WAS_SPENT: &str =
        "Nothing was sent to the blockchain and no XCH was spent. Your profile is unchanged — you          can change what you typed and try again.";

    /// Said over a profile whose stored content does not match what the chain anchors.
    ///
    /// A refusal, worded as one. There is no retry and no repair a person can perform from here,
    /// and implying either would send them round a loop that cannot end.
    pub const INCONSISTENT: &str = "This profile's saved details do not match what the blockchain \
                                    says they should be, so DIG will not show them. Nothing here \
                                    can be trusted until that is resolved, and DIG will not change \
                                    a profile it cannot read.";
}

pub use adapter::{AccountEditSeam, MintNetwork, NodeProfileContent};
pub use bodies::{BodyRead, BodyStore, BodyStoreError};
pub use commit::{
    CommitOutcome, EditRoute, EditSeams, ProfileEditError, ProfileEditSeam, ProfileSnapshot,
};
pub use draft::{ProfileDraft, SlotChange, MAX_BODY_BYTES, MAX_SLOT_PAYLOAD};
pub use field::{FieldGroup, FieldKind, ProfileField};
pub use offer::{EditBlocked, ProfileEditing};
pub use pending::{
    drain, DrainReport, MemoryPending, PendingBodies, PendingBody, PendingError,
    SealedPendingBodies,
};
pub use picture::chosen;
pub use seed::{ProfileSeedRequest, SeedDraft};
pub use service::EditService;

/// What the app can honestly say about the profile it is editing.
///
/// Five states, because a pane drawing this has five different things to say and no way to
/// distinguish them from an `Option<BTreeMap<_, _>>`. The middle two are the ones that get
/// collapsed by accident: **a profile with no fields set** is a working profile a person has not
/// filled in, and **a profile nobody could read** is a fault with a retry. Drawn the same way, the
/// second reads as the first and a person edits over a profile they cannot see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileReading {
    /// A read is under way. Nothing has answered yet.
    Pending,
    /// The profile was read and verified against the root the chain anchors.
    ///
    /// Holds the draft, so a pane never has to build one — including in the empty case, where the
    /// draft is over no values and [`ProfileDraft::is_empty`] is true.
    Known(ProfileDraft),
    /// Nobody could read it, in the deciding party's own words.
    ///
    /// Carries the reason rather than a flag: "your node is not running" and "this profile's body
    /// does not match the root on chain" are different situations with different remedies, and the
    /// second is a security refusal that must never be worded as a network hiccup.
    Unreadable(String),
    /// The store is real and nothing has ever been published under it.
    ///
    /// Not a fault and not an empty profile: there is no draft, because a draft is computed against
    /// what was read and there is nothing to read. A person here is told what is true and offered
    /// the way to publish something — never a retry (dig_ecosystem#3036).
    Unpublished,
    /// The chain anchors a root whose content is gone for good (dig_ecosystem#3041).
    ///
    /// # The one state here that offers a draft it did not read
    ///
    /// Every other failure withholds the form, and for a good reason: a person typing over a profile
    /// the app merely FAILED to read commits a body missing everything it still held. That reason
    /// does not apply here, because there is nothing left to lose — the bytes are unrecoverable, so
    /// an empty form destroys nothing and is the only way back to a working profile.
    ///
    /// So the draft is empty and [`is_empty`](Self::is_empty) is deliberately FALSE. The two facts
    /// together are what force a surface to draw this as *your details are gone, type them again*
    /// rather than as *you have not filled this in yet* — which would let a person press Save on
    /// three blank fields believing they were preserving what was there.
    BodyLost {
        /// The unrecoverable root, carried so the sentence can name it.
        root: String,
        /// An empty draft to type into. Empty because nothing survived, never because the profile
        /// was empty.
        draft: ProfileDraft,
    },
    /// A body exists and contradicts the root the chain anchors.
    ///
    /// The refusal, which must never be drawn as weather: no draft, and no retry.
    Inconsistent,
}

impl ProfileReading {
    /// A reading over a profile that answered with these values.
    pub fn known(values: BTreeMap<ProfileField, String>, body_len: usize) -> Self {
        Self::Known(ProfileDraft::over(values, body_len))
    }

    /// The reading a failed read produces, keeping the three states apart.
    ///
    /// # The defect this method IS
    ///
    /// Every failure used to become `Unreadable(error.while_reading())`, so *your profile has never
    /// published anything* and *your node is not answering* reached a person as one sentence about
    /// the node — and the remedy they were given, restart things, could not help, because nothing
    /// was broken (dig_ecosystem#3036). The mapping is here, once, so no surface can re-merge them.
    pub fn of_read_failure(error: &ProfileEditError) -> Self {
        match error {
            ProfileEditError::Unpublished => Self::Unpublished,
            ProfileEditError::BodyLost { root } => Self::body_lost(root),
            ProfileEditError::Inconsistent => Self::Inconsistent,
            other => Self::Unreadable(other.while_reading()),
        }
    }

    /// The reading over a profile whose content is unrecoverable, with the empty form to retype into.
    pub fn body_lost(root: &str) -> Self {
        Self::BodyLost {
            root: root.to_string(),
            draft: ProfileDraft::over(BTreeMap::new(), 0),
        }
    }

    /// What to say about this reading, when it is one of the states that carries a sentence.
    pub fn sentence(&self) -> Option<&str> {
        match self {
            Self::Unreadable(why) => Some(why),
            Self::Unpublished => Some(copy::UNPUBLISHED),
            Self::BodyLost { .. } => None,
            Self::Inconsistent => Some(copy::INCONSISTENT),
            _ => None,
        }
    }

    /// What to say about this reading, as an owned sentence, for the one state whose wording is
    /// computed rather than constant.
    ///
    /// [`sentence`](Self::sentence) borrows, and `BodyLost`'s sentence names the root, so it has no
    /// `&str` to lend. Rather than let that state quietly return `None` everywhere and reach a person
    /// as a blank card, every caller that can hold a `String` uses this and gets all five.
    pub fn says(&self) -> Option<String> {
        match self {
            Self::BodyLost { root, .. } => Some(copy::body_lost(root)),
            other => other.sentence().map(str::to_string),
        }
    }

    /// The draft to edit, when there is one.
    ///
    /// `BodyLost` is included deliberately: its draft is EMPTY, and handing it over is what lets a
    /// person whose content is unrecoverable type it in again (dig_ecosystem#3041). Every other
    /// non-`Known` state still withholds it.
    pub fn draft(&self) -> Option<&ProfileDraft> {
        match self {
            Self::Known(draft) | Self::BodyLost { draft, .. } => Some(draft),
            _ => None,
        }
    }

    /// Whether the form this reading offers is a RE-ENTRY over content that is gone, rather than the
    /// profile's own values.
    ///
    /// The surface needs this separately from [`draft`](Self::draft), because the two cases produce
    /// an identical empty form and only one of them may be drawn as *your profile*.
    pub fn is_re_entry(&self) -> bool {
        matches!(self, Self::BodyLost { .. })
    }

    /// Whether the profile answered and holds nothing — the empty state, which is not a fault.
    ///
    /// Keyed on `Known` alone. `BodyLost` also carries an empty draft and must NOT report true: it is
    /// not a profile with nothing in it, it is a profile whose contents were destroyed, and drawing
    /// the second as the first is how a person comes to press Save on blank fields believing they
    /// are keeping what was there.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Known(draft) if draft.is_empty())
    }

    /// Whether a person may be offered a retry: exactly the failed read, never the empty one.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unreadable(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_edit::commit::ProfileEditError;

    #[test]
    fn an_empty_profile_is_not_a_failed_read() {
        let empty = ProfileReading::known(BTreeMap::new(), 5);
        assert!(empty.is_empty());
        assert!(!empty.is_retryable());
        assert!(
            empty.draft().is_some(),
            "an empty profile is still editable"
        );
    }

    /// The inverse, which is the half that actually loses data: a read that FAILED must never be
    /// offered as an editable empty profile, or a person types their name over a profile the app
    /// could not see and commits a body missing everything it already held.
    #[test]
    fn a_failed_read_is_not_an_empty_profile_and_offers_no_draft() {
        let failed = ProfileReading::Unreadable("no node answered".into());
        assert!(!failed.is_empty());
        assert!(failed.is_retryable());
        assert!(failed.draft().is_none());
    }

    /// The defect #3036 is about: three states that had one sentence between them.
    ///
    /// # Why all three are asserted together
    ///
    /// Each state in isolation passes against the broken version too — every one of them WAS an
    /// `Unreadable`, so any single-state assertion about "it says something" held before the fix.
    /// What the fix changes is that they are DISTINGUISHABLE, so the property is pairwise: three
    /// failures, three different sentences, and only the middle one retryable.
    #[test]
    fn the_three_read_states_say_three_different_things_and_only_one_retries() {
        let unpublished = ProfileReading::of_read_failure(&ProfileEditError::Unpublished);
        let unreachable = ProfileReading::of_read_failure(&ProfileEditError::ChainUnreachable(
            "no node answered".into(),
        ));
        let inconsistent = ProfileReading::of_read_failure(&ProfileEditError::Inconsistent);

        let said: Vec<&str> = [&unpublished, &unreachable, &inconsistent]
            .iter()
            .map(|reading| reading.sentence().expect("each state says something"))
            .collect();
        assert_eq!(
            said.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3,
            "two of the three states are worded the same, so a person cannot tell them apart: \
             {said:?}"
        );

        assert!(
            unreachable.is_retryable(),
            "the only genuine failure lost its retry"
        );
        assert!(
            !unpublished.is_retryable(),
            "a profile that has published nothing was offered a retry, which cannot help"
        );
        assert!(
            !inconsistent.is_retryable(),
            "a body contradicting the chain was offered a retry, which cannot help"
        );
    }

    /// None of the three offers a draft. An unpublished profile especially: it reads as the empty
    /// state, and an editable form over it would commit a body against a root nothing verified.
    #[test]
    fn no_failed_state_hands_out_a_draft_to_edit_over() {
        for state in [
            ProfileReading::Unpublished,
            ProfileReading::Inconsistent,
            ProfileReading::Unreadable("no node".into()),
        ] {
            assert!(state.draft().is_none(), "{state:?} offered a draft");
            assert!(!state.is_empty(), "{state:?} was drawn as an empty profile");
        }
    }

    /// The unpublished sentence does not blame the node, which is the exact wording defect: a
    /// person told their node refused them restarts things that were never broken.
    #[test]
    fn the_unpublished_sentence_does_not_blame_the_node() {
        let said = ProfileEditError::Unpublished.sentence();
        assert!(!said.contains("node"), "{said}");
        assert!(!said.contains("could not read"), "{said}");
        assert!(said.contains("no published information"), "{said}");
    }

    /// **dig_ecosystem#3041.** A profile whose content is unrecoverable is told the truth AND
    /// handed the form to type it in again.
    ///
    /// # Why every one of these is asserted together
    ///
    /// Each clause alone passes against a different wrong version, and the wrong versions are the
    /// ones this state was actually shipped as:
    ///
    /// * *offers a draft* alone passes for the version that reports `Known(empty)` — which is the
    ///   destructive one, because it draws as *you have not filled this in yet* and invites Save
    ///   over three blank fields. `is_empty()` being FALSE is what separates them.
    /// * *is not empty and not retryable* alone passes for the version shipped before this fix,
    ///   which reported `Unpublished` — no draft, no way out, and a false sentence.
    /// * *says the content is gone* alone passes for a version that says so and still withholds the
    ///   form, which is the dead end the ticket is about.
    ///
    /// So the property is the conjunction: honest sentence, no retry, not drawn as an empty
    /// profile, and a form all the same.
    #[test]
    fn an_unrecoverable_body_is_named_as_gone_and_still_offers_a_form_to_retype_into() {
        const ROOT: &str = "371a39b04742cd4d4b45bdf61a99f3838b700587fad093330dddb4766feba454";
        let lost = ProfileReading::of_read_failure(&ProfileEditError::BodyLost {
            root: ROOT.to_string(),
        });

        let draft = lost.draft().expect(
            "a person whose content is unrecoverable was given no way to publish a fresh body",
        );
        assert!(
            draft.is_empty(),
            "the re-entry form was pre-filled from somewhere"
        );
        assert!(
            lost.is_re_entry(),
            "the form is indistinguishable from an ordinary edit of this person's own values"
        );
        assert!(
            !lost.is_empty(),
            "a destroyed profile was drawn as one that had simply never been filled in"
        );
        assert!(
            !lost.is_retryable(),
            "a retry was offered for bytes no amount of asking can produce"
        );

        let said = lost.says().expect("the state says nothing at all");
        assert!(
            said.contains(ROOT),
            "the sentence does not name the root: {said}"
        );
        assert!(
            !said.contains("Nothing has gone wrong"),
            "the reassurance from the UNPUBLISHED sentence survived onto a destroyed profile:              {said}"
        );
        assert!(
            crate::window_model::label_names_a_remedy(&said),
            "a permanent loss was stated with no next action: {said}"
        );
    }

    /// The two states a node answering `body_b64: null` can mean are worded DIFFERENTLY.
    ///
    /// # Why the control is the unpublished sentence and not a length check
    ///
    /// Both reach a person through the same node answer, and the defect was that one sentence
    /// served both — so the only thing that proves the fix is that the two strings differ, and
    /// specifically that the destroyed one does not inherit the reassuring one. A test over
    /// `BodyLost` alone cannot see a re-merge, because a re-merge keeps `BodyLost` saying something.
    #[test]
    fn a_destroyed_profile_and_an_unwritten_one_do_not_share_a_sentence() {
        let destroyed = ProfileReading::of_read_failure(&ProfileEditError::BodyLost {
            root: "aa".repeat(32),
        })
        .says()
        .expect("says something");
        let unwritten = ProfileReading::Unpublished.says().expect("says something");

        assert_ne!(destroyed, unwritten);
        assert!(
            unwritten.contains("never been written"),
            "the control lost the claim that makes it the WRONG thing to say here: {unwritten}"
        );
        assert!(
            !destroyed.contains("never been written"),
            "a person whose details were destroyed was told they had never written any: {destroyed}"
        );
        // And the unwritten state still withholds the form, so widening the draft did not widen it
        // to the state that has nothing to recover.
        assert!(ProfileReading::Unpublished.draft().is_none());
        assert!(!ProfileReading::Unpublished.is_re_entry());
    }

    #[test]
    fn a_read_in_flight_is_neither() {
        assert!(!ProfileReading::Pending.is_empty());
        assert!(!ProfileReading::Pending.is_retryable());
        assert!(ProfileReading::Pending.draft().is_none());
    }
}
