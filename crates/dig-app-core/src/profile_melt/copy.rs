//! What a person is told before, during and after a profile is deleted.
//!
//! # The two things every sentence here has to get right
//!
//! **It is irreversible in a way nothing else in this app is.** Money that leaves can be re-earned;
//! a melted singleton cannot be re-created, because a launcher id is derived from a coin that has
//! been spent. Every `did:chia:` reference to it, anywhere, becomes permanently unresolvable. So the
//! confirmation names what is destroyed rather than asking *are you sure*.
//!
//! **The 1 mojo per singleton is spent, not refunded.** `(51 () -113)` occupies the singleton
//! puzzle's one permitted odd-amount `CREATE_COIN`, so paying the amount back is unexpressible
//! rather than unimplemented. No sentence here promises it, and
//! [`no_copy_promises_the_mojo_back`](tests::no_copy_promises_the_mojo_back) sweeps every one of
//! them for the words that would.
//!
//! **What was already published stays published.** Peers hold profile bodies keyed on
//! `(store_id, root)`, and melting the store ends its lineage without un-serving a byte anybody
//! already has. Saying "your content is erased" would be the one claim here that is simply false.

use super::{MeltHalf, MeltStopped, MeltTarget};
use crate::transaction::Stage;

/// The delete control's label. Names the act plainly — a destructive control that hedges is one a
/// person presses without understanding it.
pub const DELETE_LABEL: &str = "Delete this profile permanently…";

/// The confirmation's heading.
pub const CONFIRM_TITLE: &str = "Delete this profile permanently?";

/// What deleting destroys, said in the terms the chain will actually honour.
///
/// Written per-profile rather than as a constant so the DID and the store are named IN the sentence:
/// a person about to end an identity should see which identity, not a generic warning.
pub fn confirm_body(target: &MeltTarget) -> String {
    format!(
        "This ends {name} on the blockchain. DIG will spend both of its coins so that neither can \
         ever exist again:\n\n\
         • the identity {did}\n\
         • the content store {store}\n\n\
         Every link to that identity stops resolving, everywhere, for everybody — and it cannot be \
         re-created, because its address is derived from a coin that will have been spent. There is \
         no undo, at any layer.\n\n\
         Each coin holds 1 mojo, and both are spent doing this. The blockchain has no way to pay \
         them back.\n\n\
         Anything you already published stays published: other computers hold copies of it and this \
         does not reach them. What ends is the blockchain record that says this profile is yours.",
        name = target.name,
        did = target.did,
        store = target.store_id,
    )
}

/// The button that goes through with it. Repeats the verb, so the destructive choice is never the
/// one labelled merely *OK*.
pub const CONFIRM_VERB: &str = "Delete permanently";

/// The way out. Present on every confirmation, and the default — `professional-ui`'s never-trap
/// rule, on the one surface in this app where a mis-press cannot be undone.
pub const CANCEL_VERB: &str = "Keep this profile";

/// What the whole ceremony IS, for the transaction sheet's heading.
pub fn what(target: &MeltTarget) -> String {
    format!("Deleting {}", target.name)
}

/// What is happening right now, named by half so a person can see how far it got.
pub fn melting(half: MeltHalf, target: &MeltTarget) -> String {
    format!("Deleting {}'s {}", target.name, half.noun())
}

/// The sentence for a profile both of whose halves are gone.
pub fn deleted(target: &MeltTarget) -> String {
    format!(
        "{} is gone from the blockchain. Its identity no longer resolves and its store has no \
         further generation. Copies of anything it published are still held by whoever already had \
         them.",
        target.name
    )
}

/// The sentence for a profile that was ALREADY off the chain before this began.
pub fn already_gone(target: &MeltTarget) -> String {
    format!(
        "{} was already gone from the blockchain, so DIG spent nothing.",
        target.name
    )
}

/// What to do about a profile that was already gone: nothing, and why that is fine.
pub const ALREADY_GONE_NEXT: &str =
    "There is nothing left to delete. This computer will stop listing the profile.";

/// A build that cannot reach the chain, told so rather than left silent.
pub const NO_TRANSPORT: &str =
    "This version of DIG cannot reach the blockchain to delete a profile, so nothing was spent.";

/// The remedy for that build — a sentence naming no door is the dead end dig_ecosystem#1800 removed.
pub const NO_TRANSPORT_NEXT: &str =
    "Start your DIG node, or install a newer DIG and a newer node, and try again.";

/// How the ceremony ended when it did not finish: what IS gone, what is NOT, and what to do.
///
/// `done` is the halves the chain has already proved, so the sentence describes the profile's real
/// state rather than the attempt's. That is the difference between *"deletion failed"* — which
/// leaves a person believing nothing happened — and a profile whose identity is genuinely ended.
pub(super) fn stopped_after(
    done: &[MeltHalf],
    stopped_at: MeltHalf,
    target: &MeltTarget,
    stopped: &MeltStopped,
) -> Stage {
    let gone = match done.is_empty() {
        true => format!("Nothing about {} was deleted.", target.name),
        false => format!(
            "{}'s {} is already gone from the blockchain and cannot be brought back.",
            target.name,
            list(done)
        ),
    };
    let (cause, next) = match stopped {
        MeltStopped::Refused(why) => (
            why.sentence(),
            match why.profile_is_unchanged() {
                true => format!(
                    "Its {} is still there. You can try deleting the profile again.",
                    stopped_at.noun()
                ),
                false => format!(
                    "DIG does not know what happened to its {}. Wait a few minutes and look at the \
                     profile again before trying a second time — a second attempt while the first \
                     is still in flight spends twice.",
                    stopped_at.noun()
                ),
            },
        ),
        MeltStopped::Unproved(pushed) => (
            format!(
                "DIG sent the deletion of {name}'s {noun} to the blockchain and stopped waiting for \
                 it. It may still go through — the coin is {coin}.",
                name = target.name,
                noun = pushed.half.noun(),
                coin = pushed.coin_id,
            ),
            "Do NOT try again yet: a second attempt while the first is still in flight spends \
             twice. Look at the profile again in a few minutes."
                .to_string(),
        ),
    };
    Stage::Failed {
        why: format!("{gone}\n\n{cause}"),
        next,
    }
}

/// The halves in `done`, as a person reads them.
fn list(done: &[MeltHalf]) -> String {
    let nouns: Vec<&str> = done.iter().map(|half| half.noun()).collect();
    nouns.join(" and ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> MeltTarget {
        MeltTarget {
            ix: 1,
            name: "“work”".to_string(),
            did: format!("did:chia:{}", "ab".repeat(16)),
            store_id: "cd".repeat(32),
        }
    }

    /// Every sentence this module can paint, so a sweep cannot fall behind the copy.
    fn every_sentence() -> Vec<String> {
        let t = target();
        let mut all = vec![
            DELETE_LABEL.to_string(),
            CONFIRM_TITLE.to_string(),
            CONFIRM_VERB.to_string(),
            CANCEL_VERB.to_string(),
            NO_TRANSPORT.to_string(),
            NO_TRANSPORT_NEXT.to_string(),
            ALREADY_GONE_NEXT.to_string(),
            confirm_body(&t),
            what(&t),
            deleted(&t),
            already_gone(&t),
        ];
        for half in [MeltHalf::Did, MeltHalf::Store] {
            all.push(melting(half, &t));
        }
        all
    }

    /// **No sentence promises the 1-mojo singleton amount back.**
    ///
    /// The one claim here that would be false at the puzzle level rather than merely optimistic:
    /// `(51 () -113)` occupies the singleton's one permitted odd-amount `CREATE_COIN`, so a refund
    /// is unexpressible. A person told they get it back and does not is being lied to about money.
    ///
    /// Swept over every sentence, because the words would arrive most naturally in the reassuring
    /// half of a confirmation rather than in the warning.
    #[test]
    fn no_copy_promises_the_mojo_back() {
        for said in every_sentence() {
            let lowered = said.to_lowercase();
            for forbidden in ["refund", "returned to your wallet", "paid back", "get it back"] {
                assert!(
                    !lowered.contains(forbidden),
                    "the deletion copy says “{forbidden}”, promising an amount the singleton puzzle \
                     cannot pay out: {said}"
                );
            }
        }
        // The control: the cost IS stated, so the sweep above is passing on copy that explains
        // rather than on copy that stays silent about money altogether.
        assert!(
            confirm_body(&target()).contains("1 mojo"),
            "the confirmation never says what deleting costs"
        );
    }

    /// **No sentence claims that already-published content is un-published.**
    ///
    /// Peers hold bodies keyed on `(store_id, root)`; melting the store ends its lineage and reaches
    /// nobody's copy. Both directions are asserted: the claim must be absent, and the truth must be
    /// present — a confirmation silent on the point leaves a person believing the opposite.
    #[test]
    fn no_copy_claims_that_published_content_is_taken_back() {
        let body = confirm_body(&target()).to_lowercase();
        for forbidden in ["erases your content", "removes it from other", "unpublish"] {
            assert!(
                !body.contains(forbidden),
                "the confirmation claims published content is withdrawn, which nothing on chain can \
                 do: {body}"
            );
        }
        assert!(
            body.contains("stays published"),
            "the confirmation never says that what was already published is still out there: {body}"
        );
    }

    /// **The confirmation names what is destroyed — this profile's own DID and store — rather than
    /// asking whether the person is sure.**
    ///
    /// The fixture's ids are distinct from each other, so a body that printed one of them twice
    /// fails; a fixture reusing one value could not tell that apart.
    #[test]
    fn the_confirmation_names_the_identity_and_the_store_it_will_end() {
        let t = target();
        let body = confirm_body(&t);
        assert!(body.contains(&t.did), "the DID being ended is not named: {body}");
        assert!(
            body.contains(&t.store_id),
            "the store being ended is not named: {body}"
        );
        assert!(
            body.to_lowercase().contains("cannot be re-created"),
            "the confirmation does not say the identity can never come back: {body}"
        );
    }

    /// **A stopped ceremony describes the PROFILE's state, not the attempt's** — and the two halves
    /// produce different sentences.
    ///
    /// The load-bearing leg is the second: after the DID melted, *"deletion failed"* would leave a
    /// person believing their identity survives when it is permanently gone. Both are asserted
    /// against the same failure so only the `done` list differs.
    #[test]
    fn a_stopped_deletion_says_which_half_is_already_permanently_gone() {
        let t = target();
        let why = MeltStopped::Refused(super::super::ProfileMeltError::Rejected("no".into()));

        let Stage::Failed { why: nothing, .. } = stopped_after(&[], MeltHalf::Did, &t, &why) else {
            panic!("a stopped ceremony did not report a failure");
        };
        assert!(
            nothing.contains("Nothing about"),
            "a ceremony that spent nothing did not say so: {nothing}"
        );

        let Stage::Failed { why: partial, .. } =
            stopped_after(&[MeltHalf::Did], MeltHalf::Store, &t, &why)
        else {
            panic!("a stopped ceremony did not report a failure");
        };
        assert!(
            partial.contains(MeltHalf::Did.noun()) && partial.contains("cannot be brought back"),
            "a profile whose identity is permanently gone was told nothing happened: {partial}"
        );
    }

    /// **Every ending names a next step**, including the one whose next step is to wait.
    #[test]
    fn every_ending_tells_the_person_what_to_do_next() {
        let t = target();
        let endings = [
            stopped_after(&[], MeltHalf::Did, &t, &MeltStopped::Refused(
                super::super::ProfileMeltError::ChainUnreachable("no node".into()),
            )),
            stopped_after(
                &[MeltHalf::Did],
                MeltHalf::Store,
                &t,
                &MeltStopped::Unproved(super::super::PushedMelt {
                    half: MeltHalf::Store,
                    coin_id: "ee".repeat(32),
                }),
            ),
        ];
        for ending in endings {
            let Stage::Failed { next, .. } = ending else {
                panic!("not a failure");
            };
            assert!(!next.trim().is_empty(), "an ending named no next step");
        }
    }
}
