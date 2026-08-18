//! Committing an edit: what the app asks of dig-account, and what it must do with the answer.
//!
//! # The one step with no error to warn you
//!
//! `commit_edit` hands back TWO things, and only one of them is on chain. The status says whether
//! the spend was pushed or confirmed; the BYTES are the body that new root commits to, and nothing
//! but this app is holding them at that moment. Drop them and the profile is unreadable — forever,
//! on every machine, with every layer reporting success, because from each layer's own point of view
//! the edit worked.
//!
//! So [`commit_and_persist`] is the only way this app commits an edit, and persisting is not a step
//! after the commit — it is PART of it. Its failures are reported with the bytes still in hand.
//!
//! # Pushed is not confirmed, and the two roots are not the same value
//!
//! `CommittedEdit::root()` is the root the edit commits to: a PREDICTION until the chain says
//! otherwise. `EditStatus::Confirmed { root }` is the chain-proved one. [`CommitOutcome`] keeps them
//! apart in its shape rather than in a comment, so a surface cannot render the first as the second.
//!
//! # Why a trait sits between this app and the crate
//!
//! [`ProfileEditSeam`] names exactly what the editor needs: read a profile, commit an edit. Two
//! things fall out. The whole editor — including the silent-loss failure above — is drivable in a
//! test against doubles, with no chain, no node and no money. And the concrete adapter is one file
//! that names the crate, so the rest of the editor holds no chia types at all.

use std::sync::Arc;
use std::thread;

use dig_account::edit::EditStatus;

use super::bodies::{BodyRead, BodyStore, BodyStoreError};
use super::draft::{ProfileDraft, SlotChange};
use super::field::ProfileField;
use super::pending::{PendingBodies, PendingBody};
use super::predict;
use crate::transaction::{Feed, Stage, Transaction};

/// A profile as it was read, in this app's vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSnapshot {
    /// The store the profile lives in, lowercase 64-hex.
    pub store_id: String,
    /// The root the chain anchors, lowercase 64-hex.
    pub root: String,
    /// The editable fields it publishes.
    pub values: std::collections::BTreeMap<ProfileField, String>,
    /// The verified body itself — the base an edit is computed over, and the base every size
    /// projection adjusts.
    ///
    /// Carried in full rather than as a length because the next body cannot be computed without it,
    /// and computing the next body BEFORE the spend is what lets it be written down before the
    /// spend (dig_ecosystem#3066).
    pub body: Vec<u8>,
}

impl ProfileSnapshot {
    /// The draft a person edits over this profile.
    pub fn draft(&self) -> ProfileDraft {
        ProfileDraft::over(self.values.clone(), self.body.len())
    }
}

/// What a commit produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Where the spend got to. The ONLY thing that may decide whether a surface says "confirmed".
    pub status: EditStatus,
    /// The root the edit commits to, lowercase 64-hex — a prediction until `status` proves it.
    pub root: String,
    /// The body those bytes are, which MUST be persisted. See this module's header.
    pub body: Vec<u8>,
}

impl CommitOutcome {
    /// The stage a surface may draw this as, given whatever the chain has reported.
    ///
    /// # The height is the evidence, and it is the ONLY evidence
    ///
    /// A height can only come from a chain read, so `Some(height)` is proof and `None` is its
    /// absence — that is the whole rule, and it is why this does not consult
    /// [`status`](Self::status).
    ///
    /// It once did, and that was wrong in both directions. A commit reports `Pushed` and never
    /// changes its mind, so a status-gated mapping could never promote a confirmation the watch went
    /// on to prove: the write sat at *waiting for the blockchain* forever, however long the chain
    /// had held it. And in the other direction, `EditStatus::Confirmed` is reachable with no height
    /// at all — the case where the edit's root was ALREADY the store's root, so nothing was spent
    /// and no block was involved — where naming a block would be inventing one.
    pub fn stage(&self, confirmed_at: Option<u32>) -> Stage {
        match confirmed_at {
            Some(height) => Stage::Confirmed {
                height,
                made: format!("Your profile now publishes {}.", self.root),
            },
            None => Stage::Pushed {
                id: self.root.clone(),
            },
        }
    }
}

/// Why an edit did not commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileEditError {
    /// The profile could not be read, so there is nothing to edit from.
    Unreadable(String),
    /// The store exists and NOTHING has ever been published under it.
    ///
    /// Its own variant because it is not a fault and has no retry (dig_ecosystem#3036): asking
    /// again cannot produce content nobody wrote. Reported only after a rebuild from this app's own
    /// mint seed has been tried and did not verify against the root the chain anchors.
    Unpublished,
    /// The chain anchors a root, and the bytes it commits to exist NOWHERE.
    ///
    /// # Why this is not [`Unpublished`](Self::Unpublished), and why the difference is the whole bug
    ///
    /// Both states reach a person through a node that answered `body_b64: null`, so for a while they
    /// were reported as one — and the one they were reported as was the reassuring one. A person
    /// whose content was permanently lost read *"nothing has gone wrong"* over a profile that had
    /// been destroyed (dig_ecosystem#3041). They are told apart by the ROOT: a store still sitting at
    /// the root its mint anchored has genuinely never published anything, and any other root was
    /// produced by a real edit whose bytes are now gone.
    ///
    /// # The remedy, which is the reason the state exists at all
    ///
    /// Nothing recovers the bytes — no node, no peer, no reinstall can produce a preimage of a hash.
    /// What a person CAN do is publish a fresh body: retype the content, and let the chain confirm
    /// the new root that commits to it. So this is an ordinary state with a door, not a dead end.
    BodyLost {
        /// The root the chain anchors and nothing holds the preimage of. Shown verbatim, so a
        /// person can check the claim themselves rather than take the app's word for it.
        root: String,
    },
    /// A body exists and does NOT commit to the root the chain anchors.
    ///
    /// Kept apart from [`Unreadable`](Self::Unreadable) because it is a security refusal rather
    /// than weather: the remedy is never "try again", and wording it as one invites a person to
    /// keep pressing a control that is correctly refusing them.
    Inconsistent,
    /// The account is locked, so nothing can be signed.
    Locked,
    /// The mempool DECLINED the bundle: a known "no", and the store's root is unchanged.
    Rejected(String),
    /// The chain could not be asked, so the outcome is UNKNOWN and the edit may still confirm.
    ///
    /// Kept apart from [`Rejected`](Self::Rejected) because the remedies invert: a rejected edit is
    /// rebuilt, an unanswered one is waited on.
    ChainUnreachable(String),
    /// The crate refused to build the edit at all — an empty batch, a protected slot, a body that
    /// cannot be encoded.
    Refused(String),
    /// The spend committed and the BYTES could not be kept.
    ///
    /// Its own variant, and the most important one here: the root may be on chain while nothing
    /// holds its preimage. A surface reaching this must say the edit went through AND that the
    /// content is not stored yet — never one without the other.
    NotPersisted {
        /// What went wrong with the store.
        why: BodyStoreError,
        /// The root that is now, or will shortly be, on chain.
        root: String,
        /// Whether this computer holds a copy of the bytes, to be handed to the node later.
        ///
        /// The difference between an inconvenience and a permanent loss, so it is a field rather
        /// than an assumption: a sentence that promised a retry this app cannot make would be the
        /// most damaging thing the editor could say.
        kept_locally: bool,
    },
}

impl ProfileEditError {
    /// What to tell a person, naming what is true and what to do.
    pub fn sentence(&self) -> String {
        match self {
            Self::Unreadable(why) => format!("DIG could not read your profile: {why}"),
            Self::Unpublished => super::copy::UNPUBLISHED.to_string(),
            Self::BodyLost { root } => super::copy::body_lost(root),
            Self::Inconsistent => super::copy::INCONSISTENT.to_string(),
            Self::Locked => {
                "Your account is locked, so DIG cannot sign the change. Unlock it and try again."
                    .to_string()
            }
            Self::Rejected(why) => {
                format!("The blockchain declined the change, so your profile is unchanged: {why}")
            }
            Self::ChainUnreachable(why) => format!(
                "DIG could not reach the blockchain, so it does not know whether your change went \
                 through: {why}. Wait a minute and look at your profile again before trying it a \
                 second time."
            ),
            Self::Refused(why) => format!("DIG could not make that change: {why}"),
            Self::NotPersisted {
                why,
                root,
                kept_locally,
            } => format!(
                "Your change was sent to the blockchain, but DIG could not store the profile \
                 content it points at ({root}) on your node, so other people cannot read your \
                 profile yet. {} {}",
                why.sentence(),
                match kept_locally {
                    true =>
                        "DIG has kept a copy of it on this computer, so nothing is lost. It keeps \
                         offering that copy to your node while DIG is open, and again the next time \
                         DIG starts.",
                    // No copy was kept, so there is nothing on this computer to offer again — and a
                    // sentence inviting the person to wait would have them waiting on a retry with
                    // no bytes behind it (dig_ecosystem#3080). Making the change again is the only
                    // remedy this app has, so it is the only one it names.
                    false =>
                        "DIG could NOT keep a copy on this computer, so it has nothing left to \
                         offer your node: the change will need to be made again.",
                }
            ),
        }
    }

    /// What to tell a person when this failure happened during a READ.
    ///
    /// # Why the same failure needs two sentences
    ///
    /// [`sentence`](Self::sentence) is written for a commit, and every word of it assumes one: an
    /// unreachable chain becomes *"DIG does not know whether your change went through"*, which is
    /// exactly right after a push and a fabrication after a read, where nothing was ever sent. A
    /// person told that by a card that is merely failing to LOAD has been informed of a transaction
    /// they did not make — and the advice attached to it, wait before trying again, is advice about
    /// a spend.
    ///
    /// The arms that can only arise from a commit keep their commit wording, because reaching them
    /// from a read is a bug rather than a state, and inventing a read-flavoured sentence for them
    /// would hide it.
    pub fn while_reading(&self) -> String {
        match self {
            Self::ChainUnreachable(why) => format!(
                "DIG could not reach the blockchain to read your profile: {why}. Nothing has \
                 changed — try again in a moment."
            ),
            Self::Locked => {
                "Your account is locked, so DIG cannot read your profile. Unlock it to see and \
                 change what it says."
                    .to_string()
            }
            // The READ wording, which invites the person to type the details in again. Its commit
            // counterpart in `sentence` is the refusal, because answering a press of publish with
            // "publish them" is a loop with no exit.
            Self::BodyLost { root } => super::copy::body_lost(root),
            other => other.sentence(),
        }
    }

    /// Whether the person's profile is definitely unchanged, so offering the form again is safe.
    ///
    /// Deliberately conservative: only the two outcomes that provably never reached a mempool say
    /// yes. An unreachable chain may have taken the bundle, and a failed persist happened AFTER a
    /// successful push.
    pub fn profile_is_unchanged(&self) -> bool {
        matches!(
            self,
            Self::Rejected(_)
                | Self::Refused(_)
                | Self::Locked
                | Self::Unpublished
                | Self::BodyLost { .. }
                | Self::Inconsistent
        )
    }
}

/// What the editor needs of dig-account.
///
/// Small on purpose: everything it takes and returns is a plain owned value, so no chia type crosses
/// into the editor and a test can implement the whole thing in a dozen lines.
pub trait ProfileEditSeam: Send + Sync {
    /// The store this profile's content lives in, lowercase 64-hex.
    ///
    /// # Why this is its own method and not read off a snapshot
    ///
    /// The store is decided when the seam is built — it is the anchor's launcher id — so answering
    /// costs nothing and touches no chain. Taking it from [`read`](Self::read) instead would make
    /// every caller that merely needs to NAME the store perform a node round trip, and the caller
    /// that needs it is [`EditService::save`](super::service::EditService::save), which runs on the
    /// thread that paints. That is the freeze dig-app 12.6.0 was cut to fix.
    fn store_id(&self) -> String;

    /// Read the active profile as the chain currently publishes it.
    fn read(&self) -> Result<ProfileSnapshot, ProfileEditError>;

    /// Build, sign and push the edit, and hand back the status AND the bytes it produced.
    fn commit(
        &self,
        changes: &[(ProfileField, SlotChange)],
    ) -> Result<CommitOutcome, ProfileEditError>;

    /// Publish `changes` as a WHOLE fresh profile, reading nothing first.
    ///
    /// # Why this is a second method and not a flag on [`commit`](Self::commit)
    ///
    /// A commit is a DELTA: dig-account reads the published body, applies the change, and publishes
    /// the result. Over a profile whose body bytes exist nowhere that read cannot succeed, so the
    /// delta operation cannot succeed either — the remedy the app offers such a person would fail
    /// inside the very call that was supposed to carry it out (dig_ecosystem#3041).
    ///
    /// This is `ProfileEditor::publish_profile`, whose whole capability is not reading the old body.
    /// It is required rather than defaulted because a seam that quietly fell back to the delta path
    /// would fail exactly where it is needed and nowhere else, which is the shape of defect this
    /// method exists to remove.
    ///
    /// # What the caller is agreeing to
    ///
    /// Everything not in `changes` is GONE from the published profile. Only a reading that already
    /// holds nothing — [`ProfileEditError::BodyLost`] — may take this route, and the routing is
    /// [`EditService::save`](super::service::EditService::save)'s, not a surface's.
    fn publish_fresh(
        &self,
        changes: &[(ProfileField, SlotChange)],
    ) -> Result<CommitOutcome, ProfileEditError>;

    /// Whether the chain now anchors `root`, and the height of the coin that carries it.
    ///
    /// Three answers, all of which a caller must keep apart. `Ok(Some(height))` is chain-proved and
    /// is the ONLY thing that may become [`Stage::Confirmed`]. `Ok(None)` is a real answer — the
    /// chain was asked and does not anchor that root yet. `Err` is nobody having been able to ask,
    /// which is not the same as "not yet" and must never be drawn as one.
    fn confirmation(&self, root: &str) -> Result<Option<u32>, ProfileEditError>;
}

/// The editing seams a build actually has.
///
/// Modelled as a value for [`MintSeams`](crate::account::chain_mint::MintSeams)'s reason: whether
/// the editor may be OFFERED is read off the seams that exist, never asserted beside them, so a
/// build with no chain transport cannot show a Save control that has nothing to save through.
pub enum EditSeams {
    /// A real seam and somewhere to keep the bytes.
    Wired {
        /// Reads and commits.
        seam: Arc<dyn ProfileEditSeam>,
        /// Keeps what the commit produces.
        bodies: Arc<dyn BodyStore>,
        /// Keeps it on THIS computer until the node will take it (dig_ecosystem#3066).
        pending: Arc<dyn PendingBodies>,
    },
    /// This build cannot read chain or push a bundle, so no profile can be edited on this machine.
    NoChainTransport,
}

impl EditSeams {
    /// Whether editing can be attempted at all.
    pub fn is_possible(&self) -> bool {
        matches!(self, Self::Wired { .. })
    }
}

/// Which of the two publishing operations an attempt uses.
///
/// A value rather than an inference, because the two are told apart by the READING — and the
/// reading lives in [`EditService`](super::service::EditService), not here. Passing it in keeps the
/// decision at the one place that can make it correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditRoute {
    /// The ordinary edit: read the published body, apply the change, publish the result.
    Delta,
    /// Publish a whole fresh body, reading nothing. Only over a body that is gone.
    FreshBody,
}

/// Commit `changes`, and KEEP the bytes the commit produced.
///
/// The two halves are one act. A caller cannot obtain a [`CommitOutcome`] from this function without
/// its body having been stored and read back, which is what stops the bytes being dropped by a
/// caller who simply did not know they mattered.
///
/// # The read-back, and why a successful `put` is not enough
///
/// A store that accepts everything and keeps nothing returns `Ok(())`, and the profile is then
/// exactly as lost as if nothing had been called at all. So the body is read back at the root it was
/// stored under, and a store that does not have it is a failure — [`BodyRead::Nothing`] here is not
/// an ordinary absence, it is this app's own bytes missing from the place it just put them.
pub fn commit_and_persist(
    seam: &dyn ProfileEditSeam,
    bodies: &dyn BodyStore,
    pending: &dyn PendingBodies,
    store_id: &str,
    changes: &[(ProfileField, SlotChange)],
    route: EditRoute,
) -> Result<CommitOutcome, ProfileEditError> {
    let foreseen = write_down_before_the_spend(seam, pending, store_id, changes, route);

    let outcome = match publish(seam, changes, route) {
        Ok(outcome) => outcome,
        Err(error) => {
            // Only an outcome that PROVES nothing reached a mempool may drop the copy. An
            // unanswered chain may have taken the bundle, and deleting the preimage of a root that
            // is quietly confirming is the exact loss this function exists to prevent.
            if let (Some(root), true) = (&foreseen, error.profile_is_unchanged()) {
                let _ = pending.forget(store_id, root);
            }
            return Err(error);
        }
    };

    // The prediction is never trusted over the commit's own answer: a root the commit did not
    // produce is a body no node will ever accept, so it is dropped here, in the call that made it.
    if let Some(root) = foreseen.filter(|root| root != &outcome.root) {
        let _ = pending.forget(store_id, &root);
    }
    let kept_locally = pending
        .remember(&PendingBody {
            store_id: store_id.to_string(),
            root: outcome.root.clone(),
            body: outcome.body.clone(),
        })
        .is_ok();

    let kept = |why: BodyStoreError| ProfileEditError::NotPersisted {
        why,
        root: outcome.root.clone(),
        kept_locally,
    };

    bodies
        .put(store_id, &outcome.root, &outcome.body)
        .map_err(kept)?;

    match bodies.get(store_id, &outcome.root).map_err(kept)? {
        BodyRead::Held(held) if held == outcome.body => {
            // The node has them, proved by reading them back, so this machine no longer needs to.
            let _ = pending.forget(store_id, &outcome.root);
            Ok(outcome)
        }
        BodyRead::Held(held) => Err(kept(BodyStoreError::Refused(format!(
            "your node stored {} bytes where DIG sent {}",
            held.len(),
            outcome.body.len()
        )))),
        BodyRead::Nothing => Err(kept(BodyStoreError::Refused(
            "your node accepted the profile content and then did not have it".to_string(),
        ))),
    }
}

/// Run the attempt through the operation `route` names.
///
/// The one place the two operations are chosen between, so a reader can see that a `FreshBody`
/// attempt never reaches [`ProfileEditSeam::commit`] and a `Delta` one never reaches
/// [`ProfileEditSeam::publish_fresh`].
fn publish(
    seam: &dyn ProfileEditSeam,
    changes: &[(ProfileField, SlotChange)],
    route: EditRoute,
) -> Result<CommitOutcome, ProfileEditError> {
    match route {
        EditRoute::Delta => seam.commit(changes),
        EditRoute::FreshBody => seam.publish_fresh(changes),
    }
}

/// Work out what the edit will publish and write it down, BEFORE anything is signed or pushed.
///
/// Returns the root it wrote down, or `None` when no honest prediction was available — an
/// unreadable current profile, an unencodable next one, or a store that could not keep it. `None`
/// is not reported to anyone: it means this attempt has only the post-commit copy to fall back on,
/// which is what shipped before, and refusing to save someone's profile because a cache write
/// failed would be a second failure invented from the first.
fn write_down_before_the_spend(
    seam: &dyn ProfileEditSeam,
    pending: &dyn PendingBodies,
    store_id: &str,
    changes: &[(ProfileField, SlotChange)],
    route: EditRoute,
) -> Option<String> {
    let (root, body) = match route {
        EditRoute::Delta => {
            let snapshot = seam.read().ok()?;
            let current_root = root_bytes(&snapshot.root)?;
            predict::predicted_body(&snapshot.body, current_root, changes)?
        }
        // Nothing is read, and nothing CAN be: this route exists because the published body is
        // gone. The fresh body is computed from the typed fields alone, by the same constructor the
        // seam publishes from, so the copy written down here is the preimage of the root the chain
        // will confirm rather than a second guess at it.
        EditRoute::FreshBody => predict::fresh_body(changes)?,
    };
    pending
        .remember(&PendingBody {
            store_id: store_id.to_string(),
            root: root.clone(),
            body,
        })
        .ok()?;
    Some(root)
}

/// A 64-hex root as the bytes the format checks against.
fn root_bytes(root: &str) -> Option<[u8; 32]> {
    hex::decode(root).ok()?.try_into().ok()
}

/// The line a person reads while their edit is being written.
const WHAT: &str = "Saving your profile";

/// How patiently a pushed edit is watched.
///
/// A value rather than three constants so a test can drive the whole watch — including the two
/// giving-up paths — in milliseconds instead of a quarter of an hour. A watch nobody can exercise
/// cheaply is a watch nobody exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    /// How long to keep looking before giving up.
    pub within: std::time::Duration,
    /// How long to wait between looks.
    pub every: std::time::Duration,
    /// How many consecutive UNANSWERED looks end the watch.
    ///
    /// An unreachable chain is not a "no", so a handful are ridden out. Enough in a row means the
    /// app cannot see the chain at all, and polling a node that is not there tells nobody anything.
    pub unreachable_looks_allowed: usize,
}

impl Default for Watch {
    /// Generous enough that an ordinary mainnet confirmation always resolves on screen, and bounded
    /// because a worker that watches forever is a thread this app never gets back.
    fn default() -> Self {
        Self {
            within: std::time::Duration::from_secs(15 * 60),
            every: std::time::Duration::from_secs(10),
            unreachable_looks_allowed: 12,
        }
    }
}

/// Watch a pushed edit until the chain proves it, publishing the result into `feed`.
///
/// Every exit is honest about what is known. Confirmed carries the height the chain reported.
/// Running out of patience does NOT become a failure of the edit — it becomes a statement that the
/// app stopped watching and that the change may still land, with the one instruction that matters:
/// do not send it again.
fn watch_for_confirmation(
    seam: &dyn ProfileEditSeam,
    outcome: &CommitOutcome,
    opening: &Transaction,
    feed: &Feed,
    watch: Watch,
) {
    let until = std::time::Instant::now() + watch.within;
    let mut unanswered = 0usize;

    while std::time::Instant::now() < until {
        match seam.confirmation(&outcome.root) {
            Ok(Some(height)) => {
                feed.publish(opening.at(outcome.stage(Some(height))));
                return;
            }
            Ok(None) => unanswered = 0,
            Err(_) => {
                unanswered += 1;
                if unanswered >= watch.unreachable_looks_allowed {
                    break;
                }
            }
        }
        std::thread::sleep(watch.every);
    }

    feed.publish(opening.at(Stage::Failed {
        why: format!(
            "Your change was sent to the blockchain and DIG stopped waiting for it. It may still \
             confirm — the change is at {}.",
            outcome.root
        ),
        next: "Do NOT save it again yet: a second attempt while the first is still waiting spends \
               twice. Open your profile in a few minutes to see what it says."
            .to_string(),
    }));
}

/// Run a commit OFF the painting thread, reporting into `feed`.
///
/// # Why this is not called inline
///
/// dig-app 12.6.0 exists because a chain write ran on the thread that paints: the window stopped
/// repainting for the length of a mainnet ceremony, which from outside is indistinguishable from a
/// crash. An edit is a shorter ceremony than a mint and it is the same defect — a person who
/// force-quits a frozen window during a push has a root heading for the chain and an app that never
/// stored its body.
///
/// Returns immediately. Everything a surface needs to draw is published to the feed.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authority: what to publish, which operation publishes it,               where the bytes go, and where progress is reported"
)]
pub fn start_commit(
    seam: Arc<dyn ProfileEditSeam>,
    bodies: Arc<dyn BodyStore>,
    pending: Arc<dyn PendingBodies>,
    store_id: String,
    changes: Vec<(ProfileField, SlotChange)>,
    route: EditRoute,
    feed: Feed,
    watch: Watch,
) {
    let opening = Transaction::starting(WHAT, None);
    feed.publish(opening.clone());
    thread::spawn(move || {
        // Signing happens inside the seam, on THIS thread and in this process (§908). The stage is
        // published before the call rather than after, because the call is the slow part and a
        // person watching deserves to know which slow part it is.
        feed.publish(opening.at(Stage::Signing));
        match commit_and_persist(&*seam, &*bodies, &*pending, &store_id, &changes, route) {
            Ok(outcome) => {
                // Published BEFORE the watch begins, because the push is a fact the moment it
                // happens and the watch takes minutes. The stage is `Pushed` — never `Confirmed` —
                // until the chain says otherwise.
                feed.publish(opening.at(outcome.stage(None)));
                watch_for_confirmation(&*seam, &outcome, &opening, &feed, watch);
            }
            Err(error) => feed.publish(
                opening.at(Stage::Failed {
                    why: error.sentence(),
                    next: match error.profile_is_unchanged() {
                        // The money sentence, on the ONLY outcomes that prove no bundle reached a
                        // mempool. It is said here rather than in any one arm's own wording because
                        // the question a person has after pressing a control that costs XCH is the
                        // same question whatever refused them, and a failure that goes silent on it
                        // leaves them to guess (dig_ecosystem#3041).
                        true => super::copy::NOTHING_WAS_SPENT.into(),
                        false => {
                            "Open your profile again in a minute to see what it says before you \
                              try a second time."
                                .into()
                        }
                    },
                }),
            ),
        }
    });
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Seams for tests that need a `Wired` shape and never call through it — the capability
    //! readings, which are about whether seams EXIST rather than what they answer.

    use super::*;

    /// A seam that would refuse everything, if anything asked it.
    pub(crate) struct NeverSeam;

    impl ProfileEditSeam for NeverSeam {
        /// Never routed here: this double stands for a DELTA edit, and a fresh publish
        /// replaces the whole profile. Refusing rather than delegating means a test that
        /// took the wrong route fails instead of quietly passing on the other one.
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Refused(
                "this double publishes deltas only".into(),
            ))
        }
        fn store_id(&self) -> String {
            "00".repeat(32)
        }
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            Err(ProfileEditError::Locked)
        }
        fn commit(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Locked)
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Err(ProfileEditError::Locked)
        }
    }

    /// A body store that would refuse everything, if anything asked it.
    pub(crate) struct NeverBodies;

    impl BodyStore for NeverBodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Err(BodyStoreError::NoToken)
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            Err(BodyStoreError::NoToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use dig_account::edit::EditError;
    use dig_social_profile::body::VerifiedBody;
    use dig_social_profile::profile::Profile;
    use dig_social_profile::slot::SlotId;
    use dig_social_profile::value::Value;

    use super::super::bodies::doubles::{ForgetfulBodies, InMemoryBodies, RefusingBodies};
    use super::super::pending::doubles::{InMemoryPending, RefusingPending};
    use super::super::pending::{PendingBodies as _, PendingBody};
    use super::*;

    /// The profile the seams below are editing, as real DPB bytes and the root they commit to.
    ///
    /// Real rather than a placeholder because the pre-spend write is computed FROM these bytes: a
    /// fixture the format cannot open predicts nothing, and every test of the pre-spend write over
    /// it would pass while proving the write never happens.
    fn current_body() -> (Vec<u8>, [u8; 32]) {
        let mut profile = Profile::new();
        profile.set(
            SlotId(ProfileField::DisplayName.slot().id()),
            Value::Utf8("Ada".into()),
        );
        let body = VerifiedBody::from_profile(&profile).expect("a body");
        (body.as_bytes().to_vec(), body.root())
    }

    /// A seam that commits the edit the way the real crate does: the body it returns is the one
    /// the changes actually produce over [`current_body`], at the root that body commits to.
    ///
    /// [`Committing`] deliberately does NOT — it answers a fixed, unrelated root — so the two
    /// together cover both sides of the prediction check.
    struct Honest;

    impl Honest {
        /// What committing `changes` publishes.
        fn published(changes: &[(ProfileField, SlotChange)]) -> (String, Vec<u8>) {
            let (bytes, root) = current_body();
            super::super::predict::predicted_body(&bytes, root, changes)
                .expect("the fixture edit encodes")
        }
    }

    impl ProfileEditSeam for Honest {
        /// Never routed here: this double stands for a DELTA edit, and a fresh publish
        /// replaces the whole profile. Refusing rather than delegating means a test that
        /// took the wrong route fails instead of quietly passing on the other one.
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Refused(
                "this double publishes deltas only".into(),
            ))
        }
        fn store_id(&self) -> String {
            STORE.into()
        }
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            Ok(ProfileSnapshot {
                store_id: STORE.into(),
                root: hex::encode(current_body().1),
                values: BTreeMap::new(),
                body: current_body().0,
            })
        }
        fn commit(
            &self,
            changes: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            let (root, body) = Self::published(changes);
            Ok(CommitOutcome {
                status: EditStatus::Pushed {
                    new_root: [0x22; 32],
                },
                root,
                body,
            })
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Ok(None)
        }
    }

    /// A node that refuses every `putBody` the way the live one does while the chain is still
    /// catching up — the exact refusal measured on 12.13.0.
    fn a_node_awaiting_confirmation() -> RefusingBodies {
        RefusingBodies(BodyStoreError::Refused(
            "root 371a… is not this store's confirmed on-chain root 7165… — the chain is the              authority"
                .into(),
        ))
    }

    const STORE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NEW_ROOT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// What a seam's chain answers when asked whether a root has landed.
    #[derive(Clone)]
    enum Chain {
        /// The chain anchors it, at this height.
        Confirms(u32),
        /// The chain answered, and does not anchor it yet.
        NotYet,
        /// Nobody could ask.
        Unreachable,
    }

    /// A seam that commits whatever it is given and hands back a body.
    struct Committing {
        /// What the commit reports.
        status: EditStatus,
        /// The bytes it produces.
        body: Vec<u8>,
        /// What it was asked to change, for the tests that care.
        asked: Mutex<Vec<(ProfileField, SlotChange)>>,
        /// What its chain says when the watch looks.
        chain: Chain,
        /// How many times the watch has looked.
        looks: Mutex<usize>,
    }

    impl Committing {
        fn pushed() -> Self {
            Self {
                status: EditStatus::Pushed {
                    new_root: [0x22; 32],
                },
                body: b"DIGP\x01the new body".to_vec(),
                asked: Mutex::new(Vec::new()),
                chain: Chain::Confirms(9_154_460),
                looks: Mutex::new(0),
            }
        }

        /// The same seam, over a chain that answers differently.
        fn over(chain: Chain) -> Self {
            Self {
                chain,
                ..Self::pushed()
            }
        }
    }

    impl ProfileEditSeam for Committing {
        /// Never routed here: this double stands for a DELTA edit, and a fresh publish
        /// replaces the whole profile. Refusing rather than delegating means a test that
        /// took the wrong route fails instead of quietly passing on the other one.
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Refused(
                "this double publishes deltas only".into(),
            ))
        }
        fn store_id(&self) -> String {
            STORE.into()
        }

        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            Ok(ProfileSnapshot {
                store_id: STORE.into(),
                root: hex::encode(current_body().1),
                values: BTreeMap::new(),
                body: current_body().0,
            })
        }

        fn commit(
            &self,
            changes: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            *self.asked.lock().expect("asked") = changes.to_vec();
            Ok(CommitOutcome {
                status: self.status.clone(),
                root: NEW_ROOT.into(),
                body: self.body.clone(),
            })
        }

        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            *self.looks.lock().expect("looks") += 1;
            match self.chain {
                Chain::Confirms(height) => Ok(Some(height)),
                Chain::NotYet => Ok(None),
                Chain::Unreachable => Err(ProfileEditError::ChainUnreachable("no node".into())),
            }
        }
    }

    /// A seam that refuses.
    struct Refusing(ProfileEditError);

    impl ProfileEditSeam for Refusing {
        /// The same refusal on both routes: this double stands for the FAILURE, so the route it
        /// arrived by must not change what a person is told about it.
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(self.0.clone())
        }
        fn store_id(&self) -> String {
            STORE.into()
        }
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            Err(self.0.clone())
        }
        fn commit(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(self.0.clone())
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Err(self.0.clone())
        }
    }

    /// A watch short enough to run inside a test, with the same SHAPE as the shipped one.
    fn a_brisk_watch() -> Watch {
        Watch {
            within: std::time::Duration::from_millis(300),
            every: std::time::Duration::from_millis(5),
            unreachable_looks_allowed: 3,
        }
    }

    fn a_change() -> Vec<(ProfileField, SlotChange)> {
        vec![(ProfileField::Bio, SlotChange::Set("Builds engines.".into()))]
    }

    #[test]
    fn a_committed_edit_keeps_its_bytes_at_its_root() {
        let seam = Committing::pushed();
        let bodies = InMemoryBodies::default();
        let outcome = commit_and_persist(
            &seam,
            &bodies,
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect("the edit commits");

        assert_eq!(
            bodies.get(STORE, &outcome.root),
            Ok(BodyRead::Held(b"DIGP\x01the new body".to_vec())),
            "the bytes the commit produced are not in the store at the root it produced"
        );
    }

    /// **The silent, permanent failure, made loud.**
    ///
    /// The store here accepts every put and holds nothing — exactly what a node with a broken or
    /// full content store does, and exactly what dropping the bytes looks like from the outside. The
    /// spend succeeded, so every layer's own answer is "fine"; only the read-back can tell. Without
    /// it this test passes while the profile is unreadable forever.
    #[test]
    fn a_store_that_accepts_and_forgets_fails_the_commit_rather_than_reporting_success() {
        let error = commit_and_persist(
            &Committing::pushed(),
            &ForgetfulBodies,
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("a commit whose body was not kept must not report success");

        match &error {
            ProfileEditError::NotPersisted { root, .. } => assert_eq!(root, NEW_ROOT),
            other => panic!("the wrong failure: {other:?}"),
        }
        // And the sentence must say BOTH true things, because either alone is a lie: the change was
        // sent, and the content is not stored.
        let said = error.sentence();
        assert!(said.contains("sent to the blockchain"), "said: {said}");
        assert!(
            said.contains("cannot read your profile yet"),
            "said: {said}"
        );
        assert!(
            !error.profile_is_unchanged(),
            "a failed persist happened AFTER a successful push; offering the form again invites a \
             second spend"
        );
    }

    /// A store that returns DIFFERENT bytes is as bad as one that returns none: whatever it serves
    /// will not rebuild to the root on chain.
    #[test]
    fn a_store_that_keeps_the_wrong_bytes_fails_the_commit() {
        struct Substituting;
        impl BodyStore for Substituting {
            fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
                Ok(())
            }
            fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
                Ok(BodyRead::Held(b"something else".to_vec()))
            }
        }
        let error = commit_and_persist(
            &Committing::pushed(),
            &Substituting,
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("bytes that are not the ones committed must not be accepted");
        assert!(matches!(error, ProfileEditError::NotPersisted { .. }));
    }

    /// A store that cannot be reached fails the commit as a persist failure — not as an edit that
    /// did not happen, because it did.
    #[test]
    fn an_unreachable_store_is_reported_as_the_edit_having_gone_through() {
        let bodies = RefusingBodies(BodyStoreError::Unreachable("no node".into()));
        let error = commit_and_persist(
            &Committing::pushed(),
            &bodies,
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("an unstorable body is a failure");
        assert!(!error.profile_is_unchanged());
        assert!(error.sentence().contains("sent to the blockchain"));
    }

    /// **A read that failed never tells a person a change was sent.**
    ///
    /// The card that fails to load and the card that has just pushed a spend share this error type,
    /// and the commit wording — *"DIG does not know whether your change went through"* — is a
    /// transaction a reader did not make, attached to advice about spending twice.
    #[test]
    fn a_failed_read_is_not_described_as_a_change_that_may_be_in_flight() {
        for error in [
            ProfileEditError::ChainUnreachable("timed out".into()),
            ProfileEditError::Locked,
            ProfileEditError::Unreadable("the body does not match the root".into()),
        ] {
            let said = error.while_reading().to_lowercase();
            assert!(
                !said.contains("your change") && !said.contains("was sent"),
                "a read failure claimed a change: {said}"
            );
            assert!(said.len() > 30, "too terse to act on: {said}");
        }
        // And the control: the COMMIT wording for the same error still says it, because after a
        // push that sentence is the true and load-bearing one.
        assert!(ProfileEditError::ChainUnreachable("timed out".into())
            .sentence()
            .contains("whether your change went through"));
    }

    /// An edit the mempool declined leaves the profile alone, and the form may be offered again.
    #[test]
    fn a_rejected_edit_leaves_the_profile_unchanged() {
        let seam = Refusing(ProfileEditError::Rejected("bad signature".into()));
        let error = commit_and_persist(
            &seam,
            &InMemoryBodies::default(),
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("a rejection is a failure");
        assert!(error.profile_is_unchanged());
    }

    /// An unanswered chain is NOT an unchanged profile: the bundle may be in a mempool right now,
    /// and telling a person to try again is telling them to spend twice.
    #[test]
    fn an_unreachable_chain_does_not_promise_the_profile_is_unchanged() {
        let seam = Refusing(ProfileEditError::ChainUnreachable("timed out".into()));
        let error = commit_and_persist(
            &seam,
            &InMemoryBodies::default(),
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("an unanswered chain is a failure");
        assert!(!error.profile_is_unchanged());
        assert!(error.sentence().contains("before trying it a second time"));
    }

    /// Nothing is put anywhere when the commit itself failed — a body stored under a root no chain
    /// carries is a node serving content nobody can verify.
    #[test]
    fn a_failed_commit_stores_nothing() {
        let bodies = InMemoryBodies::default();
        let seam = Refusing(ProfileEditError::Rejected("declined".into()));
        let _ = commit_and_persist(
            &seam,
            &bodies,
            &InMemoryPending::default(),
            STORE,
            &a_change(),
            EditRoute::Delta,
        );
        assert_eq!(bodies.get(STORE, NEW_ROOT), Ok(BodyRead::Nothing));
    }

    // -- the copy that survives a restart (dig_ecosystem#3066) ----------------------------------

    /// **A body the node will not take yet is kept on this computer.**
    ///
    /// # The fixture, and what this test does NOT prove
    ///
    /// The node here answers the way the live one did when this was measured: the chain has not
    /// confirmed the new root yet, so `putBody` is refused. A store that ACCEPTED the body would
    /// clear the entry, so the refusal is what makes the assertion below load-bearing at all.
    ///
    /// It does not prove the write happened BEFORE the push — the post-commit write satisfies it
    /// identically, which was confirmed by reverting the pre-spend call and watching this stay
    /// green. The ordering is pinned by
    /// [`a_commit_whose_outcome_is_unknown_keeps_the_copy`], which is the only test here that a
    /// commit-answer-only implementation cannot pass.
    #[test]
    fn a_body_the_node_will_not_take_yet_is_kept_on_this_computer() {
        let pending = InMemoryPending::default();
        let changes = a_change();
        let (expected_root, expected_body) = Honest::published(&changes);

        let error = commit_and_persist(
            &Honest,
            &a_node_awaiting_confirmation(),
            &pending,
            STORE,
            &changes,
            EditRoute::Delta,
        )
        .expect_err("a node that will not take the body is not a success");

        assert_eq!(
            pending.all().expect("reads"),
            vec![PendingBody {
                store_id: STORE.to_string(),
                root: expected_root,
                body: expected_body,
            }],
            "the bytes the chain now commits to are held nowhere but this process"
        );
        // And the person is told the truth about BOTH halves: the change went out, and the content
        // is safe here meanwhile.
        match &error {
            ProfileEditError::NotPersisted { kept_locally, .. } => assert!(*kept_locally),
            other => panic!("the wrong failure: {other:?}"),
        }
        let said = error.sentence();
        assert!(said.contains("sent to the blockchain"), "said: {said}");
        assert!(said.contains("kept a copy"), "said: {said}");
        // Both retries it promises must be ones code actually performs. Since dig_ecosystem#3078
        // that is two: `EditService::retry_pending_bodies` on a cadence while the app is open, and
        // the start-up drain in `install_edit_seams`. Before #3078 the in-session half was a promise
        // nothing kept, and this assertion is the thing that has to move when it becomes true —
        // hence naming the mechanism rather than banning a phrase.
        assert!(said.contains("while DIG is open"), "said: {said}");
        assert!(said.contains("next time DIG starts"), "said: {said}");
    }

    /// **The pre-spend write happens even if the COMMIT never returns.**
    ///
    /// # Why this drives the seam rather than asserting on the happy path
    ///
    /// The nearest wrong implementation writes the body from the commit's own answer — which is
    /// correct in every test where the commit returns, and absent in exactly the case the ticket
    /// exists for: a process that dies between the push and the return. The seam here reports an
    /// UNANSWERED chain, which is the closest a test can get to that death and is the one commit
    /// outcome that must NOT clear the copy.
    #[test]
    fn a_commit_whose_outcome_is_unknown_keeps_the_copy() {
        struct PushedThenSilent;
        impl ProfileEditSeam for PushedThenSilent {
            /// Never routed here: this double stands for a DELTA edit, and a fresh publish
            /// replaces the whole profile. Refusing rather than delegating means a test that
            /// took the wrong route fails instead of quietly passing on the other one.
            fn publish_fresh(
                &self,
                _: &[(ProfileField, SlotChange)],
            ) -> Result<CommitOutcome, ProfileEditError> {
                Err(ProfileEditError::Refused(
                    "this double publishes deltas only".into(),
                ))
            }
            fn store_id(&self) -> String {
                STORE.into()
            }
            fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
                Honest.read()
            }
            fn commit(
                &self,
                _: &[(ProfileField, SlotChange)],
            ) -> Result<CommitOutcome, ProfileEditError> {
                Err(ProfileEditError::ChainUnreachable("no answer".into()))
            }
            fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
                Err(ProfileEditError::ChainUnreachable("no answer".into()))
            }
        }

        let pending = InMemoryPending::default();
        let changes = a_change();
        let _ = commit_and_persist(
            &PushedThenSilent,
            &InMemoryBodies::default(),
            &pending,
            STORE,
            &changes,
            EditRoute::Delta,
        );

        assert_eq!(
            pending.all().expect("reads"),
            vec![PendingBody {
                store_id: STORE.to_string(),
                root: Honest::published(&changes).0,
                body: Honest::published(&changes).1,
            }],
            "an edit that may be in a mempool right now had its only copy deleted"
        );
    }

    /// An edit the mempool DECLINED leaves nothing behind: the root is not on chain and never will
    /// be, so a copy of its body would be a file no drain can ever clear.
    #[test]
    fn a_declined_edit_leaves_no_copy_behind() {
        struct Declining;
        impl ProfileEditSeam for Declining {
            /// Never routed here: this double stands for a DELTA edit, and a fresh publish
            /// replaces the whole profile. Refusing rather than delegating means a test that
            /// took the wrong route fails instead of quietly passing on the other one.
            fn publish_fresh(
                &self,
                _: &[(ProfileField, SlotChange)],
            ) -> Result<CommitOutcome, ProfileEditError> {
                Err(ProfileEditError::Refused(
                    "this double publishes deltas only".into(),
                ))
            }
            fn store_id(&self) -> String {
                STORE.into()
            }
            fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
                Honest.read()
            }
            fn commit(
                &self,
                _: &[(ProfileField, SlotChange)],
            ) -> Result<CommitOutcome, ProfileEditError> {
                Err(ProfileEditError::Rejected("declined".into()))
            }
            fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
                Ok(None)
            }
        }

        let pending = InMemoryPending::default();
        let _ = commit_and_persist(
            &Declining,
            &InMemoryBodies::default(),
            &pending,
            STORE,
            &a_change(),
            EditRoute::Delta,
        );
        assert!(
            pending.all().expect("reads").is_empty(),
            "a body was left waiting for a root the chain refused"
        );
    }

    /// A prediction the commit CONTRADICTS is dropped in the same call that made it — otherwise the
    /// file accumulates bodies for roots that do not exist and no drain can ever clear them.
    ///
    /// [`Committing`] answers a fixed root unrelated to the edit, which is exactly that divergence.
    #[test]
    fn a_prediction_the_commit_contradicts_is_dropped() {
        let pending = InMemoryPending::default();
        commit_and_persist(
            &Committing::pushed(),
            &InMemoryBodies::default(),
            &pending,
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect("commits");

        assert!(
            pending.all().expect("reads").is_empty(),
            "the node took the real body, so nothing should still be waiting"
        );
    }

    /// Once the node HAS the bytes — proved by reading them back — this computer stops holding them.
    #[test]
    fn a_body_the_node_verifiably_holds_is_no_longer_kept_here() {
        let pending = InMemoryPending::default();
        let node = InMemoryBodies::default();
        let outcome = commit_and_persist(
            &Honest,
            &node,
            &pending,
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect("the edit commits");

        assert!(pending.all().expect("reads").is_empty());
        assert_eq!(
            node.get(STORE, &outcome.root),
            Ok(BodyRead::Held(outcome.body.clone())),
            "the entry was cleared without the node actually holding the bytes"
        );
    }

    /// A pending store that cannot keep anything says so, rather than promising a retry that will
    /// never happen. The difference decides whether a person may safely close the app.
    #[test]
    fn a_copy_that_could_not_be_kept_is_never_reported_as_kept() {
        let error = commit_and_persist(
            &Honest,
            &a_node_awaiting_confirmation(),
            &RefusingPending,
            STORE,
            &a_change(),
            EditRoute::Delta,
        )
        .expect_err("a node that will not take the body is not a success");

        match &error {
            ProfileEditError::NotPersisted { kept_locally, .. } => assert!(!*kept_locally),
            other => panic!("the wrong failure: {other:?}"),
        }
        let said = error.sentence();
        assert!(said.contains("could NOT keep a copy"), "said: {said}");
        // The remedy names making the change AGAIN, because with no copy kept there is nothing on
        // this computer for any retry to offer (dig_ecosystem#3080). The banned phrases are the
        // waiting-and-it-will-publish family: each of them is true only of the OTHER arm, and each
        // has a person leaving the app open in front of a retry with no bytes behind it.
        assert!(said.contains("made again"), "said: {said}");
        for retry_with_nothing_to_retry in [
            "leave DIG open",
            "while DIG is open",
            "next time DIG starts",
            "keeps offering",
        ] {
            assert!(
                !said.contains(retry_with_nothing_to_retry),
                "promised a retry with no copy to retry ({retry_with_nothing_to_retry}): {said}"
            );
        }
    }

    // -- what a surface may say about it -------------------------------------------------------

    /// **A pushed edit is never drawn as confirmed.** The root it carries is a prediction, and it
    /// travels as the LOOKUP HANDLE of a push, which is the only honest place for it.
    #[test]
    fn a_pushed_edit_is_drawn_as_pushed_and_carries_its_root_as_a_handle() {
        let outcome = CommitOutcome {
            status: EditStatus::Pushed {
                new_root: [0x22; 32],
            },
            root: NEW_ROOT.into(),
            body: b"body".to_vec(),
        };
        let stage = outcome.stage(None);
        assert!(!stage.is_confirmed());
        assert_eq!(
            stage,
            Stage::Pushed {
                id: NEW_ROOT.to_string()
            }
        );
    }

    /// A height the CHAIN reported is the one thing that may say confirmed — and it is the only
    /// thing, so the crate's own `Confirmed` status without a height does NOT claim a block.
    #[test]
    fn only_a_chain_reported_height_is_drawn_as_confirmed() {
        for status in [
            EditStatus::Confirmed { root: [0x22; 32] },
            EditStatus::Pushed {
                new_root: [0x22; 32],
            },
        ] {
            let outcome = CommitOutcome {
                status,
                root: NEW_ROOT.into(),
                body: b"body".to_vec(),
            };
            assert!(outcome.stage(Some(9_154_460)).is_confirmed());
            assert!(
                !outcome.stage(None).is_confirmed(),
                "a write with no height in hand named a block"
            );
        }
    }

    /// The changes reach the seam exactly as the draft expressed them — in particular a removal
    /// stays a removal, which is the half a `HashMap<field, String>` would have flattened away.
    #[test]
    fn the_seam_is_asked_for_the_changes_the_draft_expressed() {
        let seam = Committing::pushed();
        let changes = vec![
            (ProfileField::Bio, SlotChange::Remove),
            (
                ProfileField::DisplayName,
                SlotChange::Set("Ada".to_string()),
            ),
        ];
        commit_and_persist(
            &seam,
            &InMemoryBodies::default(),
            &InMemoryPending::default(),
            STORE,
            &changes,
            EditRoute::Delta,
        )
        .expect("commits");
        assert_eq!(*seam.asked.lock().expect("asked"), changes);
    }

    // -- off the painting thread ---------------------------------------------------------------

    /// The worker publishes its progress and settles, and the caller is not held while it does.
    ///
    /// The chain here confirms on the first look, so the write reaches a chain-proved end — which is
    /// the only way this test can distinguish a worker that watches from one that pushes and walks
    /// away, because both publish the same `Pushed` stage on the way.
    #[test]
    fn a_commit_runs_off_the_calling_thread_and_reports_into_the_feed() {
        let feed = Feed::detached();
        start_commit(
            Arc::new(Committing::pushed()),
            Arc::new(InMemoryBodies::default()),
            Arc::new(InMemoryPending::default()),
            STORE.to_string(),
            a_change(),
            EditRoute::Delta,
            feed.clone(),
            a_brisk_watch(),
        );
        // The transaction is visible IMMEDIATELY, before the worker has done anything: a person who
        // pressed Save sees that something is happening on the very next frame.
        let opening = feed
            .read()
            .expect("a transaction is published synchronously");
        assert_eq!(opening.what, WHAT);

        let settled = wait_for_settled(&feed);
        assert_eq!(
            settled.stage,
            Stage::Confirmed {
                height: 9_154_460,
                made: format!("Your profile now publishes {NEW_ROOT}."),
            }
        );
    }

    /// A commit that fails to PERSIST settles as a failure with a next step, not as a success.
    #[test]
    fn a_worker_whose_bytes_were_lost_settles_as_failed() {
        let feed = Feed::detached();
        start_commit(
            Arc::new(Committing::pushed()),
            Arc::new(ForgetfulBodies),
            Arc::new(InMemoryPending::default()),
            STORE.to_string(),
            a_change(),
            EditRoute::Delta,
            feed.clone(),
            a_brisk_watch(),
        );
        match wait_for_settled(&feed).stage {
            Stage::Failed { why, next } => {
                assert!(why.contains("cannot read your profile yet"), "why: {why}");
                assert!(!next.is_empty());
            }
            other => panic!("a lost body settled as {other:?}"),
        }
    }

    /// **dig_ecosystem#3041.** A failure that PROVES nothing reached a mempool says so, in money.
    ///
    /// # The defect
    ///
    /// Publishing a profile spends real XCH, and the first question a person has when the control
    /// refuses them is whether it spent any. The reassurance existed — as a constant no code path
    /// could reach — while what a person actually saw beneath a refusal said only that their
    /// profile was unchanged, which is true and silent on the money. A surface that goes quiet on
    /// whether a spend happened leaves them to choose between paying twice and never trying again.
    ///
    /// # Why the errors are built through the ADAPTER's mapping
    ///
    /// Every earlier test of this wording constructed a [`ProfileEditError`] by hand, so none of
    /// them ever exercised the translation a real failure goes through. These start from the
    /// crate's own [`EditError`], exactly as a failure from dig-account does.
    ///
    /// # The control
    ///
    /// An unanswered chain may have taken the bundle, so it must NOT be told nothing was spent —
    /// the nearest wrong version says it unconditionally, and reads identically on the first half.
    #[test]
    fn a_refusal_that_never_reached_a_mempool_says_no_xch_was_spent() {
        let next_after = |error: ProfileEditError| {
            let feed = Feed::detached();
            start_commit(
                Arc::new(Refusing(error)),
                Arc::new(InMemoryBodies::default()),
                Arc::new(InMemoryPending::default()),
                STORE.to_string(),
                a_change(),
                EditRoute::FreshBody,
                feed.clone(),
                a_brisk_watch(),
            );
            match wait_for_settled(&feed).stage {
                Stage::Failed { next, .. } => next,
                other => panic!("a refusal settled as {other:?}"),
            }
        };

        let refused = next_after(super::super::adapter::edit_error(EditError::Refused(
            "the spend gate said no".into(),
        )));
        assert!(
            refused.contains("no XCH was spent"),
            "a person who pressed a control that costs XCH was not told whether it spent any:              {refused}"
        );

        let unknown = next_after(super::super::adapter::edit_error(
            EditError::ChainUnreachable("no node answered".into()),
        ));
        assert!(
            !unknown.contains("no XCH was spent"),
            "an attempt whose fate is UNKNOWN was told nothing was spent, which invites a second              spend over the first: {unknown}"
        );
    }

    // -- the watch -----------------------------------------------------------------------------

    /// A push is drawn as a push while the chain has not answered — and stays that way. The stage
    /// must not drift towards "confirmed" merely because time passed.
    #[test]
    fn an_unconfirmed_edit_is_never_promoted_to_confirmed_by_waiting() {
        let feed = Feed::detached();
        let seam = Committing::over(Chain::NotYet);
        let outcome = CommitOutcome {
            status: EditStatus::Pushed {
                new_root: [0x22; 32],
            },
            root: NEW_ROOT.into(),
            body: b"body".to_vec(),
        };
        watch_for_confirmation(
            &seam,
            &outcome,
            &Transaction::starting(WHAT, None),
            &feed,
            a_brisk_watch(),
        );

        assert!(
            *seam.looks.lock().expect("looks") > 1,
            "the watch looked once and gave up, so it is not a watch"
        );
        let ended = feed.read().expect("the watch says something");
        assert!(!ended.stage.is_confirmed());
        // Giving up says the change may still land, and says NOT to send it again — the second
        // sentence is the one that stops a person paying twice.
        match ended.stage {
            Stage::Failed { why, next } => {
                assert!(why.contains("may still confirm"), "why: {why}");
                assert!(next.contains("Do NOT save it again"), "next: {next}");
            }
            other => panic!("a watch that ran out settled as {other:?}"),
        }
    }

    /// An unreachable chain ends the watch after a bounded number of looks rather than at the first
    /// one: a single failed read is a hiccup, and treating it as an answer would abandon a person's
    /// transaction the moment their node blinked.
    #[test]
    fn an_unreachable_chain_is_ridden_out_and_then_stops_the_watch() {
        let feed = Feed::detached();
        let seam = Committing::over(Chain::Unreachable);
        let outcome = CommitOutcome {
            status: EditStatus::Pushed {
                new_root: [0x22; 32],
            },
            root: NEW_ROOT.into(),
            body: b"body".to_vec(),
        };
        let watch = Watch {
            // Long enough that only the unreachable count can end this watch, so the test cannot
            // pass by timing out instead.
            within: std::time::Duration::from_secs(30),
            every: std::time::Duration::from_millis(1),
            unreachable_looks_allowed: 4,
        };
        watch_for_confirmation(
            &seam,
            &outcome,
            &Transaction::starting(WHAT, None),
            &feed,
            watch,
        );

        assert_eq!(*seam.looks.lock().expect("looks"), 4);
        assert!(!feed.read().expect("a verdict").stage.is_confirmed());
    }

    /// Poll the feed until the write settles. Bounded, so a worker that never finishes fails the
    /// test instead of hanging the suite behind the 600-second watchdog.
    fn wait_for_settled(feed: &Feed) -> Transaction {
        for _ in 0..500 {
            if let Some(current) = feed.read() {
                if current.is_settled() {
                    return current;
                }
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the commit never settled");
    }
}
