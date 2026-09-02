//! Deleting a profile: melting both of its singletons so neither lineage has a successor
//! (dig_ecosystem#3037).
//!
//! # What "delete" means here, exactly
//!
//! A profile is two on-chain singletons — a DID and a dig-store — so deleting one is two spends, and
//! the ceremony is arranged around that rather than around a happy path. Each spend emits
//! `MELT_SINGLETON` instead of the recreation condition every other operation uses, so the lineage
//! ends: no coin of the next generation is ever created and the launcher id can never be re-derived.
//!
//! # The order is DID first, and it is chosen for the failure
//!
//! The second spend can fail after the first confirms, so one of the two half-states is a state a
//! real person lands in. They are not equally bad. A live DID whose store is gone still resolves and
//! still presents as an identity while pointing at nothing; a melted DID beside a still-live store
//! leaves content nobody's identity claims. So the DID goes first, and a failure at the second step
//! leaves the better half behind.
//!
//! # The mojo is spent, and no copy may promise it back
//!
//! The singleton top layer permits exactly one odd-amount `CREATE_COIN`, and the melt magic
//! condition `(51 () -113)` occupies it. Recovering the 1-mojo singleton amount is therefore
//! *unexpressible* under the puzzle rather than merely unimplemented — there is no version of this
//! code that could pay it back. Every sentence in [`copy`] states it as spent.
//!
//! # Nothing here infers a deletion from a push
//!
//! A push is an acceptance by a mempool, not an inclusion in a block. [`start_melt`] publishes
//! [`Stage::Pushed`] and then WATCHES, and only a chain read proving the coin spent may become
//! [`Stage::Confirmed`] — the same rule [`crate::profile_edit::commit`] holds, for the same reason.

pub mod adapter;
pub mod aim;
pub mod copy;

pub use adapter::{AccountMeltSeam, MintNetwork};
pub use aim::{aim_at, MeltUnaimed};

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::transaction::{Feed, Stage, Transaction, Writing};

/// The profile a melt is aimed at, as a person and a chain both name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeltTarget {
    /// The HD index the profile derives at — its stable identity in every control that acts on it.
    pub ix: u32,
    /// What to call it in a sentence: its own label, or its ordinal.
    pub name: String,
    /// Its canonical `did:chia:…` string.
    pub did: String,
    /// The launcher id of the store its content lives in.
    pub store_id: String,
}

/// One half of a profile, named so a partial outcome can say WHICH half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeltHalf {
    /// The DID singleton — who the profile is.
    Did,
    /// The dig-store singleton — where its content lives.
    Store,
}

impl MeltHalf {
    /// The noun a sentence about this half uses.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Did => "identity",
            Self::Store => "content store",
        }
    }
}

/// A melt spend that reached a mempool. Proves nothing about the chain — see [`MeltProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedMelt {
    /// Which half was spent.
    pub half: MeltHalf,
    /// The coin the melt spent, so a person can look it up themselves. Shown verbatim.
    pub coin_id: String,
}

/// A melt the CHAIN has proved: the coin is spent and its lineage has no successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeltProof {
    /// The block height the spend was seen at.
    pub height: u32,
}

/// Why a melt did not happen.
///
/// Kept apart along the lines the REMEDIES differ on, which is the only distinction a person can act
/// on: a refusal is never retried, an unanswered chain is waited on, a rejection is rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMeltError {
    /// The account is locked, so nothing can be signed.
    Locked,
    /// The singleton could not be read, so there is nothing to build a spend against.
    Unreadable(String),
    /// The chain says this singleton has no unspent coin — it was already melted, or never launched.
    ///
    /// Its own variant because it is not a fault and has no retry: asking again cannot resurrect a
    /// lineage that ended. The ceremony treats it as this half being ALREADY done.
    AlreadyGone,
    /// The mempool DECLINED the bundle: a known "no", and the singleton is untouched.
    Rejected(String),
    /// The chain could not be asked, so the outcome is UNKNOWN and the melt may still confirm.
    ChainUnreachable(String),
    /// The spend could not be built or signed at all — a wrong owner, a custody policy that refuses.
    Refused(String),
}

impl ProfileMeltError {
    /// What to tell a person: what is true, and what to do about it.
    pub fn sentence(&self) -> String {
        match self {
            Self::Locked => {
                "Your account is locked, so DIG cannot sign the deletion. Unlock it and try again."
                    .to_string()
            }
            Self::Unreadable(why) => format!(
                "DIG could not read this profile from the blockchain, so it did not delete \
                 anything: {why}"
            ),
            Self::AlreadyGone => {
                "This part of the profile is no longer on the blockchain.".to_string()
            }
            Self::Rejected(why) => {
                format!("The blockchain declined the deletion, and the profile is unchanged: {why}")
            }
            Self::ChainUnreachable(why) => format!(
                "DIG could not reach the blockchain, so it does not know whether the deletion went \
                 through: {why}"
            ),
            Self::Refused(why) => {
                format!("DIG would not build the deletion, so nothing was spent: {why}")
            }
        }
    }

    /// Whether the profile is CERTAINLY untouched by this failure.
    ///
    /// The distinction that decides what a person may safely do next: a refusal or a rejection left
    /// the singletons alone and can be retried, while an unreachable chain may have a melt in flight
    /// and a second attempt would spend twice.
    pub fn profile_is_unchanged(&self) -> bool {
        matches!(
            self,
            Self::Locked | Self::Unreadable(_) | Self::Rejected(_) | Self::Refused(_)
        )
    }
}

/// What the app needs of the chain to delete one profile.
///
/// Written as a trait of plain owned values for [`ProfileEditSeam`]'s reason: the whole ceremony —
/// including its partial-failure behaviour, which is the part worth testing — runs against doubles
/// with no chain, no node and no money, and the concrete adapter is the one file that names chia
/// types.
///
/// A seam is bound to ONE profile, decided when it is built, exactly as the editor's is.
///
/// [`ProfileEditSeam`]: crate::profile_edit::ProfileEditSeam
pub trait ProfileMeltSeam: Send + Sync {
    /// Build, sign and push the melt of `half`, returning the coin it spent.
    ///
    /// Signing happens in THIS process from the unlocked account's own seed; the publisher is handed
    /// an already-signed bundle and has nowhere to put a key (§908).
    fn melt(&self, half: MeltHalf) -> Result<PushedMelt, ProfileMeltError>;

    /// Whether the chain now shows `coin_id` spent with no successor.
    ///
    /// Three answers a caller must keep apart. `Ok(Some(proof))` is chain-proved and is the ONLY
    /// thing that may become [`Stage::Confirmed`]. `Ok(None)` is a real answer — the chain was asked
    /// and the coin is not spent yet. `Err` is nobody having been able to ask, which is not the same
    /// as "not yet" and must never be drawn as one.
    fn confirmation(&self, coin_id: &str) -> Result<Option<MeltProof>, ProfileMeltError>;
}

/// The melt seams a build actually has.
///
/// A value rather than an `Option` for [`EditSeams`]'s reason: whether the delete control may be
/// OFFERED is read off the seams that exist, never asserted beside them.
///
/// [`EditSeams`]: crate::profile_edit::EditSeams
#[derive(Clone)]
pub enum MeltSeams {
    /// A real seam for one profile.
    Wired(Arc<dyn ProfileMeltSeam>),
    /// This build cannot read chain or push a bundle, so no profile can be deleted on this machine.
    NoChainTransport,
}

impl MeltSeams {
    /// Whether a deletion can be attempted at all.
    pub fn is_possible(&self) -> bool {
        matches!(self, Self::Wired(_))
    }
}

/// The seams the running app will actually delete through, once something has installed them.
///
/// A `Mutex` rather than a `OnceLock` because a melt seam is bound to ONE profile: the shell rebuilds
/// it as the active profile changes, where the editor's is installed once and read for the life of
/// the process. Reading before anything installs answers [`MeltSeams::NoChainTransport`], which
/// withholds the control rather than closing the door on a later install — the two-static shape
/// `EditService` needed, expressed as one replaceable value.
static APP_SEAMS: std::sync::Mutex<Option<MeltSeams>> = std::sync::Mutex::new(None);

/// Install the LIVE seam a real deletion runs through. Replaces whatever was installed before.
///
/// # It takes the seam, not a [`MeltSeams`], and that is the guard
///
/// The parameter used to be the two-valued enum, so `install_seams(MeltSeams::NoChainTransport)`
/// was a way to *install a withdrawal* — an install that is really a retraction, spelled as an
/// install. Two verbs for one direction is how a slot ends up written to by callers who believe
/// they are doing opposite things, and it left [`clear_seams`] with no production caller at all
/// (dig-app#285).
///
/// Narrowing the argument makes the dangerous direction UNREPRESENTABLE rather than merely
/// discouraged: [`MeltSeams::NoChainTransport`] can now only be reached through [`clear_seams`],
/// which says what it does at the call site.
pub fn install_seams(seam: Arc<dyn ProfileMeltSeam>) {
    if let Ok(mut held) = APP_SEAMS.lock() {
        *held = Some(MeltSeams::Wired(seam));
    }
}

/// Retract the seams, so no deletion is offered until something installs a live one again.
///
/// The counterpart to [`install_seams`], and the reason this exists as its own verb rather than
/// leaving callers to write `install_seams(MeltSeams::NoChainTransport)`: a slot with only a writer
/// is a write-only latch, and [`MeltSeams::is_possible`] then answers "a seam was installed once"
/// instead of "a node is reachable". `ProfileMeltSeam`'s constructors perform no I/O, so a seam
/// built against a dead address succeeds exactly as one built against a live one — the installed
/// value can only stay truthful if whoever installs it also takes it back (dig-app#281).
pub fn clear_seams() {
    if let Ok(mut held) = APP_SEAMS.lock() {
        *held = Some(MeltSeams::NoChainTransport);
    }
}

/// The app's melt seams, or [`MeltSeams::NoChainTransport`] while nothing has installed any.
///
/// A poisoned lock answers the same way, which is the fail-closed direction: the control disappears
/// rather than leading to an irreversible spend this app can no longer reason about.
pub fn app_seams() -> MeltSeams {
    APP_SEAMS
        .lock()
        .ok()
        .and_then(|held| held.clone())
        .unwrap_or(MeltSeams::NoChainTransport)
}

/// How long the ceremony waits for each half, and how often it looks.
#[derive(Debug, Clone, Copy)]
pub struct Watch {
    /// The gap between two chain reads.
    pub every: Duration,
    /// How long to keep looking before saying so.
    pub until: Duration,
    /// How many consecutive unanswered looks end the watch.
    ///
    /// More than one, because a single failed read is weather; a run of them is a chain this app
    /// cannot see.
    pub unreachable_looks_allowed: usize,
}

impl Default for Watch {
    /// Just under a block between looks, for four blocks — long enough for an ordinary inclusion and
    /// short enough that a person is not left watching a spinner.
    fn default() -> Self {
        Self {
            every: Duration::from_secs(15),
            until: Duration::from_secs(75),
            unreachable_looks_allowed: 3,
        }
    }
}

/// Melt both halves of `target` OFF the painting thread, reporting into `feed`.
///
/// Returns immediately. Everything a surface needs to draw is published to the feed, and nothing is
/// reported as deleted until a chain read has proved it.
///
/// # Why the halves are sequential and not concurrent
///
/// The second spend is only worth attempting if the first one landed. Running both at once would
/// double the ways a person ends up half-deleted, in exchange for saving a minute on an act nobody
/// performs twice.
/// Returns `false` when the app is already writing to the chain and NOTHING was started
/// (dig_ecosystem#3004) — the caller owes the person that sentence, because a melt refused in
/// silence is a Delete control that does nothing.
#[must_use = "a refused melt has told nobody, and the caller is the only surface that can"]
pub fn start_melt(seams: MeltSeams, target: MeltTarget, feed: Feed, watch: Watch) -> bool {
    let opening = Transaction::starting(copy::what(&target), None);
    // Claimed before anything is built: a melt destroys a profile, so starting one whose progress
    // another ceremony is about to overwrite is the worst case of the clobber, not a mild one.
    let Some(feed) = feed.begin(opening) else {
        return false;
    };
    let MeltSeams::Wired(seam) = seams else {
        // Unreachable from the app, whose control is gated on the seams existing. Reported rather
        // than ignored, because a silent no-op on a control a person pressed is the dead end
        // dig_ecosystem#1800 removed.
        feed.publish(
            Transaction::starting(copy::what(&target), None).at(Stage::Failed {
                why: copy::NO_TRANSPORT.to_string(),
                next: copy::NO_TRANSPORT_NEXT.to_string(),
            }),
        );
        return true;
    };
    thread::spawn(move || run(&*seam, &target, &feed, watch));
    true
}

/// The ceremony itself: DID, then store, each pushed and then PROVED before the next begins.
fn run(seam: &dyn ProfileMeltSeam, target: &MeltTarget, feed: &Writing, watch: Watch) {
    let opening = Transaction::starting(copy::what(target), None);
    feed.publish(opening.clone());

    let mut done = Vec::new();
    let mut last_proof = None;
    for half in [MeltHalf::Did, MeltHalf::Store] {
        match melt_one(seam, half, target, &opening, feed, watch) {
            Ok(proof) => {
                done.push(half);
                last_proof = proof.or(last_proof);
            }
            Err(stopped) => {
                feed.publish(opening.at(copy::stopped_after(&done, half, target, &stopped)));
                return;
            }
        }
    }
    // The height is the LAST one the chain actually reported. A profile whose halves were both
    // already gone has none, and naming a block there would be inventing one — the same rule
    // `CommitOutcome::stage` holds when an edit committed the root the store already had.
    feed.publish(opening.at(match last_proof {
        Some(height) => Stage::Confirmed {
            height,
            made: copy::deleted(target),
        },
        None => Stage::Failed {
            why: copy::already_gone(target),
            next: copy::ALREADY_GONE_NEXT.to_string(),
        },
    }));
}

/// Melt one half and wait for the chain to prove it, reporting the height it proved at.
///
/// `Ok(None)` is the half that was ALREADY off the chain — nothing was spent and no block is
/// involved, so there is no height to name. Treating that as a failure would strand anyone retrying
/// after an unanswered push.
fn melt_one(
    seam: &dyn ProfileMeltSeam,
    half: MeltHalf,
    target: &MeltTarget,
    opening: &Transaction,
    feed: &Writing,
    watch: Watch,
) -> Result<Option<u32>, MeltStopped> {
    feed.publish(opening.mid_ceremony(copy::melting(half, target), Stage::Signing));
    let pushed = match seam.melt(half) {
        Ok(pushed) => pushed,
        Err(ProfileMeltError::AlreadyGone) => return Ok(None),
        Err(why) => return Err(MeltStopped::Refused(why)),
    };
    feed.publish(opening.mid_ceremony(
        copy::melting(half, target),
        Stage::Pushed {
            id: pushed.coin_id.clone(),
        },
    ));
    prove(seam, &pushed, watch).map(Some)
}

/// Watch the chain until it proves `pushed`, or until the watch gives up.
fn prove(
    seam: &dyn ProfileMeltSeam,
    pushed: &PushedMelt,
    watch: Watch,
) -> Result<u32, MeltStopped> {
    let until = Instant::now() + watch.until;
    let mut unanswered = 0;
    while Instant::now() < until {
        match seam.confirmation(&pushed.coin_id) {
            Ok(Some(proof)) => return Ok(proof.height),
            Ok(None) => unanswered = 0,
            Err(_) => {
                unanswered += 1;
                if unanswered >= watch.unreachable_looks_allowed {
                    break;
                }
            }
        }
        thread::sleep(watch.every);
    }
    Err(MeltStopped::Unproved(pushed.clone()))
}

/// Why the ceremony stopped, which decides what the person is told to do next.
enum MeltStopped {
    /// Nothing was spent for this half.
    Refused(ProfileMeltError),
    /// A melt was pushed and the chain never proved it. It may still land, so a retry could spend
    /// twice — the one outcome whose advice is *wait*.
    Unproved(PushedMelt),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn target() -> MeltTarget {
        MeltTarget {
            ix: 1,
            name: "“work”".to_string(),
            did: format!("did:chia:{}", "ab".repeat(16)),
            store_id: "cd".repeat(32),
        }
    }

    /// What a seam's chain says when the watch looks.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Chain {
        /// The coin is spent, at this height.
        Proves(u32),
        /// The chain answered, and the coin is not spent yet.
        NotYet,
        /// Nobody could ask.
        Unreachable,
    }

    /// A seam that answers per HALF, so one half can behave differently from the other — the fixture
    /// property every partial-failure test here needs.
    struct Halves {
        did: Result<PushedMelt, ProfileMeltError>,
        store: Result<PushedMelt, ProfileMeltError>,
        chain: Chain,
        asked: Mutex<Vec<MeltHalf>>,
    }

    impl Halves {
        fn of(
            did: Result<PushedMelt, ProfileMeltError>,
            store: Result<PushedMelt, ProfileMeltError>,
            chain: Chain,
        ) -> Arc<Self> {
            Arc::new(Self {
                did,
                store,
                chain,
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    fn pushed(half: MeltHalf) -> Result<PushedMelt, ProfileMeltError> {
        Ok(PushedMelt {
            half,
            coin_id: match half {
                MeltHalf::Did => "11".repeat(32),
                MeltHalf::Store => "22".repeat(32),
            },
        })
    }

    impl ProfileMeltSeam for Halves {
        fn melt(&self, half: MeltHalf) -> Result<PushedMelt, ProfileMeltError> {
            self.asked.lock().expect("asked").push(half);
            match half {
                MeltHalf::Did => self.did.clone(),
                MeltHalf::Store => self.store.clone(),
            }
        }

        fn confirmation(&self, _: &str) -> Result<Option<MeltProof>, ProfileMeltError> {
            match self.chain {
                Chain::Proves(height) => Ok(Some(MeltProof { height })),
                Chain::NotYet => Ok(None),
                Chain::Unreachable => {
                    Err(ProfileMeltError::ChainUnreachable("no node".to_string()))
                }
            }
        }
    }

    /// A watch that gives up immediately, so a test never sleeps through a real cadence.
    fn brisk() -> Watch {
        Watch {
            every: Duration::from_millis(1),
            until: Duration::from_millis(20),
            unreachable_looks_allowed: 1,
        }
    }

    /// Run the ceremony to completion on this thread and hand back what the feed ended on.
    fn settled(seam: Arc<dyn ProfileMeltSeam>) -> Transaction {
        let feed = Feed::detached();
        let writing = feed
            .begin(Transaction::starting(copy::what(&target()), None))
            .expect("a detached feed is free");
        run(&*seam, &target(), &writing, brisk());
        feed.read().expect("the ceremony published nothing at all")
    }

    /// **Both singletons are melted, and only a chain proof reports the profile deleted.**
    ///
    /// The fixture pushes both halves and lets the chain PROVE them, which is the only route to the
    /// confirmed sentence — `Chain::NotYet` below is the control that the sentence is not simply
    /// printed at the end of the loop.
    #[test]
    fn a_profile_is_reported_deleted_only_once_the_chain_proved_both_melts() {
        let seam = Halves::of(
            pushed(MeltHalf::Did),
            pushed(MeltHalf::Store),
            Chain::Proves(7),
        );
        let ended = settled(seam.clone());

        assert!(
            ended.stage.is_confirmed(),
            "both melts were proved and the ceremony did not report the profile deleted: {:?}",
            ended.stage
        );
        assert_eq!(
            *seam.asked.lock().expect("asked"),
            vec![MeltHalf::Did, MeltHalf::Store],
            "the halves were not melted DID-first, so a failure at the second step leaves a live \
             identity pointing at nothing"
        );
    }

    /// **A push the chain never proved is NOT reported as a deletion** — the whole honesty property.
    ///
    /// The fixture is identical to the one above except that the chain answers *not yet*: a
    /// ceremony that inferred success from the push agrees with the previous test and disagrees
    /// here, which is exactly the mistake worth catching.
    #[test]
    fn a_pushed_melt_the_chain_never_proved_is_not_reported_as_a_deletion() {
        let ended = settled(Halves::of(
            pushed(MeltHalf::Did),
            pushed(MeltHalf::Store),
            Chain::NotYet,
        ));

        assert!(
            !ended.stage.is_confirmed(),
            "a melt that only reached a mempool was reported as a deleted profile: {:?}",
            ended.stage
        );
        let said = ended.stage.detail().to_lowercase();
        assert!(
            said.contains("do not") || said.contains("wait"),
            "an unproved melt did not warn against a second attempt, which would spend twice: \
             {said}"
        );
    }

    /// **A profile whose DID melted and whose store did not is told exactly that.**
    ///
    /// The state the ticket is designed around, and the fixture varies ONE actor: the DID half
    /// succeeds honestly and only the store half refuses, so a ceremony that reported "nothing was
    /// deleted" on any failure fails here while an all-halves-hostile fixture could not see it.
    #[test]
    fn a_half_deleted_profile_names_which_half_is_gone_and_which_remains() {
        let ended = settled(Halves::of(
            pushed(MeltHalf::Did),
            Err(ProfileMeltError::Rejected("bad spend".to_string())),
            Chain::Proves(9),
        ));

        assert!(!ended.stage.is_confirmed());
        let said = ended.stage.detail().to_lowercase();
        assert!(
            said.contains(MeltHalf::Did.noun()),
            "the half that IS gone was never named, so a person cannot tell what happened: {said}"
        );
        assert!(
            said.contains(MeltHalf::Store.noun()),
            "the half that remains was never named: {said}"
        );
    }

    /// **A half that is already off the chain is not a failure, and does not stop the other half.**
    ///
    /// This is what makes a retry after an unanswered push safe: the DID melted on the first
    /// attempt, so the second attempt finds it gone and must go on to the store rather than
    /// reporting a fault.
    #[test]
    fn a_lineage_that_already_ended_lets_the_ceremony_finish_the_other_half() {
        let seam = Halves::of(
            Err(ProfileMeltError::AlreadyGone),
            pushed(MeltHalf::Store),
            Chain::Proves(3),
        );
        let ended = settled(seam.clone());

        assert!(
            ended.stage.is_confirmed(),
            "a profile whose DID was already melted could never be finished: {:?}",
            ended.stage
        );
        assert_eq!(
            *seam.asked.lock().expect("asked"),
            vec![MeltHalf::Did, MeltHalf::Store],
            "the store half was never attempted"
        );
    }

    /// **An unreachable chain leaves the outcome UNKNOWN and says so** — never "deleted", never
    /// "nothing happened".
    #[test]
    fn an_unanswerable_chain_reports_neither_a_deletion_nor_an_untouched_profile() {
        let ended = settled(Halves::of(
            pushed(MeltHalf::Did),
            pushed(MeltHalf::Store),
            Chain::Unreachable,
        ));

        assert!(!ended.stage.is_confirmed());
        let said = ended.stage.detail().to_lowercase();
        assert!(
            !said.contains("nothing was deleted"),
            "an unknown outcome claimed the profile is untouched: {said}"
        );
    }

    /// **A build with no transport reports a refusal rather than doing nothing.**
    #[test]
    fn a_build_with_no_transport_says_so_instead_of_swallowing_the_press() {
        let feed = Feed::detached();
        // `true`, not `false`: the press WAS acted on — it reached the feed and said why it could
        // go no further. `false` is reserved for a refusal that reached nobody, which is the one
        // case the caller owes a sentence for.
        assert!(
            start_melt(MeltSeams::NoChainTransport, target(), feed.clone(), brisk()),
            "a melt with no transport reported itself as never having started, so the bin would \
             say the feed was busy over a failure already on screen"
        );
        let ended = feed.read().expect("a pressed control published nothing");
        assert!(matches!(ended.stage, Stage::Failed { .. }));
    }

    /// **A failure that certainly spent nothing is distinguished from one that may have.**
    ///
    /// Pinned from both sides against the same taxonomy, because the two advices are opposites: a
    /// rejected melt is retried, an unanswered one is waited on, and a classifier that answered one
    /// way for everything would be right about half the states by accident.
    #[test]
    fn only_the_failures_that_spent_nothing_claim_the_profile_is_unchanged() {
        for certain in [
            ProfileMeltError::Locked,
            ProfileMeltError::Rejected("no".into()),
            ProfileMeltError::Refused("no".into()),
            ProfileMeltError::Unreadable("no".into()),
        ] {
            assert!(
                certain.profile_is_unchanged(),
                "{certain:?} left the singletons alone and did not say so"
            );
        }
        assert!(
            !ProfileMeltError::ChainUnreachable("no".into()).profile_is_unchanged(),
            "an unanswered chain claimed the profile is untouched, which invites a second spend"
        );
    }

    /// A retraction must take the offer BACK, not merely fail to renew it.
    ///
    /// Both cases live in one test because [`APP_SEAMS`] is process-global: as two `#[test]` fns they
    /// would race each other for the same static and pass or fail on scheduling.
    ///
    /// The install-and-hold half is the control, and it is the half that catches the write-only
    /// latch. A fixture that only ever retracted would answer `false` with the latch fully present —
    /// nothing was ever installed, so nothing had to be taken back. Only a run that first proves the
    /// offer went UP can show that the retraction is what brings it down (dig-app#281).
    #[test]
    fn a_retracted_seam_withdraws_the_offer_an_installed_one_made() {
        let live = || {
            Halves::of(
                pushed(MeltHalf::Did),
                pushed(MeltHalf::Store),
                Chain::NotYet,
            )
        };

        // Control: installed and HELD. The offer must be up, or the retraction below proves nothing.
        install_seams(live());
        assert!(
            app_seams().is_possible(),
            "an installed live seam did not offer deletion, so this test cannot see a retraction"
        );

        // The property under test: the same slot, retracted.
        clear_seams();
        assert!(
            !app_seams().is_possible(),
            "the delete control survived the engine going away: `is_possible()` proves only that a seam was installed once, not that a node is reachable"
        );

        // And it must be re-offerable afterwards: a retraction is not a door closing for the process.
        install_seams(live());
        assert!(
            app_seams().is_possible(),
            "a reconnect could not re-offer deletion, so the retraction was terminal"
        );
        clear_seams();
    }
}
