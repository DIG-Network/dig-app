//! The one place the app reads its profile from and writes it back through.
//!
//! # Why a service and not a plumbed handle
//!
//! The editor needs three things the pane cannot hold: seams that reach the chain, a reading that
//! outlives a frame, and a worker thread. The window is rebuilt from a snapshot every repaint, so
//! anything the pane owns is either recomputed (a chain read, twice a second) or lost.
//!
//! This is the same shape [`Feed`] uses, for the same reason and with the
//! same cost: one process-wide value the binary installs once and every surface reads. And with the
//! same escape — [`EditService::detached`] — so a test never sees another test's profile.
//!
//! # What it will not do
//!
//! It does not decide whether the editor is OFFERED. That is
//! [`ProfileEditing`], built from the seams and carried on the
//! view like every other enablement, so the tray and the window answer that question identically.
//! What this owns is the doing.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::commit::{start_commit, EditRoute, EditSeams, Watch};
use super::draft::SlotChange;
use super::field::ProfileField;
use super::offer::ProfileEditing;
use super::repair::{self, BodyRepair, RepairOutcome};
use super::ProfileReading;
use crate::profiles::RootReading;
use crate::transaction::Feed;

/// The shortest interval between two chain reads of the profile.
///
/// A profile's root moves when a block carries an edit, and a Chia block is roughly 18.75 seconds —
/// so re-reading faster than this asks the same node the same question about the same unchanged
/// coin. Chosen just under one block so nothing published is shown late by more than a block, and
/// deliberately not *shorter*: the read is a singleton lineage walk plus a `coinById`, and each of
/// those spends a token from the node's wallet rate limiter (dig_ecosystem#3044).
pub const READ_INTERVAL: Duration = Duration::from_secs(15);

/// The shortest gap between two attempts to hand waiting profile content to the node.
///
/// Bounded by the thing that usually refuses it: `putBody` declines a body whose root the chain has
/// not confirmed yet, and that resolves in a block or two. Retrying faster asks the same node about
/// the same unconfirmed root; retrying much slower turns a several-minute wait into one a person
/// resolves by restarting the app, which is the state dig_ecosystem#3078 exists to remove.
pub const DRAIN_INTERVAL: Duration = Duration::from_secs(30);

/// The longest that gap may grow to.
///
/// Not every refusal resolves with time. A body that does not rebuild to its root never becomes
/// acceptable, and an entry like that would otherwise ask forever at the fastest cadence — so the
/// gap doubles on every attempt that moves nothing, and stops widening here. Eight minutes still
/// recovers on its own within one sitting once the obstacle clears.
pub const DRAIN_CEILING: Duration = Duration::from_secs(480);

/// Reads the wall clock. Injected so a test can pin the RATE without sleeping through it.
type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The editor's seams, its current reading, and the thread that refreshes it.
pub struct EditService {
    /// What this build can do about profiles.
    seams: EditSeams,
    /// The last answer, or the state of the read that is under way.
    reading: Mutex<ProfileReading>,
    /// What the last read said about the root the chain anchors, kept beside the reading rather
    /// than inside it: the profile card names the root over a modal nobody has opened, and
    /// [`ProfileReading::Known`] carries a draft rather than the snapshot the root came off.
    root: Mutex<RootReading>,
    /// What the last read said about putting this profile's content back for free (dig-app#207).
    ///
    /// Measured off the SAME read as [`root`](Self::root) and kept beside it for the same reason: a
    /// surface that paired one read's root with another read's repairability would offer a control
    /// aimed at a value the chain no longer anchors.
    repair: Mutex<BodyRepair>,
    /// Whether a read is already running, so a pane asking every frame starts one worker and not
    /// a hundred and twenty.
    reading_now: Mutex<bool>,
    /// When the most recent read was STARTED, so [`refresh`](EditService::refresh) can hold the
    /// rate rather than merely the concurrency. `None` until the first read.
    ///
    /// Timed from the start and not the finish, because that is what makes the bound exact: at most
    /// one read begins per `interval` ([`READ_INTERVAL`] in the app), whatever a single read costs.
    last_read: Mutex<Option<Instant>>,
    /// The shortest gap between two reads. [`READ_INTERVAL`] outside tests.
    interval: Duration,
    /// When the most recent drain was STARTED. `None` until the first one.
    last_drain: Mutex<Option<Instant>>,
    /// Whether a drain is already running, so a pane asking every frame starts one worker and not
    /// a hundred and twenty.
    draining_now: Mutex<bool>,
    /// How many drains in a row have moved nothing, which is what widens the gap between them.
    ///
    /// A COUNT rather than the duration itself, so the first retry after a single refusal still
    /// happens at the plain [`DRAIN_INTERVAL`]: that refusal is nearly always a root the chain has
    /// not confirmed yet, and it is the one case where waiting longer is exactly wrong.
    fruitless_drains: Mutex<u32>,
    /// Where "now" comes from.
    clock: Clock,
    /// Where a chain write publishes its progress.
    feed: Feed,
}

/// The app's one service, once something has installed it.
static APP_SERVICE: OnceLock<Arc<EditService>> = OnceLock::new();

/// The service every reader gets until then.
///
/// # Why this is a SECOND static and not `APP_SERVICE.get_or_init(...)`
///
/// The seams cannot exist when the app opens: they need the endpoint the engine actually connected
/// to, and an unlocked account. So the shell READS the service (to draw the card's honest blocked
/// state) long before it can INSTALL one. With a single `get_or_init`, that first read would occupy
/// the slot with an unwired service, permanently — the app would draw *this version of DIG cannot
/// reach the blockchain* for the rest of the session, on a machine where editing works, and
/// `install` would silently do nothing.
///
/// Keeping the fallback apart means looking costs nothing: reading never closes the door.
static NO_SEAMS: OnceLock<Arc<EditService>> = OnceLock::new();

/// What became of a Save press: the write started, or the one reason it did not.
///
/// Three refusals rather than one `false`. They differ in what a person should DO — wait, restart the
/// app with a node, or nothing at all — so a surface that cannot tell them apart cannot say anything
/// true about any of them.
///
/// Every variant other than [`Started`](Self::Started) shares the same guarantees, and they are what
/// make a wrong SENTENCE the whole of the defect rather than a symptom of a worse one: nothing was
/// signed, nothing was broadcast, no money moved, and the typing is still on the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a save that did not start must not be treated as one that did"]
pub enum SaveOutcome {
    /// The write is running.
    Started,
    /// This build has no chain transport wired, so nothing could have been published from here.
    NotWired,
    /// The profile's current body could not be read, and an edit is computed against what was read.
    ProfileUnreadable,
    /// The app is already writing to the chain and holds the feed — the one-write-at-a-time rule.
    AnotherWriteInFlight,
}

impl SaveOutcome {
    /// The verdict `start_commit` reached: it refuses only by failing to claim the feed.
    fn of_started(started: bool) -> Self {
        match started {
            true => Self::Started,
            false => Self::AnotherWriteInFlight,
        }
    }

    /// Whether a write is now running.
    #[must_use]
    pub fn started(self) -> bool {
        matches!(self, Self::Started)
    }
}

impl EditService {
    /// A service over `seams`, publishing chain writes into `feed`.
    pub fn new(seams: EditSeams, feed: Feed) -> Self {
        Self {
            seams,
            // `Pending` and not `Unreadable`: nothing has been asked yet, and an app that has not
            // looked has not failed.
            reading: Mutex::new(ProfileReading::Pending),
            // For the reading's reason: an app that has not looked has not failed, and must not
            // draw a root it has never asked about.
            root: Mutex::new(RootReading::Pending),
            // `Unmeasured` and never `NotOffered`: nothing has looked, and withholding a free
            // remedy because nobody looked is the failure this state exists to prevent.
            repair: Mutex::new(BodyRepair::Unmeasured),
            reading_now: Mutex::new(false),
            last_read: Mutex::new(None),
            interval: READ_INTERVAL,
            // `None`, so the first frame after a launch drains immediately: a body pending at the
            // last shutdown should not wait out a cadence built for retries.
            last_drain: Mutex::new(None),
            draining_now: Mutex::new(false),
            fruitless_drains: Mutex::new(0),
            clock: Arc::new(Instant::now),
            feed,
        }
    }

    /// A service whose reads are paced by `interval` and timed by `clock`, for tests that assert a
    /// RATE and cannot afford to spend the interval waiting for it.
    #[cfg(test)]
    fn paced(seams: EditSeams, interval: Duration, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            interval,
            clock,
            ..Self::new(seams, Feed::detached())
        })
    }

    /// Install the app's service. The first caller wins; later ones are ignored.
    ///
    /// Called once by the binary, with whatever seams that host actually has.
    pub fn install(service: Arc<EditService>) {
        let _ = APP_SERVICE.set(service);
    }

    /// Whether a service has been installed yet.
    ///
    /// # Why the shell needs to ask
    ///
    /// The seams cannot be built at start-up: they need the node endpoint the engine actually
    /// CONNECTED to, and the account being unlocked — neither of which is true when the app opens.
    /// So the shell tries on each repaint, and this is what makes that cheap: without it every frame
    /// would assemble a seam only for [`install`](Self::install) to discard it.
    ///
    /// Answers whether the slot is TAKEN, not whether the seams work — a host that installed a
    /// deliberately unwired service has made its decision, and a shell must not keep retrying over
    /// it every frame.
    pub fn is_installed() -> bool {
        APP_SERVICE.get().is_some()
    }

    /// The app's service — a build with no chain transport until something installs one.
    ///
    /// Reading this does NOT install anything. The unwired fallback lives in its own static, so a
    /// read cannot take the install slot — which is what makes a late install possible at all.
    pub fn app() -> Arc<EditService> {
        APP_SERVICE
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::clone(no_seams()))
    }

    /// A service connected to nothing, for tests and galleries.
    pub fn detached(seams: EditSeams) -> Arc<Self> {
        Arc::new(Self::new(seams, Feed::detached()))
    }

    /// Whether this build can edit a profile at all.
    pub fn is_possible(&self) -> bool {
        self.seams.is_possible()
    }

    /// The offer, read off THIS service's own seams plus the two facts they cannot know.
    ///
    /// # Why the shell asks the service instead of building a second `EditSeams`
    ///
    /// [`ProfileEditing::of_seams`] must be given the seams the app will actually save through, and
    /// the app has exactly one set — the ones installed here. A shell that constructed its own value
    /// to read the offer from would be a second expression of the same capability, which is how a
    /// control comes to be offered by a surface that has nothing behind it (dig_ecosystem#2377's
    /// shape). There is one, and the surface reads it.
    pub fn editing(&self, has_profile: bool, unlocked: bool) -> ProfileEditing {
        ProfileEditing::of_seams(&self.seams, has_profile, unlocked)
    }

    /// The current reading. Never blocks on a chain read.
    pub fn reading(&self) -> ProfileReading {
        self.reading
            .lock()
            .map(|held| held.clone())
            // A poisoned lock is a fault this app cannot describe, and reporting it as a profile
            // holding nothing would be a claim about someone's identity. It reports the fault.
            .unwrap_or_else(|_| {
                ProfileReading::Unreadable("DIG could not read its own state.".to_string())
            })
    }

    /// What the last chain read said about the root this profile publishes at.
    ///
    /// Never blocks, like [`reading`](Self::reading), because the profile card asks every frame.
    pub fn root_reading(&self) -> RootReading {
        self.root
            .lock()
            .map(|held| held.clone())
            // A poisoned lock says nothing about the chain, so it cannot be reported as a profile
            // that has published nothing. It reports the fault, in the words the card will print.
            .unwrap_or_else(|_| RootReading::Unreadable("DIG could not read its own state.".into()))
    }

    /// Whether the last read established that this profile's content can be put back on this
    /// computer without a chain write (dig-app#207).
    ///
    /// Never blocks, like [`reading`](Self::reading), because the profile card asks every frame.
    pub fn repair_offer(&self) -> BodyRepair {
        self.repair
            .lock()
            .map(|held| held.clone())
            // A poisoned lock measured nothing. Reporting it as `NotOffered` would withdraw a free
            // remedy on the strength of a fault that says nothing about the profile.
            .unwrap_or(BodyRepair::Unmeasured)
    }

    /// Put this profile's published content back on this computer, from the seed it was minted with.
    ///
    /// **No chain write, no signature, no spend** — see [`super::repair`]. It runs on the CALLING
    /// thread and must therefore never be called from the one that paints the window; the tray's
    /// menu handler is where it belongs, which is the same place `reset_coin_db`'s own one-shot
    /// control call runs (dig-app#295).
    ///
    /// # Why it acts on the measured offer and not on a root it is handed
    ///
    /// The offer carries the root it was measured against, off the same read as everything else the
    /// card is drawing. Taking a root from the caller instead would let a menu row drawn a tick ago
    /// aim this at a value the chain has since moved past — and the bytes would then be stored under
    /// a root nothing anchors. A control drawn from a stale row therefore refuses rather than acting
    /// on the stale value.
    ///
    /// On success the profile is read again, so the surface shows the restored content rather than
    /// the banner it was still drawing.
    pub fn repair_body(self: &Arc<Self>) -> RepairOutcome {
        let EditSeams::Wired { seam, bodies, .. } = &self.seams else {
            return RepairOutcome::NotOffered;
        };
        let Some(root) = self.repair_offer().root().map(str::to_owned) else {
            return RepairOutcome::NotOffered;
        };

        let outcome = repair::restore(&**bodies, &seam.store_id(), &root);
        if matches!(outcome, RepairOutcome::Restored { .. }) {
            self.read_again();
        }
        outcome
    }

    /// Read the profile from chain, off the calling thread.
    ///
    /// Safe to call every frame, and it is called every frame: the pane has no cadence of its own.
    ///
    /// # Why the in-flight guard was not enough
    ///
    /// It de-duplicates CONCURRENT reads only, and it clears the instant a read returns — so the
    /// next frame started another, and the reads ran back to back for as long as the pane was open.
    /// Each one is a singleton lineage walk plus a `coinById`, which measured as ~8 chain reads per
    /// second sustained against the node, exhausting its wallet rate limiter. The app then denied
    /// itself the very read it wanted, permanently and stably: closing the app was the only cure
    /// (dig_ecosystem#3044).
    ///
    /// So the rate is bounded here, by [`READ_INTERVAL`], which also means a REFUSED
    /// read is never retried immediately — a tight retry against a rate limit re-creates the same
    /// equilibrium at any baseline cadence.
    pub fn refresh(self: &Arc<Self>) {
        if !self.due() {
            return;
        }
        if !self.begin_reading() {
            return;
        }
        let EditSeams::Wired { seam, .. } = &self.seams else {
            // One sentence, said once: the reading and the root describe the same missing seam, and
            // two copies of a sentence are two sentences waiting to disagree.
            let why = "This version of DIG cannot reach the blockchain to read your profile.";
            self.finish_reading(
                ProfileReading::Unreadable(why.to_string()),
                RootReading::Unreadable(why.to_string()),
                // Nothing was measured, so nothing may be reported as unrepairable either.
                BodyRepair::Unmeasured,
            );
            return;
        };

        let seam = Arc::clone(seam);
        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let read = seam.read();
            // All three facts come off the SAME read, so the card can never name a root from one
            // read beside a state — or a repair offer — from another.
            let root = RootReading::of_read(read.as_ref());
            let repair = BodyRepair::of_read(read.as_ref());
            let answer = match &read {
                Ok(snapshot) => ProfileReading::Known(snapshot.draft()),
                // Three states, three sentences: a profile that has published nothing and a node
                // that could not be asked have opposite remedies (dig_ecosystem#3036), and the
                // mapping that keeps them apart lives in one place.
                Err(error) => ProfileReading::of_read_failure(error),
            };
            service.finish_reading(answer, root, repair);
        });
    }

    /// Forget the current answer and read again — the retry a failed read offers.
    ///
    /// This is the ONE path that skips the interval, because a person pressed a button and a retry
    /// that visibly does nothing for fifteen seconds reads as a broken control. It is bounded by
    /// how fast a hand can press, and by the in-flight guard, so it cannot become the automatic
    /// loop [`refresh`](Self::refresh) exists to prevent.
    pub fn read_again(self: &Arc<Self>) {
        if let Ok(mut held) = self.reading.lock() {
            *held = ProfileReading::Pending;
        }
        // Forgotten with the reading it came from: a root left behind here would be drawn beside
        // *reading your profile…* as though it had already been confirmed by the read in flight.
        if let Ok(mut held) = self.root.lock() {
            *held = RootReading::Pending;
        }
        // Forgotten with them, for the same reason: an offer left behind here would draw a repair
        // row against a root the read in flight has not confirmed is still the current one.
        if let Ok(mut held) = self.repair.lock() {
            *held = BodyRepair::Unmeasured;
        }
        if let Ok(mut last) = self.last_read.lock() {
            *last = None;
        }
        self.refresh();
    }

    /// Commit `changes`, off the calling thread, reporting into the feed.
    ///
    /// Silently does nothing without seams. The control that reaches here is withheld by the model
    /// in that state, so this is the belt to that braces rather than a path a person can take.
    ///
    /// Says whether a write STARTED and, when it did not, WHY.
    ///
    /// It used to answer a `bool`, and every caller reported the single sentence "another write is in
    /// flight" for all three refusals — so a build with no chain transport told a person to wait for a
    /// write that did not exist (dig-app#318, F3). The OUTCOME was honest throughout: nothing was
    /// signed, nothing was spent, and the typing was kept. Only the stated cause was wrong, which is
    /// the worse failure, because a reader who checks the behaviour finds it correct and never checks
    /// the reason.
    #[must_use = "a save that did not start must not be treated as one that did"]
    pub fn save(&self, changes: Vec<(ProfileField, SlotChange)>) -> SaveOutcome {
        let EditSeams::Wired {
            seam,
            bodies,
            pending,
        } = &self.seams
        else {
            return SaveOutcome::NotWired;
        };
        // Two readings may be published from, and the second is the exception that proves the rule.
        //
        // Nothing may be committed over a profile this app FAILED to read: the edit is computed
        // against what was read, so against a failed read it would be computed against nothing and
        // would publish a body missing everything the profile still held.
        //
        // `BodyLost` is not that. Its content is not on this computer and no seed rebuilds it, so
        // there is nothing LOCAL left for a fresh body to lose, and refusing here is what made the
        // remedy a silent no-op: the form invited a
        // person to publish, the press did nothing, and the modal closed exactly as it does on a
        // real save (dig_ecosystem#3041, the shape of #3069). The attempt now runs, and whatever the
        // seam answers — today a refusal, because dig-account computes an edit as a delta over a
        // body it must read first — is REPORTED rather than swallowed.
        // The route is decided HERE, from the reading, because this is the only place that holds
        // one. A fresh publish REPLACES the whole profile, so it is offered on exactly the states
        // that have nothing left to replace: sending a `Known` profile down it would delete every
        // slot the form does not carry, silently and on chain.
        //
        // `Unpublished` is the second of those and the safest (dig-app#207): the store commits no
        // content at all, so a first publish replaces nothing rather than replacing something the
        // app merely could not see. It reached here as `ProfileUnreadable` until now, which made
        // the card's own sentence — *publishing writes to the blockchain and costs a small amount
        // of XCH* — an offer the app would refuse.
        let route = match self.reading() {
            ProfileReading::Known(_) => EditRoute::Delta,
            ProfileReading::BodyLost { .. } | ProfileReading::Unpublished { .. } => {
                EditRoute::FreshBody
            }
            _ => return SaveOutcome::ProfileUnreadable,
        };
        SaveOutcome::of_started(start_commit(
            Arc::clone(seam),
            Arc::clone(bodies),
            Arc::clone(pending),
            // Asked of the seam directly, never taken from a fresh `read()`: naming the store costs
            // nothing, and reading it would put a node round trip on the thread that pressed Save.
            seam.store_id(),
            changes,
            route,
            self.feed.clone(),
            Watch::default(),
        ))
    }

    /// Offer every body still waiting on this computer to the node again, off the calling thread.
    ///
    /// # Why a start-up drain was not enough
    ///
    /// A body waits on disk because the node would not take it, and the commonest reason is a root
    /// the chain has not confirmed yet — which resolves by itself within a block or two. Until this
    /// existed the only drain ran once per process, so that body stayed unreadable to everyone else
    /// until the person happened to restart dig-app, for a reason they had no way to know
    /// (dig_ecosystem#3078). Nothing was ever at risk — the bytes are on disk and sealed — but the
    /// profile stayed private for as long as the app stayed open, which is the opposite of what a
    /// person who pressed Save was told.
    ///
    /// # It is safe to call from a repaint
    ///
    /// Every frame may call it. The cadence gate answers first and costs an atomic clock read, the
    /// in-flight guard stops two overlapping, and the work itself happens on its own thread — the
    /// node round trips must never land on the thread that paints the window (dig_ecosystem#2995).
    ///
    /// An entry is cleared only by [`drain`](super::pending::drain)'s verified read-back, which this
    /// does not relax: retrying more often changes how soon a body is offered, never what counts as
    /// the node having it.
    pub fn retry_pending_bodies(self: &Arc<Self>) {
        let EditSeams::Wired {
            bodies, pending, ..
        } = &self.seams
        else {
            return;
        };
        if !self.drain_due() || !self.begin_draining() {
            return;
        }

        let bodies = Arc::clone(bodies);
        let pending = Arc::clone(pending);
        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let report = super::pending::drain(&*pending, &*bodies);
            service.finish_draining(report);
        });
    }

    /// Whether enough time has passed since the last drain STARTED to start another.
    ///
    /// Timed from the START, like [`due`](Self::due), because that is what makes the bound exact: at
    /// most one drain begins per gap, whatever a single drain costs. A poisoned lock answers `false`
    /// — the conservative direction is to ask the node less.
    fn drain_due(&self) -> bool {
        let Ok(last) = self.last_drain.lock() else {
            return false;
        };
        let gap = self.drain_gap();
        last.map_or(true, |started| {
            (self.clock)().duration_since(started) >= gap
        })
    }

    /// How long to wait before the next drain.
    ///
    /// [`DRAIN_INTERVAL`] until two attempts in a row have moved nothing, then doubling per
    /// fruitless attempt up to [`DRAIN_CEILING`]. A poisoned lock answers the ceiling: the safe
    /// direction is to ask the node less often, and the bytes are on disk either way.
    fn drain_gap(&self) -> Duration {
        let Ok(fruitless) = self.fruitless_drains.lock() else {
            return DRAIN_CEILING;
        };
        DRAIN_INTERVAL
            .saturating_mul(2u32.saturating_pow(fruitless.saturating_sub(1).min(16)))
            .min(DRAIN_CEILING)
    }

    /// Claim the right to run a drain, and record when it began. `false` when one is already running.
    fn begin_draining(&self) -> bool {
        match self.draining_now.lock() {
            Ok(mut running) if !*running => {
                *running = true;
                if let Ok(mut last) = self.last_drain.lock() {
                    *last = Some((self.clock)());
                }
                true
            }
            _ => false,
        }
    }

    /// Release the claim, and set the gap the next attempt will wait.
    ///
    /// Progress resets the cadence; an attempt that moved nothing doubles it. Which of those a
    /// report describes is read from the report itself rather than from the refusal text, because the
    /// two refusals that matter are told apart by their OUTCOME over time — an unconfirmed root
    /// starts succeeding, a body that does not rebuild to its root never will — and backing off is
    /// the one response that is correct for both.
    fn finish_draining(&self, report: super::pending::DrainReport) {
        if report.stored > 0 {
            tracing::info!(
                stored = report.stored,
                waiting = report.waiting,
                "the node has taken profile content that was waiting on this computer"
            );
        }
        if let Ok(mut fruitless) = self.fruitless_drains.lock() {
            *fruitless = match report.stored > 0 || report.waiting == 0 {
                true => 0,
                false => fruitless.saturating_add(1),
            };
        }
        if let Ok(mut running) = self.draining_now.lock() {
            *running = false;
        }
    }

    /// Whether enough time has passed since the last read STARTED to start another.
    ///
    /// A poisoned lock answers `false` — the conservative direction here is to read LESS, since the
    /// failure this paces is reading too much.
    fn due(&self) -> bool {
        let Ok(last) = self.last_read.lock() else {
            return false;
        };
        last.map_or(true, |started| {
            (self.clock)().duration_since(started) >= self.interval
        })
    }

    /// Claim the right to run a read, and record when it began. `false` when one is already running.
    fn begin_reading(&self) -> bool {
        match self.reading_now.lock() {
            Ok(mut running) if !*running => {
                *running = true;
                if let Ok(mut last) = self.last_read.lock() {
                    *last = Some((self.clock)());
                }
                true
            }
            _ => false,
        }
    }

    /// Publish an answer and release the claim.
    fn finish_reading(&self, answer: ProfileReading, root: RootReading, repair: BodyRepair) {
        if let Ok(mut held) = self.reading.lock() {
            *held = answer;
        }
        if let Ok(mut held) = self.root.lock() {
            *held = root;
        }
        if let Ok(mut held) = self.repair.lock() {
            *held = repair;
        }
        if let Ok(mut running) = self.reading_now.lock() {
            *running = false;
        }
    }
}

/// The unwired service, created once and shared.
fn no_seams() -> &'static Arc<EditService> {
    NO_SEAMS.get_or_init(|| Arc::new(EditService::new(EditSeams::NoChainTransport, Feed::app())))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::bodies::doubles::{InMemoryBodies, NodeThatWarmsUp};
    use super::super::commit::{CommitOutcome, ProfileEditError, ProfileEditSeam, ProfileSnapshot};
    use super::super::pending::doubles::InMemoryPending;
    use super::super::pending::{PendingBodies, PendingBody};
    use super::*;

    /// A seam over a profile that reads, with a counter so a test can see how often.
    struct Reading {
        answer: Result<ProfileSnapshot, ProfileEditError>,
        reads: Mutex<usize>,
        /// How often a DELTA commit was ATTEMPTED. The observable for a control that must not be
        /// silent, and half of the observable for which operation an attempt routed to.
        commits: Mutex<usize>,
        /// How often a FRESH publish was attempted. The other half: the two counters together are
        /// what tell a routed attempt apart from an attempt that merely happened.
        fresh_publishes: Mutex<usize>,
    }

    impl Reading {
        fn of(answer: Result<ProfileSnapshot, ProfileEditError>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                reads: Mutex::new(0),
                commits: Mutex::new(0),
                fresh_publishes: Mutex::new(0),
            })
        }
    }

    impl ProfileEditSeam for Reading {
        fn store_id(&self) -> String {
            a_profile().store_id
        }
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            *self.reads.lock().expect("reads") += 1;
            self.answer.clone()
        }
        fn commit(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            *self.commits.lock().expect("commits") += 1;
            Err(ProfileEditError::Locked)
        }
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            *self.fresh_publishes.lock().expect("fresh publishes") += 1;
            Err(ProfileEditError::Locked)
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Ok(None)
        }
    }

    /// A profile as REAL DPB bytes, at the root those bytes actually commit to.
    ///
    /// # Why the body cannot be a placeholder
    ///
    /// A delta edit is computed from these bytes before anything is signed, and since
    /// dig_ecosystem#3114 a body the format cannot open stops the spend instead of being ignored.
    /// A `vec![b'x'; 22]` fixture therefore no longer reaches the seam at all — it stands for a
    /// profile no real seam can return, and every assertion made over it would be about the
    /// placeholder rather than about the routing. `commit.rs` holds the same fixture for the same
    /// reason.
    fn a_profile() -> ProfileSnapshot {
        use dig_social_profile::body::VerifiedBody;
        use dig_social_profile::profile::Profile;
        use dig_social_profile::slot::SlotId;
        use dig_social_profile::value::Value;

        let mut profile = Profile::new();
        profile.set(
            SlotId(ProfileField::DisplayName.slot().id()),
            Value::Utf8("Ada".into()),
        );
        let body = VerifiedBody::from_profile(&profile).expect("the fixture profile encodes");

        let mut values = BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada".to_string());
        ProfileSnapshot {
            store_id: "11".repeat(32),
            root: hex::encode(body.root()),
            values,
            body: body.as_bytes().to_vec(),
        }
    }

    fn service_over(seam: Arc<dyn ProfileEditSeam>) -> Arc<EditService> {
        EditService::detached(EditSeams::Wired {
            seam,
            bodies: Arc::new(InMemoryBodies::default()),
            pending: Arc::new(InMemoryPending::default()),
        })
    }

    /// Wait for the reading to stop being `Pending`, bounded so a stuck worker fails the test
    /// rather than hanging the suite.
    fn settled(service: &Arc<EditService>) -> ProfileReading {
        for _ in 0..500 {
            let reading = service.reading();
            if !matches!(reading, ProfileReading::Pending) {
                return reading;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the read never answered");
    }

    /// A clock a test moves by hand, so a cadence measured in seconds can be asserted in
    /// milliseconds.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<Instant>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().expect("the clock");
            *now += by;
        }

        fn handle(&self) -> Clock {
            let shared = Arc::clone(&self.0);
            Arc::new(move || *shared.lock().expect("the clock"))
        }
    }

    /// Wait for any in-flight read to finish, so the next frame sees the state a real frame would.
    fn idle(service: &Arc<EditService>) {
        for _ in 0..500 {
            if !*service.reading_now.lock().expect("the guard") {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("a read never finished");
    }

    /// An open pane repainting every frame reads the chain at the POLL INTERVAL, not at frame rate.
    ///
    /// # Why the assertion is a rate, and why the fixture lets each read FINISH
    ///
    /// The in-flight guard already stopped two reads overlapping, so every test that merely shows a
    /// read succeeds — or that a second read is not started *while the first runs* — passed against
    /// the version that starved the node. What it did not bound is the rate: the guard clears the
    /// moment a read returns, so the next frame opened another, and the reads ran back to back for
    /// as long as the pane was open (~8 chain reads/second measured, dig_ecosystem#3044).
    ///
    /// So the fixture must let each read COMPLETE between frames — a fixture whose reads block, or
    /// which never idles, hides the defect behind the guard and cannot fail. `idle` is that, and it
    /// is what makes this test load-bearing.
    ///
    /// Bounded from BOTH sides. The ceiling is the defect. The floor is the opposite failure — a
    /// pane that stops refreshing entirely would satisfy any ceiling and would never show an edit
    /// somebody published from another machine.
    #[test]
    fn a_pane_repainting_every_frame_reads_the_chain_at_the_poll_interval() {
        const INTERVAL: Duration = Duration::from_secs(15);
        const FRAME: Duration = Duration::from_millis(500);
        const RUN_SECS: u64 = 60;

        let seam = Reading::of(Ok(a_profile()));
        let clock = TestClock::new();
        let service = EditService::paced(
            EditSeams::Wired {
                seam: seam.clone(),
                bodies: Arc::new(InMemoryBodies::default()),
                pending: Arc::new(InMemoryPending::default()),
            },
            INTERVAL,
            clock.handle(),
        );

        let frames = Duration::from_secs(RUN_SECS).as_millis() / FRAME.as_millis();
        for _ in 0..frames {
            service.refresh();
            idle(&service);
            clock.advance(FRAME);
        }

        let reads = *seam.reads.lock().expect("reads");
        let ceiling = (RUN_SECS / INTERVAL.as_secs() + 1) as usize;
        assert!(
            reads <= ceiling,
            "{reads} chain reads in {RUN_SECS}s of an idle open pane; at one per {INTERVAL:?} at \
             most {ceiling} are justified. A read per frame starves the node's rate limiter and the \
             app then denies itself the read it needs."
        );
        assert!(
            reads >= (RUN_SECS / INTERVAL.as_secs()) as usize,
            "{reads} reads in {RUN_SECS}s: the pane stopped refreshing, so an edit published \
             elsewhere would never appear"
        );
    }

    /// **dig_ecosystem#3041.** Publishing from the re-entry form is a real ATTEMPT, not a silent
    /// no-op.
    ///
    /// # The defect this is the observable for
    ///
    /// The card tells a person whose content is not on this computer to type the details in and
    /// publish
    /// them. `save` returned early on every reading that was not `Known`, so the press reached no
    /// seam, produced no error, and closed the modal exactly as a real save does — a promise in
    /// copy that the code did not keep, and the dead-control shape of #3069 arriving through a door
    /// nobody had checked.
    ///
    /// # Why the control is `Unreadable` and not `NoChainTransport`
    ///
    /// The nearest wrong fix is deleting the reading guard altogether, and against an unwired
    /// service that version looks identical — nothing commits either way, because there is no seam.
    /// `Unreadable` is the state that MUST still refuse over a fully wired seam: its bytes may be
    /// perfectly intact behind a node that is merely not answering, so committing there publishes a
    /// body missing everything the profile still holds. One state gained the attempt; the other
    /// must not have.
    #[test]
    fn publishing_a_fresh_body_reaches_the_seam_while_an_unread_profile_still_refuses() {
        let changes = vec![(ProfileField::DisplayName, SlotChange::Set("Ada".into()))];

        let lost = Reading::of(Err(ProfileEditError::BodyLost {
            root: "33".repeat(32),
        }));
        let service = service_over(lost.clone());
        service.refresh();
        assert!(matches!(settled(&service), ProfileReading::BodyLost { .. }));

        assert!(
            service.save(changes.clone()).started(),
            "the re-entry publish was refused a feed nobody was holding"
        );
        assert!(
            waited_for(|| *lost.fresh_publishes.lock().expect("fresh publishes") > 0),
            "pressing publish on the re-entry form reached no seam: it wrote nothing, said \
             nothing, and closed as though it had saved"
        );
        // The ROUTE, not merely the attempt. A delta commit reads the published body first, so over
        // a body that is gone it fails inside the very call meant to carry out the remedy — which
        // is what shipped, and is indistinguishable from this version to any test that only counts
        // attempts (dig_ecosystem#3041).
        assert_eq!(
            *lost.commits.lock().expect("commits"),
            0,
            "the fresh publish was routed through the DELTA commit, which must read the body \
             that is not on this computer before it can write anything"
        );

        // The other side of the routing, and the reason it is a route rather than a fallback: a
        // profile that READ must never go down the fresh path, which publishes only the typed
        // fields and would delete every slot the form does not carry.
        let known = Reading::of(Ok(a_profile()));
        let editing = service_over(known.clone());
        editing.refresh();
        assert!(matches!(settled(&editing), ProfileReading::Known(_)));

        assert!(
            editing.save(changes.clone()).started(),
            "an ordinary edit was refused a feed nobody was holding"
        );
        assert!(
            waited_for(|| *known.commits.lock().expect("commits") > 0),
            "an ordinary edit reached no seam at all"
        );
        assert_eq!(
            *known.fresh_publishes.lock().expect("fresh publishes"),
            0,
            "an ordinary edit was published as a WHOLE fresh profile, which deletes every slot \
             the form does not carry"
        );

        // The control: a profile that merely FAILED to read still refuses, because its bytes may be
        // intact behind a node that is not answering.
        let unread = Reading::of(Err(ProfileEditError::ChainUnreachable("no node".into())));
        let refusing = service_over(unread.clone());
        refusing.refresh();
        assert!(matches!(settled(&refusing), ProfileReading::Unreadable(_)));

        // The exact REASON, not merely "not started": a refusal reported as an in-flight write
        // would tell a person to wait for something that is not happening (dig-app#318, F3).
        assert_eq!(
            refusing.save(changes),
            SaveOutcome::ProfileUnreadable,
            "a save over an unreadable profile reported the wrong cause, or reported itself as              started"
        );
        assert!(
            !waited_for(|| *unread.commits.lock().expect("commits") > 0),
            "a commit was built over a profile this app could not read, so it would publish a \
             body missing everything the profile still holds"
        );
    }

    /// Poll `done` for up to a second. The commit runs on its own thread, so an immediate assertion
    /// would be a race that passes on a fast machine and fails on a loaded one.
    fn waited_for(done: impl Fn() -> bool) -> bool {
        for _ in 0..200 {
            if done() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
    }

    /// Pressing Save does not perform a CHAIN READ on the thread that pressed it.
    ///
    /// # What this catches, and why the count is the assertion
    ///
    /// `save` needs the store id, and the obvious way to get one is to ask the seam to read the
    /// profile — which is a node round trip and a chain walk, run on the painting thread. dig-app
    /// 12.6.0 exists because a chain call ran there during a mint and the window stopped repainting
    /// for the length of the ceremony; from outside, that is a crash.
    ///
    /// A test asserting only that the commit happened cannot see this: the version that blocks
    /// commits too, just after freezing the window. So the observable is the READ COUNT across the
    /// call. The seam counts, one read has already happened to produce the reading `save` requires,
    /// and any read `save` itself performs is a second one.
    #[test]
    fn pressing_save_does_not_read_the_chain_on_the_calling_thread() {
        let seam = Reading::of(Ok(a_profile()));
        let service = service_over(seam.clone());
        service.refresh();
        assert!(matches!(settled(&service), ProfileReading::Known(_)));
        let after_the_read = *seam.reads.lock().expect("reads");

        assert!(
            service
                .save(vec![(
                    ProfileField::DisplayName,
                    SlotChange::Set("Grace".into()),
                )])
                .started(),
            "the edit was refused a feed nobody was holding"
        );

        assert_eq!(
            *seam.reads.lock().expect("reads"),
            after_the_read,
            "Save performed a chain read on the thread that pressed it"
        );
    }

    /// A read that takes a LONG time does not hold the thread that asked for it.
    ///
    /// # Why the fixture blocks rather than merely counting
    ///
    /// The existing count-based test next to this one catches a read performed on the caller's
    /// thread only if that read is CHEAP enough to return — which every double's read is. The
    /// failure a person actually experiences is the slow one: a body call has a 30-second budget
    /// and the recovery path reaches it on a store that holds nothing, so a synchronous
    /// `refresh` would stop the window repainting for half a minute. From outside, that is a crash
    /// (dig-app 12.6.0 was cut for the same shape during a mint).
    ///
    /// So the seam BLOCKS until the test releases it, and the observable is that `refresh` returned
    /// while it was still blocked.
    #[test]
    fn a_slow_read_does_not_hold_the_thread_that_asked_for_it() {
        struct Blocking {
            release: Arc<std::sync::Barrier>,
        }
        impl ProfileEditSeam for Blocking {
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
                a_profile().store_id
            }
            fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
                self.release.wait();
                Ok(a_profile())
            }
            fn commit(
                &self,
                _: &[(ProfileField, SlotChange)],
            ) -> Result<CommitOutcome, ProfileEditError> {
                Err(ProfileEditError::Locked)
            }
            fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
                Ok(None)
            }
        }

        let release = Arc::new(std::sync::Barrier::new(2));
        let service = service_over(Arc::new(Blocking {
            release: Arc::clone(&release),
        }));

        // Returns only if the read is somewhere else; a synchronous one deadlocks here, because
        // nothing has reached the barrier's second party yet.
        service.refresh();

        assert_eq!(
            service.reading(),
            ProfileReading::Pending,
            "the read answered before it was released, so it did not run where the test thinks"
        );
        release.wait();
        assert!(matches!(settled(&service), ProfileReading::Known(_)));
    }

    /// The three states survive the service: a seam reporting *nothing published* reaches the
    /// surface as that state, with no retry — not as the node failure it used to be reported as.
    #[test]
    fn an_unpublished_profile_reaches_the_surface_as_its_own_state() {
        let service = service_over(Reading::of(Err(ProfileEditError::Unpublished)));
        service.refresh();
        let reading = settled(&service);

        assert_eq!(reading, ProfileReading::unpublished());
        assert!(
            !reading.is_retryable(),
            "a profile that has published nothing was offered a retry"
        );
        // The control: the SAME service shape, one variant different, still retries — so the
        // assertion above is about the state and not about retries having been removed.
        let failed = service_over(Reading::of(Err(ProfileEditError::ChainUnreachable(
            "no node".into(),
        ))));
        failed.refresh();
        assert!(settled(&failed).is_retryable());
    }

    /// Reading the app service before anything is installed does NOT take the install slot.
    ///
    /// # The trap, which this file walked into once
    ///
    /// The seams need the endpoint the engine connected to and an unlocked account, so the shell
    /// reads the service to draw its honest blocked state many frames before it can install one. A
    /// single `get_or_init` behind `app()` makes that first read permanent: `install` becomes a
    /// silent no-op and the app reports *this version of DIG cannot reach the blockchain* for the
    /// rest of the session, on a machine where editing works perfectly.
    ///
    /// The read comes FIRST here, because that ordering is the whole property — asserting only that
    /// `is_installed` follows `install` would pass against the broken version too.
    #[test]
    fn reading_the_app_service_early_does_not_close_the_door_on_installing_one() {
        assert!(
            !EditService::is_installed(),
            "this test must run before anything installs a service"
        );
        // What the shell does on every frame before an account is unlocked.
        let early = EditService::app();
        assert!(!early.is_possible());

        EditService::install(service_over(Reading::of(Ok(a_profile()))));

        assert!(EditService::is_installed());
        assert!(
            EditService::app().is_possible(),
            "an early read took the install slot, so the real seams could never be installed"
        );
    }

    #[test]
    fn a_service_starts_out_having_asked_nothing() {
        let service = service_over(Reading::of(Ok(a_profile())));
        assert_eq!(service.reading(), ProfileReading::Pending);
    }

    #[test]
    fn a_refresh_publishes_what_the_seam_read() {
        let service = service_over(Reading::of(Ok(a_profile())));
        service.refresh();
        let reading = settled(&service);
        let draft = reading.draft().expect("a draft");
        assert_eq!(draft.value(ProfileField::DisplayName), "Ada");
    }

    /// A failed read is drawn as a failure with a retry — never as a profile holding nothing.
    #[test]
    fn a_failed_read_is_reported_as_unreadable_and_offers_a_retry() {
        let service = service_over(Reading::of(Err(ProfileEditError::ChainUnreachable(
            "no node".into(),
        ))));
        service.refresh();
        let reading = settled(&service);
        assert!(reading.is_retryable());
        assert!(!reading.is_empty());
    }

    /// The pane calls this every frame. Without the in-flight guard that is a chain read every
    /// frame — twice a second, forever, against a node that is rate-limited.
    #[test]
    fn a_pane_asking_every_frame_starts_one_read_and_not_a_hundred() {
        let seam = Reading::of(Ok(a_profile()));
        let service = service_over(Arc::clone(&seam) as Arc<dyn ProfileEditSeam>);
        for _ in 0..100 {
            service.refresh();
        }
        settled(&service);
        let reads = *seam.reads.lock().expect("reads");
        assert!(reads <= 2, "a frame-rate read storm: {reads} reads");
    }

    /// A build with no seams says so, rather than sitting at "still reading" forever — which is a
    /// spinner that can never resolve, and the dead end #1800 removed.
    #[test]
    fn a_build_with_no_chain_transport_says_so_instead_of_waiting_forever() {
        let service = EditService::detached(EditSeams::NoChainTransport);
        assert!(!service.is_possible());
        service.refresh();
        match settled(&service) {
            ProfileReading::Unreadable(why) => assert!(why.contains("cannot reach")),
            other => panic!("a transport-less build reported {other:?}"),
        }
    }

    /// Nothing is committed over a profile that was never read: the change set is computed against
    /// what was read, so against a failed read it would be computed against nothing at all — which
    /// is a spend that removes every field the person could not see.
    #[test]
    fn nothing_is_committed_over_a_profile_that_could_not_be_read() {
        let service = service_over(Reading::of(Err(ProfileEditError::ChainUnreachable(
            "no node".into(),
        ))));
        service.refresh();
        settled(&service);
        assert_eq!(
            service.save(vec![(ProfileField::Bio, SlotChange::Remove)]),
            SaveOutcome::ProfileUnreadable,
            "a save over an unreadable profile reported the wrong cause, or reported itself as              started"
        );
        assert!(
            service.feed.read().is_none(),
            "a commit was started over a profile nobody could read"
        );
    }

    /// A body the node has not taken yet, as one would sit on disk after a refused `putBody`.
    fn a_waiting_body() -> PendingBody {
        PendingBody {
            store_id: a_profile().store_id,
            root: a_profile().root,
            body: a_profile().body,
        }
    }

    /// A service whose pending set and node a test holds, paced by a clock it moves by hand.
    fn service_draining(
        pending: Arc<InMemoryPending>,
        node: Arc<NodeThatWarmsUp>,
        clock: &TestClock,
    ) -> Arc<EditService> {
        EditService::paced(
            EditSeams::Wired {
                seam: Reading::of(Ok(a_profile())),
                bodies: node,
                pending,
            },
            READ_INTERVAL,
            clock.handle(),
        )
    }

    /// Wait for any in-flight drain to finish, so the next frame sees what a real frame would.
    fn drained(service: &Arc<EditService>) {
        for _ in 0..500 {
            if !*service.draining_now.lock().expect("the guard") {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("a drain never finished");
    }

    /// **A body refused once is offered again WITHOUT a restart** (dig_ecosystem#3078).
    ///
    /// # Why the fixture is a node that changes its mind
    ///
    /// The refusal this exists for is temporary: `putBody` declines a root the chain has not
    /// confirmed, and a block or two later the same bytes are accepted. So the only fixture that can
    /// see the defect is one that refuses and then accepts — against a permanently-refusing node
    /// every implementation leaves the entry pending and passes, and against a permanently-accepting
    /// one the start-up drain alone passes. The nearest wrong implementation is the code this
    /// replaces: it drains once per process, so it is the flip-then-retry that it fails.
    ///
    /// The clock is fake, so a thirty-second cadence is asserted in microseconds.
    #[test]
    fn a_body_the_node_refused_is_taken_later_in_the_same_session() {
        let clock = TestClock::new();
        let pending = Arc::new(InMemoryPending::default());
        pending.remember(&a_waiting_body()).expect("remembers");
        let node = Arc::new(NodeThatWarmsUp::default());
        let service = service_draining(Arc::clone(&pending), Arc::clone(&node), &clock);

        // The first attempt, as the start-up drain would make it: the chain is behind, so the node
        // refuses and the body correctly stays on disk.
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(
            pending.all().expect("reads").len(),
            1,
            "a refused body was dropped from disk, which is the loss #3066 closed"
        );

        // A block carries the new root. Nothing in the app is told; nothing in the app asks again
        // until the cadence comes round.
        node.catch_up();
        clock.advance(DRAIN_INTERVAL);
        service.retry_pending_bodies();
        drained(&service);

        assert!(
            pending.all().expect("reads").is_empty(),
            "the profile is still private to everyone else until the person restarts dig-app"
        );
    }

    /// The same call from every frame is one offer per cadence, not one per frame.
    ///
    /// Bounded from BOTH sides: the ceiling is a retry storm against a rate-limited node, and the
    /// floor is a cadence so cautious it never retries at all — which is the defect being fixed.
    #[test]
    fn frames_between_cadences_do_not_re_offer_the_body() {
        let clock = TestClock::new();
        let pending = Arc::new(InMemoryPending::default());
        pending.remember(&a_waiting_body()).expect("remembers");
        let node = Arc::new(NodeThatWarmsUp::default());
        let service = service_draining(Arc::clone(&pending), Arc::clone(&node), &clock);

        // Two hundred repaints inside one cadence — about a minute and a half of an open pane.
        for _ in 0..200 {
            service.retry_pending_bodies();
            drained(&service);
        }
        assert_eq!(
            node.offers(),
            1,
            "an open pane hammered the node once per frame"
        );

        clock.advance(DRAIN_INTERVAL);
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(node.offers(), 2, "the cadence never came round");
    }

    /// An entry that can never be accepted backs off — but not on its FIRST refusal.
    ///
    /// # Both directions are defects, and they pull opposite ways
    ///
    /// Backing off too eagerly is the one that hurts the common case: a single refusal almost always
    /// means the chain has not caught up, so doubling the wait then delays exactly the body that was
    /// about to succeed. Never backing off is the other — an entry whose body does not rebuild to its
    /// root can never be accepted, and asking every thirty seconds forever is a node this app is
    /// pointlessly loading. So the schedule is pinned at both ends here.
    #[test]
    fn refusals_widen_the_gap_but_the_first_retry_is_still_prompt() {
        let clock = TestClock::new();
        let pending = Arc::new(InMemoryPending::default());
        pending.remember(&a_waiting_body()).expect("remembers");
        let node = Arc::new(NodeThatWarmsUp::default());
        let service = service_draining(Arc::clone(&pending), Arc::clone(&node), &clock);

        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(
            service.drain_gap(),
            DRAIN_INTERVAL,
            "one refusal delayed the retry that was most likely to succeed"
        );

        // The second refusal is the one that starts widening the gap.
        clock.advance(DRAIN_INTERVAL);
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(node.offers(), 2, "the first cadence never came round");
        assert_eq!(service.drain_gap(), DRAIN_INTERVAL * 2);

        // One interval is no longer enough, and the widened gap does come round.
        clock.advance(DRAIN_INTERVAL);
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(node.offers(), 2, "the gap widened but was not respected");
        clock.advance(DRAIN_INTERVAL);
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(node.offers(), 3, "the widened gap never came round");

        // And it stops widening: many refusals later the wait is the ceiling, not an eternity.
        for _ in 0..20 {
            clock.advance(DRAIN_CEILING);
            service.retry_pending_bodies();
            drained(&service);
        }
        assert_eq!(
            service.drain_gap(),
            DRAIN_CEILING,
            "the back-off grew past its ceiling and stopped retrying in any useful time"
        );

        // A node that finally accepts resets the cadence, so the next waiting body is prompt again.
        node.catch_up();
        clock.advance(DRAIN_CEILING);
        service.retry_pending_bodies();
        drained(&service);
        assert_eq!(
            service.drain_gap(),
            DRAIN_INTERVAL,
            "progress did not reset the back-off, so a healthy node is still asked once an hour"
        );
    }
}
