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

use super::commit::{start_commit, EditSeams, Watch};
use super::draft::SlotChange;
use super::field::ProfileField;
use super::offer::ProfileEditing;
use super::ProfileReading;
use crate::transaction::Feed;

/// The editor's seams, its current reading, and the thread that refreshes it.
pub struct EditService {
    /// What this build can do about profiles.
    seams: EditSeams,
    /// The last answer, or the state of the read that is under way.
    reading: Mutex<ProfileReading>,
    /// Whether a read is already running, so a pane asking every frame starts one worker and not
    /// a hundred and twenty.
    reading_now: Mutex<bool>,
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

impl EditService {
    /// A service over `seams`, publishing chain writes into `feed`.
    pub fn new(seams: EditSeams, feed: Feed) -> Self {
        Self {
            seams,
            // `Pending` and not `Unreadable`: nothing has been asked yet, and an app that has not
            // looked has not failed.
            reading: Mutex::new(ProfileReading::Pending),
            reading_now: Mutex::new(false),
            feed,
        }
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

    /// Read the profile from chain, off the calling thread.
    ///
    /// Safe to call every frame: a read already in flight is not started twice, which is what stops
    /// a pane that repaints twice a second from opening a chain read twice a second.
    pub fn refresh(self: &Arc<Self>) {
        if !self.begin_reading() {
            return;
        }
        let EditSeams::Wired { seam, .. } = &self.seams else {
            self.finish_reading(ProfileReading::Unreadable(
                "This version of DIG cannot reach the blockchain to read your profile.".to_string(),
            ));
            return;
        };

        let seam = Arc::clone(seam);
        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let answer = match seam.read() {
                Ok(snapshot) => ProfileReading::Known(snapshot.draft()),
                // Three states, three sentences: a profile that has published nothing and a node
                // that could not be asked have opposite remedies (dig_ecosystem#3036), and the
                // mapping that keeps them apart lives in one place.
                Err(error) => ProfileReading::of_read_failure(&error),
            };
            service.finish_reading(answer);
        });
    }

    /// Forget the current answer and read again — the retry a failed read offers.
    pub fn read_again(self: &Arc<Self>) {
        if let Ok(mut held) = self.reading.lock() {
            *held = ProfileReading::Pending;
        }
        self.refresh();
    }

    /// Commit `changes`, off the calling thread, reporting into the feed.
    ///
    /// Silently does nothing without seams. The control that reaches here is withheld by the model
    /// in that state, so this is the belt to that braces rather than a path a person can take.
    pub fn save(&self, changes: Vec<(ProfileField, SlotChange)>) {
        let EditSeams::Wired { seam, bodies } = &self.seams else {
            return;
        };
        let ProfileReading::Known(_) = self.reading() else {
            // Nothing may be committed over a profile this app has not read: the edit is computed
            // against what was read, and against a failed read it would be computed against nothing.
            return;
        };
        start_commit(
            Arc::clone(seam),
            Arc::clone(bodies),
            // Asked of the seam directly, never taken from a fresh `read()`: naming the store costs
            // nothing, and reading it would put a node round trip on the thread that pressed Save.
            seam.store_id(),
            changes,
            self.feed.clone(),
            Watch::default(),
        );
    }

    /// Claim the right to run a read. `false` when one is already running.
    fn begin_reading(&self) -> bool {
        match self.reading_now.lock() {
            Ok(mut running) if !*running => {
                *running = true;
                true
            }
            _ => false,
        }
    }

    /// Publish an answer and release the claim.
    fn finish_reading(&self, answer: ProfileReading) {
        if let Ok(mut held) = self.reading.lock() {
            *held = answer;
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

    use super::super::bodies::doubles::InMemoryBodies;
    use super::super::commit::{CommitOutcome, ProfileEditError, ProfileEditSeam, ProfileSnapshot};
    use super::*;

    /// A seam over a profile that reads, with a counter so a test can see how often.
    struct Reading {
        answer: Result<ProfileSnapshot, ProfileEditError>,
        reads: Mutex<usize>,
    }

    impl Reading {
        fn of(answer: Result<ProfileSnapshot, ProfileEditError>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                reads: Mutex::new(0),
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
            Err(ProfileEditError::Locked)
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Ok(None)
        }
    }

    fn a_profile() -> ProfileSnapshot {
        let mut values = BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada".to_string());
        ProfileSnapshot {
            store_id: "11".repeat(32),
            root: "22".repeat(32),
            values,
            body_len: 22,
        }
    }

    fn service_over(seam: Arc<dyn ProfileEditSeam>) -> Arc<EditService> {
        EditService::detached(EditSeams::Wired {
            seam,
            bodies: Arc::new(InMemoryBodies::default()),
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

        service.save(vec![(
            ProfileField::DisplayName,
            SlotChange::Set("Grace".into()),
        )]);

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

        assert_eq!(reading, ProfileReading::Unpublished);
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
        service.save(vec![(ProfileField::Bio, SlotChange::Remove)]);
        assert!(
            service.feed.read().is_none(),
            "a commit was started over a profile nobody could read"
        );
    }
}
