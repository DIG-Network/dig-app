//! The one place a profile lookup runs, and the one place its answer is kept.
//!
//! # Why a service and not something the pane owns
//!
//! The window is rebuilt from a snapshot every repaint, so anything the pane holds is either
//! recomputed sixty times a second or lost. A lookup is several seconds of chain reads, and running
//! one per frame would ask the same node the same question about the same store until it stopped
//! answering. So the answer outlives the frame here, exactly as
//! [`EditService`](crate::profile_edit::service::EditService) does for the account's own profile, and
//! for the same reason.
//!
//! # What it will not do
//!
//! It spends nothing, signs nothing, and holds no key. Reading somebody's profile is a chain read
//! and a body fetch; there is nowhere in this file for a key to go, which is the property that keeps
//! a viewing surface from becoming an authorising one.

use std::sync::{Arc, Mutex, OnceLock};

use super::chain::StoreProfiles;
use super::{DidOutcome, ViewedProfile};

/// Said when there is no node to ask at all.
///
/// A build with nothing wired reports that it could not ask — never that there is no profile. The
/// two have opposite remedies and only one of them is about what the person typed.
const NO_NODE: &str =
    "This copy of DIG is not connected to a node, so it cannot look a profile up.";

/// A lookup source, its latest answer, and the guard that keeps one worker running at a time.
pub struct LookupService {
    /// Where a store id is resolved. `None` in a build with no chain and no node, which reads as an
    /// honest [`ViewedProfile::Unreachable`] rather than as a profile that does not exist.
    source: Option<Arc<dyn StoreProfiles>>,
    /// The latest answer, or the state of the lookup under way.
    reading: Mutex<ViewedProfile>,
}

/// The app's one service, once something has installed it.
static APP_SERVICE: OnceLock<Arc<LookupService>> = OnceLock::new();

/// The service every reader gets until then.
///
/// A SECOND static rather than `get_or_init`, for [`EditService`]'s reason: the shell reads the
/// service to draw the pane long before it can build one over a live endpoint, and a `get_or_init`
/// read would occupy the slot with an unwired service for the rest of the session.
///
/// [`EditService`]: crate::profile_edit::service::EditService
static NO_SOURCE: OnceLock<Arc<LookupService>> = OnceLock::new();

impl LookupService {
    /// A service that looks profiles up through `source`.
    pub fn new(source: Arc<dyn StoreProfiles>) -> Self {
        Self {
            source: Some(source),
            reading: Mutex::new(ViewedProfile::NotLookedUp),
        }
    }

    /// Install `service` as the app's. The first call wins; later ones are ignored.
    pub fn install(service: Arc<LookupService>) {
        let _ = APP_SERVICE.set(service);
    }

    /// Whether a real service has been installed yet.
    pub fn is_installed() -> bool {
        APP_SERVICE.get().is_some()
    }

    /// The app's service, or one that can look nothing up.
    pub fn app() -> Arc<LookupService> {
        APP_SERVICE
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::clone(no_source()))
    }

    /// A service over `source` that no other test can see.
    pub fn detached(source: Arc<dyn StoreProfiles>) -> Arc<Self> {
        Arc::new(Self::new(source))
    }

    /// What is currently known about the profile somebody asked to see.
    pub fn reading(&self) -> ViewedProfile {
        self.reading
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// Forget the current answer, so the surface returns to the state it opened in.
    pub fn clear(&self) {
        self.put(ViewedProfile::NotLookedUp);
    }

    /// Look `store_id` up, on a worker, and publish the answer when it arrives.
    ///
    /// A lookup already under way is left alone: a person pressing the button twice is asking the
    /// same question, and starting a second walk would make which answer lands a race.
    pub fn look_up(self: &Arc<Self>, store_id: &str) {
        if self.reading().is_looking() {
            return;
        }
        let store_id = store_id.to_string();
        self.put(ViewedProfile::Looking {
            store_id: store_id.clone(),
        });

        let Some(source) = self.source.clone() else {
            // No chain and no node: an honest "could not ask", never "no such profile". The two
            // have opposite remedies and only one of them is about the person's store id.
            self.put(ViewedProfile::Unreachable {
                store_id,
                why: NO_NODE.to_string(),
            });
            return;
        };

        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let answer = source.look_up(&store_id);
            service.put(answer);
        });
    }

    /// Resolve `did` to the store that holds its profile and look that up, on a worker.
    ///
    /// Shares [`look_up`](Self::look_up)'s in-flight guard rather than having its own, because they
    /// publish into the same slot: two walks running at once would make which answer a person ends
    /// up looking at a race, and the losing one could be about a different identity entirely.
    ///
    /// The answer a resolved DID publishes is an ORDINARY store reading — the source resolves and
    /// then looks up, so nothing here re-renders a profile a second way.
    pub fn look_up_did(self: &Arc<Self>, did: &str) {
        if self.reading().is_looking() {
            return;
        }
        let did = did.to_string();
        self.put(ViewedProfile::Did {
            did: did.clone(),
            outcome: DidOutcome::Looking,
        });

        let Some(source) = self.source.clone() else {
            self.put(ViewedProfile::Did {
                did,
                outcome: DidOutcome::Unreachable {
                    why: NO_NODE.to_string(),
                },
            });
            return;
        };

        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let answer = source.look_up_did(&did);
            service.put(answer);
        });
    }

    /// Publish `answer` as the current reading.
    fn put(&self, answer: ViewedProfile) {
        if let Ok(mut held) = self.reading.lock() {
            *held = answer;
        }
    }
}

/// The service returned before one is installed: it can look nothing up, and says so.
fn no_source() -> &'static Arc<LookupService> {
    NO_SOURCE.get_or_init(|| {
        Arc::new(LookupService {
            source: None,
            reading: Mutex::new(ViewedProfile::NotLookedUp),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A source that answers whatever it was built with.
    struct Fixed(ViewedProfile);

    impl StoreProfiles for Fixed {
        fn look_up(&self, _store_id: &str) -> ViewedProfile {
            self.0.clone()
        }
        fn look_up_did(&self, _did: &str) -> ViewedProfile {
            self.0.clone()
        }
    }

    /// A source that blocks until it is told to answer, so a lookup can be observed mid-flight.
    struct Held(Mutex<mpsc::Receiver<ViewedProfile>>);

    impl StoreProfiles for Held {
        fn look_up(&self, _store_id: &str) -> ViewedProfile {
            self.answer()
        }
        fn look_up_did(&self, _did: &str) -> ViewedProfile {
            self.answer()
        }
    }

    impl Held {
        /// Block until the test sends the one answer this fixture is for.
        fn answer(&self) -> ViewedProfile {
            self.0
                .lock()
                .expect("the fixture holds the receiver alone")
                .recv()
                .expect("the test sends exactly one answer")
        }
    }

    /// Wait for `service` to stop looking, or fail loudly rather than hanging the suite.
    fn settled(service: &Arc<LookupService>) -> ViewedProfile {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let reading = service.reading();
            if !reading.is_looking() {
                return reading;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the lookup never produced an answer");
    }

    /// A store id, of the right shape, for a fixture that never resolves one.
    const ID: &str = "371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0";

    /// **The source's answer is what the service publishes, unaltered.**
    ///
    /// The fixture is the state that is most easily lost on the way through a service: a root with
    /// no body behind it. A service that reduced its source's answer to "did it work" would publish
    /// a failure here, and the pane would say the profile does not exist.
    #[test]
    fn a_root_with_no_body_survives_the_journey_through_the_service() {
        let answer = ViewedProfile::BodyMissing {
            store_id: ID.to_string(),
            root: "0x371a39b0".to_string(),
        };
        let service = LookupService::detached(Arc::new(Fixed(answer.clone())));
        service.look_up(ID);
        assert_eq!(settled(&service), answer);
    }

    /// **A second press does not start a second walk.**
    ///
    /// The distinguishing fixture is a source that BLOCKS: with an instant source both presses
    /// finish before either could be observed, so the test would pass against an implementation
    /// with no guard at all. Holding the first lookup open makes the second press happen while the
    /// first is genuinely in flight, which is the only moment the guard does anything.
    ///
    /// The second answer is the one the guard must NOT let through — if it appears, the second
    /// press started its own walk.
    #[test]
    fn a_second_press_while_a_lookup_is_in_flight_does_not_start_another() {
        let (send, receive) = mpsc::channel();
        let service = LookupService::detached(Arc::new(Held(Mutex::new(receive))));

        service.look_up(ID);
        assert!(
            service.reading().is_looking(),
            "the first lookup was not reported as in flight, so this test cannot see the guard"
        );

        service.look_up(ID);

        let first = ViewedProfile::NoProfile {
            store_id: ID.to_string(),
            why: "the first walk".to_string(),
        };
        send.send(first.clone()).expect("the worker is waiting");
        assert_eq!(
            settled(&service),
            first,
            "the answer published was not the first walk's, so the second press started its own"
        );
    }

    /// A well-formed DID, of the shape a person pastes.
    const DID: &str = "did:chia:1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    /// **A DID resolution that reached a store publishes THAT store's reading, unaltered.**
    ///
    /// The fixture is a resolved profile rather than a DID state, because that is the answer most
    /// easily lost on the way through: a service keeping its own idea of "this was a DID lookup"
    /// would re-wrap it, and the card would draw a DID state over a profile that resolved.
    #[test]
    fn a_did_that_resolved_publishes_the_store_reading_it_became() {
        let answer = ViewedProfile::BodyMissing {
            store_id: ID.to_string(),
            root: "0x371a39b0".to_string(),
        };
        let service = LookupService::detached(Arc::new(Fixed(answer.clone())));
        service.look_up_did(DID);
        assert_eq!(settled(&service), answer);
    }

    /// **A DID walk in flight blocks a second press, whichever kind that press is.**
    ///
    /// Both walks publish into the SAME slot, so a second one starting would make which answer a
    /// person ends up looking at a race — and the loser could be about a different identity
    /// entirely. The distinguishing fixture is a source that BLOCKS: with an instant one, both
    /// presses finish before either could be observed and the test would pass with no guard at all.
    ///
    /// The second press is a STORE lookup rather than another DID, because a guard that only knew
    /// about its own kind of walk would pass a same-kind test and let this one through.
    #[test]
    fn a_store_lookup_pressed_during_a_did_walk_does_not_start_its_own() {
        let (send, receive) = mpsc::channel();
        let service = LookupService::detached(Arc::new(Held(Mutex::new(receive))));

        service.look_up_did(DID);
        assert!(
            service.reading().is_looking(),
            "a DID walk in flight was not reported as a lookup in flight, so this test cannot see \
             the guard"
        );

        service.look_up(ID);

        let first = ViewedProfile::Did {
            did: DID.to_string(),
            outcome: DidOutcome::NoStore,
        };
        send.send(first.clone()).expect("the worker is waiting");
        assert_eq!(
            settled(&service),
            first,
            "the answer published was not the DID walk's, so the second press started its own"
        );
    }

    /// **A build with nothing to ask says it could not ask, never that there is no profile.**
    ///
    /// The two states have opposite remedies: one is about this machine and one is about the store
    /// id a person typed. Reporting the first as the second sends somebody to check an id that was
    /// correct all along.
    #[test]
    fn a_service_with_no_source_reports_that_it_could_not_ask() {
        let service = LookupService::app();
        assert!(
            !LookupService::is_installed(),
            "another test installed the app service, so this one is not measuring the fallback"
        );
        service.look_up(ID);
        match settled(&service) {
            ViewedProfile::Unreachable { store_id, why } => {
                assert_eq!(store_id, ID);
                assert!(
                    !why.to_lowercase().contains("no such"),
                    "an unasked question was worded as an absent profile: {why}"
                );
            }
            other => panic!("a service with no source did not say it could not ask: {other:?}"),
        }
        service.clear();

        // A DID has one MORE way to get this wrong: with no node behind it the answer must be
        // neither an identity that does not exist nor one that has published nothing, since both
        // are claims about the blockchain from a machine that never reached it.
        //
        // Asserted here rather than in a test of its own because both presses drive the one
        // process-global fallback service, and two tests doing that in parallel would race for its
        // single reading slot.
        service.look_up_did(DID);
        match settled(&service) {
            ViewedProfile::Did { did, outcome } => {
                assert_eq!(did, DID);
                assert!(
                    matches!(outcome, DidOutcome::Unreachable { .. }),
                    "an unasked question was answered as something about the blockchain: \
                     {outcome:?}"
                );
            }
            other => panic!("a DID with no source did not say it could not ask: {other:?}"),
        }
        service.clear();
    }
}
