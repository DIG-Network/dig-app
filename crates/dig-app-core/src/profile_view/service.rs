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
use super::ViewedProfile;

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
                why: "This copy of DIG is not connected to a node, so it cannot look a profile up."
                    .to_string(),
            });
            return;
        };

        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let answer = source.look_up(&store_id);
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
    }

    /// A source that blocks until it is told to answer, so a lookup can be observed mid-flight.
    struct Held(Mutex<mpsc::Receiver<ViewedProfile>>);

    impl StoreProfiles for Held {
        fn look_up(&self, _store_id: &str) -> ViewedProfile {
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
    }
}
