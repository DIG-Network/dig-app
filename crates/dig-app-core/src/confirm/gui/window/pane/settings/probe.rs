//! "Test connection": ask the node the settings name, without freezing the window.
//!
//! # Why this is a thread and not a call
//!
//! [`crate::control::fetch_status`] is a blocking HTTP exchange with a timeout measured in seconds,
//! and this runs inside a frame on the prompt thread. Calling it inline would stop the window
//! drawing — including the scrim and the Close button — for as long as an unreachable address takes
//! to time out. So the frame starts the ask and returns, the answer lands in shared state, and the
//! context is asked to repaint when it does.
//!
//! # Why the pane offers this at all
//!
//! Nothing about a node address can be checked by looking at it: `http://localhost:9778` is
//! well-formed on a machine with no node. Validation says what is certainly wrong; only a real
//! exchange says whether anything is there — and it is the same exchange the agent will make, so a
//! pass here means the setting works rather than that it parses.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long one tier is given to answer.
///
/// Long enough for a loopback node under load, short enough that a person watching a spinner learns
/// the answer rather than giving up on it.
const TIMEOUT: Duration = Duration::from_secs(3);

/// What the last connection test is doing, or what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe {
    /// Nothing has been asked yet.
    Idle,
    /// An ask is in flight against these candidates.
    Asking,
    /// It finished: the endpoint that answered, or why nothing did.
    Answered(Result<String, String>),
}

/// The shared cell one frame writes and later frames read.
#[derive(Clone, Default)]
pub(crate) struct Tester {
    cell: Arc<Mutex<Option<Probe>>>,
}

impl Tester {
    /// What the test is doing right now.
    pub(crate) fn state(&self) -> Probe {
        self.cell
            .lock()
            .expect("a probe cell is never poisoned: the worker only ever stores")
            .clone()
            .unwrap_or(Probe::Idle)
    }

    /// Ask the candidates `configured` resolves to, on a thread, and repaint when the answer lands.
    ///
    /// Deliberately re-startable: pressing the button again while an ask is in flight starts a
    /// second one rather than being refused. The states are drawn from whatever finishes last,
    /// which is what a person means by pressing it again.
    pub(crate) fn start(&self, ctx: &egui::Context, configured: Option<String>) {
        let ladder = self.begin(configured);
        let (cell, ctx) = (Arc::clone(&self.cell), ctx.clone());
        // Detached: the answer is delivered through the cell, and a window closed mid-ask must not
        // wait for a timeout it can no longer show.
        std::thread::spawn(move || {
            let token = crate::control::load_control_token();
            let outcome = ask(&ladder, token.as_deref());
            *cell.lock().expect("not poisoned") = Some(Probe::Answered(outcome));
            ctx.request_repaint();
        });
    }

    /// Move to the in-flight state and report the candidates to ask, in order.
    ///
    /// Separate from the spawn so the state a frame draws BETWEEN the press and the answer can be
    /// tested without a network and without a race: a test that started the thread and then read the
    /// state would be asserting which of the two got there first.
    fn begin(&self, configured: Option<String>) -> Vec<String> {
        let ladder = crate::control::endpoint_ladder(configured.as_deref());
        self.store(Probe::Asking);
        ladder
    }

    /// Forget the last answer — used when the address is edited, because an answer about a
    /// different address is worse than none.
    pub(crate) fn forget(&self) {
        self.store(Probe::Idle);
    }

    fn store(&self, probe: Probe) {
        *self.cell.lock().expect("not poisoned") = Some(probe);
    }
}

/// Walk `ladder` and report the endpoint that answered, or every reason none did.
fn ask(ladder: &[String], token: Option<&str>) -> Result<String, String> {
    crate::control::resolve_status(ladder, token, TIMEOUT)
        .map(|(endpoint, _)| endpoint)
        .map_err(|failures| describe(&failures))
}

/// Why nothing answered, in one sentence per candidate tried.
///
/// Every tier is named rather than only the last: on the automatic ladder "nothing answered" is two
/// different facts, and a person deciding whether to type an address needs to know which tier they
/// are missing. The reasons are [`crate::control::ControlCallError`]'s own — it already writes them
/// for a reader, and a second phrasing here would be a second vocabulary for one failure.
fn describe(failures: &[(String, crate::control::ControlCallError)]) -> String {
    if failures.is_empty() {
        // Unreachable: `resolve_status` fails with one entry per candidate and the ladder is never
        // empty. Written anyway, because a blank error message is the one thing this must not be.
        return "DIG had no address to try.".to_string();
    }
    failures
        .iter()
        .map(|(endpoint, why)| format!("{endpoint} — {why}"))
        .collect::<Vec<_>>()
        .join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlCallError;

    /// **A failed test names every address it tried and why each one failed.**
    ///
    /// Two candidates, differing in their reason, because the message a person acts on is the
    /// difference between "nothing is listening" and "it answered and refused us". A summary that
    /// kept only the first, or collapsed both to one sentence, passes a one-candidate test.
    #[test]
    fn a_failure_names_each_tier_and_keeps_its_own_reason() {
        let said = describe(&[
            (
                "http://dig.local".to_string(),
                ControlCallError::Unreachable("no route to host".to_string()),
            ),
            (
                "http://localhost:9778".to_string(),
                ControlCallError::Refused("unknown control token".to_string()),
            ),
        ]);
        assert!(said.contains("http://dig.local"), "{said}");
        assert!(said.contains("http://localhost:9778"), "{said}");
        assert!(said.contains("no route to host"), "{said}");
        assert!(
            said.contains("refused") || said.contains("unknown control token"),
            "the second tier's reason was replaced by the first's: {said}"
        );
    }

    /// **A tester with nothing asked is idle, and a started one is visibly in flight.**
    ///
    /// The state a frame draws BETWEEN the press and the answer is the loading state, and a tester
    /// that stayed `Idle` until its thread finished would draw the window as though nothing had been
    /// pressed. Asserted through [`Tester::begin`] rather than [`Tester::start`] on purpose: with
    /// the thread running, a fast refusal could answer before the assertion, so the test would be
    /// reporting a race rather than the property.
    #[test]
    fn a_started_test_is_visibly_in_flight_before_it_answers() {
        let tester = Tester::default();
        assert_eq!(tester.state(), Probe::Idle);

        let ladder = tester.begin(Some("http://my.node:9778".to_string()));
        assert_eq!(tester.state(), Probe::Asking);
        assert_eq!(
            ladder,
            crate::control::endpoint_ladder(Some("http://my.node:9778")),
            "the test asked something other than what the setting names"
        );

        tester.forget();
        assert_eq!(tester.state(), Probe::Idle);
    }

    /// **An empty address is tested against the ladder DIG would actually walk.**
    ///
    /// The automatic case is the one a person is most likely to press, and testing "nothing" would
    /// answer a question nobody asked.
    #[test]
    fn testing_an_automatic_address_asks_every_tier_dig_would() {
        let tester = Tester::default();
        assert_eq!(tester.begin(None), crate::control::endpoint_ladder(None));
    }
}
