//! Telling the node which addresses belong to this account (dig_ecosystem#2848).
//!
//! A dig-node follows the addresses it has been ASKED to follow, and nothing else. An account that
//! exists only inside dig-app is therefore invisible to it: the replica syncs perfectly over
//! somebody else's key, the user's coins are never copied into it, and every money surface in the
//! app truthfully reports that it has no figure. Enrolment is the one call that closes that gap.
//!
//! # What crosses the boundary
//!
//! The **synthetic BLS public key** and nothing else. It is public by construction — it is what
//! curries the standard puzzle the user's coins already live at, and it is derivable by anyone
//! holding the address. No seed, no signing capability, no §908 concern: the node gains the ability
//! to WATCH an address, never to spend from it.
//!
//! # Why the synthetic key specifically
//!
//! dig-node curries the enrolled key directly into `StandardArgs::curry_tree_hash` — it does not
//! call `derive_synthetic()` on what it is given. dig-account's `WalletKey::puzzle_hash()` curries
//! its own synthetic key by the same route, so enrolling
//! [`WalletOps::public_key`](dig_account::UnlockedAccount::wallet_ops) makes the node derive exactly
//! the address the app displays.
//!
//! Enrolling the PRE-synthetic key would fail SILENTLY, which is what makes this worth a paragraph:
//! the node would accept it, `watched_addresses` would become non-zero, and it would faithfully
//! sync a real address the user does not own. Nothing anywhere would report an error and the
//! balance would simply never arrive. `AccountResidency::wallet_public_keys_hex`'s
//! `wallet_keys_curry_to_the_address_on_screen`
//! is the assertion that catches it.
//!
//! # Reconciliation, not fire-and-forget
//!
//! The app may not assume a node remembers: nodes restart, get replaced, and are shared with other
//! clients. So enrolment ASKS what the node already follows
//! ([`ControlMethod::WalletWatched`])
//! and registers only what is missing. Re-watching a key is a no-op on the node, so this is safe to
//! repeat; asking first is what keeps the app's own report ([`Enrolment`]) about the node's state
//! rather than about its own history.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dig_account::{Clock, SystemClock};
use dig_node_control_interface::method::ControlMethod;
use dig_node_control_interface::params::{WalletWatchParams, WalletWatchedParams};

use crate::control::{self, ControlFailure};
use crate::engine::EngineState;

/// How long ONE enrolment exchange may take before it is abandoned.
///
/// Sized like the balance read rather than like a liveness probe: `control.wallet.watched` and
/// `control.wallet.watch` touch the node's subscription store, and a node mid-startup can be slow
/// to answer. An abandoned attempt costs a retry after [`RETRY_INTERVAL`], never a wrong answer.
pub const ENROL_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a FAILED exchange is remembered before the same node is asked again.
///
/// A memo with no expiry is what turns one bad moment into a permanent state: the failure this
/// interval exists for is a node that was merely slow at startup, and remembering that forever
/// leaves an account unenrolled for the rest of the session while the money surface tells its owner
/// DIG registers addresses while unlocked. It also breaks the `SPEC.md` MUST that a node restarted
/// at the same endpoint is re-asserted rather than assumed.
///
/// The memo is EXPIRING rather than cleared on failure, because clearing it would let the repaint
/// rate become the retry rate — twice a second against a node that is already struggling. Thirty
/// seconds is long enough that a refusing node is asked twice a minute, and short enough that a
/// slow start heals while the user is still looking at the window.
///
/// A SUCCESS never expires: it is re-derived from the node's own answer whenever the endpoint or
/// the key set changes, which is the only way it can go stale.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// What this app knows about whether the node follows its account's addresses.
///
/// Deliberately about the NODE's state, never about this app's history: "we sent the keys once" is
/// not the same claim as "the node follows them", and only the second one licenses a surface to
/// stop explaining itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Enrolment {
    /// No node has been asked yet — there is no account unlocked, no node reachable, or the first
    /// exchange has not landed. Not a fault, and it states nothing about the node.
    #[default]
    Unasked,
    /// The node's enrolled set contains every key this account derives.
    ///
    /// Note what this does NOT claim: that the node is FOLLOWING them yet. Enrolment reaches the
    /// live subscription only at the node's next start (dig_ecosystem#2826), and the live count is
    /// [`NetworkStanding::watched_addresses`](crate::network::NetworkStanding::watched_addresses) —
    /// a separate reading, which is why the two are never collapsed here.
    Registered,
    /// The node was asked and would not take the keys, with its own words.
    ///
    /// Kept distinct from [`Unasked`](Self::Unasked) because they call for opposite readings: one
    /// says nothing is known, the other says something was refused.
    Refused(String),
}

/// Registers this account's wallet keys with whichever node is currently reachable, and remembers
/// what it learned.
///
/// One instance for the process, driven from the same tick as the other pollers. It **never
/// blocks**: an exchange runs on a worker and the observation answers from what has already landed,
/// exactly like [`NodeBalance`](crate::wallet::node::NodeBalance) — a repaint may not wait on a
/// node.
pub struct KeyEnrolment {
    state: Arc<Mutex<EnrolState>>,
    timeout: Duration,
    retry_after: Duration,
    read_token: fn() -> Option<String>,
    /// The time source the retry memo expires against — INJECTED, never `Instant::now()`.
    ///
    /// A memo whose expiry is read from the wall clock can only be tested by sleeping through it,
    /// and a test that sleeps measures the machine as much as the code: the first version of the
    /// retry test paced 40 observations through a 250 ms window and got 9 of them on a loaded CI
    /// runner, so it failed there while passing here. The same reasoning is written out on
    /// `account::money`'s `NOW`, where a real clock made the period-cap tests assert nothing.
    clock: Arc<dyn Clock>,
}

/// What the enroller has learned, and what it has learned it ABOUT.
#[derive(Default)]
struct EnrolState {
    /// The endpoint + key set the outcome below describes. A change to either invalidates it: a
    /// different node has a different subscription, and a widened derivation window is a different
    /// question.
    asked: Option<(String, Vec<String>)>,
    outcome: Enrolment,
    /// When the exchange behind [`outcome`](Self::outcome) finished, in seconds since the epoch —
    /// the reading the retry interval is measured from.
    settled: Option<u64>,
    /// Whether an exchange is running, so a twice-a-second repaint starts one exchange, not a
    /// hundred.
    in_flight: bool,
}

impl EnrolState {
    /// Whether the memo for `target` still answers, or has expired and must be re-established.
    ///
    /// Only a FAILURE expires. A success is a fact about a node's key set that nothing but a change
    /// of node or of key set can invalidate — both of which change `target` and so miss this check
    /// entirely — and re-asking a node that already agreed would spend a round trip to be told the
    /// same thing.
    fn answers(
        &self,
        target: &(String, Vec<String>),
        retry_after: Duration,
        now: Option<u64>,
    ) -> bool {
        if self.asked.as_ref() != Some(target) {
            return false;
        }
        match &self.outcome {
            Enrolment::Registered => true,
            // An unreadable clock (`now` is `None`) leaves the memo ANSWERING rather than expired.
            // The two errors are not symmetric: holding the memo costs a retry that does not happen,
            // while treating every observation as expired would make the repaint rate the retry rate
            // against a node that may already be struggling — the storm this whole memo exists to
            // prevent, arriving through the one path that cannot measure whether it is warranted.
            Enrolment::Unasked | Enrolment::Refused(_) => match (self.settled, now) {
                (Some(settled), Some(now)) => now.saturating_sub(settled) < retry_after.as_secs(),
                (Some(_), None) => true,
                (None, _) => false,
            },
        }
    }
}

impl Default for KeyEnrolment {
    fn default() -> Self {
        Self {
            state: Arc::default(),
            timeout: ENROL_TIMEOUT,
            retry_after: RETRY_INTERVAL,
            read_token: control::load_control_token,
            clock: Arc::new(SystemClock),
        }
    }
}

impl KeyEnrolment {
    /// An enroller that obtains its control token from `read_token` rather than the on-disk install,
    /// and retries a failure after `retry_after` rather than after [`RETRY_INTERVAL`].
    #[cfg(test)]
    fn with_token_reader(
        timeout: Duration,
        retry_after: Duration,
        read_token: fn() -> Option<String>,
    ) -> Self {
        Self::with_clock(timeout, retry_after, read_token, Arc::new(SystemClock))
    }

    /// An enroller reading `clock` instead of the system time, so a test drives the retry memo by
    /// ADVANCING time rather than by waiting for it.
    #[cfg(test)]
    fn with_clock(
        timeout: Duration,
        retry_after: Duration,
        read_token: fn() -> Option<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            state: Arc::default(),
            timeout,
            retry_after,
            read_token,
            clock,
        }
    }

    /// The current time in epoch seconds, or `None` when the clock could not be read.
    ///
    /// A failure is reported rather than substituted: a wrong "now" would silently expire or
    /// preserve every memo, and [`EnrolState::answers`] decides what an unknown time means.
    fn now(&self) -> Option<u64> {
        match self.clock.now_unix() {
            Ok(now) => Some(now),
            Err(error) => {
                tracing::warn!(%error, "the clock could not be read; the enrolment memo is held");
                None
            }
        }
    }

    /// Reconcile `keys` against the node behind `link`, and report what is known right now.
    ///
    /// **Never blocks.** With no keys (a locked account) or no node there is nothing to reconcile,
    /// and the answer is [`Enrolment::Unasked`] — an absence of knowledge, never a refusal.
    pub fn observe(&self, link: &EngineState, keys: &[String]) -> Enrolment {
        let EngineState::Connected { endpoint, .. } = link else {
            return Enrolment::Unasked;
        };
        if keys.is_empty() {
            return Enrolment::Unasked;
        }

        let mut state = self.lock();
        let target = (endpoint.clone(), keys.to_vec());
        if state.answers(&target, self.retry_after, self.now()) || state.in_flight {
            return state.outcome.clone();
        }
        state.in_flight = true;
        // A verdict about a DIFFERENT node (or a narrower key set) is discarded rather than shown
        // while this exchange runs: it would report enrolment on a node that never heard of these
        // keys — the one claim this type exists to avoid making. An EXPIRED failure for this same
        // node is kept, because it is still the last thing known about it and a retry in flight is
        // not a reason to un-say it.
        if state.asked.as_ref() != Some(&target) {
            state.outcome = Enrolment::Unasked;
        }
        let carried = state.outcome.clone();
        drop(state);

        let shared = Arc::clone(&self.state);
        let token = (self.read_token)();
        let timeout = self.timeout;
        let clock = Arc::clone(&self.clock);
        std::thread::spawn(move || {
            let outcome = reconcile(&target.0, &target.1, token.as_deref(), timeout);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.asked = Some(target);
            state.outcome = outcome;
            // Stamped from when the exchange FINISHED, not when it started: a 20-second timeout
            // would otherwise consume most of the retry interval it is supposed to precede.
            state.settled = clock.now_unix().ok();
            state.in_flight = false;
        });

        carried
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, EnrolState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Ask the node what it follows, register whatever is missing, and report the end state.
///
/// The read comes first so the app registers a DIFFERENCE rather than re-sending its whole set every
/// time. That is not an optimisation — re-watching is free — it is what makes the outcome a
/// statement about the node: a set that already contains every key yields [`Enrolment::Registered`]
/// without a write, and a node that refuses the read is never reported as enrolled.
fn reconcile(endpoint: &str, keys: &[String], token: Option<&str>, timeout: Duration) -> Enrolment {
    let watched =
        match control::call_control_result(endpoint, &WalletWatchedParams {}, token, timeout) {
            Ok(result) => result.public_keys,
            Err(failure) => return refused(ControlMethod::WalletWatched, failure),
        };
    let missing: Vec<String> = keys
        .iter()
        .filter(|key| !watched.iter().any(|known| known == *key))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Enrolment::Registered;
    }
    let params = WalletWatchParams {
        public_keys: missing,
    };
    match control::call_control_result(endpoint, &params, token, timeout) {
        Ok(_) => Enrolment::Registered,
        Err(failure) => refused(ControlMethod::WalletWatch, failure),
    }
}

/// A refusal, logged with the method that drew it and reported in the node's own words.
fn refused(method: ControlMethod, failure: ControlFailure) -> Enrolment {
    tracing::warn!(
        method = method.name(),
        error = %failure,
        "the node would not enrol this account's addresses"
    );
    Enrolment::Refused(failure.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node::{FakeNode, WatchReply};
    use std::time::Instant;

    /// A key that is not this account's, pre-enrolled on the fake so a reconcile has something to
    /// leave alone — the shape the live node was found in (a hand-registered test key).
    const FOREIGN_KEY: &str = "a1";

    /// A retry interval no test that is not ABOUT retrying can reach — so those tests measure the
    /// behaviour they name, and a retry can never rescue or corrupt one of them by firing partway
    /// through.
    const NO_RETRY: Duration = Duration::from_secs(3600);

    fn key(byte: &str) -> String {
        byte.repeat(48)
    }

    fn fake_token() -> Option<String> {
        Some(FakeNode::TOKEN.to_string())
    }

    fn connected_to(node: &FakeNode) -> EngineState {
        EngineState::Connected {
            endpoint: node.endpoint(),
            status: Box::new(crate::test_support::node::fake_status_result()),
        }
    }

    /// A fixed instant for the retry memo to be measured against — an ordinary epoch second, chosen
    /// so nothing in these tests depends on how long they take to run or on how fast the machine is.
    const NOW: u64 = 1_767_225_600;

    /// Observe once and wait for whatever exchange that started to finish, WITHOUT requiring an
    /// outcome — so a caller can assert about the node's request count without racing a worker.
    fn settle_quietly(enrolment: &KeyEnrolment, link: &EngineState, keys: &[String]) {
        enrolment.observe(link, keys);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while enrolment.lock().in_flight && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Poll `enrolment` until it stops being `Unasked`, or give up — the worker is a thread, so a
    /// bare read after `observe` would race it.
    fn settle(enrolment: &KeyEnrolment, link: &EngineState, keys: &[String]) -> Enrolment {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = enrolment.observe(link, keys);
            if seen != Enrolment::Unasked || Instant::now() > deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A node that follows nothing of ours is sent exactly our keys, and reports them registered.
    #[test]
    fn registers_the_keys_a_node_does_not_hold() {
        let node = FakeNode::serving_watch(WatchReply::holding(&[FOREIGN_KEY.repeat(48)]));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        let keys = vec![key("b2")];

        assert_eq!(
            settle(&enrolment, &connected_to(&node), &keys),
            Enrolment::Registered
        );
        assert_eq!(
            node.enrolled(),
            vec![FOREIGN_KEY.repeat(48), key("b2")],
            "the foreign key is left alone and ours is added"
        );
    }

    /// The reconcile sends only what is MISSING, and the discriminator is the second key: an
    /// implementation that re-sent its whole set would put the already-held key on the wire too.
    /// Asserting only the end state cannot see that, because re-watching is idempotent and both
    /// implementations end at the same set.
    #[test]
    fn sends_only_the_keys_the_node_lacks() {
        let held = key("c3");
        let node = FakeNode::serving_watch(WatchReply::holding(std::slice::from_ref(&held)));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        let keys = vec![held.clone(), key("d4")];

        assert_eq!(
            settle(&enrolment, &connected_to(&node), &keys),
            Enrolment::Registered
        );
        let watch_requests = node.watch_requests();
        assert_eq!(watch_requests.len(), 1, "one write, not one per key");
        assert!(
            watch_requests[0].contains(&key("d4")) && !watch_requests[0].contains(&held),
            "only the missing key is sent: {}",
            watch_requests[0]
        );
    }

    /// A node already holding every key is not written to at all, and still reports registered.
    #[test]
    fn a_node_that_already_holds_the_keys_is_not_written_to() {
        let keys = vec![key("e5")];
        let node = FakeNode::serving_watch(WatchReply::holding(&keys));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);

        assert_eq!(
            settle(&enrolment, &connected_to(&node), &keys),
            Enrolment::Registered
        );
        assert!(
            node.watch_requests().is_empty(),
            "nothing was missing, so nothing was written"
        );
    }

    /// A refusal is reported as one, in the node's words — never as registered.
    #[test]
    fn a_refused_enrolment_is_never_reported_as_registered() {
        let node = FakeNode::serving_watch(WatchReply::rejected(-32001, "UNAUTHORIZED"));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);

        let seen = settle(&enrolment, &connected_to(&node), &[key("f6")]);
        assert!(
            matches!(seen, Enrolment::Refused(_)),
            "a refusal must not read as enrolled: {seen:?}"
        );
    }

    /// **A failure must not disable enrolment for the session, and must not become a request storm
    /// either.** Both halves, in one test, because each alone is satisfied by the wrong fix.
    ///
    /// The gate measured the first half missing: after ONE refused exchange, forty further
    /// observations left the node's served count at one — no spin, and no retry ever. The failure
    /// that strands is the expected one, a node still starting up, and the surface then tells its
    /// owner DIG registers addresses while unlocked, which is false at that moment on the money
    /// surface.
    ///
    /// # Time is ADVANCED, never waited for
    ///
    /// Two earlier drafts of this test were wrong in opposite ways, and both are worth recording.
    ///
    /// The first looped forty times as fast as it could and PASSED against the
    /// clear-the-memo-on-failure implementation it existed to reject: the loop finished inside one
    /// exchange, so `in_flight` suppressed all forty and the count never moved. The property was
    /// real; the fixture could not exhibit its violation.
    ///
    /// The second paced those observations 5 ms apart across a 250 ms window and asserted it had
    /// made more than twenty. That exposed the storm correctly on this machine and FAILED on CI,
    /// where a loaded macOS runner took ~28 ms per iteration and fitted nine — a test measuring the
    /// runner rather than the code. Lengthening the window or lowering the threshold would only have
    /// traded a certain red for an intermittent one.
    ///
    /// So the memo's expiry reads an injected [`Clock`] and this test drives it by SETTING the time:
    /// half one is N observations at a frozen instant, half two is one observation after the clock
    /// has moved past the interval. No sleeps, no pacing, nothing machine-dependent. The `in_flight`
    /// reasoning above still holds — each observation here is serialised behind `settle`, so a
    /// suppressed request cannot be mistaken for a memo that answered.
    #[test]
    fn a_failed_exchange_is_retried_later_but_not_every_repaint() {
        let node = FakeNode::serving_watch(WatchReply::rejected(-32001, "UNAUTHORIZED"));
        let retry_after = Duration::from_secs(30);
        let clock = Arc::new(dig_account::FixedClock::new(NOW));
        let enrolment = KeyEnrolment::with_clock(
            Duration::from_secs(5),
            retry_after,
            fake_token,
            clock.clone(),
        );
        let link = connected_to(&node);
        let keys = vec![key("a9")];

        assert!(matches!(
            settle(&enrolment, &link, &keys),
            Enrolment::Refused(_)
        ));
        let after_first = node.request_count();

        // Repaints INSIDE the memo's life. The clock does not move, so no amount of observing may
        // reach the node — this is the half that rejects clearing the memo on failure. Each call
        // waits for any exchange it started, so a request suppressed by `in_flight` cannot be
        // mistaken for one the memo prevented.
        for second in 0..(retry_after.as_secs() - 1) {
            clock.set(NOW + second);
            settle_quietly(&enrolment, &link, &keys);
        }
        assert_eq!(
            node.request_count(),
            after_first,
            "a repaint-driven caller must not turn a failure into a request storm"
        );

        // Past the memo's life: the node IS asked again. Without this the code that shipped —
        // remembering the failure forever — reads as correct.
        clock.set(NOW + retry_after.as_secs());
        settle_quietly(&enrolment, &link, &keys);
        assert!(
            node.request_count() > after_first,
            "an expired failure must be re-asked, or a slow node at startup leaves the account              unenrolled for the session"
        );
    }

    /// **A retry that succeeds replaces the failure.** The state a slow node at startup actually
    /// heals into, and the reason the retry above is worth having at all.
    ///
    /// The two fakes stand in for one node before and after it finished starting: the endpoint
    /// changes, which is honest — a real node keeps its endpoint — but the property under test is
    /// that a Refused verdict is not sticky, and the sibling
    /// `a_failed_exchange_is_retried_later_but_not_every_repaint` already pins the same-endpoint
    /// retry against the node's own request count.
    #[test]
    fn a_refusal_is_replaced_by_a_later_success() {
        let keys = vec![key("ba")];
        let refusing = FakeNode::serving_watch(WatchReply::rejected(-32001, "UNAUTHORIZED"));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        assert!(matches!(
            settle(&enrolment, &connected_to(&refusing), &keys),
            Enrolment::Refused(_)
        ));

        let healthy = FakeNode::serving_watch(WatchReply::holding(&[]));
        let link = connected_to(&healthy);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = enrolment.observe(&link, &keys);
            if seen == Enrolment::Registered || Instant::now() > deadline {
                assert_eq!(seen, Enrolment::Registered, "a refusal must not be sticky");
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(healthy.enrolled(), keys);
    }

    /// **A success is not re-asked on a timer.** The expiry is for failures only: re-reading a node
    /// that already agreed would spend a round trip every interval, forever, to be told the same
    /// thing — and the facts that CAN invalidate a success (a different node, a wider key set) both
    /// change the memo's target and so never reach the expiry at all.
    ///
    /// Driven by ADVANCING the injected clock well past the interval rather than by sleeping, for
    /// the reason written out on `a_failed_exchange_is_retried_later_but_not_every_repaint`: a
    /// sleeping test measures the machine. The clock is moved several intervals forward, so an
    /// implementation that expired successes too would have many chances to re-ask.
    #[test]
    fn a_success_is_not_re_asked_when_the_memo_would_have_expired() {
        let keys = vec![key("cb")];
        let node = FakeNode::serving_watch(WatchReply::holding(&keys));
        let retry_after = Duration::from_secs(30);
        let clock = Arc::new(dig_account::FixedClock::new(NOW));
        let enrolment = KeyEnrolment::with_clock(
            Duration::from_secs(5),
            retry_after,
            fake_token,
            clock.clone(),
        );
        let link = connected_to(&node);

        assert_eq!(settle(&enrolment, &link, &keys), Enrolment::Registered);
        let after_first = node.request_count();

        for interval in 1..=5 {
            clock.set(NOW + retry_after.as_secs() * interval);
            settle_quietly(&enrolment, &link, &keys);
            assert_eq!(enrolment.observe(&link, &keys), Enrolment::Registered);
        }
        assert_eq!(
            node.request_count(),
            after_first,
            "an agreed node is not re-read on a timer"
        );
    }

    /// With no node there is nothing to ask, and nothing is claimed.
    #[test]
    fn a_disconnected_link_claims_nothing() {
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        assert_eq!(
            enrolment.observe(
                &EngineState::Disconnected {
                    reason: "no node".to_string()
                },
                &[key("a7")]
            ),
            Enrolment::Unasked
        );
    }

    /// A locked account derives no keys, and an empty enrolment is not a claim about the node.
    #[test]
    fn no_keys_means_nothing_was_asked() {
        let node = FakeNode::serving_watch(WatchReply::holding(&[]));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        assert_eq!(
            enrolment.observe(&connected_to(&node), &[]),
            Enrolment::Unasked
        );
        assert!(node.watch_requests().is_empty());
    }

    /// A REPLACED node is asked again rather than answered from the previous node's verdict.
    ///
    /// The second node is deliberately one that holds nothing, so a carried-forward `Registered`
    /// would be visibly wrong: it would claim enrolment on a node that had never heard of the key.
    #[test]
    fn a_different_node_is_asked_again() {
        let keys = vec![key("a8")];
        let first = FakeNode::serving_watch(WatchReply::holding(&keys));
        let enrolment =
            KeyEnrolment::with_token_reader(Duration::from_secs(5), NO_RETRY, fake_token);
        assert_eq!(
            settle(&enrolment, &connected_to(&first), &keys),
            Enrolment::Registered
        );

        let second = FakeNode::serving_watch(WatchReply::holding(&[]));
        settle(&enrolment, &connected_to(&second), &keys);
        assert_eq!(
            second.enrolled(),
            keys,
            "the new node was asked and enrolled, not assumed"
        );
    }
}
