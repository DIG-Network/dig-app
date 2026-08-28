//! The activity gate (dig-app#312): hold a notification until the person is there.
//!
//! **User directive, 2026-08-28, verbatim:** *"we want the notification to appear when activity is
//! detected on the computer, not in the middle of the night"*.
//!
//! # Presence, not a clock
//!
//! The obvious implementation of that sentence is quiet hours — suppress between 23:00 and 08:00 —
//! and it is the wrong one. The signal asked for is **the person being present**, which is a
//! different question from what time it is: a night-shift operator is awake at 03:00 and a laptop
//! shut in a bag is idle at 14:00. So nothing here reads a wall clock or a calendar. The gate holds
//! until something OBSERVES input ([`crate::notify::presence`]) and releases then.
//!
//! The two clocks are also deliberately different. Expiry and the "when was this detected" phrase
//! both run on [`std::time::Instant`] — monotonic, unaffected by a clock change or a suspend/resume skew — so
//! a notification cannot be aged out by the system clock being corrected while the machine slept.
//!
//! # One mechanism, three callers
//!
//! [`HoldKey`] names the three conditions that will use it (#306, #305, #300). **The caller supplies
//! the content and the urgency; the gate owns the timing** — otherwise each grows its own rule and
//! the three disagree about what quiet means, which is the defect this module was written to
//! prevent.
//!
//! It answers **when**, never **whether**. A condition that must not notify at all must not be
//! handed to it: #306's `below_recommended_buffer` is a readout, `runway::notification` returns
//! `None` for it, and that decision belongs to the caller. Nothing in this module inspects a
//! condition to decide whether it deserves a toast — by the time something reaches [`ActivityGate`],
//! that question has already been answered.
//!
//! # The queue cannot grow
//!
//! Not "is trimmed" — **cannot**. [`HoldKey`] is a closed enum and the held set is keyed on it, so a
//! machine nobody touches for a year holds at most one entry per key: three, forever, by
//! construction. Re-holding a key that is already held REPLACES its content and KEEPS its original
//! detection instant, because the condition was detected then and the toast has to say so.
//!
//! The second bound is [`HoldPolicy::max_hold`]: an entry older than that is **dropped**, not
//! delivered late. A week-old *"a new version was installed"* is not worth interrupting anybody
//! with, and delivering it on the next mouse move would be the 03:00 toast wearing a different hat.
//!
//! # Say when it was DETECTED
//!
//! The released copy carries [`elapsed_phrase`](crate::notify::gate::elapsed_phrase) for every entry, so a Monday-morning toast about a
//! Saturday install says *"2 days ago"* rather than implying it happened just now. That is the
//! money-lie rule applied to time: a surface must not assert something the system did not observe.
//!
//! # Released once
//!
//! A release CLEARS the held set, so the same notification never re-arrives on the next activity
//! resumption. A caller that re-raises a persisting condition is separately suppressed for
//! [`HoldPolicy::repeat_after`] — the collateral shortfall is re-read every poll and would otherwise
//! toast on every one of them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::presence::Presence;
use super::{Notification, Route};

/// Which condition a held notification is about.
///
/// A closed enum rather than a string: it is what bounds the queue (see the module docs), and it
/// makes "the same condition raised twice" a key collision rather than two entries that a reader
/// has to notice are duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoldKey {
    /// The node is short of $DIG for collateral (dig-app#306).
    Collateral,
    /// A new version of dig-app was installed (dig-app#305).
    Installed,
    /// An automated spend could not be made for want of funds (dig-app#300).
    OutOfFunds,
}

/// How long a notification may wait, and how soon the same condition may speak again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldPolicy {
    /// The longest a notification may be held before it is dropped unshown.
    ///
    /// Dropped rather than delivered: see the module docs. Twelve hours covers an overnight idle —
    /// the case this whole mechanism exists for — without carrying yesterday's news into tomorrow.
    pub max_hold: Duration,
    /// The shortest gap between two deliveries about the SAME key.
    ///
    /// A persisting condition (a shortfall that is still a shortfall) is re-raised by its caller on
    /// every poll. Without this the gate would deliver on every poll where the person is present,
    /// which is the recurring, ignorable alert that teaches people to dismiss the urgent ones.
    pub repeat_after: Duration,
}

impl Default for HoldPolicy {
    fn default() -> Self {
        Self {
            max_hold: Duration::from_secs(12 * 60 * 60),
            repeat_after: Duration::from_secs(60 * 60),
        }
    }
}

/// One notification waiting for its person.
#[derive(Debug, Clone)]
struct Held {
    notification: Notification,
    /// When the CONDITION was observed — never when the toast was drawn. Preserved across a
    /// re-hold of the same key, which is what makes the released copy's age honest.
    detected: Instant,
}

/// Holds notifications until activity is detected, then releases them coalesced, exactly once.
///
/// Pure and clock-injected: every entry point takes `now`, so the tests below pin an explicit
/// timeline rather than sleeping. Drive it with [`hold`](Self::hold) from any number of callers and
/// [`poll`](Self::poll) from one place.
#[derive(Debug)]
pub struct ActivityGate {
    held: BTreeMap<HoldKey, Held>,
    /// When each key last DELIVERED, for the repeat suppression. Bounded by `HoldKey` like `held`.
    last_released: BTreeMap<HoldKey, Instant>,
    policy: HoldPolicy,
}

impl Default for ActivityGate {
    fn default() -> Self {
        Self::new(HoldPolicy::default())
    }
}

impl ActivityGate {
    /// A gate governed by `policy`.
    #[must_use]
    pub fn new(policy: HoldPolicy) -> Self {
        Self {
            held: BTreeMap::new(),
            last_released: BTreeMap::new(),
            policy,
        }
    }

    /// Offer a notification for `key`, detected at `now`.
    ///
    /// Returns whether it was taken. It is REFUSED — silently, and that is the normal case — when
    /// the same key delivered less than [`HoldPolicy::repeat_after`] ago, so a condition re-read on
    /// a thirty-second poller does not become a toast every thirty seconds.
    ///
    /// Re-holding a key already held replaces the copy (the amount to add may have moved) but keeps
    /// the FIRST detection instant, because that is when the condition arose.
    pub fn hold(&mut self, now: Instant, key: HoldKey, notification: Notification) -> bool {
        if let Some(released) = self.last_released.get(&key) {
            if now.duration_since(*released) < self.policy.repeat_after {
                return false;
            }
        }
        match self.held.get_mut(&key) {
            Some(existing) => existing.notification = notification,
            None => {
                self.held.insert(
                    key,
                    Held {
                        notification,
                        detected: now,
                    },
                );
            }
        }
        true
    }

    /// Whether anything is waiting. Exposed for the drivers' logging and for the tests' bounds.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Age out anything held too long, and release the rest if the person is here.
    ///
    /// Returns the ONE coalesced notification to show, or `None`. Call it on whatever cadence the
    /// host already has; it does no I/O and never blocks.
    ///
    /// - [`Presence::Present`] — release everything still fresh, as one notification, and clear.
    /// - [`Presence::Away`] — keep holding (expiry still runs; a machine idle past `max_hold`
    ///   discards rather than accumulates).
    /// - [`Presence::Unobservable`] — the same as away, forever. On a host where input cannot be
    ///   seen at all (a headless server, a Wayland session) the entries expire unshown and nothing
    ///   is retried. That is the supported outcome, not an error: see [`Presence`].
    pub fn poll(&mut self, now: Instant, presence: Presence) -> Option<Notification> {
        let max_hold = self.policy.max_hold;
        self.held
            .retain(|_, held| now.duration_since(held.detected) <= max_hold);

        if presence != Presence::Present || self.held.is_empty() {
            return None;
        }

        let released = std::mem::take(&mut self.held);
        for key in released.keys() {
            self.last_released.insert(*key, now);
        }
        Some(coalesce(now, &released))
    }
}

/// Fold every released entry into one notification.
///
/// One entry keeps its own copy verbatim, with its age appended — a single condition should read
/// exactly as its author wrote it. Several become a roll-up that NAMES each, because four toasts
/// arriving the instant the mouse moves is the behaviour this gate exists to prevent.
fn coalesce(now: Instant, released: &BTreeMap<HoldKey, Held>) -> Notification {
    let mut entries = released.values();
    let first = entries.next().expect("a release is never empty");
    if released.len() == 1 {
        return Notification {
            title: first.notification.title.clone(),
            body: format!(
                "{} (detected {})",
                first.notification.body,
                elapsed_phrase(now.duration_since(first.detected))
            ),
            route: first.notification.route,
        };
    }

    let lines = released
        .values()
        .map(|held| {
            format!(
                "• {} — detected {}",
                held.notification.title,
                elapsed_phrase(now.duration_since(held.detected))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Notification {
        title: format!("DIG — {} things need your attention", released.len()),
        body: lines,
        route: shared_route(released),
    }
}

/// The route for a roll-up: the one every entry agrees on, or `None`.
///
/// A click can only land in one place, and sending a person to the deposit screen for a roll-up
/// that was half about an install is worse than sending them nowhere — they arrive somewhere that
/// does not explain why the toast appeared.
fn shared_route(released: &BTreeMap<HoldKey, Held>) -> Option<Route> {
    let mut routes = released.values().map(|held| held.notification.route);
    let first = routes.next().flatten()?;
    routes.all(|route| route == Some(first)).then_some(first)
}

/// How long ago something happened, in words, from a monotonic elapsed time.
///
/// Deliberately relative rather than a weekday or a timestamp: it is a pure function of a
/// [`Duration`], so it needs no wall clock, no calendar dependency and no timezone — and it cannot
/// disagree with the monotonic clock the expiry bound uses. Coarse on purpose; the person needs to
/// know whether this is news or history, not the minute.
#[must_use]
pub fn elapsed_phrase(elapsed: Duration) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    let secs = elapsed.as_secs();
    match secs {
        s if s < 2 * MINUTE => "just now".to_string(),
        s if s < HOUR => format!("{} minutes ago", s / MINUTE),
        s if s < 2 * HOUR => "an hour ago".to_string(),
        s if s < DAY => format!("{} hours ago", s / HOUR),
        s if s < 2 * DAY => "yesterday".to_string(),
        s => format!("{} days ago", s / DAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed origin every case measures from, so no test depends on how long it took to run.
    fn origin() -> Instant {
        Instant::now()
    }

    fn note(title: &str, route: Option<Route>) -> Notification {
        Notification {
            title: title.to_string(),
            body: format!("body of {title}"),
            route,
        }
    }

    fn policy() -> HoldPolicy {
        HoldPolicy {
            max_hold: Duration::from_secs(3600),
            repeat_after: Duration::from_secs(600),
        }
    }

    /// **Held while away, released on activity — and the away leg is a real control.**
    ///
    /// The away poll happens at a time when the entry is comfortably inside `max_hold`, so its
    /// silence can only be explained by the presence verdict. A fixture where the entry had already
    /// expired would pass against an implementation that ignored presence entirely.
    #[test]
    fn a_notification_waits_for_activity_and_then_arrives() {
        let t0 = origin();
        let mut gate = ActivityGate::new(policy());
        assert!(gate.hold(t0, HoldKey::Collateral, note("Add $DIG", None)));

        let overnight = t0 + Duration::from_secs(1800);
        assert_eq!(
            gate.poll(overnight, Presence::Away),
            None,
            "nobody is there"
        );
        assert!(!gate.is_empty(), "and it is still waiting, not discarded");

        let toast = gate
            .poll(overnight, Presence::Present)
            .expect("the person arrived");
        assert_eq!(toast.title, "Add $DIG");
    }

    /// **A release happens ONCE.**
    ///
    /// The second present poll is the assertion; the third — after a fresh, permitted hold — is the
    /// control that stops "always `None` after the first" from passing. Without it an
    /// implementation that simply refused to deliver twice ever would be indistinguishable.
    #[test]
    fn a_held_notification_is_released_once_and_a_later_one_still_arrives() {
        let t0 = origin();
        let mut gate = ActivityGate::new(policy());
        gate.hold(t0, HoldKey::Collateral, note("Add $DIG", None));

        assert!(gate.poll(t0, Presence::Present).is_some());
        assert_eq!(
            gate.poll(t0 + Duration::from_secs(1), Presence::Present),
            None,
            "activity resuming again must not re-deliver it"
        );

        let later = t0 + Duration::from_secs(700); // past repeat_after
        assert!(gate.hold(later, HoldKey::Collateral, note("Add $DIG", None)));
        assert!(
            gate.poll(later, Presence::Present).is_some(),
            "a genuinely new raise still speaks"
        );
    }

    /// **A condition re-raised on every poll speaks at most once per `repeat_after`.**
    ///
    /// This is the shape a real caller has: the collateral reading is re-read on a poller and the
    /// shortfall is still a shortfall, so `hold` is called again and again.
    #[test]
    fn a_persisting_condition_does_not_toast_on_every_poll() {
        let t0 = origin();
        let mut gate = ActivityGate::new(policy());
        gate.hold(t0, HoldKey::Collateral, note("Add $DIG", None));
        assert!(gate.poll(t0, Presence::Present).is_some());

        for tick in 1..20 {
            let now = t0 + Duration::from_secs(tick * 30);
            assert!(
                !gate.hold(now, HoldKey::Collateral, note("Add $DIG", None)),
                "the re-raise at {tick} must be refused"
            );
            assert_eq!(gate.poll(now, Presence::Present), None);
        }
    }

    /// **Several conditions arrive as ONE notification that names each, with each one's own age.**
    ///
    /// The two entries are detected 90 minutes apart and their `max_hold` is longer than that, so a
    /// correct roll-up must carry two DIFFERENT age phrases. An implementation that stamped the
    /// release time on both — the nearest wrong one, and the one that quietly turns a Saturday
    /// install into a Monday event — produces the same phrase twice and fails here.
    #[test]
    fn several_conditions_coalesce_into_one_toast_naming_each_and_its_own_age() {
        let t0 = origin();
        let mut gate = ActivityGate::new(HoldPolicy {
            max_hold: Duration::from_secs(12 * 3600),
            repeat_after: Duration::from_secs(600),
        });
        gate.hold(t0, HoldKey::Installed, note("Updated to 12.41.0", None));
        gate.hold(
            t0 + Duration::from_secs(90 * 60),
            HoldKey::Collateral,
            note("Add $DIG", Some(Route::Deposit)),
        );

        let now = t0 + Duration::from_secs(150 * 60);
        let toast = gate.poll(now, Presence::Present).expect("both release");

        assert!(toast.title.contains('2'), "{}", toast.title);
        assert!(toast.body.contains("Updated to 12.41.0"), "{}", toast.body);
        assert!(toast.body.contains("Add $DIG"), "{}", toast.body);
        assert!(
            toast.body.contains("2 hours ago") && toast.body.contains("an hour ago"),
            "each entry must carry its OWN detection age, not the release time: {}",
            toast.body
        );
        assert_eq!(
            toast.route, None,
            "one entry routes to deposit and the other nowhere; a click cannot honour both"
        );
    }

    /// **A roll-up keeps a route only when every entry agrees on it.**
    ///
    /// The control for the disagreement assertion above: without this, `route: None` unconditionally
    /// would pass that test.
    #[test]
    fn a_rollup_keeps_the_route_every_entry_shares() {
        let t0 = origin();
        let mut gate = ActivityGate::new(policy());
        gate.hold(
            t0,
            HoldKey::Collateral,
            note("Add $DIG", Some(Route::Deposit)),
        );
        gate.hold(
            t0,
            HoldKey::OutOfFunds,
            note("A spend was skipped", Some(Route::Deposit)),
        );
        let toast = gate.poll(t0, Presence::Present).expect("both release");
        assert_eq!(toast.route, Some(Route::Deposit));
    }

    /// **The hold is bounded, and the bound is pinned from BOTH sides.**
    ///
    /// At exactly `max_hold` it still delivers; one second over it is gone and the queue is empty.
    /// A bound tested only from above would be satisfied by a gate that dropped everything.
    #[test]
    fn the_hold_expires_just_over_the_bound_and_survives_at_it() {
        let t0 = origin();
        let max = policy().max_hold;

        let mut at_bound = ActivityGate::new(policy());
        at_bound.hold(t0, HoldKey::Installed, note("Updated", None));
        assert!(
            at_bound.poll(t0 + max, Presence::Present).is_some(),
            "at the bound it is still worth delivering"
        );

        let mut over_bound = ActivityGate::new(policy());
        over_bound.hold(t0, HoldKey::Installed, note("Updated", None));
        let over = t0 + max + Duration::from_secs(1);
        assert_eq!(over_bound.poll(over, Presence::Present), None);
        assert!(over_bound.is_empty(), "dropped, never delivered late");
    }

    /// **An unobservable host holds, never delivers, and never accumulates.**
    ///
    /// Two properties in one timeline: nothing is shown across a long run of polls, and the queue is
    /// empty at the end because expiry ran anyway. The later `Present` poll returning `None` is what
    /// separates "held forever" (a leak) from "expired" (the intended outcome).
    #[test]
    fn an_unobservable_host_stays_silent_and_ends_with_an_empty_queue() {
        let t0 = origin();
        let mut gate = ActivityGate::new(policy());
        gate.hold(t0, HoldKey::Collateral, note("Add $DIG", None));

        for tick in 1..=10u64 {
            let now = t0 + Duration::from_secs(tick * 600);
            assert_eq!(
                gate.poll(now, Presence::Unobservable),
                None,
                "silent at tick {tick}"
            );
        }
        assert!(gate.is_empty(), "expired rather than queued forever");
        assert_eq!(
            gate.poll(t0 + Duration::from_secs(6000), Presence::Present),
            None,
            "and there is nothing left to deliver late"
        );
    }

    /// **Re-holding a key keeps the ORIGINAL detection instant while taking the new copy.**
    ///
    /// The amount to add moves between polls; when the condition arose does not. Both halves are
    /// asserted, because an implementation that replaced the whole entry passes a copy-only check.
    #[test]
    fn a_rehold_updates_the_copy_but_not_when_the_condition_arose() {
        let t0 = origin();
        let mut gate = ActivityGate::new(HoldPolicy {
            max_hold: Duration::from_secs(12 * 3600),
            repeat_after: Duration::from_secs(600),
        });
        gate.hold(t0, HoldKey::Collateral, note("Add 12 $DIG", None));
        gate.hold(
            t0 + Duration::from_secs(3 * 3600),
            HoldKey::Collateral,
            note("Add 31 $DIG", None),
        );

        let toast = gate
            .poll(t0 + Duration::from_secs(4 * 3600), Presence::Present)
            .expect("released");
        assert_eq!(toast.title, "Add 31 $DIG", "the newest figure wins");
        assert!(
            toast.body.contains("4 hours ago"),
            "the age must date from the FIRST detection, not the last re-raise: {}",
            toast.body
        );
    }

    /// **The queue cannot exceed the number of distinct conditions.**
    ///
    /// A thousand raises across all three keys leave three entries and release one toast.
    #[test]
    fn the_queue_is_bounded_by_the_number_of_keys() {
        let t0 = origin();
        let mut gate = ActivityGate::new(HoldPolicy {
            max_hold: Duration::from_secs(12 * 3600),
            repeat_after: Duration::from_secs(600),
        });
        for i in 0..1000u64 {
            let key = match i % 3 {
                0 => HoldKey::Collateral,
                1 => HoldKey::Installed,
                _ => HoldKey::OutOfFunds,
            };
            gate.hold(t0 + Duration::from_secs(i), key, note("something", None));
        }
        let toast = gate
            .poll(t0 + Duration::from_secs(1000), Presence::Present)
            .expect("released");
        assert!(
            toast.title.contains('3'),
            "three conditions, not a thousand: {}",
            toast.title
        );
        assert!(gate.is_empty());
    }

    #[test]
    fn the_age_phrase_reads_naturally_at_each_scale() {
        let cases = [
            (0, "just now"),
            (119, "just now"),
            (120, "2 minutes ago"),
            (3599, "59 minutes ago"),
            (3600, "an hour ago"),
            (7200, "2 hours ago"),
            (86_399, "23 hours ago"),
            (86_400, "yesterday"),
            (172_800, "2 days ago"),
        ];
        for (secs, expected) in cases {
            assert_eq!(
                elapsed_phrase(Duration::from_secs(secs)),
                expected,
                "{secs}s"
            );
        }
    }
}
