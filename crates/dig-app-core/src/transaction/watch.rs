//! Tells the person when a chain write settles while nobody could be watching it happen live
//! (dig_ecosystem#3003).
//!
//! # The gap this closes
//!
//! [`Feed`] already keeps a settled write on screen once the app window is open — closing the
//! window loses nothing there, because the feed is a process-wide slot ([`Feed::app`]) that
//! outlives any one window and is read fresh every time one opens. What was missing is a signal
//! for the case the feed cannot cover on its own: the window is not open AT ALL when the write
//! finishes, so there is nothing anywhere for the person to see until they think to reopen it.
//! This module is that signal, raised the same way every other one-shot condition this app raises
//! is (dig-app#306/#305/#300): offer a [`crate::notify::Notification`] to the shared activity gate, which holds
//! it until somebody is actually at the machine.
//!
//! # Two decisions this ticket asked to be made explicitly, not left accidental
//!
//! * **Fires once per settled write.** A write settles and then sits on the feed — until the
//!   person dismisses it or starts a new one — so a check with no memory of what it has already
//!   reported would re-offer the SAME notification on every tray tick for as long as it stays
//!   there. And the gate's own [`crate::notify::gate::HoldPolicy::repeat_after`] must not
//!   be leaned on for this: that throttle exists for a condition that keeps being TRUE (a
//!   collateral shortfall re-read every poll), not for an event that happened exactly once —
//!   leaning on it would mean the toast can return, unprompted, an hour after the write settled.
//!   [`crate::transaction::watch::ChainWriteWatch`] keeps the one piece of memory this needs: the last write it has already
//!   reacted to, settled or otherwise handled.
//! * **Suppressed while the window is open.** The window already carries a live, honest status
//!   sheet for the write in progress, floated over every tab rather than tied to one — see
//!   `crate::confirm::gui::window::chain_status`. A native toast arriving beside it would tell the
//!   person nothing the sheet does not, while they are already looking at it. So a settled write
//!   observed with the window open is marked handled WITHOUT being offered — not merely delayed —
//!   because the person already had their chance to see it live; offering it later, once the
//!   window happens to close, would be the stale-repeat problem above wearing a different hat.
//!
//!   This is deliberately keyed on **the window**, not on [`crate::notify::presence::Presence`]:
//!   presence answers "is anybody at this machine at all", which is what the shared gate already
//!   uses to decide WHEN to release a held toast. It says nothing about whether THIS app happens
//!   to be the thing on screen, which is the question that decides whether a toast would be a
//!   duplicate. The two checks compose rather than overlap: this module decides whether to offer
//!   at all; the gate decides when an offered one is actually shown.
//!
//! # What it does not do
//!
//! It does not decide whether money moved — that is [`Stage::is_confirmed`]/[`Stage::detail`]'s
//! job — and this module quotes their words verbatim rather than composing a second,
//! independently-worded claim about the same chain state. And it persists nothing of its own: the
//! feed itself is process-wide and resets on restart, so there is nothing durable left to remember
//! across one.

use std::sync::Mutex;

#[cfg(test)]
use super::Stage;
use super::{Feed, Transaction};
use crate::notify::gate::HoldKey;
use crate::notify::Notification;

/// Watches the app's one chain-write feed and offers a notification the first time a write is
/// seen to have settled with no live window able to show it.
pub struct ChainWriteWatch {
    /// The last write this watcher has already reacted to, whether that reaction was "offered a
    /// notification" or "the window was open, so nothing was owed". `None` means the feed was
    /// last seen empty, or has never been observed — either way, the next settled write starts
    /// from a clean slate.
    last_reported: Mutex<Option<Transaction>>,
    /// Offers a notification to the gate, returning whether it was taken. Injected, like every
    /// other watch in this app, so a test can see WHAT was offered rather than only that nothing
    /// crashed.
    offer: fn(HoldKey, Notification) -> bool,
}

impl Default for ChainWriteWatch {
    fn default() -> Self {
        Self::new(crate::notify::shared::hold)
    }
}

impl ChainWriteWatch {
    /// A watch with its one seam stated.
    #[must_use]
    pub fn new(offer: fn(HoldKey, Notification) -> bool) -> Self {
        Self {
            last_reported: Mutex::new(None),
            offer,
        }
    }

    /// Look at `feed`'s current occupant and react if it just settled.
    ///
    /// `window_open` is a plain bool rather than an injected seam like `offer`: every production
    /// caller reads the exact same process-wide signal
    /// (`crate::confirm::consent_surface_is_up`), so there is nothing for a caller-supplied
    /// function to vary — a test simply states which answer it is exercising.
    ///
    /// **Never blocks.** A feed read is a mutex and a clone; both this call and `offer` are plain
    /// function calls with no I/O.
    pub fn observe(&self, feed: &Feed, window_open: bool) {
        let current = feed.read();
        let mut last = self.last_reported.lock().unwrap_or_else(|e| e.into_inner());
        react(current, &mut last, window_open, self.offer);
    }
}

/// The decision, as a pure function of what the feed holds now and what was last reported.
///
/// Separated from the locking so the property under test — react once per settled write, and only
/// while no window could already be showing it — is exercised directly rather than through a
/// mutex and a real gate.
fn react(
    current: Option<Transaction>,
    last_reported: &mut Option<Transaction>,
    window_open: bool,
    offer: fn(HoldKey, Notification) -> bool,
) {
    if current == *last_reported {
        return; // Nothing changed since the last tick — whether that is "still nothing in
                // flight" or "the same settled write we already reacted to".
    }
    let Some(transaction) = &current else {
        *last_reported = None; // The slot cleared. The next write starts from a clean slate.
        return;
    };
    if !transaction.is_settled() {
        return; // Still in flight (or mid-ceremony — a settled STAGE is not a settled write, see
                // `Transaction::is_settled`). `last_reported` is left as it was, so whichever
                // write settled before this one stays remembered until THIS one reaches an
                // outcome of its own.
    }
    if !window_open {
        offer(HoldKey::ChainWrite, notification_for(transaction));
    }
    // Marked handled either way: an open window means the person already had their chance to see
    // this live, and re-litigating that once the window later closes would be exactly the
    // stale-repeat problem the module docs describe.
    *last_reported = current;
}

/// The notification a settled write warrants, quoting the same words the in-window sheet would
/// have shown.
fn notification_for(transaction: &Transaction) -> Notification {
    Notification {
        title: format!("DIG — {}", transaction.stage.word()),
        body: format!("{}. {}", transaction.what, transaction.stage.detail()),
        // No destination: there is no tab that shows this specific write, and the corner sheet
        // this notification stands in for is drawn over every tab already (see
        // `crate::confirm::gui::window::chain_status`), so sending a click to one particular tab
        // would claim a relevance this notification does not have. Matches the funds-received
        // notification's own `route: None` for the same reason.
        route: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// What the last `react`/`observe` offered, so a `fn` pointer (which cannot capture) can still
    /// report back to the test that supplied it.
    fn offered() -> &'static Mutex<Vec<Notification>> {
        static OFFERED: OnceLock<Mutex<Vec<Notification>>> = OnceLock::new();
        OFFERED.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// The recorder is a `static`, so two cases writing to it at once would each see the other's
    /// offers. This serializes them, and each case clears it before running rather than depending
    /// on the order tests happen to run in.
    fn exclusively() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record(key: HoldKey, notification: Notification) -> bool {
        assert_eq!(
            key,
            HoldKey::ChainWrite,
            "this watch only ever raises its own key"
        );
        offered().lock().unwrap().push(notification);
        true
    }

    /// A ceremony's opening write: nothing built, nothing sent.
    fn starting() -> Transaction {
        Transaction::starting("Creating your profile", None)
    }

    /// A write that has reached its real, chain-observed end — the shape `Transaction::at`
    /// produces, which is the only shape `Transaction::is_settled` accepts as truly over.
    fn confirmed(made: &str) -> Transaction {
        starting().at(Stage::Confirmed {
            height: 9_154_458,
            made: made.to_string(),
        })
    }

    /// A write that stopped before it reached the chain.
    fn failed(why: &str, next: &str) -> Transaction {
        starting().at(Stage::Failed {
            why: why.to_string(),
            next: next.to_string(),
        })
    }

    /// The real shape a MID-ceremony confirmation takes: a genuine, chain-observed
    /// `Stage::Confirmed`, but `more_to_come` — the store has not launched yet. See
    /// `crate::account::creation_progress::of_step`'s own `DidConfirmed` arm, which this mirrors:
    /// the DID's confirmation is real and is still not the end.
    fn confirmed_mid_ceremony(made: &str) -> Transaction {
        starting().mid_ceremony(
            "Creating your profile — launching your store",
            Stage::Confirmed {
                height: 9_154_450,
                made: made.to_string(),
            },
        )
    }

    fn reset() {
        offered().lock().unwrap().clear();
    }

    /// **A settled write with no window open is reported, and reported exactly once.**
    ///
    /// The second `react` call passes the SAME transaction again — the shape of a later tray tick
    /// where nothing has changed — and is the fixture that catches a watch with no memory: one
    /// that re-derives "is this settled" from the feed alone would re-offer here, since the feed
    /// still holds the same confirmed write until it is dismissed.
    #[test]
    fn a_settled_write_with_no_window_open_is_reported_once() {
        let _exclusive = exclusively();
        reset();
        let mut last = None;
        let tx = confirmed("MARKER_MADE_TEXT");

        react(Some(tx.clone()), &mut last, false, record);
        let first = offered().lock().unwrap().clone();
        assert_eq!(
            first.len(),
            1,
            "a settled write with the window closed is reported"
        );
        assert_eq!(first[0].title, "DIG — Confirmed");
        assert!(
            first[0].body.contains("MARKER_MADE_TEXT"),
            "the body must quote the chain's own words, not invent a generic one: {}",
            first[0].body
        );

        react(Some(tx), &mut last, false, record);
        assert_eq!(
            offered().lock().unwrap().len(),
            1,
            "the same settled write observed again must not be reported twice"
        );
    }

    /// **A settled write is NOT reported while the window is open — and staying open does not
    /// later earn it a toast either.**
    ///
    /// The first call is the suppression itself: a watch that ignores `window_open` entirely would
    /// fail this half. The second call — the SAME write, window now closed — is what proves the
    /// write was marked handled rather than merely postponed: a watch that only checks
    /// `window_open` at the moment of the LATEST reading (rather than remembering it already
    /// decided) would wrongly fire here, the exact stale-repeat problem the module exists to avoid.
    #[test]
    fn a_settled_write_is_not_reported_while_the_window_is_open_and_closing_it_later_does_not_earn_a_toast(
    ) {
        let _exclusive = exclusively();
        reset();
        let mut last = None;
        let tx = confirmed("MARKER_MADE_TEXT");

        react(Some(tx.clone()), &mut last, true, record);
        assert_eq!(
            offered().lock().unwrap().len(),
            0,
            "the live in-window sheet already shows this; a toast beside it is noise"
        );

        react(Some(tx), &mut last, false, record);
        assert_eq!(
            offered().lock().unwrap().len(),
            0,
            "the person already saw this settle live; closing the window afterwards must not \
             raise it a beat late"
        );
    }

    /// **An in-flight write is never reported, including the pushed-but-unconfirmed stage.**
    #[test]
    fn a_write_still_in_flight_is_not_reported() {
        let _exclusive = exclusively();
        reset();
        let mut last = None;
        let pushed = starting().mid_ceremony(
            "Creating your profile",
            Stage::Pushed {
                id: "Identity coin 0xabc".to_string(),
            },
        );

        react(Some(pushed), &mut last, false, record);
        assert_eq!(offered().lock().unwrap().len(), 0);
    }

    /// **A settled STAGE mid-ceremony is not a settled write.**
    ///
    /// `DidConfirmed` is a real, chain-observed `Stage::Confirmed` — `Stage::is_confirmed` is
    /// `true` for it — with the store launch still to come. A watch that asked `stage.is_settled()`
    /// instead of `Transaction::is_settled()` would fire here, announcing a ceremony as done while
    /// it is still spending: the exact money-lie class `Transaction::more_to_come` exists to make
    /// unrepresentable one level up.
    #[test]
    fn a_real_but_mid_ceremony_confirmation_is_not_reported() {
        let _exclusive = exclusively();
        reset();
        let mut last = None;
        let tx = confirmed_mid_ceremony("MARKER_DID_CONFIRMED");
        assert!(
            tx.stage.is_confirmed(),
            "the stage really is a chain-observed confirmation"
        );
        assert!(
            !tx.is_settled(),
            "but the ceremony is not over — more is coming"
        );

        react(Some(tx), &mut last, false, record);
        assert_eq!(
            offered().lock().unwrap().len(),
            0,
            "a mid-ceremony confirmation must not be announced as the write's outcome"
        );
    }

    /// **A stopped write is reported as stopped, never as confirmed.**
    #[test]
    fn a_failed_write_is_reported_as_stopped() {
        let _exclusive = exclusively();
        reset();
        let mut last = None;
        let tx = failed("MARKER_WHY_TEXT", "MARKER_NEXT_TEXT");

        react(Some(tx), &mut last, false, record);
        let offers = offered().lock().unwrap().clone();
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].title, "DIG — Stopped");
        assert!(!offers[0].title.contains("Confirmed"));
        assert!(offers[0].body.contains("MARKER_WHY_TEXT"));
        assert!(offers[0].body.contains("MARKER_NEXT_TEXT"));
    }

    /// **Once the feed clears, a NEW settled write is reported again.**
    ///
    /// Distinguishes real per-write memory from a global "have I ever notified" latch: a watch that
    /// only ever fires once for the life of the process would pass every test above and still fail
    /// this one, because the second profile creation in the same session would go unannounced.
    #[test]
    fn a_new_settled_write_after_the_feed_clears_is_reported_again() {
        let _exclusive = exclusively();
        reset();
        let mut last = None;

        react(
            Some(confirmed("MARKER_FIRST_WRITE")),
            &mut last,
            false,
            record,
        );
        assert_eq!(offered().lock().unwrap().len(), 1);

        react(None, &mut last, false, record); // Dismissed / the slot cleared.
        assert_eq!(
            offered().lock().unwrap().len(),
            1,
            "clearing the feed itself reports nothing new"
        );

        react(
            Some(confirmed("MARKER_SECOND_WRITE")),
            &mut last,
            false,
            record,
        );
        let offers = offered().lock().unwrap().clone();
        assert_eq!(
            offers.len(),
            2,
            "a later, different settled write is reported on its own"
        );
        assert!(offers[1].body.contains("MARKER_SECOND_WRITE"));
    }

    /// **The watch itself — not just the pure decision function — reaches the gate through a real
    /// feed.** Proves `ChainWriteWatch::observe` wires `Feed::read` and its own mutex correctly,
    /// which the `react`-level tests above cannot see because they never touch either.
    #[test]
    fn the_watch_reports_a_real_feeds_settled_write_through_its_own_state() {
        let _exclusive = exclusively();
        reset();
        let feed = Feed::detached();
        let writing = feed
            .begin(starting())
            .expect("an empty feed always accepts a claim");
        writing.publish(confirmed("MARKER_REAL_FEED"));

        let watch = ChainWriteWatch::new(record);
        watch.observe(&feed, false);
        let offers = offered().lock().unwrap().clone();
        assert_eq!(offers.len(), 1);
        assert!(offers[0].body.contains("MARKER_REAL_FEED"));

        // The same settled write, still sitting on the feed on the next tick: not reported again.
        watch.observe(&feed, false);
        assert_eq!(offered().lock().unwrap().len(), 1);
    }
}
