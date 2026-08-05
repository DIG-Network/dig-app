//! The one-way seam between the thread that decides what the tray should say and the thread that
//! draws it.
//!
//! # Why there is a seam at all
//!
//! `tray-icon` draws its context menu with `TrackPopupMenu`, a nested modal message loop that runs
//! inside the tray window proc. While a menu is up that loop owns its thread completely — measured
//! on dig-app#86: nothing else on that thread runs, at all, for as long as the menu is open. When
//! the tray shared a thread with the app's tick, a menu that would not dismiss was therefore not a
//! stuck menu but a stuck *application*: no clipboard timeout, no idle auto-lock, no status poll, no
//! diagnostics, permanently and in silence.
//!
//! The tray's own handle cannot move to fix that. `tray_icon::TrayIcon` is an
//! `Rc<RefCell<platform_impl::TrayIcon>>` (`tray-icon-0.23.1/src/lib.rs:346`) and the crate declares
//! no `unsafe impl Send` for it — the only one it has is for `WinIcon`
//! (`platform_impl/windows/icon.rs:67`). So `set_icon`, `set_tooltip` and `set_menu` are pinned to
//! the thread that created the tray, forever.
//!
//! What CAN cross a thread is the *description* of what to draw. So the handle stays where it is,
//! the work moves, and this module is the crossing: **data goes over, handles never do.**
//!
//! # Why a latch and not a queue
//!
//! A wedged menu means paints pile up. Queueing them would have the renderer, on the menu finally
//! closing, redraw every intermediate state the app passed through — none of which anybody can see,
//! and the last of which is the only one that is true. So [`Latest`] holds exactly one value and a
//! second put REPLACES it. The producer is a twice-a-second poll of a display model; older values
//! are not history, they are noise.
//!
//! # The property this exists to guarantee
//!
//! [`TrayLink::paint`] **never waits for the renderer.** Not "usually does not" — the lock it takes
//! is held for a pointer move and is never held across a draw, so the tick's cost is the same
//! whether the renderer is idle or three minutes into a wedged menu. That is the whole of what makes
//! the tray unable to stall the app, and it is what
//! `tests::a_wedged_renderer_does_not_stall_the_producer` measures.

use std::sync::{Arc, Mutex, MutexGuard};

/// A one-slot mailbox holding the most recent value that has not been collected yet.
///
/// Both operations are O(1) under a lock that is never held across anything slower than a move, so
/// neither side can delay the other. See the module docs for why replacing beats queueing.
#[derive(Debug, Default)]
pub struct Latest<T> {
    slot: Mutex<Option<T>>,
}

impl<T> Latest<T> {
    /// An empty mailbox.
    pub fn empty() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// Leave `value` for the collector, replacing anything it has not taken yet.
    ///
    /// Returns whether the mailbox had been EMPTY, which is how the caller knows a wake is needed:
    /// a collector that has not yet taken the previous value is already on its way and does not need
    /// telling twice. Without this, a renderer wedged behind an open menu would accumulate one wake
    /// per tick for as long as the menu stayed up.
    pub fn put(&self, value: T) -> bool {
        let mut slot = self.hold();
        slot.replace(value).is_none()
    }

    /// Take whatever is waiting, leaving the mailbox empty.
    ///
    /// The value is moved OUT before the caller does anything with it, which is what keeps the lock
    /// free while a draw is in progress.
    pub fn take(&self) -> Option<T> {
        self.hold().take()
    }

    /// Lock the slot, recovering rather than propagating a poisoning.
    ///
    /// A poisoned slot means one side panicked while holding it — during a pointer move, so the slot
    /// is either the old value or the new one and both are coherent. Refusing every later paint over
    /// that would leave the user a tray frozen on whatever it last drew, which is a far worse answer
    /// than carrying on.
    fn hold(&self) -> MutexGuard<'_, Option<T>> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The producer's end: hand over what the tray should show, and never wait for it to be shown.
///
/// Cloneable so more than one place can paint, though today only the tick does.
pub struct TrayLink<T> {
    pending: Arc<Latest<T>>,
    /// Nudges the renderer's event loop. In production this is a `tao::EventLoopProxy::send_event`,
    /// which is itself non-blocking (an unbounded send followed by a `PostMessage`); it is a closure
    /// rather than the proxy so this module owes nothing to a windowing library and can be tested
    /// without one.
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl<T> Clone for TrayLink<T> {
    fn clone(&self) -> Self {
        Self {
            pending: Arc::clone(&self.pending),
            wake: Arc::clone(&self.wake),
        }
    }
}

impl<T> std::fmt::Debug for TrayLink<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrayLink").finish_non_exhaustive()
    }
}

impl<T> TrayLink<T> {
    /// Wire a producer to `pending`, waking the renderer with `wake` when a fresh value arrives.
    pub fn new(pending: Arc<Latest<T>>, wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            pending,
            wake: Arc::new(wake),
        }
    }

    /// Say what the tray should show now.
    ///
    /// Returns immediately whatever the renderer is doing — see the module docs. The wake is skipped
    /// when a previous value is still uncollected, because the renderer is already coming back.
    pub fn paint(&self, value: T) {
        if self.pending.put(value) {
            (self.wake)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    /// The mailbox keeps the newest value and nothing else.
    ///
    /// The nearest wrong implementation is a queue, and this is the input that tells them apart:
    /// three puts and one take. A queue answers `1` — the state the app was in a second and a half
    /// ago — and then has two more stale redraws waiting behind it.
    #[test]
    fn a_second_value_replaces_the_first_rather_than_queueing_behind_it() {
        let latest = Latest::empty();
        latest.put(1);
        latest.put(2);
        latest.put(3);

        assert_eq!(
            latest.take(),
            Some(3),
            "the collector must see the CURRENT state; a queue would hand it the oldest"
        );
        assert_eq!(
            latest.take(),
            None,
            "and nothing stale behind it — a queue would have two more redraws to do"
        );
    }

    /// A put reports whether a wake is owed, so a wedged renderer is nudged once and not per tick.
    #[test]
    fn only_the_put_that_finds_an_empty_mailbox_asks_for_a_wake() {
        let latest = Latest::empty();

        assert!(
            latest.put(1),
            "the first value must wake a resting renderer"
        );
        assert!(
            !latest.put(2),
            "the renderer has not collected yet, so it is already on its way; waking again per \
             tick is what fills its event queue while a menu is open"
        );
        assert_eq!(latest.take(), Some(2));
        assert!(
            latest.put(3),
            "once collected, the renderer is resting again and the next value must wake it"
        );
    }

    /// **A renderer stuck in a modal menu does not stop the producer.**
    ///
    /// This is the acceptance test for dig-app#90 — the one the previous shape could not pass. Under
    /// that shape the producer and the renderer were the same thread, so a menu that would not
    /// dismiss stopped the tick, and with it the clipboard timeout, the idle auto-lock and every
    /// diagnostic the app had.
    ///
    /// # What the fixture is careful about
    ///
    /// **It asserts on the producer ADVANCING, never on a call returning `Ok`.** An enqueue that
    /// succeeded proves nothing about whether anything moved — that mistake is exactly what let the
    /// old `break_modal_menu` log a rescue it had not performed.
    ///
    /// **The renderer is genuinely wedged, mid-collection.** It takes one paint and then blocks
    /// holding no lock and answering nothing, which is what `TrackPopupMenu` does to its thread. A
    /// fixture whose renderer merely ran slowly would pass against a rendezvous channel too.
    ///
    /// **The wait is BOUNDED, sampled from a third thread, and the fixture can always UNWIND.** This
    /// is the part that had to be fixed after it bit: the neighbouring wrong implementation — a
    /// rendezvous, or a lock held across the draw — does not fail a careless version of this test, it
    /// HANGS on it, and a test that hangs names nothing.
    ///
    /// Two separate things are needed for that, and having only the first is not enough. The count is
    /// SAMPLED at the deadline, before anything is released, so the verdict is about the wedged
    /// period. And then the renderer is not merely un-wedged but made to DRAIN until the producer
    /// finishes: a rendezvous producer is blocked on a full slot, and a renderer that wakes up and
    /// returns leaves it blocked forever. Releasing without draining hangs on `join`, which is how
    /// the first version of this fixture spent twenty minutes proving nothing.
    #[test]
    fn a_wedged_renderer_does_not_stall_the_producer() {
        /// How many ticks the producer must get through while the menu is up. At the shipped 500 ms
        /// refresh this is thirty seconds of app life — well past the point a user notices a frozen
        /// tray, and far more than one, which a single-shot buffer would also satisfy.
        const TICKS: u32 = 60;

        let pending = Arc::new(Latest::<u32>::empty());
        let ticks_done = Arc::new(AtomicU32::new(0));
        let menu_is_open = Arc::new(AtomicBool::new(true));
        let renderer_collected = Arc::new(AtomicBool::new(false));
        let producer_finished = Arc::new(AtomicBool::new(false));
        // The newest frame the renderer ever actually collected. Read instead of the mailbox
        // itself, because the drain below empties it.
        let last_collected = Arc::new(AtomicU32::new(0));

        let renderer = {
            let pending = Arc::clone(&pending);
            let menu_is_open = Arc::clone(&menu_is_open);
            let collected = Arc::clone(&renderer_collected);
            let producer_finished = Arc::clone(&producer_finished);
            let last_collected = Arc::clone(&last_collected);
            std::thread::spawn(move || {
                // One ordinary paint, so the renderer is proven live before it wedges — a renderer
                // that never worked would pass a test that only checks the producer.
                while pending.take().is_none() {
                    std::thread::yield_now();
                }
                collected.store(true, Ordering::SeqCst);
                // And now the menu is up and this thread does nothing at all.
                while menu_is_open.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                // The menu closed. Keep collecting until the producer is done, so a producer that
                // this fixture has WEDGED can always finish and be joined. See the doc above.
                let collect = || {
                    if let Some(frame) = pending.take() {
                        last_collected.store(frame, Ordering::SeqCst);
                    }
                };
                while !producer_finished.load(Ordering::SeqCst) {
                    collect();
                    std::thread::yield_now();
                }
                // Once more after the flag, for the frame that may have landed between the last
                // collect and the store. Without it the final assertion is a race the fixture wins
                // most of the time, which is the worst kind.
                collect();
            })
        };

        let link = TrayLink::new(Arc::clone(&pending), || {});
        link.paint(0);
        while !renderer_collected.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        let producer = {
            let ticks_done = Arc::clone(&ticks_done);
            let producer_finished = Arc::clone(&producer_finished);
            std::thread::spawn(move || {
                for tick in 1..=TICKS {
                    link.paint(tick);
                    ticks_done.fetch_add(1, Ordering::SeqCst);
                }
                producer_finished.store(true, Ordering::SeqCst);
            })
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        while ticks_done.load(Ordering::SeqCst) < TICKS && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        // Sampled while the menu is still open: the verdict is about the WEDGED period, so it has to
        // be read before anything below unwinds the fixture.
        let advanced = ticks_done.load(Ordering::SeqCst);

        menu_is_open.store(false, Ordering::SeqCst);
        producer.join().expect("the producer thread");
        renderer.join().expect("the renderer thread");

        assert_eq!(
            advanced, TICKS,
            "the tick must keep advancing for the whole time a tray menu is open; it got {advanced} \
             of {TICKS} before the deadline, which is the app-wide stall dig-app#86 reported"
        );
        assert_eq!(
            last_collected.load(Ordering::SeqCst),
            TICKS,
            "and when the menu finally closes the renderer must reach the CURRENT state, not \
             stop at the first frame it missed"
        );
    }

    /// The producer is not delayed by the renderer holding the mailbox either.
    ///
    /// Distinct from the test above, which wedges a renderer that has already let go. This one is
    /// the other neighbouring mistake: a collector that takes the lock and keeps it for the draw.
    /// The assertion is on the producer's own elapsed time, because that is the quantity a user
    /// feels — a tick that takes as long as a draw is a tick that has been serialised behind it.
    #[test]
    fn collecting_does_not_hold_the_mailbox_across_the_work_it_collected() {
        let pending = Arc::new(Latest::<u32>::empty());
        let link = TrayLink::new(Arc::clone(&pending), || {});
        link.paint(1);

        let taken = pending.take().expect("a value was waiting");
        assert_eq!(taken, 1);

        // The "draw" is happening right now, in this scope, with `taken` in hand. A collector that
        // held the lock across it would block this next call for the draw's whole duration.
        let started = Instant::now();
        link.paint(2);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "painting while a draw is in flight must not wait for it"
        );
        assert_eq!(pending.take(), Some(2));
    }
}
