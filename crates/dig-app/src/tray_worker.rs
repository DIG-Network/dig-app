//! Running tray menu actions somewhere other than the event loop.
//!
//! # Why this exists
//!
//! The tray used to handle menu actions INSIDE its event loop, so every handler that waited for
//! something held the whole tray hostage while it waited — and the tray's icon, tooltip and menu are
//! the only surfaces telling the user anything. Nearly every handler waits for something:
//!
//! * a confirm/input window runs its own nested message loop for as long as the window is open;
//! * quitting waits for the agent to stop;
//! * copying to the clipboard waits on a child process;
//! * and the Windows Hello step *blocked the very thread Hello needed in order to raise its prompt*,
//!   which was not a stall but a permanent deadlock — the app froze and nothing appeared
//!   (dig_ecosystem#1926).
//!
//! Fixing the biometric alone would have fixed the worst symptom of a defect the whole class shares.
//! So the event loop no longer runs handlers at all: it hands each action to an [`ActionWorker`] and
//! returns immediately, which makes "a handler blocked the tray" unexpressible rather than merely
//! absent from today's handlers.
//!
//! # Why one worker thread, and why a second click is refused
//!
//! Custody actions destroy accounts. Two of them running at once — or queued up behind each other
//! because a user clicked twice at a tray that *looked* frozen — is precisely the sequence that must
//! not be able to open two destroy flows. So there is exactly ONE worker, and an action submitted
//! while another is in flight is REFUSED rather than queued: the answer to a double-click is the one
//! dialog already on screen, never a second one waiting behind it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread;

/// A single background thread that runs one tray action at a time.
///
/// Submitting never blocks, so an event loop can hand off an action and get straight back to drawing.
pub struct ActionWorker<A> {
    /// Capacity 1, and only ever holding an action `busy` has already reserved the worker for.
    submit: SyncSender<A>,
    /// Reserved at SUBMIT time, released when the handler returns — so a second click during the gap
    /// between accepting an action and starting it is refused like any other second click.
    busy: Arc<AtomicBool>,
    /// Set once a handler has reported that the app should stop; the event loop polls it.
    stopping: Arc<AtomicBool>,
}

impl<A: Send + 'static> ActionWorker<A> {
    /// Start a worker that runs `handle` for each accepted action.
    ///
    /// `handle` returns whether the app should now stop — the answer travels back to the event loop
    /// through [`ActionWorker::stop_requested`], since the loop is the only place that can exit.
    pub fn spawn<H>(mut handle: H) -> Self
    where
        H: FnMut(A) -> bool + Send + 'static,
    {
        let (submit, actions) = sync_channel::<A>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));

        let worker_busy = Arc::clone(&busy);
        let worker_stopping = Arc::clone(&stopping);
        thread::Builder::new()
            .name("dig-tray-actions".to_string())
            .spawn(move || {
                for action in actions {
                    // A panicking handler must cost the user one action, never the tray: without this
                    // the thread would die and every later click would be silently refused.
                    let stop =
                        catch_unwind(AssertUnwindSafe(|| handle(action))).unwrap_or_else(|_| {
                            tracing::error!(
                                "a tray action panicked; the tray stays live and does nothing"
                            );
                            false
                        });
                    worker_busy.store(false, Ordering::SeqCst);
                    if stop {
                        worker_stopping.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            })
            .expect("the tray action worker thread could not be started");

        Self {
            submit,
            busy,
            stopping,
        }
    }

    /// Hand `action` to the worker. Returns whether it was accepted.
    ///
    /// `false` means another action is already in flight and this one was DROPPED — deliberately, see
    /// the module docs. Never blocks.
    pub fn submit(&self, action: A) -> bool {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        if self.submit.try_send(action).is_err() {
            // The worker is gone (it stopped, or its thread died). Release the reservation so the
            // state stays honest, and report the action as not taken.
            self.busy.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Whether an action is in flight right now.
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    /// Whether a handler has asked the app to stop.
    pub fn stop_requested(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::thread::ThreadId;
    use std::time::{Duration, Instant};

    /// Wait for `condition`, up to a second — enough that a loaded CI machine is not flaky, short
    /// enough that a genuine failure is a failure rather than a hang.
    fn eventually(condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        condition()
    }

    /// The property the deadlock violated: a handler must not run on the thread that submitted it.
    #[test]
    fn an_action_runs_off_the_submitting_thread() {
        let (report, observed) = channel::<ThreadId>();
        let worker = ActionWorker::spawn(move |_: ()| {
            report.send(thread::current().id()).expect("id delivered");
            false
        });

        assert!(worker.submit(()));

        let ran_on = observed.recv().expect("the handler reported its thread");
        assert_ne!(
            ran_on,
            thread::current().id(),
            "the handler ran on the event loop's own thread"
        );
    }

    /// Submitting returns immediately even when the handler is slow — this is what keeps the tray
    /// drawing while a dialog is open. An event loop that called the handler inline would take the
    /// handler's whole duration to get here.
    #[test]
    fn submitting_returns_long_before_a_slow_handler_finishes() {
        let done = Arc::new(AtomicBool::new(false));
        let handler_done = Arc::clone(&done);
        let worker = ActionWorker::spawn(move |_: ()| {
            thread::sleep(Duration::from_millis(300));
            handler_done.store(true, Ordering::SeqCst);
            false
        });

        let started = Instant::now();
        assert!(worker.submit(()));
        let handed_off = started.elapsed();

        assert!(
            handed_off < Duration::from_millis(100),
            "handing off took {handed_off:?} — the event loop waited for the handler"
        );
        assert!(
            !done.load(Ordering::SeqCst),
            "the handler had already finished"
        );
        assert!(
            eventually(|| done.load(Ordering::SeqCst)),
            "the handler never ran"
        );
    }

    /// A second click at a tray that looks busy must not open a second flow — not concurrently, and
    /// not queued up behind the first.
    #[test]
    fn a_second_action_while_one_is_in_flight_is_refused() {
        let runs = Arc::new(AtomicBool::new(false));
        let (counted, count) = channel::<()>();
        let first = Arc::clone(&runs);
        let worker = ActionWorker::spawn(move |_: ()| {
            first.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(300));
            counted.send(()).expect("run counted");
            false
        });

        assert!(worker.submit(()), "the first action is accepted");
        assert!(
            eventually(|| runs.load(Ordering::SeqCst)),
            "the first action started"
        );
        assert!(
            !worker.submit(()),
            "the second action was accepted while one was in flight"
        );

        count.recv().expect("the first action finished");
        assert!(
            count.recv_timeout(Duration::from_millis(300)).is_err(),
            "the refused action ran anyway — it was queued rather than dropped"
        );
    }

    /// Refusal is only for the overlap: once the action finishes the tray takes work again.
    #[test]
    fn the_worker_accepts_work_again_once_the_action_finishes() {
        let (ran, runs) = channel::<()>();
        let worker = ActionWorker::spawn(move |_: ()| {
            ran.send(()).expect("run reported");
            false
        });

        assert!(worker.submit(()));
        runs.recv().expect("the first action ran");
        assert!(eventually(|| !worker.is_busy()), "the worker stayed busy");
        assert!(worker.submit(()), "the worker refused work after finishing");
        runs.recv().expect("the second action ran");
    }

    /// Quit happens on the worker, but only the event loop can exit — so the request must reach it.
    #[test]
    fn a_handler_that_asks_to_stop_is_reported_to_the_event_loop() {
        let worker = ActionWorker::spawn(|_: ()| true);
        assert!(!worker.stop_requested(), "nothing has asked to stop yet");

        assert!(worker.submit(()));

        assert!(
            eventually(|| worker.stop_requested()),
            "the loop was never told to exit"
        );
    }

    /// A panicking handler is one lost action, not a dead tray — and it is not a quit.
    #[test]
    fn a_panicking_handler_neither_wedges_the_worker_nor_stops_the_app() {
        let (ran, runs) = channel::<()>();
        let worker = ActionWorker::spawn(move |explode: bool| {
            assert!(!explode, "the handler panics on purpose");
            ran.send(()).expect("run reported");
            false
        });

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        assert!(worker.submit(true));
        let recovered = eventually(|| !worker.is_busy());
        std::panic::set_hook(previous);

        assert!(recovered, "the worker stayed busy after a panic");
        assert!(
            !worker.stop_requested(),
            "a panic was read as a request to quit"
        );
        assert!(
            worker.submit(false),
            "the worker refused work after a panic"
        );
        runs.recv().expect("the later action still ran");
    }
}
