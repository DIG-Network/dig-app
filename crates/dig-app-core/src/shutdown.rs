//! A cooperative shutdown signal for the agent run loop.
//!
//! The agent core runs a blocking [`crate::agent::Agent::run`] loop; something outside that loop
//! (a tray "Quit" click, a `SIGTERM` handler, a service-stop request) needs to ask it to stop and
//! have it exit **promptly and cleanly**. [`Shutdown`] is that one-way latch: once triggered it
//! stays triggered, and any thread parked in [`Shutdown::wait_timeout`] wakes immediately.
//!
//! It is a cloneable handle over shared state, so the loop keeps one clone while the tray shell (or
//! a signal handler) keeps another and trips it from a different thread.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A cloneable, one-way "please stop" latch shared between the agent loop and whatever asks it to
/// stop. Cloning yields another handle onto the *same* signal.
#[derive(Clone)]
pub struct Shutdown {
    inner: Arc<Inner>,
}

struct Inner {
    /// `true` once shutdown has been requested. Guarded by the mutex paired with `changed`.
    triggered: Mutex<bool>,
    /// Notified whenever `triggered` flips, so a parked waiter wakes without polling.
    changed: Condvar,
}

impl Shutdown {
    /// Create a fresh, un-triggered shutdown signal.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                triggered: Mutex::new(false),
                changed: Condvar::new(),
            }),
        }
    }

    /// Request shutdown. Idempotent: triggering an already-triggered signal is a no-op. Wakes every
    /// thread currently parked in [`Shutdown::wait_timeout`].
    pub fn trigger(&self) {
        let mut triggered = self.lock();
        *triggered = true;
        self.inner.changed.notify_all();
    }

    /// Whether shutdown has been requested.
    pub fn is_triggered(&self) -> bool {
        *self.lock()
    }

    /// Park until shutdown is triggered or `timeout` elapses, whichever comes first. Returns
    /// immediately if shutdown was already triggered. This is how the run loop sleeps between ticks
    /// without busy-spinning while staying instantly interruptible.
    pub fn wait_timeout(&self, timeout: Duration) {
        let triggered = self.lock();
        if *triggered {
            return;
        }
        // We do not need the guard the wait returns — we only wake to re-check the loop condition.
        let _ = self
            .inner
            .changed
            .wait_timeout(triggered, timeout)
            .expect("shutdown mutex poisoned");
    }

    /// Lock the flag, treating poisoning as fatal: a poisoned shutdown latch means a panic left the
    /// agent in an unknown state, and continuing to run would be worse than surfacing it.
    fn lock(&self) -> std::sync::MutexGuard<'_, bool> {
        self.inner
            .triggered
            .lock()
            .expect("shutdown mutex poisoned")
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn starts_un_triggered() {
        assert!(!Shutdown::new().is_triggered());
    }

    #[test]
    fn trigger_latches_and_is_idempotent() {
        let s = Shutdown::new();
        s.trigger();
        assert!(s.is_triggered());
        s.trigger(); // second trigger must not panic or un-latch
        assert!(s.is_triggered());
    }

    #[test]
    fn wait_returns_immediately_when_already_triggered() {
        let s = Shutdown::new();
        s.trigger();
        let start = std::time::Instant::now();
        s.wait_timeout(Duration::from_secs(30));
        // Would block ~30s if the pre-triggered fast path were missing.
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn wait_returns_without_triggering_when_never_triggered() {
        // A condvar wait may return on the timeout OR a spurious wakeup (the run loop re-checks its
        // condition either way), so we assert the observable contract — it returns and leaves the
        // signal un-triggered — not a fragile lower bound on the elapsed time.
        let s = Shutdown::new();
        s.wait_timeout(Duration::from_millis(20));
        assert!(!s.is_triggered());
    }

    #[test]
    fn a_clone_wakes_a_parked_waiter() {
        let s = Shutdown::new();
        let trigger = s.clone();
        let waiter = thread::spawn(move || {
            let start = std::time::Instant::now();
            s.wait_timeout(Duration::from_secs(30));
            start.elapsed()
        });
        thread::sleep(Duration::from_millis(20));
        trigger.trigger();
        let waited = waiter.join().unwrap();
        // Woken by the trigger, not by the 30s timeout.
        assert!(waited < Duration::from_secs(1));
    }
}
