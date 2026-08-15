//! Session-lock lifecycle (WSEC-D, dig_ecosystem#965) — **security-critical / custody**.
//!
//! The account stays unlocked only as long as its master seed / data-encryption keys live in the
//! in-memory [`AccountResidency`](crate::account::residency::AccountResidency) (SPEC §3.1). Leaving
//! that key resident indefinitely opens a window an attacker can walk into: someone who reaches the
//! unattended machine while the user is away. This module closes it by **dropping the DEK** —
//! re-sealing the session — and requiring re-authentication only when the next operation actually
//! needs the key.
//!
//! # The lock policy: exactly three triggers (dig_ecosystem#2953)
//!
//! Once a session is unlocked it stays unlocked until one of these, and nothing else:
//!
//! - **One-tap lock-now** — [`SessionLock::lock_now`] locks immediately, with NO confirmation prompt
//!   (a tray action a user hits on the way out). With a 24-hour idle window this is the only
//!   *immediate* lock, so it must stay offered at the top level of the tray menu.
//! - **24 hours of no USER activity** — [`SessionLock::poll_idle`] locks once no activity has been
//!   noted for the configured [`idle_timeout`](SessionLock::idle_timeout), defaulting to
//!   [`DEFAULT_IDLE_TIMEOUT`]. The tray drives it from its refresh tick. What counts as activity is a
//!   contract in its own right — see [`SessionLock::note_activity`].
//! - **The app was closed and reopened** — structural, not a code path here. The DEK lives only in the
//!   in-memory residency, so process exit drops it and a fresh process starts locked.
//!
//! Locking the OS screen is deliberately NOT a trigger: a person who locks their machine to go to
//! lunch has not asked dig-app to forget their session. `tests/no_os_screen_lock_trigger.rs` keeps a
//! platform listener from being re-introduced.
//!
//! # Bounds this module must not drift across
//!
//! Nothing may ever persist an unlocked session across a restart. "Closed and reopened re-locks" is
//! true *by construction* only because the key material is memory-resident and unserialised; writing
//! it anywhere durable would silently delete the strictest of the three triggers.
//!
//! # Frictionless consumption is preserved (§6.0)
//!
//! Reading and browsing DIG content never touch the identity key, so a lock NEVER interrupts them and
//! NEVER prompts. Only **signing** consults the lock: after a lock, [`SessionLock::reauth_required`]
//! is true, so the next signing operation re-authenticates (biometric / passphrase) via the keystore
//! unlock path — while reads keep flowing untouched. This is the tiered re-auth contract: the lock
//! gates the key, not the content.
//!
//! # Boundary
//!
//! This module only *drops* the DEK and tracks whether a re-auth is owed. It never holds, derives, or
//! re-derives key material: unlocking is the account boot's job ([`crate::account::boot`]), and the
//! app calls [`SessionLock::note_resumed`] once a re-unlock succeeds to
//! clear the owed re-auth and restart the idle clock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The default idle window before an unattended session auto-locks: **24 hours** (SPEC §3.6).
///
/// # Why a day, and why that is defensible
///
/// This window governs how often a person retypes a password to authorise their OWN LOCAL actions —
/// not whether a remote party can act for them. Under §908 the node never holds the user's key, and
/// signing is local and per-operation, so a longer window widens only the unattended-machine window on
/// a device the user already controls; it grants no remote capability at all. The cost of a short one
/// is real and constant: a password prompt in front of every ordinary action, which trains people to
/// type it reflexively.
///
/// # It is a maximum, not a promise of liveness
///
/// Nothing keeps the process alive to honour the full day. An app closed at hour 3 has already lost
/// the session — process exit is the third and stricter rule — so 24 hours is the ceiling on an
/// untouched, still-running app, never a guarantee the session will last that long.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// The in-memory key material a lock event drops. Implemented by the master-HD
/// [`AccountResidency`](crate::account::residency::AccountResidency) in production (dropping the
/// unlocked account zeroizes the master seed); a test double elsewhere.
///
/// Keeping this a narrow seam is what lets the lock lifecycle be exhaustively unit-tested without a
/// real keystore, and keeps this module unable to do anything with the keys except drop them and ask
/// whether any remain.
pub trait SessionKeys {
    /// Drop the unlocked account's key material from memory, re-sealing the session.
    fn lock_all(&self);

    /// Whether the account is currently unlocked (i.e. a lock still has key material to drop, and
    /// signing would not yet need a re-unlock).
    fn is_any_unlocked(&self) -> bool;
}

/// A monotonic time source, seamed so the idle logic is deterministic in tests. Production uses
/// [`SystemClock`] (`Instant`-backed); tests advance a `ManualClock` by exact durations.
pub trait MonotonicClock {
    /// Monotonic time elapsed since this clock's fixed origin. Only differences are meaningful.
    fn elapsed(&self) -> Duration;
}

/// The production [`MonotonicClock`]: elapsed time since the clock was created, from `Instant`.
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// The session-lock lifecycle controller: owns the idle clock and the "re-auth owed" flag, and drives
/// the [`SessionKeys`] DEK drop on each lock trigger.
///
/// One controller governs the whole session (all profiles lock together): a walk-away should not
/// leave any profile's key resident. It is cheap to share behind an `Arc` — the tray tick calls
/// [`poll_idle`](Self::poll_idle) and a menu action calls [`lock_now`](Self::lock_now).
pub struct SessionLock<K: SessionKeys, C: MonotonicClock> {
    keys: K,
    clock: C,
    idle_timeout: Duration,
    /// Elapsed time (per `clock`) of the last noted activity; the idle deadline is this plus
    /// `idle_timeout`.
    last_activity: Mutex<Duration>,
    /// Whether a lock has dropped the DEK and the next signing therefore owes a re-authentication.
    reauth_owed: AtomicBool,
}

impl<K: SessionKeys, C: MonotonicClock> SessionLock<K, C> {
    /// Build a controller over `keys`, timing idle with `clock` and locking after `idle_timeout` of
    /// inactivity. The session starts un-owed (no re-auth pending) with the idle clock running from
    /// now.
    pub fn new(keys: K, clock: C, idle_timeout: Duration) -> Self {
        let now = clock.elapsed();
        Self {
            keys,
            clock,
            idle_timeout,
            last_activity: Mutex::new(now),
            reauth_owed: AtomicBool::new(false),
        }
    }

    /// The idle window before an inactive session auto-locks.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Record **user** activity, resetting the idle clock.
    ///
    /// # Only a human at the machine may call this
    ///
    /// "No activity" means no person, not no work. A tray app polls constantly, and an idle clock fed
    /// by the app's own work never elapses — the 24-hour timeout would become dead code that merely
    /// *looks* like a security control. So background work MUST NEVER call this: not the refresh
    /// tick, not status polls, not repaints, not node reads, not notifications. A content read in
    /// particular is not evidence of presence; with a day-long window a background read stream would
    /// hold the session open forever.
    ///
    /// The two legitimate call sites, and there are no others:
    ///
    /// - a tray/window menu click (`dig-app.rs`, the tray event loop),
    /// - `SessionReauthGate::authorize_sign` on an already-authorised sign
    ///   ([`crate::sign_service`]), which is user-driven by definition.
    ///
    /// The refresh tick calls only [`poll_idle`](Self::poll_idle), which READS the clock and never
    /// feeds it. That asymmetry is what makes the timeout real.
    pub fn note_activity(&self) {
        *self
            .last_activity
            .lock()
            .expect("session-lock mutex poisoned") = self.clock.elapsed();
    }

    /// Lock immediately with no confirmation (the one-tap tray "Lock now"): drop every DEK and mark a
    /// re-auth owed. Returns whether any key material was actually dropped.
    pub fn lock_now(&self) -> bool {
        let had_keys = self.keys.is_any_unlocked();
        self.keys.lock_all();
        self.reauth_owed.store(true, Ordering::SeqCst);
        had_keys
    }

    /// Lock if the session has been idle at least [`idle_timeout`](Self::idle_timeout). Idempotent and
    /// cheap enough to call on every tray tick: it locks only when a key is still unlocked and the
    /// idle deadline has passed, and returns whether this call performed the lock.
    pub fn poll_idle(&self) -> bool {
        if !self.keys.is_any_unlocked() {
            return false;
        }
        let idle_for = self.clock.elapsed().saturating_sub(
            *self
                .last_activity
                .lock()
                .expect("session-lock mutex poisoned"),
        );
        if idle_for < self.idle_timeout {
            return false;
        }
        self.lock_now()
    }

    /// Whether a lock has occurred and the next **signing** operation must re-authenticate before it
    /// can use the key. Reads/browsing MUST NOT consult this — it is the tiered-re-auth gate for
    /// signing only (§6.0). Stays true from a lock until [`note_resumed`](Self::note_resumed).
    pub fn reauth_required(&self) -> bool {
        self.reauth_owed.load(Ordering::SeqCst)
    }

    /// Clear the owed re-auth and restart the idle clock, called once a re-unlock has succeeded (the
    /// keystore re-populated the session). After this, signing proceeds without prompting again until
    /// the next lock.
    pub fn note_resumed(&self) {
        self.reauth_owed.store(false, Ordering::SeqCst);
        self.note_activity();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// A fake DEK store: a boolean "is a profile unlocked" plus a count of `lock_all` calls, so tests
    /// can assert exactly when the DEK is dropped without a real keystore.
    #[derive(Clone, Default)]
    struct FakeKeys {
        unlocked: Arc<AtomicBool>,
        locks: Arc<AtomicUsize>,
    }

    impl FakeKeys {
        fn unlocked() -> Self {
            let keys = Self::default();
            keys.unlocked.store(true, Ordering::SeqCst);
            keys
        }

        fn lock_count(&self) -> usize {
            self.locks.load(Ordering::SeqCst)
        }
    }

    impl SessionKeys for FakeKeys {
        fn lock_all(&self) {
            self.unlocked.store(false, Ordering::SeqCst);
            self.locks.fetch_add(1, Ordering::SeqCst);
        }

        fn is_any_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
    }

    /// A clock whose elapsed time is set explicitly, so idle expiry is exercised deterministically.
    #[derive(Clone, Default)]
    struct ManualClock {
        now: Arc<Mutex<Duration>>,
    }

    impl ManualClock {
        fn advance(&self, by: Duration) {
            *self.now.lock().unwrap() += by;
        }
    }

    impl MonotonicClock for ManualClock {
        fn elapsed(&self) -> Duration {
            *self.now.lock().unwrap()
        }
    }

    /// A short, TEST-LOCAL idle window. Deliberately not [`DEFAULT_IDLE_TIMEOUT`]: the lifecycle tests
    /// below are about *how* the deadline behaves, and a five-minute figure keeps their arithmetic
    /// readable. The shipped window is exercised by the two day-long tests at the end of this module.
    const TEST_IDLE_WINDOW: Duration = Duration::from_secs(300);

    fn lock_with(keys: FakeKeys, clock: ManualClock) -> SessionLock<FakeKeys, ManualClock> {
        SessionLock::new(keys, clock, TEST_IDLE_WINDOW)
    }

    #[test]
    fn lock_now_drops_the_dek_and_owes_reauth() {
        let keys = FakeKeys::unlocked();
        let lock = lock_with(keys.clone(), ManualClock::default());

        assert!(!lock.reauth_required(), "a fresh session owes no re-auth");
        assert!(
            lock.lock_now(),
            "lock-now reports it dropped live key material"
        );

        assert!(!keys.is_any_unlocked(), "the DEK is gone after lock-now");
        assert_eq!(keys.lock_count(), 1);
        assert!(
            lock.reauth_required(),
            "the next signing must re-authenticate"
        );
    }

    #[test]
    fn lock_now_takes_no_confirmation_and_is_idempotent_on_an_already_locked_session() {
        let keys = FakeKeys::default(); // already locked
        let lock = lock_with(keys.clone(), ManualClock::default());

        assert!(!lock.lock_now(), "nothing to drop when already locked");
        assert_eq!(keys.lock_count(), 1, "lock_all still runs (fail-safe)");
        assert!(lock.reauth_required());
    }

    #[test]
    fn idle_below_the_timeout_does_not_lock() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = lock_with(keys.clone(), clock.clone());

        clock.advance(Duration::from_secs(299));
        assert!(!lock.poll_idle(), "just under the 5-minute idle window");
        assert!(keys.is_any_unlocked());
        assert!(!lock.reauth_required());
    }

    #[test]
    fn idle_past_the_timeout_locks_and_drops_the_dek() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = lock_with(keys.clone(), clock.clone());

        clock.advance(Duration::from_secs(300));
        assert!(lock.poll_idle(), "the idle deadline elapsed");
        assert!(!keys.is_any_unlocked(), "idle auto-lock dropped the DEK");
        assert!(lock.reauth_required());
    }

    #[test]
    fn activity_postpones_the_idle_deadline() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = lock_with(keys.clone(), clock.clone());

        clock.advance(Duration::from_secs(299));
        lock.note_activity(); // reset the clock just before expiry
        clock.advance(Duration::from_secs(299));
        assert!(!lock.poll_idle(), "activity pushed the deadline out");
        assert!(keys.is_any_unlocked());

        clock.advance(Duration::from_secs(1));
        assert!(lock.poll_idle(), "idle again 300s after the last activity");
    }

    #[test]
    fn poll_idle_never_locks_an_already_locked_session() {
        let keys = FakeKeys::default(); // locked
        let clock = ManualClock::default();
        let lock = lock_with(keys.clone(), clock.clone());

        clock.advance(Duration::from_secs(10_000));
        assert!(!lock.poll_idle(), "nothing unlocked, so nothing to lock");
        assert_eq!(keys.lock_count(), 0);
    }

    #[test]
    fn a_read_after_lock_does_not_prompt_but_the_next_sign_reauthenticates() {
        // Model the tiered contract: a read never consults the lock; a sign does. After a lock the
        // read still proceeds untouched while the sign is told to re-authenticate.
        let keys = FakeKeys::unlocked();
        let lock = lock_with(keys.clone(), ManualClock::default());

        // A "read" that, by contract, never asks whether re-auth is required.
        let read = || "content bytes";
        assert_eq!(read(), "content bytes", "reads flow before a lock");

        lock.lock_now();

        // The read is entirely unaffected — it does not touch the key and is never gated.
        assert_eq!(
            read(),
            "content bytes",
            "reads still flow after a lock (§6.0)"
        );
        // A "sign" consults the gate and finds it must re-authenticate.
        assert!(
            lock.reauth_required(),
            "the next sign after a lock re-authenticates"
        );
    }

    #[test]
    fn resume_clears_the_owed_reauth_and_restarts_the_idle_clock() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = lock_with(keys.clone(), clock.clone());

        lock.lock_now();
        assert!(lock.reauth_required());

        // The keystore re-unlocked the session; the app notes the resume.
        keys.unlocked.store(true, Ordering::SeqCst);
        clock.advance(Duration::from_secs(200));
        lock.note_resumed();

        assert!(
            !lock.reauth_required(),
            "a successful re-unlock clears the owed re-auth"
        );
        clock.advance(Duration::from_secs(299));
        assert!(
            !lock.poll_idle(),
            "the idle clock restarted at note_resumed"
        );
        clock.advance(Duration::from_secs(1));
        assert!(lock.poll_idle(), "and expires 300s after the resume");
    }

    #[test]
    fn default_idle_timeout_is_twenty_four_hours() {
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(24 * 60 * 60));
        let lock = SessionLock::new(
            FakeKeys::unlocked(),
            SystemClock::new(),
            DEFAULT_IDLE_TIMEOUT,
        );
        assert_eq!(lock.idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    }

    /// A session built on the shipped default, so these two tests exercise the window a user actually
    /// gets rather than a test-local one.
    fn default_windowed_lock(
        keys: FakeKeys,
        clock: ManualClock,
    ) -> SessionLock<FakeKeys, ManualClock> {
        SessionLock::new(keys, clock, DEFAULT_IDLE_TIMEOUT)
    }

    #[test]
    fn a_session_idle_for_twenty_three_hours_fifty_nine_minutes_is_still_unlocked() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = default_windowed_lock(keys.clone(), clock.clone());

        // Derived from the constant, not from a literal 86_400: the test must track a future change to
        // the window rather than silently pin the number it was written against.
        clock.advance(DEFAULT_IDLE_TIMEOUT - Duration::from_secs(60));
        assert!(!lock.poll_idle(), "one minute short of the day-long window");
        assert!(keys.is_any_unlocked(), "the DEK is still resident");
        assert!(!lock.reauth_required());
    }

    #[test]
    fn a_session_idle_for_exactly_twenty_four_hours_locks() {
        let keys = FakeKeys::unlocked();
        let clock = ManualClock::default();
        let lock = default_windowed_lock(keys.clone(), clock.clone());

        clock.advance(DEFAULT_IDLE_TIMEOUT);
        assert!(lock.poll_idle(), "the day-long idle deadline elapsed");
        assert!(!keys.is_any_unlocked(), "idle auto-lock dropped the DEK");
        assert!(lock.reauth_required());
    }
}
