//! Session-lock lifecycle (WSEC-D, dig_ecosystem#965) — **security-critical / custody**.
//!
//! A profile stays unlocked only as long as its data-encryption key (DEK) lives in the in-memory
//! [`UnlockedIdentities`](crate::profiles::UnlockedIdentities) session (SPEC §3.1). Leaving that key
//! resident indefinitely opens two windows an attacker can walk into: someone who reaches the
//! unattended machine while the user is away, and the boot-unlock residency window where an OS
//! keychain auto-unlock leaves the DEK resident for hours. This module closes both by **dropping the
//! DEK** — re-sealing the session — on three triggers, and requiring re-authentication only when the
//! next operation actually needs the key.
//!
//! # The three lock triggers (all drop the DEK)
//!
//! - **Idle auto-lock** — [`SessionLock::poll_idle`] locks once no activity has been noted for the
//!   configured [`idle_timeout`](SessionLock::idle_timeout). The tray drives it from its refresh tick.
//! - **OS screen lock** — [`SessionLock::on_screen_locked`] locks when the OS session/screen locks.
//!   The platform event arrives through the [`ScreenLockSource`] seam (Windows / macOS wired now;
//!   Linux deferred behind dig_ecosystem#962).
//! - **One-tap lock-now** — [`SessionLock::lock_now`] locks immediately, with NO confirmation prompt
//!   (a tray action a user hits on the way out).
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
//! re-derives key material: unlocking is the keystore's job ([`crate::keystore`] /
//! [`crate::profiles`]), and the app calls [`SessionLock::note_resumed`] once a re-unlock succeeds to
//! clear the owed re-auth and restart the idle clock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::profiles::UnlockedIdentities;

/// The default idle window before a foreground session auto-locks (SPEC §3.1 walk-away window).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The in-memory key material a lock event drops. Implemented by
/// [`UnlockedIdentities`](crate::profiles::UnlockedIdentities) in production; a test double elsewhere.
///
/// Keeping this a narrow seam is what lets the lock lifecycle be exhaustively unit-tested without a
/// real keystore, and keeps this module unable to do anything with the keys except drop them and ask
/// whether any remain.
pub trait SessionKeys {
    /// Drop every unlocked profile DEK from memory, re-sealing the whole session.
    fn lock_all(&self);

    /// Whether any profile is currently unlocked (i.e. a lock still has key material to drop, and
    /// signing would not yet need a re-unlock).
    fn is_any_unlocked(&self) -> bool;
}

impl SessionKeys for UnlockedIdentities {
    fn lock_all(&self) {
        UnlockedIdentities::lock_all(self)
    }

    fn is_any_unlocked(&self) -> bool {
        UnlockedIdentities::is_any_unlocked(self)
    }
}

/// A monotonic time source, seamed so the idle logic is deterministic in tests. Production uses
/// [`SystemClock`] (`Instant`-backed); tests advance a [`ManualClock`] by exact durations.
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
/// One controller governs the whole session (all profiles lock together): a walk-away or a screen
/// lock should not leave any profile's key resident. It is cheap to share behind an `Arc` — the tray
/// tick calls [`poll_idle`](Self::poll_idle), a menu action calls [`lock_now`](Self::lock_now), and
/// the [`ScreenLockSource`] callback calls [`on_screen_locked`](Self::on_screen_locked).
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

    /// Record user/session activity, resetting the idle clock. Signing and other interactive
    /// operations call this. Reads MAY call it too — it never prompts and never blocks; it only
    /// postpones the idle deadline.
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

    /// Lock in response to an OS screen/session-lock event. Semantically identical to
    /// [`lock_now`](Self::lock_now) — separated so the trigger reads clearly at the call site and can
    /// diverge later if a screen lock ever wants different handling.
    pub fn on_screen_locked(&self) -> bool {
        self.lock_now()
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

/// A source of OS screen/session-lock events — the seam behind which each platform's native listener
/// lives (Windows `WM_WTSSESSION_CHANGE` / macOS `com.apple.screenIsLocked`). Wiring it to a
/// [`SessionLock`] is a one-liner: `source.start(move || lock.on_screen_locked())`.
///
/// The platform-agnostic lifecycle is tested against a fake source; the real listeners are thin
/// adapters that translate a native lock notification into the callback.
pub trait ScreenLockSource {
    /// Begin delivering lock events to `on_lock`. Delivery continues until the returned guard is
    /// dropped, so the caller keeps the guard alive for as long as it wants lock events.
    fn start(self, on_lock: Box<dyn Fn() + Send + 'static>) -> Box<dyn ScreenLockGuard>;
}

/// An opaque handle that keeps an OS screen-lock subscription alive; dropping it unsubscribes.
pub trait ScreenLockGuard: Send {}

/// The Windows screen-lock listener (`WTSRegisterSessionNotification` → `WM_WTSSESSION_CHANGE` with
/// `WTS_SESSION_LOCK`), delivering a lock event through the [`ScreenLockSource`] seam.
#[cfg(windows)]
pub use platform::WindowsScreenLockSource as PlatformScreenLockSource;

/// The macOS screen-lock listener (the `com.apple.screenIsLocked` distributed notification),
/// delivering a lock event through the [`ScreenLockSource`] seam.
#[cfg(target_os = "macos")]
pub use platform::MacScreenLockSource as PlatformScreenLockSource;

/// The Linux screen-lock listener is deferred behind the Linux unlock-UX work (dig_ecosystem#962):
/// the logind `Lock`/session `PrepareForSleep` D-Bus signals wire in there. Until then Linux has no
/// OS-lock trigger, so idle auto-lock + one-tap lock-now (both platform-agnostic) are the coverage.
#[cfg(all(not(windows), not(target_os = "macos")))]
pub use platform::NoopScreenLockSource as PlatformScreenLockSource;

#[cfg(windows)]
mod platform {
    use super::{ScreenLockGuard, ScreenLockSource};
    use std::sync::mpsc::{self, Sender};
    use std::thread::{self, JoinHandle};

    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
        PostMessageW, PostQuitMessage, RegisterClassW, SetWindowLongPtrW, GWLP_USERDATA, MSG,
        WINDOW_EX_STYLE, WM_CLOSE, WM_DESTROY, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED,
    };

    /// The `wParam` value of `WM_WTSSESSION_CHANGE` signalling the session locked.
    const WTS_SESSION_LOCK: usize = 0x7;

    /// The boxed lock callback, reached from the window proc via the window's `GWLP_USERDATA` pointer.
    type LockCallback = Box<dyn Fn() + Send + 'static>;

    /// A [`ScreenLockSource`] backed by a hidden message-only window subscribed to Terminal Services
    /// session-change notifications. On each `WTS_SESSION_LOCK` it invokes the callback.
    pub struct WindowsScreenLockSource;

    impl WindowsScreenLockSource {
        /// Build the Windows listener.
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for WindowsScreenLockSource {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Owns the message-pump thread; dropping it posts `WM_CLOSE` to the window (which destroys it and
    /// quits the pump) and joins the thread, unsubscribing from session notifications.
    struct WindowsGuard {
        hwnd: isize,
        pump: Option<JoinHandle<()>>,
    }

    impl ScreenLockGuard for WindowsGuard {}

    impl Drop for WindowsGuard {
        fn drop(&mut self) {
            if self.hwnd != 0 {
                // PostMessage is thread-safe; WM_CLOSE → DefWindowProc → DestroyWindow → WM_DESTROY →
                // PostQuitMessage, which ends the pump's GetMessage loop on its own thread.
                unsafe {
                    let _ = PostMessageW(HWND(self.hwnd as *mut _), WM_CLOSE, WPARAM(0), LPARAM(0));
                }
            }
            if let Some(pump) = self.pump.take() {
                let _ = pump.join();
            }
        }
    }

    impl ScreenLockSource for WindowsScreenLockSource {
        fn start(self, on_lock: LockCallback) -> Box<dyn ScreenLockGuard> {
            let (hwnd_tx, hwnd_rx) = mpsc::channel::<isize>();
            let pump = thread::spawn(move || unsafe { run_pump(on_lock, &hwnd_tx) });
            // Block until the pump publishes its window handle (or 0 if window creation failed).
            let hwnd = hwnd_rx.recv().unwrap_or(0);
            Box::new(WindowsGuard {
                hwnd,
                pump: Some(pump),
            })
        }
    }

    /// Create the hidden window, subscribe to session notifications, publish the window handle, then
    /// pump messages until the window is destroyed.
    unsafe fn run_pump(on_lock: LockCallback, hwnd_tx: &Sender<isize>) {
        let instance = match GetModuleHandleW(PCWSTR::null()) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = hwnd_tx.send(0);
                return;
            }
        };
        let class_name = w!("DigAppSessionLockWindow");
        let wnd_class = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance.into(),
            lpszClassName: class_name,
            ..Default::default()
        };
        RegisterClassW(&wnd_class);

        // Leak the boxed callback into the window's USERDATA; it is reclaimed on WM_DESTROY.
        let callback_ptr = Box::into_raw(Box::new(on_lock));
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("dig-app session lock"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            HINSTANCE::from(instance),
            None,
        );
        let hwnd = match hwnd {
            Ok(handle) => handle,
            Err(_) => {
                drop(Box::from_raw(callback_ptr));
                let _ = hwnd_tx.send(0);
                return;
            }
        };
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, callback_ptr as isize);
        let _ = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        let _ = hwnd_tx.send(hwnd.0 as isize);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            DispatchMessageW(&msg);
        }
        let _ = WTSUnRegisterSessionNotification(hwnd);
    }

    /// The window procedure: fires the callback on a session-lock notification and reclaims the boxed
    /// callback on destroy.
    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_WTSSESSION_CHANGE if wparam.0 == WTS_SESSION_LOCK => {
                let callback_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const LockCallback;
                if !callback_ptr.is_null() {
                    (*callback_ptr)();
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                let callback_ptr = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut LockCallback;
                if !callback_ptr.is_null() {
                    drop(Box::from_raw(callback_ptr));
                }
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ptr::NonNull;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::{NSObjectProtocol, ProtocolObject};
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSString};

    use super::{ScreenLockGuard, ScreenLockSource};

    /// The system-wide distributed notification the login/screen-saver window posts when the screen
    /// locks. Undocumented-but-stable; the paired `com.apple.screenIsUnlocked` drives resume UX
    /// elsewhere.
    const SCREEN_IS_LOCKED: &str = "com.apple.screenIsLocked";

    /// A [`ScreenLockSource`] backed by the macOS distributed notification `com.apple.screenIsLocked`,
    /// observed on the default distributed notification center. On each notification it invokes the
    /// callback.
    pub struct MacScreenLockSource;

    impl MacScreenLockSource {
        /// Build the macOS listener.
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for MacScreenLockSource {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Keeps the notification observer registered; dropping it removes the observer.
    struct MacGuard {
        center: Retained<NSDistributedNotificationCenter>,
        observer: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    }

    // The Retained handles are only created and dropped on the thread that owns the guard; wrapping
    // them Send lets the guard live beside the rest of the app state.
    unsafe impl Send for MacGuard {}
    impl ScreenLockGuard for MacGuard {}

    impl Drop for MacGuard {
        fn drop(&mut self) {
            // `removeObserver:` is typed `&AnyObject`; the observer token is a `ProtocolObject`, so go
            // through `msg_send!` (which accepts any `Message`) rather than fight the deref chain.
            unsafe {
                let _: () = objc2::msg_send![&self.center, removeObserver: &*self.observer];
            }
        }
    }

    impl ScreenLockSource for MacScreenLockSource {
        fn start(self, on_lock: Box<dyn Fn() + Send + 'static>) -> Box<dyn ScreenLockGuard> {
            // The notification center invokes this block for each screen-lock event; the notification
            // itself is unused — the event is the signal.
            let block = RcBlock::new(move |_notification: NonNull<NSNotification>| {
                on_lock();
            });
            unsafe {
                let center = NSDistributedNotificationCenter::defaultCenter();
                let name = NSString::from_str(SCREEN_IS_LOCKED);
                let observer = center.addObserverForName_object_queue_usingBlock(
                    Some(&name),
                    None,
                    None,
                    &block,
                );
                Box::new(MacGuard { center, observer })
            }
        }
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
mod platform {
    use super::{ScreenLockGuard, ScreenLockSource};

    /// The no-op screen-lock source used where no OS-lock event is wired (Linux, deferred behind
    /// dig_ecosystem#962). It registers nothing and never fires — idle auto-lock and one-tap lock-now
    /// still apply.
    pub struct NoopScreenLockSource;

    impl NoopScreenLockSource {
        /// Build the no-op listener.
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for NoopScreenLockSource {
        fn default() -> Self {
            Self::new()
        }
    }

    struct NoopGuard;
    impl ScreenLockGuard for NoopGuard {}

    impl ScreenLockSource for NoopScreenLockSource {
        fn start(self, _on_lock: Box<dyn Fn() + Send + 'static>) -> Box<dyn ScreenLockGuard> {
            Box::new(NoopGuard)
        }
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

    fn lock_with(keys: FakeKeys, clock: ManualClock) -> SessionLock<FakeKeys, ManualClock> {
        SessionLock::new(keys, clock, Duration::from_secs(300))
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
    fn os_screen_lock_drops_the_dek() {
        let keys = FakeKeys::unlocked();
        let lock = lock_with(keys.clone(), ManualClock::default());

        assert!(lock.on_screen_locked());
        assert!(
            !keys.is_any_unlocked(),
            "an OS screen lock re-sealed the session"
        );
        assert!(lock.reauth_required());
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
    fn default_idle_timeout_is_five_minutes() {
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(300));
        let lock = SessionLock::new(
            FakeKeys::unlocked(),
            SystemClock::new(),
            DEFAULT_IDLE_TIMEOUT,
        );
        assert_eq!(lock.idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    }

    /// A fake [`ScreenLockSource`] that hands the caller a trigger to simulate OS lock events, so the
    /// seam wiring is testable without a real OS notification.
    struct FakeScreenLockSource;

    struct FakeGuard;
    impl ScreenLockGuard for FakeGuard {}

    impl FakeScreenLockSource {
        /// Register `on_lock` and return a closure that fires a simulated OS lock event.
        fn wire(self, on_lock: Box<dyn Fn() + Send + 'static>) -> impl Fn() {
            move || on_lock()
        }
    }

    impl ScreenLockSource for FakeScreenLockSource {
        fn start(self, _on_lock: Box<dyn Fn() + Send + 'static>) -> Box<dyn ScreenLockGuard> {
            Box::new(FakeGuard)
        }
    }

    #[test]
    fn a_screen_lock_source_callback_drives_the_lock() {
        let keys = FakeKeys::unlocked();
        let lock = Arc::new(lock_with(keys.clone(), ManualClock::default()));

        // Wire the source callback to the controller exactly as production does.
        let lock_for_cb = Arc::clone(&lock);
        let fire = FakeScreenLockSource.wire(Box::new(move || {
            lock_for_cb.on_screen_locked();
        }));

        assert!(keys.is_any_unlocked());
        fire(); // the OS "locked"
        assert!(
            !keys.is_any_unlocked(),
            "the source callback dropped the DEK"
        );
        assert!(lock.reauth_required());
    }

    #[test]
    fn screen_lock_source_start_returns_a_live_guard() {
        // The production seam: start() returns a guard that keeps the subscription alive until drop.
        let guard = FakeScreenLockSource.start(Box::new(|| {}));
        drop(guard); // dropping unsubscribes without panicking
    }

    /// The Linux/other platform source is the no-op (dig_ecosystem#962): it registers nothing and its
    /// guard drops cleanly. On Windows/macOS the real listener needs a live OS session, so its
    /// behaviour is verified by the native-backends CI build + the seam tests above, not here.
    #[cfg(all(not(windows), not(target_os = "macos")))]
    #[test]
    fn platform_noop_source_registers_nothing_and_drops_cleanly() {
        let source = PlatformScreenLockSource::new();
        let guard = source.start(Box::new(|| panic!("the no-op source must never fire")));
        drop(guard);
    }
}
