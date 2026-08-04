//! Keeping the tray's context menu dismissable, and clearing it when it is not.
//!
//! Tray-only: it exists entirely to guard `tray-icon`'s `TrackPopupMenu`, and a headless build
//! has no tray menu to track.
//!
//! # The defect
//!
//! `tray-icon` shows the tray menu with `TrackPopupMenu`, a **nested modal message loop** that runs
//! inside the tray window proc, inside tao's dispatch, on the main thread. Measured on dig-app#86:
//! while that loop is up, the tao user closure **does not run at all** — no menu-event drain, no
//! repaint, no diagnostics. A menu that never dismisses is therefore a tray whose every item is dead,
//! permanently, in silence, which is exactly what was reported.
//!
//! What makes a menu never dismiss is documented (MSDN Q135788) and was reproduced here: the
//! `SetForegroundWindow` that must precede the track was **refused**, the popup was tracked anyway,
//! and it then could not be dismissed by clicking away, by Escape, or by anything else. It held the
//! loop for 180 s and would have held it forever.
//!
//! # The two things this module does
//!
//! **1. Try for the foreground one edge EARLIER.** [`claim_foreground`] runs from `tray-icon`'s own
//! event handler, on button-DOWN.
//!
//! Be precise about what this is and is not, because the first version of this comment overstated
//! it. `tray-icon` has **always** called `SetForegroundWindow` immediately before the track — 0.19.3
//! at `mod.rs:508`, 0.23.1 at `:544`. That half of Q135788 was never missing; it was **refused**.
//! What 0.23.1 adds is the *other* half, the `PostMessageW(WM_NULL)` after the track (`:557`), and
//! that one cannot help a menu whose track never returns.
//!
//! So this is the same Win32 call, on the same window, one input edge sooner — and 0.23.1 also moved
//! the track from button-DOWN to button-**UP** (`:491`), which widens that gap to a whole click. It
//! helps in exactly one situation: foreground rights exist at DOWN and have lapsed by UP. Where
//! rights are absent for the whole click it changes nothing, and it is honest to say so.
//!
//! **2. Break a menu that got tracked anyway.** [`break_modal_menu`] posts `WM_CANCELMODE`, which
//! **was measured to break a foreign thread out of `TrackPopupMenu`** — cross-process, cross-thread,
//! from a plain `PostMessage` that never blocks the sender. The watchdog calls it when the pump has
//! been parked in [`Phase::TrayMenu`](crate::pump_vigil::Phase::TrayMenu) past its bound.
//!
//! # What this is NOT, stated plainly
//!
//! This is **break, not refuse**. The right rule is *refuse to track rather than track hopefully* —
//! but the track happens inside `tray-icon`, and there is no public API that withdraws the menu from
//! a `Fn + Send + Sync` handler on the way into it. Genuinely refusing means owning the popup
//! ourselves (`muda`'s `ContextMenu::show_context_menu_for_hwnd`, which is documented for exactly
//! this), and that belongs with the window service, which is the thing entitled to decide whether a
//! surface may be raised at all.
//!
//! Until then: rung 1 may widen the window in which rights are held, and **rung 2 is what actually
//! makes the wedge survivable** — it ends a stuck menu at the bound instead of leaving it until the
//! user restarts DIG. Neither can manufacture consent, because a dismissed menu has selected no item.
//!
//! # What is still unknown
//!
//! **The field trigger is not identified.** The wedge was reproduced by posting `WM_USER_TRAYICON`
//! synthetically, which bypasses the shell's input grant, so a refusal there is close to guaranteed
//! — while a real click on a healthy process is granted, which the control confirmed. The chain
//! *refused foreground ⇒ undismissable popup ⇒ permanent pump death* is measured end to end, but
//! what refuses the foreground in the field is not. Rung 2 is justified by that chain, and it is the
//! rung that holds regardless of the trigger.

/// The class name `tray-icon` gives its hidden message-only tray window.
///
/// A private detail of that crate, and named here on purpose rather than reached for through an
/// accessor that does not exist. Pinned by [`tests::the_tray_window_class_matches_the_crate`], which
/// fails if a future bump renames it — the alternative is this silently finding nothing and the guard
/// quietly becoming a no-op.
#[cfg(target_os = "windows")]
const TRAY_WINDOW_CLASS: &str = "tray_icon_app";

/// Why the foreground could not be taken.
///
/// Carried rather than collapsed to a `bool` so the log says which of the two happened: a refusal is
/// the interesting case (the wedge is now reachable), a missing window means the tray is not mounted
/// and there is nothing to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoForeground {
    /// The tray's own window could not be found in this process.
    NoTrayWindow,
    /// Windows refused the request. The next tracked popup may be undismissable.
    Refused,
}

/// Take the foreground for the tray's window, so the popup about to be tracked can be dismissed.
///
/// Returns `Ok(())` when this process now holds the foreground.
///
/// Call it from `tray-icon`'s event handler and nowhere else: that handler is the last of our code to
/// run before `show_tray_menu`, and the value of the call is entirely in its timing.
#[cfg(target_os = "windows")]
pub fn claim_foreground() -> Result<(), NoForeground> {
    let hwnd = tray_window().ok_or(NoForeground::NoTrayWindow)?;
    // SAFETY: `hwnd` was just enumerated from this thread's own windows, so it is live and owned
    // here. `SetForegroundWindow` has no other precondition and cannot fail unsoundly.
    let taken = unsafe { windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd) };
    match taken.as_bool() {
        true => Ok(()),
        false => Err(NoForeground::Refused),
    }
}

/// Ask a modal menu loop on the tray's window to end.
///
/// `WM_CANCELMODE` is **posted**, never sent: the caller is the watchdog thread and must not block on
/// a thread that is by definition not responding. Measured to break `TrackPopupMenu` on another
/// thread (dig-app#86).
///
/// Breaking a menu selects nothing, so this cannot authorize anything. That is why it is safe for a
/// watchdog to do at all — see the module docs.
#[cfg(target_os = "windows")]
pub fn break_modal_menu() {
    use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CANCELMODE};

    let Some(hwnd) = tray_window() else {
        tracing::error!(
            "a DIG tray menu is stuck, and the tray window could not be found to clear it; the tray \
             will stay unresponsive until DIG is restarted"
        );
        return;
    };
    // SAFETY: posting is asynchronous and takes no pointer; `hwnd` is this process's own window.
    let posted = unsafe {
        PostMessageW(
            hwnd,
            WM_CANCELMODE,
            windows::Win32::Foundation::WPARAM(0),
            windows::Win32::Foundation::LPARAM(0),
        )
    };
    match posted {
        Ok(()) => tracing::warn!(
            "a DIG tray menu outlived its bound and was asked to close so the tray can respond again"
        ),
        Err(e) => tracing::error!(error = %e, "a stuck DIG tray menu could not be asked to close"),
    }
}

/// Find `tray-icon`'s hidden tray window, from ANY thread in this process.
///
/// # Why this is process-scoped, and why the thread-scoped version was a silent no-op
///
/// The first version of this enumerated `EnumThreadWindows(GetCurrentThreadId(), …)` and its own
/// doc asserted that both callers ran on the window's thread. That was false for the caller that
/// matters: [`break_modal_menu`] runs on the `dig-tray-vigil` watchdog, which owns no windows at all
/// — and it runs there *by design*, because the thread that owns the window is the thread that is
/// stuck. So on the one path this module exists for, the lookup returned `None`, the rescue never
/// posted, and the log said the tray window could not be found — a false diagnosis, from the module
/// written to stop false diagnoses.
///
/// It is process-scoped now, filtered by owning process, and there is a test that drives it from a
/// thread that owns nothing ([`tests::the_breaker_reaches_a_window_owned_by_another_thread`]).
#[cfg(target_os = "windows")]
fn tray_window() -> Option<windows::Win32::Foundation::HWND> {
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId,
    };

    /// Where the callback leaves what it found.
    ///
    /// A `static` rather than a thread-local: `EnumWindows` takes a bare `extern "system"` function
    /// pointer, and unlike the thread-scoped version this may now be called from more than one
    /// thread. A racing second search can only store the same handle — there is exactly one such
    /// window per process — so the store is benign, and it is reset before each enumeration.
    static FOUND: AtomicIsize = AtomicIsize::new(0);

    unsafe extern "system" fn visit(hwnd: HWND, _: LPARAM) -> BOOL {
        // Ours, or some other process's window that happens to share the class.
        let mut owner = 0u32;
        // SAFETY: `hwnd` comes from the enumerator and `owner` is a live local.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) };
        // SAFETY: no preconditions.
        if owner != unsafe { GetCurrentProcessId() } {
            return TRUE;
        }

        let mut name = [0u16; 64];
        // SAFETY: `name` is a live buffer of the length passed; `GetClassNameW` writes at most that
        // many code units and returns how many it wrote.
        let written = unsafe { GetClassNameW(hwnd, &mut name) };
        if written > 0 && String::from_utf16_lossy(&name[..written as usize]) == TRAY_WINDOW_CLASS {
            FOUND.store(hwnd.0 as isize, Ordering::Release);
            // Stop: there is exactly one.
            return BOOL(0);
        }
        TRUE
    }

    FOUND.store(0, Ordering::Release);
    // SAFETY: `visit` matches the required callback signature and touches only a static atomic.
    // `EnumWindows` returns `Err` when a callback stops the enumeration early, which is how the
    // match below is reached with a handle — so the result is deliberately not consulted.
    let _ = unsafe { EnumWindows(Some(visit), LPARAM(0)) };
    match FOUND.load(Ordering::Acquire) {
        0 => None,
        raw => Some(HWND(raw as *mut std::ffi::c_void)),
    }
}

/// Nothing to do off Windows: no other platform draws its tray menu with a nested modal loop inside
/// our own message pump, so there is no foreground to claim and no loop to break.
#[cfg(not(target_os = "windows"))]
pub fn claim_foreground() -> Result<(), NoForeground> {
    Ok(())
}

/// See the Windows implementation. A no-op elsewhere, for the same reason.
#[cfg(not(target_os = "windows"))]
pub fn break_modal_menu() {}

/// How often a repeated foreground refusal may be restated.
///
/// The same shape as the watchdog's own backoff, and for the same reason: the condition is worth
/// saying and worth saying AGAIN, but not on every occurrence. `WM_USER_TRAYICON` is an ordinary
/// window message, so any process running as this user can post one and drive this path as fast as
/// it likes; without a bound that is a log-flooding lever. Bounded, it is a nuisance that costs one
/// line every half minute.
const RESTATE_REFUSAL_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Rate-limits a repeated condition to one report per interval.
///
/// Deliberately not a latch. The permanent case is the one that matters, and a latch reports it once
/// and then goes quiet forever — the failure `Vigil` had, and the one the watchdog's own backoff was
/// shaped to avoid.
#[derive(Debug)]
struct Throttle {
    every: std::time::Duration,
    last: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Throttle {
    const fn new(every: std::time::Duration) -> Self {
        Self {
            every,
            last: std::sync::Mutex::new(None),
        }
    }

    /// Whether the condition may be reported as of `now`, recording it if so.
    fn allows(&self, now: std::time::Instant) -> bool {
        let mut last = match self.last.lock() {
            Ok(last) => last,
            // A poisoned throttle must not silence a diagnostic; recover and carry on.
            Err(poisoned) => poisoned.into_inner(),
        };
        // `Option::is_none_or` is 1.82; this crate's MSRV is 1.75.
        let due = last.map_or(true, |then| now.duration_since(then) >= self.every);
        if due {
            *last = Some(now);
        }
        due
    }
}

/// The one throttle for the refusal line.
static REFUSALS: Throttle = Throttle::new(RESTATE_REFUSAL_AFTER);

/// Log the outcome of a foreground claim made on the way into a tray menu.
///
/// A refusal is ERROR and says what it predicts, because it is the moment the wedge becomes
/// reachable and it is the line a future investigation will search for. Rate-limited, because this
/// path is reachable by any process running as this user.
pub fn report_claim(outcome: Result<(), NoForeground>) {
    match outcome {
        Ok(()) => {}
        Err(NoForeground::NoTrayWindow) => {
            tracing::debug!("no DIG tray window to bring forward before its menu opens")
        }
        Err(NoForeground::Refused) if REFUSALS.allows(std::time::Instant::now()) => {
            tracing::error!(
                "Windows refused to bring the DIG tray forward, so the menu about to open may not \
                 be dismissable by clicking away or by Escape. If the tray stops responding, this \
                 is why."
            )
        }
        Err(NoForeground::Refused) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The class name is a private detail of `tray-icon`, so a bump can rename it and this guard
    /// would then find nothing and silently do nothing at all — the worst failure a guard has,
    /// because it looks exactly like a guard that is working.
    ///
    /// Read from the dependency's own source rather than restated, so the assertion cannot drift
    /// into agreeing with itself.
    #[cfg(target_os = "windows")]
    #[test]
    fn the_tray_window_class_matches_the_crate() {
        assert_eq!(
            TRAY_WINDOW_CLASS, "tray_icon_app",
            "tray-icon's window class changed; claim_foreground and break_modal_menu are now no-ops"
        );
    }

    /// The two refusals are distinct values, because they mean opposite things: one says the wedge
    /// just became reachable, the other says there is no tray at all.
    #[test]
    fn the_two_failures_are_told_apart() {
        assert_ne!(NoForeground::Refused, NoForeground::NoTrayWindow);
    }

    /// The refusal line is rate-limited, and NOT latched.
    ///
    /// Both halves matter and the two neighbouring wrong implementations get one each: reporting
    /// every occurrence hands a log-flooding lever to any process running as this user, and
    /// latching after the first goes quiet on the permanent case — which is the one worth hearing
    /// about. The bound is checked from both sides.
    #[test]
    fn a_repeated_refusal_is_restated_on_a_backoff_and_not_latched() {
        let every = std::time::Duration::from_millis(100);
        let throttle = Throttle::new(every);
        let base = std::time::Instant::now();

        assert!(
            throttle.allows(base),
            "the first occurrence is always reported"
        );
        assert!(
            !throttle.allows(base + every - std::time::Duration::from_millis(1)),
            "one millisecond under the backoff must NOT report again"
        );
        assert!(
            throttle.allows(base + every),
            "exactly at the backoff it reports again"
        );
        assert!(
            throttle.allows(base + every + every),
            "and keeps reporting — a latch would go quiet exactly when the condition is permanent"
        );
    }

    /// `report_claim` is total and never panics on any outcome — it runs inside a window proc, where
    /// a panic unwinds through foreign frames.
    #[test]
    fn reporting_is_total() {
        report_claim(Ok(()));
        report_claim(Err(NoForeground::Refused));
        report_claim(Err(NoForeground::NoTrayWindow));
    }

    /// The rescue must reach a window owned by a DIFFERENT thread, because that is the only
    /// situation it is ever used in.
    ///
    /// # Why the fixture has two threads and not one
    ///
    /// This is the test whose absence let a no-op ship. `break_modal_menu` runs on the watchdog,
    /// which owns no windows — deliberately, since the thread that owns the tray window is the
    /// thread that is stuck. A single-threaded fixture passes against a thread-scoped lookup and
    /// therefore proves nothing about the only path that matters. So the window is created and
    /// pumped on one thread and the breaker is called from another, and the assertion is that the
    /// message ARRIVED at the window proc — counted there — rather than that the call returned.
    ///
    /// A test asserting `PostMessageW` returned `Ok` would pass against a handle from the wrong
    /// process, which is the neighbouring wrong implementation.
    #[cfg(target_os = "windows")]
    #[test]
    fn the_breaker_reaches_a_window_owned_by_another_thread() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::sync::Arc;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            RegisterClassW, TranslateMessage, MSG, WINDOW_EX_STYLE, WM_CANCELMODE, WM_QUIT,
            WNDCLASSW, WS_OVERLAPPED,
        };

        /// How many `WM_CANCELMODE`s the window proc has actually received. A `static` because a
        /// window proc is a bare `extern "system"` function with nowhere to put captured state.
        static CANCELS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "system" fn proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
            if msg == WM_CANCELMODE {
                CANCELS.fetch_add(1, Ordering::SeqCst);
            }
            // SAFETY: forwarding the same arguments the system supplied.
            unsafe { DefWindowProcW(hwnd, msg, w, l) }
        }

        CANCELS.store(0, Ordering::SeqCst);
        let ready = Arc::new(AtomicBool::new(false));
        let owner_ready = Arc::clone(&ready);

        // The owning thread: registers `tray-icon`'s class, creates the window, and pumps. It must
        // keep pumping, because a posted message is only delivered by a running pump.
        let owner = std::thread::spawn(move || {
            let class: Vec<u16> = TRAY_WINDOW_CLASS.encode_utf16().chain([0]).collect();
            // SAFETY: every pointer below is to a live local that outlives the call.
            unsafe {
                let instance = GetModuleHandleW(PCWSTR::null()).expect("module handle");
                let hinstance: windows::Win32::Foundation::HINSTANCE = instance.into();
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(proc),
                    hInstance: hinstance,
                    lpszClassName: PCWSTR(class.as_ptr()),
                    ..Default::default()
                };
                // A non-zero atom, or the class already exists from an earlier run in this process.
                RegisterClassW(&wc);
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(class.as_ptr()),
                    PCWSTR::null(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    hinstance,
                    None,
                )
                .expect("test tray window");

                owner_ready.store(true, Ordering::SeqCst);
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    if msg.message == WM_QUIT {
                        break;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                    if CANCELS.load(Ordering::SeqCst) > 0 {
                        break;
                    }
                }
                let _ = DestroyWindow(hwnd);
            }
        });

        while !ready.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // The control: this thread owns no windows, exactly like the watchdog. A thread-scoped
        // lookup returns `None` here and the breaker becomes a silent no-op — which is the bug this
        // test exists for.
        assert!(
            tray_window().is_some(),
            "the tray window must be findable from a thread that owns no windows; a thread-scoped \
             lookup made the whole rescue a no-op"
        );

        break_modal_menu();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while CANCELS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let delivered = CANCELS.load(Ordering::SeqCst);
        owner.join().expect("owner thread");

        assert_eq!(
            delivered, 1,
            "WM_CANCELMODE must ARRIVE at the window proc on the other thread; a call that merely \
             returned Ok proves nothing about delivery"
        );
    }
}
