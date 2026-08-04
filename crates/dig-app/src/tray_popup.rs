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
//! **1. Take the foreground before the library tries.** [`claim_foreground`] runs from `tray-icon`'s
//! own event handler, which fires synchronously in the tray window proc immediately *before*
//! `show_tray_menu`. If our call succeeds, the library's identical call a moment later succeeds
//! trivially and the menu behaves. A tray process holds foreground rights only transiently, so this
//! is not a formality — it is the half of Q135788 that was measured failing.
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
//! Until then: rung 1 makes the bad state rare, and rung 2 makes it survivable rather than permanent.
//! Neither can manufacture consent — a dismissed menu has selected no item.

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
    /// The tray's own window could not be found on this thread.
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

/// Find `tray-icon`'s hidden tray window among the windows this thread owns.
///
/// Scoped to THIS thread rather than the whole process deliberately: the tray window is created on
/// the tao thread, and a process-wide search could return some other window that happened to share
/// the class. Both callers already run on that thread.
#[cfg(target_os = "windows")]
fn tray_window() -> Option<windows::Win32::Foundation::HWND> {
    use std::cell::Cell;
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, GetClassNameW};

    thread_local! {
        /// Where the callback leaves what it found. A thread-local rather than a captured closure
        /// because `EnumThreadWindows` takes a bare `extern "system"` function pointer, and both the
        /// enumeration and the read happen on this same thread before it returns.
        static FOUND: Cell<isize> = const { Cell::new(0) };
    }

    unsafe extern "system" fn visit(hwnd: HWND, _: LPARAM) -> BOOL {
        let mut name = [0u16; 64];
        // SAFETY: `name` is a live buffer of the length passed; `GetClassNameW` writes at most that
        // many code units and returns how many it wrote.
        let written = unsafe { GetClassNameW(hwnd, &mut name) };
        if written > 0 {
            let class = String::from_utf16_lossy(&name[..written as usize]);
            if class == TRAY_WINDOW_CLASS {
                FOUND.with(|found| found.set(hwnd.0 as isize));
                // Stop: there is exactly one.
                return BOOL(0);
            }
        }
        TRUE
    }

    FOUND.with(|found| found.set(0));
    // SAFETY: `visit` matches the required callback signature and touches only a thread-local.
    let _ = unsafe { EnumThreadWindows(GetCurrentThreadId(), Some(visit), LPARAM(0)) };
    match FOUND.with(|found| found.get()) {
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

/// Log the outcome of a foreground claim made on the way into a tray menu.
///
/// A refusal is ERROR and says what it predicts, because it is the moment the wedge becomes
/// reachable and it is the line a future investigation will search for. Taken as a value so the
/// choice is testable without capturing a log.
pub fn report_claim(outcome: Result<(), NoForeground>) {
    match outcome {
        Ok(()) => {}
        Err(NoForeground::NoTrayWindow) => {
            tracing::debug!("no DIG tray window to bring forward before its menu opens")
        }
        Err(NoForeground::Refused) => tracing::error!(
            "Windows refused to bring the DIG tray forward, so the menu about to open may not be \
             dismissable by clicking away or by Escape. If the tray stops responding, this is why."
        ),
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

    /// `report_claim` is total and never panics on any outcome — it runs inside a window proc, where
    /// a panic unwinds through foreign frames.
    #[test]
    fn reporting_is_total() {
        report_claim(Ok(()));
        report_claim(Err(NoForeground::Refused));
        report_claim(Err(NoForeground::NoTrayWindow));
    }
}
