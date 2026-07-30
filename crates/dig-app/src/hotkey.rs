//! Claiming the global shortcut from the OS (dig_ecosystem#1839) — the platform half.
//!
//! Everything decidable lives in [`dig_app_core::hotkey`]: which chord, whether it is expressible, what
//! the app says about it. This module does one thing that cannot be tested from a `cargo test` process —
//! ask Windows for the chord and deliver the presses — and it is deliberately the whole of what is not
//! covered by a unit test, in the same spirit as the tray's `render`.
//!
//! # Why a dedicated thread with its own message loop
//!
//! `RegisterHotKey(NULL, …)` posts `WM_HOTKEY` to the message queue of the **thread that registered it**,
//! and it is a THREAD message with no window attached, so it never reaches a window procedure. Handing it
//! to tao's event loop would mean depending on tao forwarding a message it has no reason to surface, and
//! would couple the launcher's latency to the tray's 500 ms repaint tick — a launcher that opens a third
//! of a second after the keystroke feels broken.
//!
//! So the shortcut owns a thread: it registers, then pumps its own queue and calls back on each press.
//! The bar it opens is drawn by the same window class every other DIG window uses, which already runs its
//! own modal message loop on whatever thread calls it — so the bar is drawn ON this thread and the tray's
//! loop is never blocked by a user standing at the bar.
//!
//! # Release
//!
//! Windows unregisters a thread's hotkeys when the thread ends, and this thread ends only with the
//! process, so quitting DIG releases the chord — there is no state to unwind and no path on which the
//! chord outlives the app.

use dig_app_core::hotkey::{Hotkey, HotkeyError, HotkeyState};

/// Claim `shortcut` system-wide and call `on_press` on each press.
///
/// Returns what to tell the user ([`HotkeyState`]), which is the whole point of the return value: this
/// **never fails the caller**. A chord another application already owns, a desktop with no global-shortcut
/// mechanism, and a config file with a typo all produce a state the tray reports in `Status` while the
/// `Open URL…` row goes on working exactly as before. Starting the app must never depend on a shortcut.
///
/// `shortcut` arrives as a `Result` rather than a `Hotkey` so a MALFORMED setting keeps its own error
/// message all the way to the user — see [`dig_app_core::config::AgentConfig::open_bar_shortcut`].
pub fn install(
    shortcut: Result<Hotkey, HotkeyError>,
    on_press: impl Fn() + Send + 'static,
) -> HotkeyState {
    let hotkey = match shortcut {
        Ok(hotkey) => hotkey,
        // Nothing was attempted, so there is no chord to report as unavailable — only a setting to fix.
        Err(e) => {
            tracing::warn!(error = %e, "the configured shortcut could not be understood");
            return HotkeyState::Unsupported {
                reason: format!("the shortcut in your settings is not valid — {e}"),
            };
        }
    };
    let state = claim(hotkey, on_press);
    match &state {
        HotkeyState::Registered(hotkey) => tracing::info!(%hotkey, "the DIG bar shortcut is live"),
        // Not an error: another launcher holding the chord is an ordinary desktop, and the tray route is
        // untouched. Logged at warn so it is findable when a user asks why the chord does nothing.
        other => tracing::warn!(summary = %other.summary(), "no DIG bar shortcut"),
    }
    state
}

/// Ask the platform for the chord. Windows only, so far.
#[cfg(not(windows))]
fn claim(_hotkey: Hotkey, _on_press: impl Fn() + Send + 'static) -> HotkeyState {
    // Honest rather than aspirational. macOS needs a `CGEventTap`/`NSEvent` global monitor, which requires
    // the user to grant Accessibility permission — a consent flow, not a function call. Under Wayland a
    // global grab is simply not available to an ordinary client at all; the compositor owns shortcuts. Both
    // are real work with real user-visible consent steps, and claiming otherwise here would ship a chord
    // that silently does nothing on two of three platforms.
    HotkeyState::Unsupported {
        reason: "global shortcuts are not available on this platform yet".to_string(),
    }
}

#[cfg(windows)]
fn claim(hotkey: Hotkey, on_press: impl Fn() + Send + 'static) -> HotkeyState {
    use std::sync::mpsc;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, HOT_KEY_MODIFIERS};
    use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

    /// This process's id for the chord. Any value in 0x0000–0xBFFF is ours to choose; there is only one.
    const HOTKEY_ID: i32 = 1;

    let (report, registered) = mpsc::channel();
    std::thread::Builder::new()
        .name("dig-bar-hotkey".to_string())
        .spawn(move || {
            // SAFETY: `RegisterHotKey` with a null window registers against THIS thread's queue, which is
            // the queue pumped below. Both arguments come from the unit-tested `hotkey` model.
            let claimed = unsafe {
                RegisterHotKey(
                    HWND::default(),
                    HOTKEY_ID,
                    HOT_KEY_MODIFIERS(hotkey.modifiers()),
                    hotkey.virtual_key(),
                )
            };
            // Report BEFORE pumping: the caller is blocked on this, and the loop below never returns.
            let _ = report.send(claimed.as_ref().err().map(|e| e.message()));
            if claimed.is_err() {
                return;
            }
            let mut message = MSG::default();
            // SAFETY: a documented message loop over this thread's own queue with a valid out-param.
            while unsafe { GetMessageW(&mut message, HWND::default(), 0, 0) }.as_bool() {
                if message.message == WM_HOTKEY {
                    on_press();
                }
            }
        })
        // A thread that will not spawn is not a chord that is taken — say what happened rather than
        // implying another application holds it.
        .map_err(|e| e.to_string())
        .and_then(|_| registered.recv().map_err(|e| e.to_string()))
        .map_or_else(
            |reason| HotkeyState::Unavailable { hotkey, reason },
            |failure| match failure {
                None => HotkeyState::Registered(hotkey),
                // The overwhelmingly common cause, and the one the OS error text does not name: Windows
                // says only "Hot key is already registered", never by whom.
                Some(message) => HotkeyState::Unavailable {
                    hotkey,
                    reason: format!("{message} — another application is probably using it"),
                },
            },
        )
}
