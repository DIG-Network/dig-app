//! The global shortcut against the REAL operating system (dig_ecosystem#1839).
//!
//! # Why these are integration tests and not unit tests
//!
//! Everything decidable about a shortcut is unit-tested in `dig_app_core::hotkey`. What is left is the
//! only part that can actually be wrong in the field: whether the OS gives us the chord, whether it tells
//! us when it will not, and whether a press reaches us when **nothing of ours has focus**. None of that is
//! expressible against a fake — a mock `RegisterHotKey` that returns what we told it to proves nothing
//! about Windows.
//!
//! So these call the real API. They deliberately use an obscure chord rather than the shipped `Alt+Space`,
//! because a test that ran on a developer's desktop must not take the shortcut out from under whatever
//! they are doing, and the properties under test are chord-independent.

#![cfg(all(windows, feature = "tray"))]

use dig_app_core::hotkey::{Hotkey, HotkeyState};
use std::sync::mpsc;
use std::time::Duration;

/// The chord these tests claim. `Ctrl+Alt+Shift+F24` is not a shortcut any shipping application uses, so
/// running the suite cannot collide with the developer's desktop — or with `Alt+Space`, which the app
/// itself may be holding on this very machine.
const TEST_CHORD: &str = "Ctrl+Alt+Shift+F24";

/// **The graceful-degradation path, against the real OS.**
///
/// A second claim on a chord the OS has already given away MUST report [`HotkeyState::Unavailable`] and
/// leave the first registration alone. This is the field scenario exactly — another launcher already owns
/// the chord — reproduced without needing that other launcher, because `RegisterHotKey` is desktop-wide
/// and does not care that both claims came from one process.
///
/// The FIRST claim is asserted `Registered` in the same test on purpose. Without it, an `install` that had
/// simply broken and returned `Unavailable` for everything would satisfy the second assertion perfectly —
/// the honest control is what makes the failure assertion mean anything.
#[test]
fn a_chord_another_holder_already_owns_degrades_and_never_fails_the_caller() {
    let chord = Hotkey::parse(TEST_CHORD).unwrap();

    let first = dig_app::hotkey::install(Ok(chord), || {});
    assert_eq!(
        first,
        HotkeyState::Registered(chord),
        "the OS refused a chord nothing should own — is another test run still live?"
    );

    let second = dig_app::hotkey::install(Ok(chord), || {});
    match second {
        HotkeyState::Unavailable { hotkey, reason } => {
            assert_eq!(hotkey, chord, "the report must name the chord that failed");
            assert!(
                !reason.is_empty(),
                "a failure with no reason explains nothing"
            );
            // The user must be pointed at the route that still works, from the state alone.
            let summary = HotkeyState::Unavailable {
                hotkey,
                reason: reason.clone(),
            }
            .summary();
            assert!(summary.contains("Open URL…"), "{summary}");
        }
        other => panic!("a chord already taken must degrade, got {other:?}"),
    }

    // The first claim is still live: a failed second claim must not have released what it could not take.
    assert!(
        matches!(
            dig_app::hotkey::install(Ok(chord), || {}),
            HotkeyState::Unavailable { .. }
        ),
        "a refused claim must not have freed the chord the first one holds"
    );
}

/// A shortcut the user mistyped never reaches the OS, and never claims a chord.
#[test]
fn a_malformed_setting_is_reported_and_nothing_is_claimed() {
    let state = dig_app::hotkey::install(Hotkey::parse("Ctrl+Banana"), || {});
    match &state {
        HotkeyState::Unsupported { reason } => assert!(reason.contains("Banana"), "{reason}"),
        other => panic!("a typo must be reported as its own problem, got {other:?}"),
    }
    assert_eq!(state.shortcut(), None, "nothing may be advertised");
}

/// **The whole point of a GLOBAL hotkey: it fires when nothing of ours has focus.**
///
/// The chord is registered on a background thread that owns **no window at all** — it cannot be the
/// foreground window, cannot receive focus, and has no window procedure. The keystroke is then synthesized
/// with `SendInput`, which posts to the desktop's input queue exactly as a physical key does, and is
/// delivered by Windows to the registering thread's queue because the hotkey is global. If the shortcut
/// only worked while a DIG window had focus, this test could not pass: there is no DIG window.
///
/// Ignored by default because `SendInput` requires an interactive, UNLOCKED desktop session — on a locked
/// desktop or a headless CI agent the input goes to a different desktop and never arrives, which would be
/// a flake rather than a finding. Run it deliberately:
///
/// ```text
/// cargo test -p dig-app --test global_hotkey -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs an interactive, unlocked desktop session (SendInput)"]
fn the_chord_fires_when_no_window_of_ours_has_focus() {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
        VIRTUAL_KEY,
    };

    let chord = Hotkey::parse(TEST_CHORD).unwrap();
    let (pressed, presses) = mpsc::channel();
    let state = dig_app::hotkey::install(Ok(chord), move || {
        let _ = pressed.send(());
    });
    assert_eq!(state, HotkeyState::Registered(chord));

    /// `VK_CONTROL`, `VK_MENU` (Alt), `VK_SHIFT` — the modifiers of [`TEST_CHORD`].
    const MODIFIERS: [u16; 3] = [0x11, 0x12, 0x10];

    let key = |vk: u16, up: bool| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: match up {
                    true => KEYEVENTF_KEYUP,
                    false => KEYBD_EVENT_FLAGS(0),
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    let mut events: Vec<INPUT> = MODIFIERS.iter().map(|vk| key(*vk, false)).collect();
    events.push(key(chord.virtual_key() as u16, false));
    events.push(key(chord.virtual_key() as u16, true));
    events.extend(MODIFIERS.iter().rev().map(|vk| key(*vk, true)));

    // SAFETY: a documented call over a slice of well-formed `INPUT` structures.
    let sent = unsafe { SendInput(&events, std::mem::size_of::<INPUT>() as i32) };
    assert_eq!(
        sent as usize,
        events.len(),
        "the keystroke could not be synthesized — is the desktop locked?"
    );

    // A locked desktop is the one false negative to rule out FIRST: `SendInput` still reports success
    // there (it queued the events), but the session's input goes to the Winlogon desktop and never
    // reaches ours — which looks identical to a shortcut that does not work.
    presses.recv_timeout(Duration::from_secs(5)).expect(
        "the chord did not reach the app with no window of ours in the foreground — if the session \
         was LOCKED, that is why: unlock it and run this test again",
    );
}
