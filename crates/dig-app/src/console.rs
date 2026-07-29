//! Giving a GUI-subsystem binary somewhere to print (dig_ecosystem#1797).
//!
//! # The problem, and the trap
//!
//! `dig-app` is a tray application, so its PE header declares the **`WINDOWS_GUI` subsystem** (2). Until
//! #1797 it declared `WINDOWS_CUI` (3), which made Windows allocate a console for it: a black window
//! appeared at every launch, and the tray's lifetime was tied to that window — closing it killed the
//! agent. WireGuard's tray application on the same machine is subsystem 2; `dig-node` is 3 and correctly
//! so, because it is a service and a CLI.
//!
//! The trap is that a GUI-subsystem process **has no console**, so `println!` writes to an invalid handle
//! and vanishes. That matters here for one specific, load-bearing reason: the update beacon health-gates
//! this component by spawning `dig-app --version` and requiring one line on stdout within ten seconds
//! (`dig_updater_broker::probe`). Flipping the subsystem without this module would silently regress
//! `--version` to empty output — reintroducing the exact defect #1749 closed.
//!
//! # What [`attach_to_parent`] does, and the case it must not break
//!
//! It attaches to the console of whichever process launched us (`cmd.exe`, PowerShell, Windows Terminal)
//! and re-points the C/Rust standard handles at it. The subtlety is **redirection**: when stdout is a pipe
//! or a file — which is exactly how the update beacon reads `--version` — the inherited handle is already
//! valid and must be left alone. Overwriting it with `CONOUT$` would send the version line to a console
//! the beacon is not reading and hand it an empty answer. So the re-point is conditional on the inherited
//! handle being absent, never unconditional.
//!
//! On every non-Windows target this is a no-op: those platforms give a process its inherited standard
//! streams regardless of any subsystem notion.

/// Attach this process to its parent's console, if it has none of its own.
///
/// Call this ONLY on the code paths that print for a human or a machine (`--version`, `--help`, a
/// start-up failure). It is deliberately not called unconditionally at start-up: a tray application that
/// grabbed its launcher's console on every run would print agent chatter into the user's shell.
///
/// Returns whether a console is now available. The caller does not need to branch on it — printing to an
/// unattached handle is a harmless no-op — but the tests do, and it makes the fallible step visible rather
/// than swallowed.
#[cfg(target_os = "windows")]
pub fn attach_to_parent() -> bool {
    use windows::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };

    // SAFETY: all four calls take/return plain handles. `AttachConsole` fails harmlessly when there is no
    // parent console (a launch from Explorer or a service manager) or when one is already attached, which is
    // why its result is inspected rather than propagated.
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return false;
        }
        // Re-point ONLY the handles we do not already have. See the module docs: clobbering a redirected
        // stdout is how the update beacon's `--version` probe would start reading nothing.
        for (slot, name) in [
            (STD_OUTPUT_HANDLE, windows::core::w!("CONOUT$")),
            (STD_ERROR_HANDLE, windows::core::w!("CONOUT$")),
        ] {
            let inherited = GetStdHandle(slot);
            if inherited
                .map(|handle| !handle.is_invalid())
                .unwrap_or(false)
            {
                continue;
            }
            if let Ok(console) = open_console(name) {
                let _ = SetStdHandle(slot, console);
            }
        }
        true
    }
}

/// Open the console's own output device (`CONOUT$`) for writing.
///
/// # Safety
///
/// A console must already be attached; `name` must be a valid NUL-terminated wide string.
#[cfg(target_os = "windows")]
unsafe fn open_console(
    name: windows::core::PCWSTR,
) -> windows::core::Result<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    CreateFileW(
        name,
        FILE_GENERIC_WRITE.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
}

/// Non-Windows hosts hand a process its standard streams regardless of any subsystem notion, so there is
/// nothing to attach.
#[cfg(not(target_os = "windows"))]
pub fn attach_to_parent() -> bool {
    true
}
