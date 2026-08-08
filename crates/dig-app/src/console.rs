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

/// Spawn `command` without letting Windows give the child a console window (dig_ecosystem#2311).
///
/// # The mirror image of this module's other problem
///
/// [`attach_to_parent`] exists because this process has NO console and sometimes needs one. This
/// exists because the processes it spawns DO get one and must not: `dig-updater`, and the clipboard
/// helpers, are console-subsystem binaries, so Windows allocates a console for each child and paints a
/// real window for as long as it runs. From a GUI parent that reads as the application flashing a
/// black box — and a caller that spawns on a timer flashes one every tick, which is how #2311 was
/// found by a user rather than by a test.
///
/// `CREATE_NO_WINDOW` suppresses the console without suppressing the child: stdout and stderr are still
/// captured normally, which is the whole point, since every caller here is reading the child's output.
///
/// # When NOT to use it
///
/// Only for children whose output DIG consumes. A child the user is meant to see — an opener, a
/// launched application, the elevation helper that raises the UAC prompt — must keep its normal
/// creation flags.
///
/// On every non-Windows target this is a no-op returning the command unchanged, so call sites stay
/// free of `cfg` noise.
pub fn without_console_window(command: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// `CREATE_NO_WINDOW`, taken from the Win32 metadata rather than written out as a literal.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = windows::Win32::System::Threading::CREATE_NO_WINDOW.0;

#[cfg(all(test, target_os = "windows"))]
mod tests {
    /// The flag is the documented `CREATE_NO_WINDOW`, pinned against a second, independent source.
    ///
    /// Whether a console window appears is an OS-level effect no unit test can observe — a test binary
    /// is console-subsystem, so its children inherit a console and nothing is painted either way. What
    /// CAN be pinned is that the value we pass is the right one, and pinning it against the constant we
    /// already read from the Win32 metadata would only prove that constant equals itself. So the literal
    /// here comes from the Win32 documentation, and disagreement means one of the two moved.
    #[test]
    fn the_suppression_flag_is_the_documented_win32_value() {
        assert_eq!(
            super::CREATE_NO_WINDOW,
            0x0800_0000,
            "CREATE_NO_WINDOW is documented as 0x08000000; a different value here suppresses nothing"
        );
    }
}
