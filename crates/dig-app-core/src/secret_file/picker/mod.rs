//! Ask the user where to put a file, using the platform's own save dialog.
//!
//! # Why a seam rather than a function
//!
//! Raising a save dialog is untestable by nature — it waits for a human. What is NOT untestable is
//! everything that hangs off the ANSWER: a cancel must abandon the write, an unavailable dialog
//! must fall back rather than fail, and neither must ever be confused for the other. So the OS call
//! sits behind [`SaveFilePicker`] and the decision it feeds lives in
//! [`super::choose_secret_file_path`], where a test drives all three answers.
//!
//! # Why these three platform implementations
//!
//! * **Windows** — `GetSaveFileNameW`, the common-dialog entry point, called directly. It is
//!   preferred over the COM `IFileSaveDialog` because it needs no apartment initialisation, and
//!   this process already joins the MTA for WinRT elsewhere (dig_ecosystem#1926).
//! * **macOS and Linux** — the desktop's own dialog helper, driven as a subprocess: `osascript`'s
//!   `choose file name` and `zenity`/`kdialog` respectively.
//!
//! The macOS choice is deliberate and worth stating, because `NSSavePanel` is right there in a
//! crate this binary already links. A panel has to be driven on the main thread, its modal loop
//! re-enters the tray's, and none of that is verifiable from the machines this code is written and
//! reviewed on — whereas a one-line `osascript` invocation is verifiable by reading it, matches how
//! this codebase already raises Linux dialogs, and adds no dependency surface to a binary holding a
//! master seed. If the panel is ever wanted, this is the one seam it has to satisfy.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// What to show the user when asking them where to save.
pub struct SaveFileRequest<'a> {
    /// The dialog's title. Names the thing being saved, in the user's terms.
    pub title: &'a str,
    /// The file name to offer, pre-filled and editable.
    pub file_name: &'a str,
    /// The folder to open in. `None` lets the platform pick its usual default.
    pub starting_dir: Option<&'a Path>,
}

/// The user's answer to [`SaveFilePicker::ask`].
///
/// [`Cancelled`](Self::Cancelled) and [`Unavailable`](Self::Unavailable) are kept apart because
/// they mean opposite things: one is the user declining, the other is the machine being unable to
/// ask. Collapsing them would either write a secret the user just refused, or refuse to write one
/// on every host without a desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickedPath {
    /// The user chose this path.
    Chosen(PathBuf),
    /// The user dismissed the dialog. Nothing is to be written.
    Cancelled,
    /// No dialog could be raised here — a headless host, or no desktop helper installed.
    Unavailable,
}

/// Ask the user where a file should be written.
pub trait SaveFilePicker {
    /// Raise the platform's save dialog and block until the user answers.
    ///
    /// Implementations MUST return [`PickedPath::Unavailable`] rather than a guessed path when no
    /// dialog can be raised, and MUST NOT treat a dismissal as an error.
    fn ask(&self, request: &SaveFileRequest<'_>) -> PickedPath;
}

/// The platform's own save dialog.
pub struct NativeSavePicker;

impl SaveFilePicker for NativeSavePicker {
    fn ask(&self, request: &SaveFileRequest<'_>) -> PickedPath {
        #[cfg(windows)]
        {
            windows::ask(request)
        }
        #[cfg(target_os = "macos")]
        {
            macos::ask(request)
        }
        #[cfg(target_os = "linux")]
        {
            linux::ask(request)
        }
        // Any other target has no dialog to raise, and saying so is the honest answer: the caller
        // falls back to a known path rather than being handed a guess.
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = request;
            PickedPath::Unavailable
        }
    }
}
