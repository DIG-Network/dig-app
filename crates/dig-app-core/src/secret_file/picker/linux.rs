//! The Linux save dialog, driven through the desktop's own helper.
//!
//! Same shape, and the same two helpers, as the confirm windows: `zenity` on GNOME/GTK and
//! `kdialog` on KDE. Both exit `0` when the user picks a file and `1` when they dismiss the dialog,
//! and both print the chosen path on stdout.

use std::path::PathBuf;
use std::process::Command;

use super::{PickedPath, SaveFileRequest};

/// Raise the save dialog and block until the user answers.
pub(super) fn ask(request: &SaveFileRequest<'_>) -> PickedPath {
    // A dialog helper on a host with no display will fail in its own way and at its own pace; ask
    // the cheap question first so a headless agent falls back immediately instead of waiting.
    if !has_display(|name| std::env::var_os(name)) {
        return PickedPath::Unavailable;
    }

    let suggested = request.starting_dir.map_or_else(
        || PathBuf::from(request.file_name),
        |dir| dir.join(request.file_name),
    );

    for helper in [Helper::Zenity, Helper::Kdialog] {
        match helper.ask(request.title, &suggested) {
            // A real answer from the user. Done.
            Some(answer @ (PickedPath::Chosen(_) | PickedPath::Cancelled)) => return answer,
            // This helper could not ask — it is not installed, it could not reach the display, or
            // it rejected an option a newer version renamed. Try the other one before giving up:
            // returning here would send the seed to the fixed fallback path, which is the outcome
            // this whole feature exists to avoid, on a desktop that may well have the other helper.
            Some(PickedPath::Unavailable) | None => continue,
        }
    }
    PickedPath::Unavailable
}

/// True when `lookup` reports a display server to draw a dialog on.
///
/// The environment is a parameter rather than read directly so this stays a pure decision a test can
/// drive — including the case a `is_some()` check gets wrong, where the variable is SET but empty,
/// which is what a stripped systemd unit or a `su` into another account tends to leave behind.
fn has_display(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|name| lookup(name).is_some_and(|value| !value.is_empty()))
}

#[derive(Clone, Copy)]
enum Helper {
    /// GNOME/GTK.
    Zenity,
    /// KDE.
    Kdialog,
}

impl Helper {
    /// Run this helper, or return `None` if it is not installed.
    fn ask(self, title: &str, suggested: &std::path::Path) -> Option<PickedPath> {
        let output = Command::new(self.program())
            .args(self.args(title, suggested))
            .output()
            .ok()?;
        Some(interpret(output.status.code(), &output.stdout))
    }

    fn program(self) -> &'static str {
        match self {
            Self::Zenity => "zenity",
            Self::Kdialog => "kdialog",
        }
    }

    /// The helper's own spelling of "save-file dialog, titled this, pre-filled with that".
    ///
    /// The title reaches these as a separate argv entry rather than inside a formatted string, so
    /// there is no shell to quote for and nothing here can be read as an option or as markup.
    fn args(self, title: &str, suggested: &std::path::Path) -> Vec<String> {
        let suggested = suggested.to_string_lossy().into_owned();
        match self {
            Self::Zenity => vec![
                "--file-selection".to_string(),
                "--save".to_string(),
                "--confirm-overwrite".to_string(),
                "--title".to_string(),
                title.to_string(),
                "--filename".to_string(),
                suggested,
            ],
            Self::Kdialog => vec![
                "--getsavefilename".to_string(),
                suggested,
                "*.txt|Text file".to_string(),
                "--title".to_string(),
                title.to_string(),
            ],
        }
    }
}

/// Read a helper's exit code and stdout as the user's answer.
///
/// `0` is a chosen path and `1` is a dismissal, in both helpers. Anything else — a helper that could
/// not reach the display, one killed by a signal, a version that failed to parse its own arguments —
/// is the MACHINE failing rather than the user declining, and must not be read as a refusal: a
/// refusal abandons the backup, where an unavailable dialog falls back to a known path.
fn interpret(code: Option<i32>, stdout: &[u8]) -> PickedPath {
    match code {
        Some(0) => {
            let path = String::from_utf8_lossy(stdout).trim().to_string();
            if path.is_empty() {
                PickedPath::Unavailable
            } else {
                PickedPath::Chosen(PathBuf::from(path))
            }
        }
        Some(1) => PickedPath::Cancelled,
        _ => PickedPath::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{has_display, interpret, Helper, PickedPath};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// Look up `name` in a fixed set, as `std::env::var_os` would.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(*value))
        }
    }

    #[test]
    fn either_display_variable_means_there_is_a_display() {
        assert!(has_display(env(&[("DISPLAY", ":0")])));
        assert!(has_display(env(&[("WAYLAND_DISPLAY", "wayland-0")])));
    }

    #[test]
    fn no_display_variable_means_headless() {
        assert!(!has_display(env(&[])));
        assert!(!has_display(env(&[("HOME", "/root")])));
    }

    /// A variable that is SET but EMPTY is not a display — the case a bare `is_some()` gets wrong,
    /// and the one a stripped service environment actually produces.
    #[test]
    fn an_empty_display_variable_is_not_a_display() {
        assert!(!has_display(env(&[
            ("DISPLAY", ""),
            ("WAYLAND_DISPLAY", "")
        ])));
    }

    #[test]
    fn a_chosen_path_comes_back_trimmed() {
        assert_eq!(
            interpret(Some(0), b"/media/usb/words.txt\n"),
            PickedPath::Chosen(PathBuf::from("/media/usb/words.txt")),
            "the helper prints the path with a trailing newline"
        );
    }

    #[test]
    fn a_dismissal_is_a_cancel() {
        assert_eq!(interpret(Some(1), b""), PickedPath::Cancelled);
    }

    /// The distinction the whole fallback rests on: a helper that FAILED is not a user who said no.
    #[test]
    fn a_failing_helper_is_unavailable_rather_than_a_refusal() {
        for code in [Some(2), Some(5), Some(127), None] {
            assert_eq!(
                interpret(code, b""),
                PickedPath::Unavailable,
                "exit {code:?} is the helper failing, and must not abandon the backup"
            );
        }
    }

    /// A success that names no file is not a choice either — falling back beats writing to `""`.
    #[test]
    fn success_with_no_path_is_unavailable() {
        assert_eq!(interpret(Some(0), b"   \n"), PickedPath::Unavailable);
    }

    /// The title and the pre-filled path travel as their own argv entries, so a folder name
    /// containing a space, a quote, or a leading dash cannot become an option or a second argument.
    #[test]
    fn the_suggested_path_is_one_argument_whatever_is_in_it() {
        let awkward = Path::new("/home/a b/--not-a-flag/my \"words\".txt");

        for helper in [Helper::Zenity, Helper::Kdialog] {
            let args = helper.args("Save your DIG recovery phrase", awkward);
            assert!(
                args.iter()
                    .any(|arg| arg == "/home/a b/--not-a-flag/my \"words\".txt"),
                "{} must pass the path verbatim as a single argument, got {args:?}",
                helper.program()
            );
            assert!(
                args.iter()
                    .any(|arg| arg == "Save your DIG recovery phrase"),
                "{} must pass the title verbatim as a single argument",
                helper.program()
            );
        }
    }

    /// Both helpers are asked for a SAVE dialog, not an open one — the difference decides whether
    /// the user can name a file that does not exist yet.
    #[test]
    fn both_helpers_are_asked_for_a_save_dialog() {
        let path = Path::new("/home/dig/dig-recovery-phrase.txt");

        assert!(Helper::Zenity
            .args("t", path)
            .contains(&"--save".to_string()));
        assert!(Helper::Kdialog
            .args("t", path)
            .contains(&"--getsavefilename".to_string()));
    }
}
