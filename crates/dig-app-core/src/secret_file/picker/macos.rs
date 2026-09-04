//! The macOS save dialog, driven through `osascript`'s `choose file name`.
//!
//! See the [module docs](super) for why this is a subprocess rather than an `NSSavePanel`.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{PickedPath, SaveFileRequest};

/// AppleScript's own error number for "the user pressed Cancel".
///
/// It is the one non-zero exit that means the user answered rather than the machine failed, so it
/// is matched explicitly and everything else falls back.
const USER_CANCELLED: &str = "-128";

/// Raise the save dialog and block until the user answers.
pub(super) fn ask(request: &SaveFileRequest<'_>) -> PickedPath {
    let script = script(request.title, request.file_name, request.starting_dir);
    let Ok(output) = Command::new("osascript").args(["-e", &script]).output() else {
        return PickedPath::Unavailable;
    };
    interpret(output.status.success(), &output.stdout, &output.stderr)
}

/// Read `osascript`'s result as the user's answer.
///
/// A failure is only a REFUSAL when AppleScript says the user cancelled. Any other failure — no
/// window server, an automation-policy denial, a script that would not compile — is the machine
/// being unable to ask, and is reported as such (see [`PickedPath`]).
fn interpret(succeeded: bool, stdout: &[u8], stderr: &[u8]) -> PickedPath {
    if succeeded {
        let path = String::from_utf8_lossy(stdout).trim().to_string();
        return if path.is_empty() {
            PickedPath::Unavailable
        } else {
            PickedPath::Chosen(PathBuf::from(path))
        };
    }

    if String::from_utf8_lossy(stderr).contains(USER_CANCELLED) {
        PickedPath::Cancelled
    } else {
        PickedPath::Unavailable
    }
}

/// The one-line script: show a save sheet, print the chosen POSIX path.
fn script(title: &str, file_name: &str, starting_dir: Option<&Path>) -> String {
    let mut choose = format!(
        "choose file name with prompt \"{}\" default name \"{}\"",
        applescript_string(title),
        applescript_string(file_name),
    );
    if let Some(dir) = starting_dir {
        choose.push_str(&format!(
            " default location POSIX file \"{}\"",
            applescript_string(&dir.to_string_lossy()),
        ));
    }
    format!("POSIX path of ({choose})")
}

/// Escape `text` for an AppleScript string literal.
///
/// Only the backslash and the double quote can end the literal, and the backslash is replaced first
/// so the escapes this introduces are not themselves escaped. Nothing here is attacker-controlled
/// today — the strings are our own constants and a home-directory path — but a literal that a path
/// can break out of is a code-injection seam, and the fix is one line.
fn applescript_string(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::{applescript_string, interpret, script, PickedPath};
    use std::path::{Path, PathBuf};

    #[test]
    fn a_chosen_path_comes_back_trimmed() {
        assert_eq!(
            interpret(true, b"/Users/dig/Desktop/words.txt\n", b""),
            PickedPath::Chosen(PathBuf::from("/Users/dig/Desktop/words.txt"))
        );
    }

    /// AppleScript reports a dismissal as error `-128`, and only that is a refusal.
    #[test]
    fn the_cancel_error_number_is_a_refusal() {
        assert_eq!(
            interpret(false, b"", b"execution error: User canceled. (-128)"),
            PickedPath::Cancelled
        );
    }

    /// The distinction the whole fallback rests on: osascript FAILING is not a user who said no.
    #[test]
    fn any_other_failure_is_unavailable_rather_than_a_refusal() {
        assert_eq!(
            interpret(
                false,
                b"",
                b"execution error: Not authorized to send Apple events. (-1743)"
            ),
            PickedPath::Unavailable,
            "an automation-policy denial must fall back, not abandon the backup"
        );
        assert_eq!(interpret(false, b"", b""), PickedPath::Unavailable);
    }

    #[test]
    fn success_with_no_path_is_unavailable() {
        assert_eq!(interpret(true, b"\n", b""), PickedPath::Unavailable);
    }

    #[test]
    fn the_script_asks_for_a_save_sheet_and_prints_a_posix_path() {
        let script = script(
            "Save your DIG recovery phrase",
            "dig-recovery-phrase.txt",
            Some(Path::new("/Users/dig")),
        );

        assert!(script.starts_with("POSIX path of (choose file name with prompt "));
        assert!(script.contains("\"Save your DIG recovery phrase\""));
        assert!(script.contains("default name \"dig-recovery-phrase.txt\""));
        assert!(script.contains("default location POSIX file \"/Users/dig\""));
    }

    #[test]
    fn a_missing_starting_directory_is_simply_omitted() {
        let script = script("t", "n.txt", None);

        assert!(!script.contains("default location"));
    }

    /// A quote or a backslash in a folder name must stay INSIDE the string literal — otherwise the
    /// path is no longer data, it is script.
    #[test]
    fn quotes_and_backslashes_cannot_escape_the_literal() {
        assert_eq!(
            applescript_string(r#"a"b\c"#),
            r#"a\"b\\c"#,
            "the quote and the backslash must both be escaped, backslash first"
        );

        let script = script(
            "t",
            "n.txt",
            Some(Path::new(r#"/Users/a" & (do shell script "x")"#)),
        );

        // Counting unescaped quotes is the assertion that actually distinguishes escaped from
        // unescaped — a substring search cannot, because `\"` contains `"`. Strip the escape
        // sequences and every quote that remains is a literal delimiter: two each for the prompt,
        // the name and the location. A quote that escaped its literal would add two more.
        let delimiters = script
            .replace(r"\\", "")
            .replace("\\\"", "")
            .matches('"')
            .count();
        assert_eq!(
            delimiters, 6,
            "the injected quotes must stay inside the location literal, leaving three pairs of \
             delimiters: {script}"
        );
    }
}
