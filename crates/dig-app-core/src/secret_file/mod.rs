//! Putting a secret on disk: where it goes, and who can read it once it is there.
//!
//! The recovery-phrase backup (SPEC §3.1a) is the one flow in dig-app that deliberately writes an
//! account's custody root out in the clear, at the user's explicit and twice-confirmed request.
//! Everything in this module exists because of what that implies: whoever can read the resulting
//! file holds the funds.
//!
//! Two decisions have to be right, and they are coupled:
//!
//! * **Where the file goes** — [`picker`] asks the user, through the platform's own save dialog,
//!   instead of dropping the seed at a fixed and therefore predictable path (dig_ecosystem#1966).
//! * **Who can read it** — [`write_owner_only`] restricts the file to its owner AT CREATION on
//!   every platform, including Windows, where mode bits mean nothing (dig_ecosystem#1965).
//!
//! Letting the user choose the destination is what makes the second half load-bearing rather than
//! belt-and-braces: a chosen folder is far more likely to be a shared or cloud-synced one — a
//! Desktop, a Documents folder, a OneDrive tree — than the profile root ever was.

mod owner_only;
pub mod picker;
#[cfg(windows)]
mod windows_acl;

use std::path::{Path, PathBuf};

pub use owner_only::write_owner_only;
pub use picker::{NativeSavePicker, PickedPath, SaveFilePicker, SaveFileRequest};

/// Where a secret file is to be written, once the user has been asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFileDestination {
    /// Write it here.
    At(PathBuf),
    /// The user declined. Write nothing.
    Declined,
    /// There is nowhere to write it: no dialog could be raised and no fallback folder is known.
    Nowhere,
}

/// Ask the user where to save, and say what should happen with the answer.
///
/// # The two failure directions, which are not the same failure
///
/// A save dialog can end without a path for two unrelated reasons, and treating them alike breaks
/// something either way:
///
/// * **The user cancelled.** They were shown a dialog and said no. Falling back to `fallback_dir`
///   here would write the secret to a predictable path they had just declined to write it to — the
///   dialog would be theatre. So a cancel is [`SecretFileDestination::Declined`], full stop.
/// * **No dialog could be raised.** A headless host, or a desktop with no dialog helper installed.
///   The user asked for a file and never got the chance to choose; refusing would remove a working
///   feature from every such host. So this falls back to `fallback_dir`, which is exactly the fixed
///   path this flow used before it could ask (dig_ecosystem#1966).
///
/// `fallback_dir` is normally the user's home directory. When it is unknown as well, there is
/// genuinely nowhere to put the file and the caller must say so rather than invent a path.
pub fn choose_secret_file_path(
    picker: &dyn SaveFilePicker,
    request: &SaveFileRequest<'_>,
    fallback_dir: Option<&Path>,
) -> SecretFileDestination {
    match picker.ask(request) {
        PickedPath::Chosen(path) => SecretFileDestination::At(path),
        PickedPath::Cancelled => SecretFileDestination::Declined,
        PickedPath::Unavailable => match fallback_dir {
            Some(dir) => SecretFileDestination::At(dir.join(request.file_name)),
            None => SecretFileDestination::Nowhere,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A picker that answers however the test says, without a dialog.
    struct Answering(PickedPath);

    impl SaveFilePicker for Answering {
        fn ask(&self, _request: &SaveFileRequest<'_>) -> PickedPath {
            self.0.clone()
        }
    }

    fn request() -> SaveFileRequest<'static> {
        SaveFileRequest {
            title: "Save your DIG recovery phrase",
            file_name: "dig-recovery-phrase.txt",
            starting_dir: None,
        }
    }

    fn decide(answer: PickedPath, fallback: Option<&Path>) -> SecretFileDestination {
        choose_secret_file_path(&Answering(answer), &request(), fallback)
    }

    #[test]
    fn a_chosen_path_is_used_as_given() {
        let chosen = Path::new("/media/usb/my-words.txt");

        assert_eq!(
            decide(
                PickedPath::Chosen(chosen.to_path_buf()),
                Some(Path::new("/home/dig"))
            ),
            SecretFileDestination::At(chosen.to_path_buf()),
            "a chosen path wins outright — the fallback is not consulted"
        );
    }

    /// The one that matters: a cancel must NOT quietly write the secret to the old fixed path.
    #[test]
    fn a_cancel_writes_nothing_even_when_a_fallback_exists() {
        assert_eq!(
            decide(PickedPath::Cancelled, Some(Path::new("/home/dig"))),
            SecretFileDestination::Declined,
            "cancelling the dialog must abandon the write, not redirect it"
        );
    }

    /// The other side of that coin: a host that CANNOT ask must not lose the feature.
    #[test]
    fn an_unavailable_dialog_falls_back_to_the_known_folder() {
        assert_eq!(
            decide(PickedPath::Unavailable, Some(Path::new("/home/dig"))),
            SecretFileDestination::At(Path::new("/home/dig/dig-recovery-phrase.txt").to_path_buf()),
            "with no dialog available the user still gets their file, at the documented path"
        );
    }

    #[test]
    fn nowhere_to_write_is_reported_rather_than_guessed() {
        assert_eq!(
            decide(PickedPath::Unavailable, None),
            SecretFileDestination::Nowhere,
            "with no dialog and no known folder there is no path to invent"
        );
    }
}
