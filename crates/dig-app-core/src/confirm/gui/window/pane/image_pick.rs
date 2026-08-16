//! Choosing a picture for one of the profile editor's image fields (dig_ecosystem#3028).
//!
//! # What lives here, and why it is not in the pane
//!
//! Two things a person can do — press *Choose an image* and get the system's own file chooser, or
//! drag a file onto the field — arrive by completely different routes and then do the SAME thing:
//! turn a path into the data URL that field holds, or into a sentence saying why it could not. That
//! shared ending is [`apply`], and it is a plain function over a draft and a map so it can be driven
//! by a test that opens no dialog and drags nothing.
//!
//! The reading itself is [`crate::profile_edit::chosen`]'s, unchanged. This module decides only
//! WHERE the answer lands.
//!
//! # The chooser runs on its own thread
//!
//! [`rfd`]'s dialog blocks until the person answers, and they may take a minute over it. Blocking
//! the painting thread for that minute is an application that has stopped responding — the freeze
//! `professional-ui` counts as a missing state — so the dialog is opened on a thread of its own and
//! the pane holds an [`InFlight`] it polls each frame. While it is in flight the field says so.
//!
//! # A failed choice never touches the value
//!
//! Somebody who already has a picture and then picks an unreadable file still has their picture.
//! The refusal is attached to that field, and the field keeps what it held — the alternative is a
//! form that silently empties a slot in response to an error, which on save would publish the
//! removal.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::profile_edit::{chosen, ProfileDraft, ProfileField};

/// What a person's choice came back as.
///
/// `None` is a cancelled dialog, which is not a failure and says nothing on the field.
pub(crate) type Answer = Option<Result<String, String>>;

/// What went wrong with the last choice, per field.
///
/// Per FIELD, not one line for the form: the editor has two image fields and a person who picks a
/// bad file for the header must not see the complaint under their profile picture.
pub(crate) type PickProblems = BTreeMap<ProfileField, String>;

/// Land a completed choice on `field`.
///
/// A success replaces that field's value and clears whatever it last complained about; a failure
/// records the sentence and leaves the value alone; a cancellation does neither, because a person
/// who changed their mind has said nothing about the picture they already had.
pub(crate) fn apply(
    draft: &mut ProfileDraft,
    problems: &mut PickProblems,
    field: ProfileField,
    answer: Answer,
) {
    match answer {
        Some(Ok(url)) => {
            draft.set(field, url);
            problems.remove(&field);
        }
        Some(Err(sentence)) => {
            problems.insert(field, sentence);
        }
        None => {}
    }
}

/// Read the file at `path` for `field` and land it, for a file that was DRAGGED onto the form.
///
/// The same ending as the dialog's, reached without one: a drop already knows its path, so there is
/// nothing to wait for.
pub(crate) fn dropped(
    draft: &mut ProfileDraft,
    problems: &mut PickProblems,
    field: ProfileField,
    path: &Path,
) {
    apply(draft, problems, field, Some(chosen(path)));
}

/// A file chooser that is open right now, and the field its answer belongs to.
///
/// Cloneable, and every clone shares the one answer: the pane's session is copied into egui's store
/// each frame, so a handle that did not share would poll a slot the dialog never writes to.
#[derive(Clone)]
pub(crate) struct InFlight {
    /// The field the person opened the chooser from.
    pub(crate) field: ProfileField,
    /// Filled in once by the chooser thread, taken once by the pane.
    answer: Arc<Mutex<Option<Answer>>>,
}

impl InFlight {
    /// Open the system's file chooser for `field`, on a thread of its own.
    #[cfg(feature = "gui")]
    pub(crate) fn open(field: ProfileField, repaint: egui::Context) -> Self {
        let flight = Self {
            field,
            answer: Arc::new(Mutex::new(None)),
        };
        let slot = Arc::clone(&flight.answer);
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .add_filter("Images", &["png", "jpg", "jpeg", "gif", "webp"])
                .set_title("Choose an image")
                .pick_file();
            *slot.lock().expect("the chooser slot") = Some(picked.map(|p| read(&p)));
            // The window may have been idle the whole time the dialog was up, and an answer nobody
            // repaints for is an answer nobody sees until the next mouse move.
            repaint.request_repaint();
        });
        flight
    }

    /// The answer, once, or `None` while the person is still choosing.
    pub(crate) fn taken(&self) -> Option<Answer> {
        self.answer.lock().expect("the chooser slot").take()
    }
}

/// Read a chosen path. Separated only so [`InFlight::open`]'s thread body stays one line of intent.
fn read(path: &PathBuf) -> Result<String, String> {
    chosen(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    /// A real PNG on disk, of the kind a chooser would return.
    fn a_png(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let image = DynamicImage::ImageRgb8(RgbImage::from_fn(48, 48, |x, y| {
            image::Rgb([(x * 4) as u8, (y * 4) as u8, 0x20])
        }));
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("encodes");
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).expect("writes");
        path
    }

    /// A draft with BOTH image fields already holding something, so every assertion below has a
    /// truthful control beside the field under test. A fixture with one image field could not tell
    /// a per-field answer from a form-wide one.
    fn a_form_with_both_pictures() -> ProfileDraft {
        let mut draft = ProfileDraft::empty();
        draft.set(ProfileField::Avatar, "data:image/png;base64,AAAA");
        draft.set(ProfileField::Banner, "data:image/png;base64,BBBB");
        draft
    }

    /// **A dropped file lands in the field it was dropped on, and in no other.**
    ///
    /// The nearest wrong implementation is not "nothing happens" — it is a pick routed to whichever
    /// field the form last touched, which on a one-image fixture is indistinguishable from correct.
    /// So the other image field is loaded first, and its value is asserted UNCHANGED.
    #[test]
    fn a_dropped_image_lands_on_the_field_it_was_dropped_on() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let mut draft = a_form_with_both_pictures();
        let mut problems = PickProblems::new();

        dropped(
            &mut draft,
            &mut problems,
            ProfileField::Banner,
            &a_png(&dir, "wide.png"),
        );

        let banner = draft.value(ProfileField::Banner);
        assert!(banner.starts_with("data:image/"), "{banner}");
        assert_ne!(banner, "data:image/png;base64,BBBB", "the drop did nothing");
        assert_eq!(
            draft.value(ProfileField::Avatar),
            "data:image/png;base64,AAAA",
            "a drop on the header rewrote the profile picture"
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// **A refusal is said on the field that was chosen for, and the value it held survives.**
    ///
    /// Two properties in one fixture because they fail together: an implementation that stores the
    /// message form-wide, and one that clears the slot on failure, both look like a working picker
    /// on a field that was empty to begin with.
    #[test]
    fn a_refused_file_complains_on_its_own_field_and_keeps_the_picture_already_there() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let not_an_image = dir.path().join("notes.txt");
        std::fs::write(&not_an_image, b"this is not a picture").expect("writes");

        let mut draft = a_form_with_both_pictures();
        let mut problems = PickProblems::new();
        dropped(
            &mut draft,
            &mut problems,
            ProfileField::Banner,
            &not_an_image,
        );

        assert!(
            problems.get(&ProfileField::Banner).is_some(),
            "the header field says nothing about the file it refused"
        );
        assert_eq!(
            problems.get(&ProfileField::Avatar),
            None,
            "a header refusal is being shown under the profile picture too"
        );
        assert_eq!(
            draft.value(ProfileField::Banner),
            "data:image/png;base64,BBBB",
            "a refused file emptied a slot that already held a picture"
        );
    }

    /// A field complains about the file it refused only until a good one replaces it. A message
    /// that outlives its cause is a form telling somebody their valid picture is invalid.
    #[test]
    fn a_good_choice_clears_the_message_the_last_one_left() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let mut draft = ProfileDraft::empty();
        let mut problems = PickProblems::new();

        apply(
            &mut draft,
            &mut problems,
            ProfileField::Avatar,
            Some(Err("no".into())),
        );
        dropped(
            &mut draft,
            &mut problems,
            ProfileField::Avatar,
            &a_png(&dir, "me.png"),
        );

        assert_eq!(problems.get(&ProfileField::Avatar), None);
        assert!(draft.value(ProfileField::Avatar).starts_with("data:image/"));
    }

    /// Closing the chooser without choosing says nothing and changes nothing — including not
    /// clearing a message the person still needs in order to know why their last file was refused.
    #[test]
    fn a_cancelled_chooser_changes_nothing_and_says_nothing_new() {
        let mut draft = a_form_with_both_pictures();
        let mut problems = PickProblems::new();
        problems.insert(ProfileField::Avatar, "too large".into());

        apply(&mut draft, &mut problems, ProfileField::Avatar, None);

        assert_eq!(
            draft.value(ProfileField::Avatar),
            "data:image/png;base64,AAAA"
        );
        assert_eq!(
            problems.get(&ProfileField::Avatar).map(String::as_str),
            Some("too large"),
            "cancelling erased the reason the previous file was refused"
        );
    }
}
