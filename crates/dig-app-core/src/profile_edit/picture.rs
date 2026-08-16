//! Turning a file a person chose — browsed for, or dragged onto the form — into the data URL an
//! image slot holds (dig_ecosystem#3028).
//!
//! # Why this is a module and not four lines in the pane
//!
//! Everything here is a path in and a `String` out: no window, no dialog, no event loop. That is what
//! makes the two properties worth having testable at all — that an over-long file is refused
//! **before** it is read, and that whatever comes back is a value
//! [`ProfileDraft::problem`](super::draft::ProfileDraft::problem) will accept. The pane owns the
//! dialog and the drop target and nothing else.
//!
//! # The order of the two size checks is the point
//!
//! [`profile_image::intake`](crate::profile_image::intake) already refuses an over-long input, but it
//! refuses a `&[u8]` that is by then in memory. A file is on disk, and its length can be read without
//! reading it — so the check happens against the file's METADATA first. Without that, dragging a
//! multi-gigabyte file onto the form allocates it before anything says no.
//!
//! That ordering is invisible from a return value alone: `intake`'s own refusal carries the same two
//! numbers, so a test asserting *"too long"* passes on both placements. It is observable in ONE
//! respect, and the refusal is written to make it so — this module knows the file's NAME and `intake`
//! cannot, so the early refusal says which file, and that is what the test reads.
//!
//! # There is no second intake here
//!
//! The decode, the bomb refusal, the fit-within and the encoding are all
//! [`crate::profile_image`]'s, unchanged. This module reads bytes and reports failures in the words
//! that module already wrote.

use std::path::Path;

use crate::profile_image::{intake, DecodeBounds};

/// Read the image at `path` and produce the data URL to store in an image slot.
///
/// The bounds are [`DecodeBounds::LOCAL_PICK`]: this is the person's own file, so the input bound is
/// generous and the defence is the header check inside `intake`. `RECEIVED` is for bytes a peer sent
/// and must never be used here — a camera photograph would fail it.
///
/// Failure is a sentence to show, not an error type: every one of them is already written for a
/// person in [`IntakeError`](crate::profile_image::IntakeError), and this path adds only the one case
/// that module cannot have — a file the filesystem would not give us.
pub fn chosen(path: &Path) -> Result<String, String> {
    chosen_within(path, DecodeBounds::LOCAL_PICK)
}

/// [`chosen`], with the bound named — so a test can drive the length gate without a file the size of
/// the real limit.
fn chosen_within(path: &Path, bounds: DecodeBounds) -> Result<String, String> {
    // Before the read, deliberately. See the module header.
    let len = std::fs::metadata(path)
        .map_err(|e| unreadable(path, &e))?
        .len();
    if len > bounds.max_input_bytes as u64 {
        return Err(too_long(path, len, bounds.max_input_bytes));
    }

    let bytes = std::fs::read(path).map_err(|e| unreadable(path, &e))?;
    Ok(intake(&bytes, bounds).map_err(|e| e.to_string())?.to_url())
}

/// The sentence for a file too long to open, taken from its length rather than from its contents.
///
/// It NAMES the file, which is the one thing
/// [`IntakeError::InputTooLong`](crate::profile_image::IntakeError::InputTooLong) cannot do — that
/// error is over a byte slice with no provenance. So the naming is both the better message (a person
/// who dragged in several files learns which one) and the only outward evidence that the length was
/// read before the file was.
fn too_long(path: &Path, len: u64, limit: usize) -> String {
    format!(
        "{} is {len} bytes, larger than the {limit} this app will open. Choose a smaller image.",
        named(path)
    )
}

/// The sentence for a file the filesystem would not hand over.
///
/// Names the file, because the two ordinary causes — it was moved between the drop and the read, or
/// it is somewhere this user cannot read — are both ones a person resolves by looking at that file
/// rather than at DIG.
fn unreadable(path: &Path, error: &std::io::Error) -> String {
    format!("DIG could not open {}: {error}", named(path))
}

/// The file's own name, for a sentence a person reads — never the whole path, which on a Windows
/// profile directory is longer than the message it is part of.
fn named(path: &Path) -> std::borrow::Cow<'_, str> {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    /// A real PNG of `side` square, written where a picker would have found one.
    fn a_png_file(dir: &tempfile::TempDir, side: u32) -> std::path::PathBuf {
        let image = DynamicImage::ImageRgb8(RgbImage::from_fn(side, side, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 0x40])
        }));
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("encodes");
        let path = dir.path().join("me.png");
        std::fs::write(&path, &bytes).expect("writes");
        path
    }

    /// **What comes back is a value the form will actually accept and commit.**
    ///
    /// Asserted against the draft's OWN check rather than against a prefix written here: the whole
    /// point of the wiring is that the picker feeds the same gate a paste does, and a second opinion
    /// about what an image slot may hold is how the two come to disagree.
    #[test]
    fn a_chosen_png_becomes_a_value_the_draft_accepts() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let url = chosen(&a_png_file(&dir, 64)).expect("a real png is taken");

        let mut draft = super::super::ProfileDraft::empty();
        draft.set(super::super::ProfileField::Avatar, url.clone());
        assert_eq!(
            draft.problem(super::super::ProfileField::Avatar),
            None,
            "the picker produced a value the form refuses: {}",
            &url[..url.len().min(64)]
        );
        assert!(draft.is_committable());
    }

    /// **A file larger than the bound is refused from its LENGTH, before its bytes are read.**
    ///
    /// # Why this asserts the file's name and not the two numbers
    ///
    /// The nearest wrong implementation is not "no bound at all" — it is the bound applied one layer
    /// down, inside `intake`, after the whole file is in memory. That implementation refuses the same
    /// input with the same two numbers in the same words, so *"the message says 100 bytes"* passes on
    /// BOTH and pins nothing. (Written that way first, and the revert-proof caught it.)
    ///
    /// The name is the one thing that cannot survive being moved: `intake` takes a `&[u8]` and has no
    /// path to name. So a refusal carrying `huge.bin` can only have been decided here, from the
    /// metadata.
    #[test]
    fn an_over_long_file_is_refused_from_its_length_and_not_from_its_bytes() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("huge.bin");
        std::fs::write(&path, vec![b'x'; 100]).expect("writes");

        let tiny = DecodeBounds {
            max_input_bytes: 10,
            ..DecodeBounds::LOCAL_PICK
        };
        let refusal = chosen_within(&path, tiny).expect_err("a 100-byte file under a 10-byte bound");
        assert!(
            refusal.contains("huge.bin"),
            "the refusal does not name the file, so it was decided from the bytes rather than from \
             the length: {refusal}"
        );
        assert!(refusal.contains("100"), "{refusal}");

        // The control: the SAME file, under the real bound, is refused for what it IS. Without this
        // the assertion above would also pass on an implementation that refuses everything by length.
        let by_content = chosen(&path).expect_err("a text file is not an image");
        assert!(
            by_content.contains("supported image"),
            "an ordinary non-image was not refused for its content: {by_content}"
        );
        assert!(
            !by_content.contains("huge.bin"),
            "a content refusal claimed to be a length refusal: {by_content}"
        );
    }

    /// A file that is not there is named, and is never confused with a file that is not an image —
    /// the two have different remedies and only one of them is about the picture.
    #[test]
    fn a_missing_file_is_reported_as_a_file_problem() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let refusal = chosen(&dir.path().join("gone.png")).expect_err("nothing is there");
        assert!(refusal.contains("gone.png"), "{refusal}");
        assert!(!refusal.contains("supported image"), "{refusal}");
    }

    /// The bounds are the LOCAL ones. A person's own camera photograph is far past
    /// [`DecodeBounds::RECEIVED`]'s 512-pixel side, and refusing it would be a defect rather than a
    /// defence — so this pins which of the two constants the picker passes.
    #[test]
    fn a_camera_sized_photograph_is_taken_rather_than_refused() {
        let dir = tempfile::tempdir().expect("a temp dir");
        // Comfortably over RECEIVED's 512 side and its 4 MiB input bound is irrelevant here; what is
        // pinned is that the side limit applied is not the peer-facing one.
        let taken = chosen(&a_png_file(&dir, 900)).expect("a 900px photograph is a normal picture");
        assert!(taken.starts_with("data:image/"));
    }
}
