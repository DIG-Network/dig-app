//! The image well: what a picture in a profile LOOKS like, beside the two ways to change it
//! (dig_ecosystem#3069, criterion 9).
//!
//! # Why the text box is removed rather than hidden
//!
//! An image slot holds an RFC 2397 data URL, which for an ordinary photograph is tens of thousands
//! of base64 characters. Drawn in a `TextEdit` — which is what shipped before this module — that is
//! a wall of noise where a picture should be, and it invites the two things a person should never be
//! able to do by accident: select half of it, and type into the middle of it.
//!
//! Hiding the input would leave both hazards one focus-change away and leave no way to CLEAR a
//! picture, since emptying the box was the only way. So the box is gone and **Remove picture** takes
//! its place. That control is not a nicety; it is the replacement for the capability the removal
//! takes away, and without it this module would be a dead end.
//!
//! # The decode is [`crate::profile_image::preview`]'s, and there is no second one
//!
//! That function already carries the bound a pasted value needs — a decompression bomb in an iCCP
//! chunk is refused there, on a value that reached the profile from anywhere. A preview path with
//! its own decode would be a second opinion about which bytes are safe to expand on the painting
//! thread, and the first divergence between them is the one an attacker uses.
//!
//! # The texture is keyed on the VALUE, not on the field
//!
//! egui caches an uploaded texture under a name. Named after the field, the name never changes when
//! the value does — so a person who chooses a new picture keeps seeing the old one, with nothing
//! reporting a fault. The name carries a hash of the value instead, so a changed value is a
//! different texture by construction and the previous handle is dropped.

use std::hash::{Hash, Hasher};

use egui::{Rect, Ui, Vec2};

use super::text;
use crate::confirm::gui::render::{radius, rgba, space};
use crate::confirm::gui::theme::Tokens;
use crate::profile_image::{preview, PreviewPixels};

/// How large the preview tile is drawn, at most.
///
/// Big enough to recognise a face in, small enough that two of them plus their controls do not push
/// the rest of the form off the card.
const TILE: f32 = 96.0;

/// What the well is currently showing.
///
/// The four states `professional-ui` requires of any surface that reads something, named rather
/// than inferred — a well that decided between them at the draw site would have to re-derive
/// "loading" from a chooser flag and "error" from a problem string, and would silently gain a fifth
/// meaning the first time either changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Well {
    /// No picture, and nothing wrong. The ordinary state of a profile nobody has filled in.
    Empty,
    /// The system's file chooser is open for this field.
    Choosing,
    /// There is a value, and it cannot be shown. The sentence says why, in the words of whatever
    /// refused it.
    Unshowable(String),
    /// A picture, decoded and ready to draw.
    Showing(PreviewPixels),
}

impl Well {
    /// What to show for `value`, given whether a chooser is open and what last went wrong.
    ///
    /// # Why a refusal outranks a decodable value
    ///
    /// A person who picked an unreadable file still HAS their previous picture — `image_pick` is
    /// careful never to clear it — so the value decodes and the refusal is about a different file
    /// entirely. Showing the old picture with no explanation would report the pick as having
    /// worked. Showing the refusal beside the picture they still have is the honest answer, and it
    /// is what the caller draws: the sentence belongs to the FIELD and is drawn under the well by
    /// the form, not here.
    pub(crate) fn of(value: &str, choosing: bool) -> Self {
        if choosing {
            return Self::Choosing;
        }
        if value.is_empty() {
            return Self::Empty;
        }
        match preview(value) {
            Some(pixels) => Self::Showing(pixels),
            // Deliberately not the value itself, and never a fragment of it: a slice of base64 is
            // the noise this module exists to remove.
            None => Self::Unshowable(UNSHOWABLE.to_string()),
        }
    }

    /// Whether there is a value to remove, whatever it looks like.
    ///
    /// True for a value that will not decode, on purpose. A picture nobody can display is exactly
    /// the one a person most needs to be able to clear.
    pub(crate) fn holds_something(&self) -> bool {
        matches!(self, Self::Showing(_) | Self::Unshowable(_))
    }
}

/// The short form, drawn INSIDE the tile, where the full sentence would not fit.
///
/// A named constant rather than a literal so a surface asserting that a picture rendered can say so
/// against the words the tile actually draws — the long form below never appears inside a tile, so a
/// guard written against it could not fail.
pub(crate) const UNSHOWABLE_SHORT: &str = "Cannot be shown";

/// Said in place of a picture that cannot be shown.
///
/// It says what DIG can and cannot do, and never that the value is empty — the two states have
/// opposite remedies, and a person told their picture is missing when it is merely undisplayable
/// will replace something that other clients may render perfectly well.
pub(crate) const UNSHOWABLE: &str = concat!(
    "There is a picture here, but DIG cannot display it. ",
    "It may be in a format DIG does not read, or larger than DIG will open. ",
    "Choosing another replaces it.",
);

/// Said in the tile while there is no picture.
pub(crate) const NO_PICTURE: &str = "No picture yet";

/// Said in the tile while the system's chooser is open.
pub(crate) const CHOOSING: &str = "Waiting for your file…";

/// Draw the well for `state` at `at`, and report the height it took.
///
/// Draws the TILE only. The label above it and the controls beside it belong to the form, which
/// already owns the field's label, its help and its error — a second opinion about any of those
/// here is how one field comes to say two things.
pub(crate) fn tile(ui: &mut Ui, at: Rect, t: &Tokens, state: &Well, name: &str) -> f32 {
    let side = TILE.min(at.width());
    let frame = Rect::from_min_size(at.left_top(), Vec2::splat(side));

    ui.painter().rect(
        frame,
        egui::CornerRadius::same(radius::SM),
        rgba(t.surface_2),
        egui::Stroke::new(1.0_f32, rgba(t.border)),
        egui::StrokeKind::Inside,
    );

    match state {
        Well::Showing(pixels) => draw_picture(ui, frame, pixels, name),
        // Every other state says its own words INSIDE the tile. An empty bordered square with
        // nothing in it is indistinguishable from a picture that failed to paint.
        other => {
            let word = match other {
                Well::Choosing => CHOOSING,
                Well::Empty => NO_PICTURE,
                // The sentence is drawn in full under the field by the form; the tile carries the
                // short form so the square is never mute.
                Well::Unshowable(_) => UNSHOWABLE_SHORT,
                Well::Showing(_) => unreachable!("handled above"),
            };
            let inner = frame.shrink(space::S2);
            text::caption(ui, inner, t, word);
        }
    }
    side
}

/// Upload `pixels` once and paint them inside `frame`, preserving their proportions.
///
/// Letterboxed rather than stretched: a wide header image squashed into a square is a picture the
/// person did not choose, and the header field's whole point is its shape.
fn draw_picture(ui: &mut Ui, frame: Rect, pixels: &PreviewPixels, name: &str) {
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [pixels.width as usize, pixels.height as usize],
        &pixels.rgba,
    );
    // Named for the VALUE — see the module header. `load_texture` returns the existing handle for a
    // name already uploaded, so a value that has not changed is not re-uploaded every frame.
    let texture = ui
        .ctx()
        .load_texture(texture_name(name, pixels), image, Default::default());

    let scale = (frame.width() / pixels.width as f32)
        .min(frame.height() / pixels.height as f32)
        .min(1.0);
    let size = Vec2::new(pixels.width as f32 * scale, pixels.height as f32 * scale);
    let inside = Rect::from_center_size(frame.center(), size);
    egui::Image::new(&texture).paint_at(ui, inside);
}

/// The texture's cache name: the field's own name, plus a hash of the pixels it is showing.
///
/// The hash is what makes the name change when the picture does. Over the DECODED pixels rather
/// than the data URL, because that is what was uploaded — two different encodings of one image are
/// one texture, and one encoding cannot name two pictures.
fn texture_name(name: &str, pixels: &PreviewPixels) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pixels.rgba.hash(&mut hasher);
    pixels.width.hash(&mut hasher);
    pixels.height.hash(&mut hasher);
    format!("dig-profile-image-{name}-{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;

    /// A real PNG of `side` square, as a data URL an image slot would hold.
    fn a_picture(side: u32) -> String {
        let image = DynamicImage::ImageRgb8(RgbImage::from_fn(side, side, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 0x40])
        }));
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("encodes");
        crate::profile_image::intake(&bytes, crate::profile_image::DecodeBounds::LOCAL_PICK)
            .expect("a real png")
            .to_url()
    }

    /// **The four states are four different answers, and none of them is another's.**
    ///
    /// The pair that matters is `Empty` against `Unshowable`: they are the two a wrong
    /// implementation merges, by treating "no picture to draw" as one state. Their remedies are
    /// opposite — one person needs to choose a picture, the other already has one and would be
    /// destroying it.
    #[test]
    fn a_value_that_will_not_decode_is_never_reported_as_no_picture_at_all() {
        assert_eq!(Well::of("", false), Well::Empty);
        assert_eq!(Well::of("", true), Well::Choosing);

        let broken = Well::of("data:image/png;base64,bm90LWEtcG5n", false);
        assert!(
            matches!(broken, Well::Unshowable(_)),
            "a value DIG cannot decode was not reported as an undisplayable picture: {broken:?}"
        );
        assert!(
            broken.holds_something(),
            "a picture nobody can display cannot be removed, which is the one a person most needs \
             to be able to clear"
        );

        // The control: a real picture, through the same call, must reach `Showing` — otherwise
        // "everything is Unshowable" would satisfy the assertions above.
        let good = Well::of(&a_picture(48), false);
        assert!(matches!(good, Well::Showing(_)), "{good:?}");
        assert!(good.holds_something());
        assert!(!Well::Empty.holds_something());
    }

    /// **A chooser that is open outranks the value underneath it.**
    ///
    /// The state a person is IN while the system dialog is up. Without it the well would report
    /// the picture they are in the middle of replacing, which reads as a dialog that did nothing.
    /// Asserted over a field that already HOLDS a picture, because over an empty one `Choosing` and
    /// `Empty` would be told apart by nothing.
    #[test]
    fn an_open_chooser_is_shown_over_a_field_that_already_holds_a_picture() {
        let held = a_picture(48);
        assert_eq!(Well::of(&held, true), Well::Choosing);
        assert!(matches!(Well::of(&held, false), Well::Showing(_)));
    }

    /// **Two different pictures are two different textures; the same picture is one.**
    ///
    /// The hazard the module header names. A texture named after the FIELD satisfies "there is a
    /// name" and shows the previous picture forever after a change — the failure is invisible,
    /// because a stale texture paints perfectly.
    ///
    /// Both directions, because a name that hashed something incidental (a frame counter, a
    /// pointer) would also differ between two pictures, and would re-upload the same picture on
    /// every frame.
    #[test]
    fn the_texture_name_follows_the_picture_and_not_the_field() {
        let one = preview(&a_picture(48)).expect("decodes");
        let other = preview(&a_picture(64)).expect("decodes");
        let same_again = preview(&a_picture(48)).expect("decodes");

        assert_ne!(
            texture_name("avatar", &one),
            texture_name("avatar", &other),
            "one field's two pictures share a texture name, so choosing a new one leaves the old \
             one on screen"
        );
        assert_eq!(
            texture_name("avatar", &one),
            texture_name("avatar", &same_again),
            "the same picture is uploaded under a new name each time it is drawn"
        );
        assert_ne!(
            texture_name("avatar", &one),
            texture_name("banner", &one),
            "the two image fields share a texture"
        );
    }

    /// **The undisplayable sentence never tells a person their picture is missing.**
    ///
    /// The two states have opposite remedies, and this is the sentence that keeps them apart on
    /// screen after `Well::of` has kept them apart in the model.
    #[test]
    fn the_undisplayable_sentence_says_a_picture_is_there() {
        let said = UNSHOWABLE.to_lowercase();
        assert!(
            said.contains("there is a picture here"),
            "the sentence does not say the picture exists: {said}"
        );
        assert!(
            !said.contains("no picture"),
            "an undisplayable picture is worded as an absent one: {said}"
        );
        assert_ne!(UNSHOWABLE, NO_PICTURE);
    }
}
