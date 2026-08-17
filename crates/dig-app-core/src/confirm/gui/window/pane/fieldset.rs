//! A collapsible group of fields: its heading, whether it is folded, and the one rule that stops a
//! fold hiding something a person has to fix (dig_ecosystem#3069, criterion 8).
//!
//! # The trap this layout creates, and the guard that removes it
//!
//! Folding the Enhanced fields away is what makes the form stop being intimidating. It also creates
//! a dead end that did not exist while every box was on screen: a value with a problem in it stops
//! Save from being pressable, and if that value is inside a CLOSED fieldset, a person is looking at
//! a disabled control with no visible cause and no way to discover one. They would have to open a
//! group they had no reason to open.
//!
//! So a fieldset holding a problem **opens itself**, and says so in its heading. It is the one thing
//! this module decides for the person, and it only ever reveals — it never folds anything away that
//! they opened.
//!
//! The heading says **needs attention** in words, beside a glyph. `professional-ui` forbids carrying
//! meaning in colour alone, and this heading is the only signal a person gets that the form has
//! something wrong further down.

use egui::{Rect, Ui, Vec2};

use super::{card, flow::Flow, text};
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;

/// One fieldset's fold state and what it is called.
pub(crate) struct Fieldset<'a> {
    /// The heading, as a person reads it.
    pub(crate) title: &'a str,
    /// The sentence under the heading, saying what is inside before it is opened.
    pub(crate) summary: &'a str,
    /// Whether the person has it open.
    pub(crate) open: bool,
    /// Whether anything inside it has a problem. Forces it open, whatever `open` says.
    pub(crate) needs_attention: bool,
    /// The element id of the header control.
    pub(crate) id: egui::Id,
}

impl Fieldset<'_> {
    /// Whether the fields inside are drawn this frame.
    ///
    /// A person's own choice, EXCEPT that a problem inside opens it. See the module header: the
    /// alternative is a disabled Save control with its cause folded out of sight.
    pub(crate) fn is_showing(&self) -> bool {
        self.open || self.needs_attention
    }

    /// What the header says, which is the title plus the attention marker when one is warranted.
    ///
    /// The marker is a WORD, with a glyph beside it. A coloured heading alone would be invisible to
    /// a person who cannot distinguish the colour, and this is the only place the form says that
    /// something below is wrong.
    pub(crate) fn heading(&self) -> String {
        match self.needs_attention {
            true => format!("{} {} — {NEEDS_ATTENTION}", self.title, MARKER),
            false => self.title.to_string(),
        }
    }
}

/// The words that mark a fieldset holding something wrong.
pub(crate) const NEEDS_ATTENTION: &str = "needs attention";

/// The glyph beside those words.
///
/// An exclamation mark rather than a symbol from a pictographic block: the window's font stack has
/// no emoji coverage, and a missing glyph photographs as a tofu box (`tray_menu::channel_row_label`
/// records the same constraint for the tick that is a word here for the same reason).
const MARKER: &str = "!";

/// The label of the control that folds a fieldset away.
pub(crate) const HIDE: &str = "Hide";

/// The label of the control that opens one.
pub(crate) const SHOW: &str = "Show";

/// Draw `set`'s header and, when it is showing, its `fields`. Reports whether the header was pressed.
///
/// The whole fieldset is inside a panel so the fold is visibly a container rather than a heading
/// that happens to have things under it — which is what makes it obvious there is more here when it
/// is closed.
pub(crate) fn fieldset(
    flow: &mut Flow,
    t: &Tokens,
    set: &Fieldset<'_>,
    fields: impl FnOnce(&mut Flow),
) -> bool {
    let heading = set.heading();
    let summary = set.summary;
    let showing = set.is_showing();
    let live = flow.live();
    // A fieldset held open by a problem cannot be folded away — the control would be one that
    // visibly does nothing, since the next frame reopens it. So it is not offered, and the
    // heading says why in its own words.
    let toggle = match (set.needs_attention, showing) {
        (true, _) => None,
        (false, true) => Some(HIDE),
        (false, false) => Some(SHOW),
    };
    let id = set.id;

    flow.place(|ui, at| {
        let mut hit = false;
        let height = card::panel(ui, at, t, None, |inner| {
            inner.place(|ui, row| {
                // The heading is laid out in the space the control does NOT take, so a long title
                // wraps above the button rather than under it.
                let width = toggle.map_or(0.0, |_| BUTTON_WIDTH + space::S3);
                let titled = Rect::from_min_size(
                    row.left_top(),
                    Vec2::new((row.width() - width).max(1.0), row.height()),
                );
                let used = text::heading(ui, titled, t, &heading);
                if let Some(label) = toggle {
                    hit = header_button(ui, row, t, live, label, id);
                }
                (used.max(paint::BUTTON_HEIGHT), ())
            });
            inner.gap(space::S1);
            inner.place(|ui, row| (text::caption(ui, row, t, summary), ()));
            if showing {
                inner.gap(space::S4);
                fields(inner);
            }
        });
        (height, hit)
    })
}

/// The fold control, drawn at the RIGHT of the heading's row.
///
/// Beside the heading rather than under it, because the heading is what it acts on — and a person
/// scanning a folded form reads the title and the control as one thing to press.
fn header_button(
    ui: &mut Ui,
    row: Rect,
    t: &Tokens,
    live: bool,
    label: &str,
    id: egui::Id,
) -> bool {
    let width = BUTTON_WIDTH.min(row.width() / 2.0);
    let at = Rect::from_min_size(
        egui::Pos2::new(row.right() - width, row.top()),
        Vec2::new(width, paint::BUTTON_HEIGHT),
    );
    let (_, hit) = super::action::buttons(
        ui,
        at,
        t,
        live,
        &[super::action::Action {
            label: label.to_string(),
            weight: Weight::Ghost,
            enabled: live,
            id: (),
            element: id,
        }],
    );
    hit.is_some()
}

/// How wide the fold control is drawn.
const BUTTON_WIDTH: f32 = 88.0;

#[cfg(test)]
mod tests {
    use super::*;

    fn a_set(open: bool, needs_attention: bool) -> Fieldset<'static> {
        Fieldset {
            title: "Enhanced information",
            summary: "Pronouns, location, links.",
            open,
            needs_attention,
            id: egui::Id::new("fieldset-test"),
        }
    }

    /// **A closed fieldset holding a problem opens itself, and says why.**
    ///
    /// This is the dead end the fold creates: Save is disabled by a value the person cannot see,
    /// inside a group they have no reason to open. The fixture is the exact state — CLOSED, with a
    /// problem — because that is the only combination in which the guard does anything at all.
    ///
    /// The control leg is the same fieldset closed with NOTHING wrong, which must stay closed.
    /// Without it, "always open" passes.
    #[test]
    fn a_closed_fieldset_with_a_problem_inside_it_opens_and_says_so() {
        let hiding_a_problem = a_set(false, true);
        assert!(
            hiding_a_problem.is_showing(),
            "a fieldset folded a problem away, so Save is disabled with its cause off screen"
        );
        assert!(
            hiding_a_problem.heading().contains(NEEDS_ATTENTION),
            "the fieldset opened itself and never said why: {}",
            hiding_a_problem.heading()
        );

        let quiet = a_set(false, false);
        assert!(
            !quiet.is_showing(),
            "a fieldset with nothing wrong in it will not stay closed, so the fold does nothing"
        );
        assert!(
            !quiet.heading().contains(NEEDS_ATTENTION),
            "a healthy fieldset claims something is wrong: {}",
            quiet.heading()
        );
    }

    /// **An OPEN fieldset is never folded away by this module** — the guard only ever reveals.
    #[test]
    fn a_fieldset_the_person_opened_stays_open() {
        assert!(a_set(true, false).is_showing());
        assert!(a_set(true, true).is_showing());
    }

    /// **The attention marker is a WORD, not only a glyph and not only a colour.**
    ///
    /// `professional-ui` forbids meaning carried by colour alone, and this heading is the form's
    /// only signal that something below it is wrong. The glyph is there too, for a person scanning
    /// rather than reading — but the words are what must survive.
    #[test]
    fn the_attention_marker_is_readable_without_seeing_a_colour() {
        let said = a_set(false, true).heading();
        assert!(said.contains(NEEDS_ATTENTION), "{said}");
        assert!(said.contains("Enhanced information"), "{said}");
        assert!(
            NEEDS_ATTENTION.chars().any(|c| c.is_alphabetic()),
            "the marker is not a word"
        );
    }
}
