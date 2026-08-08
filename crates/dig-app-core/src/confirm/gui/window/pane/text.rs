//! The pane's type: four roles, and a semantic colour for each.
//!
//! # Why roles rather than sizes
//!
//! A call site that picks `size::SM` and `t.muted` is making a design decision in rendering code,
//! and the next call site will make a slightly different one. There are exactly four things a pane
//! says in prose — what this pane IS, what this group of facts is called, the sentence explaining
//! something, and the aside under a control — so there are exactly four functions here, and no
//! parameters for size or colour.
//!
//! Anything that is a VALUE rather than prose belongs in [`super::data`], and anything a person acts
//! on belongs in [`super::action`].

use egui::{Rect, Ui, Vec2};

use crate::confirm::gui::render::{regular, rgba, semibold, size};
use crate::confirm::gui::theme::Tokens;

/// The pane's own name, at the top. Exactly one per pane.
pub(crate) fn title(ui: &Ui, at: Rect, t: &Tokens, text: &str) -> f32 {
    paragraph(ui, at, text, semibold(size::HEADING), rgba(t.text))
}

/// The name of a group of related content — a card's title, or a run of readouts.
///
/// One step under [`title`], and in the primary text colour rather than the muted one: a heading a
/// person is meant to navigate by has to win against the body under it, and hub's `--muted` at 13 px
/// loses that contest on both themes.
pub(crate) fn heading(ui: &Ui, at: Rect, t: &Tokens, text: &str) -> f32 {
    paragraph(ui, at, text, semibold(size::LG), rgba(t.text))
}

/// An explanatory sentence. The default for anything that is prose rather than a value.
pub(crate) fn body(ui: &Ui, at: Rect, t: &Tokens, text: &str) -> f32 {
    paragraph(ui, at, text, regular(size::BASE), rgba(t.muted))
}

/// A short aside under the thing it qualifies — the unit a figure is in, or what a control will do.
///
/// `--muted`, never `--faint`: a caption is text a person is expected to READ, so it takes AA's
/// 4.5:1 bar. `--faint` is 3.34:1 on hub's light surface and is reserved for content that is
/// deliberately unavailable rather than merely secondary.
pub(crate) fn caption(ui: &Ui, at: Rect, t: &Tokens, text: &str) -> f32 {
    paragraph(ui, at, text, regular(size::SM), rgba(t.muted))
}

/// Lay `text` out wrapped to `at`'s width, draw it at the top of `at`, and report its height.
///
/// Wrapped, never truncated: a pane's prose is the explanation of what the person is looking at, and
/// half a sentence with an ellipsis is worse than a taller block. Truncation belongs to the tab strip,
/// where a chip must stay one control wide.
fn paragraph(ui: &Ui, at: Rect, text: &str, font: egui::FontId, colour: egui::Color32) -> f32 {
    let galley = ui
        .painter()
        .layout(text.to_owned(), font, colour, measure(at.width()));
    ui.painter()
        .galley(at.left_top(), galley.clone(), egui::Color32::PLACEHOLDER);
    galley.size().y
}

/// The widest a line of prose is allowed to get, in pixels.
///
/// `professional-ui` caps a readable measure at roughly 65–75 characters. At 15 px Space Grotesk an
/// average character is a little over 7 px, so ~70 characters is about here. A pane in a maximised
/// window would otherwise run a sentence the full 1,400 px, which is the one layout failure that gets
/// WORSE the more room you give it.
const MAX_MEASURE: f32 = 520.0;

/// The width prose actually wraps to inside a column `column` wide.
pub(crate) fn measure(column: f32) -> f32 {
    column.clamp(1.0, MAX_MEASURE)
}

/// A single line of `text`, cut short with an ellipsis when it will not fit `max_width`.
///
/// For values that must stay ONE line inside a control — a chip, a table cell — never for prose.
pub(crate) fn one_line(
    ui: &Ui,
    text: &str,
    font: egui::FontId,
    colour: egui::Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat {
            font_id: font,
            color: colour,
            ..Default::default()
        },
    );
    job.wrap = egui::text::TextWrapping {
        max_width: max_width.max(0.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('\u{2026}'),
    };
    ui.fonts(|fonts| fonts.layout_job(job))
}

/// The size of a square that fits inside `at`, capped so a pane never gives one block everything.
pub(crate) fn square_within(at: Rect, cap: f32) -> Vec2 {
    let side = at.width().min(at.height()).min(cap).max(0.0);
    Vec2::splat(side)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How tall one line of `font` is — the vacuity guard's yardstick for "did this actually wrap".
    fn line_height(ui: &Ui, font: egui::FontId) -> f32 {
        ui.fonts(|fonts| fonts.row_height(&font))
    }

    /// **Prose stops wrapping at a readable measure however wide the pane gets.**
    ///
    /// The fixture is a column MUCH wider than the cap and a sentence long enough to fill it, so a
    /// body that ignored the cap would come back one line tall. Asserted on the drawn height rather
    /// than on `measure` alone, because a cap the drawing code does not consult is not a cap.
    #[test]
    fn a_wide_pane_wraps_prose_at_a_readable_measure_instead_of_its_own_width() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let sentence = "The DIG agent is running and connected to a node, and this sentence is \
                        deliberately long enough to need more than one line at a readable measure.";

        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32, 0.0_f32));
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("measure-test")).show(ctx, |ui| {
                    let wide = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(1400.0, 400.0));
                    let capped =
                        Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(MAX_MEASURE, 400.0));
                    measured.set((
                        body(ui, wide, &t, sentence),
                        body(ui, capped, &t, sentence),
                        line_height(ui, regular(size::BASE)),
                    ));
                });
            });
        }

        let (at_1400, at_cap, one_line) = measured.get();
        assert!(
            at_cap > one_line * 1.5,
            "the fixture fits on one line even at the cap, so it proves nothing"
        );
        assert_eq!(
            at_1400, at_cap,
            "a 1400 px pane wrapped prose differently from a {MAX_MEASURE} px one, so the measure \
             cap is not being applied where the text is drawn"
        );
    }

    /// A degenerate column still produces a positive wrap width, rather than a NaN layout.
    #[test]
    fn a_collapsed_column_still_has_a_positive_measure() {
        assert!(measure(0.0) > 0.0);
        assert!(measure(-40.0) > 0.0);
    }

    /// A square block never exceeds its slot in either axis, nor its own cap.
    #[test]
    fn a_square_fits_its_slot_and_its_cap() {
        let wide = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(400.0, 90.0));
        assert_eq!(square_within(wide, 300.0).x, 90.0, "height should have won");
        let tall = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(70.0, 900.0));
        assert_eq!(square_within(tall, 300.0).x, 70.0, "width should have won");
        let roomy = Rect::from_min_size(egui::Pos2::ZERO, Vec2::splat(900.0));
        assert_eq!(
            square_within(roomy, 300.0).x,
            300.0,
            "the cap should have won"
        );
    }
}
