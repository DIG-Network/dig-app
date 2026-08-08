//! The container that groups related facts: a titled card, and the recessed panel inside it.
//!
//! # Why a card is not just a rounded rectangle
//!
//! Grouping is the whole job. A pane that is a flat run of rows makes the reader work out for
//! themselves which figures belong together — which is exactly how the tray's row list reads, and
//! why dig_ecosystem#2326 exists. A card says *these three things are one subject* before a word of
//! it is read.
//!
//! # Why the background is drawn after the content
//!
//! A card's height is whatever its content came to, and its content cannot be measured without
//! laying it out. Rather than measure everything twice, the card reserves a shape slot up front,
//! lays its content out, and then writes the real rectangle into the slot it already holds — so the
//! background lands BEHIND the content in paint order while being computed after it.

use egui::{Rect, Ui, Vec2};

use super::flow::Flow;
use super::text;
use crate::confirm::gui::render::{radius, rgba, space};
use crate::confirm::gui::theme::Tokens;

/// The padding between a card's edge and its content.
pub(crate) const CARD_PAD: f32 = space::S5;

/// A titled card. Returns the height it took.
///
/// `title` is optional: a card holding one self-describing thing — a QR code with its caption — does
/// not need a heading repeating what the reader can see.
pub(crate) fn card(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    title: Option<&str>,
    content: impl FnOnce(&mut Flow),
) -> f32 {
    container(ui, at, Face::Card, t, true, title, content).0
}

/// A recessed panel — the same container one level down, for a group INSIDE a card.
///
/// Use it to separate a subordinate detail from its parent card. Do not nest it further: three
/// levels of surface is a box in a box in a box, and the reader stops seeing the grouping at all.
pub(crate) fn panel(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    title: Option<&str>,
    content: impl FnOnce(&mut Flow),
) -> f32 {
    container(ui, at, Face::Panel, t, true, title, content).0
}

/// Which surface a container is drawn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Face {
    /// `--surface` inside `--border` at the card radius: a top-level group in a pane.
    Card,
    /// `--surface-2` inside `--border`: a group nested inside a card.
    Panel,
}

impl Face {
    /// The fill, the edge and the corner this face is drawn with.
    fn look(self, t: &Tokens) -> (egui::Color32, egui::Color32, u8) {
        match self {
            Self::Card => (rgba(t.surface), rgba(t.border), radius::BASE),
            Self::Panel => (rgba(t.surface_2), rgba(t.border), radius::SM),
        }
    }
}

/// A card whose content senses clicks, and reports what was pressed.
///
/// The same container as [`card`]; separate only because a card of FACTS should not be able to
/// return a click, and a signature that cannot express one is the cheapest way to say so.
pub(crate) fn interactive_card<R>(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    title: Option<&str>,
    content: impl FnOnce(&mut Flow) -> R,
) -> (f32, Option<R>) {
    container(ui, at, Face::Card, t, live, title, content)
}

/// Draw a container with `face`, and report the height it came to and what its content returned.
fn container<R>(
    ui: &mut Ui,
    at: Rect,
    face: Face,
    t: &Tokens,
    live: bool,
    title: Option<&str>,
    content: impl FnOnce(&mut Flow) -> R,
) -> (f32, Option<R>) {
    // Reserved BEFORE the content so the fill paints under it; written below, once the content has
    // told us how tall the container is.
    let slot = ui.painter().add(egui::Shape::Noop);

    let inner = Rect::from_min_max(
        at.left_top() + Vec2::splat(CARD_PAD),
        egui::Pos2::new(at.right() - CARD_PAD, at.bottom()),
    );
    if inner.width() <= 0.0 {
        return (0.0, None);
    }

    let mut flow = Flow::new(ui, inner, live);
    if let Some(title) = title {
        flow.place(|ui, at| (text::heading(ui, at, t, title), ()));
        flow.gap(space::S3);
    }
    let result = content(&mut flow);
    let height = flow.cursor() - inner.top() + CARD_PAD * 2.0;

    let (fill, edge, corner) = face.look(t);
    ui.painter().set(
        slot,
        egui::epaint::RectShape::new(
            Rect::from_min_size(at.left_top(), Vec2::new(at.width(), height)),
            egui::CornerRadius::same(corner),
            fill,
            egui::Stroke::new(1.0_f32, edge),
            egui::StrokeKind::Inside,
        ),
    );
    (height, Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run one settled frame and hand `body` a real `Ui`.
    fn in_a_frame<R: Copy + Default>(body: impl Fn(&mut Ui) -> R) -> R {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let out = std::cell::Cell::new(R::default());
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("card-test")).show(ctx, |ui| out.set(body(ui)));
            });
        }
        out.get()
    }

    /// The rect a card wrote into its reserved slot on the last frame.
    fn card_background(ctx_shapes: &[egui::epaint::ClippedShape]) -> Option<Rect> {
        fn walk(shape: &egui::Shape, found: &mut Vec<Rect>) {
            match shape {
                egui::Shape::Rect(rect) => found.push(rect.rect),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for clipped in ctx_shapes {
            walk(&clipped.shape, &mut found);
        }
        found.into_iter().next()
    }

    /// **A card's background is as tall as the content it actually laid out.**
    ///
    /// This is the property the reserved-slot mechanism exists for, and the nearest wrong
    /// implementation — reserving a guessed height — passes any fixture whose content happens to be
    /// that tall. So the fixture runs the SAME card with two different amounts of content and
    /// requires the backgrounds to differ by the height the extra content measured. A card that
    /// ignored its content would return two identical rectangles.
    #[test]
    fn a_cards_background_grows_with_the_content_rather_than_a_reserved_guess() {
        let one_line = "One line.";
        let three_lines =
            "A sentence long enough to wrap onto several lines inside a narrow card, so that the \
             content this card is measuring is unambiguously taller than the single line above.";

        let (short, tall) = in_a_frame(|ui| {
            let t = crate::confirm::gui::theme::Theme::Light.tokens();
            let at = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(280.0, 600.0));
            let short = card(ui, at, &t, Some("Node"), |flow| {
                flow.place(|ui, at| (text::body(ui, at, &t, one_line), ()));
            });
            let tall = card(ui, at, &t, Some("Node"), |flow| {
                flow.place(|ui, at| (text::body(ui, at, &t, three_lines), ()));
            });
            (short, tall)
        });

        assert!(
            tall > short + 10.0,
            "a card with three lines of content ({tall}) came out no taller than one with a single \
             line ({short}) — the height is a guess, not a measurement"
        );
    }

    /// **The background rectangle a card paints matches the height it reports.**
    ///
    /// Reported height and painted height are two separate outputs, and a card that returned the
    /// right number while painting a stale rectangle would leave the next block overlapping a fill.
    #[test]
    fn a_cards_painted_background_matches_the_height_it_reports() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let reported = std::cell::Cell::new(0.0_f32);
        let mut output = egui::FullOutput::default();
        for _ in 0..2 {
            output = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("card-paint")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let at = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(300.0, 600.0));
                    reported.set(card(ui, at, &t, Some("Node"), |flow| {
                        flow.place(|ui, at| (text::body(ui, at, &t, "Connected to a node."), ()));
                    }));
                });
            });
        }
        let painted = card_background(&output.shapes).expect("the card painted a background");
        assert!(
            (painted.height() - reported.get()).abs() < 0.01,
            "the card reported {} px and painted {} px",
            reported.get(),
            painted.height()
        );
    }

    /// A card narrower than its own padding degrades to nothing rather than an inverted rectangle.
    #[test]
    fn a_card_narrower_than_its_padding_draws_nothing() {
        let height = in_a_frame(|ui| {
            let t = crate::confirm::gui::theme::Theme::Light.tokens();
            let at = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(CARD_PAD, 400.0));
            card(ui, at, &t, Some("Node"), |_| {})
        });
        assert_eq!(height, 0.0);
    }
}
