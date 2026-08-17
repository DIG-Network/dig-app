//! The form field: a labelled text input with its help text, and its error attached beneath IT.
//!
//! # Why the error belongs to the field
//!
//! `professional-ui` is explicit that an error is attached to the control that caused it rather than
//! dumped at the bottom of a form. On a pane that will grow more than one setting, a shared error
//! line at the foot would make a person guess which field it was about — and the guess is wrong
//! exactly when two fields are wrong at once.
//!
//! # Why the input is the prompt's input
//!
//! The consent prompts already draw a text field ([`super::super::super::window`]): `TextEdit`, the
//! recessed surface, hub's margins and the brand face. This places that same control in a rectangle
//! the pane chose rather than through egui's layout, for the reason
//! [`paint::button_at`](crate::confirm::gui::paint::button_at) exists — a second input style would
//! be a second look for one product.

use egui::{Rect, Ui, Vec2};

use super::text;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{radius, regular, rgba, size, space};
use crate::confirm::gui::theme::Tokens;

/// One labelled text input, and everything said about it.
pub(crate) struct Field<'a> {
    /// The name of the setting, above the input.
    pub(crate) label: &'a str,
    /// What the input expects, drawn in the input while it is empty. Never a fake value: this is
    /// what an empty field MEANS, which for every setting here is "DIG chooses".
    pub(crate) placeholder: &'a str,
    /// The sentence under the input when there is nothing wrong with it.
    pub(crate) help: &'a str,
    /// What is wrong with what was typed, if anything. Replaces [`help`](Self::help), because two
    /// lines under one input is a person reading the wrong one.
    pub(crate) error: Option<String>,
    /// The element id, so focus and the caret survive the pane being rebuilt every frame.
    pub(crate) id: egui::Id,
}

/// The gap between a label and the control it names: the smallest step, because they are one thing.
const LABEL_GAP: f32 = space::S1;

/// Draw `field` over `text`, and report the height it took.
///
/// `live` is false while a prompt is up, and the field is then drawn but not editable — the same
/// rule every other control on the pane follows, so the scrim's "you cannot use this right now" is
/// not contradicted by a caret blinking underneath it.
pub(crate) fn text_field(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    field: &Field<'_>,
    value: &mut String,
) -> f32 {
    labelled(ui, at, t, field, paint::BUTTON_HEIGHT, |ui, input| {
        input_box(ui, input, t, live, field, value, Lines::One);
    })
}

/// The same field, over a box a person may press Return inside.
///
/// # Why this is a second entry point and not a flag on [`text_field`]
///
/// `text_field` has six callers across four panes, and every one of them constructs a [`Field`]
/// literal. Adding a variant to either would edit all six for the benefit of the one field that
/// needs it — so the shared scaffolding is extracted and this sits beside it, changing nothing that
/// already works.
///
/// `rows` is the box's height in lines of text. It is a floor and not a cap: the value may be longer
/// and the box scrolls, exactly as a paragraph control should — a value silently truncated to what
/// fits would be published truncated.
pub(crate) fn paragraph_field(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    field: &Field<'_>,
    value: &mut String,
    rows: usize,
) -> f32 {
    let height = paint::BUTTON_HEIGHT + LINE_HEIGHT * rows.saturating_sub(1) as f32;
    labelled(ui, at, t, field, height, |ui, input| {
        input_box(ui, input, t, live, field, value, Lines::Many(rows));
    })
}

/// The label above, the input in the middle, and the one sentence under it.
///
/// Everything a field draws EXCEPT the control itself, so the single-line and multi-line boxes
/// cannot come to disagree about where their label sits or which sentence they show.
fn labelled(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    field: &Field<'_>,
    input_height: f32,
    draw_input: impl FnOnce(&mut Ui, Rect),
) -> f32 {
    let mut y = at.top();
    y += text::caption(ui, row(at, y), t, field.label);
    y += LABEL_GAP;

    let input = Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width().min(INPUT_CAP), input_height),
    );
    draw_input(ui, input);
    y = input.bottom() + LABEL_GAP;

    y += match &field.error {
        Some(problem) => error_text(ui, row(at, y), t, problem),
        None => text::caption(ui, row(at, y), t, field.help),
    };
    y - at.top()
}

/// How many lines of text a box takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lines {
    /// One, and Return does not insert anything.
    One,
    /// Several, and Return inserts a newline.
    Many(usize),
}

/// How much taller each line past the first makes a box.
///
/// egui lays a paragraph out at its own line height, so this is used only to RESERVE the rectangle;
/// the widget is what decides where the glyphs land inside it.
const LINE_HEIGHT: f32 = 20.0;

/// The widest an input is drawn.
///
/// A card stretches to the pane; a one-line setting does not benefit past this. It is the same
/// reasoning — and the same figure — as the grid cap in [`super::data`]: a 1,400 px box for
/// `http://localhost:9778` reads as a mistake, not as generosity.
const INPUT_CAP: f32 = 640.0;

/// A full-width strip of `at` starting at `y`, for a block that measures its own height.
fn row(at: Rect, y: f32) -> Rect {
    Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width(), f32::INFINITY),
    )
}

/// The input itself: the prompt's `TextEdit`, placed in a rectangle the pane chose.
fn input_box(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    field: &Field<'_>,
    value: &mut String,
    lines: Lines,
) {
    let invalid = field.error.is_some();
    // Drawn under the widget so the edge is the field's, not egui's: the `TextEdit` itself is
    // frameless, and the border is what carries "there is something wrong here" alongside the
    // message — colour is never the only thing saying it.
    let edge = match (invalid, live) {
        (true, _) => t.danger,
        (false, _) => t.border,
    };
    ui.painter().rect(
        at,
        egui::CornerRadius::same(radius::SM),
        rgba(t.surface_2),
        egui::Stroke::new(1.0_f32, rgba(edge)),
        egui::StrokeKind::Inside,
    );

    let edit = match lines {
        Lines::One => egui::TextEdit::singleline(value),
        // `desired_rows` rather than a clipped `singleline`: a multi-line value in a one-line box
        // shows its first line and hides the rest, so a person editing four links would see one and
        // conclude the others were lost.
        Lines::Many(rows) => egui::TextEdit::multiline(value).desired_rows(rows),
    };
    let edit = edit
        .id(field.id)
        .frame(false)
        .interactive(live)
        .hint_text(field.placeholder)
        .desired_width(at.width() - space::S3 * 2.0)
        .margin(egui::Margin::symmetric(space::S3 as i8, space::S2 as i8))
        .text_color(rgba(t.text))
        .font(regular(size::BASE));
    let response = ui.put(at, edit);

    // The focus ring is the button's ring, for the button's reason: on a window where a control can
    // change what this computer talks to, the person has to be able to SEE which one is focused.
    if response.has_focus() {
        ui.painter().rect_stroke(
            at.expand(2.0),
            egui::CornerRadius::same(radius::SM),
            egui::Stroke::new(2.0_f32, rgba(t.dig_purple)),
            egui::StrokeKind::Outside,
        );
    }
}

/// The inline error, in the destructive text colour at the caption size.
///
/// The one place this module picks a colour, and deliberately: `text` carries PROSE roles, and an
/// error attached to a control is not prose — it is part of the control. `danger_text` rather than
/// `danger`, because the bright accent fails AA as small text on a light surface (that is precisely
/// why the theme carries both).
fn error_text(ui: &mut Ui, at: Rect, t: &Tokens, problem: &str) -> f32 {
    let galley = ui.painter().layout(
        problem.to_string(),
        regular(size::SM),
        rgba(t.danger_text),
        at.width(),
    );
    // Selectable, like every other piece of text a pane draws (dig_ecosystem#2569). An error is the
    // sentence a person is most likely to need to hand to somebody else, and it is frequently the
    // one they cannot paraphrase.
    super::selectable::text(ui, at.left_top(), galley)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::theme::Theme;

    /// Every string the painter was asked to draw in `output`.
    fn painted(output: &egui::FullOutput) -> Vec<String> {
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// Draw one field into a real context and report what came back.
    fn drawn(field: &Field<'_>, value: &str) -> (f32, Vec<String>) {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(480.0, 480.0));
        let mut text = value.to_string();
        let mut height = 0.0;
        // Two frames: the first builds the font atlas, the second lays out against it.
        let mut output = egui::FullOutput::default();
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("field-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            height = text_field(ui, screen, &t, true, field, &mut text);
                        });
                },
            );
        }
        (height, painted(&output))
    }

    fn field(error: Option<&str>) -> Field<'static> {
        Field {
            label: "Node address",
            placeholder: "Automatic",
            help: "Leave this empty and DIG finds a node itself.",
            error: error.map(str::to_string),
            id: egui::Id::new("field-test-input"),
        }
    }

    /// **An invalid field shows the problem INSTEAD of its help text, not beside it.**
    ///
    /// Two things are pinned at once because they are one property: the reader must see the reason,
    /// and must not be left choosing between two sentences about the same control. A field that
    /// appended the error would satisfy "the error is visible" and fail this.
    #[test]
    fn an_error_replaces_the_help_text_rather_than_joining_it() {
        let problem = "DIG talks to a node over http or https.";
        let (_, said) = drawn(&field(Some(problem)), "ftp://nope");
        assert!(
            said.iter().any(|line| line.contains(problem)),
            "the field never drew its error: {said:?}"
        );
        assert!(
            !said.iter().any(|line| line.contains("Leave this empty")),
            "the field drew its help text under an error, so two sentences describe one input: \
             {said:?}"
        );

        let (_, healthy) = drawn(&field(None), "");
        assert!(
            healthy.iter().any(|line| line.contains("Leave this empty")),
            "the field drops its help text even when nothing is wrong: {healthy:?}"
        );
    }

    /// **The label and the placeholder are both drawn, and the placeholder is not a value.**
    ///
    /// A hint that reads as a value is the honesty rule one level down: `Automatic` is what an EMPTY
    /// field means here, and it must not survive into the box once a person types.
    #[test]
    fn the_placeholder_shows_only_while_the_field_is_empty() {
        let (_, empty) = drawn(&field(None), "");
        assert!(empty.iter().any(|line| line.contains("Node address")));
        assert!(
            empty.iter().any(|line| line.contains("Automatic")),
            "an empty field said nothing about what empty means: {empty:?}"
        );

        let (_, typed) = drawn(&field(None), "http://localhost:9778");
        assert!(
            typed
                .iter()
                .any(|line| line.contains("http://localhost:9778")),
            "the field did not draw what was typed into it: {typed:?}"
        );
        assert!(
            !typed.iter().any(|line| line.contains("Automatic")),
            "the placeholder is still drawn over a filled field: {typed:?}"
        );
    }

    /// How many LINES the painter laid `needle`'s text out on.
    ///
    /// Not how many characters it was handed. A single-line `TextEdit` holding a value with
    /// newlines in it produces a galley whose `text()` is the whole string — every line present,
    /// every character intact — laid out on ONE row. So a test that reads the galley's text sees a
    /// three-line value in a control that shows one line of it, and passes on both. The row count
    /// is what a person actually sees, and it is the only reading here that tells them apart.
    /// (Written the other way first; the revert-proof caught it.)
    fn laid_out_rows(output: &egui::FullOutput, needle: &str) -> Vec<usize> {
        fn walk(shape: &egui::Shape, out: &mut Vec<(String, usize)>) {
            match shape {
                egui::Shape::Text(text) => {
                    out.push((text.galley.text().to_owned(), text.galley.rows.len()))
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut seen = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut seen);
        }
        seen.into_iter()
            .filter(|(text, _)| text.contains(needle))
            .map(|(_, rows)| rows)
            .collect()
    }

    /// Draw one field through `draw`, and hand back the frame it produced.
    fn frame_of(draw: impl Fn(&mut Ui, Rect, &Tokens, &mut String)) -> egui::FullOutput {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(480.0, 480.0));
        let mut text = A_THREE_LINE_VALUE.to_string();
        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("lines-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| draw(ui, screen, &t, &mut text));
                },
            );
        }
        output
    }

    /// Three links, which is what the schema's newline separator is FOR.
    const A_THREE_LINE_VALUE: &str =
        "https://one.example\nhttps://two.example\nhttps://three.example";

    /// **A paragraph field lays a three-line value out on three lines; the shipped single-line box
    /// lays the same value out on one.**
    ///
    /// This is what dig_ecosystem#3070's fix rests on. `dig-social-profile` defines the links slot
    /// as newline-separated, so the editor now asks for one address per line — and that instruction
    /// is unfollowable in a control that shows the first line only.
    ///
    /// # Why the single-line control is the fixture's control leg
    ///
    /// The nearest wrong implementation is not "no box at all": it is the box that ships today,
    /// which accepts the same string and shows one line of it. Both draw the label, both draw the
    /// help, both report a height, and — the part that made the first version of this test vacuous
    /// — both produce a galley whose TEXT holds all three lines. Only the layout differs, so both
    /// are drawn here and their row counts are required to differ.
    #[test]
    fn a_paragraph_field_lays_out_every_line_where_the_single_line_box_lays_out_one() {
        let links = a_links_field();

        let many = frame_of(|ui, at, t, value| {
            paragraph_field(ui, at, t, true, &links, value, 3);
        });
        assert_eq!(
            laid_out_rows(&many, "one.example"),
            vec![3],
            "the paragraph box did not lay the three links out on three lines, so a person \
             editing them can see only the first"
        );

        // The control: the SAME value through the shipped single-line control, which must give the
        // other answer. Without it, an assertion about "three rows" says nothing about whether
        // this control is any different from the one it replaces.
        let one = frame_of(|ui, at, t, value| {
            text_field(ui, at, t, true, &links, value);
        });
        assert_eq!(
            laid_out_rows(&one, "one.example"),
            vec![1],
            "the single-line box already laid the value out on several lines, so the assertion \
             above distinguishes nothing"
        );
    }

    /// The Links field, as the profile form describes it.
    fn a_links_field() -> Field<'static> {
        Field {
            label: "Links",
            placeholder: "None",
            help: "Web addresses, one per line.",
            error: None,
            id: egui::Id::new("links-test-input"),
        }
    }

    /// **A field reports a height that contains everything it drew.**
    ///
    /// The flow places the NEXT block at this offset, so a short answer overlaps the field's own
    /// error — and an error that draws under the next card is one nobody reads. Compared against a
    /// field with no error rather than against a pixel count (#2320): the property is that the taller
    /// content reserves more room, not that it reserves 61 px.
    #[test]
    fn the_height_grows_to_cover_a_wrapped_error() {
        let short = drawn(&field(None), "").0;
        let long = drawn(
            &field(Some(
                "A node address needs a host, like http://localhost:9778 — this one has none, so \
                 DIG would not know what to dial.",
            )),
            "http://",
        )
        .0;
        assert!(
            long > short,
            "a field with a wrapped two-line error reserved no more room ({long}) than one with a \
             one-line help text ({short}), so the next block would be drawn over it"
        );
    }
}
