//! The dropdown: a labelled chooser over a short list of options, one of which is in force.
//!
//! # Why a dropdown and not a row of buttons
//!
//! A run of buttons says "here are some things you could do". A chooser says "this is the setting,
//! and here is what it is" — which is what a channel, a cache preset or any other one-of-N setting
//! IS. It also keeps the card's height flat as options are added, where buttons grow it.
//!
//! # Why `egui::ComboBox` and not a hand-rolled popup
//!
//! `professional-ui`'s reuse rule, and one specific hazard behind it: an open popup is a blocking
//! element, so it MUST have a way out. `ComboBox` already closes on `Esc`, on a click outside it and
//! on a selection, and it is keyboard-navigable. A popup written here would be a second escape
//! implementation to get right, and the failure mode of getting it wrong is a person stuck with a
//! list they cannot dismiss.
//!
//! What this module adds is the LOOK: egui's default widget palette is not hub's, so the control is
//! dressed in [`Tokens`] before it draws — one place, so a second chooser elsewhere in the window
//! cannot be a different shade of the same control.
//!
//! # What it does NOT decide
//!
//! Nothing. The options are the model's own rows, with the model's labels, unchanged — including the
//! word that marks which one is in force, which is a WORD and not a tick because the window's font
//! stack has no U+2713 and a glyph would photograph as a tofu box (`tray_menu::channel_row_label`).

use egui::{Rect, Ui, Vec2};

use super::text;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{radius, regular, rgba, size, space};
use crate::confirm::gui::theme::Tokens;

/// One thing a person can choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Choice<Id> {
    /// What it says — the model's label, verbatim.
    pub(crate) label: String,
    /// What the caller gets back when it is chosen.
    pub(crate) id: Id,
}

/// A labelled chooser over `options`, with `selected` in force.
pub(crate) struct Select<'a, Id> {
    /// The name of the setting, above the control.
    pub(crate) label: &'a str,
    /// The options, in the model's order.
    pub(crate) options: &'a [Choice<Id>],
    /// Which option is in force, if the surface knows. `None` draws the prompt instead of a value —
    /// never a guess at the first option, which would show a setting nobody reported.
    pub(crate) selected: Option<usize>,
    /// Said in the closed control when nothing is selected.
    pub(crate) unknown: &'a str,
    /// The element id, so the open list survives the pane being rebuilt every frame.
    pub(crate) id: egui::Id,
}

/// The gap between the label and the control it names.
const LABEL_GAP: f32 = space::S1;

/// How wide the closed control is drawn, at most.
///
/// The same reasoning as the input cap in [`super::field`]: a chooser holding `Stable — tested
/// releases only — current` needs this much and no more, and a full-pane-width dropdown reads as a
/// mistake.
const SELECT_CAP: f32 = 640.0;

/// Draw `select`, and report the option CHOSEN — which is `None` unless a person just picked one.
///
/// Picking the option already in force reports nothing: the person asked for the state the machine
/// is already in, and running a privileged command to reach it would ask for an administrator to
/// change nothing. That is a presentation choice about a no-op, not a rule about which options
/// exist — every option the model offered is still offered.
pub(crate) fn select<Id: Clone + PartialEq>(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    select: &Select<'_, Id>,
) -> (f32, Option<Id>) {
    let mut y = at.top();
    y += text::caption(ui, row(at, y), t, select.label);
    y += LABEL_GAP;

    let control = Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width().min(SELECT_CAP), paint::BUTTON_HEIGHT),
    );

    let shown = select
        .selected
        .and_then(|at| select.options.get(at))
        .map(|choice| choice.label.clone())
        .unwrap_or_else(|| select.unknown.to_string());

    let mut chosen = None;
    ui.scope_builder(egui::UiBuilder::new().max_rect(control), |ui| {
        dress(ui, t);
        if !live {
            // While a prompt is up nothing on the pane is pressable, and a chooser that could still
            // be opened would contradict the scrim over it.
            ui.disable();
        }
        egui::ComboBox::from_id_salt(select.id)
            .selected_text(egui::RichText::new(shown).font(regular(size::BASE)))
            .width(control.width() - space::S4)
            .show_ui(ui, |ui| {
                for (index, option) in select.options.iter().enumerate() {
                    let already = select.selected == Some(index);
                    let picked = ui
                        .selectable_label(
                            already,
                            egui::RichText::new(option.label.clone()).font(regular(size::BASE)),
                        )
                        .clicked();
                    if picked && !already {
                        chosen = Some(option.id.clone());
                    }
                }
            });
    });

    (control.bottom() - at.top(), chosen)
}

/// A full-width strip of `at` starting at `y`, for a block that measures its own height.
fn row(at: Rect, y: f32) -> Rect {
    Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width(), f32::INFINITY),
    )
}

/// Dress egui's widget palette in hub's tokens, for the width of this control.
///
/// Scoped rather than global on purpose: this is the one place in the window that uses an egui
/// widget rather than a painted one, and changing the context-wide style to suit it would quietly
/// restyle anything else that ever does.
fn dress(ui: &mut Ui, t: &Tokens) {
    let visuals = &mut ui.visuals_mut().widgets;
    for (state, edge) in [
        (&mut visuals.inactive, t.border),
        (&mut visuals.hovered, t.border_strong),
        (&mut visuals.active, t.dig_purple),
        (&mut visuals.open, t.dig_purple),
    ] {
        state.bg_fill = rgba(t.surface_2);
        state.weak_bg_fill = rgba(t.surface_2);
        state.bg_stroke = egui::Stroke::new(1.0_f32, rgba(edge));
        state.fg_stroke = egui::Stroke::new(1.0_f32, rgba(t.text));
        state.corner_radius = egui::CornerRadius::same(radius::SM);
    }
    let visuals = ui.visuals_mut();
    // The focus ring the rest of the pane draws, on the control egui draws for us.
    visuals.selection.bg_fill = rgba(t.dig_wash);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, rgba(t.text));
    visuals.window_fill = rgba(t.surface);
    visuals.window_stroke = egui::Stroke::new(1.0_f32, rgba(t.border));
    visuals.panel_fill = rgba(t.surface);
    visuals.override_text_color = Some(rgba(t.text));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::theme::Theme;

    /// Two options, the second in force.
    fn options() -> Vec<Choice<u8>> {
        vec![
            Choice {
                label: "Stable — tested releases only".to_string(),
                id: 0,
            },
            Choice {
                label: "Nightly — the newest builds, tested less — current".to_string(),
                id: 1,
            },
        ]
    }

    /// Run frames over one chooser, feeding `events`, and report what it drew and what was chosen.
    fn drawn(selected: Option<usize>, events: Vec<Vec<egui::Event>>) -> (Vec<String>, Option<u8>) {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(480.0, 480.0));
        let choices = options();
        let mut chosen = None;
        let mut output = egui::FullOutput::default();

        // Two settling frames first: the font atlas is built on the first, laid out against on the
        // second, so a click in the third lands on a control that is where it will stay.
        let frames = [vec![Vec::new(), Vec::new()], events].concat();
        for events in frames {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("select-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let (_, picked) = select(
                                ui,
                                screen,
                                &t,
                                true,
                                &Select {
                                    label: "Which builds to follow",
                                    options: &choices,
                                    selected,
                                    unknown: "Not reported",
                                    id: egui::Id::new("select-test-control"),
                                },
                            );
                            chosen = chosen.or(picked);
                        });
                },
            );
        }

        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut said = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut said);
        }
        (said, chosen)
    }

    /// A click at `pos`, as three events.
    fn click(pos: egui::Pos2) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]
    }

    /// **The closed control shows the option in force, with the model's own words for it.**
    ///
    /// Including the word that marks it as current: the mark is a WORD because the window's font has
    /// no tick glyph, and a chooser that showed only the channel's NAME would drop the mark that
    /// `tray_menu` deliberately spells out. Asserted against the option's whole label rather than a
    /// substring, so a control that truncated or re-worded it fails.
    #[test]
    fn the_closed_control_says_which_option_is_in_force() {
        let (said, _) = drawn(Some(1), Vec::new());
        assert!(
            said.contains(&options()[1].label),
            "the closed chooser did not show the option in force verbatim: {said:?}"
        );
        assert!(
            !said.contains(&options()[0].label),
            "the closed chooser drew the option that is NOT in force: {said:?}"
        );
    }

    /// **A surface that does not know the setting says so rather than showing the first option.**
    ///
    /// The honesty rule on a chooser: a dropdown resting on option one is indistinguishable from one
    /// reporting that option one is in force.
    #[test]
    fn an_unknown_setting_is_never_drawn_as_the_first_option() {
        let (said, chosen) = drawn(None, Vec::new());
        assert!(said.iter().any(|line| line == "Not reported"), "{said:?}");
        assert!(!said.contains(&options()[0].label), "{said:?}");
        assert_eq!(chosen, None);
    }

    /// **Opening the list shows every option; `Esc` closes it and chooses nothing.**
    ///
    /// The escape is the point (`professional-ui` HARD RULE 1): an open popup is a blocking element,
    /// and one that could not be dismissed would leave a person stuck over a list. The pair also
    /// pins that dismissing is not the same as choosing — a close that reported a selection would
    /// change the channel of anyone who changed their mind.
    #[test]
    fn the_list_opens_and_escape_closes_it_without_choosing() {
        let open = click(egui::Pos2::new(100.0, 40.0));
        let (opened, chosen) = drawn(Some(1), vec![open.clone(), Vec::new()]);
        assert!(
            opened.contains(&options()[0].label),
            "the list did not open, so nothing below is being tested: {opened:?}"
        );
        assert_eq!(chosen, None, "merely opening the list chose something");

        let escape = vec![egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::default(),
        }];
        let (closed, chosen) = drawn(Some(1), vec![open, Vec::new(), escape, Vec::new()]);
        assert!(
            !closed.contains(&options()[0].label),
            "Escape left the list open: {closed:?}"
        );
        assert_eq!(chosen, None, "Escape chose an option");
    }
}
