//! The one place a pane puts text on the screen — and why every piece of it can be selected
//! (dig_ecosystem#2569).
//!
//! # A value you cannot select is a value you have to retype
//!
//! The window shows addresses, DIDs, coin ids, store ids, capsule ids and error text. Every one of
//! those is useless when it cannot be copied and DANGEROUS when it is retyped: a `xch1…` address
//! copied by eye is how money goes to the wrong place, and a 64-hex store id transcribed by hand is
//! wrong more often than it is right.
//!
//! # Selectability is a property of the drawing, not of the call sites
//!
//! egui makes an [`egui::Label`] selectable by default; it makes a galley painted straight onto
//! [`egui::Painter`] selectable never. Every pane here painted galleys, so every readout in the
//! window was dead text — and annotating call sites one at a time would leave the NEXT readout dead
//! again, which is how the defect got here in the first place.
//!
//! So there is exactly one function, [`text`], and every pane draws through it. A new readout
//! inherits selection by existing. Nothing about the pixels changes: the galley is laid out by the
//! caller exactly as before and handed to the widget already positioned, so this is the same ink
//! with a widget wrapped around it.
//!
//! # Selection does NOT replace a copy button
//!
//! A copy affordance beside a 64-hex value is still the right control — it is one click, it cannot
//! half-select, and it works for a person who cannot drag a pointer accurately. Selection is the
//! floor, not the ceiling, and every existing copy control stays exactly where it is.

use std::sync::Arc;

use egui::{Galley, Rect, Ui, Vec2};

/// Draw an already-laid-out `galley` with its top-left at `at`, selectable, and report its height.
///
/// The galley is laid out by the CALLER, which is what keeps this a change of widget rather than a
/// change of layout: wrap width, font, colour and position are decided exactly where they were
/// before, and this only decides that the result is a widget rather than paint.
pub(crate) fn text(ui: &mut Ui, at: egui::Pos2, galley: Arc<Galley>) -> f32 {
    let height = galley.size().y;
    // Sized to the galley, so the label's own hit area is the text and nothing around it. A label
    // given a larger rectangle would extend the selection target over whatever sits beside it.
    let rect = Rect::from_min_size(at, galley.size().max(Vec2::splat(1.0)));
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        // `Color32::PLACEHOLDER` is what the painter path passed too: the galley's own sections
        // already carry their colours, and a fallback here would silently repaint a `--faint`
        // absence in the body colour.
        ui.add(egui::Label::new(galley).selectable(true));
    });
    height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::{mono, regular, size};

    /// A 64-hex store id — the value class this module exists for, and the one nobody can retype.
    const STORE_ID: &str = "3f9a1c0b7e2d48561a0c9f3b8d47e25610fa3c9b2e5d704816af39c2b0d5e871";

    /// Drag across `text` drawn by `draw`, press Ctrl+C, and report what reached the clipboard.
    ///
    /// A REAL pointer drag and a REAL copy, because the property under test is that the drawn text
    /// participates in egui's selection at all. Asserting that a `Label` was constructed would
    /// assert the implementation; asserting that dragging over it puts its characters on the
    /// clipboard asserts what the person actually gets.
    fn drag_and_copy(draw: impl Fn(&mut Ui)) -> Vec<String> {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let mut copied = Vec::new();
        // Frame 1 builds the font atlas, 2 lays out against it, 3-5 press, drag and release, 6
        // copies. The pointer path is separate events on separate frames because egui decides a
        // drag from movement BETWEEN frames.
        let events = [
            vec![],
            vec![],
            vec![egui::Event::PointerMoved(egui::Pos2::new(2.0, 6.0))],
            vec![egui::Event::PointerButton {
                pos: egui::Pos2::new(2.0, 6.0),
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            }],
            vec![egui::Event::PointerMoved(egui::Pos2::new(2_000.0, 6.0))],
            vec![egui::Event::PointerButton {
                pos: egui::Pos2::new(2_000.0, 6.0),
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            }],
            vec![egui::Event::Copy],
        ];
        for batch in events {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(2_400.0, 200.0),
                    )),
                    events: batch,
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("selectable-test"))
                        .fixed_pos(egui::Pos2::ZERO)
                        .show(ctx, |ui| draw(ui));
                },
            );
            for command in output.platform_output.commands {
                if let egui::OutputCommand::CopyText(said) = command {
                    copied.push(said);
                }
            }
        }
        copied
    }

    /// **Text drawn through this module can be selected and copied.**
    ///
    /// The load-bearing test for the whole feature. The fixture is a 64-hex store id drawn in the
    /// identifier font, which is the exact class of value the window shows and a person cannot
    /// retype.
    #[test]
    fn a_value_drawn_through_this_module_can_be_dragged_over_and_copied() {
        let copied = drag_and_copy(|ui| {
            let galley = ui.painter().layout_no_wrap(
                STORE_ID.to_owned(),
                mono(size::SM),
                egui::Color32::BLACK,
            );
            text(ui, egui::Pos2::new(1.0, 1.0), galley);
        });
        assert!(
            copied.iter().any(|said| said.contains(STORE_ID)),
            "dragging across a store id copied nothing usable, so the value is dead text: {copied:?}"
        );
    }

    /// **The control that proves the test above is not passing by accident.**
    ///
    /// The SAME drag and the SAME copy over a galley painted the old way — straight onto the
    /// painter. It must copy nothing. Without this, a harness that put the string on the clipboard
    /// for some unrelated reason would make every selectability claim in this crate vacuous.
    #[test]
    fn the_same_text_painted_the_old_way_copies_nothing() {
        let copied = drag_and_copy(|ui| {
            let galley = ui.painter().layout_no_wrap(
                STORE_ID.to_owned(),
                mono(size::SM),
                egui::Color32::BLACK,
            );
            ui.painter().galley(
                egui::Pos2::new(1.0, 1.0),
                galley,
                egui::Color32::PLACEHOLDER,
            );
        });
        assert!(
            copied.is_empty(),
            "painted-only text was copyable, so the test above proves nothing about the widget: \
             {copied:?}"
        );
    }

    /// A degenerate galley still draws without panicking, and reports its own height.
    #[test]
    fn an_empty_value_is_drawn_without_a_zero_sized_rectangle() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let height = std::cell::Cell::new(-1.0_f32);
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("empty-value")).show(ctx, |ui| {
                    let galley = ui.painter().layout_no_wrap(
                        String::new(),
                        regular(size::SM),
                        egui::Color32::BLACK,
                    );
                    height.set(text(ui, egui::Pos2::ZERO, galley));
                });
            });
        }
        assert!(height.get() >= 0.0);
    }
}
