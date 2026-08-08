//! Values a person takes somewhere else: the copy affordance, and the scannable code.
//!
//! A `xch1…` address, a store id, a peer id and a log path have one thing in common — nobody types
//! them. Showing such a value without a way to lift it off the screen is showing it twice as slowly.

use egui::{Rect, Ui, Vec2};

use super::copy;
use super::data::{self, Value};
use super::text;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{rgba, space, Weight};
use crate::confirm::gui::theme::Tokens;

/// How long the control reads "Copied" before returning to "Copy", in seconds.
///
/// Long enough to be seen after the eye returns from wherever it was pasting, short enough that the
/// control is honest about its resting state by the time anyone looks again.
const CONFIRMATION: f64 = 1.6;

/// A value with a copy control beside it. Returns the height used.
///
/// # Why this can copy without asking the model
///
/// Copying puts on the clipboard a string the pane is ALREADY showing. It grants no capability the
/// reader does not have with their eyes and a keyboard, so it is a presentation affordance rather
/// than a verb — which is why it does not need, and must not invent, a `TrayAction`. A control that
/// revealed something not on screen would be a different thing entirely and would belong to the
/// model.
pub(crate) fn copyable(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    label: &str,
    value: &Value,
    element: egui::Id,
    live: bool,
) -> f32 {
    let control_width = paint::button_width(ui, copy::clipboard::COPIED);
    // The value keeps the full column when there is no room for a control beside it; the control
    // then sits under it rather than squeezing an address into nothing.
    let side_by_side = at.width() > control_width * 2.5;
    let value_width = match side_by_side {
        true => at.width() - control_width - space::S3,
        false => at.width(),
    };

    let mut height = data::readout(
        ui,
        Rect::from_min_size(at.left_top(), Vec2::new(value_width, at.height())),
        t,
        &data::Readout::new(label, value.clone()),
    );

    // Nothing to copy is not a control to disable, it is a control that does not exist: an absent
    // value's readout already carries the sentence saying why, and a greyed Copy beside it would add
    // a second, less informative statement of the same fact.
    if !value.is_known() {
        return height;
    }

    let control = match side_by_side {
        true => Rect::from_min_size(
            egui::Pos2::new(at.right() - control_width, at.top()),
            Vec2::new(control_width, paint::BUTTON_HEIGHT),
        ),
        false => Rect::from_min_size(
            egui::Pos2::new(at.left(), at.top() + height + space::S2),
            Vec2::new(control_width, paint::BUTTON_HEIGHT),
        ),
    };
    if !side_by_side {
        height += space::S2 + paint::BUTTON_HEIGHT;
    }

    let just_copied = confirming(ui, element);
    let response = paint::button_at(
        ui,
        control,
        element,
        match just_copied {
            true => copy::clipboard::COPIED,
            false => copy::clipboard::COPY,
        },
        Weight::Ghost,
        live,
        t,
    );
    // `clicked()` covers the keyboard too: egui synthesises a primary click for a focused widget
    // that senses clicks, and refuses one to a control that does not. See `super::action`.
    if response.clicked() {
        ui.ctx().copy_text(value.shown().to_owned());
        remember_copy(ui, element);
    }
    height
}

/// Whether `element` copied something recently enough to still be confirming it.
///
/// Reading the clock rather than holding a countdown: an immediate-mode surface has no frame loop of
/// its own to tick, and a repaint is requested for the moment the confirmation expires so the label
/// reverts even if nothing else on the window changes.
fn confirming(ui: &Ui, element: egui::Id) -> bool {
    let now = ui.input(|i| i.time);
    let at: Option<f64> = ui.ctx().data(|d| d.get_temp(element));
    match at {
        Some(at) if now - at < CONFIRMATION => {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64(
                    CONFIRMATION - (now - at),
                ));
            true
        }
        _ => false,
    }
}

/// Record that `element` just copied, so the next frames show the confirmation.
fn remember_copy(ui: &Ui, element: egui::Id) {
    let now = ui.input(|i| i.time);
    ui.ctx().data_mut(|d| d.insert_temp(element, now));
}

/// The largest a scannable code is drawn, in pixels.
///
/// A QR only has to be big enough for a phone camera to resolve its modules; past that it is a large
/// grey square dominating a pane.
const QR_CAP: f32 = 220.0;

/// A scannable code on its own plate, with a caption saying what to do with it. Returns the height
/// used.
///
/// # Why the value is NOT printed under the code (dig_ecosystem#2357)
///
/// It used to be, and every caller draws a [`copyable`] readout of the same value immediately below
/// — so Wallet and Status each showed one address twice, three lines apart, in two different faces.
/// A reader who sees the same identifier twice on one card has to compare them before trusting
/// either. The code is the machine's copy of the value and the readout is the reader's; printing a
/// third is not redundancy, it is a question.
///
/// # Why the code is black on white in a dark theme too
///
/// A camera reads CONTRAST, and a dark-theme code drawn in `--surface` on `--text` is one most
/// phones refuse — `paint::qr` says so at its definition and this component does not second-guess
/// it. What IS theme-aware is the surround: the white plate sits inside a themed card with padding,
/// so in dark mode it reads as a deliberate light plate rather than a rendering fault.
///
/// # Why an unencodable value draws nothing
///
/// `QrArt::encode` returns `None` for a string no QR version can hold. The block is then OMITTED and
/// the layout reflows, rather than a blank white square being drawn — an empty plate reads as a
/// broken image, and a person will point a camera at it for as long as it takes to give up.
pub(crate) fn scannable(ui: &mut Ui, at: Rect, t: &Tokens, value: &str, caption: &str) -> f32 {
    let Some(art) = crate::confirm::QrArt::encode(value) else {
        return 0.0;
    };

    let plate_pad = space::S3;
    let side = text::square_within(at, QR_CAP).x - plate_pad * 2.0;
    if side <= 0.0 {
        return 0.0;
    }

    // Centred in the column: a code is a target, and an off-centre target under a centred caption
    // reads as a layout accident.
    let drawn = paint::qr(
        ui,
        egui::Pos2::new(at.center().x - side / 2.0, at.top() + plate_pad),
        side,
        &art,
    );
    let mut y = drawn.bottom() + space::S3;

    y += text::caption(
        ui,
        Rect::from_min_size(
            egui::Pos2::new(at.left(), y),
            Vec2::new(at.width(), (at.bottom() - y).max(0.0)),
        ),
        t,
        caption,
    );
    y - at.top()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame runner that keeps its context, so a test can act across frames.
    struct Surface {
        ctx: egui::Context,
        width: f32,
    }

    impl Surface {
        fn new(width: f32) -> Self {
            let ctx = egui::Context::default();
            crate::confirm::gui::window::install_fonts(&ctx);
            let surface = Self { ctx, width };
            surface.run(Vec::new(), |_, _, _| 0.0);
            surface.run(Vec::new(), |_, _, _| 0.0);
            surface
        }

        /// Draw `body` into a full-width pane for one frame, returning what it measured.
        fn run(
            &self,
            events: Vec<egui::Event>,
            mut body: impl FnMut(&mut Ui, Rect, &Tokens) -> f32,
        ) -> f32 {
            let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(self.width, 700.0));
            let out = std::cell::Cell::new(0.0_f32);
            let _ = self.ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("identity-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            ui.set_clip_rect(screen);
                            let t = crate::confirm::gui::theme::Theme::Light.tokens();
                            out.set(body(ui, screen, &t));
                        });
                },
            );
            out.get()
        }
    }

    /// A real mainnet-shaped address, long enough to exercise wrapping and encoding.
    const ADDRESS: &str = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxjjgtu";

    /// **A value that cannot be encoded draws nothing at all, and one that can draws something.**
    ///
    /// Both sides, because "returns 0" is also what a component that never draws anything returns.
    /// The unencodable fixture is a string longer than the largest QR version can hold — chosen from
    /// the format's own limit (version 40 at this error correction tops out in the low thousands of
    /// bytes) rather than from a number that merely looks big.
    #[test]
    fn an_unencodable_value_is_omitted_and_an_encodable_one_is_drawn() {
        let surface = Surface::new(520.0);
        let too_long = "x".repeat(8_000);
        assert!(
            crate::confirm::QrArt::encode(&too_long).is_none(),
            "the fixture encodes after all, so the omission path is never taken"
        );

        let omitted = surface.run(Vec::new(), |ui, at, t| {
            scannable(ui, at, t, &too_long, copy::qr::RECEIVE_CAPTION)
        });
        assert_eq!(omitted, 0.0, "an unencodable value drew a plate anyway");

        let drawn = surface.run(Vec::new(), |ui, at, t| {
            scannable(ui, at, t, ADDRESS, copy::qr::RECEIVE_CAPTION)
        });
        assert!(drawn > 0.0, "an encodable address drew nothing");
    }

    /// **A code is never drawn at a fractional module size.**
    ///
    /// Asserted against the whole range of pane widths the window spans rather than one, because
    /// the rounding only matters at the widths where the division is not exact — a single width
    /// picked by hand is very likely to be one where it is.
    #[test]
    fn a_code_is_always_a_whole_number_of_pixels_per_module() {
        let art = crate::confirm::QrArt::encode(ADDRESS).expect("an address encodes");
        for available in 60..=QR_CAP as i32 {
            let module = art.module_pixels(available);
            assert!(module >= 1, "at {available} px the module collapsed");
            assert!(
                art.drawn_pixels(module) <= available,
                "at {available} px the code drew {} px",
                art.drawn_pixels(module)
            );
        }
    }

    /// **Copying puts the value on the clipboard, and the control says so afterwards.**
    ///
    /// The confirmation is the half that is easy to fake: a control that always read "Copy" would
    /// still copy correctly. So the label is read from the painted shapes BEFORE and AFTER the
    /// click, and both are asserted — a control stuck on either word fails one of them.
    #[test]
    fn copying_reaches_the_clipboard_and_the_control_confirms_it() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let element = egui::Id::new("copy-test-control");
        let value = Value::Identifier(ADDRESS.to_string());

        let mut copied: Option<String> = None;
        let mut labels: Vec<Vec<String>> = Vec::new();

        let frame = |events: Vec<egui::Event>,
                     copied: &mut Option<String>,
                     labels: &mut Vec<Vec<String>>| {
            let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(600.0, 400.0));
            let out = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("copy-frame"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            ui.set_clip_rect(screen);
                            let t = crate::confirm::gui::theme::Theme::Light.tokens();
                            copyable(ui, screen, &t, "Receive address", &value, element, true);
                        });
                },
            );
            if !out.platform_output.commands.is_empty() {
                for command in &out.platform_output.commands {
                    if let egui::OutputCommand::CopyText(text) = command {
                        *copied = Some(text.clone());
                    }
                }
            }
            labels.push(painted_words(&out.shapes));
        };

        frame(Vec::new(), &mut copied, &mut labels);
        frame(Vec::new(), &mut copied, &mut labels);
        let control = ctx
            .read_response(element)
            .expect("the copy control was laid out")
            .rect;
        assert!(
            labels
                .last()
                .expect("a frame")
                .iter()
                .any(|w| w == copy::clipboard::COPY),
            "the resting control does not read {:?}",
            copy::clipboard::COPY
        );

        let at = control.center();
        for event in [
            egui::Event::PointerMoved(at),
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ] {
            frame(vec![event], &mut copied, &mut labels);
        }
        frame(Vec::new(), &mut copied, &mut labels);

        assert_eq!(
            copied.as_deref(),
            Some(ADDRESS),
            "the address did not reach the clipboard"
        );
        assert!(
            labels
                .last()
                .expect("a frame")
                .iter()
                .any(|w| w == copy::clipboard::COPIED),
            "after copying, the control still does not read {:?}",
            copy::clipboard::COPIED
        );
    }

    /// **An absent value offers no copy control.**
    ///
    /// A greyed Copy beside "the node has not answered yet" states the same fact less clearly. The
    /// control must be absent, not disabled — asserted by asking egui whether it was laid out at
    /// all, which a merely-dimmed control would still have been.
    #[test]
    fn an_absent_value_has_no_copy_control() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let element = egui::Id::new("absent-copy-control");
        let absent = Value::Unknown("Unlock this account to see its address.".to_string());
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(600.0, 400.0));
        for _ in 0..2 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("absent-frame")).show(ctx, |ui| {
                        let t = crate::confirm::gui::theme::Theme::Light.tokens();
                        copyable(ui, screen, &t, "Receive address", &absent, element, true);
                    });
                },
            );
        }
        assert!(
            ctx.read_response(element).is_none(),
            "a copy control was laid out for a value there is nothing to copy from"
        );
    }

    /// Every word painted in a frame, so a test can read a control's label back.
    fn painted_words(shapes: &[egui::epaint::ClippedShape]) -> Vec<String> {
        fn walk(shape: &egui::Shape, found: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => found.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut found);
        }
        found
    }
}
