//! The status strip the whole window carries, under the chrome and above every tab.
//!
//! # Why two facts follow the reader everywhere (dig_ecosystem#2358)
//!
//! Whether the agent is running and whether a node is reachable are the two facts that explain the
//! rest of the window. They used to live on one tab, which meant a person standing on Wallet had to
//! go and look somewhere else to learn the node was down — and a down node is frequently *why* the
//! balance in front of them reads "Not known". A fact that explains every other surface belongs on
//! every other surface.
//!
//! # It says only what it can say in two words
//!
//! One line, two badges, no prose. The strip is a GLANCE: it answers "is anything obviously wrong"
//! and nothing else. The reading behind each badge — the node's own sentence, the version, the
//! remedy — stays on the Home tab, because a strip that tried to carry a remedy would either
//! truncate it at 480 px or push the content pane down on every tab to make room for a sentence most
//! readers do not need.
//!
//! # Nothing here is a second derivation
//!
//! Both badges come from the same [`PaneFacts`] the panes read, through the same functions:
//! [`crate::confirm::gui::window::pane::copy::agent_state`] and [`PaneFacts::node_state`]. So the
//! strip and the Home tab cannot come to describe one machine differently — which is the failure the
//! duplicated cache meter was (one figure, two layouts, in two files).

use egui::{Rect, Ui, Vec2};

use super::super::paint;
use super::super::render::{regular, rgba, size, space};
use super::super::theme::Tokens;
use super::pane::{copy, data, facts::PaneFacts};

/// How tall the strip is.
///
/// Sized from what it holds rather than chosen: a badge is [`data::badge`]'s own height, and the
/// padding above and below it is one step of the 4 px rhythm.
pub(super) const HEADER_HEIGHT: f32 = 36.0;

/// Draw the strip across the top of `at`, and report the height it used.
///
/// It senses nothing. Every badge here is a READING, and a reading that responds to a click is a
/// control a person will press expecting something to happen.
pub(super) fn draw(ui: &mut Ui, at: Rect, t: &Tokens, facts: &PaneFacts) -> f32 {
    let bar = Rect::from_min_size(at.left_top(), Vec2::new(at.width(), HEADER_HEIGHT));
    ui.painter().rect_filled(bar, 0, rgba(t.surface));
    paint::rule(ui, bar, bar.bottom(), t);

    let mut x = bar.left() + space::S4;
    x = reading(
        ui,
        egui::Pos2::new(x, bar.center().y),
        t,
        copy::header::AGENT_LABEL,
        copy::agent_state(facts.agent_running),
        agent_tone(facts.agent_running),
    );
    x += space::S4;

    let (node_word, node_tone) = facts.node_state();
    reading(
        ui,
        egui::Pos2::new(x, bar.center().y),
        t,
        copy::header::NODE_LABEL,
        node_word,
        node_tone,
    );

    HEADER_HEIGHT
}

/// How worried to be about the agent's own state.
///
/// A starting agent is a WAIT, not a fault — `window_model` says so in the Home tab's banner, and a
/// strip painting it amber over that banner would be two surfaces disagreeing about one fact. It is
/// still not `Good`, because "Starting" is not a working machine yet.
fn agent_tone(running: bool) -> data::Tone {
    match running {
        true => data::Tone::Good,
        false => data::Tone::Neutral,
    }
}

/// One `label · badge` pair, left-aligned from `at`. Returns the x the next pair may start at.
fn reading(
    ui: &mut Ui,
    at: egui::Pos2,
    t: &Tokens,
    label: &str,
    word: &str,
    tone: data::Tone,
) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), regular(size::XS), rgba(t.muted));
    ui.painter().galley(
        egui::Pos2::new(at.x, at.y - galley.size().y / 2.0),
        galley.clone(),
        egui::Color32::PLACEHOLDER,
    );

    let badge_left = at.x + galley.size().x + space::S2;
    // `badge` measures itself from its own word, so the strip never has to guess a width — which is
    // what keeps a longer word (`Looking for a node`) from being drawn over the next reading.
    let drawn = data::badge(
        ui,
        egui::Pos2::new(badge_left, at.y - space::S3),
        t,
        word,
        tone,
    );
    drawn.right()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray_menu::TrayView;

    /// Every string the strip painted for `view`, at `width`.
    fn painted(view: &TrayView, width: f32) -> Vec<String> {
        laid_out(view, width)
            .into_iter()
            .map(|(said, _where)| said)
            .collect()
    }

    /// Every string the strip painted for `view`, WITH the rectangle it occupies.
    ///
    /// Position is the half a string alone cannot carry: a reading drawn 400 px off the right edge
    /// is painted exactly as faithfully as one that fits, so a test that only collects text cannot
    /// tell a correct layout from an overflowing one.
    fn laid_out(view: &TrayView, width: f32) -> Vec<(String, Rect)> {
        let ctx = egui::Context::default();
        super::super::install_fonts(&ctx);
        let facts = PaneFacts::of_tray(view);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(width, 200.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("header-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            draw(ui, screen, &t, &facts);
                        });
                },
            );
        }

        fn walk(shape: &egui::Shape, out: &mut Vec<(String, Rect)>) {
            match shape {
                egui::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut said = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut said);
        }
        said
    }

    /// **The strip reports the node's state, and it CHANGES with the node** (dig_ecosystem#2358).
    ///
    /// The point of the strip is that a person on any tab learns the node is down without moving, so
    /// the load-bearing half is that the two cases read differently. A strip that painted
    /// `Connected` unconditionally would satisfy any single-case check — which is why both are
    /// driven, and why each is asserted to say the other's word NOWHERE rather than merely to
    /// contain its own.
    #[test]
    fn the_strip_reports_the_node_and_says_something_different_when_it_is_down() {
        let up = painted(
            &TrayView {
                running: true,
                node_connected: true,
                ..TrayView::default()
            },
            960.0,
        );
        let down = painted(
            &TrayView {
                running: true,
                node_connected: false,
                ..TrayView::default()
            },
            960.0,
        );

        use super::super::pane::facts::{NODE_CONNECTED, NODE_SEARCHING};
        assert!(
            up.iter().any(|said| said == NODE_CONNECTED),
            "a connected node is not reported in the strip: {up:?}"
        );
        assert!(
            !up.iter().any(|said| said == NODE_SEARCHING),
            "a connected node was ALSO described as searching: {up:?}"
        );
        assert!(
            down.iter().any(|said| said == NODE_SEARCHING),
            "the strip does not say the node is unreachable, which is the whole reason it exists: \
             {down:?}"
        );
        assert!(
            !down.iter().any(|said| said == NODE_CONNECTED),
            "an unreachable node was reported as connected: {down:?}"
        );
    }

    /// **The strip reports the agent, and it changes with the agent.**
    ///
    /// The control for the test above: a strip that reported only the node would leave the reader
    /// unable to tell "no node" from "DIG is not running yet", which are different problems with
    /// different remedies.
    #[test]
    fn the_strip_reports_the_agent_separately_from_the_node() {
        let running = painted(
            &TrayView {
                running: true,
                ..TrayView::default()
            },
            960.0,
        );
        let starting = painted(&TrayView::default(), 960.0);

        assert!(running.iter().any(|said| said == copy::agent_state(true)));
        assert!(!running.iter().any(|said| said == copy::agent_state(false)));
        assert!(starting.iter().any(|said| said == copy::agent_state(false)));
        assert!(!starting.iter().any(|said| said == copy::agent_state(true)));
    }

    /// **Both readings survive the narrowest window a person can drag to.**
    ///
    /// The strip is one line and the node's longest word is `Looking for a node`, so 480 px is where
    /// the second reading either fits or is drawn over the first. Asserted by driving the WORST
    /// case — a searching node, whose word is the long one — rather than the connected case, which
    /// fits with room to spare and would prove nothing about the layout under pressure.
    ///
    /// Asserted on GEOMETRY, not on the presence of the strings. An earlier version of this test
    /// checked only that all four strings were painted, which overflow, overlap and a correct
    /// layout all satisfy identically: pushing the node reading 400 px off the right edge of a
    /// 480 px window left it green. What "fits" means is that the last reading's ink ends inside
    /// the bar and the two readings do not occupy the same pixels, so that is what is checked.
    /// Where `word` was painted, failing loudly if the strip never painted it at all.
    fn placed(laid_out: &[(String, Rect)], word: &str) -> Rect {
        laid_out
            .iter()
            .find(|(said, _)| said == word)
            .unwrap_or_else(|| panic!("the strip never painted {word:?}: {laid_out:?}"))
            .1
    }

    #[test]
    fn both_readings_fit_at_the_narrowest_width() {
        let width = super::super::shell::SHELL_MIN;
        let laid = laid_out(
            &TrayView {
                running: true,
                node_connected: false,
                ..TrayView::default()
            },
            width,
        );

        let agent = placed(&laid, copy::header::AGENT_LABEL)
            .union(placed(&laid, copy::agent_state(true)));
        let node = placed(&laid, copy::header::NODE_LABEL)
            .union(placed(&laid, super::super::pane::facts::NODE_SEARCHING));

        // A badge's chip is wider than the word inside it: `data::badge` sizes itself to the galley
        // plus `space::S3`, centred, so the ink the reader sees extends half a step past the text on
        // each side. Measuring the text alone would under-report the strip's true extent by exactly
        // that, and let a reading whose CHIP is clipped pass as fitting.
        let chip_overhang = space::S3 / 2.0;
        assert!(
            node.right() + chip_overhang <= width,
            "the node reading ends at {} px in a {width} px window, so it is drawn off the right \
             edge: {laid:?}",
            node.right() + chip_overhang
        );
        assert!(
            !agent.intersects(node),
            "the two readings overlap — agent occupies {agent:?}, node {node:?}"
        );
    }
}
