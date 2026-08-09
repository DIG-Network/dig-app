//! The states a pane can be in, and how each one looks.
//!
//! # Four states — the ones `professional-ui` asks for, and no more (dig_ecosystem#2397)
//!
//! Loading, error, empty, success. There was briefly a fifth, `Unwired`, because tabs shipped as
//! designed skeletons ahead of the node plumbing behind them (dig_ecosystem#2326): a card whose data
//! did not exist yet said so in words rather than drawing a plausible zero.
//!
//! It is gone because the last two skeletons were plumbed in, and a state nothing can reach is worse
//! than no state at all — it is a banner a pane can still opt into, saying a card is not reporting on
//! this machine when it is. What it protected is now carried by the four real states plus
//! [`data::Value::Unknown`](super::data::Value::Unknown): a read in flight is [`Self::Waiting`], a
//! read that failed is [`Self::Unreachable`] naming the remedy, and a figure nobody has is an
//! `Unknown` carrying its own reason. The honesty rule is unchanged — **a card must never imply a
//! fact it does not have** — and every one of those spellings is now a claim about the MACHINE
//! rather than about dig-app's build order.
//!
//! Success draws no banner at all: a pane whose content is present says so by showing it. A banner
//! reading "loaded successfully" over a working pane is noise that trains people to skip banners.

use egui::{Rect, Ui, Vec2};

use super::text;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{rgba, space};
use crate::confirm::gui::theme::Tokens;
use crate::window_model::PaneNote;

/// How complete a pane's content is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PaneState {
    /// Everything is present. Draws nothing.
    Ready,
    /// The figures are on their way. Names what is being waited for, so the wait is not a mystery.
    Waiting(String),
    /// The figures could not be fetched. Names the remedy, because an error with no way forward is
    /// a dead end.
    Unreachable(String),
    /// The pane works and has nothing for this person. Names what would change that.
    Empty(String),
}

impl PaneState {
    /// The model's own note for a tab, as a pane state.
    ///
    /// A straight mapping: the four async states are decided by [`crate::window_model`] from the
    /// same snapshot the rows come from, and re-deciding them here would be the second
    /// implementation this whole design exists to avoid.
    ///
    /// A CARD may still build a state directly — the Content tab's list card does, because the
    /// hosted-store read has its own three-state reading and its own remedies, which the tab-level
    /// note knows nothing about. That is a state about one card, drawn inside it, beneath the tab's
    /// own banner.
    pub(crate) fn of_note(note: &PaneNote) -> Self {
        match note {
            PaneNote::Ready => Self::Ready,
            PaneNote::Waiting(text) => Self::Waiting((*text).to_string()),
            PaneNote::Unreachable(text) => Self::Unreachable((*text).to_string()),
            PaneNote::Empty(text) => Self::Empty((*text).to_string()),
        }
    }

    /// Whether this state draws a banner at all.
    pub(crate) fn is_silent(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Draw the pane's state banner at the top of `at`. Returns the height used — zero when silent.
pub(crate) fn banner(ui: &mut Ui, at: Rect, t: &Tokens, state: &PaneState) -> f32 {
    match state {
        PaneState::Ready => 0.0,
        PaneState::Waiting(sentence) => notice(ui, at, t, Look::Neutral, sentence),
        PaneState::Empty(sentence) => notice(ui, at, t, Look::Neutral, sentence),
        // Only the state that means something is WRONG gets the amber treatment. Painting a
        // still-loading pane in warning colours teaches people to ignore the warning colour.
        PaneState::Unreachable(sentence) => notice(ui, at, t, Look::Problem, sentence),
    }
}

/// The two treatments a banner has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    /// A recessed panel. For anything that is not wrong.
    Neutral,
    /// The amber panel. For a state a person needs to act on or account for.
    Problem,
}

/// One banner: a sentence inside a panel. Returns its height.
fn notice(ui: &mut Ui, at: Rect, t: &Tokens, look: Look, sentence: &str) -> f32 {
    let pad = space::S3;
    let inner_width = (at.width() - pad * 2.0).max(1.0);
    let ink = match look {
        Look::Neutral => t.muted,
        Look::Problem => t.amber,
    };

    let body = ui.painter().layout(
        sentence.to_owned(),
        crate::confirm::gui::render::regular(crate::confirm::gui::render::size::SM),
        rgba(ink),
        text::measure(inner_width),
    );
    let height = pad + body.size().y + pad;

    let panel = Rect::from_min_size(at.left_top(), Vec2::new(at.width(), height));
    match look {
        Look::Neutral => paint::panel(ui, panel, t),
        Look::Problem => paint::warning_panel(ui, panel, t),
    }

    ui.painter().galley(
        egui::Pos2::new(at.left() + pad, at.top() + pad),
        body,
        egui::Color32::PLACEHOLDER,
    );
    height
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every model note maps onto a pane state, and only success is silent.**
    ///
    /// Exhaustive over `PaneNote`, so a new note added upstream fails to compile here rather than
    /// falling through to a wrong banner. Both sides of silence are asserted: Ready draws nothing,
    /// and each of the other three draws something — a mapping that made everything silent would
    /// satisfy a Ready-only test.
    #[test]
    fn every_note_becomes_a_state_and_only_success_is_silent() {
        let cases = [
            (PaneNote::Ready, true),
            (PaneNote::Waiting("Still starting."), false),
            (PaneNote::Unreachable("Start the node."), false),
            (PaneNote::Empty("Nothing to show."), false),
        ];
        for (note, silent) in cases {
            let state = PaneState::of_note(&note);
            assert_eq!(
                state.is_silent(),
                silent,
                "{note:?} became {state:?}, whose silence is wrong"
            );
        }
    }

    /// **A banner's height matches what it drew, at both widths the window spans.**
    ///
    /// The sentence is a long one — the shape the hosted-store reasons take — so it wraps to more
    /// lines at 300 px than at 520, and a height computed from anything but the laid-out text leaves
    /// the next block sitting on the banner's last line. The narrow case is where that shows.
    #[test]
    fn a_banner_is_taller_when_its_sentence_has_to_wrap_further() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let sentence = PaneState::Unreachable(super::super::copy::content::stores_unknown(
            &crate::hosted_stores::HostedStoresUnknown::Unauthorized,
        ));
        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32));
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("banner-test")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let narrow = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(300.0, 400.0));
                    let wide = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(520.0, 400.0));
                    measured.set((
                        banner(ui, narrow, &t, &sentence),
                        banner(ui, wide, &t, &sentence),
                    ));
                });
            });
        }
        let (narrow, wide) = measured.get();
        assert!(wide > 0.0 && narrow > wide, "narrow {narrow}, wide {wide}");
    }

    /// A ready pane's banner takes no space, so the content starts at the top of the pane.
    #[test]
    fn a_ready_pane_draws_no_banner() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let height = std::cell::Cell::new(-1.0_f32);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::Area::new(egui::Id::new("ready-banner")).show(ctx, |ui| {
                let t = crate::confirm::gui::theme::Theme::Light.tokens();
                height.set(banner(
                    ui,
                    Rect::from_min_size(egui::Pos2::ZERO, Vec2::splat(400.0)),
                    &t,
                    &PaneState::Ready,
                ));
            });
        });
        assert_eq!(height.get(), 0.0);
    }
}
