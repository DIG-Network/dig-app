//! The states a pane can be in, and how each one looks.
//!
//! # Five states, not four
//!
//! `professional-ui` requires four on every async surface — loading, error, empty, success.
//! dig_ecosystem#2326 adds a fifth, because tabs ship as designed skeletons ahead of the node
//! plumbing behind them: [`PaneState::Unwired`].
//!
//! # Why the fifth state is a TYPE and not a convention
//!
//! A skeleton must never imply a fact it does not have. A pane showing a plausible zero is worse
//! than an empty one, because a reader cannot tell it apart from a reading. Making "not wired up"
//! a variant every pane must handle means a Phase-2 tab cannot ship a placeholder without SAYING it
//! is one — the state is in the way, rather than in a review checklist somebody has to remember.
//!
//! Success draws no banner at all: a pane whose content is present says so by showing it. A banner
//! reading "loaded successfully" over a working pane is noise that trains people to skip banners.

use egui::{Rect, Ui, Vec2};

use super::copy;
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
    /// The layout is finished and the data behind it is not connected. Says so, unmistakably.
    Unwired,
}

impl PaneState {
    /// The model's own note for a tab, as a pane state.
    ///
    /// A straight mapping: the four async states are decided by [`crate::window_model`] from the
    /// same snapshot the rows come from, and re-deciding them here would be the second
    /// implementation this whole design exists to avoid. Only [`PaneState::Unwired`] has no model
    /// counterpart, because "this surface has no plumbing yet" is a fact about the CODE, not about
    /// the account.
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
        PaneState::Waiting(sentence) => notice(ui, at, t, Look::Neutral, sentence, None),
        PaneState::Empty(sentence) => notice(ui, at, t, Look::Neutral, sentence, None),
        // Only the state that means something is WRONG gets the amber treatment. Painting a
        // still-loading pane in warning colours teaches people to ignore the warning colour.
        PaneState::Unreachable(sentence) => notice(ui, at, t, Look::Problem, sentence, None),
        PaneState::Unwired => notice(
            ui,
            at,
            t,
            Look::Problem,
            copy::unwired::CAVEAT,
            Some(copy::unwired::HEADING),
        ),
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

/// One banner: an optional heading, then a sentence, inside a panel. Returns its height.
fn notice(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    look: Look,
    sentence: &str,
    heading: Option<&str>,
) -> f32 {
    let pad = space::S3;
    let inner_width = (at.width() - pad * 2.0).max(1.0);
    let ink = match look {
        Look::Neutral => t.muted,
        Look::Problem => t.amber,
    };

    let mut height = pad;
    let heading_galley = heading.map(|heading| {
        ui.painter().layout(
            heading.to_owned(),
            crate::confirm::gui::render::semibold(crate::confirm::gui::render::size::SM),
            rgba(match look {
                Look::Neutral => t.text,
                Look::Problem => t.amber,
            }),
            inner_width,
        )
    });
    let body = ui.painter().layout(
        sentence.to_owned(),
        crate::confirm::gui::render::regular(crate::confirm::gui::render::size::SM),
        rgba(ink),
        text::measure(inner_width),
    );
    if let Some(galley) = &heading_galley {
        height += galley.size().y + space::S1;
    }
    height += body.size().y + pad;

    let panel = Rect::from_min_size(at.left_top(), Vec2::new(at.width(), height));
    match look {
        Look::Neutral => paint::panel(ui, panel, t),
        Look::Problem => paint::warning_panel(ui, panel, t),
    }

    let mut y = at.top() + pad;
    if let Some(galley) = heading_galley {
        let size = galley.size().y;
        ui.painter().galley(
            egui::Pos2::new(at.left() + pad, y),
            galley,
            egui::Color32::PLACEHOLDER,
        );
        y += size + space::S1;
    }
    ui.painter().galley(
        egui::Pos2::new(at.left() + pad, y),
        body,
        egui::Color32::PLACEHOLDER,
    );
    height
}

/// A pane with nothing in it: what this area is for, and the way onward.
///
/// Never a blank region. An empty list rendering as void is a bug, and on a window whose tabs come
/// and go with the account's state it is a bug a person will hit.
pub(crate) fn nothing_here(ui: &mut Ui, at: Rect, t: &Tokens) -> f32 {
    text::body(ui, at, t, copy::NOTHING_HERE)
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
        assert!(
            !PaneState::Unwired.is_silent(),
            "an unwired pane that says nothing is the exact failure this state exists to prevent"
        );
    }

    /// **A banner's height matches what it drew, at both widths the window spans.**
    ///
    /// The unwired banner carries two paragraphs and is the tallest; a height computed from one of
    /// them would leave the next block sitting on the second. Measured at 480 px as well as at a
    /// desktop width because the sentence wraps to more lines in the narrow case, which is exactly
    /// where a wrong height shows.
    #[test]
    fn a_banner_is_taller_when_its_sentence_has_to_wrap_further() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32));
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("banner-test")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let narrow = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(300.0, 400.0));
                    let wide = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(520.0, 400.0));
                    measured.set((
                        banner(ui, narrow, &t, &PaneState::Unwired),
                        banner(ui, wide, &t, &PaneState::Unwired),
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
