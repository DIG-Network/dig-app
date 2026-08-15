//! The appearance setting: which of the two themes the app window paints in.
//!
//! # Why the theme is operated here and stored where it always was
//!
//! The theme used to be a control in the 44 px window chrome, beside Minimize, Maximize and Close
//! (dig_ecosystem#2997). It never belonged there: those three act on the WINDOW, and a theme is a
//! preference that outlives the window — it is stored on disk, it applies to every prompt the app
//! ever draws, and it sits alongside the update channel and the cache size rather than alongside
//! Close. Moving it also gives the chrome back a slot, which is what lets the window controls
//! become square icons without crowding.
//!
//! Only the operating surface moved. [`ThemeChoice`](crate::confirm::gui::theme::ThemeChoice) is
//! still the one authority on where the preference lives, and the shell still owns the write — see
//! [`Exchange`] for why the pane asks rather than writes.

use egui::Context;

use super::super::card;
use super::super::flow::Flow;
use super::super::select::{self, Choice, Select};
use super::super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::{Theme, Tokens};

/// The card's title.
pub(crate) const CARD: &str = "Appearance";

/// What the card is for, said before the control.
pub(crate) const ABOUT: &str =
    "Which theme DIG draws in. The choice is remembered, and it applies \
                                to every DIG window — this one and every approval prompt.";

/// The chooser's label.
pub(crate) const FIELD: &str = "Theme";

/// The light option, in the words a person picks it by.
pub(crate) const LIGHT: &str = "Light";

/// The dark option.
pub(crate) const DARK: &str = "Dark";

/// The theme in force, and a theme somebody just asked for, passed between the pane and the shell.
///
/// # Why a memory exchange and not a returned action
///
/// A pane reports one thing to the shell: a [`TrayAction`](crate::tray_menu::TrayAction), which is
/// a verb the shell hands to a WORKER. The theme is neither — nothing off this thread can paint,
/// and inventing a tray verb for it would put a window preference into the vocabulary the tray menu
/// is built from. This module follows the rule the rest of the Settings pane already follows for
/// its non-verb controls (`prefs`, the notification switch): the pane handles it locally.
///
/// The shell stays the only writer of the preference. The pane records what was CHOSEN; the shell
/// takes that at the top of the next frame, applies it and persists it through its own
/// [`ThemeChoice`](crate::confirm::gui::theme::ThemeChoice). So there is exactly one place a theme
/// is written, which is what stops the pane and the chrome ever disagreeing about what is stored.
pub(crate) struct Exchange;

impl Exchange {
    /// Where the shell publishes the theme it is painting this frame.
    fn in_force() -> egui::Id {
        egui::Id::new("dig-settings-theme-in-force")
    }

    /// Where the pane records a theme a person just picked.
    fn requested() -> egui::Id {
        egui::Id::new("dig-settings-theme-requested")
    }

    /// Say which theme is being painted, so the chooser can show the one in force.
    ///
    /// Published every frame by the shell rather than read from disk by the pane: the file is the
    /// store of record, but re-reading it while painting would put a filesystem call in the frame
    /// loop and would still be the wrong answer for the frame in which it changed.
    pub(crate) fn publish(ctx: &Context, theme: Theme) {
        ctx.memory_mut(|m| m.data.insert_temp(Self::in_force(), theme));
    }

    /// The theme being painted, or `None` before any shell has said.
    ///
    /// `None` draws the chooser's unknown prompt rather than guessing Light — a setting shown as a
    /// value nobody reported is the class of lie this pane's read-back rule exists to prevent.
    pub(crate) fn in_force_now(ctx: &Context) -> Option<Theme> {
        ctx.memory(|m| m.data.get_temp(Self::in_force()))
    }

    /// Record that a person chose `theme`.
    pub(crate) fn request(ctx: &Context, theme: Theme) {
        ctx.memory_mut(|m| m.data.insert_temp(Self::requested(), theme));
    }

    /// Take the chosen theme, leaving nothing behind.
    ///
    /// Taking rather than reading is what makes this a one-shot: a request that stayed in memory
    /// would be re-applied on every subsequent frame, which would pin the theme and make the
    /// chrome's own history irrelevant.
    pub(crate) fn take_request(ctx: &Context) -> Option<Theme> {
        ctx.memory_mut(|m| m.data.remove_temp::<Theme>(Self::requested()))
    }
}

/// Draw the appearance card, recording a chosen theme for the shell to apply.
pub(crate) fn card(flow: &mut Flow, t: &Tokens) {
    let live = flow.live();
    let options = [
        Choice {
            label: LIGHT.to_string(),
            id: Theme::Light,
        },
        Choice {
            label: DARK.to_string(),
            id: Theme::Dark,
        },
    ];

    let chosen = flow.place(|ui, at| {
        let selected = Exchange::in_force_now(ui.ctx()).map(index_of);
        let mut chosen = None;
        let height = card::interactive_card(ui, at, t, live, Some(CARD), |inner| {
            inner.place(|ui, at| (text::caption(ui, at, t, ABOUT), ()));
            inner.gap(space::S4);
            chosen = inner.place(|ui, at| {
                select::select(
                    ui,
                    at,
                    t,
                    live,
                    &Select {
                        label: FIELD,
                        options: &options,
                        selected,
                        unknown: LIGHT,
                        id: egui::Id::new("dig-settings-theme"),
                    },
                )
            });
        })
        .0;
        (height, chosen)
    });

    if let Some(theme) = chosen {
        flow.place(|ui, _| {
            Exchange::request(ui.ctx(), theme);
            (0.0, ())
        });
    }
}

/// Where `theme` sits in the option list this card draws.
///
/// Written against the same order the list is built in, and asserted by
/// `every_theme_selects_its_own_option` — an index computed one way and a list built another is the
/// classic way a chooser comes to show the wrong value in force.
fn index_of(theme: Theme) -> usize {
    match theme {
        Theme::Light => 0,
        Theme::Dark => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both options are offered, in the order [`index_of`] indexes.
    #[test]
    fn every_theme_selects_its_own_option() {
        let labels = [LIGHT, DARK];
        for theme in [Theme::Light, Theme::Dark] {
            let shown = labels[index_of(theme)];
            let expected = match theme {
                Theme::Light => LIGHT,
                Theme::Dark => DARK,
            };
            assert_eq!(shown, expected, "{theme:?} showed the wrong option");
        }
    }

    /// Nothing published means nothing claimed.
    #[test]
    fn shows_no_theme_in_force_before_a_shell_says() {
        let ctx = Context::default();
        assert_eq!(Exchange::in_force_now(&ctx), None);
    }

    /// What the shell publishes is what the chooser reads back.
    #[test]
    fn reads_back_the_theme_the_shell_published() {
        let ctx = Context::default();
        Exchange::publish(&ctx, Theme::Dark);
        assert_eq!(Exchange::in_force_now(&ctx), Some(Theme::Dark));
    }

    /// A request is delivered exactly once, so it cannot pin the theme.
    #[test]
    fn a_request_is_taken_once_and_then_gone() {
        let ctx = Context::default();
        Exchange::request(&ctx, Theme::Dark);
        assert_eq!(Exchange::take_request(&ctx), Some(Theme::Dark));
        assert_eq!(Exchange::take_request(&ctx), None);
    }
}
