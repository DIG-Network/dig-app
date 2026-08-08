//! Open ONE content pane in a real window, at a chosen tab, size and theme — for photography.
//!
//! # Why this exists
//!
//! Every pane has to be photographed at the default size and at `SHELL_MIN`, in both themes
//! (dig_ecosystem#2326). The app window opens on `Status` and the only route to another tab is a
//! CLICK, so photographing the Apps or Settings tab meant driving synthetic input — which is
//! forbidden for a committed capture, and for a good reason: a synthetic click steals foreground and
//! the capture ends up being of whatever was behind the window.
//!
//! So this opens the pane directly. It is the same [`super::panes::draw`] the shell calls, with the
//! same model, the same facts and the same tokens — the only thing it leaves out is the shell's
//! chrome and its prompt hosting, neither of which belongs to a pane. A picture taken here is a
//! picture of the pane the application draws.
//!
//! # What it is NOT
//!
//! Not a second window for users, and not on any path a user reaches: nothing in `dig-app` calls it.
//! It exists for `examples/pane_preview.rs` and it only ever DRAWS — clicks are read and discarded,
//! because a verb dispatched from a gallery would run against the real machine.

use egui::{Rect, Vec2};

use super::super::theme::{Theme, ThemeChoice};
use crate::tray_menu::TrayView;
use crate::window_model::{self, TabId};

/// Open `tab` at `size` logical pixels in `theme`, and block until the window is closed.
///
/// `view` is the snapshot the model and the facts are BOTH built from — one value, so the pane
/// cannot be photographed describing two different instants.
///
/// Returns an error string when this host cannot open a window at all.
pub fn open_pane_preview(
    theme: Theme,
    tab: TabId,
    size: (f32, f32),
    view: TrayView,
) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(size.0, size.1))
            .with_title("DIG"),
        // Without this eframe RESTORES the last run's window size and silently ignores the one
        // asked for — so a 480 px capture came out at whatever the previous run was, and the two
        // pictures were identical while claiming different widths.
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "dig-pane-preview",
        options,
        Box::new(move |cc| {
            super::super::window::install_fonts(&cc.egui_ctx);
            Ok(Box::new(Preview { theme, tab, view }))
        }),
    )
    .map_err(|e| format!("this host cannot open a preview window: {e}"))
}

/// The pane, drawn frame after frame from one snapshot.
struct Preview {
    theme: Theme,
    tab: TabId,
    view: TrayView,
}

impl eframe::App for Preview {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let t = self.theme.tokens();
        let model = window_model::build(&self.view);
        // The same snapshot projected twice, exactly as the shell does it.
        let facts = super::pane::facts::PaneFacts::of_tray(&self.view);
        let screen = ctx.screen_rect();
        egui::Area::new(egui::Id::new("dig-pane-preview"))
            .fixed_pos(screen.left_top())
            .order(egui::Order::Background)
            .show(ctx, |ui| {
                ui.set_clip_rect(screen);
                ui.painter()
                    .rect_filled(screen, 0, super::super::render::rgba(t.bg));
                // The selected tab is a parameter here rather than state, which is the whole point:
                // no click is needed to photograph a tab that is not the first one.
                let _ = super::panes::draw(
                    ui,
                    Rect::from_min_max(screen.left_top(), screen.right_bottom()),
                    &t,
                    &model,
                    &facts,
                    self.tab,
                    true,
                );
            });
    }
}

/// The theme the preview should open in, without disturbing the host's stored preference.
///
/// The shell gallery writes the real preference file because the prompts it raises read it; a pane
/// preview raises nothing, so it has no reason to touch a person's setting.
pub fn preview_theme(name: &str) -> Option<Theme> {
    match name {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    }
}

/// The host's stored theme, for a caller that wants to preview whatever the app would show.
pub fn stored_theme() -> Theme {
    ThemeChoice::for_host().read()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A theme name that is not one of the two is refused rather than guessed.**
    ///
    /// A gallery that silently fell back to light would photograph the wrong theme and label the
    /// picture with the one that was asked for — a committed screenshot is a claim.
    #[test]
    fn only_the_two_real_themes_are_accepted() {
        assert_eq!(preview_theme("light"), Some(Theme::Light));
        assert_eq!(preview_theme("dark"), Some(Theme::Dark));
        assert_eq!(preview_theme("Dark"), None);
        assert_eq!(preview_theme(""), None);
    }
}
