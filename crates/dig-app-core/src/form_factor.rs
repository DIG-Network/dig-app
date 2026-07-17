//! Form-factor detection — the headless agent core vs the optional GUI tray shell.
//!
//! The user app is designed as a **headless per-user agent core** (identity/keys/profiles/IPC/
//! gateway) with an **optional** desktop tray shell layered on top (Windows system tray · macOS
//! menu-bar `LSUIElement` · Linux AppIndicator). On a GUI-less host — a Linux server, headless
//! Windows/macOS Server — the app runs as the agent + the `dign` CLI, with no tray. This module is
//! the single decision point for that degrade.

/// Whether the app presents a desktop tray shell or runs headless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFactor {
    /// A desktop session is present — mount the branded tray / menu-bar shell over the agent core.
    Tray,
    /// No desktop session — run the agent core + `dign` CLI only, no tray.
    Headless,
}

impl FormFactor {
    /// Resolve the form factor from whether a usable desktop display is available.
    ///
    /// The caller supplies the display presence (e.g. on Linux: `$DISPLAY`/`$WAYLAND_DISPLAY` set;
    /// on Windows/macOS: an interactive session) so this decision stays pure + testable. A tray is
    /// only mounted when a display is present; every GUI-less host degrades to [`FormFactor::Headless`].
    pub fn detect(has_display: bool) -> Self {
        if has_display {
            FormFactor::Tray
        } else {
            FormFactor::Headless
        }
    }

    /// Whether this form factor mounts the GUI tray shell.
    pub fn has_tray(self) -> bool {
        matches!(self, FormFactor::Tray)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_present_yields_tray() {
        assert_eq!(FormFactor::detect(true), FormFactor::Tray);
        assert!(FormFactor::detect(true).has_tray());
    }

    #[test]
    fn no_display_degrades_headless() {
        assert_eq!(FormFactor::detect(false), FormFactor::Headless);
        assert!(!FormFactor::detect(false).has_tray());
    }
}
