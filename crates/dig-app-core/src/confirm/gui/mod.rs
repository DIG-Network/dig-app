//! The branded DIG prompt GUI (dig_ecosystem#2038) — one window implementation for every platform.
//!
//! # What this replaces, and what it deliberately does not
//!
//! Before this module, each platform drew consent its own way: a hand-built Win32 GDI dialog, a macOS
//! `NSAlert`, and on Linux a `zenity`/`kdialog` SUBPROCESS. Three implementations of one window, in
//! three visual languages, none of them branded — and on Linux, a dialog that simply did not appear
//! if neither helper happened to be installed.
//!
//! This module is a `ForegroundWindow` + `ForegroundInput` pair drawn with `egui`, so all three
//! platforms get the same window, in hub.dig.net's visual language, from the same code.
//!
//! **It changes only how the window is DRAWN.** The security policy — `gated_consent`, the
//! never-blind-sign short circuit, the fail-closed defaults on every unimplemented prompt — is
//! untouched, still lives in the parent module, and is still what decides every outcome. This module
//! answers exactly one question: what did the human click.
//!
//! # Why a Rust renderer rather than a webview (the #2038 decision)
//!
//! Every dynamic value these windows display is attacker-influenced — store names, peer ids, amounts,
//! the requesting app's identity, the decoded transaction. The old Linux backend forced its text to be
//! PLAIN for exactly that reason (`zenity --no-markup`, `escape_kdialog_plain`), because a hostile
//! field that is INTERPRETED rather than displayed lets an attacker forge convincing UI inside a real
//! consent dialog, and the user then approves something other than what they read.
//!
//! A webview does not remove that hazard; it enlarges it from Pango markup to HTML, in the window that
//! authorises spending real mainnet funds, and defends it with an escape call at every render site
//! forever. A measured comparison (#2038) confirmed the failure mode is a *complete forged consent
//! panel*, not a cosmetic glitch, and that a script-oriented CSP does not stop it — the forgery is
//! markup plus inline styles, both of which a `style-src 'unsafe-inline'` policy permits.
//!
//! Here the class cannot occur. [`egui::Painter::text`] rasterises glyphs; there is no markup
//! interpreter in the process to opt out of, so `<b>` is drawn as `<`, `b`, `>`. There is no escape
//! function, and therefore no escape function to forget. `render::tests` pins that property.
//!
//! # Fail closed, everywhere
//!
//! Drawing needs a windowing system and a GL context. On a headless host — dig-app's supported
//! server shape — [`available`] answers `false`, the per-OS confirmer falls back to
//! [`HeadlessConfirmer`](super::HeadlessConfirmer), and every prompt returns
//! [`ConfirmDecision::Unavailable`](super::ConfirmDecision::Unavailable). If the window fails to open
//! or the loop dies mid-prompt, `BrandedWindow::show` returns `WindowIntent::Unavailable`. No path
//! anywhere in this module produces an approval that the user did not click.

mod paint;
mod render;
pub mod theme;
mod window;

pub use theme::{Theme, ThemeChoice, Tokens};
pub use window::{open_app_window, AppWindow, BrandedInput, BrandedWindow};

/// Whether this host can draw a prompt window at all.
///
/// Answers the question the per-OS `confirmer()` constructors ask before building a backed confirmer:
/// a `false` here means the caller MUST fall back to the fail-closed
/// [`HeadlessConfirmer`](super::HeadlessConfirmer) rather than construct a window that cannot open.
///
/// The check is deliberately the cheap, static one — is there a display server — and not "try to
/// open a window and see". Opening a real window costs a GL context and steals focus, which is not
/// something a startup probe may do on a machine where the user is working.
pub fn available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Wayland or X11. Matches the check the zenity backend used, so a host that could raise a
        // dialog before can still raise one now.
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows and macOS always have a window server available to an interactive session, and a
        // service-session build never reaches here (the per-OS confirmer gates on its own session
        // check first).
        true
    }
}

#[cfg(test)]
mod tests {
    /// `available()` must be callable on every target the crate builds for, and must not panic on a
    /// CI host with no display — the answer there is `false`, not a crash.
    #[test]
    fn availability_is_answerable_without_a_display() {
        let _ = super::available();
    }
}
