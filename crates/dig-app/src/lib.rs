//! `dig-app` shell support library.
//!
//! The `dig-app`/`dign` binaries in this crate stay deliberately thin (per-process entrypoints), so
//! what lives here is the real, unit-testable logic that belongs to the *shell* rather than to the
//! identity-agent core in `dig-app-core`:
//!
//! * [`autostart`] — the per-user platform artifacts that make the shell start itself at login, per
//!   SPEC §4's form-factor table.
//! * [`brand`] — the embedded DIG mark the tray paints, and its decoder (tray builds only).
//! * [`logging`] — the shared dual-sink field log the shell installs for the user's whole session.

pub mod autostart;
/// The embedded DIG brand mark the tray paints as its icon.
///
/// Tray-only: a headless build has no icon to paint, so it carries neither the artwork nor a PNG
/// decoder.
#[cfg(feature = "tray")]
pub mod brand;
pub mod logging;
