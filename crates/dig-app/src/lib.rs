//! `dig-app` shell support library.
//!
//! The `dig-app`/`dign` binaries in this crate stay deliberately thin (per-process entrypoints), so
//! what lives here is the real, unit-testable logic that belongs to the *shell* rather than to the
//! identity-agent core in `dig-app-core`:
//!
//! * [`argv`] — the `--version`/`--help` command line, including the exact output shape the update
//!   beacon's health probe parses.
//! * [`autostart`] — the per-user platform artifacts that make the shell start itself at login, per
//!   SPEC §4's form-factor table.
//! * [`brand`] — the embedded DIG mark the tray paints, its state badges, and its decoder (tray builds
//!   only).
//! * [`console`] — where a GUI-subsystem binary prints, so `dig-app --version` still answers the update
//!   beacon's health probe (dig_ecosystem#1797).
//! * [`logging`] — the shared dual-sink field log the shell installs for the user's whole session.
//! * [`tray_guard`] — surviving a desktop stack that panics instead of failing (tray builds only).

pub mod argv;
pub mod autostart;
/// The embedded DIG brand mark the tray paints as its icon.
///
/// Tray-only: a headless build has no icon to paint, so it carries neither the artwork nor a PNG
/// decoder.
#[cfg(feature = "tray")]
pub mod brand;
pub mod console;
pub mod logging;
/// Surviving a desktop stack that panics instead of failing.
///
/// Tray-only, for the same reason as [`brand`]: a headless build mounts no tray.
#[cfg(feature = "tray")]
pub mod tray_guard;
