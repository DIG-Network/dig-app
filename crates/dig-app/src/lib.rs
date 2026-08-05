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
//! * [`hotkey`] — claiming the global shortcut that opens the URN bar (tray builds only).
//! * [`logging`] — the shared dual-sink field log the shell installs for the user's whole session.
//! * [`pump_vigil`] — watching the tray's own event loop from outside it, so a loop that stops
//!   running can say so.
//! * [`tray_guard`] — surviving a desktop stack that panics instead of failing (tray builds only).
//! * `tray_popup` — keeping the tray's context menu dismissable, and clearing it when it is not
//!   (tray builds only).

pub mod argv;
pub mod autostart;
/// The embedded DIG brand mark the tray paints as its icon.
///
/// Tray-only: a headless build has no icon to paint, so it carries neither the artwork nor a PNG
/// decoder.
#[cfg(feature = "tray")]
pub mod brand;
pub mod console;
/// Claiming the global shortcut that opens the URN bar.
///
/// Tray-only: a headless build has no desktop to open a bar on, and nothing to press a chord from.
#[cfg(feature = "tray")]
pub mod hotkey;
pub mod logging;
// No outer doc comment here, for the reason spelled out above `tray_popup` below: outer docs on a
// `pub mod` are MERGED with the module's own `//!` docs and the merged block resolves its
// intra-doc links in the crate-root scope, so a link to one of the module's own items fails with
// an error carrying no file and no line. `pump_vigil` documents itself.
pub mod pump_vigil;
/// Surviving a desktop stack that panics instead of failing.
///
/// Tray-only, for the same reason as [`brand`]: a headless build mounts no tray.
#[cfg(feature = "tray")]
pub mod tray_guard;
// NOTE: no outer doc comment here, for the same reason as `tray_popup` below — an outer doc on a
// `pub mod` is MERGED with the module's own `//!` docs and the merged block resolves its intra-doc
// links in the CRATE-ROOT scope, so `[`Latest`]` fails to resolve with an error carrying no file and
// no line. That is the trap this file already warns about, and it caught this module too.
// `tray_link` documents itself. Not tray-gated: it is a mailbox and a wake, with no desktop
// dependency, and the property it exists for — a producer that never waits for its consumer — is
// worth checking in every build.
pub mod tray_link;
// NOTE: no outer doc comment here on purpose. A module carrying BOTH outer docs on its `pub mod`
// declaration and inner `//!` docs has the two MERGED, and the merged block then resolves its
// intra-doc links in the CRATE-ROOT scope — so a link to one of the module's own items fails to
// resolve, with a rustdoc error that carries no file and no line. It broke the doc gate twice on
// dig-app#86. `tray_popup` documents itself.
#[cfg(feature = "tray")]
pub mod tray_popup;
/// Running tray menu actions off the event loop, so no handler can freeze the tray.
///
/// Not tray-gated: it is plain threading with no desktop dependency, and its guarantees (nothing runs
/// on the caller's thread, one action at a time, a panic is not a quit) are worth checking in every
/// build (dig_ecosystem#1926).
pub mod tray_worker;
