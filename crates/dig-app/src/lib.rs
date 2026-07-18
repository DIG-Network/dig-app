//! `dig-app` shell support library.
//!
//! The `dig-app`/`dign` binaries in this crate stay deliberately thin (per-process entrypoints); the
//! one piece of real, unit-testable logic that belongs to the *shell* (not the identity-agent core in
//! `dig-app-core`) is **per-user autostart wiring** — the platform artifacts that make the shell start
//! itself at login, per SPEC §4's form-factor table. See [`autostart`].

pub mod autostart;
pub mod logging;
