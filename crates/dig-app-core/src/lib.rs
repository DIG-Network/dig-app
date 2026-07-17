//! # dig-app-core — the DIG user-app identity-agent core
//!
//! This crate is the **identity half** of the DIG engine/identity split (epic
//! [dig_ecosystem#908]). The DIG Node service is the *identity-agnostic engine* (P2P, content
//! serve, chain watch; it holds only a machine transport `peer_id`). **dig-app is the user's
//! interaction with that engine — and it IS the user identity.** This library holds everything
//! identity-specific and runs *as the interactive user*:
//!
//! - [`keystore`] — hold / unlock / **sign with** the DIG identity + wallet keys (dig-keystore
//!   DIGOP1 at-rest sealing; the user key never enters the engine).
//! - [`profiles`] — multi-DID profiles via `dig-identity`; create / select / edit the active one.
//! - [`wallet`] — the per-profile wallet host (spend building + signing stays local).
//! - [`storage`] — per-user AppData layout, DIGOP1-sealed at rest (NC-2 / NC-3).
//! - [`ipc`] — the identity-authenticated session channel to the engine (named pipe / Unix socket).
//! - [`gateway`] — the CLI/RPC front door: authenticate callers, proxy engine work.
//! - [`identity`] — the two-identity model (transport peer-identity vs the user identity).
//! - [`form_factor`] — headless agent core vs optional GUI tray shell.
//!
//! The normative contract for all of the above is the repo `SPEC.md`. U1 (this work unit) ships the
//! module skeleton + the small set of pure helpers the architecture needs from day one; the
//! security-critical subsystems are stubbed for U4–U7 to implement to the SPEC.
//!
//! [dig_ecosystem#908]: https://github.com/DIG-Network/dig_ecosystem/issues/908

pub mod form_factor;
pub mod gateway;
pub mod identity;
pub mod ipc;
pub mod keystore;
pub mod profiles;
pub mod storage;
pub mod wallet;

/// The operating system the user app is running on. Used by [`storage`] and [`ipc`] to resolve the
/// per-OS AppData layout and the native IPC endpoint without touching the real environment (so the
/// resolution logic is pure + unit-testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Windows — `%LOCALAPPDATA%\DigNetwork`, named-pipe IPC.
    Windows,
    /// macOS — `~/Library/Application Support/DigNetwork`, Unix-domain-socket IPC.
    MacOs,
    /// Linux — `$XDG_DATA_HOME/dignetwork`, Unix-domain-socket IPC.
    Linux,
}

/// Errors surfaced by the identity-agent core. Variants are added by the U4–U7 subsystems; U1
/// defines the type so the public API shape is stable from the first release.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A per-user path could not be resolved because a required environment variable was absent.
    #[error("could not resolve {what}: environment variable {var} is not set")]
    MissingEnv {
        /// What was being resolved (e.g. "the AppData directory").
        what: &'static str,
        /// The environment variable that was expected but missing.
        var: &'static str,
    },
}

/// The crate result type.
pub type Result<T> = core::result::Result<T, Error>;
