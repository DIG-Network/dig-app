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
//! - [`ipc`] — the per-user IPC endpoint address (named pipe / Unix socket) the session dials.
//! - [`session`] — the identity-authenticated engine session over that channel: the begin→attach
//!   handshake, the engine→app `sign` callback, detach, and re-attach.
//! - [`pairing`] — the extension↔dig-app pairing store + per-frame pairing-token authentication
//!   (HMAC + monotonic nonce) for the APP-SIGN loopback channel (SPEC §5.6.3).
//! - [`confirm`] — the [`confirm::NativeConfirmer`] seam: the OS-native confirm + biometric that is
//!   the sole authorization to pair, connect, or sign (SPEC §5.6.1).
//! - [`loopback`] — the browser-reachable `ws://[127.0.0.1|::1]:9779` identity server the paired
//!   extension relays to (SPEC §5.6).
//! - [`gateway`] — the CLI/RPC front door: authenticate callers, proxy engine work.
//! - [`identity`] — the two-identity model (transport peer-identity vs the user identity).
//! - [`form_factor`] — headless agent core vs optional GUI tray shell.
//!
//! The agent lifecycle that binds these together (U3) lives in:
//!
//! - [`agent`] — the per-user agent: start/stop, the reconcile run loop, and the live status.
//! - [`environment`] — the resolved per-user host facts every boot decision derives from.
//! - [`config`] — the agent's non-secret on-disk runtime settings (AppData, plaintext pre-U4).
//! - [`engine`] — the connection state + reachability probe to the identity-agnostic engine.
//! - [`shutdown`] — the cooperative shutdown latch that stops the run loop promptly.
//!
//! The normative contract for all of the above is the repo `SPEC.md`. U1 shipped the module skeleton
//! plus the pure helpers; U3 added the agent lifecycle and tray shell; U4 implemented [`keystore`]
//! (identity key generation / unlock / sign, DIGOP1 at-rest sealing, OS-credential-store primary +
//! sealed-file fallback, rotation); U5 implemented [`profiles`] (multi-DID create/select/list/edit
//! with per-profile sealed AppData), consuming U4's DEK sealing through the
//! [`profiles::ProfileSealer`] seam. U6 implemented [`session`] (the identity-authenticated engine
//! session: begin→attach handshake, the `sign` callback, detach, re-attach, multi-session). U7
//! implemented [`gateway`] (the CLI/RPC front door: route each command LOCAL vs engine-PROXY, over
//! the [`gateway::EngineProxy`] / [`gateway::LocalIdentity`] / [`gateway::LinkOpener`] seams).
//!
//! [dig_ecosystem#908]: https://github.com/DIG-Network/dig_ecosystem/issues/908

pub mod agent;
pub mod config;
pub mod confirm;
pub mod decode;
pub mod engine;
pub mod environment;
pub mod events;
pub mod form_factor;
pub mod gateway;
pub mod identity;
pub mod ipc;
pub mod keystore;
pub mod loopback;
pub mod notify;
pub mod onboarding;
pub mod pairing;
pub mod profiles;
pub mod session;
pub mod session_lock;
pub mod shutdown;
pub mod sign_policy;
pub mod sign_service;
pub mod spend_summary;
pub mod storage;
pub mod wallet;
pub mod whitelist;

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

/// Errors surfaced by the identity-agent core. Further variants are added by the U4–U7 subsystems;
/// the type is defined here so the public API shape is stable from the first release.
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

    /// An I/O error while reading or writing the agent's on-disk state (e.g. the config file).
    #[error("agent I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The agent's config file could not be (de)serialized — a malformed config file.
    #[error("agent config is malformed: {0}")]
    Config(#[from] serde_json::Error),

    /// A key-management failure (unlock, sealing, rotation, or the OS credential store). See
    /// [`keystore::KeystoreError`] for the specific cause. Deliberately opaque about *why* an
    /// unlock failed so a wrong-passphrase attempt never leaks whether the ciphertext or the
    /// password was at fault.
    #[error("key management error: {0}")]
    Keystore(#[from] keystore::KeystoreError),

    /// A profile-management failure (create / select / edit / seal — see [`profiles::ProfileError`]).
    #[error(transparent)]
    Profiles(#[from] profiles::ProfileError),

    /// A wallet-host failure (key/address derivation, spend build, local signing, sealed wallet
    /// state, or the engine seam — see [`wallet::WalletError`]).
    #[error(transparent)]
    Wallet(#[from] wallet::WalletError),

    /// The dig-peer is not yet usable because onboarding is incomplete — a wallet or a profile is
    /// still required (see [`onboarding::OnboardingError`]).
    #[error(transparent)]
    Onboarding(#[from] onboarding::OnboardingError),
}

/// The crate result type.
pub type Result<T> = core::result::Result<T, Error>;
