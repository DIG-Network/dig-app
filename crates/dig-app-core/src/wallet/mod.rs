//! The per-profile wallet host (U8, epic #908 — SECURITY-CRITICAL: it builds and signs spends).
//!
//! The wallet is user-identity state, so it lives in dig-app (migrated out of the engine's
//! `dig-wallet`). This module is the *focused host*, not a port of the engine's `sage/*` tree:
//!
//! - **State** ([`state`]) — the per-profile addresses / coins view / balance, DIGOP1-sealed at rest
//!   per profile through the U4/U5 [`ProfileSealer`](crate::profiles::ProfileSealer) seam (NC-2).
//! - **Keys + signing** ([`signing`]) — the in-memory wallet key builds spends and **signs them
//!   locally**; the private key never leaves the process and never crosses the IPC boundary to the
//!   engine (the same custody boundary as the session `sign` callback, §2.3).
//! - **Spend building** ([`spend`]) — spend bundles are constructed **only** via the canonical chip35
//!   spend builders (never hand-rolled); $DIG payments target the canonical DIG treasury.
//! - **Engine seam** ([`engine`]) — a contract-first `control.wallet.*` method set (broadcast a signed
//!   bundle, read coins / balance) the engine (NODE-1, #910) implements; behind a trait seam so
//!   dig-app compiles and tests standalone until the real transport drops in.
//!
//! # The custody boundary in one place
//!
//! Money moves through exactly one flow: build the (unsigned) spend via [`spend`] → sign it locally
//! with [`signing::WalletKey::sign_bundle`] → [`encode_signed_bundle`] to hex → hand the SIGNED
//! bytes to the engine via [`engine::WalletEngine::broadcast`]. The private key is used only inside
//! the wallet; the engine only ever sees signed bytes.

pub mod engine;
pub mod signing;
pub mod spend;
pub mod state;

use chia_protocol::SpendBundle;
use chia_traits::Streamable;

use crate::profiles::SealError;

/// A failure in the wallet host. Wrapped into [`crate::Error::Wallet`].
///
/// The variants name the wallet's distinct failure surfaces — key/address derivation, spend
/// construction, local signing, at-rest sealing, and the engine seam — so a caller can react
/// precisely (and so a custody review can see exactly where each failure originates).
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Encoding the wallet's address failed (a bech32m encode error).
    #[error("could not encode wallet address: {0}")]
    Address(String),

    /// Building a spend via chip35 failed (bad coin inputs, insufficient funds, or driver error).
    #[error("could not build spend: {0}")]
    Spend(String),

    /// Local signing failed (required-signature extraction from the coin spends).
    #[error("could not sign spend: {0}")]
    Sign(String),

    /// Serializing the signed bundle for broadcast failed.
    #[error("could not encode signed bundle: {0}")]
    Encode(String),

    /// Reading or writing the sealed wallet state / key on disk failed.
    #[error("wallet state error: {0}")]
    State(String),

    /// Sealing or opening a per-profile wallet blob failed (locked profile, or a foreign DEK —
    /// fail-closed).
    #[error(transparent)]
    Seal(#[from] SealError),

    /// An I/O error persisting a sealed wallet blob.
    #[error("wallet I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The engine seam reported a failure (broadcast rejected, chain read failed, transport down).
    #[error("wallet engine error: {0}")]
    Engine(String),
}

/// Serialize a fully-signed [`SpendBundle`] to the lowercase-hex wire form the engine broadcast seam
/// ([`engine::BroadcastRequest`]) carries — the chia `Streamable` bytes, hex-encoded.
pub fn encode_signed_bundle(bundle: &SpendBundle) -> Result<String, WalletError> {
    let bytes = bundle
        .to_bytes()
        .map_err(|e| WalletError::Encode(e.to_string()))?;
    Ok(hex::encode(bytes))
}
