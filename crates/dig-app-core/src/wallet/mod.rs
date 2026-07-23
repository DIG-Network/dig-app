//! The per-profile wallet host (epic #908 — SECURITY-CRITICAL: it holds sealed wallet state and the
//! engine broadcast seam).
//!
//! The wallet is user-identity state, so it lives in dig-app (migrated out of the engine's
//! `dig-wallet`). Money SIGNING lives in the master-HD custody path — the
//! [`MoneyPath`](crate::account::money::MoneyPath) over the
//! [`AccountResidency`](crate::account::residency::AccountResidency), which builds a `dig-account`
//! money signer over the master seed; the wallet host owns only the surrounding, non-key pieces:
//!
//! - **State** ([`state`]) — the per-profile addresses / coins view / balance, DIGOP1-sealed at rest
//!   per profile through the [`ProfileSealer`](crate::sealer::ProfileSealer) seam (NC-2).
//! - **Engine seam** ([`engine`]) — a contract-first `control.wallet.*` method set (broadcast a signed
//!   bundle, read coins / balance) the engine (NODE-1, #910) implements; behind a trait seam so
//!   dig-app compiles and tests standalone until the real transport drops in.
//!
//! # The custody boundary in one place
//!
//! Money moves through exactly one flow: build the (unsigned) coin spends via the canonical chip35
//! builders → sign them through [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign)
//! (authorize-before-sign over the master-HD account) → [`encode_signed_bundle`] to hex → hand the
//! SIGNED bytes to the engine via [`engine::WalletEngine::broadcast`]. The private key stays inside the
//! `dig-account` signer; the engine only ever sees signed bytes.

pub mod engine;
pub mod state;

use chia_protocol::SpendBundle;
use chia_traits::Streamable;

use crate::sealer::SealError;

/// A failure in the wallet host. Wrapped into [`crate::Error::Wallet`].
///
/// The variants name the wallet's distinct failure surfaces — address derivation, at-rest sealing,
/// bundle encoding, and the engine seam — so a caller can react precisely (and so a custody review can
/// see exactly where each failure originates).
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Encoding the wallet's address failed (a bech32m encode error).
    #[error("could not encode wallet address: {0}")]
    Address(String),

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
