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
pub mod enrol;
pub mod node;
pub mod overview;
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

    /// Nothing answered the engine seam — no node is reachable.
    ///
    /// Distinct from [`Engine`](Self::Engine) because the remedy differs: this one says *start your
    /// node*, and the surface that renders it must not tell the user their read failed.
    #[error("no DIG node answered: {0}")]
    EngineUnreachable(String),

    /// A node accepted the connection and did not finish the read inside its budget.
    ///
    /// Distinct from [`EngineUnreachable`](Self::EngineUnreachable) because the two are different
    /// facts, not two shades of one: the socket CONNECTED, so a node is demonstrably present and the
    /// only thing that failed is this call. Collapsing them is what told a user with a perfectly
    /// healthy node that no node was running (dig_ecosystem#2325).
    #[error("the DIG node did not answer the balance read in time: {0}")]
    EngineTimedOut(String),

    /// A node answered, but this build of it does not serve the requested wallet read.
    ///
    /// The honest end of a capability probe: the app asked, and the running node said it cannot.
    /// The remedy is an upgrade, not a retry.
    #[error("this DIG node does not serve wallet reads")]
    EngineUnsupported,

    /// A node answered, but its chain view is still catching up, so any figure it gave would be
    /// stale. Reported rather than rendered — a stale number still reads as the truth.
    #[error("the DIG node is still syncing")]
    EngineNotSynced,

    /// A node answered and refused on AUTHORIZATION grounds, on a method that is token-gated.
    ///
    /// Deliberately not [`EngineUnsupported`](Self::EngineUnsupported). On the two OPEN wallet
    /// reads an authorization refusal can only come from a build that predates them, so it means
    /// "upgrade". On a GATED method — the push — it means this app could not read the node's
    /// control token, and telling that person to upgrade a node that already serves the method
    /// sends them after the wrong remedy entirely.
    #[error("this app is not authorized to ask the DIG node to do that")]
    EngineUnauthorized,

    /// A node answered and DOES serve the read, but has no live chain source to answer it FROM.
    ///
    /// Separate from [`EngineUnsupported`](Self::EngineUnsupported) (that build is not capable) and
    /// from [`EngineNotSynced`](Self::EngineNotSynced) (there is no chain view to be behind). This
    /// is the state a default dig-node install is actually in today.
    #[error("the DIG node has no live chain source")]
    EngineNoChainSource,

    /// The node's own replica answered and has synced NOTHING — it reported no peak height at all.
    ///
    /// Its `balance: 0` is therefore *no data*, not *no money*, and the two must never be collapsed:
    /// a zero shown here is a false statement about the user's funds. Reported as an error precisely
    /// so the surface renders the balance ABSENT rather than as a figure.
    ///
    /// Distinct from [`EngineNoChainSource`](Self::EngineNoChainSource) (there is no source at all)
    /// and from [`EngineNotSynced`](Self::EngineNotSynced) (the node itself refused the read).
    #[error("the DIG node's chain replica has not synced anything yet")]
    EngineNoReplicaData,
}

/// Serialize a fully-signed [`SpendBundle`] to the lowercase-hex wire form the engine broadcast seam
/// ([`engine::BroadcastRequest`]) carries — the chia `Streamable` bytes, hex-encoded.
pub fn encode_signed_bundle(bundle: &SpendBundle) -> Result<String, WalletError> {
    let bytes = bundle
        .to_bytes()
        .map_err(|e| WalletError::Encode(e.to_string()))?;
    Ok(hex::encode(bytes))
}
