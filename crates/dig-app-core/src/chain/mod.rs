//! The chain seams dig-account's minter is generic over, served by the local dig-node.
//!
//! dig-account keeps READING and PUSHING apart as two traits, deliberately: the canonical read
//! trait is structurally incapable of broadcasting, so a host can hand a minter a reader with no way
//! to spend. This module supplies one concrete implementation of each, both over the same loopback
//! control plane:
//!
//! - [`ControlChainSource`] — [`ChainSource`](dig_chainsource_interface::ChainSource) over five OPEN
//!   `control.wallet.*` reads, needing no control token.
//! - [`ControlSpendPublisher`] — [`SpendPublisher`](dig_account::mint::SpendPublisher) over
//!   `control.wallet.broadcast`, the one wallet method that does need one.
//!
//! # The custody boundary (§908)
//!
//! Reads are reads; the push takes an ALREADY-SIGNED bundle. No key, seed, phrase or unsigned spend
//! crosses into the node from anywhere in this module, and the wire types it uses have nowhere to
//! put one.
//!
//! # The one rule every file here is built around
//!
//! An absence is an ANSWER and a failure is NOT. `Ok(None)`, `vec![]` and a short child page are
//! reachable only from a node that consulted a chain and reported what it found; every other
//! outcome is a [`ChainReadError`]. The reason is money: on
//! [`coin_spend`](dig_chainsource_interface::ChainSource::coin_spend), `Ok(None)` means *unspent or
//! unknown*, which a caller reads as safe to spend.
//!
//! # Not wired up yet, on purpose
//!
//! Nothing here is handed to a minter — [`crate::account::chain_mint`]'s seams are unchanged, so
//! this adds capability without changing any existing behaviour. Wiring, and the
//! [`resolve_singleton_lineage`](dig_chainsource_interface::ChainSource::resolve_singleton_lineage)
//! walk it still needs, are later stages of dig_ecosystem#2398.

pub mod error;
pub mod publish;
pub mod source;

#[cfg(test)]
mod tests;

pub use error::ChainReadError;
pub use publish::{ControlSpendPublisher, PublishFailure, PUSH_TIMEOUT};
pub use source::{ControlChainSource, Freshness, READ_TIMEOUT};
