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
//! # The ONE place that rule is knowingly bent, and why
//!
//! [`ChainSource::coin_records_by_puzzle_hash`](dig_chainsource_interface::ChainSource::coin_records_by_puzzle_hash)
//! is specified over ALL coins paying to a puzzle hash, but `control.wallet.coins` is scoped to one
//! asset, so this implementation asks for XCH and only XCH. A puzzle hash holding only $DIG CAT
//! coins therefore answers `vec![]` — an absence that is not the whole truth. It is tolerated
//! because the only caller on the mint path selects XCH funding coins, and it is written down here
//! (and in `SPEC.md` §3.1b) rather than left to be rediscovered by whoever first asks this source
//! about a CAT. The related mainnet-only `"xch"` address HRP is documented at the method.
//!
//! # Not wired up yet, on purpose
//!
//! [`readiness`] measures — off the painting thread — whether the connected node can service the
//! reads a whole-profile mint needs. Nothing consumes that measurement at this revision:
//! [`NodeChainReadiness`] has no caller outside its own module, and the shell still hardcodes the
//! seam it hands the wizard. The poller already owns its cadence; what it lacks is a caller, and
//! only once that caller and a creation control land together will a reading decide where the
//! shell offers profile creation (dig_ecosystem#2398).
//!
//! Saying that plainly is the rule [`readiness`] itself argues, turned on this file: an unmeasured
//! node is not a measured absence, and a seam nobody reads is not a seam in use.
//!
//! The DID-only wizard's seams ([`crate::account::chain_mint`]) are deliberately unchanged: a
//! DID-only seam says nothing about whether a PROFILE can be completed.

pub mod error;
pub mod publish;
pub mod readiness;
pub mod source;

#[cfg(test)]
mod tests;

pub use error::ChainReadError;
pub use publish::{
    ControlSpendPublisher, DetailedSpendPublisher, PublishFailure, PUSH_TIMEOUT,
};
pub use readiness::NodeChainReadiness;
pub use source::{ControlChainSource, Freshness, CHILD_PAGE_SIZE, MAX_CHILD_PAGES, READ_TIMEOUT};
