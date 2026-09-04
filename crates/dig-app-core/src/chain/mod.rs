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
//! An absence is only an answer when the tier that gave it was CAUGHT UP. A present coin may be
//! believed from any tier — a replica that is behind can only be behind, never ahead — while an
//! empty answer from `synced: false` is the one reply a stale replica produces indistinguishably
//! from the chain itself.
//!
//! That rule is enforced on `coin_records_by_puzzle_hash` and, today, ONLY there. `coin_record` and
//! `coin_records_by_parent` are not scoped to the wallet, so dig-node routes them to the fallback
//! tier whatever its sync state and they can never report `synced: true` — a guard on them would not
//! be strict, it would be permanently on, and permanently on shuts profile creation on every healthy
//! machine. `ControlChainSource::believe_absence` carries the measurements, the producer-side cause,
//! and the one lie that stays open because of it.
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
//! # Measured, and what the measurement is allowed to decide
//!
//! [`readiness`] measures — off the painting thread — whether the connected node can service the
//! reads a whole-profile mint needs. The shell now takes that reading every repaint and carries it
//! on `TrayView::mint_chain` (dig_ecosystem#2398).
//!
//! Exactly ONE surface consumes it: the tray's DID explainer, which without it named a cause nobody
//! had measured — telling a machine whose node serves both reads that *on-chain minting is not
//! available in this version*. The explainer gates nothing and offers no control, which is what
//! makes it safe to speak from a reading.
//!
//! A reading still does NOT decide availability. That is read off
//! [`ProfileMintSeams`](crate::account::profile_mint::ProfileMintSeams), which needs a mint door the
//! poller cannot hold, and the shell is held to it mechanically by
//! `the_binary_cannot_open_the_profile_creation_gate`. Profile creation becomes offerable when a
//! creation control lands WITH it, not when a reading turns green.
//!
//! Saying that plainly is the rule [`readiness`] itself argues, turned on this file: an unmeasured
//! node is not a measured absence, and a seam nobody reads is not a seam in use.
//!
//! There used to be a second, DID-only seam here too, deliberately left untouched by this reading
//! because a DID-only seam says nothing about whether a PROFILE can be completed. It is retired
//! along with the rest of the DID-only mint path (dig-app#210); `ProfileMintSeams` is now the only
//! seam creation is ever read from.

pub mod error;
pub mod publish;
pub mod readiness;
pub mod source;

#[cfg(test)]
mod tests;

pub use error::ChainReadError;
pub use publish::{ControlSpendPublisher, DetailedSpendPublisher, PublishFailure, PUSH_TIMEOUT};
pub use readiness::NodeChainReadiness;
pub use source::{
    AbsenceWarrant, AbsenceWitness, ControlChainSource, Freshness, CHILD_PAGE_SIZE,
    MAX_CHILD_PAGES, READ_TIMEOUT,
};
