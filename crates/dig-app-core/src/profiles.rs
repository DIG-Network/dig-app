//! Profiles — multi-DID identity, one active at a time (U5).
//!
//! *This module is a U1 skeleton; U5 (SECURITY-CRITICAL) implements it to `SPEC.md` under the dual
//! review + loop-security gate, consuming `dig-identity` (dig_ecosystem#771) release-first.*
//!
//! A **profile** is `{ DID (did:chia singleton), keys (signing 0x0010 + encryption 0x0011), paired
//! chip35 DataLayer store, local data (config / subscriptions / wallet / prefs) }`. The on-chain
//! identity is the `dig-identity` #771 DID paired with a chip35 store via the store `description`
//! field; profile fields are standard SMT slots. dig-app creates (mint DID + paired store via
//! chip35 delegation), selects, edits (write SMT slots), and reads profiles — never a reinvented
//! format. Each profile's local data is DIGOP1-sealed under its own per-profile DEK
//! ([`crate::keystore`]) in its own [`crate::storage::profile_dir`] (NC-2 / NC-3).

/// A local reference to a profile — the DID plus a cache of its on-chain SMT metadata. U5 defines
/// the full shape; U1 fixes the identifier so the storage + IPC layers can key on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRef {
    /// The profile's `did:chia:` decentralized identifier (the on-chain singleton launcher id).
    pub did: String,
}
