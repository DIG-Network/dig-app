//! The per-profile wallet host (U4).
//!
//! *This module is a U1 skeleton; U4 implements it to `SPEC.md`.*
//!
//! The wallet is user-identity state, so it lives in dig-app (migrated out of the engine's
//! `dig-wallet`). Spend bundles are built via the canonical wasm spend builders / chip35 delegation
//! and **signed locally** with the in-memory unlocked key ([`crate::keystore`]); the finished
//! signed bundle is handed to the engine to broadcast. The engine only ever sees signed bytes —
//! it never holds the wallet key. Wallet state is DIGOP1-sealed per profile (NC-2).
