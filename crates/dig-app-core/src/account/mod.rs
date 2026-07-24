//! The app-side custody HARNESS for the master-HD account model (#1509 Phase 1, strangler step 2 /
//! Model A).
//!
//! # Division of responsibility (LOCKED, #1509)
//!
//! The reusable **object model + crypto** — `AccountStore`/`AccountSession`/`UnlockedAccount`, the
//! keystore at-rest crypto, the `AuthPolicy` verification + KDF unlock, per-profile identity signing
//! (`ProfileSigner: dig_ipc_protocol::SessionSigner`), the wallet money-path (`WalletOps`), DEK, and
//! DID/dig-store mint — lives in the dedicated **`dig-account`** crate, defined ONCE and reused. dig-app
//! **consumes** it.
//!
//! This module owns the harness parts that are inherently app-side:
//!
//! - [`registry`] — the **Accounts registry**: which accounts exist, which ONE is the default account,
//!   and which is currently active. Generic over the loaded-account handle so it needs no `dig-account`
//!   type (it is specialized to `dig_account::AccountSession` on adoption).
//! - `auth` (LATER, on dig-account adoption) — the harness [`dig_account::AuthProvider`] impl: the
//!   OS-native factor-collection + signing-modal ceremony dig-account calls BACK through. dig-account
//!   verifies the collected `AuthFactors`; the harness never draws its UI from inside the crate.
//! - `session`/`signer` wiring (LATER) — bind `UnlockedAccount::identity_signer(ix)` (a
//!   `SessionSigner`) into the engine→app sign callback, and stream `WalletEvent`s to notifications.
//!
//! # Strangler discipline (#1509)
//!
//! Built ALONGSIDE the existing modules; no consumer is wired to it yet, so the crate stays green at
//! every commit. The mechanical switchover is a later pass.

pub mod auth;
pub mod boot;
pub mod ceremony;
pub mod lifecycle;
pub mod money;
pub mod registry;
pub mod residency;
pub mod sealer;

/// The account identifier is the one defined by `dig-account`, re-exported so the harness (the
/// [`registry`] and the [`auth`] provider) keys every account by the SAME opaque id the custody crate's
/// [`AccountStore`](dig_account::AccountStore) addresses blobs by. It is an app-local handle — NOT a DID
/// and NOT derived from key material — so relabelling an account never disturbs its custody root. There
/// is deliberately no second, harness-local id type to drift out of sync with the crate's.
pub use dig_account::AccountId;

/// The profile index within an account, re-exported so harness code (the tray shell, the boot glue)
/// names the default profile ([`ProfileIx::ROOT`](dig_account::ProfileIx::ROOT)) without depending on
/// `dig-account` directly.
pub use dig_account::ProfileIx;
