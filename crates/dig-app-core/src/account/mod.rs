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
//! - [`auth`] — the harness [`dig_account::AuthProvider`] impl: the OS-native factor-collection +
//!   signing-modal ceremony dig-account calls BACK through. dig-account verifies the collected
//!   `AuthFactors`; the harness never draws its UI from inside the crate.
//! - [`boot`]/[`residency`] wiring — bind `UnlockedAccount::identity_signer(ix)` (a `SessionSigner`)
//!   into the engine→app sign callback, and stream `WalletEvent`s to notifications, holding the live
//!   account in the lockable [`residency::AccountResidency`].
//!
//! # This is the live custody path (#1530)
//!
//! The switchover has shipped: [`boot`] is the production custody boot path, the app enrols-or-unlocks
//! the master seed through it, and the retired keystore no longer holds custody. The `dig-account`
//! object model + crypto is fully adopted here, and consumers sign through [`residency::AccountResidency`].

pub mod active_profile;
pub mod auth;
pub mod boot;
pub mod ceremony;
pub mod chain_mint;
pub mod did;
pub mod first_profile;
pub mod journey;
pub mod lifecycle;
pub mod migration;
pub mod mint;
pub mod money;
pub mod password;
pub mod phrase_vault;
pub mod profile_creation;
pub mod profile_mint;
pub mod profile_session;
pub mod recovery;
pub mod registry;
pub mod residency;
pub mod sealer;
pub mod second_factor;

/// The account identifier is the one defined by `dig-account`, re-exported so the harness (the
/// [`registry`] and the [`auth`] provider) keys every account by the SAME opaque id the custody crate's
/// [`AccountStore`](dig_account::AccountStore) addresses blobs by. It is an app-local handle — NOT a DID
/// and NOT derived from key material — so relabelling an account never disturbs its custody root. There
/// is deliberately no second, harness-local id type to drift out of sync with the crate's.
pub use dig_account::AccountId;

/// The profile index within an account, re-exported so harness code (the tray shell, the boot glue)
/// names the default profile ([`ProfileIx::ROOT`](dig_account::ProfileIx::ROOT)) without depending on
/// `dig-account` directly.
///
/// A bare `ProfileIx` names ANY index in the HD tree. Which index the app is actually deriving at is
/// a LIVE question, answered only by [`profile_session::ProfileSession`] (dig_ecosystem#2398) — so
/// prefer [`active_profile::WalletSlot`] or [`active_profile::MintTarget`] wherever an index selects a
/// wallet or a mint, and never store the scalar.
pub use dig_account::ProfileIx;

/// The live active-profile types, re-exported for the same reason as [`ProfileIx`].
pub use active_profile::{ActiveSlot, MintTarget, WalletSlot};

/// The live profile registry the whole app reads its active index from.
pub use profile_mint::{
    liveness_of, DeathEvidence, MintLiveness, ProfileMint, ProfileMintAvailability,
    ProfileMintDoor, ProfileMintSeams,
};
pub use profile_session::{
    MintDoorError, PersistOutcome, ProfileError, ProfileSession, ProfileSwitched,
};
