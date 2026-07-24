//! The identity-authenticated engine session — the app side of the IPC channel (U6, epic #908,
//! **security-critical / custody**).
//!
//! dig-app proves possession of the active profile's identity to the identity-agnostic engine, then
//! keeps a live session over which the engine may ask the app to sign engine-initiated operations.
//! The private key never crosses this boundary: the app signs *in process* and returns only the
//! signature.
//!
//! ## The contract lives in `dig-ipc-protocol` (single source of truth)
//!
//! The IPC session/signing contract — the domain-separated message builders (app signs, engine
//! verifies), the frame/size bounds, the JSON-RPC `control.session.*` wire types + the engine→app
//! `sign` callback, the seam traits, and the generic client role-half — is owned by the canonical
//! [`dig_ipc_protocol`] crate (dig_ecosystem#1074). Both dig-app (the CLIENT, here) and dig-node (the
//! ENGINE, #1080) depend on that ONE definition, so the two halves can never silently drift.
//!
//! This module **re-exports** that contract at the paths app code already imports (`crate::session::*`
//! — unchanged). The concrete [`SessionSigner`] the loopback router signs with is the master-HD
//! [`ResidencySigner`](crate::account::residency::ResidencySigner) (a `dig-account` `ProfileSigner`
//! behind the lockable [`AccountResidency`](crate::account::residency::AccountResidency)), injected
//! through the sign seam by the tray boot. The production [`SignPolicy`] — the decode-then-native-confirm
//! [`NativeConfirmSignPolicy`](crate::sign_policy::NativeConfirmSignPolicy) — lives in
//! [`crate::sign_policy`]; the crate ships only the [`AllowAllSignPolicy`] / [`DenyAllSignPolicy`] test
//! doubles.
//!
//! ## Boundary invariants (upheld here)
//!
//! - The identity private key is resolved through the [`SessionSigner`] seam (the U4/U5 unlocked
//!   identity), never held raw outside the keystore and never serialized onto the wire.
//! - Blind-signing is the custody risk: the engine chooses the callback payload. [`SignPolicy`] is
//!   the mandatory gate — there is no default-allow — so an operator can require confirmation or
//!   scope which `payload_type`s an attached session may sign.
//! - The local per-user pipe/socket frames are NOT end-to-end sealed: the OS per-user ACL is the
//!   confidentiality boundary here (ecosystem §5.4). This module moves only session-control frames
//!   and detached signatures, so it never undermines the recipient-sealing that happens upstream.

// --- The canonical IPC contract, re-exported at the paths app code imports (paths unchanged; the
// definitions now live in `dig-ipc-protocol`). ---
pub use dig_ipc_protocol::{
    challenge_message, sign_callback_message, user_sign_message, verify_signature,
    AllowAllSignPolicy, DenyAllSignPolicy, FrameTransport, LineTransport, ProfileAttachment,
    Session, SessionClient, SessionError, SessionRegistry, SessionSigner, SignDecision, SignPolicy,
    SignRequest, SESSION_CHALLENGE_DOMAIN, SIGN_CALLBACK_DOMAIN, USER_SIGN_DOMAIN,
};

// The concrete production `SessionSigner` is the master-HD `ResidencySigner`
// (crate::account::residency): it signs session challenges and engine callbacks through the lockable
// `AccountResidency`, so the identity key stays owned by `dig-account` and a lock immediately relocks
// it. Its round-trip + fail-closed behaviour is proven in `crate::account::residency`'s tests. This
// module contributes only the canonical re-exports above.
