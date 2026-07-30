//! The **second factor** — an authenticator-app code on a DIFFERENT DEVICE (dig_ecosystem#1840).
//!
//! # What this buys, stated honestly
//!
//! Verifying a TOTP code requires the shared secret to be present locally. So an attacker who can
//! already unlock this account can, in principle, also read the secret and mint codes. **This is not
//! protection against full local compromise, and no copy in this module may imply that it is.**
//!
//! What it genuinely raises the bar against:
//!
//! - a shoulder-surfed, guessed, phished or reused unlock credential — knowing it is no longer enough;
//! - an unattended unlocked machine, because the destructive verbs demand a code the passer-by does
//!   not have;
//! - anyone who knows the password but does not have the phone.
//!
//! Windows Hello (the [`BiometricVerifier`](crate::confirm) behind every authorization) is already a
//! factor. What it is *not* is a factor on another device: Hello is bound to this machine and this
//! logon session, so it cannot distinguish "the owner" from "whoever is sitting at the owner's
//! unlocked machine with their finger available"… and it is gone entirely if the machine is. An
//! authenticator app is somewhere else. That difference is the whole justification, and the enrolment
//! window says so in those terms.
//!
//! # The three shape decisions, and why
//!
//! **What the code gates.** Enrolment, disabling, and every DESTRUCTIVE account action (replace /
//! remove). Not ordinary reads and not ordinary signatures, which stay on Hello — a second factor
//! demanded for everything is a second factor people turn off, and one demanded for nothing is
//! decoration. Gating UNLOCK is deliberately deferred to dig_ecosystem#1817: unlock today is
//! zero-prompt from the OS credential store, so a code there would be the *only* factor at unlock
//! rather than a second one.
//!
//! **Where the secret is sealed.** Under the profile DEK, through the same audited
//! [`ProfileSealer`](crate::sealer::ProfileSealer) / DIGOP1 container (AES-256-GCM + Argon2id) the
//! recovery-phrase vault uses — no new primitive (NC-1) — inside a domain-separated, versioned
//! envelope so a blob can never be substituted between vaults. A *distinct KDF path* was considered
//! and rejected as security theatre here: any key this process could derive is derivable from the
//! same unlock, so a separate path re-labels the trust boundary rather than moving it. The honest gain
//! is domain separation, and the envelope delivers exactly that at the same level.
//!
//! **QR rendering.** There is none, on purpose. A QR encoder would be a new crate in a binary that
//! holds master seeds, added solely to draw a secret that must be shown as text anyway (the enrolment
//! window shows the base32 for anyone who cannot scan). The convenience is real; paying for it with an
//! un-audited code path that consumes secret material, plus a bitmap element in the security-critical
//! window class, is not a trade this binary should make. The window shows the secret in
//! four-character groups and the full `otpauth://` URI instead — both accepted by every authenticator's
//! manual-entry field.

pub mod journey;
pub mod recovery_codes;
pub mod totp;
pub mod vault;
