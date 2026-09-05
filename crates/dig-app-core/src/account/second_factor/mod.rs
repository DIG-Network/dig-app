//! The **second factor** — an asymmetric WebAuthn credential on a key you carry (dig-app#348,
//! superseding the TOTP factor of dig_ecosystem#1840).
//!
//! # What it is
//!
//! A WebAuthn/FIDO2 credential held by a **roaming authenticator**: a security key over USB, NFC or
//! BLE, or a phone reached over the hybrid transport. dig-app verifies its assertions in-process.
//!
//! The at-rest record holds a PUBLIC key, a credential id, a signature counter and the salted
//! recovery-code digests. **It holds no secret.** Nothing in it, even together with the account DEK,
//! is enough to produce an assertion — the private key never leaves the authenticator and was never
//! here to leave.
//!
//! # What this buys, stated honestly
//!
//! **For.** An attacker who holds the account password on this machine cannot mint an assertion from
//! anything stored here, so the second factor is not collapsed into the first. That is the property
//! the previous TOTP design could not have: verifying a code required the shared secret to be present
//! locally, so whoever could unlock the account could also read the secret and mint codes. It keeps
//! everything the old design did raise the bar against, too — a shoulder-surfed, guessed, phished or
//! reused unlock credential; an unattended unlocked machine; someone who knows the password but does
//! not hold the key.
//!
//! **Not full local compromise.** An attacker running code as the user while the account is unlocked
//! holds the DEK the record is sealed under, and can therefore REWRITE it — enrolling their own key.
//! The envelope's integrity is exactly the DEK's, nothing stronger. The app's own surfaces refuse to
//! replace an enrolment without the enrolled factor ([`journey::disable_unlocked`]); what is left is
//! tooling-level tampering, which SPEC §7 classes as the-user-is-the-user. **No copy in this module
//! may describe the factor as protection against that.** A reader may conclude that the record cannot
//! be USED by such an attacker. A reader may NOT conclude that it cannot be REPLACED.
//!
//! **Not user identity.** Assertions are user-presence only: the verifier is built with
//! `danger_set_user_presence_only_security_keys`, because requiring user VERIFICATION would demand a
//! PIN or an on-key biometric and make a touch-only key unusable. A passing assertion proves the
//! enrolled authenticator was physically present and touched — not who touched it. Possession is what
//! this adds; the platform biometric ([`crate::confirm`], §3.1d) remains the identity check and is
//! unchanged.
//!
//! # The shape decisions, and why
//!
//! **What it gates.** Enrolment, disabling, and every DESTRUCTIVE account action (replace / remove).
//! Not ordinary reads and not ordinary signatures, which stay on the platform biometric — a second
//! factor demanded for everything is one people turn off, and one demanded for nothing is decoration.
//! Gating UNLOCK stays deliberately deferred to dig_ecosystem#1817: unlock today is zero-prompt from
//! the OS credential store, so a factor there would be the *only* factor at unlock rather than a
//! second one.
//!
//! **Where the record is sealed.** Under the profile DEK, through the same audited
//! [`ProfileSealer`](crate::sealer::ProfileSealer) / DIGOP1 container the recovery-phrase vault uses —
//! no new primitive (NC-1) — inside a domain-separated, versioned envelope so a blob can never be
//! substituted between vaults. Its CONFIDENTIALITY is not load-bearing here (the contents are public
//! material); its INTEGRITY is, and that is the bound stated above.
//!
//! **Why an outside crate is trusted with this and was not with TOTP.** The objection recorded here
//! against pulling an unaudited crate into a binary that holds master seeds was about a dependency
//! that would handle SECRET material. [`verifier`] consumes public keys and signatures only, so the
//! objection does not transfer. The dependency that WOULD have handled a secret — a QR encoder drawing
//! an `otpauth://` URI — is gone with the secret it existed to draw.
//!
//! # The TOTP record is superseded, not migrated
//!
//! A `DIG2FA1` record cannot become a credential: there is no key inside it to promote. It is
//! [`vault::EnrolmentState::Superseded`] — it clears no gate, it is never reported as "not enrolled",
//! and the only writes that touch it are its removal and a complete fresh enrolment. It is retired
//! through the ordinary disable path with its own material (a recovery code, or a TOTP code checked
//! by the read-only verifier [`totp`] retains for exactly this). Removing that verifier together with
//! the `DIG2FA1` read path is <https://github.com/DIG-Network/dig-app/issues/373>.
//!
//! # Platform scope
//!
//! The client exists on **Windows only** in this version. macOS and Linux get
//! [`authenticator::NoProvider`], which refuses honestly, and every surface there says *not available
//! on this platform in this version* — a platform limitation, never a feature that is switched off.
//! No ENROLMENT fallback is offered there: nothing else may stand in for a key, so a build with no
//! client cannot turn the factor on at all.
//!
//! An account that already HAS a factor is a different question, and the answer is not "nothing".
//! Carrying an enrolled record onto such a host — the same profile directory opened by a macOS build,
//! say — leaves a gate that binds with no way to run a ceremony, so [`journey::challenge`] treats
//! `NoProvider` exactly as it treats a ceremony that did not finish and OFFERS the recovery-code path.
//! That is the difference between a platform limit and a trap: the codes are the way through, and
//! without them such an account could never be replaced or removed again. Tracked as
//! <https://github.com/DIG-Network/dig-app/issues/372>.

pub mod authenticator;
pub mod journey;
pub mod recovery_codes;
pub mod totp;
pub mod vault;
pub mod verifier;
