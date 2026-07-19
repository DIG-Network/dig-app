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
//! — unchanged), and adds the two things the contract deliberately leaves to the consumer because
//! they depend on app-specific identity + profile data: the concrete [`SessionSigner`] implementations
//! [`IdentitySecrets`] (the unlocked identity) and [`ProfileSessionSigner`] (the active-profile signer
//! the loopback router signs with). The production [`SignPolicy`] — the decode-then-native-confirm
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

use dig_ipc_protocol::{Signature, SigningPublicKey};

use crate::keystore::IdentitySecrets;

// --- The canonical IPC contract, re-exported at the paths app code imports (paths unchanged; the
// definitions now live in `dig-ipc-protocol`). ---
pub use dig_ipc_protocol::{
    challenge_message, sign_callback_message, user_sign_message, verify_signature,
    AllowAllSignPolicy, DenyAllSignPolicy, FrameTransport, LineTransport, ProfileAttachment,
    Session, SessionClient, SessionError, SessionRegistry, SessionSigner, SignDecision, SignPolicy,
    SignRequest, SESSION_CHALLENGE_DOMAIN, SIGN_CALLBACK_DOMAIN, USER_SIGN_DOMAIN,
};

/// The unlocked profile identity signs session challenges and engine callbacks directly. The key
/// itself stays owned by [`IdentitySecrets`]; this impl only borrows its signing primitive and wraps
/// the raw bytes in the contract's [`SigningPublicKey`] / [`Signature`] boundary newtypes.
impl SessionSigner for IdentitySecrets {
    fn signing_public_key(&self) -> SigningPublicKey {
        SigningPublicKey::new(IdentitySecrets::signing_public_key(self))
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature::new(IdentitySecrets::sign(self, message))
    }
}

/// A [`SessionSigner`] bound to the ACTIVE profile's unlocked identity in the shared
/// [`UnlockedIdentities`](crate::profiles::UnlockedIdentities) session, addressed by DID.
///
/// This is the production signer the APP-SIGN loopback [`FrameRouter`](crate::loopback::dispatch)
/// signs approved `sign.request`s with: it delegates every signature to the session's
/// [custody-preserving seam](crate::profiles::UnlockedIdentities::sign), so the identity private key
/// stays owned by the session and is never copied into the router. It signs whatever
/// domain-separated message it is handed (the router builds the `DIGNET-SIGN-v1` message via
/// [`sign_callback_message`]); it never signs raw caller bytes.
///
/// **Fail-closed when the profile is locked.** If the active profile is locked (its identity absent
/// from the session), there is no key to sign with, so [`try_sign`](SessionSigner::try_sign) returns
/// `None` — the router maps that to a `LOCKED` error rather than framing a bogus signature into a
/// success response. The infallible [`sign`](SessionSigner::sign) still returns an all-zero
/// (non-verifying) signature as a last-resort fail-safe for any caller that ignores `try_sign`, so a
/// locked profile can never produce a forgery. In production the router only serves while the profile
/// is unlocked; this guards the mid-session lock edge.
pub struct ProfileSessionSigner {
    identities: crate::profiles::UnlockedIdentities,
    profile_did: String,
}

impl ProfileSessionSigner {
    /// Bind a signer to `profile_did`'s identity in the shared session `identities`.
    pub fn new(
        identities: crate::profiles::UnlockedIdentities,
        profile_did: impl Into<String>,
    ) -> Self {
        Self {
            identities,
            profile_did: profile_did.into(),
        }
    }
}

impl SessionSigner for ProfileSessionSigner {
    fn signing_public_key(&self) -> SigningPublicKey {
        SigningPublicKey::new(
            self.identities
                .signing_public_key(&self.profile_did)
                .unwrap_or([0u8; 32]),
        )
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.try_sign(message).unwrap_or_else(|| {
            // The profile locked between service start and this infallible-sign call — fail safe with
            // a non-verifying zero signature rather than a forgery. Callers on the custody path use
            // `try_sign` and surface `LOCKED` instead of ever framing this. (NEVER log the message.)
            tracing::warn!(
                profile_did = %self.profile_did,
                "sign requested for a locked profile — returning a non-verifying signature"
            );
            Signature::new([0u8; 64])
        })
    }

    fn try_sign(&self, message: &[u8]) -> Option<Signature> {
        self.identities
            .sign(&self.profile_did, message)
            .map(Signature::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    const DID: &str = "did:chia:testprofile";

    /// A test nonce, DERIVED (not a literal) so it is unmistakably a fixture — the production nonce is
    /// minted by the engine, never hard-coded.
    fn nonce() -> Vec<u8> {
        Sha256::digest(b"dig-app session concrete-signer test nonce").to_vec()
    }

    fn signer() -> IdentitySecrets {
        IdentitySecrets::generate_with_rng(&mut ChaCha20Rng::seed_from_u64(42))
    }

    #[test]
    fn identity_secrets_signs_a_challenge_the_engine_half_verifies() {
        // The client half (this concrete signer) builds + signs the canonical attach challenge; the
        // engine half's `verify_signature` (same crate) must accept it against the advertised key.
        // This is the round-trip conformance proof: app-produced bytes ↔ engine-shape verify.
        let id = signer();
        let pubkey = SessionSigner::signing_public_key(&id);

        let message = challenge_message(&nonce(), DID);
        let signature = SessionSigner::sign(&id, &message);

        assert!(
            verify_signature(&pubkey, &message, &signature),
            "an IdentitySecrets-signed attach challenge must verify on the engine-half shape"
        );
        // The advertised hex is the wire form the engine resolves the DID's key against.
        assert_eq!(
            id.signing_public_key_hex(),
            hex::encode(IdentitySecrets::signing_public_key(&id))
        );
    }

    #[test]
    fn a_signed_callback_message_verifies_but_the_raw_payload_does_not() {
        // The app signs the DOMAIN-SEPARATED callback message, never the engine's raw payload — the
        // cross-protocol signing-oracle defence. Prove the round-trip AND the domain separation.
        let id = signer();
        let pubkey = SessionSigner::signing_public_key(&id);
        let payload = b"spend-bundle-bytes";

        let message = sign_callback_message("spend", payload).unwrap();
        let signature = SessionSigner::sign(&id, &message);

        assert!(verify_signature(&pubkey, &message, &signature));
        assert!(
            !verify_signature(&pubkey, payload, &signature),
            "the signature must NOT verify over the raw payload — it is domain-separated"
        );
    }

    #[test]
    fn a_locked_profile_signer_try_sign_returns_none_and_never_forges() {
        // `ProfileSessionSigner` over a session with no unlocked identity for the DID is locked: the
        // fallible path yields None (mapped to LOCKED upstream), and the infallible fail-safe returns
        // a non-verifying zero signature — never a forgery.
        let identities = crate::profiles::UnlockedIdentities::new();
        let locked = ProfileSessionSigner::new(identities, DID);

        assert!(
            locked.try_sign(b"anything").is_none(),
            "a locked profile must not produce a signature"
        );

        let pubkey = SessionSigner::signing_public_key(&locked);
        let fallback = SessionSigner::sign(&locked, b"anything");
        assert!(
            !verify_signature(&pubkey, b"anything", &fallback),
            "the locked fail-safe signature must not verify (no forgery)"
        );
    }

    #[test]
    fn an_unlocked_profile_signer_signs_what_the_engine_half_verifies() {
        let identities = crate::profiles::UnlockedIdentities::new();
        let secrets = signer();
        let pubkey_bytes = IdentitySecrets::signing_public_key(&secrets);
        identities.unlock(DID, secrets);
        let unlocked = ProfileSessionSigner::new(identities, DID);

        let message = challenge_message(&nonce(), DID);
        let signature = unlocked.try_sign(&message).expect("unlocked profile signs");

        assert_eq!(unlocked.signing_public_key().as_bytes(), &pubkey_bytes);
        assert!(verify_signature(
            &SigningPublicKey::new(pubkey_bytes),
            &message,
            &signature
        ));
    }
}
