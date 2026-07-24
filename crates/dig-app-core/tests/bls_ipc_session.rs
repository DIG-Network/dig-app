//! The headline regression proof for dig_ecosystem#1211: a CURRENT dig-app opens an IPC session with
//! a CURRENT dig-node.
//!
//! Before this migration dig-app pinned `dig-ipc-protocol` 0.1 (Ed25519: 32-byte key, 64-byte sig)
//! while dig-node ran 0.2 (BLS12-381 G1: 48-byte key, 96-byte G2 sig). The byte lengths disagreed, so
//! the attach handshake failed at the wire and no session could ever open. These tests drive the
//! dig-app client-side signer (the master-HD [`ResidencySigner`], a `SessionSigner`) against the SAME
//! `dig-ipc-protocol` 0.2 engine half dig-node runs — the engine `begin` → app signs the canonical
//! `challenge_message` in-process → engine `attach` — and prove the handshake now SUCCEEDS.
//!
//! The custody invariant is preserved and asserted: only the 96-byte detached signature and the
//! 48-byte public key cross the boundary; the private key never leaves the app process.

use std::sync::Arc;

use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
use dig_app_core::account::residency::{AccountResidency, ResidencySigner};
use dig_app_core::session::{challenge_message, SessionSigner};
use dig_ipc_protocol::{
    AttachError, AttachParams, BeginParams, DidSigningKeyResolver, EngineSessionRegistry,
    OsEntropy, ProfileAttachment, SigningPublicKey,
};
use dig_keystore::MemoryBackend;
use dig_session::{Password, SEED_LEN};

const DID: &str = "did:chia:testprofile1211";

/// A live-view master-HD identity signer over a freshly-enrolled account (a distinct random seed each
/// call), exactly the signer the loopback router signs with in production.
fn app_signer() -> ResidencySigner {
    use rand_core::RngCore;
    let mut seed = [0u8; SEED_LEN];
    rand_core::OsRng.fill_bytes(&mut seed);
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("bls-ipc-test"),
        Password::new("pw"),
        &seed,
        ProfileIx::ROOT,
    )
    .expect("enrol a fresh account");
    AccountResidency::new(unlocked).signer(ProfileIx::ROOT)
}

/// The engine's DID→published-key backstop. dig-node resolves this from the profile DID's on-chain
/// slot-`0x0010` BLS G1 key; here it returns the app identity's own advertised key, modelling a DID
/// whose published key is the one the app signs with (the success path).
struct FixedKeyResolver {
    key: SigningPublicKey,
}

impl DidSigningKeyResolver for FixedKeyResolver {
    fn resolve_signing_key(&self, profile_did: &str) -> Option<SigningPublicKey> {
        (profile_did == DID).then_some(self.key)
    }
}

fn profile() -> ProfileAttachment {
    ProfileAttachment {
        did: DID.to_string(),
        subscriptions: vec![],
        config_digest: "d".to_string(),
    }
}

/// The exact break, repaired: a dig-app BLS identity signs the attach challenge and the current
/// dig-ipc-protocol 0.2 engine ACCEPTS it, opening a session. This test cannot even compile — let
/// alone pass — against the pre-migration Ed25519 (32/64-byte) contract.
#[test]
fn a_current_dig_app_opens_a_session_with_a_current_dig_node_engine() {
    let app = app_signer();
    let advertised = SessionSigner::signing_public_key(&app);

    let mut engine = EngineSessionRegistry::new(OsEntropy, FixedKeyResolver { key: advertised });

    // 1. Engine mints the per-attach nonce + candidate.
    let begin = engine
        .begin(&BeginParams {
            profile_did: DID.to_string(),
            signing_pubkey_hex: advertised.to_hex(),
        })
        .expect("begin succeeds");

    // 2. App signs the canonical domain-separated challenge IN-PROCESS. Only the detached signature
    //    (96 bytes) and the public key (48 bytes) will cross the wire — never the private key.
    let nonce = base64_decode(&begin.nonce_b64);
    let signature = SessionSigner::sign(&app, &challenge_message(&nonce, DID));
    assert_eq!(
        signature.as_bytes().len(),
        96,
        "BLS G2 signature is 96 bytes"
    );
    assert_eq!(advertised.as_bytes().len(), 48, "BLS G1 key is 48 bytes");

    // 3. Engine verifies against the DID's published key and opens the session.
    let attach = engine
        .attach(&AttachParams {
            session_candidate: begin.session_candidate,
            signature_b64: base64_encode(signature.as_bytes()),
            profile: profile(),
        })
        .expect("attach succeeds — the BLS handshake verifies");

    assert!(engine.session(&attach.session_id).is_some());
    assert_eq!(engine.open_sessions(), 1);
}

/// A foreign key cannot open the session: if the app signs with a DIFFERENT identity than the DID
/// publishes, the engine's published-key backstop rejects the attach. This guards against the
/// migration accidentally verifying against the wrong key.
#[test]
fn a_foreign_identity_cannot_attach() {
    let published = app_signer();
    let attacker = app_signer();

    let mut engine = EngineSessionRegistry::new(
        OsEntropy,
        FixedKeyResolver {
            key: SessionSigner::signing_public_key(&published),
        },
    );

    // The attacker advertises + signs with its OWN key — not the key the DID published.
    let attacker_key = SessionSigner::signing_public_key(&attacker);
    let begin = engine
        .begin(&BeginParams {
            profile_did: DID.to_string(),
            signing_pubkey_hex: attacker_key.to_hex(),
        })
        .expect("begin succeeds");
    let nonce = base64_decode(&begin.nonce_b64);
    let signature = SessionSigner::sign(&attacker, &challenge_message(&nonce, DID));

    let err = engine
        .attach(&AttachParams {
            session_candidate: begin.session_candidate,
            signature_b64: base64_encode(signature.as_bytes()),
            profile: profile(),
        })
        .expect_err("a foreign identity must not attach");
    assert_eq!(err, AttachError::KeyMismatch);
    assert_eq!(engine.open_sessions(), 0);
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
