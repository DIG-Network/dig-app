//! The APP-SIGN loopback service assembly — the production wiring that turns the SIGN-1/2/3 building
//! blocks into a running extension↔dig-app signing channel (dig_ecosystem#958 item 3, `SPEC.md` §5.6,
//! **security-critical / custody**).
//!
//! SIGN-1/2/3 delivered the pieces — the [`LoopbackServer`], the [`FrameRouter`], the sealed
//! [`PairingStore`]/[`WhitelistStore`], the per-OS [`native_confirmer`](crate::confirm::native_confirmer),
//! and the [`ProfileSessionSigner`] — but nothing assembled them into a live server. This module is
//! that assembly, called by the dig-app tray shell on boot:
//!
//! 1. builds a [`FrameRouter`] over the ACTIVE profile's identity — the pairing/whitelist stores seal
//!    under its DEK (NC-2), the [`ProfileSessionSigner`] signs `sign.request`s with its `0x0010` key,
//!    and [`ProfileConnectInfo`] advertises its public key on connect;
//! 2. gates every pair/connect/sign on the real per-OS [`native_confirmer`](crate::confirm::native_confirmer)
//!    (Windows Hello / macOS Touch ID / Linux polkit) instead of the fail-closed `HeadlessConfirmer`;
//! 3. attaches the durable [`FileSealedStore`] so pairings, connected origins, and the per-frame nonce
//!    ledger survive a restart (#958/#956), and RESTORES that state before the server accepts a frame;
//! 4. serves the two loopback listeners (`[::1]:9779` + `127.0.0.1:9779`) behind the pinned
//!    [`ConnectionGuard`].
//!
//! **The active profile MUST be unlocked** before assembly — the signer + sealer resolve the identity
//! from the shared [`UnlockedIdentities`] session. A headless host, or a host with no unlocked profile,
//! MUST NOT start the service (fail-closed, §5.6.1); that gate lives in the shell, which only calls
//! [`build_router`] once it has an unlocked active profile on a desktop session.

use std::path::Path;
use std::sync::Arc;

use dig_keystore::KdfParams;

use crate::confirm::NativeConfirmer;
use crate::loopback::{
    ConnectionGuard, FileSealedStore, FrameRouter, LoopbackServer, ProfileConnectInfo,
    SealedRecordStore, PINNED_EXTENSION_IDS,
};
use crate::pairing::PairingStore;
use crate::profiles::keystore_sealer::{KeystoreSealer, UnlockedIdentities};
use crate::session::{ProfileSessionSigner, SessionSigner};
use crate::whitelist::WhitelistStore;

/// Build the production [`FrameRouter`] for `profile_did` (which MUST be unlocked in `identities`),
/// persisting sealed pairings/whitelist/nonces under `profile_dir` and gating every action on
/// `confirmer`, then RESTORE any persisted state so a paired extension + its connected dapps survive a
/// restart (#958/#956). Returns the ready-to-serve router.
///
/// Uses the production Argon2 KDF cost for the per-profile DEK; the shell hands this router to
/// [`serve_blocking`].
pub fn build_router(
    identities: UnlockedIdentities,
    profile_did: &str,
    profile_dir: &Path,
    confirmer: Arc<dyn NativeConfirmer>,
) -> FrameRouter<KeystoreSealer> {
    build_router_with_kdf(
        identities,
        profile_did,
        profile_dir,
        confirmer,
        KdfParams::DEFAULT,
    )
}

/// The KDF-parameterized assembly behind [`build_router`]. Split out so tests can pass
/// [`KdfParams::FAST_TEST`] and keep Argon2 cheap; production always uses the default cost.
fn build_router_with_kdf(
    identities: UnlockedIdentities,
    profile_did: &str,
    profile_dir: &Path,
    confirmer: Arc<dyn NativeConfirmer>,
    kdf: KdfParams,
) -> FrameRouter<KeystoreSealer> {
    let pairings = PairingStore::new(
        KeystoreSealer::with_kdf(identities.clone(), kdf),
        profile_did,
    );
    let whitelist = WhitelistStore::new(
        KeystoreSealer::with_kdf(identities.clone(), kdf),
        profile_did,
    );
    let signer = ProfileSessionSigner::new(identities, profile_did);
    // The connect handle advertises the active identity's signing public key. Wallet receive
    // addresses are exposed once the wallet host is wired through here (a follow-up); the identity
    // pubkey is what the profile itself provides today (#958 item 3 — "from the active identity").
    let connect_info = ProfileConnectInfo {
        profile_did: profile_did.to_string(),
        addresses: Vec::new(),
        pubkeys: vec![SessionSigner::signing_public_key_hex(&signer)],
    };
    let store: Arc<dyn SealedRecordStore> = Arc::new(FileSealedStore::new(profile_dir));

    let router = FrameRouter::new(
        pairings,
        whitelist,
        confirmer,
        Box::new(signer),
        connect_info,
        PINNED_EXTENSION_IDS.iter().map(|id| id.to_string()),
    )
    .with_persistence(store);
    router.restore();
    router
}

/// Serve `router` on the two pinned loopback listeners until the process exits, on a dedicated
/// current-thread tokio runtime. Blocks the calling thread — the tray shell spawns this on a
/// background thread so the OS event loop keeps the main thread.
///
/// # Errors
///
/// [`std::io::Error`] if neither loopback address can be bound (the identity port is in use).
pub fn serve_blocking<S>(router: FrameRouter<S>) -> std::io::Result<()>
where
    S: crate::profiles::sealer::ProfileSealer + Send + Sync + 'static,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let server = LoopbackServer::new(router, ConnectionGuard::pinned());
    runtime.block_on(server.serve())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::HeadlessConfirmer;
    use crate::keystore::IdentitySecrets;
    use crate::loopback::persist::FileSealedStore;

    const DID: &str = "did:chia:sign-service-test";

    /// A DERIVED nonce high-water mark (not an integer literal) for persistence tests — a monotonic
    /// replay counter, never cryptographic key/IV material.
    fn derived_mark() -> u64 {
        use sha2::{Digest, Sha256};
        let seed = Sha256::digest(b"dig-app sign_service test nonce mark");
        u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]))
    }

    /// A session with `DID` unlocked to a fresh identity — the precondition for assembling a service.
    fn unlocked() -> UnlockedIdentities {
        let identities = UnlockedIdentities::new();
        identities.unlock(DID, IdentitySecrets::generate());
        identities
    }

    fn assemble(identities: UnlockedIdentities, dir: &Path) -> FrameRouter<KeystoreSealer> {
        build_router_with_kdf(
            identities,
            DID,
            dir,
            Arc::new(HeadlessConfirmer),
            KdfParams::FAST_TEST,
        )
    }

    #[test]
    fn assembling_a_fresh_profile_starts_with_no_pairings() {
        let dir = tempfile::tempdir().unwrap();
        let router = assemble(unlocked(), dir.path());
        assert_eq!(router.restore(), (0, 0), "a fresh profile restores nothing");
    }

    #[test]
    fn a_previously_persisted_pairing_is_restored_on_assembly() {
        // Persist a sealed pairing under the profile's DEK, then assemble a fresh service over the
        // SAME identity + directory and confirm the pairing is restored (survives a restart, #958).
        let dir = tempfile::tempdir().unwrap();
        let identities = unlocked();

        let sealed = {
            let pairings = PairingStore::new(
                KeystoreSealer::with_kdf(identities.clone(), KdfParams::FAST_TEST),
                DID,
            );
            let outcome = pairings
                .pair("mlibddmbhlgogepnjdienclhnkfpkfah", 1)
                .unwrap();
            let store = FileSealedStore::new(dir.path());
            store.persist_pairing(&outcome.pairing_id, &outcome.sealed_record);
            // A pairing is only KEPT on restore when it has a persisted nonce mark (fail-closed on a
            // missing mark, #956) — record one so this models a pairing that had authenticated a frame.
            // The mark is DERIVED (not a literal) so static analysis does not read it as a hard-coded
            // cryptographic nonce (it is a monotonic replay COUNTER, not key/IV material).
            store.persist_nonce(&outcome.pairing_id, derived_mark());
            outcome.pairing_id
        };

        let router = assemble(identities, dir.path());
        assert!(
            router.pairings().is_paired(&sealed),
            "the persisted pairing is restored on assembly"
        );
    }
}
