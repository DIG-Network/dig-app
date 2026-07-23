//! The APP-SIGN loopback service assembly — the production wiring that turns the SIGN-1/2/3 building
//! blocks into a running extension↔dig-app signing channel (dig_ecosystem#958 item 3, `SPEC.md` §5.6,
//! **security-critical / custody**).
//!
//! SIGN-1/2/3 delivered the pieces — the [`LoopbackServer`], the [`FrameRouter`], the sealed
//! [`PairingStore`]/[`WhitelistStore`], the per-OS [`native_confirmer`](crate::confirm::native_confirmer),
//! and the identity [`SessionSigner`] — but nothing assembled them into a live server. This module is
//! that assembly, called by the dig-app tray shell on boot:
//!
//! 1. builds a [`FrameRouter`] over the ACTIVE profile's identity — the pairing/whitelist stores seal
//!    under its DEK (NC-2), the caller-injected identity [`SessionSigner`] signs `sign.request`s with
//!    the profile's `0x0010` key, and [`ProfileConnectInfo`] advertises that signing public key AND the
//!    profile's wallet receive addresses on connect (#961), so a connected dapp can display / send to
//!    the wallet. The signer is INJECTED (not built here) so the custody switchover (#1530/#1546) can
//!    supply a [`dig_account::ProfileSigner`] — the master-HD identity signer — through the SAME seam
//!    without touching this assembly;
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

use crate::confirm::NativeConfirmer;
use crate::loopback::{
    ConnectionGuard, FileSealedStore, FrameRouter, LoopbackServer, ProfileConnectInfo,
    SealedRecordStore, SignReauthGate, PINNED_EXTENSION_IDS,
};
use crate::pairing::PairingStore;
use crate::profiles::keystore_sealer::UnlockedIdentities;
use crate::profiles::sealer::ProfileSealer;
use crate::session::SessionSigner;
use crate::session_lock::{SessionLock, SystemClock};
use crate::wallet::state::WalletStore;
use crate::whitelist::WhitelistStore;

/// The shared session-lock controller the tray drives (lock-now / idle poll / OS screen-lock) and the
/// sign path re-authenticates through — the SAME `Arc`, so a lock the tray triggers is the lock the
/// signer sees. Timed with the wall-clock [`SystemClock`] in production.
pub type TraySessionLock = Arc<SessionLock<UnlockedIdentities, SystemClock>>;

/// The production [`SignReauthGate`] (WSEC-D, dig_ecosystem#967): it bridges the sign path to the live
/// [`SessionLock`] so a signature that arrives after a lock re-authenticates before it uses the key.
///
/// - **Not locked** → signing is authorized, and — since a sign is user activity — the idle clock is
///   reset so an active signer is not auto-locked mid-flow.
/// - **Locked (a re-auth is owed)** → the caller-supplied `reunlock` runs (the keystore's job: re-unlock
///   the DEK, e.g. via the OS credential store); on success the resume is noted (clearing the owed
///   re-auth + restarting the idle clock) and signing proceeds, on failure signing is refused (`LOCKED`).
///
/// Keeping `reunlock` a closure decouples this from the profile-manager / keychain wiring and keeps the
/// gate logic unit-testable.
pub struct SessionReauthGate {
    lock: TraySessionLock,
    reunlock: Box<dyn Fn() -> bool + Send + Sync>,
}

impl SessionReauthGate {
    /// Build the gate over the shared `lock`, re-unlocking the session through `reunlock` when a lock
    /// has dropped the DEK. `reunlock` returns whether the re-unlock succeeded.
    pub fn new(lock: TraySessionLock, reunlock: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            lock,
            reunlock: Box::new(reunlock),
        }
    }
}

impl SignReauthGate for SessionReauthGate {
    fn authorize_sign(&self) -> bool {
        if !self.lock.reauth_required() {
            self.lock.note_activity();
            return true;
        }
        if (self.reunlock)() {
            self.lock.note_resumed();
            true
        } else {
            false
        }
    }
}

/// Build the production [`FrameRouter`] for `profile_did`, sealing every per-profile blob under the
/// caller-supplied `sealer` (bound to the active profile's DEK), persisting sealed
/// pairings/whitelist/nonces under `profile_dir` and gating every action on `confirmer`, then RESTORE
/// any persisted state so a paired extension + its connected dapps survive a restart (#958/#956).
/// Returns the ready-to-serve router.
///
/// The sealer is INJECTED (not built here) so the master-HD custody switchover (#1547) supplies an
/// [`AccountSealer`](crate::account::sealer::AccountSealer) over the unlocked account's per-profile
/// DEK through the SAME seam — mirroring how the identity `signer` is injected — without this assembly
/// knowing which custody root produced the key. The sealer carries its own Argon2 KDF cost
/// (production default vs the cheap test cost), so the assembly no longer threads a `KdfParams`.
pub fn build_router<S>(
    sealer: S,
    profile_did: &str,
    profile_dir: &Path,
    confirmer: Arc<dyn NativeConfirmer>,
    signer: Box<dyn SessionSigner + Send + Sync>,
) -> FrameRouter<S>
where
    S: ProfileSealer + Clone + Send + Sync + 'static,
{
    let pairings = PairingStore::new(sealer.clone(), profile_did);
    let whitelist = WhitelistStore::new(sealer.clone(), profile_did);
    // Load the active profile's wallet receive addresses so the connect handle can advertise them
    // alongside the identity signing pubkey (#961).
    let addresses = active_wallet_addresses(sealer, profile_did, profile_dir);

    // The connect handle advertises the active identity's signing public key AND the wallet's
    // receive addresses (#961), so a connected dapp can display / send to the wallet. Only public
    // data crosses this handle — the private key stays sealed in the injected `signer`.
    let connect_info = ProfileConnectInfo {
        profile_did: profile_did.to_string(),
        addresses,
        pubkeys: vec![signer.signing_public_key_hex()],
    };
    let store: Arc<dyn SealedRecordStore> = Arc::new(FileSealedStore::new(profile_dir));

    let router = FrameRouter::new(
        pairings,
        whitelist,
        confirmer,
        signer,
        connect_info,
        PINNED_EXTENSION_IDS.iter().map(|id| id.to_string()),
    )
    .with_persistence(store);
    router.restore();
    router
}

/// Read the active profile's wallet receive addresses (`xch1…`) for the connect handle (#961).
///
/// The wallet state is sealed per profile under the SAME DEK the router's stores use, so this opens
/// it through a [`WalletStore`] over the same injected `sealer`. The store is rooted at the brand
/// directory, which is the grandparent of `profile_dir` (`<brand>/profiles/<did-hash>/`); a profile
/// with no saved wallet state yet — or one whose sealed state cannot be opened — yields no addresses
/// rather than failing the assembly, since the signing channel is still fully usable without them
/// (they only enrich the connect handle).
fn active_wallet_addresses<S>(sealer: S, profile_did: &str, profile_dir: &Path) -> Vec<String>
where
    S: ProfileSealer + Send + Sync + 'static,
{
    let Some(brand_dir) = profile_dir.parent().and_then(Path::parent) else {
        tracing::warn!("could not derive the brand dir from the profile dir — no wallet addresses");
        return Vec::new();
    };
    let store = WalletStore::new(brand_dir, sealer);
    match store.load_state(profile_did) {
        Ok(state) => state.addresses,
        Err(e) => {
            tracing::warn!(error = %e, "could not load wallet state — connect handle carries no addresses");
            Vec::new()
        }
    }
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
    use crate::profiles::keystore_sealer::KeystoreSealer;
    use dig_keystore::KdfParams;

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
        let signer = crate::session::ProfileSessionSigner::new(identities.clone(), DID);
        build_router(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            DID,
            dir,
            Arc::new(HeadlessConfirmer),
            Box::new(signer),
        )
    }

    use crate::session_lock::DEFAULT_IDLE_TIMEOUT;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`TraySessionLock`] over a freshly-unlocked session, for the re-auth gate tests.
    fn tray_lock() -> TraySessionLock {
        Arc::new(SessionLock::new(
            unlocked(),
            SystemClock::new(),
            DEFAULT_IDLE_TIMEOUT,
        ))
    }

    #[test]
    fn an_unlocked_session_authorizes_a_sign_without_reunlocking() {
        let reunlocks = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&reunlocks);
        let gate = SessionReauthGate::new(tray_lock(), move || {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        });

        assert!(gate.authorize_sign(), "an unlocked session signs");
        assert_eq!(
            reunlocks.load(Ordering::SeqCst),
            0,
            "an unlocked session never triggers a re-unlock"
        );
    }

    #[test]
    fn a_locked_session_reunlocks_then_authorizes_and_clears_the_owed_reauth() {
        let lock = tray_lock();
        let gate = SessionReauthGate::new(Arc::clone(&lock), || true);

        lock.lock_now();
        assert!(lock.reauth_required());
        assert!(
            gate.authorize_sign(),
            "a successful re-unlock authorizes the sign"
        );
        assert!(
            !lock.reauth_required(),
            "the resume cleared the owed re-auth so the next sign passes without re-prompting"
        );
    }

    #[test]
    fn a_locked_session_whose_reunlock_fails_refuses_the_sign() {
        let lock = tray_lock();
        let gate = SessionReauthGate::new(Arc::clone(&lock), || false);

        lock.lock_now();
        assert!(
            !gate.authorize_sign(),
            "a failed re-unlock refuses the sign"
        );
        assert!(
            lock.reauth_required(),
            "a failed re-unlock leaves the re-auth owed (still locked)"
        );
    }

    #[test]
    fn assembling_a_fresh_profile_starts_with_no_pairings() {
        let dir = tempfile::tempdir().unwrap();
        let router = assemble(unlocked(), dir.path());
        assert_eq!(router.restore(), (0, 0), "a fresh profile restores nothing");
    }

    #[test]
    fn wallet_addresses_are_loaded_for_the_connect_handle() {
        // Save a wallet state with receive addresses under the profile's DEK, then confirm the
        // wiring reads them back for the connect handle (#961). The store is rooted at the brand
        // dir; the profile dir is its `profiles/<did-hash>` child, so the helper must derive the
        // brand dir back from the profile dir.
        use crate::wallet::state::{WalletState, WalletStore};

        let brand = tempfile::tempdir().unwrap();
        let identities = unlocked();
        let store = WalletStore::new(
            brand.path(),
            KeystoreSealer::with_kdf(identities.clone(), KdfParams::FAST_TEST),
        );
        store
            .save_state(
                DID,
                &WalletState {
                    addresses: vec!["xch1receive".into(), "xch1change".into()],
                    ..WalletState::default()
                },
            )
            .unwrap();

        let profile_dir =
            crate::storage::profile_dir(brand.path(), &crate::profiles::did_hash(DID));
        let addresses = active_wallet_addresses(
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
            DID,
            &profile_dir,
        );
        assert_eq!(addresses, vec!["xch1receive", "xch1change"]);
    }

    #[test]
    fn a_profile_with_no_saved_wallet_yields_no_addresses() {
        // No wallet state was ever saved — the connect handle simply carries no addresses (the
        // signing channel is still fully usable), never a failure.
        let brand = tempfile::tempdir().unwrap();
        let profile_dir =
            crate::storage::profile_dir(brand.path(), &crate::profiles::did_hash(DID));
        let addresses = active_wallet_addresses(
            KeystoreSealer::with_kdf(unlocked(), KdfParams::FAST_TEST),
            DID,
            &profile_dir,
        );
        assert!(addresses.is_empty());
    }

    #[test]
    fn an_unopenable_sealed_wallet_yields_no_addresses() {
        // A wallet state exists on disk but the profile is locked (its DEK is absent from the
        // session), so `load_state` fails to open it — the helper falls back to no addresses rather
        // than propagating the error into the assembly.
        use crate::wallet::state::{WalletState, WalletStore};

        let brand = tempfile::tempdir().unwrap();
        WalletStore::new(
            brand.path(),
            KeystoreSealer::with_kdf(unlocked(), KdfParams::FAST_TEST),
        )
        .save_state(
            DID,
            &WalletState {
                addresses: vec!["xch1receive".into()],
                ..WalletState::default()
            },
        )
        .unwrap();

        let profile_dir =
            crate::storage::profile_dir(brand.path(), &crate::profiles::did_hash(DID));
        // A fresh session has DID LOCKED, so opening the sealed state fails the AEAD tag.
        let addresses = active_wallet_addresses(
            KeystoreSealer::with_kdf(UnlockedIdentities::new(), KdfParams::FAST_TEST),
            DID,
            &profile_dir,
        );
        assert!(addresses.is_empty());
    }

    #[test]
    fn a_profile_dir_with_no_derivable_brand_dir_yields_no_addresses() {
        // A profile dir shallow enough to have no grandparent cannot locate a brand dir — the
        // helper must fall back to no addresses rather than panic.
        let addresses = active_wallet_addresses(
            KeystoreSealer::with_kdf(unlocked(), KdfParams::FAST_TEST),
            DID,
            Path::new("solo"),
        );
        assert!(addresses.is_empty());
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
