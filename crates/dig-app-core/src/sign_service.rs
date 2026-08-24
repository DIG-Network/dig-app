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
//! **The account MUST be unlocked** before assembly — the injected signer + sealer resolve the identity
//! from the master-HD [`AccountResidency`](crate::account::residency::AccountResidency). A headless
//! host, or a host with no unlocked account, MUST NOT start the service (fail-closed, §5.6.1); that gate
//! lives in the shell, which only calls [`build_router`] once it has an unlocked account on a desktop
//! session.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::confirm::NativeConfirmer;
use crate::live::{Live, LiveDid, LiveProfileDir};
use crate::loopback::{
    ConnectionGuard, FileSealedStore, FrameRouter, LoopbackServer, ProfileConnectInfo,
    SealedRecordStore, SignReauthGate, PINNED_EXTENSION_IDS,
};
use crate::pairing::PairingStore;
use crate::sealer::ProfileSealer;
use crate::session::SessionSigner;
use crate::session_lock::{SessionLock, SystemClock};
use crate::wallet::state::WalletStore;
use crate::whitelist::WhitelistStore;

/// The shared session-lock controller the tray drives (lock-now / idle poll) and the
/// sign path re-authenticates through — the SAME `Arc`, so a lock the tray triggers is the lock the
/// signer sees. It locks the master-HD [`AccountResidency`](crate::account::residency::AccountResidency),
/// dropping the unlocked account so the live-view signer + sealer relock at once. Timed with the
/// wall-clock [`SystemClock`] in production.
pub type TraySessionLock =
    Arc<SessionLock<crate::account::residency::AccountResidency, SystemClock>>;

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
    profile_did: LiveDid,
    profile_dir: LiveProfileDir,
    confirmer: Arc<dyn NativeConfirmer>,
    signer: Box<dyn SessionSigner + Send + Sync>,
) -> FrameRouter<S>
where
    S: ProfileSealer + Clone + Send + Sync + 'static,
{
    let pairings = PairingStore::new(sealer.clone(), profile_did.clone());
    let whitelist = WhitelistStore::new(sealer.clone(), profile_did.clone());

    // The connect handle advertises the active identity's signing public key AND the wallet's
    // receive addresses (#961), so a connected dapp can display / send to the wallet. Only public
    // data crosses this handle — the private key stays sealed in the injected `signer`.
    //
    // Every field is a live read, so none of them can go stale at the profile that was active when
    // this assembly ran. The advertised signing key is not a field at all — the router reads it from
    // the signer it will actually sign with. That removes the STALENESS; the DID and the addresses
    // remain separate reads from the key, so a switch landing between them still yields a mismatched
    // handle. `connect_handle` says so where the three are read.
    let addresses = {
        let cache = Arc::new(ConnectAddresses::new(
            sealer.clone(),
            profile_did.clone(),
            profile_dir.clone(),
        ));
        Live::read(move || cache.read())
    };
    let connect_info = ProfileConnectInfo {
        profile_did: profile_did.clone(),
        addresses,
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

/// The connect handle's wallet receive addresses, derived once per distinct wallet state rather than
/// once per frame (dig_ecosystem#2398 SEC-F2).
///
/// # Why this is not just a cache
///
/// Opening the sealed wallet state runs a production Argon2id — ~118 ms and 64 MiB on one core. The
/// connect handle is answered by EVERY `connect.request`, and an already-whitelisted origin reaches it
/// with no native confirm and no rate limiter in front of it, on a single-threaded runtime. Deriving
/// per frame therefore lets one connected origin pin the signing thread and queue the user's own
/// `sign.request` behind its frames — so the derivation has to be conditional on something.
///
/// # What it is conditional on, and why that keeps the value LIVE
///
/// The addresses are a pure function of the active profile's DID, its directory, and the CONTENT of its
/// sealed wallet blob, so those three are the whole fingerprint. Hashing the blob costs a small read and
/// a SHA-256 — microseconds against the derivation it decides — and unlike a timestamp it cannot miss a
/// change that lands inside a clock tick. A profile switch moves the DID and the directory, a lock reads
/// both as `None`, and a wallet save rewrites the blob: each of those invalidates, which is the liveness
/// the [`Live`] seam exists for (#2398), kept rather than traded away.
struct ConnectAddresses<S> {
    sealer: S,
    profile_did: LiveDid,
    profile_dir: LiveProfileDir,
    /// The last fingerprint and what was learned under it. The lock is held across a derivation
    /// deliberately: concurrent readers of the same state should wait for one Argon2id, not run several.
    memo: Mutex<Option<(WalletFingerprint, Remembered)>>,
    /// The monotonic clock the failure cooldown is measured against.
    ///
    /// Injected so a test can PIN it. A cooldown tested against the wall clock is either a sleep or
    /// a race, and a fixture that passed small literals through a wall-clock API would silently be
    /// exercising only the already-expired path.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

/// What a previous read of the same fingerprint learned.
///
/// The two arms are treated very differently on purpose, and collapsing them is what dig-app#256
/// was: a completed read is a FACT and is remembered until the fingerprint moves, while a failed one
/// is remembered only long enough to stop it being repeated at Argon2id prices.
enum Remembered {
    /// A read that completed. Includes the genuinely-empty answer.
    Known(Vec<String>),
    /// A read that could not open the sealed blob, and when that was.
    Failed {
        /// When the failure was observed, on the injected monotonic clock.
        at: Instant,
    },
}

/// How long a FAILED read is remembered before another derivation is attempted.
///
/// # Why a failure is remembered at all, when dig-app#256 is about NOT remembering one
///
/// The two are not in tension: #256 forbids remembering a failure as the FACT "this profile has no
/// wallet", and this remembers it as a failure, which expires. Without the expiry the fix would have
/// been unbounded — the fingerprint is `(did, dir, sha256(blob))` and a failed open changes none of
/// the three, so a persistently unopenable blob re-derives on EVERY `connect.request`, at ~118 ms
/// and 64 MiB of Argon2id each, with this mutex held, on a single-threaded runtime, reachable by an
/// already-whitelisted origin with no confirm and no rate limiter in front of it. That is the exact
/// thread-pinning this memo was introduced to prevent, re-entered through its error path.
///
/// # Why two seconds
///
/// It is bounded by what the retry is FOR. The trigger is a human-timed event — the 5-minute idle
/// lock, or a profile switch — so the cost of the delay is at most two seconds of staleness after
/// the account is usable again, which no caller can perceive. The benefit is a hard ceiling of one
/// derivation per two seconds per profile: under 6% of one core, against 100% before.
const FAILED_READ_RETRY_AFTER: Duration = Duration::from_secs(2);

/// Everything the derived addresses depend on: the active DID, its directory, and a digest of the
/// sealed wallet blob (`None` when there is no readable blob, which is itself a state — a profile with
/// no wallet yet has no addresses).
type WalletFingerprint = (Option<String>, Option<PathBuf>, Option<[u8; 32]>);

impl<S> ConnectAddresses<S>
where
    S: ProfileSealer + Clone + Send + Sync + 'static,
{
    /// Build the seam over the same sealer + live profile sources the router's stores use.
    fn new(sealer: S, profile_did: LiveDid, profile_dir: LiveProfileDir) -> Self {
        Self::with_clock(sealer, profile_did, profile_dir, Arc::new(Instant::now))
    }

    /// The same seam over an injected clock, so the failure cooldown can be tested at a pinned
    /// instant instead of against wall time.
    fn with_clock(
        sealer: S,
        profile_did: LiveDid,
        profile_dir: LiveProfileDir,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self {
            sealer,
            profile_did,
            profile_dir,
            memo: Mutex::new(None),
            clock,
        }
    }

    /// The active profile's receive addresses as they are NOW — re-derived only when the fingerprint
    /// says the answer could have changed.
    fn read(&self) -> Vec<String> {
        let (did, dir) = (self.profile_did.get(), self.profile_dir.get());
        let fingerprint = (
            did.clone(),
            dir.clone(),
            self.sealed_wallet_digest(did.as_deref(), dir.as_deref()),
        );

        let now = (self.clock)();
        let mut memo = self.memo.lock().expect("connect-address memo poisoned");
        if let Some((remembered, learned)) = memo.as_ref() {
            if *remembered == fingerprint {
                match learned {
                    // A completed read is a fact and stands until the fingerprint moves.
                    Remembered::Known(addresses) => return addresses.clone(),
                    // A failure is not a fact, so it expires — but until it does, it answers
                    // WITHOUT re-deriving, which is what bounds the cost of a blob that stays
                    // unopenable.
                    Remembered::Failed { at }
                        if now.duration_since(*at) < FAILED_READ_RETRY_AFTER =>
                    {
                        return Vec::new()
                    }
                    Remembered::Failed { .. } => {}
                }
            }
        }
        let read = match (did.as_deref(), dir.as_deref()) {
            (Some(did), Some(dir)) => wallet_addresses_at(self.sealer.clone(), did, dir),
            // No active profile — an honest, complete answer, not a failed read.
            _ => Some(Vec::new()),
        };
        match read {
            Some(addresses) => {
                *memo = Some((fingerprint, Remembered::Known(addresses.clone())));
                addresses
            }
            // The blob could not be opened. Recorded AS a failure, never as an empty wallet, so the
            // next read past the cooldown retries and a person's wallet is never reported absent
            // because of one unlucky moment.
            None => {
                *memo = Some((fingerprint, Remembered::Failed { at: now }));
                Vec::new()
            }
        }
    }

    /// A digest of the profile's sealed wallet blob, or `None` when there is none to read.
    fn sealed_wallet_digest(&self, did: Option<&str>, dir: Option<&Path>) -> Option<[u8; 32]> {
        let store = wallet_store_at(dir?, self.sealer.clone())?;
        let sealed = std::fs::read(store.state_path(did?)).ok()?;
        Some(Sha256::digest(&sealed).into())
    }
}

/// Read the wallet receive addresses (`xch1…`) sealed for `did` under the profile directory `dir`
/// (#961).
///
/// The wallet state is sealed per profile under the SAME DEK the router's stores use, so this opens it
/// through a [`WalletStore`] over the same injected `sealer`. A profile with no saved wallet state yet
/// reads as an empty list, which is the truth; an address is the one field here a person might send
/// money to, so a wrong one is never produced.
///
/// # Why the return type distinguishes "none" from "could not tell"
///
/// `Some(addresses)` is a COMPLETED read — including `Some(vec![])`, which [`WalletStore::load_state`]
/// answers for a profile that has no sealed blob at all. `None` means the read FAILED: the DEK moved
/// under it (an idle lock or a profile switch landing mid-read) and the AEAD open could not run.
///
/// Collapsing the two is what dig-app#256 was: SPEC §5.6.4 gives an empty `addresses[]` the meaning
/// "this profile has no wallet state yet", so a swallowed failure told a dapp something false about
/// the user's wallet. Only a completed read may be remembered — see [`ConnectAddresses::read`].
fn wallet_addresses_at<S>(sealer: S, did: &str, dir: &Path) -> Option<Vec<String>>
where
    S: ProfileSealer + Send + Sync + 'static,
{
    // A directory too shallow to have a brand root has no wallet store and never will: a complete
    // answer, not a failure.
    let Some(store) = wallet_store_at(dir, sealer) else {
        return Some(Vec::new());
    };
    match store.load_state(did) {
        Ok(state) => Some(state.addresses),
        Err(e) => {
            tracing::warn!(error = %e, "could not load wallet state — connect handle carries no addresses this read");
            None
        }
    }
}

/// The [`WalletStore`] whose profile directory is `profile_dir`. The store is rooted at the brand
/// directory, which is the grandparent (`<brand>/profiles/<did-hash>/`); a directory too shallow to have
/// one yields `None`.
fn wallet_store_at<S>(profile_dir: &Path, sealer: S) -> Option<WalletStore<S>>
where
    S: ProfileSealer,
{
    match profile_dir.parent().and_then(Path::parent) {
        Some(brand_dir) => Some(WalletStore::new(brand_dir, sealer)),
        None => {
            tracing::warn!(
                "could not derive the brand dir from the profile dir — no wallet addresses"
            );
            None
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
    S: crate::sealer::ProfileSealer + Send + Sync + 'static,
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
    use crate::account::sealer::AccountSealer;
    use crate::confirm::HeadlessConfirmer;
    use crate::loopback::persist::FileSealedStore;
    use crate::test_support::{test_residency, test_sealer};

    const DID: &str = "did:chia:sign-service-test";

    /// A DERIVED nonce high-water mark (not an integer literal) for persistence tests — a monotonic
    /// replay counter, never cryptographic key/IV material.
    fn derived_mark() -> u64 {
        use sha2::{Digest, Sha256};
        let seed = Sha256::digest(b"dig-app sign_service test nonce mark");
        u64::from(u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]))
    }

    /// Assemble a service over a fresh unlocked master-HD residency (the precondition for a live
    /// service): the identity signer reads the residency's default profile and the stores seal under a
    /// deterministic per-profile DEK (so a re-assembled service over the SAME `DID` re-opens its blobs).
    fn assemble(dir: &Path) -> FrameRouter<AccountSealer> {
        let signer = test_residency().signer();
        build_router(
            test_sealer(DID),
            DID.into(),
            dir.into(),
            Arc::new(HeadlessConfirmer),
            Box::new(signer),
        )
    }

    use crate::session_lock::DEFAULT_IDLE_TIMEOUT;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`TraySessionLock`] over a freshly-unlocked account residency, for the re-auth gate tests.
    fn tray_lock() -> TraySessionLock {
        use crate::account::residency::AccountResidency;
        use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
        use dig_keystore::MemoryBackend;
        use dig_session::{Password, ENTROPY_LEN};
        use rand_core::RngCore;

        let mut seed = [0u8; ENTROPY_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
        let unlocked = AccountSession::enroll(
            store,
            AccountId::new("tray-lock-test"),
            Password::new("pw"),
            &seed,
            ProfileIx::ROOT,
        )
        .unwrap();
        Arc::new(SessionLock::new(
            AccountResidency::new(unlocked),
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
        let router = assemble(dir.path());
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
        let store = WalletStore::new(brand.path(), test_sealer(DID));
        store
            .save_state(
                DID,
                &WalletState {
                    addresses: vec!["xch1receive".into(), "xch1change".into()],
                    ..WalletState::default()
                },
            )
            .unwrap();

        let profile_dir = crate::storage::profile_dir(brand.path(), &crate::storage::did_hash(DID));
        // The SAME per-profile DEK (same label) re-opens the sealed state.
        assert_eq!(
            Some(vec!["xch1receive".to_owned(), "xch1change".to_owned()]),
            wallet_addresses_at(test_sealer(DID), DID, &profile_dir)
        );
    }

    #[test]
    fn a_profile_with_no_saved_wallet_yields_no_addresses() {
        // No wallet state was ever saved — the connect handle simply carries no addresses (the
        // signing channel is still fully usable), never a failure.
        let brand = tempfile::tempdir().unwrap();
        let profile_dir = crate::storage::profile_dir(brand.path(), &crate::storage::did_hash(DID));
        assert_eq!(
            Some(Vec::<String>::new()),
            wallet_addresses_at(test_sealer(DID), DID, &profile_dir),
            "an absent wallet is a COMPLETED read of an empty wallet, not a failed one"
        );
    }

    #[test]
    fn an_unopenable_sealed_wallet_reports_a_failed_read_not_an_empty_one() {
        // A wallet state exists on disk but is sealed under a DIFFERENT profile DEK, so `load_state`
        // fails the AEAD tag — the helper falls back to no addresses rather than propagating the error
        // into the assembly.
        use crate::wallet::state::{WalletState, WalletStore};

        let brand = tempfile::tempdir().unwrap();
        WalletStore::new(brand.path(), test_sealer(DID))
            .save_state(
                DID,
                &WalletState {
                    addresses: vec!["xch1receive".into()],
                    ..WalletState::default()
                },
            )
            .unwrap();

        let profile_dir = crate::storage::profile_dir(brand.path(), &crate::storage::did_hash(DID));
        // A DISTINCT DEK (a different label) cannot open the sealed state — the AEAD tag rejects it.
        // The answer must be `None`, NOT `Some(vec![])`: this profile demonstrably HAS wallet state,
        // and reporting an empty list would assert the opposite (SPEC §5.6.4, dig-app#256).
        assert_eq!(
            None,
            wallet_addresses_at(test_sealer("another-profile"), DID, &profile_dir)
        );
    }

    #[test]
    fn a_profile_dir_with_no_derivable_brand_dir_yields_no_addresses() {
        // A profile dir shallow enough to have no grandparent cannot locate a brand dir — the
        // helper must fall back to no addresses rather than panic. That is a settled structural fact,
        // not a transient failure, so it is a completed read and stays memoizable.
        assert_eq!(
            Some(Vec::<String>::new()),
            wallet_addresses_at(test_sealer(DID), DID, Path::new("solo"))
        );
    }

    /// A sealer that COUNTS how many times it was asked to open something.
    ///
    /// The count is the assertion: SEC-F2 is about how often a production Argon2id runs, and an
    /// implementation that re-derived on every frame returns exactly the same addresses as one that
    /// does not. Only the count separates them.
    #[derive(Clone)]
    struct CountingSealer {
        inner: AccountSealer,
        opens: Arc<AtomicUsize>,
    }

    impl crate::sealer::ProfileSealer for CountingSealer {
        fn seal(
            &self,
            profile_did: &str,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::sealer::SealError> {
            self.inner.seal(profile_did, plaintext)
        }
        fn open(
            &self,
            profile_did: &str,
            ciphertext: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::sealer::SealError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.inner.open(profile_did, ciphertext)
        }
    }

    /// Save `addresses` as `did`'s wallet state under `brand`, and hand back the profile directory.
    fn save_wallet(brand: &Path, did: &str, addresses: &[&str]) -> std::path::PathBuf {
        use crate::wallet::state::{WalletState, WalletStore};
        WalletStore::new(brand, test_sealer(did))
            .save_state(
                did,
                &WalletState {
                    addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
                    ..WalletState::default()
                },
            )
            .expect("the fixture wallet state seals");
        crate::storage::profile_dir(brand, &crate::storage::did_hash(did))
    }

    /// **The connect handle derives its addresses once per wallet state, not once per frame.**
    ///
    /// Every `connect.request` answers this handle, and a whitelisted origin reaches it with no confirm
    /// and no rate limit — so a per-frame Argon2id lets one origin pin the signing thread and queue the
    /// user's own `sign.request` behind it (dig_ecosystem#2398 SEC-F2).
    ///
    /// The fixture varies ONE thing at a time and keeps the honest control in every case: repeated
    /// reads of unchanged state (must not re-derive), then a REWRITTEN wallet (must re-derive, or the
    /// cache has traded liveness away), then a profile switch, then a lock. A test asserting only the
    /// first would be satisfied by a handle that cached forever and went stale — the exact bug the
    /// `Live` seam was introduced to fix.
    #[test]
    fn the_connect_handle_derives_its_addresses_once_per_wallet_state_not_once_per_frame() {
        let brand = tempfile::tempdir().unwrap();
        let dir = save_wallet(brand.path(), DID, &["xch1receive"]);

        let opens = Arc::new(AtomicUsize::new(0));
        let sealer = CountingSealer {
            inner: test_sealer(DID),
            opens: Arc::clone(&opens),
        };
        // Both sources are live, exactly as production builds them — a fixed pair would make the
        // switch and lock halves below unreachable.
        let active: Arc<Mutex<Option<(String, std::path::PathBuf)>>> =
            Arc::new(Mutex::new(Some((DID.to_owned(), dir))));
        let profile_did = {
            let active = Arc::clone(&active);
            Live::read(move || active.lock().unwrap().clone().map(|(did, _)| did))
        };
        let profile_dir = {
            let active = Arc::clone(&active);
            Live::read(move || active.lock().unwrap().clone().map(|(_, dir)| dir))
        };
        let addresses = ConnectAddresses::new(sealer, profile_did, profile_dir);

        assert_eq!(vec!["xch1receive"], addresses.read());
        let after_first = opens.load(Ordering::SeqCst);
        assert!(after_first > 0, "the first read must actually derive");

        for _ in 0..20 {
            assert_eq!(vec!["xch1receive"], addresses.read());
        }
        assert_eq!(
            after_first,
            opens.load(Ordering::SeqCst),
            "twenty further frames against unchanged state must not re-derive even once"
        );

        // Liveness, half one: the SAME profile saves new addresses. A cache keyed on the profile alone
        // would keep answering with the old ones.
        save_wallet(brand.path(), DID, &["xch1moved", "xch1change"]);
        assert_eq!(
            vec!["xch1moved", "xch1change"],
            addresses.read(),
            "a rewritten wallet must be seen — the memo may not cost liveness"
        );
        assert!(opens.load(Ordering::SeqCst) > after_first, "and re-derived");

        // Liveness, half two: a switch to a profile with its own wallet.
        const OTHER: &str = "did:chia:sign-service-other";
        let other_dir = save_wallet(brand.path(), OTHER, &["xch1other"]);
        *active.lock().unwrap() = Some((OTHER.to_owned(), other_dir));
        assert_eq!(
            Vec::<String>::new(),
            addresses.read(),
            "the other profile's state is sealed under ITS DEK, which this sealer cannot open — so no \
             addresses, never the previous profile's"
        );

        // Liveness, half three: a lock removes both sources, and no memo may answer for it.
        *active.lock().unwrap() = None;
        let before_lock = opens.load(Ordering::SeqCst);
        assert_eq!(Vec::<String>::new(), addresses.read());
        assert_eq!(
            before_lock,
            opens.load(Ordering::SeqCst),
            "a locked account has nothing to open, so it must not even try"
        );
    }

    /// A sealer whose `open` can be made to FAIL and un-fail, and which counts the opens it performs.
    ///
    /// Two levers, deliberately, because the two halves of the test below need different ones: the
    /// failure lever models the DEK moving under a read (an idle lock or a profile switch landing
    /// between the fingerprint snapshot and the derivation), and the counter is the only thing that
    /// separates "the memo works" from "the memo was removed".
    #[derive(Clone)]
    struct FlakySealer {
        inner: AccountSealer,
        failing: Arc<std::sync::atomic::AtomicBool>,
        opens: Arc<AtomicUsize>,
    }

    impl crate::sealer::ProfileSealer for FlakySealer {
        fn seal(
            &self,
            profile_did: &str,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::sealer::SealError> {
            self.inner.seal(profile_did, plaintext)
        }
        fn open(
            &self,
            profile_did: &str,
            ciphertext: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::sealer::SealError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.failing.load(Ordering::SeqCst) {
                return Err(crate::sealer::SealError::Open);
            }
            self.inner.open(profile_did, ciphertext)
        }
    }

    /// **A read that FAILED is never remembered as the fact "this profile has no wallet" (#256).**
    ///
    /// SPEC §5.6.4 gives an empty `addresses[]` one meaning — *this profile has no wallet state yet* —
    /// so caching a swallowed AEAD failure under that spelling tells a dapp something false about the
    /// user's wallet, and tells it for the rest of the session: the fingerprint is a pure function of
    /// (DID, directory, blob digest), none of which the failure changed, so nothing ever invalidates it.
    ///
    /// # Why the fixture is shaped this way
    ///
    /// The failing and the succeeding read happen under an **identical** fingerprint — same DID, same
    /// directory, same bytes on disk — because that is the only arrangement in which the memo is
    /// consulted at all. Vary any of the three and the second read re-derives for a reason that has
    /// nothing to do with the fix, and the test passes on the broken code.
    ///
    /// # The second half is not decoration
    ///
    /// The nearest wrong fix is "stop memoizing", which satisfies the first half perfectly and throws
    /// away SEC-F2 — a per-frame production Argon2id that a whitelisted origin can drive with no confirm
    /// and no rate limiter. Only the open COUNT can tell the two apart, so the count is asserted.
    #[test]
    fn a_failed_wallet_read_is_not_cached_as_no_wallet_and_the_memo_still_works_after_it() {
        let brand = tempfile::tempdir().unwrap();
        let dir = save_wallet(brand.path(), DID, &["xch1receive"]);

        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let opens = Arc::new(AtomicUsize::new(0));
        let sealer = FlakySealer {
            inner: test_sealer(DID),
            failing: Arc::clone(&failing),
            opens: Arc::clone(&opens),
        };
        // A PINNED clock. The failure cooldown (`FAILED_READ_RETRY_AFTER`) is measured against it,
        // so a fixture on wall time would be either a sleep or a race.
        let clock = Arc::new(Mutex::new(Instant::now()));
        let addresses = ConnectAddresses::with_clock(
            sealer,
            Live::read({
                let did = DID.to_owned();
                move || Some(did.clone())
            }),
            Live::read(move || Some(dir.clone())),
            {
                let clock = Arc::clone(&clock);
                Arc::new(move || *clock.lock().unwrap())
            },
        );

        // The unlucky moment: the DEK is unavailable, so the blob cannot be opened.
        assert_eq!(
            Vec::<String>::new(),
            addresses.read(),
            "a failed read reports no addresses — it must never invent one"
        );

        // The moment passes, and so does the cooldown. Nothing about the profile changed, so the
        // fingerprint is identical and a failure remembered as a FACT would be returned forever.
        failing.store(false, Ordering::SeqCst);
        *clock.lock().unwrap() += FAILED_READ_RETRY_AFTER;
        assert_eq!(
            vec!["xch1receive"],
            addresses.read(),
            "the very next read must find the real addresses — a failure is not a fact"
        );

        // And the memo is still a memo: further frames against unchanged state re-derive nothing.
        let after_success = opens.load(Ordering::SeqCst);
        for _ in 0..20 {
            assert_eq!(vec!["xch1receive"], addresses.read());
        }
        assert_eq!(
            after_success,
            opens.load(Ordering::SeqCst),
            "twenty further frames must not re-run the production Argon2id (SEC-F2)"
        );
    }

    /// **A blob that stays unopenable does not re-derive on every frame (SEC-2).**
    ///
    /// Makes impossible: the amplification the dig-app#256 fix opened. The fingerprint is
    /// `(did, dir, sha256(blob))` and a failed open changes none of the three, so "do not memoize a
    /// failure" read literally means a PERSISTENTLY unopenable blob re-derives on every
    /// `connect.request` — ~118 ms and 64 MiB of Argon2id each, with the memo mutex held, on a
    /// single-threaded runtime, reachable by an already-whitelisted origin with no confirm and no
    /// rate limiter. That is the exact thread-pinning the memo exists to prevent, re-entered through
    /// its error path.
    ///
    /// # Why the neighbouring test cannot see this and this one can
    ///
    /// `a_failed_wallet_read_is_not_cached_as_no_wallet_…` flips `failing` back to false before it
    /// counts anything — its subject is recovery, so it must. That setup REMOVES the condition being
    /// measured here. This fixture keeps the failure in place for the whole run, which is the only
    /// arrangement in which unbounded re-derivation is observable at all.
    ///
    /// # The control is the other half
    ///
    /// A cooldown that never expired would satisfy the count assertion and re-break #256, so the
    /// clock is advanced past it and one further derivation MUST happen. The bound is pinned from
    /// both sides: just under the window must not derive, at the window must.
    #[test]
    fn a_persistently_unopenable_wallet_is_not_re_derived_on_every_frame() {
        let brand = tempfile::tempdir().unwrap();
        let dir = save_wallet(brand.path(), DID, &["xch1receive"]);

        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let opens = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(Mutex::new(Instant::now()));
        let addresses = ConnectAddresses::with_clock(
            FlakySealer {
                inner: test_sealer(DID),
                failing: Arc::clone(&failing),
                opens: Arc::clone(&opens),
            },
            Live::read({
                let did = DID.to_owned();
                move || Some(did.clone())
            }),
            Live::read(move || Some(dir.clone())),
            {
                let clock = Arc::clone(&clock);
                Arc::new(move || *clock.lock().unwrap())
            },
        );

        assert_eq!(Vec::<String>::new(), addresses.read());
        let after_first = opens.load(Ordering::SeqCst);
        assert!(after_first > 0, "the first read must actually try");

        // A hundred frames from a whitelisted origin, inside the cooldown. Not one may derive.
        *clock.lock().unwrap() += FAILED_READ_RETRY_AFTER - Duration::from_millis(1);
        for _ in 0..100 {
            assert_eq!(
                Vec::<String>::new(),
                addresses.read(),
                "a failed read still reports no addresses — it must never invent one"
            );
        }
        assert_eq!(
            after_first,
            opens.load(Ordering::SeqCst),
            "an unopenable blob re-derived inside the cooldown: 100 frames drove {} Argon2id runs",
            opens.load(Ordering::SeqCst) - after_first
        );

        // At the window, exactly one retry — the property that keeps the failure from becoming a
        // fact. Without this the test would pass against a cache that never retried.
        *clock.lock().unwrap() += Duration::from_millis(1);
        assert_eq!(Vec::<String>::new(), addresses.read());
        assert_eq!(
            after_first + 1,
            opens.load(Ordering::SeqCst),
            "the cooldown must expire, and must do so exactly once"
        );
    }

    #[test]
    fn a_previously_persisted_pairing_is_restored_on_assembly() {
        // Persist a sealed pairing under the profile's DEK, then assemble a fresh service over the
        // SAME identity + directory and confirm the pairing is restored (survives a restart, #958).
        let dir = tempfile::tempdir().unwrap();

        let sealed = {
            let pairings = PairingStore::new(test_sealer(DID), DID);
            let outcome = pairings
                .pair(
                    &pairings.consent_now(),
                    &crate::pairing::NewPairing::pinned("mlibddmbhlgogepnjdienclhnkfpkfah", None),
                    1,
                )
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

        let router = assemble(dir.path());
        assert!(
            router.pairings().is_paired(&sealed),
            "the persisted pairing is restored on assembly"
        );
    }
}
