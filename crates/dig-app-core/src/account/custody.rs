//! Where the app decides **what protects the master seed at rest**, and how honestly it may degrade.
//!
//! dig-keystore ships the [`HardwareBoundBackend`] envelope and dig-keystore-hardware ships the
//! platform FFI that fills it. Neither decides what dig-app should do when the host cannot answer —
//! that decision is this module, and it is the whole reason the module exists rather than the four
//! call sites in [`boot`](super::boot) each calling `bind_strongest` inline.
//!
//! # The ladder this app composes, and the rung it deliberately does not take
//!
//! | rung | what | taken here |
//! |---|---|---|
//! | 1 | host trusted component, non-exportable wrapping key | **yes** — the outer `DIGHW1` envelope |
//! | 2 | OS credential store ([`dig_keystore::OsKeychainBackend`]) | **no** — see below |
//! | 3 | AES-256-GCM + Argon2id passphrase envelope (`DIGOP1`) | **yes** — the floor, never skipped |
//!
//! **Rung 2 is not taken, and that is a decision rather than an oversight.** `inner` stays the same
//! per-user [`FileBackend`] the app has always written, at the same path. Swapping it for
//! `OsKeychainBackend` would move every existing account's custody root into the credential store,
//! which is a data migration with its own recovery story — a strictly larger and separately-gated
//! change than adding an outer envelope. Composing here changes exactly one thing: on a host with a
//! working trusted component, newly-written bytes gain the `DIGHW1` wrapper. On a host without one,
//! the bytes written are **byte-identical** to what was written before, because a provider-less
//! [`HardwareBoundBackend`] passes `write` straight through to `inner`.
//!
//! # Why the policy is `Preferred`, and why that alone would brick a Mac
//!
//! [`HardwarePolicy::Preferred`] degrades on a *confident* absence and **errors** on an
//! [`Indeterminate`](dig_keystore::hardware::HardwareProbe::Indeterminate) probe. That refusal is
//! right when a brand-new seed is about to be sealed: downgrading "I could not tell" into "there is
//! none" is how a transient probe failure silently writes a wallet that opens on any machine.
//!
//! It is **wrong when opening a keystore that already exists**. Refusing there protects nothing — the
//! blob at rest is whatever it already is, and no probe result changes it — while costing the user
//! every key they own. An adoption that applied `Preferred` uniformly could not open a wallet at all
//! on a host whose probe is indeterminate.
//!
//! So the policy is applied per [`CustodyIntent`], and the fallback is safe for a reason that is
//! checked rather than assumed: a degraded [`HardwareBoundBackend`] **refuses** a blob that carries a
//! hardware envelope ([`KeystoreError::NotHardwareBound`]) instead of handing back ciphertext. Falling
//! back therefore cannot weaken a key that IS hardware-bound; it can only avoid bricking one that is
//! not.
//!
//! # What this module does not do
//!
//! It never calls [`HardwareBoundBackend::bind`]. Binding rewrites a live master seed in place and is
//! irreversible once the hardware is gone, so no code path here migrates an at-rest blob. An existing
//! software-tier keystore stays software-tier until something rewrites it through a composed backend
//! on a hardware-capable host.

use std::path::PathBuf;
use std::sync::Arc;

use dig_keystore::hardware::{
    DegradeReason, HardwareBoundBackend, HardwarePolicy, HardwareProvider,
};
use dig_keystore::KeystoreError;
use dig_session::FileBackend;

/// Why a custody backend is being composed — the input that decides what an unanswerable hardware
/// probe means.
///
/// Two values rather than a `bool` because the names are the argument: `Sealing` and `Opening` read at
/// the call site as the question the policy actually turns on, where `strict: true` would not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyIntent {
    /// A master seed is about to be written for the first time.
    ///
    /// An indeterminate probe **refuses**. Nothing is stranded by that refusal — no account exists yet
    /// — and sealing a fresh seed under a protection tier nobody could establish is the downgrade
    /// [`HardwarePolicy::Preferred`] exists to prevent.
    Sealing,

    /// A keystore that already exists is being read, unlocked, probed for existence, or deleted.
    ///
    /// An indeterminate probe **degrades**, carrying the reason. The blob's own protection is already
    /// fixed on disk; refusing here would lock the owner out of their own keys to defend a property
    /// the refusal cannot affect.
    Opening,
}

/// The hardware-binding candidates to walk.
///
/// The injection seam that makes every decision in this module testable on a CI runner with no
/// trusted component — which is every CI runner this ecosystem has.
pub enum Candidates<'a> {
    /// Walk the real providers this build ships for the host platform.
    ///
    /// Routed through [`dig_keystore_hardware::bind_strongest`] rather than
    /// [`bind_strongest_from`](dig_keystore_hardware::bind_strongest_from) so that a platform with no
    /// provider reports [`DegradeReason::PlatformUnsupported`] — "this build could not ask" — instead
    /// of the caller-shaped `NotRequested` an empty candidate list would settle on.
    Platform,

    /// Walk exactly these, for tests and for a consumer injecting a provider this build does not ship.
    Injected(&'a [Arc<dyn HardwareProvider>]),
}

/// Compose the custody backend for the account keystore rooted at `dir`.
///
/// # Errors
///
/// [`KeystoreError::HardwareProbeIndeterminate`] under [`CustodyIntent::Sealing`] when the host's
/// trusted component could not be inspected. Every other outcome — no hardware, unusable hardware, an
/// unsupported platform — degrades to the passphrase-envelope floor and reports the reason through
/// [`HardwareBoundBackend::tier`].
pub fn compose(
    dir: PathBuf,
    intent: CustodyIntent,
    candidates: Candidates<'_>,
) -> Result<HardwareBoundBackend, KeystoreError> {
    let bound = match candidates {
        Candidates::Platform => dig_keystore_hardware::bind_strongest(
            FileBackend::new(dir.clone()),
            HardwarePolicy::Preferred,
        ),
        Candidates::Injected(list) => dig_keystore_hardware::bind_strongest_from(
            FileBackend::new(dir.clone()),
            list,
            HardwarePolicy::Preferred,
        ),
    };

    match bound {
        Ok(backend) => Ok(backend),
        // The ONE refusal this app answers for itself. Every other error is a genuine failure to
        // compose and is propagated unchanged.
        Err(KeystoreError::HardwareProbeIndeterminate { detail }) => match intent {
            CustodyIntent::Sealing => {
                Err(KeystoreError::HardwareProbeIndeterminate { detail })
            }
            CustodyIntent::Opening => {
                tracing::warn!(
                    detail = %detail,
                    concat!(
                        "could not determine whether this host has a hardware trusted component; ",
                        "opening the existing keystore on the passphrase envelope alone. A key ",
                        "that IS hardware-bound still refuses to open, so this cannot weaken one."
                    )
                );
                // Rebuilt rather than reused: `bind_strongest*` consumes `inner`, and the path is the
                // whole of a `FileBackend`'s identity, so a second one over the same directory is the
                // same backend.
                Ok(HardwareBoundBackend::degraded(
                    FileBackend::new(dir),
                    DegradeReason::ProbeIndeterminate { detail },
                ))
            }
        },
        Err(e) => Err(e),
    }
}

/// [`compose`] over the real platform providers, as an `Arc<dyn KeychainBackend>` ready for
/// [`account_store`](super::lifecycle::account_store).
///
/// # Errors
///
/// As [`compose`].
pub fn account_backend(
    dir: PathBuf,
    intent: CustodyIntent,
) -> Result<Arc<dyn dig_session::KeychainBackend>, KeystoreError> {
    Ok(Arc::new(compose(dir, intent, Candidates::Platform)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::hardware::double::FakeDevice;
    use dig_keystore::hardware::{HardwareKind, ProtectionTier};
    use dig_keystore::{BackendKey, KeychainBackend};

    fn indeterminate() -> Vec<Arc<dyn HardwareProvider>> {
        vec![Arc::new(FakeDevice::indeterminate(
            HardwareKind::WindowsTpm20,
            "the platform crypto provider did not answer",
        ))]
    }

    fn absent() -> Vec<Arc<dyn HardwareProvider>> {
        vec![Arc::new(FakeDevice::absent(HardwareKind::WindowsTpm20))]
    }

    /// The decision this module exists for: ONE probe outcome, TWO intents, TWO different observable
    /// results.
    ///
    /// A test that only asserted the `Opening` half would pass just as happily against a
    /// degrade-always adoption, and a test that only asserted the `Sealing` half would pass against a
    /// uniform `Preferred` — the exact adoption that cannot open a wallet on a Mac. Only the pair
    /// distinguishes this implementation from both of its nearest wrong neighbours, so they are
    /// asserted together in one test.
    #[test]
    fn an_indeterminate_probe_refuses_a_seal_and_permits_an_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let providers = indeterminate();

        let sealing = compose(
            dir.path().to_path_buf(),
            CustodyIntent::Sealing,
            Candidates::Injected(&providers),
        );
        assert!(
            matches!(
                sealing,
                Err(KeystoreError::HardwareProbeIndeterminate { .. })
            ),
            "sealing a fresh seed under an uninspectable host must refuse, got {sealing:?}"
        );

        let opening = compose(
            dir.path().to_path_buf(),
            CustodyIntent::Opening,
            Candidates::Injected(&providers),
        )
        .expect("an existing keystore must still open when the probe cannot answer");
        assert_eq!(
            opening.tier(),
            &ProtectionTier::Software(DegradeReason::ProbeIndeterminate {
                detail: "the platform crypto provider did not answer".to_owned(),
            }),
            "the degrade must carry the indeterminate reason, not a confident absence"
        );
    }

    /// A *confident* absence is not the indeterminate case and must not borrow its refusal: both
    /// intents open, and both report `NoHardwarePresent`.
    ///
    /// This is the control for the test above. Without it, an implementation that refused `Sealing`
    /// on every non-hardware outcome would pass there while making first-run setup impossible on
    /// every machine without a TPM.
    #[test]
    fn a_confident_absence_seals_and_opens_alike() {
        let dir = tempfile::tempdir().expect("temp dir");
        let providers = absent();

        for intent in [CustodyIntent::Sealing, CustodyIntent::Opening] {
            let backend = compose(
                dir.path().to_path_buf(),
                intent,
                Candidates::Injected(&providers),
            )
            .unwrap_or_else(|e| panic!("a host with no hardware must compose for {intent:?}: {e}"));
            assert_eq!(
                backend.tier(),
                &ProtectionTier::Software(DegradeReason::NoHardwarePresent),
                "{intent:?} must report the confident absence it actually observed"
            );
        }
    }

    /// The at-rest guarantee #287 asks for, asserted on the **stored bytes** rather than a round-trip.
    ///
    /// A round-trip cannot see this: a composed backend and a bare `FileBackend` both return what they
    /// were given, so a read-back is satisfied by any storage at all. Reading the file the backend
    /// wrote is what proves the floor was not changed.
    #[test]
    fn a_host_with_no_hardware_writes_the_same_bytes_a_bare_file_backend_writes() {
        let composed_dir = tempfile::tempdir().expect("temp dir");
        let bare_dir = tempfile::tempdir().expect("temp dir");
        let providers = absent();
        let key = BackendKey::new("account-default");
        let blob = b"DIGOP1-shaped bytes that must cross unchanged";

        compose(
            composed_dir.path().to_path_buf(),
            CustodyIntent::Sealing,
            Candidates::Injected(&providers),
        )
        .expect("composes")
        .write(&key, blob)
        .expect("writes");
        FileBackend::new(bare_dir.path().to_path_buf())
            .write(&key, blob)
            .expect("writes");

        let composed = read_only_file(composed_dir.path());
        let bare = read_only_file(bare_dir.path());
        assert_eq!(
            composed, bare,
            "a provider-less composition must add no envelope to the stored bytes"
        );
        assert_eq!(composed, blob, "and the floor's bytes are the blob itself");
    }

    /// The single file written under `dir`, read raw. Panics unless exactly one exists, so a layout
    /// change cannot make this assertion quietly compare nothing.
    fn read_only_file(dir: &std::path::Path) -> Vec<u8> {
        let mut found = Vec::new();
        collect(dir, &mut found);
        assert_eq!(found.len(), 1, "expected exactly one stored blob in {dir:?}");
        std::fs::read(&found[0]).expect("read the stored blob")
    }

    fn collect(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}
