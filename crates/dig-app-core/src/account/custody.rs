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
//! | 2 | OS credential store (`OsKeychainBackend`) | **no** — see below |
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

/// A composition whose indeterminate-probe verdict has **not been settled yet**.
///
/// [`compose`] settles that verdict from an intent the caller worked out beforehand, which is right
/// for a caller that already KNOWS its intent — a migration reseal knows it is sealing. It is wrong
/// for a caller whose intent is decided by READING the custody root, because working the intent out
/// beforehand means composing once to read and once to use: two observations of one predicate, with
/// a window between them (dig-app#338 S-1). Such a caller takes this instead, probes the host
/// **once**, and settles the verdict from a presence read taken through the very backend that read
/// settles.
pub enum Composition {
    /// The probe answered. Both intents compose identically from here, so there is nothing left to
    /// settle and the caller simply uses this backend.
    Settled(HardwareBoundBackend),

    /// The host's trusted component could not be inspected, so the verdict depends on what the
    /// caller is about to do.
    ///
    /// `opened` is what [`CustodyIntent::Opening`] yields and is safe to READ through: a blob that
    /// IS hardware-bound refuses it ([`KeystoreError::NotHardwareBound`]) rather than handing back
    /// ciphertext. Whether it may be SEALED into is [`CustodyIntent::Sealing`]'s question, and only
    /// the caller's own read of the custody root answers that.
    Undecided {
        /// The passphrase-envelope floor, carrying the indeterminate reason.
        opened: HardwareBoundBackend,
        /// Why the host could not be inspected, so a refusal can name it.
        detail: String,
    },
}

/// Compose the custody backend for the account keystore rooted at `dir`, leaving an indeterminate
/// probe **undecided** for the caller to settle.
///
/// The one probe of the host happens here. A caller that needs the custody root's own contents to
/// choose its intent must take this, so that its presence read and its composition are one
/// observation rather than two.
///
/// # Errors
///
/// Every failure to compose except [`KeystoreError::HardwareProbeIndeterminate`], which is returned
/// as [`Composition::Undecided`] rather than as an error, because it is not this function's to
/// decide.
pub fn compose_undecided(
    dir: PathBuf,
    candidates: Candidates<'_>,
) -> Result<Composition, KeystoreError> {
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
        Ok(backend) => Ok(Composition::Settled(backend)),
        // The ONE refusal this app answers for itself. Every other error is a genuine failure to
        // compose and is propagated unchanged.
        Err(KeystoreError::HardwareProbeIndeterminate { detail }) => Ok(Composition::Undecided {
            // Rebuilt rather than reused: `bind_strongest*` consumes `inner`, and the path is the
            // whole of a `FileBackend`'s identity, so a second one over the same directory is the
            // same backend. Building it here is free of side effects — `FileBackend` creates its
            // directory lazily on the first write — so a caller that goes on to REFUSE has not
            // touched the host.
            opened: HardwareBoundBackend::degraded(
                FileBackend::new(dir),
                DegradeReason::ProbeIndeterminate {
                    detail: detail.clone(),
                },
            ),
            detail,
        }),
        Err(e) => Err(e),
    }
}

/// Compose the custody backend for the account keystore rooted at `dir`, for a caller whose `intent`
/// is already known.
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
    match compose_undecided(dir, candidates)? {
        Composition::Settled(backend) => Ok(backend),
        Composition::Undecided { opened, detail } => match intent {
            CustodyIntent::Sealing => Err(KeystoreError::HardwareProbeIndeterminate { detail }),
            CustodyIntent::Opening => {
                tracing::warn!(
                    detail = %detail,
                    concat!(
                        "could not determine whether this host has a hardware trusted component; ",
                        "opening the existing keystore on the passphrase envelope alone. A key ",
                        "that IS hardware-bound still refuses to open, so this cannot weaken one."
                    )
                );
                Ok(opened)
            }
        },
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

    /// The composition running against **this host's real trusted component** — which nothing else in
    /// this module does. Every fixture above injects a [`FakeDevice`], so until this test dig-app had
    /// never once observed what [`Candidates::Platform`] actually resolves to on a real machine.
    ///
    /// # It asserts an implication, so it is meaningful on every runner
    ///
    /// The tier legitimately differs per host, so a fixed expectation would either fail on ordinary CI
    /// or assert nothing on TPM silicon. Instead: *if* this host resolved hardware, the bytes at rest
    /// MUST carry the envelope and MUST refuse to open without the wrapping key; *if* it did not, the
    /// floor MUST be byte-for-byte what a bare `FileBackend` writes. Both halves are checkable
    /// everywhere and neither is satisfied by doing nothing.
    ///
    /// The hardware half's anchor is the **`DIGHW1` magic read back off the file**, and
    /// [`HardwareBoundBackend::blob_tier`] is asserted beside it because it is a SECOND independent
    /// reading of the same bytes, not a restatement of `tier()`: `blob_tier` re-reads the file and
    /// answers `Software(BlobNotWrapped)` when the bytes carry no envelope, so it disagrees with a
    /// `Hardware(..)` `tier()` exactly when wrapping has silently stopped. That is the distinction
    /// SPEC.md makes normative — `blob_tier()` is a claim about THIS key, `tier()` a claim about the
    /// HOST — and the two are never interchangeable.
    ///
    /// # The second-machine half, and what it honestly is
    ///
    /// dig-app#287 asks that the blob be *refused on a second machine*. **There are two kinds of
    /// second machine, and this test covers only the first.** One with NO trusted component holds no
    /// provider at all, and is modelled here by reading the very same stored bytes through a
    /// provider-less composition, which must fail [`KeystoreError::NotHardwareBound`] rather than hand
    /// back ciphertext.
    ///
    /// A second machine that has its OWN TPM takes a different arm entirely — it holds a provider, so
    /// the read reaches the unwrap and fails [`KeystoreError::HardwareUnwrapFailed`] under a wrapping
    /// key that is not the sealing one. That arm cannot be reached from the real platform composition,
    /// because a test cannot give this host a second machine's TPM; it is covered on every runner by
    /// [`a_second_machine_with_its_own_hardware_cannot_open_this_ones_blob`].
    ///
    /// [`CustodyIntent::Opening`] rather than `Sealing`, so a host whose probe is *indeterminate*
    /// reports that honestly instead of failing: an uninspectable runner is a fact about the runner,
    /// not a defect in the composition.
    #[test]
    fn the_real_platform_composition_wraps_at_rest_or_reports_that_it_cannot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = BackendKey::new("account-default");
        let blob = b"DIGOP1-shaped bytes standing in for the sealed master seed";

        let backend = compose(
            dir.path().to_path_buf(),
            CustodyIntent::Opening,
            Candidates::Platform,
        )
        .expect("the real platform composition must always compose under Opening");

        // Captured BEFORE the write, so the branch taken below is decided by what the host resolved
        // rather than by anything the write itself produced.
        let host = backend.tier().clone();

        // ALWAYS ON, and it is the real guard. `Candidates::Platform` routes through
        // `bind_strongest`, which reports `PlatformUnsupported` — "this build could not ask" — for a
        // platform it ships no provider for. `NotRequested` is the caller-shaped reason an EMPTY
        // candidate list settles on, so correct code cannot produce it here on any host. A regression
        // that stops asking the platform for hardware is therefore caught on every runner, including
        // one with no trusted component, without anyone remembering to set an env var.
        assert!(
            !matches!(host, ProtectionTier::Software(DegradeReason::NotRequested)),
            "Candidates::Platform must never settle on the caller-shaped NotRequested; \
             that reason means the composition stopped asking the platform at all"
        );

        // Belt and braces for a run on known silicon. The assertion above catches a composition that
        // stopped asking; this catches a host that was asked and, contrary to the operator's
        // knowledge, did not answer with hardware — which the implication below would otherwise
        // record as the unremarkable software branch.
        if std::env::var_os("DIG_REQUIRE_HARDWARE_TIER").is_some() {
            assert!(
                matches!(host, ProtectionTier::Hardware(_)),
                "DIG_REQUIRE_HARDWARE_TIER asserts this host resolves a trusted component, \
                 but the composition settled on {host:?}"
            );
        }
        backend
            .write(&key, blob)
            .expect("writes through the composition");
        let stored = read_only_file(dir.path());

        match &host {
            ProtectionTier::Hardware(kind) => {
                assert_eq!(
                    stored.get(..6),
                    Some(&b"DIGHW1"[..]),
                    "a host that resolved {kind} must wrap the bytes at rest"
                );
                assert_eq!(
                    backend.blob_tier(&key).expect("classify the stored blob"),
                    ProtectionTier::Hardware(*kind),
                    "the stored blob must classify as the hardware the host resolved"
                );

                let elsewhere = HardwareBoundBackend::degraded(
                    FileBackend::new(dir.path().to_path_buf()),
                    DegradeReason::NoHardwarePresent,
                );
                let refused = elsewhere.read(&key);
                // The Ok payload is never rendered: on the branch that fails this assertion it is
                // precisely the plaintext the backend was supposed to refuse to hand back.
                let observed = match &refused {
                    Ok(_) => "Ok(plaintext handed back)".to_owned(),
                    Err(e) => format!("Err({e})"),
                };
                assert!(
                    matches!(refused, Err(KeystoreError::NotHardwareBound { .. })),
                    "the same bytes must be REFUSED without the wrapping key, got {observed}"
                );

                eprintln!("EXERCISED: this host bound the stored blob to {kind}");
            }
            ProtectionTier::Software(reason) => {
                assert_eq!(
                    stored, blob,
                    "with no usable trusted component the floor must stay byte-identical"
                );
                eprintln!("NOT EXERCISED: no usable trusted component on this host ({reason:?})");
            }
        }
    }

    /// The **other** kind of second machine: one that has its own working trusted component.
    ///
    /// This is the case dig-app#287's acceptance bar actually describes, and the one the real-platform
    /// test structurally cannot reach. It matters because the two fail through different arms of
    /// `HardwareBoundBackend::read`, and only this one depends on the wrapping key being unreachable:
    ///
    /// - no trusted component -> `provider` is `None` -> [`KeystoreError::NotHardwareBound`], a
    ///   refusal that says "I hold no provider" and would hold even if the sealing key were freely
    ///   exportable;
    /// - its own trusted component -> `provider` is `Some` -> the unwrap runs against a DIFFERENT
    ///   device key and must fail [`KeystoreError::HardwareUnwrapFailed`].
    ///
    /// Two [`FakeDevice`]s with different `device_id`s are the crate's own idiom for two machines, so
    /// this runs on every runner rather than only on silicon.
    #[test]
    fn a_second_machine_with_its_own_hardware_cannot_open_this_ones_blob() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = BackendKey::new("account-default");
        let blob = b"DIGOP1-shaped bytes standing in for the sealed master seed";

        let sealing = vec![Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 1))
            as Arc<dyn HardwareProvider>];
        let here = compose(
            dir.path().to_path_buf(),
            CustodyIntent::Sealing,
            Candidates::Injected(&sealing),
        )
        .expect("a working device composes");
        assert_eq!(
            here.tier(),
            &ProtectionTier::Hardware(HardwareKind::WindowsTpm20),
            "the fixture must actually be seated on hardware, or the refusal below proves nothing"
        );
        here.write(&key, blob)
            .expect("writes through the composition");
        assert_eq!(
            read_only_file(dir.path()).get(..6),
            Some(&b"DIGHW1"[..]),
            "the sealing machine must have wrapped the bytes at rest"
        );

        // Same directory, same bytes, a different machine's device key.
        let other = vec![Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 2))
            as Arc<dyn HardwareProvider>];
        let elsewhere = compose(
            dir.path().to_path_buf(),
            CustodyIntent::Opening,
            Candidates::Injected(&other),
        )
        .expect("the second machine composes on its own hardware");

        let refused = elsewhere.read(&key);
        // Never rendered on the failing branch: that payload is precisely the master-seed plaintext
        // the backend was supposed to refuse to hand a second machine.
        let observed = match &refused {
            Ok(_) => "Ok(plaintext handed back)".to_owned(),
            Err(e) => format!("Err({e})"),
        };
        assert!(
            matches!(refused, Err(KeystoreError::HardwareUnwrapFailed { .. })),
            "a second machine's own hardware must not open this machine's blob, got {observed}"
        );
    }

    /// The single file written under `dir`, read raw. Panics unless exactly one exists, so a layout
    /// change cannot make this assertion quietly compare nothing.
    fn read_only_file(dir: &std::path::Path) -> Vec<u8> {
        let mut found = Vec::new();
        collect(dir, &mut found);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one stored blob in {dir:?}"
        );
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
