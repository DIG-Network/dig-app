//! The body a NEW profile is born holding, written down before the mint spends (dig_ecosystem#3073).
//!
//! # The loss this closes, and why it is worse than the edit one
//!
//! [`pending`](super::pending) closes the window on an EDIT: the root goes on chain and the bytes
//! are kept here until the node will take them. Creation has the same window and one extra hazard.
//! `ProfileSeedRequest::collected()` — what the wizard typed — lives in a process-wide holder that
//! does NOT survive a restart, and dig-account commits `seed.root()` into the store LAUNCH spend, so
//! a new profile's very first root is anchored on chain carrying that content. Close the app between
//! the launch landing and the body reaching a node and nothing on earth can produce the preimage:
//! the wizard's form is gone with the process, and [`recovery`](super::recovery) can rebuild only
//! `ProfileSeed::new()`, the EMPTY seed, which by construction does not hash to a root that carries
//! a person's name.
//!
//! So the seed body is written to disk BEFORE the ceremony starts — before any money moves, in the
//! same spirit as #3066's seal-before-spend — and [`recovery`](super::recovery) reads it back as a
//! rebuild candidate for the rest of that profile's life.
//!
//! # Why keeping a candidate forever is safe
//!
//! A candidate is never published on its own say-so.
//! [`seed_body_for`](super::recovery::seed_body_for) hands back bytes only when they VERIFY against
//! the root the chain anchors, so a stale, abandoned or simply wrong candidate is inert: it fails
//! the comparison and is skipped. Nothing here decides what is true —
//! it only widens the set of preimages the app is able to offer to that one check.
//!
//! # NC-2 / NC-3
//!
//! A seed body is the person's own content, so it is DIGOP1-sealed at rest like every other blob
//! this app persists. It is sealed under [`MINT_SEED_LABEL`] rather than a DID, because at the
//! moment it must be written the profile it belongs to does not exist yet — that is the entire
//! problem. The label cannot collide with a real profile: every DID this app seals under begins
//! `did:chia:`.

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use super::pending::PendingError;
use crate::sealer::ProfileSealer;
use crate::storage::seal_and_write;

/// The key label seed bodies are sealed under, standing in for the DID that does not exist yet.
///
/// Stable forever: changing it orphans every seed body already written, which is the loss this
/// module exists to prevent arriving by a different door.
pub const MINT_SEED_LABEL: &str = "dig-app:mint-seed";

/// Somewhere the bodies of seeds this app has minted from survive a restart.
///
/// A trait so the restart itself is drivable in a test — the process that writes a seed is, in the
/// case that matters, not the process that has to rebuild from it.
pub trait MintSeedBodies: Send + Sync {
    /// Write `body` down. Returns only once the bytes are on stable storage.
    fn remember(&self, body: &[u8]) -> Result<(), PendingError>;

    /// Every seed body this app could have minted from, most recent last.
    fn all(&self) -> Result<Vec<Vec<u8>>, PendingError>;
}

/// The real store: one sealed file in the brand data directory.
///
/// Brand-level and not per-profile, because a seed body is written before the profile it belongs to
/// has a DID to key a directory by.
pub struct SealedMintSeeds<S> {
    /// The file the sealed set lives in.
    path: PathBuf,
    /// The sealing seam.
    sealer: Arc<S>,
}

impl<S: ProfileSealer> SealedMintSeeds<S> {
    /// The seed set kept at `path`.
    pub fn new(path: PathBuf, sealer: Arc<S>) -> Self {
        Self { path, sealer }
    }

    /// The file name the set is kept under.
    pub const FILE_NAME: &'static str = "mint-seed-bodies.seal";

    /// Persist `bodies`, replacing whatever was there.
    fn write(&self, bodies: &[Vec<u8>]) -> Result<(), PendingError> {
        let encoded: Vec<String> = bodies.iter().map(|body| BASE64.encode(body)).collect();
        let json = serde_json::to_vec(&encoded)
            .map_err(|e| PendingError::Unreadable(format!("could not encode: {e}")))?;
        seal_and_write(&*self.sealer, MINT_SEED_LABEL, &self.path, &json)
            .map_err(|e| PendingError::Sealed(e.to_string()))
    }
}

impl<S: ProfileSealer + Send + Sync> MintSeedBodies for SealedMintSeeds<S> {
    fn remember(&self, body: &[u8]) -> Result<(), PendingError> {
        let mut bodies = self.all()?;
        // The same seed twice is one entry: a retried ceremony rebuilds the same commitment on
        // purpose, and a set that grew on every attempt would be a file that only ever gets bigger.
        if bodies.iter().any(|held| held == body) {
            return Ok(());
        }
        bodies.push(body.to_vec());
        self.write(&bodies)
    }

    fn all(&self) -> Result<Vec<Vec<u8>>, PendingError> {
        let sealed = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            // No file is an empty set: the ordinary state of a machine that has never minted.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PendingError::Io(e.to_string())),
        };
        let plain = self
            .sealer
            .open(MINT_SEED_LABEL, &sealed)
            .map_err(|e| PendingError::Sealed(e.to_string()))?;
        let encoded: Vec<String> = serde_json::from_slice(&plain)
            .map_err(|e| PendingError::Unreadable(format!("not a seed set: {e}")))?;
        encoded
            .into_iter()
            .map(|text| {
                BASE64
                    .decode(text.as_bytes())
                    .map_err(|e| PendingError::Unreadable(format!("not base64: {e}")))
            })
            .collect()
    }
}

/// A seed set held in memory, for builds and galleries that have no sealed storage.
///
/// Honest about what it is: nothing in it survives a restart, so it belongs only where nothing is
/// ever minted for real.
#[derive(Debug, Default)]
pub struct MemoryMintSeeds {
    /// What it holds.
    bodies: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl MintSeedBodies for MemoryMintSeeds {
    fn remember(&self, body: &[u8]) -> Result<(), PendingError> {
        let mut bodies = self.bodies.lock().expect("mint seeds");
        if !bodies.iter().any(|held| held == body) {
            bodies.push(body.to_vec());
        }
        Ok(())
    }

    fn all(&self) -> Result<Vec<Vec<u8>>, PendingError> {
        Ok(self.bodies.lock().expect("mint seeds").clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::sealer::SealError;
    use zeroize::Zeroizing;

    /// A body with a person's name in it — the case an empty seed can never stand in for.
    fn a_seed_body() -> Vec<u8> {
        b"DIGP\x01display-name=ada".to_vec()
    }

    /// The label a blob was sealed under, and the plaintext it holds.
    type SealedUnder = (String, Vec<u8>);

    /// A sealer that is a real AEAD in the one respect these tests depend on: bytes sealed under one
    /// label do not open under another, and the ciphertext is not the plaintext.
    #[derive(Default)]
    struct LabelKeyedSealer {
        /// Ciphertext handed out, by the label it was sealed under.
        vault: Mutex<HashMap<Vec<u8>, SealedUnder>>,
    }

    impl ProfileSealer for LabelKeyedSealer {
        fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
            let token: Vec<u8> = format!("sealed:{}:{}", label, plaintext.len()).into_bytes();
            self.vault
                .lock()
                .expect("vault")
                .insert(token.clone(), (label.to_string(), plaintext.to_vec()));
            Ok(token)
        }

        fn open(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            match self.vault.lock().expect("vault").get(ciphertext) {
                Some((sealed_for, plain)) if sealed_for == label => {
                    Ok(Zeroizing::new(plain.clone()))
                }
                _ => Err(SealError::Open),
            }
        }
    }

    /// **The restart.** A seed written before a mint is readable by a DIFFERENT process afterwards.
    ///
    /// The reader shares nothing with the writer but the path and the key, which is exactly what a
    /// second launch of dig-app shares with the first. The nearest wrong implementation keeps the
    /// set in memory and writes the file as a courtesy — it passes every test that asks the SAME
    /// object what it holds, and loses the one thing a restart was supposed to save.
    #[test]
    fn a_seed_written_before_the_mint_is_still_there_after_a_restart() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir
            .path()
            .join(SealedMintSeeds::<LabelKeyedSealer>::FILE_NAME);
        let sealer = Arc::new(LabelKeyedSealer::default());

        {
            let before_the_crash = SealedMintSeeds::new(path.clone(), sealer.clone());
            before_the_crash
                .remember(&a_seed_body())
                .expect("remembers");
        } // and the process ends here, with the launch spend already on its way.

        let after_the_restart = SealedMintSeeds::new(path, sealer);
        assert_eq!(
            after_the_restart.all().expect("reads"),
            vec![a_seed_body()],
            "the wizard's content did not survive the restart, so its anchored root has no preimage"
        );
    }

    /// The bytes on disk are ciphertext, and they do not open under another key (NC-2).
    #[test]
    fn a_seed_body_is_sealed_at_rest() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("seeds.seal");
        let sealer = Arc::new(LabelKeyedSealer::default());

        SealedMintSeeds::new(path.clone(), sealer.clone())
            .remember(&a_seed_body())
            .expect("remembers");

        let on_disk = std::fs::read(&path).expect("the file exists");
        assert!(
            !on_disk.windows(4).any(|window| window == b"DIGP"),
            "the profile body is on disk in the clear"
        );

        struct OtherLabel(Arc<LabelKeyedSealer>);
        impl ProfileSealer for OtherLabel {
            fn seal(&self, _: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
                self.0.seal("someone-else", plaintext)
            }
            fn open(&self, _: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
                self.0.open("someone-else", ciphertext)
            }
        }
        assert!(
            SealedMintSeeds::new(path, Arc::new(OtherLabel(sealer)))
                .all()
                .is_err(),
            "another key opened this account's seed bodies"
        );
    }

    /// Two different seeds are both kept: a person may abandon one creation and start another, and
    /// the abandoned one's root can still be sitting on chain.
    #[test]
    fn two_different_seeds_are_both_kept_and_a_repeat_is_one_entry() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = SealedMintSeeds::new(
            dir.path().join("seeds.seal"),
            Arc::new(LabelKeyedSealer::default()),
        );
        store.remember(&a_seed_body()).expect("first");
        store.remember(&a_seed_body()).expect("the same one again");
        store
            .remember(b"DIGP\x01display-name=grace")
            .expect("second");

        assert_eq!(
            store.all().expect("reads"),
            vec![a_seed_body(), b"DIGP\x01display-name=grace".to_vec()],
        );
    }
}
