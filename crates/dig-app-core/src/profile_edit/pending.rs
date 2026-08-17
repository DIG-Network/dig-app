//! The bytes a chain root commits to, kept on this computer until the node will take them.
//!
//! # The loss this file exists to prevent (dig_ecosystem#3066)
//!
//! A profile edit anchors a new SMT root on chain. The body that root commits to lives off chain,
//! and the node REFUSES to store it until the chain confirms the root — correctly, because a node
//! that stored unanchored bodies would serve content nobody can verify. So there is a window,
//! minutes long on mainnet, in which the root is committed FOREVER and its preimage exists only in
//! this app's memory. Close the window in that window and the profile is unreadable for all time:
//! no peer, no node and no reinstall can produce bytes that hash to a root nobody kept.
//!
//! That was measured live on 12.13.0. The remedy is not to relax the node — it is to write the
//! bytes down here, BEFORE the spend goes out, and keep them until the node has them.
//!
//! # Why "before the spend" and not "on failure"
//!
//! The window opens the moment the bundle reaches a mempool, and a crash, a power cut or a closed
//! window between the push and the app noticing is exactly the case that loses everything. A write
//! that happens after the push — or only when `putBody` refuses — is a write that is not there for
//! the crash it exists to survive.
//!
//! # NC-2 / NC-3
//!
//! A pending body is the person's own profile content, so it lives in the per-profile AppData
//! directory ([`crate::storage`]) and is DIGOP1-sealed to their key through [`ProfileSealer`] like
//! every other blob this app persists. Nothing new was invented for it.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::bodies::{BodyRead, BodyStore};
use crate::sealer::ProfileSealer;
use crate::storage::seal_and_write;

/// A body that is committed to chain and not yet held by the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingBody {
    /// The store the profile lives in, lowercase 64-hex.
    pub store_id: String,
    /// The root these bytes commit to, lowercase 64-hex.
    pub root: String,
    /// The bytes themselves, base64 on disk so the sealed blob stays plain JSON.
    #[serde(with = "body_b64")]
    pub body: Vec<u8>,
}

/// Base64 for the body, so a pending file can be read by eye when one has the key.
mod body_b64 {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Encode the bytes.
    pub fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_str(&BASE64.encode(bytes))
    }

    /// Decode them back.
    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(input)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Why a pending body could not be written down or read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingError {
    /// The account is locked, or the blob could not be sealed or opened.
    Sealed(String),
    /// The file could not be read or written.
    Io(String),
    /// The file was opened and its contents are not a pending set.
    Unreadable(String),
}

/// A clause a caller can drop into a sentence of its own, in a person's language.
///
/// Deliberately NOT [`PendingError::sentence`]: that is a whole standalone sentence, ending in its
/// own advice, and nesting it inside another caller's sentence reads as two sentences collided.
/// Callers that own the framing — the profile-creation path says what it was trying to save — need
/// only the cause, so this renders the cause alone, with no leading capital and no full stop.
impl std::fmt::Display for PendingError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sealed(why) => {
                write!(out, "your account is locked, or the details could not be secured for storage ({why})")
            }
            Self::Io(why) => write!(out, "the disk could not be read from or written to ({why})"),
            Self::Unreadable(why) => {
                write!(
                    out,
                    "the saved file was not in a form DIG could understand ({why})"
                )
            }
        }
    }
}

impl std::error::Error for PendingError {}

impl PendingError {
    /// What to tell a person, naming what is at risk.
    pub fn sentence(&self) -> String {
        match self {
            Self::Sealed(why) => format!(
                "DIG could not save a copy of your profile on this computer: {why}. Do not close \
                 DIG until your profile shows as published."
            ),
            Self::Io(why) => format!(
                "DIG could not write a copy of your profile to disk: {why}. Do not close DIG until \
                 your profile shows as published."
            ),
            Self::Unreadable(why) => {
                format!("DIG could not read the profile content it had saved: {why}")
            }
        }
    }
}

/// Somewhere pending bodies survive a restart.
///
/// A trait so the whole restart cycle is drivable in a test — including the case that matters,
/// where the process that wrote an entry is not the process that drains it.
pub trait PendingBodies: Send + Sync {
    /// Write `entry` down. Returns only once the bytes are on stable storage.
    fn remember(&self, entry: &PendingBody) -> Result<(), PendingError>;

    /// Drop the entry at `(store_id, root)`. A no-op when there is none.
    fn forget(&self, store_id: &str, root: &str) -> Result<(), PendingError>;

    /// Everything still waiting to be handed to the node.
    fn all(&self) -> Result<Vec<PendingBody>, PendingError>;
}

/// The real store: one sealed file in the profile's AppData directory.
///
/// Sealing needs the account unlocked, which it is at the moment an edit is committed. A drain
/// therefore runs when the account is available rather than at the first instant of process start —
/// the bytes are safe on disk either way, which is the property this is for.
pub struct SealedPendingBodies<S> {
    /// The file the sealed set lives in.
    path: PathBuf,
    /// The profile whose key seals it.
    did: String,
    /// The sealing seam.
    sealer: Arc<S>,
}

impl<S: ProfileSealer> SealedPendingBodies<S> {
    /// The pending set for `did`, kept at `path`.
    pub fn new(path: PathBuf, did: impl Into<String>, sealer: Arc<S>) -> Self {
        Self {
            path,
            did: did.into(),
            sealer,
        }
    }

    /// The file name a profile's pending set is kept under, beside its other sealed blobs.
    pub const FILE_NAME: &'static str = "pending-profile-bodies.seal";

    /// Persist `entries`, replacing whatever was there.
    fn write(&self, entries: &[PendingBody]) -> Result<(), PendingError> {
        let json = serde_json::to_vec(entries)
            .map_err(|e| PendingError::Unreadable(format!("could not encode: {e}")))?;
        seal_and_write(&*self.sealer, &self.did, &self.path, &json)
            .map_err(|e| PendingError::Sealed(e.to_string()))
    }
}

impl<S: ProfileSealer + Send + Sync> PendingBodies for SealedPendingBodies<S> {
    fn remember(&self, entry: &PendingBody) -> Result<(), PendingError> {
        let mut entries = self.all()?;
        // Keyed by (store, root): remembering the same body twice — which the commit path does on
        // purpose, once predicted and once actual — must not grow the file.
        if entries
            .iter()
            .any(|held| held.store_id == entry.store_id && held.root == entry.root)
        {
            return Ok(());
        }
        entries.push(entry.clone());
        self.write(&entries)
    }

    fn forget(&self, store_id: &str, root: &str) -> Result<(), PendingError> {
        let mut entries = self.all()?;
        let before = entries.len();
        entries.retain(|held| !(held.store_id == store_id && held.root == root));
        match entries.len() == before {
            true => Ok(()),
            false => self.write(&entries),
        }
    }

    fn all(&self) -> Result<Vec<PendingBody>, PendingError> {
        let sealed = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            // No file is an empty set, not a failure: the ordinary state of a machine that has
            // never had an edit in flight.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PendingError::Io(e.to_string())),
        };
        let plain = self
            .sealer
            .open(&self.did, &sealed)
            .map_err(|e| PendingError::Sealed(e.to_string()))?;
        serde_json::from_slice(&plain)
            .map_err(|e| PendingError::Unreadable(format!("not a pending set: {e}")))
    }
}

/// What a drain did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Bodies the node now holds, verified by reading them back.
    pub stored: usize,
    /// Bodies still waiting — normally because the chain has not confirmed their root yet.
    pub waiting: usize,
}

/// Hand every pending body to the node, and forget the ones it verifiably has.
///
/// # Why an entry is forgotten only after a READ
///
/// A `putBody` that returns success is a claim; the bytes being retrievable is the fact. A store
/// that accepts everything and keeps nothing answers `Ok(())` and leaves the profile exactly as
/// lost as before, so the entry is dropped only once [`BodyStore::get`] returns the same bytes at
/// the same root. Anything else leaves it pending, which costs a retry and never costs the body.
///
/// Never returns an error: a drain runs at start-up, and a node that is down is the ordinary case
/// it exists to ride out — every entry it could not hand over stays pending for the next launch.
pub fn drain(pending: &dyn PendingBodies, bodies: &dyn BodyStore) -> DrainReport {
    let Ok(entries) = pending.all() else {
        return DrainReport::default();
    };

    entries
        .iter()
        .fold(DrainReport::default(), |report, entry| {
            match handed_over(entry, bodies) {
                true => {
                    let _ = pending.forget(&entry.store_id, &entry.root);
                    DrainReport {
                        stored: report.stored + 1,
                        ..report
                    }
                }
                false => DrainReport {
                    waiting: report.waiting + 1,
                    ..report
                },
            }
        })
}

/// Whether the node now holds `entry`'s bytes at `entry`'s root, proved by reading them back.
fn handed_over(entry: &PendingBody, bodies: &dyn BodyStore) -> bool {
    if bodies
        .put(&entry.store_id, &entry.root, &entry.body)
        .is_err()
    {
        return false;
    }
    matches!(
        bodies.get(&entry.store_id, &entry.root),
        Ok(BodyRead::Held(held)) if held == entry.body
    )
}

/// A pending set held in memory, for builds and galleries that have no sealed storage.
///
/// It is honest about what it is: bodies in it do NOT survive a restart, so it belongs only where
/// nothing is ever committed for real.
#[derive(Debug, Default)]
pub struct MemoryPending {
    /// What it holds.
    entries: std::sync::Mutex<Vec<PendingBody>>,
}

impl PendingBodies for MemoryPending {
    fn remember(&self, entry: &PendingBody) -> Result<(), PendingError> {
        let mut entries = self.entries.lock().expect("pending");
        if !entries
            .iter()
            .any(|held| held.store_id == entry.store_id && held.root == entry.root)
        {
            entries.push(entry.clone());
        }
        Ok(())
    }

    fn forget(&self, store_id: &str, root: &str) -> Result<(), PendingError> {
        self.entries
            .lock()
            .expect("pending")
            .retain(|held| !(held.store_id == store_id && held.root == root));
        Ok(())
    }

    fn all(&self) -> Result<Vec<PendingBody>, PendingError> {
        Ok(self.entries.lock().expect("pending").clone())
    }
}

#[cfg(test)]
pub(crate) mod doubles {
    //! Pending sets a test can drive.

    pub(crate) use super::MemoryPending as InMemoryPending;
    use super::{PendingBodies, PendingBody, PendingError};

    /// A pending set that cannot keep anything — a locked account, or a full disk.
    #[derive(Debug, Default)]
    pub(crate) struct RefusingPending;

    impl PendingBodies for RefusingPending {
        fn remember(&self, _: &PendingBody) -> Result<(), PendingError> {
            Err(PendingError::Sealed("the account is locked".into()))
        }
        fn forget(&self, _: &str, _: &str) -> Result<(), PendingError> {
            Ok(())
        }
        fn all(&self) -> Result<Vec<PendingBody>, PendingError> {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::super::bodies::doubles::{ForgetfulBodies, InMemoryBodies, RefusingBodies};
    use super::super::bodies::{BodyStore, BodyStoreError};
    use super::doubles::InMemoryPending;
    use super::*;
    use crate::sealer::SealError;
    use zeroize::Zeroizing;

    /// A body and the root it is pending at.
    fn an_entry() -> PendingBody {
        PendingBody {
            store_id: "11".repeat(32),
            root: "22".repeat(32),
            body: b"DIGP\x01the body only this app holds".to_vec(),
        }
    }

    /// The DID a blob was sealed under, and the plaintext it holds.
    type SealedUnder = (String, Vec<u8>);

    /// A sealer that is a real AEAD in the one respect these tests depend on: bytes sealed under
    /// one DID do not open under another, and the ciphertext is not the plaintext.
    #[derive(Default)]
    struct DidKeyedSealer {
        /// Ciphertext handed out, by the DID it was sealed under.
        vault: Mutex<HashMap<Vec<u8>, SealedUnder>>,
    }

    impl ProfileSealer for DidKeyedSealer {
        fn seal(&self, did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
            let token: Vec<u8> = format!("sealed:{}:{}", did, plaintext.len()).into_bytes();
            self.vault
                .lock()
                .expect("vault")
                .insert(token.clone(), (did.to_string(), plaintext.to_vec()));
            Ok(token)
        }

        fn open(&self, did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            match self.vault.lock().expect("vault").get(ciphertext) {
                Some((sealed_for, plain)) if sealed_for == did => Ok(Zeroizing::new(plain.clone())),
                _ => Err(SealError::Open),
            }
        }
    }

    /// **The restart.** A body pending when the app stops is pending, intact, and drainable when a
    /// DIFFERENT process opens the same file.
    ///
    /// # Why the second store is constructed rather than reused
    ///
    /// The nearest wrong implementation keeps the set in memory and writes the file as a courtesy.
    /// It passes every test that asks the SAME object what it holds, and loses everything a restart
    /// was supposed to save. So the reader here shares nothing with the writer but the path and the
    /// key — which is exactly what a second launch of dig-app shares with the first.
    #[test]
    fn a_body_pending_at_shutdown_is_still_pending_at_the_next_launch() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir
            .path()
            .join(SealedPendingBodies::<DidKeyedSealer>::FILE_NAME);
        let sealer = Arc::new(DidKeyedSealer::default());
        let did = "did:chia:abc";

        {
            let before_the_crash = SealedPendingBodies::new(path.clone(), did, sealer.clone());
            before_the_crash.remember(&an_entry()).expect("remembers");
        } // and the process ends here, with the node still refusing the body.

        let after_the_restart = SealedPendingBodies::new(path.clone(), did, sealer.clone());
        assert_eq!(
            after_the_restart.all().expect("reads"),
            vec![an_entry()],
            "the body did not survive the restart, which is the whole point of writing it down"
        );

        // And it drains: the chain has confirmed by now, so the node takes it and it is forgotten.
        let node = InMemoryBodies::default();
        assert_eq!(
            drain(&after_the_restart, &node),
            DrainReport {
                stored: 1,
                waiting: 0
            }
        );
        assert!(after_the_restart.all().expect("reads").is_empty());
        assert_eq!(
            node.get(&an_entry().store_id, &an_entry().root),
            Ok(BodyRead::Held(an_entry().body)),
            "the node was never actually given the bytes"
        );
    }

    /// The bytes on disk are ciphertext, and they do not open under another profile's key (NC-2).
    #[test]
    fn a_pending_body_is_sealed_at_rest_and_isolated_per_profile() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("pending.seal");
        let sealer = Arc::new(DidKeyedSealer::default());

        SealedPendingBodies::new(path.clone(), "did:chia:mine", sealer.clone())
            .remember(&an_entry())
            .expect("remembers");

        let on_disk = std::fs::read(&path).expect("the file exists");
        assert!(
            !on_disk.windows(4).any(|window| window == b"DIGP"),
            "the profile body is on disk in the clear"
        );

        assert!(
            SealedPendingBodies::new(path, "did:chia:someone-else", sealer)
                .all()
                .is_err(),
            "another profile's key opened this profile's pending bodies"
        );
    }

    /// A node that ACCEPTS and forgets does not clear the entry. The `put` succeeded, so an
    /// implementation that trusted it would delete the last copy of the bytes on earth.
    #[test]
    fn a_node_that_accepts_and_keeps_nothing_does_not_clear_the_entry() {
        let pending = InMemoryPending::default();
        pending.remember(&an_entry()).expect("remembers");

        assert_eq!(
            drain(&pending, &ForgetfulBodies),
            DrainReport {
                stored: 0,
                waiting: 1
            }
        );
        assert_eq!(
            pending.all().expect("reads"),
            vec![an_entry()],
            "the only copy of the body was dropped on a store's unverified say-so"
        );
    }

    /// A node that returns DIFFERENT bytes does not clear the entry either — what it serves would
    /// not rebuild to the root on chain.
    #[test]
    fn a_node_that_answers_with_other_bytes_does_not_clear_the_entry() {
        struct Substituting;
        impl BodyStore for Substituting {
            fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
                Ok(())
            }
            fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
                Ok(BodyRead::Held(b"something else".to_vec()))
            }
        }
        let pending = InMemoryPending::default();
        pending.remember(&an_entry()).expect("remembers");
        assert_eq!(drain(&pending, &Substituting).waiting, 1);
        assert_eq!(pending.all().expect("reads").len(), 1);
    }

    /// The refusal the user actually met: the chain has not confirmed the root yet, so the node
    /// says no. The entry stays, and the next drain tries again.
    #[test]
    fn a_root_the_chain_has_not_confirmed_yet_stays_pending_and_is_retried() {
        let pending = InMemoryPending::default();
        pending.remember(&an_entry()).expect("remembers");

        let refusing = RefusingBodies(BodyStoreError::Refused(
            "root 371a… is not this store's confirmed on-chain root 7165…".into(),
        ));
        assert_eq!(drain(&pending, &refusing).waiting, 1);

        // Later, the chain confirms and the same entry goes through untouched.
        let node = InMemoryBodies::default();
        assert_eq!(drain(&pending, &node).stored, 1);
        assert!(pending.all().expect("reads").is_empty());
    }

    /// Remembering the same body twice keeps one entry — the commit path does it deliberately, once
    /// before the spend and once with the bytes the commit returned.
    #[test]
    fn the_same_body_remembered_twice_is_one_entry() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = SealedPendingBodies::new(
            dir.path().join("pending.seal"),
            "did:chia:abc",
            Arc::new(DidKeyedSealer::default()),
        );
        store.remember(&an_entry()).expect("remembers");
        store.remember(&an_entry()).expect("remembers again");
        assert_eq!(store.all().expect("reads").len(), 1);
    }

    /// Two bodies for the SAME store at different roots both survive: a person may edit twice
    /// before the first confirms, and dropping the older one would lose the intermediate root's
    /// preimage while its coin is still on chain.
    #[test]
    fn two_roots_for_one_store_are_both_kept() {
        let dir = tempfile::tempdir().expect("a directory");
        let store = SealedPendingBodies::new(
            dir.path().join("pending.seal"),
            "did:chia:abc",
            Arc::new(DidKeyedSealer::default()),
        );
        store.remember(&an_entry()).expect("first");
        store
            .remember(&PendingBody {
                root: "33".repeat(32),
                ..an_entry()
            })
            .expect("second");
        assert_eq!(store.all().expect("reads").len(), 2);

        store
            .forget(&an_entry().store_id, &an_entry().root)
            .expect("forgets");
        assert_eq!(
            store.all().expect("reads"),
            vec![PendingBody {
                root: "33".repeat(32),
                ..an_entry()
            }],
            "forgetting one root took the other with it"
        );
    }

    /// The three causes, each with the marker only that variant could have produced and the variant
    /// name a Debug rendering would leak.
    fn every_cause() -> [(PendingError, &'static str, &'static str); 3] {
        [
            (
                PendingError::Sealed("the-sealing-marker".into()),
                "the-sealing-marker",
                "Sealed",
            ),
            (
                PendingError::Io("the-disk-marker".into()),
                "the-disk-marker",
                "Io",
            ),
            (
                PendingError::Unreadable("the-parsing-marker".into()),
                "the-parsing-marker",
                "Unreadable",
            ),
        ]
    }

    #[test]
    fn every_cause_displays_as_a_plain_language_clause_naming_what_went_wrong() {
        for (cause, _, variant) in every_cause() {
            let shown = cause.to_string();

            // The nearest wrong implementation is `{e:?}`, which a person would read as source code.
            assert!(
                !shown.contains(variant) && !shown.contains('"'),
                "{cause:?} rendered as a Debug dump rather than a sentence: {shown}"
            );
            // The other nearest wrong implementation is delegating to `sentence()`, which is a whole
            // standalone sentence and nests absurdly inside the clause its callers wrap it in.
            assert!(
                !shown.starts_with("DIG") && !shown.contains("Do not close DIG"),
                "{cause:?} rendered a whole sentence where a clause belongs: {shown}"
            );
            assert!(
                !shown.ends_with('.'),
                "{cause:?} ended itself, so a caller's own full stop doubles up: {shown}"
            );
        }
    }

    #[test]
    fn display_keeps_the_underlying_cause_a_support_request_needs() {
        for (cause, marker, _) in every_cause() {
            assert!(
                cause.to_string().contains(marker),
                "{cause:?} dropped the detail that says WHICH failure happened: {cause}"
            );
        }
    }

    #[test]
    fn the_three_causes_do_not_read_alike() {
        // Told apart by their wording alone: the markers are stripped, so an implementation that
        // renders one fixed phrase plus the detail cannot pass this.
        let phrasings: Vec<String> = every_cause()
            .into_iter()
            .map(|(cause, marker, _)| cause.to_string().replace(marker, ""))
            .collect();

        assert_ne!(phrasings[0], phrasings[1], "sealing and disk read alike");
        assert_ne!(phrasings[1], phrasings[2], "disk and parsing read alike");
        assert_ne!(phrasings[0], phrasings[2], "sealing and parsing read alike");
    }

    #[test]
    fn display_composes_into_the_sentence_the_creation_path_wraps_it_in() {
        // The exact shape used when a mint seed cannot be written down (dig_ecosystem#3073). It is
        // the reason `Display` exists, so it is asserted here rather than left to the binary.
        let told = format!(
            "DIG could not save your new profile's details on this computer: {}.",
            PendingError::Io("the disk is full".into())
        );

        assert_eq!(
            told,
            "DIG could not save your new profile's details on this computer: the disk could not be \
             read from or written to (the disk is full).",
        );
    }

    #[test]
    fn a_cause_is_a_std_error_with_nothing_hidden_beneath_it() {
        fn only_takes_std_errors<E: std::error::Error>(
            error: &E,
        ) -> Option<&dyn std::error::Error> {
            error.source()
        }

        // The detail is already a rendered string by the time it reaches the variant, so there is no
        // inner error to chain to. Pinned so a later refactor that keeps a real source must say so.
        for (cause, _, _) in every_cause() {
            assert!(only_takes_std_errors(&cause).is_none(), "{cause:?}");
        }
    }
}
