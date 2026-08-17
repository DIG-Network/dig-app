//! Where a profile's bytes are kept: `control.profile.putBody` / `getBody` on the local node.
//!
//! # The failure this file exists to prevent
//!
//! A profile's SMT root goes on chain; the body it commits to does not. So an edit that succeeds
//! everywhere and then DROPS the bytes it produced leaves a root nothing on earth holds the preimage
//! of — the profile is unreadable, permanently, and no layer reports an error, because from each
//! layer's own point of view everything worked. That is the defect the DPB work exists to fix, and
//! this is the layer at which it would be reintroduced.
//!
//! So [`BodyStore::put`] is not an optimisation and its failure is not cosmetic: a commit whose put
//! failed is a commit that must SAY SO, loudly, with the bytes still in hand.
//!
//! # `body_b64: null` is an ANSWER; a failed read is an ERROR
//!
//! The contract is explicit that `null` means the node consulted its store and holds nothing, and
//! that it NEVER means the read failed. They need opposite handling — one is "ask a peer", the other
//! is "your node is not answering" — so they are opposite variants here ([`BodyRead::Held`] versus
//! [`BodyStoreError`]) rather than one `Option` a caller can flatten by accident.
//!
//! # The node checks the root; this client does not get to assert it
//!
//! `putBody` treats the caller's `root` as a CLAIM: the node resolves the root on chain itself and
//! refuses any body that does not rebuild to the confirmed one. dig-app is a caller like any other
//! there, which is the property that keeps the control plane from being a way to make a node serve
//! arbitrary bytes under someone else's profile. Nothing in this file may work around that.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use dig_node_control_interface::method::ControlMethod;
use dig_node_control_interface::params::{
    ProfileGetBodyParams, ProfilePutBodyParams, MAX_BODY_BYTES,
};

use crate::control::{self, ControlFailure};

/// How long one body call may take.
///
/// Longer than a chain read's budget: this moves up to 4 MiB across the loopback control plane and
/// the node re-resolves a root on chain before it accepts anything.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// What a node answered when asked for a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRead {
    /// The node holds these bytes at the root that was asked about.
    Held(Vec<u8>),
    /// The node consulted its store and holds nothing at that root.
    ///
    /// An answer, not a fault. A caller may act on it — fetch from a peer, re-put its own copy —
    /// which is precisely what it must NOT do on a [`BodyStoreError`].
    Nothing,
}

/// Why a body could not be stored or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStoreError {
    /// This app holds no control token, so the call was refused before it was sent. Both body
    /// methods are token-gated.
    NoToken,
    /// The node was asked and refused the credential.
    Unauthorized(String),
    /// Nothing answered, or the answer did not arrive intact.
    Unreachable(String),
    /// This dig-node does not serve the profile-body methods at all — an older build.
    Unsupported(String),
    /// The node understood the call and refused it — including the refusal that matters most, a
    /// body whose recomputed root is not the one the chain confirms.
    Refused(String),
    /// The bytes are larger than the contract permits, refused HERE rather than on the wire.
    TooLarge {
        /// How many bytes were offered.
        len: usize,
    },
    /// The node's answer was not decodable base64.
    Undecodable(String),
}

/// The remedy sentence IS the display form.
///
/// dig-account's [`ProfileContentSource`](dig_account::edit::ProfileContentSource) surfaces a
/// source's error through `Display`, and that string reaches a person via
/// `EditError::ContentUnavailable`. A derived `Debug`-ish rendering there would show them
/// `Unreachable("connection refused")`; this shows them what to do about it.
impl std::fmt::Display for BodyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sentence())
    }
}

impl BodyStoreError {
    /// What to tell a person, in words that name the remedy.
    pub fn sentence(&self) -> String {
        match self {
            Self::NoToken => "DIG could not prove to your node that it is allowed to store your \
                              profile. Restart DIG, or check that it can read your node's token \
                              file."
                .to_string(),
            Self::Unauthorized(detail) => {
                format!("Your node did not accept DIG's credentials: {detail}")
            }
            Self::Unreachable(detail) => {
                format!("DIG could not reach your node: {detail}")
            }
            Self::Unsupported(_) => {
                "Your node is too old to store profile content. Update it, and \
                                     DIG will store your profile then."
                    .to_string()
            }
            Self::Refused(detail) => format!("Your node refused to store the profile: {detail}"),
            Self::TooLarge { len } => format!(
                "This profile comes to {len} bytes and a profile may hold {MAX_BODY_BYTES}. Remove \
                 or shrink an image and try again."
            ),
            Self::Undecodable(detail) => {
                format!("Your node's answer could not be read: {detail}")
            }
        }
    }
}

/// Somewhere a profile body can be kept and read back.
///
/// A trait so the editor's tests can drive the whole commit — including a store that LOSES what it
/// is given, which is the case the read-back exists for — without a node.
pub trait BodyStore: Send + Sync {
    /// Hand `body` to the store, as the preimage of `root` for the profile at `store_id`.
    fn put(&self, store_id: &str, root: &str, body: &[u8]) -> Result<(), BodyStoreError>;

    /// Read back whatever is held at `root`.
    fn get(&self, store_id: &str, root: &str) -> Result<BodyRead, BodyStoreError>;
}

/// The real store: the dig-node this app is talking to.
pub struct ControlBodyStore {
    /// The control endpoint.
    endpoint: String,
    /// The control token both methods require, or `None` when this app could not read one.
    token: Option<String>,
    /// How long one call may take.
    timeout: Duration,
}

impl ControlBodyStore {
    /// A store over `endpoint`, authorized by `token`.
    pub fn new(endpoint: impl Into<String>, token: Option<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token,
            timeout: BODY_TIMEOUT,
        }
    }

    /// The same, with a timeout of the caller's choosing.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The token, or the local refusal that says the call was never sent.
    fn token(&self) -> Result<&str, BodyStoreError> {
        self.token.as_deref().ok_or(BodyStoreError::NoToken)
    }
}

impl BodyStore for ControlBodyStore {
    fn put(&self, store_id: &str, root: &str, body: &[u8]) -> Result<(), BodyStoreError> {
        // Checked here so an oversized body is refused with the size in hand rather than as a
        // generic INVALID_PARAMS after 4 MiB has crossed a socket.
        if body.len() > MAX_BODY_BYTES {
            return Err(BodyStoreError::TooLarge { len: body.len() });
        }
        let token = self.token()?;
        control::call_control_result(
            &self.endpoint,
            &ProfilePutBodyParams {
                store_id: store_id.to_string(),
                root: root.to_string(),
                body_b64: BASE64.encode(body),
            },
            Some(token),
            self.timeout,
        )
        .map(|_| ())
        .map_err(|failure| failure_of(ControlMethod::ProfilePutBody, failure))
    }

    fn get(&self, store_id: &str, root: &str) -> Result<BodyRead, BodyStoreError> {
        let token = self.token()?;
        let answer = control::call_control_result(
            &self.endpoint,
            &ProfileGetBodyParams {
                store_id: store_id.to_string(),
                root: root.to_string(),
            },
            Some(token),
            self.timeout,
        )
        .map_err(|failure| failure_of(ControlMethod::ProfileGetBody, failure))?;

        // The one line this whole module is arranged around: `null` is the node's answer that it
        // holds nothing, and it becomes `Nothing` — never an error, and never an empty `Vec`, which
        // a caller would go on to treat as a body.
        let Some(encoded) = answer.body_b64 else {
            return Ok(BodyRead::Nothing);
        };
        BASE64
            .decode(encoded.as_bytes())
            .map(BodyRead::Held)
            .map_err(|e| BodyStoreError::Undecodable(e.to_string()))
    }
}

/// Map a control failure onto the arm whose remedy is right.
fn failure_of(method: ControlMethod, failure: ControlFailure) -> BodyStoreError {
    use dig_node_control_interface::error::ControlErrorCode;

    match failure {
        ControlFailure::Transport(e) => BodyStoreError::Unreachable(e.to_string()),
        ControlFailure::Rejected(error) => match error.code_enum() {
            // On a TOKEN-GATED method this genuinely is about the credential, unlike on the open
            // chain reads where the same code can only mean an old node.
            Some(ControlErrorCode::Unauthorized) => BodyStoreError::Unauthorized(error.message),
            Some(ControlErrorCode::MethodNotFound) => BodyStoreError::Unsupported(format!(
                "this node does not serve {}: {}",
                method.name(),
                error.message
            )),
            _ => BodyStoreError::Refused(error.message),
        },
    }
}

#[cfg(test)]
pub(crate) mod doubles {
    //! Body stores a test can drive, including the ones that misbehave in the two ways that matter.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{BodyRead, BodyStore, BodyStoreError};

    /// A store that keeps what it is given.
    #[derive(Debug, Default)]
    pub(crate) struct InMemoryBodies {
        held: Mutex<HashMap<(String, String), Vec<u8>>>,
    }

    impl BodyStore for InMemoryBodies {
        fn put(&self, store_id: &str, root: &str, body: &[u8]) -> Result<(), BodyStoreError> {
            self.held
                .lock()
                .expect("bodies")
                .insert((store_id.into(), root.into()), body.to_vec());
            Ok(())
        }

        fn get(&self, store_id: &str, root: &str) -> Result<BodyRead, BodyStoreError> {
            Ok(self
                .held
                .lock()
                .expect("bodies")
                .get(&(store_id.into(), root.into()))
                .cloned()
                .map(BodyRead::Held)
                .unwrap_or(BodyRead::Nothing))
        }
    }

    /// A store that accepts everything and keeps nothing — the silent-loss failure, made loud.
    #[derive(Debug, Default)]
    pub(crate) struct ForgetfulBodies;

    impl BodyStore for ForgetfulBodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Ok(())
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            Ok(BodyRead::Nothing)
        }
    }

    /// A node that refuses a body until told to accept it, counting every attempt.
    ///
    /// The shape of the case an in-session retry exists for: the commonest refusal is a root the
    /// chain has not confirmed YET, which becomes acceptable on its own a block or two later
    /// (dig_ecosystem#3078). A double that can only ever refuse, or only ever accept, cannot express
    /// that change of mind — and a test written against either one passes for an app that offers a
    /// body exactly once.
    #[derive(Debug, Default)]
    pub(crate) struct NodeThatWarmsUp {
        /// What it holds once it starts accepting.
        held: InMemoryBodies,
        /// Whether the chain has caught up yet.
        accepting: Mutex<bool>,
        /// How many times a body has been offered, so a test can assert a RATE and not merely a
        /// success.
        offers: Mutex<usize>,
    }

    impl NodeThatWarmsUp {
        /// Start accepting, as a block carrying the new root does.
        pub(crate) fn catch_up(&self) {
            *self.accepting.lock().expect("accepting") = true;
        }

        /// How many times a body has been offered.
        pub(crate) fn offers(&self) -> usize {
            *self.offers.lock().expect("offers")
        }
    }

    impl BodyStore for NodeThatWarmsUp {
        fn put(&self, store_id: &str, root: &str, body: &[u8]) -> Result<(), BodyStoreError> {
            *self.offers.lock().expect("offers") += 1;
            if !*self.accepting.lock().expect("accepting") {
                return Err(BodyStoreError::Refused(format!(
                    "root {root} is not this store's confirmed on-chain root"
                )));
            }
            self.held.put(store_id, root, body)
        }

        fn get(&self, store_id: &str, root: &str) -> Result<BodyRead, BodyStoreError> {
            self.held.get(store_id, root)
        }
    }

    /// A store that refuses every call.
    #[derive(Debug)]
    pub(crate) struct RefusingBodies(pub(crate) BodyStoreError);

    impl BodyStore for RefusingBodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Err(self.0.clone())
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            Err(self.0.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::doubles::*;
    use super::*;

    /// The distinction the whole module is built on, asserted on the store trait itself: a node
    /// holding nothing and a node that could not be asked are different values, and neither can be
    /// obtained from the other.
    #[test]
    fn holding_nothing_and_failing_are_different_answers() {
        let held = InMemoryBodies::default();
        assert_eq!(held.get("store", "root"), Ok(BodyRead::Nothing));

        let broken = RefusingBodies(BodyStoreError::Unreachable("no node".into()));
        assert!(broken.get("store", "root").is_err());
    }

    #[test]
    fn a_body_that_was_put_reads_back_byte_for_byte() {
        let store = InMemoryBodies::default();
        store.put("store", "root", b"DIGP\x01body").expect("put");
        assert_eq!(
            store.get("store", "root"),
            Ok(BodyRead::Held(b"DIGP\x01body".to_vec()))
        );
    }

    /// A body read at a DIFFERENT root is not this profile's body. Asked at the wrong root, a store
    /// must answer `Nothing` rather than the nearest thing it has — the property that keeps a
    /// caller from mistaking an old body for the current one.
    #[test]
    fn a_body_is_only_held_at_the_root_it_was_put_at() {
        let store = InMemoryBodies::default();
        store.put("store", "root-a", b"first").expect("put");
        assert_eq!(store.get("store", "root-b"), Ok(BodyRead::Nothing));
    }

    #[test]
    fn every_failure_names_a_remedy() {
        for error in [
            BodyStoreError::NoToken,
            BodyStoreError::Unauthorized("bad token".into()),
            BodyStoreError::Unreachable("connection refused".into()),
            BodyStoreError::Unsupported("no such method".into()),
            BodyStoreError::Refused("root mismatch".into()),
            BodyStoreError::TooLarge { len: 9_000_000 },
            BodyStoreError::Undecodable("invalid base64".into()),
        ] {
            let said = error.sentence();
            // Names WHO is involved, so a person knows where to look. A sentence that says only
            // that something failed is the dead end #1800 removed.
            assert!(
                said.contains("node") || said.contains("DIG") || said.contains("profile"),
                "{error:?} names nobody: {said}"
            );
            assert!(said.len() > 30, "{error:?} is too terse to act on: {said}");
        }
    }

    /// Refused locally, with the size in hand, rather than after the bytes cross a socket.
    #[test]
    fn an_oversized_body_is_refused_before_it_is_sent() {
        let store = ControlBodyStore::new("http://127.0.0.1:1", Some("token".into()));
        let too_big = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(
            store.put("store", "root", &too_big),
            Err(BodyStoreError::TooLarge {
                len: MAX_BODY_BYTES + 1
            })
        );
    }

    /// Without a token neither call is SENT — a local refusal, distinguishable from a node that is
    /// not there, because the remedies are different.
    #[test]
    fn no_token_means_the_call_was_never_sent() {
        let store = ControlBodyStore::new("http://127.0.0.1:1", None);
        assert_eq!(
            store.put("store", "root", b"body"),
            Err(BodyStoreError::NoToken)
        );
        assert_eq!(store.get("store", "root"), Err(BodyStoreError::NoToken));
    }
}
