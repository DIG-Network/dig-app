//! Where a stranger's profile is actually read from: the chain for the root, the node for the bytes.
//!
//! # Why this does not go through `dig_account::edit::read_profile`
//!
//! That function is the right one for THIS account's profile and cannot be used for anybody else's:
//! it takes a [`ProfileAnchor`](dig_account::registry::ProfileAnchor), whose only in-process
//! constructor requires both halves of a mint THIS machine performed. There is no anchor for a
//! stranger, and manufacturing one would mean asserting a DID and two confirmation heights nobody
//! read — a fabricated record of an on-chain fact, in the one type built to make that impossible.
//!
//! So the two chain reads it would have done are done here directly, against the same crates that
//! own them: the lineage walk and tip re-parse are `dig-merkle`'s
//! ([`hydrate`](dig_merkle::hydrate)), and the body's acceptance is `dig-social-profile`'s
//! [`VerifiedBody`]. Nothing is reimplemented — the duplication is three call lines, and the
//! alternative was a fabricated anchor.
//!
//! # The verification, stated once
//!
//! The root is read from CHAIN BYTES: the store's singleton lineage is walked to its tip, and the
//! tip's creating spend is re-parsed for the store metadata. A lineage is a forward chain of genuine
//! recreations, so a coin curried to look like this store has no place in it. The body is then
//! accepted only through `VerifiedBody::open(.., AnchoredRoot::from_chain_read(root))` — the same
//! acceptance dig-node applies to a body a peer synced to it. Bytes that do not rebuild to the
//! anchored root are reported as unusable and never rendered.

use std::collections::BTreeMap;
use std::sync::Arc;

use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_social_profile::body::{AnchoredRoot, VerifiedBody};
use dig_social_profile::value::Value;

use super::ViewedProfile;
use crate::profile_edit::bodies::{BodyRead, BodyStore};
use crate::profile_edit::ProfileField;

/// Something that can answer "what does this store publish as its profile?".
///
/// A trait so the pane and the service can be driven over doubles — including the two answers that
/// matter most and are hardest to arrange for real, a root with no body behind it and bytes that do
/// not match their root — with no node and no chain.
pub trait StoreProfiles: Send + Sync {
    /// Look `store_id` (lowercase hex, no prefix) up, and say what was found.
    ///
    /// Returns a [`ViewedProfile`] rather than a `Result` because the failures ARE the answers: "no
    /// such store" and "the chain would not answer" are two of the states the surface must show, and
    /// flattening either into an error type would let a caller render them as one.
    fn look_up(&self, store_id: &str) -> ViewedProfile;
}

/// The live source: this app's chain reads, and this app's node for the bytes.
pub struct NodeStoreProfiles<C> {
    /// Chain reads. Never a write — this whole surface spends nothing and signs nothing.
    chain: Arc<C>,
    /// Where profile bodies are kept, over `control.profile.getBody`.
    bodies: Arc<dyn BodyStore>,
}

impl<C> NodeStoreProfiles<C> {
    /// A source over `chain` for roots and `bodies` for content.
    pub fn new(chain: Arc<C>, bodies: Arc<dyn BodyStore>) -> Self {
        Self { chain, bodies }
    }
}

impl<C> StoreProfiles for NodeStoreProfiles<C>
where
    C: ChainSource + Send + Sync,
{
    fn look_up(&self, store_id: &str) -> ViewedProfile {
        let owned = store_id.to_string();
        let Some(launcher) = launcher_of(store_id) else {
            return ViewedProfile::NoProfile {
                store_id: owned,
                why: "that is not a store id DIG can read".to_string(),
            };
        };

        let root = match self.anchored_root(launcher) {
            Ok(Some(root)) => root,
            Ok(None) => {
                return ViewedProfile::NoProfile {
                    store_id: owned,
                    why: "the chain has no dig-store with that id, or its lineage has ended"
                        .to_string(),
                }
            }
            Err(why) => return ViewedProfile::Unreachable { store_id: owned, why },
        };

        let root_hex = hex::encode(root);
        match self.bodies.get(store_id, &root_hex) {
            // The state this surface exists for: the chain anchors a root and nothing here holds
            // the bytes it commits to. An ANSWER, and never an empty profile.
            Ok(BodyRead::Nothing) => ViewedProfile::BodyMissing {
                store_id: owned,
                root: prefixed(&root_hex),
            },
            Ok(BodyRead::Held(bytes)) => open(&owned, root, &root_hex, &bytes),
            Err(error) => ViewedProfile::Unreachable {
                store_id: owned,
                why: error.sentence(),
            },
        }
    }
}

impl<C> NodeStoreProfiles<C>
where
    C: ChainSource + Send + Sync,
{
    /// The root the chain currently anchors for the store at `launcher`.
    ///
    /// `Ok(None)` means the chain answered and there is no such live store; `Err` means it could not
    /// be asked. Keeping them apart here is what lets the caller show two different sentences.
    fn anchored_root(&self, launcher: Bytes32) -> Result<Option<[u8; 32]>, String> {
        let Some(lineage) = self
            .chain
            .resolve_singleton_lineage(launcher)
            .map_err(|e| format!("DIG could not read the chain: {e}"))?
        else {
            return Ok(None);
        };
        let Some(creating_spend) = self
            .chain
            .parent_spend(lineage.tip())
            .map_err(|e| format!("DIG could not read the chain: {e}"))?
        else {
            return Ok(None);
        };
        // A spend that does not parse as a dig-store is a store id naming something else, which is
        // an answer about that id rather than a fault of this machine.
        let Ok(store) = dig_merkle::hydrate(&creating_spend) else {
            return Ok(None);
        };
        Ok(Some(store.info.metadata.root_hash.into()))
    }
}

/// Accept `bytes` as the profile at `root`, or say why they cannot be shown.
///
/// The one place a body becomes something a person sees, so it is the one place the acceptance rule
/// lives: bytes that do not rebuild to the CHAIN'S root become
/// [`Unverifiable`](ViewedProfile::Unverifiable) and are dropped. There is deliberately no path from
/// here that renders unverified bytes with a caveat attached — a caveat is a thing a reader can miss.
fn open(store_id: &str, root: [u8; 32], root_hex: &str, bytes: &[u8]) -> ViewedProfile {
    match VerifiedBody::open(bytes, AnchoredRoot::from_chain_read(root)) {
        Ok(body) => ViewedProfile::Held {
            store_id: store_id.to_string(),
            root: prefixed(root_hex),
            fields: fields_of(&body),
        },
        Err(why) => ViewedProfile::Unverifiable {
            store_id: store_id.to_string(),
            root: prefixed(root_hex),
            why: why.to_string(),
        },
    }
}

/// The person-facing fields `body` publishes.
///
/// A slot this app does not name is SKIPPED rather than stringified, and so is a slot holding a
/// non-text value: a profile whose body is odd reads as a profile missing that field, not as one
/// publishing a rendering of its own bytes.
fn fields_of(body: &VerifiedBody) -> BTreeMap<ProfileField, String> {
    let mut fields = BTreeMap::new();
    for (slot, value) in body.profile().iter() {
        let Some(field) = ProfileField::ALL
            .into_iter()
            .find(|known| known.slot().id() == slot.0)
        else {
            continue;
        };
        if let Value::Utf8(text) = value {
            fields.insert(field, text.clone());
        }
    }
    fields
}

/// The 32 bytes a store id names, or `None` when it is not 32 bytes of hex.
fn launcher_of(store_id: &str) -> Option<Bytes32> {
    let raw: [u8; 32] = hex::decode(store_id).ok()?.try_into().ok()?;
    Some(Bytes32::new(raw))
}

/// A root as every DIG surface prints one: `0x`-prefixed lowercase hex.
fn prefixed(root_hex: &str) -> String {
    format!("0x{root_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_social_profile::slot::SlotId;

    /// A store id, of the shape every DIG surface prints.
    const ID: &str = "371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0";

    /// A real body publishing one name, and the root it commits to.
    fn body_naming(name: &str) -> VerifiedBody {
        VerifiedBody::from_pairs(vec![(
            SlotId(ProfileField::DisplayName.slot().id()),
            Value::Utf8(name.to_string()),
        )])
        .expect("one text slot is a valid profile body")
    }

    /// **Bytes are shown only when they rebuild to the root the CHAIN anchors.**
    ///
    /// The distinguishing fixture is a body that is perfectly valid in itself and belongs to a
    /// DIFFERENT root — which is exactly what a hostile or stale answer from a node looks like, and
    /// which every check weaker than "recompute and compare" accepts. A test that only fed it
    /// garbage would pass against an implementation that merely parsed the body.
    ///
    /// The control is the same bytes against their OWN root: without it this test would also pass
    /// against an implementation that refused everything.
    #[test]
    fn a_body_belonging_to_another_root_is_named_unusable_rather_than_shown() {
        let body = body_naming("Ada");
        let other = body_naming("Grace");
        assert_ne!(
            body.root(),
            other.root(),
            "the fixture's two bodies share a root, so this test cannot see a missed comparison"
        );

        let root_hex = hex::encode(other.root());
        match open(ID, other.root(), &root_hex, body.as_bytes()) {
            ViewedProfile::Unverifiable { root, .. } => {
                assert_eq!(root, format!("0x{root_hex}"));
            }
            other => panic!("a body from another root was not refused: {other:?}"),
        }

        let own_hex = hex::encode(body.root());
        match open(ID, body.root(), &own_hex, body.as_bytes()) {
            ViewedProfile::Held { fields, root, .. } => {
                assert_eq!(root, format!("0x{own_hex}"));
                assert_eq!(
                    fields.get(&ProfileField::DisplayName).map(String::as_str),
                    Some("Ada"),
                    "a body that verifies did not reach the screen"
                );
            }
            other => panic!("a body that verifies against its own root was refused: {other:?}"),
        }
    }

    /// **A field the body does not publish is absent from the reading, not present and empty.**
    ///
    /// The two render differently — "Not published" against a blank line — and only one of them is
    /// true of a profile that never wrote the slot.
    #[test]
    fn an_unpublished_field_is_absent_rather_than_empty() {
        let body = body_naming("Ada");
        let fields = fields_of(&body);
        assert!(
            !fields.contains_key(&ProfileField::Location),
            "a slot the body never wrote arrived as a value"
        );
        assert_eq!(fields.len(), 1, "fields were invented: {fields:?}");
    }
}
