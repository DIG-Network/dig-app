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
//! ([`hydrate`](dig_merkle::hydrate())), and the body's acceptance is `dig-social-profile`'s
//! [`VerifiedBody`]. Nothing is reimplemented — the duplication is three call lines, and the
//! alternative was a fabricated anchor.
//!
//! # A DID is resolved to a store id, and then it IS a store id
//!
//! `look_up_did` decodes a `did:chia:` string to its DID launcher and hands it to
//! `dig_account::resolve_profile_store` — the derived two-hop walk of dig-account `SPEC.md` §2.4.4a:
//! the DID's own lineage, each amount-0 intermediate RECOMPUTED from the `CREATE_COIN` in the DID
//! coin's spend, and each 1-mojo store launcher recomputed from the intermediate's spend. Nothing in
//! that chain is an id a source volunteered, which is why an index answer cannot put one person's
//! profile under another person's DID.
//!
//! The store id it derives then goes through `look_up` unchanged. There is deliberately no second
//! path from a DID to a rendered profile: the verification below is the only one, whichever way the
//! store id arrived.
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
use dig_account::{ProfileResolveError, ProfileStoreResolution};
use dig_chainsource_interface::ChainSource;
use dig_social_profile::body::{AnchoredRoot, VerifiedBody};
use dig_social_profile::value::Value;

use super::{DidOutcome, ViewedProfile};
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

    /// Resolve `did` — a `did:chia:` string — to the store that holds its profile, and look that up.
    ///
    /// A DID that RESOLVES MUST answer with the ordinary store states of the store it resolved to,
    /// so a resolved DID and that store id pasted by hand are indistinguishable on screen. Only the
    /// ways a DID fails to name a store are its own, and they arrive as
    /// [`ViewedProfile::Did`] — including two that are not failures of the lookup at all: an
    /// identity that is not on chain, and one that has launched SEVERAL stores.
    ///
    /// Required rather than defaulted: a default would be one implementation's guess rendered under
    /// every other implementation's name, and the guess would be about somebody's identity.
    fn look_up_did(&self, did: &str) -> ViewedProfile;
}

/// A DID reading that did not reach a store to look at.
fn unresolved(did: &str, outcome: DidOutcome) -> ViewedProfile {
    ViewedProfile::Did {
        did: did.to_string(),
        outcome,
    }
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
            Err(why) => {
                return ViewedProfile::Unreachable {
                    store_id: owned,
                    why,
                }
            }
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

    fn look_up_did(&self, did: &str) -> ViewedProfile {
        let launcher = match dig_did::launcher_id_from_did_string(did) {
            Ok(launcher) => launcher,
            // Nothing was asked of the chain, so nothing is claimed about it: the string itself is
            // not a DID, and the remedy is to copy it again rather than to check a profile.
            Err(why) => {
                return unresolved(
                    did,
                    DidOutcome::Malformed {
                        why: why.to_string(),
                    },
                )
            }
        };

        self.answer_for(
            did,
            dig_account::resolve_profile_store(self.chain.as_ref(), launcher),
        )
    }
}

impl<C> NodeStoreProfiles<C>
where
    C: ChainSource + Send + Sync,
{
    /// What a resolution came to, on screen.
    ///
    /// Separated from the reads because the MAPPING is where a row of the outcome table can silently
    /// borrow its neighbour's sentence, and a chain that produces all seven outcomes on demand is a
    /// fixture nobody has. Split out, every row is reachable from a test — including the two whose
    /// wrong answer is a lie about somebody's identity.
    fn answer_for(
        &self,
        did: &str,
        resolution: Result<ProfileStoreResolution, ProfileResolveError>,
    ) -> ViewedProfile {
        match resolution {
            // The whole point of the hop: from here it is an ordinary store lookup, through the same
            // reads, the same verification and the same states a pasted store id takes.
            Ok(ProfileStoreResolution::Resolved {
                store_launcher_id, ..
            }) => self.look_up(&hex::encode(store_launcher_id)),
            Ok(ProfileStoreResolution::NoProfileStore) => unresolved(did, DidOutcome::NoStore),
            // Every id, never a pick. Which one the asker meant is not in the chain data, so
            // choosing would be this app deciding whose profile a DID names.
            Ok(ProfileStoreResolution::Ambiguous(ids)) => unresolved(
                did,
                DidOutcome::Ambiguous(ids.iter().map(hex::encode).collect()),
            ),
            Err(ProfileResolveError::NoIdentitySingleton) => {
                unresolved(did, DidOutcome::NotOnChain)
            }
            Err(ProfileResolveError::ChainUnreachable(why)) => {
                unresolved(did, DidOutcome::Unreachable { why })
            }
            Err(ProfileResolveError::TooManyLaunches { limit }) => {
                unresolved(did, DidOutcome::TooMany { limit })
            }
            // `ProfileResolveError` is `#[non_exhaustive]`, so a catch-all is required here whatever
            // is enumerated above. It holds `Unparseable` — a lineage served incomplete, or data
            // that did not hold together — and any refusal a later dig-account adds. The resolver's
            // own words are carried through VERBATIM rather than summarised, so an outcome nobody
            // here anticipated still reaches the reader as its own sentence instead of a shrug.
            Err(refused) => unresolved(
                did,
                DidOutcome::Refused {
                    why: refused.to_string(),
                },
            ),
        }
    }

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
    use super::super::DidOutcome;
    use super::*;
    use crate::profile_edit::bodies::BodyStoreError;
    use dig_chainsource_interface::{ChainSourceError, MockChainSource};
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

    /// A body store that answers whatever it was built with, and records what it was asked.
    struct Bodies(Result<BodyRead, crate::profile_edit::bodies::BodyStoreError>);

    impl BodyStore for Bodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Err(BodyStoreError::Refused("this double never stores".into()))
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            self.0.clone()
        }
    }

    /// The source under test, over `chain`, whose node answers `body`.
    fn source(
        chain: MockChainSource,
        body: Result<BodyRead, BodyStoreError>,
    ) -> NodeStoreProfiles<MockChainSource> {
        NodeStoreProfiles::new(Arc::new(chain), Arc::new(Bodies(body)))
    }

    /// **A chain that cannot answer is not a profile that does not exist.**
    ///
    /// The two are one line apart in the read and have opposite remedies. The fixture is a chain
    /// that FAILS rather than one that is merely empty — an empty mock returns `Ok(None)` and would
    /// exercise the absent path while looking like a failure test.
    #[test]
    fn a_chain_that_will_not_answer_is_reported_as_unreachable() {
        let unreachable = source(
            MockChainSource::new().fail_with(ChainSourceError::Transport("no node".into())),
            Ok(BodyRead::Nothing),
        )
        .look_up(ID);
        match unreachable {
            ViewedProfile::Unreachable { store_id, why } => {
                assert_eq!(store_id, ID);
                assert!(why.contains("no node"), "the reason was swallowed: {why}");
            }
            other => panic!("a chain that could not answer was not reported as such: {other:?}"),
        }

        // The control: a chain that ANSWERS and holds no such store is the other verdict.
        let absent = source(MockChainSource::new(), Ok(BodyRead::Nothing)).look_up(ID);
        assert!(
            matches!(absent, ViewedProfile::NoProfile { .. }),
            "a chain with no such store was not reported as an absent profile: {absent:?}"
        );
    }

    /// A launcher id for a fixture, distinct per tag — the shape this crate's other tests use.
    fn launcher(tag: u8) -> Bytes32 {
        Bytes32::new([tag; 32])
    }

    /// A DID string of the shape dig-did encodes, DERIVED rather than written out: a hand-typed
    /// literal would be a second encoding of the same value, with its own chance to be wrong.
    fn did_for(tag: u8) -> String {
        dig_did::did_string_from_launcher_id(launcher(tag))
    }

    /// The source under test, over a chain that REFUSES every read.
    ///
    /// Every test below drives [`NodeStoreProfiles::answer_for`] with a resolution it supplies, so
    /// the chain must never be consulted for the answer under test. Arming it to fail means an
    /// implementation that went and asked anyway shows up as `Unreachable` instead of passing.
    fn unaskable() -> NodeStoreProfiles<MockChainSource> {
        source(
            MockChainSource::new()
                .fail_with(ChainSourceError::Transport("must not be asked".into())),
            Ok(BodyRead::Nothing),
        )
    }

    /// The DID outcome an answer came to, or a panic naming what it was instead.
    fn did_outcome(answer: ViewedProfile) -> DidOutcome {
        match answer {
            ViewedProfile::Did { outcome, .. } => outcome,
            other => panic!("a DID answer was not a DID reading: {other:?}"),
        }
    }

    /// **A chain that could not be read is NEVER reported as a DID with no profile.**
    ///
    /// The bolded row of the outcome table, and the one whose wrong answer is cruellest: rendered as
    /// an absence it tells a person their identity does not exist when this machine merely could not
    /// look. The control beside it is the real absence, so this test cannot pass against an
    /// implementation that refuses everything.
    #[test]
    fn a_chain_that_could_not_be_read_is_not_a_did_with_no_profile() {
        let did = did_for(0x21);
        let unreachable = did_outcome(unaskable().answer_for(
            &did,
            Err(ProfileResolveError::ChainUnreachable("no node".into())),
        ));
        match &unreachable {
            DidOutcome::Unreachable { why } => {
                assert!(why.contains("no node"), "the reason was swallowed: {why}");
            }
            other => panic!("a chain that could not answer was not reported as such: {other:?}"),
        }
        assert_ne!(
            unreachable,
            DidOutcome::NoStore,
            "an unasked question was answered as an absent profile"
        );
        assert_ne!(
            unreachable,
            DidOutcome::NotOnChain,
            "an unasked question was answered as an absent identity"
        );

        // The control: a chain that ANSWERED and found nothing is the other verdict entirely.
        assert_eq!(
            did_outcome(unaskable().answer_for(&did, Ok(ProfileStoreResolution::NoProfileStore))),
            DidOutcome::NoStore,
            "a DID that genuinely has no profile was not reported as one"
        );
    }

    /// **An ambiguous DID is refused, and never resolved to one of its stores.**
    ///
    /// The other bolded row. Picking either id would put one person's profile under another person's
    /// DID, so the assertions are that NEITHER id became the store this reading is about and that
    /// BOTH are carried for the reader to choose from.
    ///
    /// The fixture uses two DIFFERENT ids: with one repeated, an implementation that picked the
    /// first would be indistinguishable from one that refused.
    #[test]
    fn an_ambiguous_did_is_refused_rather_than_resolved_to_one_of_its_stores() {
        let did = did_for(0x22);
        let first = launcher(0xa1);
        let second = launcher(0xa2);
        assert_ne!(
            first, second,
            "the fixture's two stores are one store, so this test cannot see a pick"
        );

        let answer = unaskable().answer_for(
            &did,
            Ok(ProfileStoreResolution::Ambiguous(vec![first, second])),
        );
        assert_eq!(
            answer.store_id(),
            None,
            "an ambiguous DID resolved to a store, which shows one person's profile under another \
             person's identity: {answer:?}"
        );
        match did_outcome(answer) {
            DidOutcome::Ambiguous(ids) => assert_eq!(
                ids,
                vec![hex::encode(first), hex::encode(second)],
                "the choice a person has to make was not carried to them in full"
            ),
            other => panic!("two stores were not reported as a choice: {other:?}"),
        }
    }

    /// **A DID that is not on chain is told apart from one that has published nothing.**
    ///
    /// One says the identity is gone and the other says it is there and empty. They send a person to
    /// different places, so the assertion is on the DIFFERENCE rather than on either alone.
    #[test]
    fn a_did_with_no_coin_is_not_a_did_with_no_profile() {
        let did = did_for(0x23);
        let absent_identity = did_outcome(
            unaskable().answer_for(&did, Err(ProfileResolveError::NoIdentitySingleton)),
        );
        let absent_profile =
            did_outcome(unaskable().answer_for(&did, Ok(ProfileStoreResolution::NoProfileStore)));
        assert_eq!(absent_identity, DidOutcome::NotOnChain);
        assert_eq!(absent_profile, DidOutcome::NoStore);
        assert_ne!(
            absent_identity, absent_profile,
            "an identity that does not exist and one that has published nothing became one answer"
        );
    }

    /// **A DID past the disambiguation cap refuses to claim how many stores it has.**
    ///
    /// Distinct from an ambiguous one because that names a COMPLETE set: reporting a truncated list
    /// as though it were whole would be a claim about how many identities somebody published.
    #[test]
    fn a_did_past_the_cap_says_it_stopped_counting_rather_than_naming_a_number() {
        let did = did_for(0x24);
        let outcome = did_outcome(unaskable().answer_for(
            &did,
            Err(ProfileResolveError::TooManyLaunches {
                limit: dig_account::MAX_PROFILE_LAUNCHES_PER_DID,
            }),
        ));
        assert_eq!(
            outcome,
            DidOutcome::TooMany {
                limit: dig_account::MAX_PROFILE_LAUNCHES_PER_DID
            }
        );
        assert!(
            !matches!(outcome, DidOutcome::Ambiguous(_)),
            "a set the resolver stopped counting was reported as a complete choice"
        );
    }

    /// **Chain data the resolver would not trust is refused, never rendered.**
    ///
    /// A lineage served incomplete reaches here. The resolver's own words are carried through, so a
    /// reader is told what did not hold rather than given a shrug — and the reason is asserted, so an
    /// implementation that replaced it with a generic sentence fails.
    #[test]
    fn chain_data_the_resolver_refused_is_reported_with_the_reason_it_refused() {
        let did = did_for(0x25);
        let coin_id = launcher(0xa3);
        let outcome = did_outcome(unaskable().answer_for(
            &did,
            Err(ProfileResolveError::Unparseable {
                coin_id,
                reason: "the lineage arrived incomplete".into(),
            }),
        ));
        match outcome {
            DidOutcome::Refused { why } => assert!(
                why.contains("the lineage arrived incomplete"),
                "the resolver's reason was replaced by a summary: {why}"
            ),
            other => panic!("an untrusted answer was not refused: {other:?}"),
        }
    }

    /// **A string that is not a DID is answered without asking the chain anything.**
    ///
    /// The fixture's chain is armed to FAIL, so an implementation that went and asked would surface
    /// as `Unreachable` and fail here. Without that, both implementations would look the same.
    #[test]
    fn a_string_that_is_not_a_did_is_answered_without_asking_the_chain() {
        let outcome = did_outcome(unaskable().look_up_did("did:chia:1notavaliddidatall"));
        match outcome {
            DidOutcome::Malformed { why } => assert!(
                !why.is_empty(),
                "a refused string was refused without saying what was wrong with it"
            ),
            other => panic!(
                "a string that is not a DID reached the chain, or was reported as a chain \
                 failure: {other:?}"
            ),
        }
    }

    /// **A resolved DID answers EXACTLY as its store id pasted by hand.**
    ///
    /// The property that keeps a DID from being a second, divergent renderer of the same profile.
    /// Asserted as equality of the whole reading rather than of a variant, because the ways the two
    /// could drift are in the payload: a different store id, a different root, a different sentence.
    ///
    /// The chain here ANSWERS (it is empty rather than failing), so both sides reach a real verdict
    /// about a real store id. A failing chain would make both sides `Unreachable` and the equality
    /// would hold for the wrong reason.
    #[test]
    fn a_resolved_did_reads_exactly_as_its_store_id_pasted_by_hand() {
        let did = did_for(0x26);
        let store = launcher(0xa4);
        let did_coin = launcher(0xa5);

        let by_did = source(MockChainSource::new(), Ok(BodyRead::Nothing)).answer_for(
            &did,
            Ok(ProfileStoreResolution::Resolved {
                store_launcher_id: store,
                did_coin_id: did_coin,
            }),
        );
        let by_hand =
            source(MockChainSource::new(), Ok(BodyRead::Nothing)).look_up(&hex::encode(store));

        assert_eq!(
            by_did, by_hand,
            "a resolved DID and its store id pasted by hand produced different readings, so the \
             DID path renders the same profile a second way"
        );
        let by_hand_id = hex::encode(store);
        assert_eq!(
            by_did.store_id(),
            Some(by_hand_id.as_str()),
            "a resolved DID's reading was not about the store it resolved to"
        );
        assert!(
            by_did.did().is_none(),
            "a resolved DID stayed a DID reading, so it cannot render as the store it found"
        );
    }

    /// **A store id that is not 32 bytes of hex never reaches the chain.**
    ///
    /// The fixture arms the chain to FAIL, so an implementation that asked it anyway would return
    /// `Unreachable` and fail here. Without that the chain would answer `Ok(None)` and the two
    /// implementations would be indistinguishable.
    #[test]
    fn a_malformed_store_id_is_answered_without_asking_the_chain() {
        let answer = source(
            MockChainSource::new()
                .fail_with(ChainSourceError::Transport("must not be asked".into())),
            Ok(BodyRead::Nothing),
        )
        .look_up("not-a-store-id");
        assert!(
            matches!(answer, ViewedProfile::NoProfile { .. }),
            "a malformed store id reached the chain, or was reported as a chain failure: {answer:?}"
        );
    }
}
