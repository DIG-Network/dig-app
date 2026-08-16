//! The one file that turns [`ProfileEditSeam`] into real calls on dig-account.
//!
//! # Why the whole crate seam is one file
//!
//! Everything else in [`super`] is written against [`ProfileEditSeam`]'s five plain owned values, so
//! it holds no chia type, needs no node, and spends nothing in a test. That property is only worth
//! anything if there is exactly ONE place the real types enter, and this is it: `ProfileAnchor`,
//! `ProfileEditor`, `ChainSource`, `SpendPublisher` and `MintNetwork` appear here and nowhere else in
//! the editor.
//!
//! # §908 — the node signs nothing
//!
//! [`ProfileEditor::commit_edit`] builds the store-recreation spend and signs it in THIS process,
//! from the unlocked account's own seed, and hands the publisher an already-signed bundle. Nothing in
//! this file takes a key, a seed or a phrase, and the two seams it reaches the node through
//! ([`ChainSource`] reads, [`SpendPublisher`] pushes) have nowhere to put one.
//!
//! # The content seam, and the one absence that must NOT read as an empty profile
//!
//! dig-account verifies a profile body against the root the chain anchors, but it cannot fetch one —
//! a chain query has no way to return a store's off-chain content. So the host supplies
//! [`ProfileContentSource`], and here that is the node's own body store.
//!
//! Its contract says an empty `Vec` means *the store published no slots* and `Err` means *the source
//! could not answer*. [`BodyRead::Nothing`] is the SECOND of those, and mapping it to the first is
//! the defect this file is arranged around: a person shown an empty profile they cannot actually see
//! types their name into it and commits a body missing everything the profile already held. So
//! `Nothing` becomes an error, and it is tested from both sides.
//!
//! # Why `dig-social-profile` is named here
//!
//! `fetch_profile_slots` returns `(slot id, encoded value)` PAIRS and the persisted artifact is
//! canonical DPB BYTES, so something must decode one into the other. That framing is a byte contract
//! with golden vectors, and a second implementation of a byte contract is a future drift bug
//! (Appendix B) — so the crate that owns the format does the decoding, in
//! [`slots_of`](self::slots_of) and nowhere else. No type from it crosses any public API here.

use std::sync::Arc;

use chia_protocol::Bytes32;
use dig_account::edit::{EditError, ProfileContentSource, ProfileEdit};
use dig_account::mint::{MintNetwork, SpendPublisher};
use dig_account::registry::ProfileAnchor;
use dig_account::ProfileIx;
use dig_chainsource_interface::ChainSource;
use dig_social_profile::body::{AnchoredRoot, VerifiedBody};

use super::bodies::{BodyRead, BodyStore, BodyStoreError};
use super::commit::{CommitOutcome, ProfileEditError, ProfileEditSeam, ProfileSnapshot};
use super::draft::SlotChange;
use super::field::ProfileField;
use crate::account::residency::AccountResidency;

/// The node's body store, seen as the content source dig-account reads a profile through.
///
/// Holds no key and authorizes nothing: dig-account re-hashes whatever this returns and refuses
/// anything that does not equal the root the chain anchors, so a hostile answer here cannot make the
/// app report fields the chain does not back.
pub struct NodeProfileContent {
    /// Where the bytes are kept.
    bodies: Arc<dyn BodyStore>,
}

impl NodeProfileContent {
    /// A content source over `bodies`.
    pub fn new(bodies: Arc<dyn BodyStore>) -> Self {
        Self { bodies }
    }
}

impl ProfileContentSource for NodeProfileContent {
    type Error = BodyStoreError;

    fn fetch_profile_slots(
        &self,
        store_launcher_id: Bytes32,
        root: [u8; 32],
    ) -> Result<Vec<(u16, Vec<u8>)>, Self::Error> {
        let store_id = hex::encode(store_launcher_id);
        let root_hex = hex::encode(root);
        match self.bodies.get(&store_id, &root_hex)? {
            BodyRead::Held(bytes) => slots_of(&bytes, root),
            // The line this module's header is about. The node consulted its store and holds nothing
            // — which is NOT "this profile publishes no slots", and returning `vec![]` here would
            // hand dig-account an empty body to verify a real root against.
            BodyRead::Nothing => Err(BodyStoreError::Refused(format!(
                "your node does not hold the profile content for {root_hex}"
            ))),
        }
    }
}

/// Decode canonical DPB bytes into the `(slot id, encoded value)` pairs the crate seam speaks.
///
/// The root is not decoration: [`VerifiedBody::open`] refuses bytes that do not rebuild to it, so a
/// body that has been altered in transit is rejected HERE, before dig-account is ever handed it.
fn slots_of(bytes: &[u8], root: [u8; 32]) -> Result<Vec<(u16, Vec<u8>)>, BodyStoreError> {
    let body = VerifiedBody::open(bytes, AnchoredRoot::from_chain_read(root))
        .map_err(|e| BodyStoreError::Refused(format!("the stored profile content is unusable: {e}")))?;
    Ok(body
        .profile()
        .iter()
        .map(|(slot, value)| (slot.0, value.encode()))
        .collect())
}

/// The live seam: dig-account's editor, over this app's node.
///
/// Generic over its chain and publisher so a test can drive the whole thing against doubles with no
/// node and no money — the concrete pair the binary builds is
/// [`ControlChainSource`](crate::chain::ControlChainSource) and
/// [`ControlSpendPublisher`](crate::chain::ControlSpendPublisher).
pub struct AccountEditSeam<C, P> {
    /// The unlock the editor is derived from, per call, so a lock stops edits at the next one.
    residency: Arc<AccountResidency>,
    /// Which profile is edited, and which key signs for it.
    ix: ProfileIx,
    /// The store and DID this profile is anchored to.
    anchor: ProfileAnchor,
    /// Chain reads.
    chain: Arc<C>,
    /// The push, which takes an already-signed bundle (§908).
    publisher: Arc<P>,
    /// Where the profile's body is fetched from.
    content: NodeProfileContent,
    /// The signing domain. `MintNetwork::mainnet()` in the shipped binary.
    network: MintNetwork,
}

impl<C, P> AccountEditSeam<C, P>
where
    C: ChainSource + Send + Sync,
    P: SpendPublisher + Send + Sync,
{
    /// Assemble the seam for the profile at `ix`, anchored at `anchor`.
    #[allow(clippy::too_many_arguments, reason = "each argument is a distinct authority")]
    pub fn new(
        residency: Arc<AccountResidency>,
        ix: ProfileIx,
        anchor: ProfileAnchor,
        chain: Arc<C>,
        publisher: Arc<P>,
        bodies: Arc<dyn BodyStore>,
        network: MintNetwork,
    ) -> Self {
        Self {
            residency,
            ix,
            anchor,
            chain,
            publisher,
            content: NodeProfileContent::new(bodies),
            network,
        }
    }

    /// The store this profile's content lives in, lowercase 64-hex — the id the body store is keyed
    /// by, and the one a caller passes to `commit_and_persist`.
    pub fn store_id(&self) -> String {
        hex::encode(self.anchor.store_launcher_id())
    }
}

impl<C, P> ProfileEditSeam for AccountEditSeam<C, P>
where
    C: ChainSource + Send + Sync,
    P: SpendPublisher + Send + Sync,
{
    fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
        let snapshot = dig_account::edit::read_profile(&self.anchor, &*self.chain, &self.content)
            .map_err(edit_error)?;
        Ok(ProfileSnapshot {
            store_id: self.store_id(),
            root: hex::encode(snapshot.root()),
            values: snapshot
                .fields()
                .iter()
                .filter_map(|(slot, value)| {
                    Some((ProfileField::of_slot(slot)?, value.to_string()))
                })
                .collect(),
            body_len: snapshot.body_bytes().len(),
        })
    }

    fn commit(
        &self,
        changes: &[(ProfileField, SlotChange)],
    ) -> Result<CommitOutcome, ProfileEditError> {
        // Derived per call, never cached: an edit spends real XCH, so an editor kept across a
        // lock-now or an idle timeout would go on spending after the user locked. Exactly the rule
        // `AccountResidency::profile_minter` is written to.
        let editor = self
            .residency
            .profile_editor()
            .ok_or(ProfileEditError::Locked)?;

        let committed = editor
            .commit_edit(
                self.ix,
                &self.anchor,
                &batch_of(changes),
                &*self.chain,
                &self.content,
                &*self.publisher,
                &self.network,
            )
            .map_err(edit_error)?;

        Ok(CommitOutcome {
            status: committed.status().clone(),
            root: hex::encode(committed.root()),
            body: committed.body_bytes().to_vec(),
        })
    }

    fn confirmation(&self, root: &str) -> Result<Option<u32>, ProfileEditError> {
        let editor = self
            .residency
            .profile_editor()
            .ok_or(ProfileEditError::Locked)?;
        let wanted = root_bytes(root)?;

        // Whether the chain anchors it at all. This answers yes/no and carries no height, which is
        // why the height is read separately below rather than inferred from the yes.
        if editor
            .edit_status(&self.anchor, wanted, &*self.chain)
            .map_err(edit_error)?
            .confirmed_root()
            .is_none()
        {
            return Ok(None);
        }
        self.tip_height()
    }
}

impl<C, P> AccountEditSeam<C, P>
where
    C: ChainSource + Send + Sync,
    P: SpendPublisher + Send + Sync,
{
    /// The height the store's CURRENT tip coin confirmed at.
    ///
    /// The tip coin is the one the edit created, so its confirmation height is the height of the
    /// edit — which is what a person is told. Deliberately not the peak: a peak height is the chain's
    /// tip and says nothing about when this change landed.
    ///
    /// A tip with no confirmed height is answered `Ok(None)` — *the chain does not prove it yet* —
    /// rather than a fabricated block. The surface then keeps showing the write as pushed, which is
    /// the conservative direction: it under-claims rather than naming a block nobody read.
    fn tip_height(&self) -> Result<Option<u32>, ProfileEditError> {
        let lineage = self
            .chain
            .resolve_singleton_lineage(self.anchor.store_launcher_id())
            .map_err(|e| ProfileEditError::ChainUnreachable(e.to_string()))?;
        let Some(lineage) = lineage else {
            return Ok(None);
        };
        Ok(self
            .chain
            .coin_record(lineage.tip())
            .map_err(|e| ProfileEditError::ChainUnreachable(e.to_string()))?
            .and_then(|record| record.confirmed_height))
    }
}

/// Turn the editor's changes into the crate's batch.
///
/// The field-to-slot mapping is [`ProfileField::slot`] and is not restated here: a second table of
/// the same slot numbers is the byte-drift bug that file's header argues against, and it is the one
/// that would write an inline image into the `dig://` reference slot.
fn batch_of(changes: &[(ProfileField, SlotChange)]) -> ProfileEdit {
    changes
        .iter()
        .fold(ProfileEdit::new(), |edit, (field, change)| match change {
            SlotChange::Set(text) => edit.set(field.slot(), text.clone()),
            SlotChange::Remove => edit.remove(field.slot()),
        })
}

/// Parse a 64-hex root into the bytes the crate takes.
fn root_bytes(root: &str) -> Result<[u8; 32], ProfileEditError> {
    let bytes = hex::decode(root)
        .map_err(|e| ProfileEditError::Refused(format!("that is not a root: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ProfileEditError::Refused(format!("a root is 32 bytes; {root} is not")))
}

/// The crate's failure, in the editor's vocabulary.
///
/// The two arms that must never merge are [`EditError::Rejected`] and
/// [`EditError::ChainUnreachable`]: a rejected edit left the store's root unchanged and is rebuilt,
/// an unanswered one may still confirm and is WAITED on. Collapsing them tells a person to try again
/// while their first attempt is in the mempool, which spends twice.
fn edit_error(error: EditError) -> ProfileEditError {
    match error {
        EditError::ChainUnreachable(why) => ProfileEditError::ChainUnreachable(why),
        EditError::Rejected(why) => ProfileEditError::Rejected(why),
        EditError::Locked => ProfileEditError::Locked,
        EditError::Refused(why) | EditError::Build(why) => ProfileEditError::Refused(why),
        EditError::NoStore => ProfileEditError::Unreadable(
            "this profile has no store on chain yet, so there is nothing to edit".to_string(),
        ),
        EditError::StaleOrTamperedContent => ProfileEditError::Unreadable(
            "your profile's content does not match what the blockchain says it should be, so DIG \
             will not show or change it"
                .to_string(),
        ),
        EditError::ContentUnavailable(why) => ProfileEditError::Unreadable(why),
        EditError::Format(why) => ProfileEditError::Unreadable(why),
    }
}

#[cfg(test)]
mod tests {
    use dig_account::edit::ProfileSlot;
    use dig_social_profile::profile::Profile;
    use dig_social_profile::slot::SlotId;
    use dig_social_profile::value::Value;

    use super::super::bodies::doubles::InMemoryBodies;
    use super::*;

    /// A body publishing a display name and one slot the editor does not name, with its real root.
    fn a_body() -> (Vec<u8>, [u8; 32]) {
        let mut profile = Profile::new();
        profile.set(SlotId(ProfileSlot::DisplayName.id()), Value::Utf8("Ada".into()));
        // A slot the form has no field for. It must survive a round trip, because the new root is
        // computed over the WHOLE body and a decode that dropped it would silently delete it.
        profile.set(SlotId(ProfileSlot::Avatar.id()), Value::Utf8("dig://av".into()));
        let body = VerifiedBody::from_profile(&profile).expect("a body");
        (body.as_bytes().to_vec(), body.root())
    }

    const STORE: Bytes32 = Bytes32::new([0x11; 32]);

    /// The decode is the round trip dig-account's own read performs, so every slot comes back —
    /// including the one the editor has no field for.
    #[test]
    fn every_published_slot_survives_the_decode_including_one_the_form_cannot_show() {
        let (bytes, root) = a_body();
        let slots = slots_of(&bytes, root).expect("decodes");
        let ids: Vec<u16> = slots.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&ProfileSlot::DisplayName.id()));
        assert!(
            ids.contains(&ProfileSlot::Avatar.id()),
            "a slot the form does not name was dropped by the decode, which deletes it on the next \
             commit"
        );
    }

    /// Bytes that do not rebuild to the root the CHAIN gave are refused here, before dig-account is
    /// handed them — the guard that stops a hostile body store answering for someone's profile.
    #[test]
    fn a_body_that_does_not_rebuild_to_the_chains_root_is_refused() {
        let (bytes, _) = a_body();
        assert!(
            slots_of(&bytes, [0x99; 32]).is_err(),
            "a body was accepted against a root it does not commit to"
        );
    }

    /// The whole reason this module exists: a node that HOLDS NOTHING is an error, never an empty
    /// profile.
    ///
    /// The fixture holds a real body at a DIFFERENT root, so the store is working and answering —
    /// which is what makes this see the mapping rather than a store that fails everything. A source
    /// that returned `Ok(vec![])` here would hand dig-account an empty body for a real root, and the
    /// person would edit over a profile they never saw.
    #[test]
    fn a_node_holding_nothing_is_an_error_and_never_an_empty_slot_list() {
        let bodies = InMemoryBodies::default();
        let (bytes, root) = a_body();
        bodies
            .put(&hex::encode(STORE), &hex::encode(root), &bytes)
            .expect("stores");

        let content = NodeProfileContent::new(Arc::new(bodies));
        // Asked for a root the store has never been given.
        let answer = content.fetch_profile_slots(STORE, [0x77; 32]);
        assert!(
            matches!(answer, Err(BodyStoreError::Refused(_))),
            "a node that holds nothing answered as a profile with no slots: {answer:?}"
        );
        // The control: the SAME store answers fully for the root it does hold, so the refusal above
        // is about the absence and not about the store.
        assert!(!content
            .fetch_profile_slots(STORE, root)
            .expect("the held root reads")
            .is_empty());
    }

    /// A change list becomes the crate's batch with removals still removals — the half a
    /// `map<field, String>` would have flattened into "set to empty", which publishes an empty
    /// string where the person asked for the field to be gone.
    #[test]
    fn a_removal_reaches_the_crate_as_a_removal() {
        let batch = batch_of(&[
            (ProfileField::Bio, SlotChange::Remove),
            (ProfileField::DisplayName, SlotChange::Set("Ada".into())),
        ]);
        let before = dig_account::edit::ProfileFields::new();
        let after = batch.preview(&before);
        assert_eq!(after.display_name(), Some("Ada"));
        assert_eq!(batch.len(), 2, "both changes reached the batch");
    }

    /// The two failures whose remedies INVERT stay apart. Merging them tells a person whose bundle
    /// is in the mempool to send it again.
    #[test]
    fn an_unanswered_chain_is_not_a_rejection() {
        assert!(matches!(
            edit_error(EditError::ChainUnreachable("timeout".into())),
            ProfileEditError::ChainUnreachable(_)
        ));
        assert!(matches!(
            edit_error(EditError::Rejected("double spend".into())),
            ProfileEditError::Rejected(_)
        ));
        assert!(
            !edit_error(EditError::ChainUnreachable("timeout".into())).profile_is_unchanged(),
            "an unanswered push was reported as leaving the profile unchanged"
        );
    }

    /// A read failure is worded for a READ. The commit wording announces a transaction the person
    /// never made.
    #[test]
    fn an_unreadable_profile_does_not_speak_of_a_transaction() {
        let sentence = edit_error(EditError::StaleOrTamperedContent).while_reading();
        assert!(!sentence.contains("sent to the blockchain"), "{sentence}");
    }
}
