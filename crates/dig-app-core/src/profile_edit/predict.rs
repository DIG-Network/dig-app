//! The body an edit WILL produce, computed before the spend that commits to it goes out.
//!
//! # Why this exists at all (dig_ecosystem#3066)
//!
//! `ProfileEditor::commit_edit` computes the new body and pushes the spend in one call, so by the
//! time this app is handed the bytes the root is already heading for a mempool. Between those two
//! moments the preimage of a root that will be committed forever exists nowhere but this process's
//! memory. To write it down BEFORE the push, the app has to know it before the push — which means
//! computing it here.
//!
//! # The format is not reimplemented, and the prediction is never trusted
//!
//! Every step is `dig-social-profile`'s own: open the verified body, apply the slot edits, build
//! the next body. Those are the same three calls dig-account makes, over the same types, so this is
//! a USE of the format authority rather than a second copy of it.
//!
//! It is still a prediction, and it is treated as one. [`super::commit::commit_and_persist`]
//! compares the predicted root against the root the commit actually returned, and a prediction that
//! did not match is discarded THERE, in the same call, before it can outlive the attempt that made
//! it. A wrong prediction therefore costs one superfluous file write and never a wrong body.
//!
//! The durable fix is for dig-account to expose the prepare/publish split so no prediction is
//! needed; until it does, this is what closes the window without a crates.io release.

use dig_social_profile::body::{AnchoredRoot, VerifiedBody};
use dig_social_profile::profile::{Profile, SlotEdit};
use dig_social_profile::slot::SlotId;
use dig_social_profile::value::Value;

use super::draft::SlotChange;
use super::field::ProfileField;

/// The body `changes` will produce over `current_body`, and the root it commits to.
///
/// `current_body` must be the bytes the chain's `current_root` anchors; they are verified against
/// it here, so a body that does not belong to that root predicts nothing rather than predicting
/// something wrong.
///
/// Returns `None` when no honest prediction is possible — unverifiable bytes, or an edited profile
/// the format refuses to encode. `None` is never an error to report: the commit proceeds and the
/// real bytes are written down the moment it returns, which is the behaviour that shipped before
/// this existed.
pub fn predicted_body(
    current_body: &[u8],
    current_root: [u8; 32],
    changes: &[(ProfileField, SlotChange)],
) -> Option<(String, Vec<u8>)> {
    let opened =
        VerifiedBody::open(current_body, AnchoredRoot::from_chain_read(current_root)).ok()?;
    let mut next = opened.into_profile();
    next.apply_all(slot_edits(changes));
    let body = VerifiedBody::from_profile(&next).ok()?;
    Some((hex::encode(body.root()), body.as_bytes().to_vec()))
}

/// The profile a FRESH publish writes: `changes` over an empty profile, nothing read.
///
/// # Why the whole profile is built here and not at the seam
///
/// The bytes this produces are sealed to the pending file BEFORE the spend goes out
/// (dig_ecosystem#3066), and the seam then publishes the profile it is handed. Both halves must be
/// the SAME profile down to the byte, because the pre-spend copy is only the preimage of the root
/// the chain confirms if it is. One constructor, used by both, is the only version of that which
/// cannot drift.
///
/// [`Profile::new`] carries the schema version, which a published profile may not be without —
/// dig-account refuses one that lacks it before spending anything.
pub fn fresh_profile(changes: &[(ProfileField, SlotChange)]) -> Profile {
    let mut profile = Profile::new();
    profile.apply_all(slot_edits(changes));
    profile
}

/// The body a fresh publish of `changes` will produce, and the root it commits to.
///
/// `None` when the format refuses to encode it — an over-long value, an inline image past the
/// format's bounds. As with [`predicted_body`], that is not an error to report: it means this
/// attempt has only the post-commit copy to fall back on.
pub fn fresh_body(changes: &[(ProfileField, SlotChange)]) -> Option<(String, Vec<u8>)> {
    let body = VerifiedBody::from_profile(&fresh_profile(changes)).ok()?;
    Some((hex::encode(body.root()), body.as_bytes().to_vec()))
}

/// The editor's changes in the schema crate's own edit vocabulary.
///
/// The slot ids come from [`ProfileField::slot`] and are not restated — the same single mapping
/// every other part of the editor goes through.
fn slot_edits(changes: &[(ProfileField, SlotChange)]) -> Vec<SlotEdit> {
    changes
        .iter()
        .map(|(field, change)| {
            let slot = SlotId(field.slot().id());
            match change {
                SlotChange::Set(text) => SlotEdit::Set(slot, Value::Utf8(text.clone())),
                SlotChange::Remove => SlotEdit::Remove(slot),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use super::*;

    /// A profile publishing a name, a bio, and a slot this editor has no field for.
    fn a_profile() -> Profile {
        let mut profile = Profile::new();
        profile.set(
            SlotId(ProfileField::DisplayName.slot().id()),
            Value::Utf8("Ada".into()),
        );
        profile.set(
            SlotId(ProfileField::Bio.slot().id()),
            Value::Utf8("Builds engines.".into()),
        );
        profile.set(SlotId(0x0003), Value::Utf8("dig://avatar".into()));
        profile
    }

    /// The body and root of [`a_profile`].
    fn a_body() -> (Vec<u8>, [u8; 32]) {
        let body = VerifiedBody::from_profile(&a_profile()).expect("a body");
        (body.as_bytes().to_vec(), body.root())
    }

    /// The prediction advances the profile the way the editor asked: a set lands, a removal
    /// removes.
    ///
    /// # What tells this apart from dig-account, and where that is actually checked
    ///
    /// This cannot prove the prediction matches what `commit_edit` will compute — only a real
    /// commit can, and nothing here has one. That comparison happens at RUNTIME, on every save:
    /// [`super::commit::commit_and_persist`] holds the predicted root beside the root the commit
    /// returned and discards the prediction when they differ, which is asserted in that module.
    /// What this pins is that the prediction is an honest application of the changes.
    #[test]
    fn a_prediction_applies_the_changes_it_was_given() {
        let (bytes, root) = a_body();
        let changes = vec![
            (
                ProfileField::DisplayName,
                SlotChange::Set("Ada Lovelace".into()),
            ),
            (ProfileField::Bio, SlotChange::Remove),
        ];

        let (predicted_root, predicted) = predicted_body(&bytes, root, &changes).expect("predicts");
        let opened = VerifiedBody::open(
            &predicted,
            AnchoredRoot::from_chain_read(root_bytes(&predicted_root)),
        )
        .expect("the predicted body opens at the predicted root");

        assert_eq!(opened.profile().display_name(), Some("Ada Lovelace"));
        assert_eq!(
            opened.profile().bio(),
            None,
            "a removal left the slot in place, so the edit publishes a value the person deleted"
        );
    }

    /// A 64-hex root as bytes.
    fn root_bytes(hex_root: &str) -> [u8; 32] {
        hex::decode(hex_root)
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    /// A slot the editor does not name SURVIVES the prediction. The new root is computed over the
    /// whole body, so a prediction that dropped it would commit to deleting it.
    #[test]
    fn a_slot_the_editor_cannot_show_survives_the_prediction() {
        let (bytes, root) = a_body();
        let (_, predicted) = predicted_body(
            &bytes,
            root,
            &[(
                ProfileField::DisplayName,
                SlotChange::Set("Ada Lovelace".into()),
            )],
        )
        .expect("predicts");

        assert!(
            String::from_utf8_lossy(&predicted).contains("dig://avatar"),
            "a slot the form has no field for was dropped, which deletes it on chain"
        );
    }

    /// Bytes that do not belong to the root the chain anchors predict NOTHING.
    ///
    /// # The fixture, and its control
    ///
    /// The bytes are a real, well-formed body — just one for a different profile — so what is being
    /// caught is the body/root mismatch itself and not malformed input. The control beside it is
    /// the same body at its OWN root, which must predict fine.
    #[test]
    fn a_body_that_does_not_belong_to_the_root_predicts_nothing() {
        let (bytes, root) = a_body();
        let changes = [(ProfileField::Bio, SlotChange::Set("new".into()))];

        assert!(
            predicted_body(&bytes, [0x77; 32], &changes).is_none(),
            "a body was advanced against a root it does not commit to"
        );
        assert!(
            predicted_body(&bytes, root, &changes).is_some(),
            "the control failed, so the refusal above says nothing about the mismatch"
        );
    }

    /// A prediction commits to what it says it does: the returned root is the root of the returned
    /// bytes, which is the only property the pending file relies on.
    #[test]
    fn the_predicted_root_is_the_root_of_the_predicted_bytes() {
        let (bytes, root) = a_body();
        let (predicted_root, predicted) = predicted_body(
            &bytes,
            root,
            &[(
                ProfileField::Bio,
                SlotChange::Set("Builds better engines.".into()),
            )],
        )
        .expect("predicts");

        assert!(
            VerifiedBody::open(
                &predicted,
                AnchoredRoot::from_chain_read(root_bytes(&predicted_root))
            )
            .is_ok(),
            "the predicted bytes do not commit to the predicted root, so the pending file would \
             hold a body no node can ever accept"
        );
        assert_ne!(
            predicted_root,
            hex::encode(root),
            "the edit changed nothing"
        );
    }
}
