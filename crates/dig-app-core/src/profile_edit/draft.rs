//! What a person has typed into the profile editor, and what it would cost to commit it.
//!
//! # The two questions this type answers
//!
//! *What would change?* — [`ProfileDraft::changes`], the set handed to the crate. A field typed back
//! to the value it already held is NOT a change, and a field emptied is a REMOVAL, not an empty
//! string: those are different acts on the SMT and only one of them leaves a slot behind.
//!
//! *Would it fit?* — [`ProfileDraft::problem`] and [`ProfileDraft::oversize`]. A profile body has two
//! separate ceilings and an image can cross either, so the editor answers before the person has
//! finished filling the form rather than after the body is assembled.
//!
//! # Why the size arithmetic is exact rather than approximate
//!
//! The DPB encoding is fixed and public (`dig-social-profile` `src/body.rs`): a 5-byte header, then
//! per slot a 6-byte record header wrapping a 5-byte value header and the payload. So a projected
//! body size is a subtraction and an addition on a length this app already knows — the bytes it read
//! — not a guess with a safety margin. A margin would be the wrong shape anyway: too small and it
//! promises a body that will be refused, too large and it refuses one that would have fit.

use std::collections::BTreeMap;

use super::field::ProfileField;

/// Bytes of DPB header on the body as a whole.
const BODY_HEADER_LEN: usize = 5;

/// Bytes of framing one slot costs beyond its payload: the record header (slot id + length) plus the
/// value header (tag + length).
const SLOT_FRAMING_LEN: usize = 6 + 5;

/// The largest ONE slot's encoded value may be — `dig_social_profile::body::MAX_SLOT_BYTES`.
///
/// The tighter of the two ceilings by a factor of three, and the one an image actually meets. Stated
/// as the payload budget a person has, which is this constant less the value framing.
pub const MAX_SLOT_PAYLOAD: usize = 1_400_000 - 5;

/// The largest a whole profile body may be — `dig_node_control_interface::params::MAX_BODY_BYTES`,
/// which is `dig-social-profile`'s own `MAX_BODY_BYTES`.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// What a commit would do to one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotChange {
    /// Put this value in the slot, replacing anything there.
    Set(String),
    /// Take the slot out of the profile entirely.
    Remove,
}

/// The profile as it stands, and what the person has typed over it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileDraft {
    /// The values the profile holds right now, as read and verified against the chain-anchored root.
    committed: BTreeMap<ProfileField, String>,
    /// What is in each input. A field absent here has not been touched.
    typed: BTreeMap<ProfileField, String>,
    /// How many bytes the body this draft edits came to. The base every projection adjusts.
    committed_body_len: usize,
}

impl ProfileDraft {
    /// A draft over a profile that has been read.
    ///
    /// `committed_body_len` is the length of the bytes the read produced — including the slots this
    /// editor never shows, which occupy the same budget as the ones it does.
    pub fn over(values: BTreeMap<ProfileField, String>, committed_body_len: usize) -> Self {
        Self {
            committed: values,
            typed: BTreeMap::new(),
            committed_body_len,
        }
    }

    /// A draft over a profile with no fields set — a real state, not a failure.
    pub fn empty() -> Self {
        Self::over(BTreeMap::new(), BODY_HEADER_LEN)
    }

    /// What the input for `field` should show.
    pub fn value(&self, field: ProfileField) -> &str {
        self.typed
            .get(&field)
            .or_else(|| self.committed.get(&field))
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// What the profile holds for `field` right now, ignoring anything typed.
    pub fn committed_value(&self, field: ProfileField) -> Option<&str> {
        self.committed.get(&field).map(String::as_str)
    }

    /// Take what a person typed.
    pub fn set(&mut self, field: ProfileField, value: impl Into<String>) {
        self.typed.insert(field, value.into());
    }

    /// Empty a field. Committed, this REMOVES the slot rather than setting it to nothing.
    pub fn clear(&mut self, field: ProfileField) {
        self.typed.insert(field, String::new());
    }

    /// Whether the profile holds no editable field at all — the empty state the editor names.
    pub fn is_empty(&self) -> bool {
        self.committed.values().all(|value| value.is_empty())
    }

    /// What a commit would change, in slot order, with nothing in it that is not a change.
    ///
    /// The three cases that must not collapse into each other:
    /// a field typed back to what it already held is absent; a field emptied that HELD something is
    /// a [`SlotChange::Remove`]; a field emptied that held nothing is absent, because removing a
    /// slot the profile does not have is a chain write that buys nothing.
    pub fn changes(&self) -> Vec<(ProfileField, SlotChange)> {
        self.typed
            .iter()
            .filter_map(|(field, typed)| {
                let held = self.committed.get(field).map(String::as_str);
                match (typed.as_str(), held) {
                    (typed, Some(held)) if typed == held => None,
                    ("", None) => None,
                    ("", Some(_)) => Some((*field, SlotChange::Remove)),
                    (typed, _) => Some((*field, SlotChange::Set(typed.to_string()))),
                }
            })
            .collect()
    }

    /// Whether there is anything to commit.
    pub fn is_dirty(&self) -> bool {
        !self.changes().is_empty()
    }

    /// How large the body this draft would produce comes to.
    ///
    /// Exact, by construction: the committed length, less what each changed field costs today, plus
    /// what it would cost after. The slots this editor never shows are inside the base and are
    /// therefore counted without being enumerated.
    pub fn projected_body_len(&self) -> usize {
        let mut len = self.committed_body_len as isize;
        for (field, change) in self.changes() {
            if let Some(held) = self.committed.get(&field) {
                len -= slot_cost(held) as isize;
            }
            if let SlotChange::Set(value) = change {
                len += slot_cost(&value) as isize;
            }
        }
        len.max(BODY_HEADER_LEN as isize) as usize
    }

    /// What is wrong with `field`'s current contents, in words a person can act on.
    ///
    /// Only ONE ceiling is reported per field, and it is the one that would refuse first: told about
    /// the whole-body budget while their single image is also three times the per-slot limit, a
    /// person removes the wrong thing.
    pub fn problem(&self, field: ProfileField) -> Option<String> {
        let value = self.value(field);
        if value.len() > MAX_SLOT_PAYLOAD {
            return Some(too_large_for_one_slot(field, value.len()));
        }
        let projected = self.projected_body_len();
        if projected > MAX_BODY_BYTES && self.contributes(field) {
            return Some(too_large_for_the_body(projected));
        }
        None
    }

    /// Whether the draft as a whole cannot be committed at any price.
    pub fn oversize(&self) -> bool {
        ProfileField::ALL
            .iter()
            .any(|field| self.problem(*field).is_some())
    }

    /// Whether this draft is ready to be committed: something to say, and nothing wrong with it.
    pub fn is_committable(&self) -> bool {
        self.is_dirty() && !self.oversize()
    }

    /// Whether `field` is one of the fields putting weight on the body budget.
    ///
    /// A body over budget is a fact about the WHOLE profile, but hanging that sentence on a field a
    /// person left empty tells them to shorten nothing.
    fn contributes(&self, field: ProfileField) -> bool {
        !self.value(field).is_empty()
    }
}

/// What one slot holding `value` costs inside a body.
fn slot_cost(value: &str) -> usize {
    match value.is_empty() {
        true => 0,
        false => SLOT_FRAMING_LEN + value.len(),
    }
}

/// The sentence for a value no single slot can hold.
///
/// Names the field, the two numbers, and the ONE thing that fixes it. An image is the only value
/// that ever reaches this, so the remedy is written for an image without pretending text cannot.
fn too_large_for_one_slot(field: ProfileField, len: usize) -> String {
    format!(
        "This {} is {} and the largest one thing a profile can hold is {}. Choose a smaller file, \
         or a smaller version of this one.",
        field.label().to_lowercase(),
        megabytes(len),
        megabytes(MAX_SLOT_PAYLOAD),
    )
}

/// The sentence for a profile that fits in no single field but not all together.
fn too_large_for_the_body(projected: usize) -> String {
    format!(
        "Your whole profile would come to {}, and a profile can hold {}. Removing or shrinking one \
         of the images is usually the quickest way down.",
        megabytes(projected),
        megabytes(MAX_BODY_BYTES),
    )
}

/// A byte count as a person reads it. One decimal place: the difference between 4.0 and 4.4 MB is
/// the difference between "nearly" and "nowhere near", and a rounded whole number hides it.
fn megabytes(bytes: usize) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A draft over a profile holding a display name and a bio.
    fn a_profile() -> ProfileDraft {
        let mut values = BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada".to_string());
        values.insert(ProfileField::Bio, "Builds engines.".to_string());
        let len = BODY_HEADER_LEN + slot_cost("Ada") + slot_cost("Builds engines.");
        ProfileDraft::over(values, len)
    }

    #[test]
    fn an_untouched_draft_changes_nothing() {
        assert!(!a_profile().is_dirty());
        assert_eq!(a_profile().changes(), vec![]);
    }

    /// Typing a value back to what it already was is not a chain write.
    #[test]
    fn retyping_the_committed_value_is_not_a_change() {
        let mut draft = a_profile();
        draft.set(ProfileField::DisplayName, "Ada");
        assert!(!draft.is_dirty());
    }

    /// The distinction the SMT actually cares about: an emptied field is a REMOVAL.
    #[test]
    fn emptying_a_field_that_held_something_removes_the_slot() {
        let mut draft = a_profile();
        draft.clear(ProfileField::Bio);
        assert_eq!(
            draft.changes(),
            vec![(ProfileField::Bio, SlotChange::Remove)]
        );
    }

    /// And the case that distinguishes a removal from an empty set: a field that held nothing.
    /// A `Set("")` here would write an empty slot, and a `Remove` would spend money removing a slot
    /// the profile does not have.
    #[test]
    fn emptying_a_field_that_held_nothing_is_not_a_change() {
        let mut draft = a_profile();
        draft.clear(ProfileField::Location);
        assert!(!draft.is_dirty(), "changes: {:?}", draft.changes());
    }

    #[test]
    fn a_new_value_on_an_unset_field_is_a_set() {
        let mut draft = a_profile();
        draft.set(ProfileField::Location, "Nairobi");
        assert_eq!(
            draft.changes(),
            vec![(
                ProfileField::Location,
                SlotChange::Set("Nairobi".to_string())
            )]
        );
    }

    /// A profile with no fields set is a real state the editor names, not an error.
    #[test]
    fn a_profile_with_no_fields_reads_as_empty() {
        assert!(ProfileDraft::empty().is_empty());
        assert!(!a_profile().is_empty());
    }

    // -- the size ceilings ---------------------------------------------------------------------

    /// A data URL of `len` bytes, so a fixture's size is the thing under test rather than its shape.
    fn an_image_of(len: usize) -> String {
        let prefix = "data:image/png;base64,";
        format!("{prefix}{}", "A".repeat(len - prefix.len()))
    }

    /// The per-slot ceiling, pinned from BOTH sides. A bound tested only from above cannot tell a
    /// correct limit from one that refuses everything.
    #[test]
    fn one_image_at_the_slot_ceiling_is_accepted_and_one_byte_over_is_not() {
        let mut at_bound = ProfileDraft::empty();
        at_bound.set(ProfileField::Avatar, an_image_of(MAX_SLOT_PAYLOAD));
        assert_eq!(at_bound.problem(ProfileField::Avatar), None);

        let mut over = ProfileDraft::empty();
        over.set(ProfileField::Avatar, an_image_of(MAX_SLOT_PAYLOAD + 1));
        assert!(over.problem(ProfileField::Avatar).is_some());
        assert!(!over.is_committable());
    }

    /// The fixture that distinguishes a whole-body check from a per-field one.
    ///
    /// # Why three fields and not two
    ///
    /// The obvious fixture — two images, each at the per-slot ceiling — does NOT cross the body
    /// ceiling: 2 × 1.4 MB is 2.8 MB against a 4 MiB budget, so a per-field-only implementation
    /// passes it and so does a correct one, which proves nothing. The fixture sizes have to come
    /// from the format's own two numbers rather than from what looks extreme. Three legal fields,
    /// summing over the budget, is the smallest arrangement no per-field check can catch.
    #[test]
    fn three_legal_fields_that_do_not_fit_together_are_refused_before_the_body_is_built() {
        let each = an_image_of(MAX_SLOT_PAYLOAD);
        let mut draft = ProfileDraft::empty();
        draft.set(ProfileField::Avatar, each.clone());
        draft.set(ProfileField::Banner, each);
        assert_eq!(
            draft.problem(ProfileField::Avatar),
            None,
            "two images at the slot ceiling still fit in a body: {}",
            draft.projected_body_len()
        );

        draft.set(ProfileField::Bio, "b".repeat(MAX_SLOT_PAYLOAD));
        assert!(
            draft.projected_body_len() > MAX_BODY_BYTES,
            "the fixture must actually cross the body ceiling: {}",
            draft.projected_body_len()
        );
        assert!(draft.problem(ProfileField::Avatar).is_some());
        assert!(draft.problem(ProfileField::Bio).is_some());
        assert!(!draft.is_committable());
    }

    /// The whole-body ceiling from BOTH sides, on a draft that sits exactly on it.
    ///
    /// Built from THREE slots because no single one may exceed 1.4 MB: a 4 MiB payload in one field
    /// is refused by the per-slot ceiling first, and a test written that way pins the wrong bound
    /// while looking like it pins this one.
    #[test]
    fn a_body_exactly_at_the_ceiling_is_accepted_and_one_byte_over_is_not() {
        let big = an_image_of(MAX_SLOT_PAYLOAD);
        let two_images = 2 * slot_cost(&big);
        let rest = MAX_BODY_BYTES - BODY_HEADER_LEN - two_images - SLOT_FRAMING_LEN;
        assert!(
            rest <= MAX_SLOT_PAYLOAD,
            "the remainder must itself be a legal slot, or this proves the per-slot bound instead"
        );

        let at_bound = |bio: usize| {
            let mut draft = ProfileDraft::empty();
            draft.set(ProfileField::Avatar, big.clone());
            draft.set(ProfileField::Banner, big.clone());
            draft.set(ProfileField::Bio, "b".repeat(bio));
            draft
        };

        let exact = at_bound(rest);
        assert_eq!(exact.projected_body_len(), MAX_BODY_BYTES);
        assert_eq!(exact.problem(ProfileField::Bio), None);
        assert!(exact.is_committable());

        let over = at_bound(rest + 1);
        assert_eq!(over.projected_body_len(), MAX_BODY_BYTES + 1);
        assert!(over.problem(ProfileField::Bio).is_some());
    }

    /// Removing an image makes room. The projection must SUBTRACT what a replaced slot costs today,
    /// not merely add what the new one costs — otherwise a person who shrinks their avatar is still
    /// told their profile is too large.
    #[test]
    fn replacing_an_image_with_a_smaller_one_frees_its_bytes() {
        let big = an_image_of(MAX_SLOT_PAYLOAD);
        let mut values = BTreeMap::new();
        values.insert(ProfileField::Avatar, big.clone());
        let committed_len = BODY_HEADER_LEN + slot_cost(&big);
        let mut draft = ProfileDraft::over(values, committed_len);

        draft.set(ProfileField::Avatar, an_image_of(1_000));
        assert_eq!(
            draft.projected_body_len(),
            BODY_HEADER_LEN + slot_cost(&an_image_of(1_000))
        );
        assert!(draft.is_committable());
    }

    /// An over-budget profile does not hang its sentence on a field the person left empty: the
    /// remedy there would be "shorten this", and there is nothing in it to shorten.
    #[test]
    fn the_body_ceiling_is_reported_on_fields_that_hold_something() {
        let each = an_image_of(MAX_SLOT_PAYLOAD);
        let mut draft = ProfileDraft::empty();
        draft.set(ProfileField::Avatar, each.clone());
        draft.set(ProfileField::Banner, each);
        draft.set(ProfileField::Bio, "b".repeat(MAX_SLOT_PAYLOAD));
        assert!(
            draft.projected_body_len() > MAX_BODY_BYTES,
            "the draft must be over budget for this to be about anything"
        );
        assert!(draft.problem(ProfileField::Location).is_none());
    }

    /// The per-slot sentence is chosen over the body one when both are true: shortening an image
    /// that is over BOTH is the only move that helps, and naming the body budget sends the person
    /// to delete something else first.
    #[test]
    fn a_single_oversized_image_is_told_about_its_own_ceiling() {
        let mut draft = ProfileDraft::empty();
        draft.set(ProfileField::Avatar, an_image_of(MAX_BODY_BYTES + 10));
        let said = draft.problem(ProfileField::Avatar).expect("a problem");
        assert!(said.contains("1.3 MB"), "said: {said}");
    }
}
