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
        // Checked BEFORE the body-budget check, because a malformed address is wrong at any size.
        //
        // # Why the real decode and not a prefix test
        //
        // This slot is where other people send money. A `starts_with("xch1")` check is worse than
        // nothing here: it passes every typo that keeps the prefix — a transposed pair, a dropped
        // character, a lookalike — which is exactly the population of mistakes a bech32m checksum
        // exists to catch, and it would let the field's own help ("check it character by
        // character") read as though the app had already done so.
        //
        // `dig-social-profile` owns the canonical parse, and it is the same one that decides
        // whether a PUBLISHED address is honoured, so a value this accepts cannot be one the
        // reader later rejects.
        if field == ProfileField::XchAddress
            && !value.is_empty()
            && !dig_social_profile::xch::is_valid_xch_address(value)
        {
            return Some(NOT_AN_XCH_ADDRESS.to_string());
        }
        // An image slot holds a data URL, and nothing downstream enforces that.
        //
        // `dig-social-profile` documents `0x0020`/`0x0021` as RFC 2397 data URLs but does not
        // validate them, so a free-text box over this slot publishes whatever is typed. Someone
        // entering a filename — the obvious thing to type into a field labelled "Profile picture" —
        // spends real XCH to put `me.png` on chain, and every client that reads it shows nothing,
        // with no error anywhere to say why. The cost is real and the failure is silent, which is
        // the pairing that makes it worth refusing before the money moves rather than after.
        //
        // This checks the SHAPE, not the pixels: a well-formed data URL of an accepted type. The
        // bytes themselves are `profile_image::intake`'s job, and wiring the picker to it is #3028
        // — until then a person can paste a data URL and be told honestly if it is not one.
        if field.is_image() && !value.is_empty() && !is_accepted_data_url(value) {
            return Some(NOT_AN_IMAGE.to_string());
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

/// Whether `value` is a data URL of a type a DIG profile image may be.
///
/// PNG and JPEG only, matching `profile_image::intake`'s allowlist — and `image/svg+xml` is
/// excluded deliberately rather than incidentally: SVG is a script-bearing document, not a bitmap,
/// and a profile image is rendered by every client that reads the profile.
fn is_accepted_data_url(value: &str) -> bool {
    const ACCEPTED: [&str; 2] = ["data:image/png;base64,", "data:image/jpeg;base64,"];
    ACCEPTED
        .iter()
        .any(|prefix| value.len() > prefix.len() && value.starts_with(prefix))
}

/// The sentence for a value in an image slot that is not an image.
///
/// Names the one thing a person is most likely to have done — typed a filename — because the field
/// is labelled "Profile picture" and a filename is the obvious answer to that label.
const NOT_AN_IMAGE: &str =
    "That is not an image. This field holds the picture itself, not a file name or a link to one,      so DIG cannot publish what is there. Choosing a file is not wired up in this version yet.";

/// The sentence for a payment address that is not one.
///
/// Says what is wrong and what to do, and deliberately does NOT guess which character is at fault:
/// a checksum failure identifies the address as wrong without identifying where, and pointing at a
/// position the maths cannot actually locate would send someone hunting in the wrong place.
const NOT_AN_XCH_ADDRESS: &str =
    "That is not a Chia address. A payment address starts with xch1 and carries a checksum that      this one fails, so a character is wrong or missing somewhere in it. Paste it again from your      wallet rather than typing it.";

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
    /// **A payment address is checked, not merely shaped.**
    ///
    /// This slot is where other people send money, and its own help tells a person to "check it
    /// character by character" — which reads as a promise that the app already did.
    ///
    /// The mutation is the assertion. Rejecting `"not-an-address"` proves nothing: a
    /// `starts_with("xch1")` test passes that too, and passes every typo that keeps the prefix,
    /// which is exactly the population of mistakes a checksum exists to catch. So the invalid
    /// fixture here is the VALID one with a single character changed — indistinguishable from the
    /// real thing by shape, length and prefix, and separable only by the bech32m checksum.
    #[test]
    fn a_payment_address_that_fails_its_checksum_is_refused() {
        // A canonical mainnet address, and the same address with one character moved along the
        // bech32 alphabet. Nothing but the checksum tells them apart.
        const VALID: &str = "xch17s7wd45k6vpmpwcqu26x43x5kac6u3n6pprjl9ssal6qp3dlvmjqf4snk5";
        let mutated = {
            let mut chars: Vec<char> = VALID.chars().collect();
            let last = chars.len() - 1;
            chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
            chars.into_iter().collect::<String>()
        };
        assert_eq!(
            mutated.len(),
            VALID.len(),
            "the mutation must not change the length, or shape alone would separate them"
        );

        let mut draft = ProfileDraft::empty();

        draft.set(ProfileField::XchAddress, VALID);
        assert_eq!(
            draft.problem(ProfileField::XchAddress),
            None,
            "a canonical address was refused"
        );

        draft.set(ProfileField::XchAddress, &mutated);
        assert!(
            draft.problem(ProfileField::XchAddress).is_some(),
            "a one-character corruption of a valid address was accepted"
        );

        // Empty stays valid: clearing the field is a REMOVAL, not a malformed address, and refusing
        // it would leave a person unable to take their address back off their profile.
        draft.set(ProfileField::XchAddress, "");
        assert_eq!(
            draft.problem(ProfileField::XchAddress),
            None,
            "emptying the field was reported as a bad address"
        );
    }

    /// Each rule is confined to the fields it belongs to — a text slot takes prose, and nothing else
    /// inherits the address or image rules.
    ///
    /// Without this, a validator applied too broadly would refuse a perfectly good bio for failing a
    /// checksum it was never supposed to have, and the field-level tests above would not notice.
    #[test]
    fn the_address_and_image_rules_do_not_reach_the_text_fields() {
        let mut draft = ProfileDraft::empty();
        for field in ProfileField::ALL.iter().copied() {
            if field == ProfileField::XchAddress || field.is_image() {
                continue;
            }
            // Deliberately address-shaped and image-shaped prose: a text slot may legitimately hold
            // either, because a person may write about one.
            draft.set(
                field,
                "xch1 is a prefix, and me.png is a file — both fine here",
            );
            assert_eq!(
                draft.problem(field),
                None,
                "{field:?} was validated by a rule that does not belong to it"
            );
        }
    }

    /// **An image slot holds a picture, not the name of one.**
    ///
    /// The field is labelled "Profile picture", so a filename is the obvious thing to type — and
    /// nothing downstream refuses it: `dig-social-profile` documents `0x0020` as a data URL but does
    /// not validate it. Committed, that spends real XCH to publish `me.png`, and every client that
    /// reads the profile shows nothing with no error anywhere.
    ///
    /// The accepted fixture is a real data URL prefix, so this cannot be satisfied by a rule that
    /// merely refuses short strings.
    #[test]
    fn an_image_field_refuses_anything_that_is_not_a_data_url() {
        let mut draft = ProfileDraft::empty();
        for field in ProfileField::ALL.iter().copied().filter(|f| f.is_image()) {
            draft.set(field, "me.png");
            assert!(
                draft.problem(field).is_some(),
                "{field:?} accepted a filename"
            );

            // SVG is refused by name, not by accident: it is a script-bearing document that every
            // client reading this profile would render.
            draft.set(field, "data:image/svg+xml;base64,PHN2Zy8+");
            assert!(
                draft.problem(field).is_some(),
                "{field:?} accepted an SVG data URL"
            );

            draft.set(field, "data:image/png;base64,iVBORw0KGgo=");
            assert_eq!(
                draft.problem(field),
                None,
                "{field:?} refused a well-formed PNG data URL"
            );

            // Emptying stays valid — that is a removal, not a malformed image.
            draft.set(field, "");
            assert_eq!(
                draft.problem(field),
                None,
                "{field:?} refused an empty value"
            );
        }
    }
}
