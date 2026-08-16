//! The named standard fields a person may edit on their dig-profile, and what each one IS.
//!
//! # Why an enum of its own, over dig-account's [`ProfileSlot`]
//!
//! The crate's slot vocabulary is wider than this editor's on purpose. It names `Avatar` and
//! `Banner` — `dig://` REFERENCES to images stored elsewhere — beside `AvatarImage` and
//! `BannerImage`, the RFC 2397 data URLs that ride inside the profile body. This editor puts an
//! image INTO the profile (epic #3008's third requirement), so it edits the inline pair and leaves
//! the reference pair alone; a pane driven by the crate's enum would offer a person a text box for
//! a URI scheme they have no way to produce.
//!
//! # The slot numbers are NOT restated here
//!
//! [`ProfileField::slot`] returns the crate's own [`ProfileSlot`], and every id, ordering and
//! encoding decision follows from that one mapping. A second table of the same numbers is the
//! byte-drift bug `ProfileSeed`'s module doc argues against, and it is the mistake this file made in
//! its first draft: it assigned the avatar to `0x0003`, which is the reference slot, so every image
//! a person chose would have been written where readers look for a `dig://` URI.

use dig_account::edit::ProfileSlot;

/// One editable field of a person's social profile.
///
/// The order is the order the editor draws them in, and it is the order a person thinks about
/// themselves: who they are, then what they look like, then where to find them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileField {
    /// The name shown to other people.
    DisplayName,
    /// A short self-description.
    Bio,
    /// The profile picture, carried inline in the body as a data URL.
    Avatar,
    /// The wide header image, carried inline in the body as a data URL.
    Banner,
    /// How this person is referred to.
    Pronouns,
    /// Where they are, in their own words.
    Location,
    /// Where else to find them.
    Links,
    /// The address other people may send money to.
    XchAddress,
}

/// What KIND of thing a field holds, which decides how it is drawn and what may be wrong with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// One line of text.
    Line,
    /// Several lines of text.
    Paragraph,
    /// An image, held in the profile as a data URL.
    Image,
    /// A Chia address.
    Address,
}

impl ProfileField {
    /// Every editable field, in the order the editor draws them.
    pub const ALL: [Self; 8] = [
        Self::DisplayName,
        Self::Pronouns,
        Self::Bio,
        Self::Location,
        Self::Avatar,
        Self::Banner,
        Self::Links,
        Self::XchAddress,
    ];

    /// How many variants the enum has, stated so [`ALL`](Self::ALL) has something to be checked
    /// against that editing `ALL` does not also edit.
    pub const EVERY_VARIANT_IS_LISTED: usize = 8;

    /// The crate slot this field is stored in — the ONE place the mapping is made.
    pub fn slot(self) -> ProfileSlot {
        match self {
            Self::DisplayName => ProfileSlot::DisplayName,
            Self::Bio => ProfileSlot::Bio,
            // The INLINE image slots, not `Avatar`/`Banner`, which are `dig://` references.
            Self::Avatar => ProfileSlot::AvatarImage,
            Self::Banner => ProfileSlot::BannerImage,
            Self::Pronouns => ProfileSlot::Pronouns,
            Self::Location => ProfileSlot::Location,
            Self::Links => ProfileSlot::Links,
            Self::XchAddress => ProfileSlot::XchAddress,
        }
    }

    /// The editable field a crate slot corresponds to, or `None` for a slot this editor does not
    /// show. Used to project a snapshot's fields into a draft without a second table.
    pub fn of_slot(slot: ProfileSlot) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.slot() == slot)
    }

    /// What sort of value it holds.
    pub fn kind(self) -> FieldKind {
        match self {
            Self::DisplayName | Self::Pronouns | Self::Location => FieldKind::Line,
            Self::Bio | Self::Links => FieldKind::Paragraph,
            Self::Avatar | Self::Banner => FieldKind::Image,
            Self::XchAddress => FieldKind::Address,
        }
    }

    /// The field's name, as a person reads it.
    pub fn label(self) -> &'static str {
        match self {
            Self::DisplayName => "Display name",
            Self::Bio => "About you",
            Self::Avatar => "Profile picture",
            Self::Banner => "Header image",
            Self::Pronouns => "Pronouns",
            Self::Location => "Location",
            Self::Links => "Links",
            Self::XchAddress => "Payment address",
        }
    }

    /// What an EMPTY field means — drawn in the input, never a fake value.
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::DisplayName | Self::Pronouns | Self::Location | Self::XchAddress => "Not set",
            Self::Bio => "Not set",
            Self::Avatar => "No picture",
            Self::Banner => "No header image",
            Self::Links => "None",
        }
    }

    /// The sentence under the input when nothing is wrong with it.
    ///
    /// Every one of these says the same load-bearing thing in its own words: a profile is PUBLIC. A
    /// person filling in a form in their own app does not necessarily know that, and finding out
    /// afterwards is not recoverable — the value is published content by then.
    pub fn help(self) -> &'static str {
        match self {
            Self::DisplayName => "The name other people see. Anyone can read it.",
            Self::Bio => "A few lines about you. Anyone can read this.",
            Self::Avatar => {
                "A picture, stored inside your profile itself. Anyone can see it, and it travels \
                 with your profile to other computers."
            }
            Self::Banner => {
                "A wide image across the top of your profile. Anyone can see it, and it travels \
                 with your profile."
            }
            Self::Pronouns => "How you would like to be referred to. Optional, and public.",
            Self::Location => "Wherever you would like to say you are. Public, and up to you.",
            // Says SPACES, not lines, because the shared form control is single-line: an
            // instruction to press Return in a box that cannot take a Return is an instruction
            // nobody can follow. A multi-line control is dig_ecosystem#3033.
            Self::Links => {
                "Web addresses, separated by spaces. Anyone can read them, and nobody checks that \
                 they are yours."
            }
            Self::XchAddress => {
                "An address anyone can send money to. Check it character by character — money sent \
                 to a wrong address cannot be recalled."
            }
        }
    }

    /// Whether this field holds an image.
    pub fn is_image(self) -> bool {
        matches!(self.kind(), FieldKind::Image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The list and the enum agree. A variant added without being listed cannot be edited by
    /// anyone, and the pane would simply not draw it — the quietest possible way to ship a gap.
    #[test]
    fn every_field_is_listed_exactly_once() {
        let listed: BTreeSet<ProfileField> = ProfileField::ALL.into_iter().collect();
        assert_eq!(listed.len(), ProfileField::ALL.len());
        assert_eq!(listed.len(), ProfileField::EVERY_VARIANT_IS_LISTED);
    }

    /// Two fields sharing a slot would make one silently overwrite the other on save.
    #[test]
    fn no_two_fields_share_a_slot() {
        let slots: BTreeSet<u16> = ProfileField::ALL.iter().map(|f| f.slot().id()).collect();
        assert_eq!(slots.len(), ProfileField::ALL.len());
    }

    /// The mapping the first draft of this file got wrong, pinned in both directions.
    ///
    /// An image the person chooses is a data URL, so it belongs in the INLINE slots. Written into
    /// `Avatar`/`Banner` — the `dig://` reference slots — the bytes would be published under ids
    /// every reader dereferences as a URI, so the picture would simply never appear, on any client,
    /// with nothing reporting a fault.
    #[test]
    fn the_image_fields_are_the_inline_slots_not_the_reference_slots() {
        assert_eq!(ProfileField::Avatar.slot(), ProfileSlot::AvatarImage);
        assert_eq!(ProfileField::Banner.slot(), ProfileSlot::BannerImage);
        assert_eq!(ProfileField::Avatar.slot().id(), 0x0020);
        assert_eq!(ProfileField::Banner.slot().id(), 0x0021);
        assert_eq!(ProfileField::of_slot(ProfileSlot::Avatar), None);
        assert_eq!(ProfileField::of_slot(ProfileSlot::Banner), None);
    }

    /// Every text field lands on the slot the schema gives it, taken from the crate rather than
    /// from a number typed here.
    #[test]
    fn the_text_fields_map_onto_their_schema_slots() {
        for (field, slot) in [
            (ProfileField::DisplayName, ProfileSlot::DisplayName),
            (ProfileField::Bio, ProfileSlot::Bio),
            (ProfileField::Pronouns, ProfileSlot::Pronouns),
            (ProfileField::Location, ProfileSlot::Location),
            (ProfileField::Links, ProfileSlot::Links),
            (ProfileField::XchAddress, ProfileSlot::XchAddress),
        ] {
            assert_eq!(field.slot(), slot);
            assert_eq!(ProfileField::of_slot(slot), Some(field));
        }
    }

    /// No editable field may land on a slot the schema reserves for machine values: a person given
    /// a text box for their key epoch can break their own profile by typing in it. `ProfileSlot`
    /// deliberately has no variant for those, so this asserts the crate's own answer rather than a
    /// list of ids kept here.
    #[test]
    fn no_editable_field_touches_a_machine_slot() {
        const MACHINE_SLOTS: [u16; 5] = [0x0000, 0x0010, 0x0012, 0x0013, 0x0018];
        for id in MACHINE_SLOTS {
            assert_eq!(
                ProfileSlot::from_id(id),
                None,
                "slot {id:#06x} is machine-owned and must not be nameable as an edit"
            );
        }
        for field in ProfileField::ALL {
            assert!(!MACHINE_SLOTS.contains(&field.slot().id()));
        }
    }

    /// Each field says something, in its own words, about who can read it. Checked as a property
    /// because the reason these sentences exist is one a later edit can quietly drop.
    #[test]
    fn every_field_says_who_can_read_it() {
        for field in ProfileField::ALL {
            let help = field.help().to_lowercase();
            assert!(
                help.contains("anyone") || help.contains("public"),
                "{field:?}'s help never says the value is public: {}",
                field.help()
            );
        }
    }
}
