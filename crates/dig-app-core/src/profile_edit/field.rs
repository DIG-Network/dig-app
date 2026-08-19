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

/// Which fieldset a field is drawn inside.
///
/// # Why the split is three fields and not "the ones with short answers"
///
/// [`Basic`](Self::Basic) is what a person would put on a name badge: who they are, what they look
/// like, and a sentence about themselves. It is deliberately SMALL — the fieldset is open when the
/// form opens, so its size is the whole of the first impression, and eight boxes at once is the
/// "busy and intimidating" the redesign exists to remove (dig_ecosystem#3069).
///
/// Everything else is real and reachable one click away. Nothing is hidden that a person needs in
/// order to finish: an empty profile is publishable, so the collapsed set never holds a requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldGroup {
    /// Shown when the form opens.
    Basic,
    /// Folded away until asked for.
    Enhanced,
}

impl FieldGroup {
    /// Both groups, in the order they are drawn.
    pub const ALL: [Self; 2] = [Self::Basic, Self::Enhanced];

    /// The fieldset's heading, as a person reads it.
    pub fn title(self) -> &'static str {
        match self {
            Self::Basic => "Basic information",
            Self::Enhanced => "Enhanced information",
        }
    }

    /// The sentence under the heading, saying what is inside before it is opened.
    ///
    /// A collapsed group with an opaque title is a person guessing whether the thing they want is
    /// in there; the summary is what makes the fold cheaper than the scroll it replaces.
    pub fn summary(self) -> &'static str {
        match self {
            Self::Basic => "Your name, your picture, and a line about you.",
            Self::Enhanced => "Pronouns, location, links and a payment address. All optional.",
        }
    }

    /// Whether the fieldset starts open.
    pub fn starts_open(self) -> bool {
        matches!(self, Self::Basic)
    }
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

    /// Which fieldset it is drawn inside.
    pub fn group(self) -> FieldGroup {
        match self {
            Self::DisplayName | Self::Avatar | Self::Bio => FieldGroup::Basic,
            Self::Banner | Self::Pronouns | Self::Location | Self::Links | Self::XchAddress => {
                FieldGroup::Enhanced
            }
        }
    }

    /// The fields of `group`, in [`ALL`](Self::ALL)'s order.
    pub fn of_group(group: FieldGroup) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|field| field.group() == group)
            .collect()
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

    /// The field's name when the profile being read belongs to SOMEBODY ELSE.
    ///
    /// One override of one word, rather than a second table: every other label is already written
    /// about the field and not about the reader, so a whole parallel set of headings would be seven
    /// duplicated strings kept in step for the sake of the eighth.
    pub fn heading(self) -> &'static str {
        match self {
            // "About you" addresses the person filling the form in. On a stranger's profile the
            // reader is not the subject, and the label would name the wrong person.
            Self::Bio => "About",
            other => other.label(),
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
            // Says LINES, which is what `dig-social-profile`'s slot `0x0007` actually defines:
            // *"UTF-8 newline-separated social/verification links"* (`slot.rs`). The sentence said
            // SPACES until dig_ecosystem#3070, because the shared control was single-line and an
            // instruction to press Return in a box that cannot take one is unfollowable. The box
            // takes a Return now, so the instruction matches the schema again.
            //
            // Nothing already published is rewritten. A space-separated value written by the old
            // copy stays exactly as it is until its owner edits it, and readers that split on
            // whitespace keep working — this changes what DIG ASKS FOR, never what it stores.
            Self::Links => {
                "Web addresses, one per line. Anyone can read them, and nobody checks that they \
                 are yours."
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

    /// **Every field is in exactly one fieldset, and the two together are the whole form.**
    ///
    /// A field in neither group is one no fieldset draws — the quietest possible way to make a
    /// setting unreachable, since the pane would simply render one box fewer and say nothing.
    #[test]
    fn the_two_fieldsets_partition_every_field() {
        let mut collected: Vec<ProfileField> = FieldGroup::ALL
            .into_iter()
            .flat_map(ProfileField::of_group)
            .collect();
        let unique: BTreeSet<ProfileField> = collected.iter().copied().collect();

        assert_eq!(
            unique.len(),
            collected.len(),
            "a field is drawn in both fieldsets, so one person sees two boxes for one value"
        );
        collected.sort();
        assert_eq!(
            collected,
            ProfileField::ALL
                .into_iter()
                .collect::<Vec<_>>()
                .tap_sorted(),
            "the fieldsets do not add up to the form"
        );
    }

    /// **The set that opens first is the SMALL one, and it holds the three things a person would
    /// put on a name badge.**
    ///
    /// Pinned by NAME rather than by count. A count alone passes on any three fields — including
    /// the payment address as an opening box, which is the intimidating form the redesign is
    /// removing — and the identity of these three is the whole of criterion 7.
    #[test]
    fn the_open_fieldset_holds_who_you_are_and_nothing_heavier() {
        assert!(FieldGroup::Basic.starts_open());
        assert!(!FieldGroup::Enhanced.starts_open());

        assert_eq!(
            ProfileField::of_group(FieldGroup::Basic),
            vec![
                ProfileField::DisplayName,
                ProfileField::Bio,
                ProfileField::Avatar,
            ]
            .tap_ordered_like_all(),
        );
        assert!(
            ProfileField::of_group(FieldGroup::Enhanced).contains(&ProfileField::XchAddress),
            "the payment address opens with the form, where a person meets it before they have \
             decided they want one"
        );
    }

    /// **The Links help asks for the separator the SCHEMA defines** (dig_ecosystem#3070).
    ///
    /// `dig-social-profile`'s slot `0x0007` is *newline-separated*, and the editor spent a release
    /// telling people to use spaces — so the app wrote a format the reader does not define. The
    /// negative leg is what pins the fix: an implementation that added "or lines" beside the old
    /// sentence would satisfy a contains-check for "line" and still be asking for the wrong thing.
    #[test]
    fn the_links_help_asks_for_one_address_per_line_and_never_for_spaces() {
        let said = ProfileField::Links.help().to_lowercase();
        assert!(
            said.contains("one per line") || said.contains("per line"),
            "the links help does not ask for one address per line: {said}"
        );
        assert!(
            !said.contains("separated by spaces"),
            "the links help still asks for a separator the schema does not define: {said}"
        );
        // The control: no OTHER field's help mentions lines, so the assertion above is about this
        // field's own sentence rather than about a word that happens to be everywhere.
        for field in ProfileField::ALL {
            if field != ProfileField::Links {
                assert!(
                    !field.help().to_lowercase().contains("per line"),
                    "{field:?} also asks for one per line"
                );
            }
        }
    }

    /// **The fields a person types prose into are the ones drawn as paragraphs.**
    ///
    /// Links joins Bio here because of the separator above: a newline-separated value cannot be
    /// entered in a control that cannot take a newline, so the kind and the help have to agree or
    /// one of them is lying.
    #[test]
    fn the_prose_fields_are_paragraphs_and_the_image_fields_are_images() {
        assert_eq!(ProfileField::Bio.kind(), FieldKind::Paragraph);
        assert_eq!(ProfileField::Links.kind(), FieldKind::Paragraph);
        assert_eq!(ProfileField::XchAddress.kind(), FieldKind::Address);
        for field in [ProfileField::Avatar, ProfileField::Banner] {
            assert_eq!(field.kind(), FieldKind::Image);
            assert!(field.is_image());
        }
        assert_eq!(ProfileField::DisplayName.kind(), FieldKind::Line);
    }

    /// Sorting helpers, so the partition test compares sets rather than orders.
    trait Sorted {
        fn tap_sorted(self) -> Self;
        fn tap_ordered_like_all(self) -> Self;
    }

    impl Sorted for Vec<ProfileField> {
        fn tap_sorted(mut self) -> Self {
            self.sort();
            self
        }

        /// Put the fields into [`ProfileField::ALL`]'s order, which is the order the form draws
        /// them — so a group's expected contents can be written in any order here.
        fn tap_ordered_like_all(self) -> Self {
            ProfileField::ALL
                .into_iter()
                .filter(|field| self.contains(field))
                .collect()
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
