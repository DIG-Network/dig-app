//! What the creation wizard collected, turned into the SMT a new profile is BORN holding
//! (dig_ecosystem#3038).
//!
//! # Why the wizard's form is the editor's form
//!
//! A profile's content is the same content whether it is being created or changed, so this module
//! adds no fields, no validation and no slot table of its own. It holds a [`ProfileDraft`] over a
//! profile that does not exist yet — committed to nothing, every value typed — which is precisely
//! what the editor's model already describes, and asks [`ProfileField::slot`] where each value
//! belongs. A second field-to-slot table is the byte-drift bug this epic has already paid for once:
//! its first draft put a chosen picture in `0x0003`, the `dig://` REFERENCE slot, where every
//! client dereferences it as a URI and nobody would ever have seen the image.
//!
//! # Why the checks happen here rather than at the mint
//!
//! `dig-account` computes the seed's root before any spend is built, so a seed it cannot encode
//! costs nothing. But a seed it CAN encode and a person cannot use — a mistyped payment address, a
//! picture past the slot ceiling — is committed by the store launch's very first generation, and by
//! then the money is spent and the only remedy is another spend. So everything the editor refuses
//! before a commit, this refuses before a mint, using the editor's own words for it.
//!
//! # Everything is optional
//!
//! [`SeedDraft::is_mintable`] is deliberately NOT [`ProfileDraft::is_committable`]. An edit with
//! nothing changed in it has nothing to write and is correctly refused; a creation with nothing
//! filled in is a person who wants an identity and no biography, and refusing that would make the
//! form mandatory when the ticket says it must not be.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use dig_account::mint::ProfileSeed;
use dig_social_profile::SlotId;

use super::draft::ProfileDraft;
use super::field::ProfileField;

/// The wizard's form: what a person has typed for a profile that does not exist yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedDraft {
    /// The editor's own model, over a profile committed to nothing.
    draft: ProfileDraft,
}

impl SeedDraft {
    /// An empty form.
    pub fn new() -> Self {
        Self {
            draft: ProfileDraft::empty(),
        }
    }

    /// What the input for `field` currently shows.
    pub fn value(&self, field: ProfileField) -> &str {
        self.draft.value(field)
    }

    /// Take what a person typed.
    pub fn set(&mut self, field: ProfileField, value: impl Into<String>) {
        self.draft.set(field, value);
    }

    /// Empty a field. Nothing is published for a field left empty.
    pub fn clear(&mut self, field: ProfileField) {
        self.draft.clear(field);
    }

    /// What is wrong with `field`'s contents, in the editor's words — `None` when nothing is.
    pub fn problem(&self, field: ProfileField) -> Option<String> {
        self.draft.problem(field)
    }

    /// How large the body this seed commits to comes to, by the editor's own arithmetic.
    pub fn projected_body_len(&self) -> usize {
        self.draft.projected_body_len()
    }

    /// Whether anything at all has been filled in.
    pub fn is_empty(&self) -> bool {
        self.values().is_empty()
    }

    /// Whether this form may start a mint: nothing wrong with it. **An empty form may.**
    pub fn is_mintable(&self) -> bool {
        is_mintable(&self.draft)
    }

    /// The mutable form the pane draws over.
    pub fn draft_mut(&mut self) -> &mut ProfileDraft {
        &mut self.draft
    }

    /// The form as a request, or `None` when something in it is wrong.
    ///
    /// The `None` is the whole point of the type: a request is what the mint path accepts, and a
    /// form that cannot produce one cannot spend.
    pub fn request(&self) -> Option<ProfileSeedRequest> {
        ProfileSeedRequest::of_draft(&self.draft)
    }

    /// The non-empty values, keyed by field.
    fn values(&self) -> BTreeMap<ProfileField, String> {
        values_of(&self.draft)
    }
}

/// Whether `draft` may start a mint: nothing wrong with any field. **An empty draft may.**
///
/// The wizard's pane asks this every frame to decide whether its control is pressable, so it is a
/// borrow rather than a method on an owned form — a copy of a draft carrying a picture is over a
/// megabyte, and doing that sixty times a second to answer a yes-or-no question is not free.
pub fn is_mintable(draft: &ProfileDraft) -> bool {
    !draft.oversize()
}

/// The non-empty values of `draft`, keyed by field.
///
/// Empty fields are absent: a slot set to nothing is a slot published as present-and-blank, which
/// is not what leaving a box alone means.
fn values_of(draft: &ProfileDraft) -> BTreeMap<ProfileField, String> {
    ProfileField::ALL
        .into_iter()
        .filter_map(|field| match draft.value(field) {
            "" => None,
            value => Some((field, value.to_string())),
        })
        .collect()
}

/// What a person asked their new profile to CONTAIN — the only part of a profile a caller supplies.
///
/// A profile's identity is derived on chain; everything a user can choose about it is content, and
/// this is that content. It names the editor's [`ProfileField`]s rather than free slot ids so that
/// the wizard, the editor and the CLI cannot disagree about where a value is stored.
///
/// The commitment root is a pure function of these slots, which is what lets a resumed mint rebuild
/// the same commitment without having journalled it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileSeedRequest {
    /// What the person filled in. A field absent here is a field they left alone.
    values: BTreeMap<ProfileField, String>,
}

impl ProfileSeedRequest {
    /// What `draft` would seed, or `None` when something in it is wrong.
    pub fn of_draft(draft: &ProfileDraft) -> Option<Self> {
        match is_mintable(draft) {
            true => Some(Self::of(values_of(draft))),
            false => None,
        }
    }

    /// A request holding nothing — a profile with an identity and no content, which is allowed.
    pub fn new() -> Self {
        Self::default()
    }

    /// The request built from `values`, dropping anything empty.
    pub fn of(values: BTreeMap<ProfileField, String>) -> Self {
        Self {
            values: values
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .collect(),
        }
    }

    /// The same request, with `field` set to `value`.
    #[must_use]
    pub fn with(mut self, field: ProfileField, value: impl Into<String>) -> Self {
        let value = value.into();
        if !value.is_empty() {
            self.values.insert(field, value);
        }
        self
    }

    /// What was asked for `field`, if anything.
    pub fn value(&self, field: ProfileField) -> Option<&str> {
        self.values.get(&field).map(String::as_str)
    }

    /// The display name, when one was given — the label a recorded profile is filed under.
    pub fn display_name(&self) -> Option<&str> {
        self.value(ProfileField::DisplayName)
    }

    /// Whether the person filled in nothing at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The seed the mint launches the store at — so the store's FIRST root already commits this.
    ///
    /// Every value goes through [`ProfileField::slot`], the one mapping, so a field can only ever
    /// land where the editor reads it back from.
    pub fn to_seed(&self) -> ProfileSeed {
        self.values
            .iter()
            .fold(ProfileSeed::new(), |seed, (field, value)| {
                seed.with_utf8(SlotId(field.slot().id()), value.clone())
            })
    }
}

/// What the wizard collected, held for the ceremony that is about to read it.
///
/// # Why a process-wide holder and not an argument
///
/// The window is rebuilt from a snapshot every repaint, so the form lives in the frame's own store
/// and nothing it holds survives the press. The ceremony, meanwhile, is started by the binary from
/// a tray verb that carries no payload. This is the one value that has to cross that gap, and it is
/// the same shape [`crate::profile_edit::EditService`] uses for the same reason.
///
/// It is READ, never taken. A ceremony that had to ask twice — a retry, a second phase — must
/// rebuild the same commitment, and a holder that emptied itself on the first read would launch the
/// store at a root whose body nobody has.
///
/// **It does not survive a restart, and nothing in this build asks it to:** an interrupted creation
/// cannot be picked back up here (`creation_progress::KEEP_DIG_RUNNING` says so to the person). A
/// build that resumes a ceremony across a restart must persist this beside the mint journal first,
/// or the resumed launch would commit to a root rebuilt from an empty form.
static COLLECTED: OnceLock<Mutex<ProfileSeedRequest>> = OnceLock::new();

/// The holder, created empty on first use.
fn collected() -> &'static Mutex<ProfileSeedRequest> {
    COLLECTED.get_or_init(|| Mutex::new(ProfileSeedRequest::new()))
}

impl ProfileSeedRequest {
    /// Hand what the wizard collected to the ceremony that will mint it.
    pub fn collect(self) {
        if let Ok(mut held) = collected().lock() {
            *held = self;
        }
    }

    /// What the wizard collected, or an empty request when it collected nothing.
    pub fn collected() -> Self {
        collected()
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_edit::draft::MAX_SLOT_PAYLOAD;

    /// A 1x1 PNG as an RFC 2397 data URL — the shape, and one of the types, the image slots hold.
    const TINY_PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    /// A real bech32m mainnet address, because the payment field runs the canonical decode and a
    /// made-up string of the right shape is exactly what that decode exists to reject.
    const VALID_ADDRESS: &str =
        "xch14vlj35vktk9uyhuau3fv2dj4gw6c9kfxex44gvmzqa4rmvluqe7qrapt26";

    fn filled() -> SeedDraft {
        let mut seed = SeedDraft::new();
        seed.set(ProfileField::DisplayName, "ada");
        seed.set(ProfileField::Bio, "counts things");
        seed
    }

    /// The property the whole module exists for: what the wizard collected is what the store's
    /// first root commits to.
    ///
    /// Compared against `dig-account`'s OWN named setters rather than against a root recorded here,
    /// so the assertion is about agreement with the crate's schema and not about a number this file
    /// could restate wrongly.
    #[test]
    fn the_collected_values_commit_to_the_crates_own_seed_root() {
        let ours = filled().request().unwrap().to_seed();
        let theirs = ProfileSeed::new()
            .with_display_name("ada")
            .with_bio("counts things");

        assert_eq!(ours.root().unwrap(), theirs.root().unwrap());
    }

    /// The mistake this epic has already made once, pinned from both sides.
    ///
    /// An image a person chooses is a data URL and belongs in the INLINE slot `0x0020`. Written to
    /// `0x0003` — the `dig://` reference slot — the bytes are published under an id every reader
    /// dereferences as a URI, so the picture never appears on any client and nothing reports a
    /// fault. The wrong root is asserted to DIFFER, because a test that only checks the right one
    /// passes for an implementation that writes both.
    #[test]
    fn a_chosen_picture_lands_in_the_inline_slot_and_not_the_reference_slot() {
        let mut wizard = SeedDraft::new();
        wizard.set(ProfileField::Avatar, TINY_PNG);
        let ours = wizard.request().unwrap().to_seed();

        let inline = ProfileSeed::new().with_utf8(SlotId(0x0020), TINY_PNG);
        let reference = ProfileSeed::new().with_utf8(SlotId(0x0003), TINY_PNG);

        assert_eq!(ours.root().unwrap(), inline.root().unwrap());
        assert_ne!(ours.root().unwrap(), reference.root().unwrap());
    }

    /// Every field the editor knows reaches the seed, checked one at a time so a field silently
    /// dropped from the mapping cannot hide behind the others.
    #[test]
    fn every_editable_field_reaches_its_own_slot_in_the_seed() {
        for field in ProfileField::ALL {
            let value = match field.is_image() {
                true => TINY_PNG,
                false => VALID_ADDRESS,
            };
            // Address validation would refuse arbitrary text in the payment slot, so that field
            // carries a real address; every other field takes it as plain text, which is fine.
            let mut wizard = SeedDraft::new();
            wizard.set(field, value);
            let request = wizard
                .request()
                .unwrap_or_else(|| panic!("{field:?} refused a value of its own kind"));

            let expected = ProfileSeed::new().with_utf8(SlotId(field.slot().id()), value);
            assert_eq!(
                request.to_seed().root().unwrap(),
                expected.root().unwrap(),
                "{field:?} does not reach slot {:#06x}",
                field.slot().id()
            );
        }
    }

    /// A person who wants only a DID gets one. This is the distinction the editor cannot express:
    /// an edit with nothing changed has nothing to write, but an empty CREATION is a whole profile.
    #[test]
    fn an_empty_form_may_still_mint_even_though_it_could_not_be_committed_as_an_edit() {
        let empty = SeedDraft::new();

        assert!(empty.is_empty());
        assert!(empty.is_mintable());
        assert_eq!(empty.request(), Some(ProfileSeedRequest::new()));
        // The editor's own verb, over the same values, says no — which is why a second verb exists.
        assert!(!ProfileDraft::empty().is_committable());
    }

    /// An empty form still commits to the SCHEMA-STAMPED root, never to an empty tree. An empty
    /// tree's root is all zeros, which `dig-social-profile` refuses as an anchor because a bare
    /// five-byte body verifies against it — a universal forgery.
    #[test]
    fn an_empty_form_seeds_the_schema_stamped_profile_and_not_a_zero_root() {
        let root = ProfileSeedRequest::new().to_seed().root().unwrap();

        assert_eq!(root, ProfileSeed::new().root().unwrap());
        assert_ne!(root, [0u8; 32]);
    }

    /// A mistyped payment address costs a real mint here, not a re-edit, so it is refused before
    /// the ceremony starts — through the same bech32m decode the editor uses.
    #[test]
    fn a_malformed_payment_address_cannot_start_a_mint() {
        let mut wizard = SeedDraft::new();
        wizard.set(ProfileField::XchAddress, "xch1notarealaddress");

        assert!(wizard.problem(ProfileField::XchAddress).is_some());
        assert!(!wizard.is_mintable());
        assert_eq!(wizard.request(), None);
    }

    /// Anything typed into an image field that is not a data URL is refused: a filename published
    /// to `0x0020` shows nothing on every client, with no error anywhere to say why.
    #[test]
    fn a_filename_typed_into_an_image_field_cannot_start_a_mint() {
        let mut wizard = SeedDraft::new();
        wizard.set(ProfileField::Avatar, "me.png");

        assert!(!wizard.is_mintable());
        assert_eq!(wizard.request(), None);
    }

    /// The size ceiling is checked BEFORE the mint begins, because at mint time it is money already
    /// committed. The fixture is taken from the protocol's own per-slot limit and pinned from both
    /// sides: one byte over must refuse, and the limit itself must pass.
    #[test]
    fn an_oversize_picture_is_refused_before_any_spend_and_the_limit_itself_is_allowed() {
        let prefix = "data:image/png;base64,";
        let over = format!("{prefix}{}", "A".repeat(MAX_SLOT_PAYLOAD + 1 - prefix.len()));
        let at_limit = format!("{prefix}{}", "A".repeat(MAX_SLOT_PAYLOAD - prefix.len()));

        let mut too_big = SeedDraft::new();
        too_big.set(ProfileField::Avatar, over);
        assert!(!too_big.is_mintable(), "one byte over the slot ceiling");
        assert_eq!(too_big.request(), None);

        let mut fits = SeedDraft::new();
        fits.set(ProfileField::Avatar, at_limit);
        assert!(fits.is_mintable(), "the ceiling itself must be usable");
    }

    /// A field left empty publishes no slot at all. Set to an empty string it would be published as
    /// present-and-blank, which is a different profile and a different root.
    #[test]
    fn an_emptied_field_publishes_no_slot() {
        let mut wizard = SeedDraft::new();
        wizard.set(ProfileField::Bio, "something");
        wizard.clear(ProfileField::Bio);

        assert!(wizard.is_empty());
        assert_eq!(
            wizard.request().unwrap().to_seed().root().unwrap(),
            ProfileSeed::new().root().unwrap()
        );
    }

    /// The label a recorded profile is filed under still comes off the request, and it comes from
    /// the display-name FIELD rather than from a second string carried beside it.
    #[test]
    fn the_display_name_is_read_off_the_collected_field() {
        assert_eq!(filled().request().unwrap().display_name(), Some("ada"));
        assert_eq!(ProfileSeedRequest::new().display_name(), None);
    }

    /// What the wizard collected reaches the ceremony, and stays there to be read again.
    ///
    /// The second read is the load-bearing half: a ceremony that asks twice — a retry, its second
    /// phase — must rebuild the SAME commitment, and a holder that emptied itself on the first read
    /// would launch the store at a root whose body nobody holds.
    #[test]
    fn what_the_wizard_collected_reaches_the_ceremony_and_survives_being_read() {
        assert!(
            ProfileSeedRequest::collected().is_empty(),
            "nothing has been collected yet"
        );

        filled().request().unwrap().collect();

        let first = ProfileSeedRequest::collected();
        let again = ProfileSeedRequest::collected();
        assert_eq!(first.display_name(), Some("ada"));
        assert_eq!(first, again);
        assert_eq!(
            again.to_seed().root().unwrap(),
            filled().request().unwrap().to_seed().root().unwrap()
        );
    }

    /// Different content commits to a different root — stated here as well as in the crate, because
    /// a mapping that dropped every value would satisfy every agreement test above.
    #[test]
    fn two_different_forms_commit_to_two_different_roots() {
        let mut other = SeedDraft::new();
        other.set(ProfileField::DisplayName, "grace");

        assert_ne!(
            filled().request().unwrap().to_seed().root().unwrap(),
            other.request().unwrap().to_seed().root().unwrap()
        );
        assert_ne!(
            other.request().unwrap().to_seed().root().unwrap(),
            ProfileSeed::new().root().unwrap()
        );
    }
}
