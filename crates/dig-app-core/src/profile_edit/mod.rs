//! Editing a dig-profile: what it holds now, what a person changed, and committing that on chain.
//!
//! # The shape (dig_ecosystem#2993, W7 of #3008)
//!
//! A profile's values live in an SMT whose ROOT is on chain and whose BODY is not. So an edit is
//! three things that must all happen, in order, or the profile is worse off than before it started:
//!
//! 1. **Read** the current body and verify it against the root the chain anchors. dig-account's
//!    `read_profile` does this; a body that does not rebuild to the anchored root is refused, so
//!    nothing here has to decide whether to trust it.
//! 2. **Commit** the change: build the update spend, sign it in THIS process, push the signed bundle
//!    through the node. §908 — the node never sees a key.
//! 3. **Persist the bytes the commit returns.** This is the step with no error to warn you: the new
//!    root is on chain the moment the spend confirms, and if nobody holds its preimage the profile
//!    becomes unreadable to everyone, permanently, with every layer reporting success. See
//!    [`bodies`].
//!
//! # What this module decides, and what it does not
//!
//! It decides the MODEL: which fields exist ([`field`]), what a person has changed and whether it
//! can fit ([`draft`]), where bytes are kept ([`bodies`]), and how a commit is run off the painting
//! thread ([`commit`]). It decides no pixel and no verb — the editor's one model verb is built in
//! [`crate::tray_menu`] like every other, and the pane draws what it is given.
//!
//! # Why the crate seam is a trait rather than a direct call
//!
//! [`commit::ProfileEditSeam`] names exactly what this app needs of dig-account: read a profile,
//! commit an edit, hand back the bytes. Two things fall out of that. A test can drive the whole
//! editor — including the failure where the bytes come back and are dropped — against a double,
//! with no chain and no money. And the concrete adapter is one small file that names the crate,
//! which is what lets the rest of the editor be written and reviewed against an API that is
//! published rather than one that is in a gate.

pub mod bodies;
pub mod commit;
pub mod draft;
pub mod field;
pub mod offer;
pub mod service;

use std::collections::BTreeMap;

pub use bodies::{BodyRead, BodyStore, BodyStoreError};
pub use commit::{CommitOutcome, EditSeams, ProfileEditError, ProfileEditSeam, ProfileSnapshot};
pub use draft::{ProfileDraft, SlotChange, MAX_BODY_BYTES, MAX_SLOT_PAYLOAD};
pub use field::{FieldKind, ProfileField};
pub use offer::{EditBlocked, ProfileEditing};
pub use service::EditService;

/// What the app can honestly say about the profile it is editing.
///
/// Four states, because a pane drawing this has four different things to say and no way to
/// distinguish them from an `Option<BTreeMap<_, _>>`. The middle two are the ones that get
/// collapsed by accident: **a profile with no fields set** is a working profile a person has not
/// filled in, and **a profile nobody could read** is a fault with a retry. Drawn the same way, the
/// second reads as the first and a person edits over a profile they cannot see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileReading {
    /// A read is under way. Nothing has answered yet.
    Pending,
    /// The profile was read and verified against the root the chain anchors.
    ///
    /// Holds the draft, so a pane never has to build one — including in the empty case, where the
    /// draft is over no values and [`ProfileDraft::is_empty`] is true.
    Known(ProfileDraft),
    /// Nobody could read it, in the deciding party's own words.
    ///
    /// Carries the reason rather than a flag: "your node is not running" and "this profile's body
    /// does not match the root on chain" are different situations with different remedies, and the
    /// second is a security refusal that must never be worded as a network hiccup.
    Unreadable(String),
}

impl ProfileReading {
    /// A reading over a profile that answered with these values.
    pub fn known(values: BTreeMap<ProfileField, String>, body_len: usize) -> Self {
        Self::Known(ProfileDraft::over(values, body_len))
    }

    /// The draft to edit, when there is one.
    pub fn draft(&self) -> Option<&ProfileDraft> {
        match self {
            Self::Known(draft) => Some(draft),
            _ => None,
        }
    }

    /// Whether the profile answered and holds nothing — the empty state, which is not a fault.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Known(draft) if draft.is_empty())
    }

    /// Whether a person may be offered a retry: exactly the failed read, never the empty one.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unreadable(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_profile_is_not_a_failed_read() {
        let empty = ProfileReading::known(BTreeMap::new(), 5);
        assert!(empty.is_empty());
        assert!(!empty.is_retryable());
        assert!(
            empty.draft().is_some(),
            "an empty profile is still editable"
        );
    }

    /// The inverse, which is the half that actually loses data: a read that FAILED must never be
    /// offered as an editable empty profile, or a person types their name over a profile the app
    /// could not see and commits a body missing everything it already held.
    #[test]
    fn a_failed_read_is_not_an_empty_profile_and_offers_no_draft() {
        let failed = ProfileReading::Unreadable("no node answered".into());
        assert!(!failed.is_empty());
        assert!(failed.is_retryable());
        assert!(failed.draft().is_none());
    }

    #[test]
    fn a_read_in_flight_is_neither() {
        assert!(!ProfileReading::Pending.is_empty());
        assert!(!ProfileReading::Pending.is_retryable());
        assert!(ProfileReading::Pending.draft().is_none());
    }
}
