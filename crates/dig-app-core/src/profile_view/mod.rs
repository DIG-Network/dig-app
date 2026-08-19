//! Looking at SOMEBODY ELSE'S profile: what was asked for, and what the chain and this node answered.
//!
//! # Why this is a separate module from [`crate::profile_edit`]
//!
//! The editor reads THIS account's profile, and everything about it assumes that: it holds an
//! unlocked residency, it can commit, and its anchor came out of a mint this machine performed. None
//! of that is available for a stranger — there is no anchor on disk, no key, and nothing to commit —
//! so the two share the artifact (a DPB body under a chain-anchored root) and nothing else.
//!
//! # The honesty rule this module is arranged around
//!
//! A profile is two halves kept in different places: a root the chain anchors, and the bytes that
//! root commits to, which live off chain. **They can be present independently**, and the state that
//! matters is the one where the chain says a profile exists and this node does not hold its content
//! (dig_ecosystem#3041 — a real user's own profile was in exactly that state, with `body_b64: NULL`
//! under an anchored root, and the app implied everything was fine).
//!
//! So [`ViewedProfile`] gives that state its own variant, [`BodyMissing`](ViewedProfile::BodyMissing),
//! and there is no path that renders it as a profile with blank fields. Every other absence gets its
//! own variant too, for the same reason: *nobody has looked yet*, *no such store*, *the chain could
//! not be asked* and *the bytes do not match the root* are four different sentences with four
//! different remedies, and an `Option` would make them one.
//!
//! # Nothing here weakens the verification
//!
//! The root comes off the chain — a singleton lineage walk to the store's tip, whose creating spend
//! is re-parsed for the anchored root — and the body is accepted only through
//! `VerifiedBody::open(.., AnchoredRoot::from_chain_read(root))`, which is the same acceptance the
//! node itself applies to a synced body. A body that does not rebuild to the anchored root becomes
//! [`Unverifiable`](ViewedProfile::Unverifiable) and is NOT shown: an unverified body must never be
//! presented as a verified one.

pub mod chain;
pub mod query;
pub mod service;

use std::collections::BTreeMap;

pub use chain::{NodeStoreProfiles, StoreProfiles};
pub use query::{ProfileQuery, QueryProblem};
pub use service::LookupService;

use crate::profile_edit::ProfileField;

/// What is known about the profile a person asked to see.
///
/// The variants are exhaustive over the states the surface can be in, so a pane matching on this
/// cannot reach the screen without having said something true about every one of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ViewedProfile {
    /// Nobody has asked for a profile yet. The state the pane opens in.
    #[default]
    NotLookedUp,
    /// A lookup is under way for this store id.
    ///
    /// Carries the store id rather than a bare flag so the pane can name what it is waiting on — a
    /// lookup is several seconds of chain reads, and an unlabelled spinner beside an input a person
    /// may have retyped is a spinner they cannot attribute.
    Looking {
        /// The store id being resolved, lowercase hex without a `0x` prefix.
        store_id: String,
    },
    /// The store id resolves to nothing that publishes a profile.
    ///
    /// An ANSWER: the chain was asked and there is no such store, or it is not a DIG store, or its
    /// lineage has ended. Asking again cannot produce a profile nobody published.
    NoProfile {
        /// The store id that was asked about.
        store_id: String,
        /// Why there is no profile, in the deciding layer's own words.
        why: String,
    },
    /// The chain anchors a root and this node does not hold the bytes it commits to.
    ///
    /// **The state this whole surface exists to be honest about.** The profile is real, its content
    /// is elsewhere, and there is nothing here to render — so the pane says exactly that rather than
    /// drawing an empty profile.
    BodyMissing {
        /// The store id that was asked about.
        store_id: String,
        /// The root the chain anchors, `0x`-prefixed lowercase hex.
        root: String,
    },
    /// The node holds bytes at the anchored root, and they do not rebuild to it.
    ///
    /// Kept apart from every other failure because of what it would mean to get it wrong: these are
    /// bytes that CLAIM to be this profile. They are named as unusable and never rendered.
    Unverifiable {
        /// The store id that was asked about.
        store_id: String,
        /// The root the chain anchors, `0x`-prefixed lowercase hex.
        root: String,
        /// What refused the bytes, in its own words.
        why: String,
    },
    /// The chain could not be asked, or the node did not answer.
    ///
    /// Not an absence and never drawn as one: retrying can change this answer, which is exactly what
    /// separates it from [`NoProfile`](Self::NoProfile).
    Unreachable {
        /// The store id that was asked about.
        store_id: String,
        /// What could not be reached, in the layer's own words.
        why: String,
    },
    /// The body is held, and it verifies against the root the chain anchors.
    Held {
        /// The store id that was asked about.
        store_id: String,
        /// The root the chain anchors, `0x`-prefixed lowercase hex.
        root: String,
        /// The person-facing fields the body publishes, in [`ProfileField::ALL`]'s order.
        ///
        /// A field the body does not publish is ABSENT from the map rather than present-and-empty:
        /// the pane draws "not set" for one and nothing at all for the other, and conflating them
        /// would put eight empty rows under a profile that published a name.
        fields: BTreeMap<ProfileField, String>,
    },
}

impl ViewedProfile {
    /// The store id this reading is about, if it is about one.
    pub fn store_id(&self) -> Option<&str> {
        match self {
            Self::NotLookedUp => None,
            Self::Looking { store_id }
            | Self::NoProfile { store_id, .. }
            | Self::BodyMissing { store_id, .. }
            | Self::Unverifiable { store_id, .. }
            | Self::Unreachable { store_id, .. }
            | Self::Held { store_id, .. } => Some(store_id),
        }
    }

    /// The chain-anchored root, for every state that got far enough to have read one.
    ///
    /// Deliberately available for [`BodyMissing`](Self::BodyMissing) and
    /// [`Unverifiable`](Self::Unverifiable): the root is the one value a person can check the claim
    /// with, and withholding it from the two states that most need checking would be the reassuring
    /// generic sentence dig_ecosystem#3041 was caused by.
    pub fn root(&self) -> Option<&str> {
        match self {
            Self::BodyMissing { root, .. }
            | Self::Unverifiable { root, .. }
            | Self::Held { root, .. } => Some(root),
            _ => None,
        }
    }

    /// Whether a lookup is under way.
    pub fn is_looking(&self) -> bool {
        matches!(self, Self::Looking { .. })
    }
}
