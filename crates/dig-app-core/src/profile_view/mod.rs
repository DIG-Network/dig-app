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
//! # A DID takes the same path, one hop earlier
//!
//! A `did:chia:` identifier is resolved to the store launched from its coin — the derived two-hop
//! walk of dig-account `SPEC.md` §2.4.4a — and then looked up as that store id, through this same
//! code. Nothing is derived twice and nothing renders a profile a second way, so a resolved DID and
//! its store id pasted by hand produce the SAME [`ViewedProfile`].
//!
//! What a DID adds is more ways to have no store: the identity may not be on chain, it may be on
//! chain and have launched nothing, or it may have launched SEVERAL. That last one is refused rather
//! than answered — picking one of two stores would show one person's profile under another person's
//! DID — and every one of them gets its own arm of [`DidOutcome`] for the reason the paragraph above
//! gives about `Option`.
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
    /// A `did:chia:` identifier that did not become a store to look at.
    ///
    /// **A DID that RESOLVES never reaches this variant.** It becomes the store-shaped states above,
    /// carrying the store id the walk derived, so a resolved DID and that same store id pasted by
    /// hand render identically — which is what keeps this from being a second, divergent renderer of
    /// the same profile.
    ///
    /// So every arm of [`DidOutcome`] is a reason there is no store to show, and each is a different
    /// sentence with a different remedy.
    Did {
        /// The `did:chia:` string that was asked about, exactly as it was given.
        did: String,
        /// What the resolution answered.
        outcome: DidOutcome,
    },
}

/// Why a `did:chia:` identifier did not become a profile to show.
///
/// One arm per outcome of `dig_account::resolve_profile_store` that is not a resolved store, plus the
/// two this crate decides for itself: a string that does not decode to a DID, and the moment before
/// the walk has answered.
///
/// # Why these are separate arms and not one "could not resolve"
///
/// They send a person to different places, and two pairs of them are one wrong word apart:
///
/// * [`NotOnChain`](Self::NotOnChain) says the identity does not exist; [`NoStore`](Self::NoStore)
///   says it exists and has published no profile. Merged, a person whose profile is merely absent is
///   told their identity is gone.
/// * [`Unreachable`](Self::Unreachable) says nothing was learned; every other arm says something was.
///   Rendered as an absence, it tells somebody their identity does not exist when this machine simply
///   could not look.
///
/// [`Ambiguous`](Self::Ambiguous) is the arm nothing may resolve on the reader's behalf: showing one
/// of two stores would put one person's profile under another person's DID, which is the failure the
/// whole derived walk is arranged to make impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidOutcome {
    /// The resolution is running. The only arm that is not an answer.
    Looking,
    /// The string carries the `did:chia:` prefix and is not a DID: it does not decode to a launcher.
    ///
    /// About the string, not about the chain — nothing was asked, and the remedy is to re-copy it.
    Malformed {
        /// What the decoder refused, in its own words.
        why: String,
    },
    /// The DID has no singleton on chain: it was never launched, or it has been deleted.
    NotOnChain,
    /// The DID is on chain and no live profile store descends from it.
    ///
    /// A profile that was launched and later melted arrives here, which is true of it: its store is
    /// gone, and the DID that launched it is not.
    NoStore,
    /// Two or more live profile stores descend from this DID, so there is no single right answer.
    ///
    /// Carries every store id, so the choice can be shown. **Nothing in this crate picks one.**
    Ambiguous(Vec<String>),
    /// More stores descend from this DID than the resolver will disambiguate, so it stopped counting.
    ///
    /// Kept apart from [`Ambiguous`](Self::Ambiguous) because that names a COMPLETE set and this
    /// names one that is unknown. Drawing a truncated list as though it were complete would be a
    /// claim about how many identities somebody published.
    TooMany {
        /// The cap the scan refused to exceed.
        limit: usize,
    },
    /// The chain could not be asked.
    ///
    /// **Never drawn as an absence.** Retrying can change this answer, and it says nothing at all
    /// about whether the DID or its profile exist.
    Unreachable {
        /// What could not be reached, in the resolver's own words.
        why: String,
    },
    /// The chain answered and the resolver refused what it said.
    ///
    /// A lineage served incomplete, or data that did not hold together. Refusing is the safe
    /// direction: the alternative to refusing an inconsistent read is rendering whatever store that
    /// read pointed at.
    Refused {
        /// What did not hold, in the resolver's own words.
        why: String,
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
            // A DID reading is about a DID. Returning the DID string from a method named for a store
            // id is how it ends up drawn under a "Store id" label, which is a different claim.
            Self::Did { .. } => None,
        }
    }

    /// The `did:chia:` identifier this reading is about, if it is about one.
    ///
    /// Only the unresolved states answer. A DID that RESOLVED became a store reading, and the store
    /// id it derived is the value that reading is about.
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::Did { did, .. } => Some(did),
            _ => None,
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
    ///
    /// Both kinds count. A DID resolution is a chain walk of the same order as a store lookup, and a
    /// guard that did not see it would let a second press start a second walk.
    pub fn is_looking(&self) -> bool {
        matches!(
            self,
            Self::Looking { .. }
                | Self::Did {
                    outcome: DidOutcome::Looking,
                    ..
                }
        )
    }
}
