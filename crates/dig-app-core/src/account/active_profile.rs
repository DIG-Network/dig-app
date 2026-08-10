//! The DIG App's **active profile slot** — which HD profile the app currently derives at, and the
//! narrow types that carry that answer to the seams which need an index (dig_ecosystem#2398).
//!
//! # What replaced what
//!
//! This module used to declare a `const ACTIVE_PROFILES: &[ProfileIx]` — a *static* set of one — plus
//! a `const assert!(len() == 1)` tripwire, because a slice can have a length other than one
//! (dig_ecosystem#2236). The active profile is now genuinely dynamic: a user can hold several minted
//! profiles and switch between them. `dig_account::ProfileRegistry` holds the answer in a scalar
//! `active: Option<ProfileIx>`, which **cannot** represent a set of size two, so the tripwire is
//! discharged structurally rather than asserted — and keeping the old constant would leave a second,
//! always-wrong source of truth beside the registry.
//!
//! # The rule these types exist to enforce
//!
//! **dig-app keeps no owned copy of the active index.** The single storage location is the registry
//! itself, behind the one `Arc<RwLock<..>>` inside
//! [`ProfileSession`](crate::account::profile_session::ProfileSession); every derivation seam re-reads
//! it per operation, exactly as the residency already re-reads the unlocked account for lock liveness.
//! [`ActiveSlot`] is therefore a *reading* — a value obtained by looking, valid for the instant it was
//! taken — and never a field a long-lived handle stores.
//!
//! [`WalletSlot`] and [`MintTarget`] are the two places an index legitimately crosses an API boundary,
//! and both are constructible only from the registry's own answer. A bare `ProfileIx` does not
//! typecheck at either, which is the property `open_or_enroll`'s signature has carried since #2236.
//!
//! # HD is ACTIVE, not deactivated
//!
//! #2236 recorded that HD was deactivated but not removed. That obligation is now discharged more
//! strongly: HD derivation is live and dynamic, and the refusal that remains is narrower and truer —
//! **there is no constructor for a wallet slot at an index the registry does not vouch for**
//! (`tests/hd_derivation_varies_by_index.rs` and the `trybuild` compile-fail case pin it).

use dig_account::registry::{ActiveProfile, ProfileRegistry};
use dig_account::ProfileIx;

/// Which profile the app is deriving at, **as read at one instant**.
///
/// This is a reading, not a record. Obtain it with [`read`](Self::read) immediately before use and
/// drop it; a handle that stored one would be storing exactly the stale copy this module exists to
/// make unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveSlot {
    /// The account has no confirmed profile — **every user's state today**, and not an error.
    ///
    /// The wallet derives at [`ProfileIx::ROOT`] so that the address a person funds BEFORE minting is
    /// the address their first profile inherits (`ProfileRegistry::next_free_ix` returns `ROOT` on an
    /// empty registry; `the_mint_target_is_the_next_free_index_and_starts_at_root` pins it). Identity surfaces have no
    /// DID in this state and **must say so** rather than fall back to showing the root signing pubkey
    /// as an identity — `boot::account_scoped_id` records that the account id is the seed-derived key
    /// precisely *because* nothing is minted.
    Unprofiled,

    /// A confirmed profile is active, and this is which.
    Profile {
        /// The HD index every key derivation for this profile takes.
        ix: ProfileIx,
        /// The profile's canonical `did:chia:…` string.
        did: String,
        /// The user's own name for it, if they gave one.
        label: Option<String>,
    },
}

impl ActiveSlot {
    /// Read the slot out of `registry`. **The only constructor** — a slot can be obtained by looking
    /// and no other way, so there is no path by which a caller states an active profile of its own.
    pub fn read(registry: &ProfileRegistry) -> Self {
        match registry.active() {
            None => Self::Unprofiled,
            Some(active) => Self::Profile {
                ix: active.ix(),
                did: active.entry().anchor().did().to_string(),
                label: active.entry().label().map(str::to_owned),
            },
        }
    }

    /// The HD index to derive at — [`ProfileIx::ROOT`] when [`Unprofiled`](Self::Unprofiled), for the
    /// funding-continuity reason in that variant's docs.
    pub fn ix(&self) -> ProfileIx {
        match self {
            Self::Unprofiled => ProfileIx::ROOT,
            Self::Profile { ix, .. } => *ix,
        }
    }

    /// Whether a confirmed profile is active. Identity surfaces branch on this rather than on
    /// [`ix`](Self::ix), which answers `ROOT` in both states and so cannot distinguish them.
    pub fn is_profiled(&self) -> bool {
        matches!(self, Self::Profile { .. })
    }

    /// The active profile's DID, or `None` while [`Unprofiled`](Self::Unprofiled).
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::Unprofiled => None,
            Self::Profile { did, .. } => Some(did),
        }
    }
}

/// An index a wallet-bearing account may be OPENED at.
///
/// There is deliberately **no bare-index constructor**: the only ways to obtain one are
/// [`unprofiled`](Self::unprofiled) — the bootstrap, at [`ProfileIx::ROOT`] — and
/// [`from_active`](Self::from_active), which consumes the registry's own
/// [`ActiveProfile`] borrow and therefore proves a confirmed profile exists at that index.
///
/// `open_or_enroll` takes this type rather than a `ProfileIx` for the reason it always has
/// (dig_ecosystem#2236): the opened handle's `wallet_ops` — and so the receive address the tray shows
/// and the key that signs spends — derives at whatever index is passed, and an index nobody vouched
/// for would silently move a user's money to an address the app does not watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletSlot(ProfileIx);

impl WalletSlot {
    /// The bootstrap slot: [`ProfileIx::ROOT`], for an account with no confirmed profile.
    pub const fn unprofiled() -> Self {
        Self(ProfileIx::ROOT)
    }

    /// The slot of the registry's active profile.
    ///
    /// Takes `ActiveProfile<'_>` rather than an index so the *registry* is what vouches for it. The
    /// borrow ends here — the index is a scalar copy of a value the registry has already established
    /// — which is what lets this be called without holding a registry guard across an unlock.
    pub fn from_active(active: ActiveProfile<'_>) -> Self {
        Self(active.ix())
    }

    /// The underlying index, for the dig-account APIs that take a bare [`ProfileIx`].
    pub const fn ix(self) -> ProfileIx {
        self.0
    }
}

impl From<WalletSlot> for ProfileIx {
    fn from(slot: WalletSlot) -> Self {
        slot.ix()
    }
}

impl std::fmt::Display for WalletSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The index a NEW profile will be minted at — deliberately a different type from [`WalletSlot`].
///
/// # Why the two must not be one type
///
/// A mint has two indices, and they are the same only while an account has at most one profile: the
/// **funding** index, whose wallet pays the mint fee, and the **target** index, where the new profile's
/// keys will derive. Collapsing them means the first second-profile mint tries to fund itself from the
/// brand-new profile's empty wallet — a latent bug the old single-index pin was hiding
/// (`chain_mint.rs` carried one `ActiveProfile` for both roles).
///
/// Like [`WalletSlot`], the only constructor consults the registry, because "which index is free" is a
/// question only the registry can answer — and answering it wrongly means paying twice for one
/// profile (see `ProfileRegistry::next_free_ix`, which never fills a gap, for why).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MintTarget(ProfileIx);

impl MintTarget {
    /// The next index `registry` considers free — one past the highest it knows of, confirmed or
    /// still minting.
    pub fn next_free(registry: &ProfileRegistry) -> Self {
        Self(registry.next_free_ix())
    }

    /// The underlying index.
    pub const fn ix(self) -> ProfileIx {
        self.0
    }
}

impl From<MintTarget> for ProfileIx {
    fn from(target: MintTarget) -> Self {
        target.ix()
    }
}

impl std::fmt::Display for MintTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{expected_did, registry_with};

    /// An account with no confirmed profile reads as [`ActiveSlot::Unprofiled`], derives at ROOT, and
    /// says it has no DID.
    ///
    /// The `is_profiled` half is what makes this more than a transcription: `ix()` answers `ROOT` in
    /// BOTH states, so a surface that branched on the index alone could not tell "no profile yet" from
    /// "the first profile" — and would render a seed-derived pubkey as if it were a minted identity.
    #[test]
    fn an_empty_registry_reads_as_unprofiled_at_root() {
        let slot = ActiveSlot::read(&ProfileRegistry::empty());

        assert_eq!(ActiveSlot::Unprofiled, slot);
        assert_eq!(ProfileIx::ROOT, slot.ix());
        assert!(!slot.is_profiled());
        assert_eq!(None, slot.did());
    }

    /// A populated registry reads the ACTIVE entry — its index, its DID and its label — not merely
    /// "some profile exists".
    #[test]
    fn a_populated_registry_reads_the_active_entrys_index_and_did() {
        let mut registry = registry_with(&[(ProfileIx::ROOT, Some("home")), (ProfileIx(1), None)]);
        let _ = registry.set_active(ProfileIx(1)).unwrap();

        let slot = ActiveSlot::read(&registry);
        assert!(slot.is_profiled());
        assert_eq!(ProfileIx(1), slot.ix());
        assert_eq!(
            registry.get(ProfileIx(1)).unwrap().anchor().did(),
            slot.did().unwrap(),
            "the DID must come from the ACTIVE entry, not from whichever entry is first"
        );
        assert_ne!(
            expected_did(ProfileIx::ROOT),
            slot.did().unwrap(),
            "the two entries must have distinguishable DIDs, or the assertion above proves nothing"
        );

        let _ = registry.set_active(ProfileIx::ROOT).unwrap();
        let back = ActiveSlot::read(&registry);
        assert_eq!(ProfileIx::ROOT, back.ix());
        assert_eq!(Some("home"), back.label());
    }

    /// A wallet slot can be built from the registry's own active profile, and the index it carries is
    /// that profile's — not the first entry's, and not ROOT.
    #[test]
    fn a_wallet_slot_comes_from_the_registry_or_from_the_bootstrap() {
        assert_eq!(ProfileIx::ROOT, WalletSlot::unprofiled().ix());

        let mut registry = registry_with(&[(ProfileIx::ROOT, None), (ProfileIx(4), None)]);
        let _ = registry.set_active(ProfileIx(4)).unwrap();
        let slot = WalletSlot::from_active(registry.active().unwrap());

        assert_eq!(ProfileIx(4), slot.ix());
        assert_eq!(ProfileIx(4), ProfileIx::from(slot));
    }

    /// The mint target is the next FREE index, which is ROOT on an empty registry and one past the
    /// highest otherwise — never a gap, and never the funding profile's own index.
    ///
    /// The empty case is the load-bearing one: it is why the address a user funds before minting is
    /// the address their first profile inherits.
    #[test]
    fn the_mint_target_is_the_next_free_index_and_starts_at_root() {
        assert_eq!(
            ProfileIx::ROOT,
            MintTarget::next_free(&ProfileRegistry::empty()).ix(),
            "the first mint must land on the index the pre-mint address was funded at"
        );

        let registry = registry_with(&[(ProfileIx::ROOT, None), (ProfileIx(2), None)]);
        assert_eq!(
            ProfileIx(3),
            MintTarget::next_free(&registry).ix(),
            "a gap is not evidence an index is free"
        );
    }

    impl ActiveSlot {
        /// The active profile's label, for the assertion above.
        fn label(&self) -> Option<&str> {
            match self {
                Self::Unprofiled => None,
                Self::Profile { label, .. } => label.as_deref(),
            }
        }
    }
}
