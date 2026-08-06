//! The DIG App's **active derivation set** — the HD profile indices the wallet actually operates on
//! (dig_ecosystem#2236).
//!
//! # Why this module exists
//!
//! The app has always used exactly one derivation index, but only by every call site happening to pass
//! [`ProfileIx::ROOT`]. That is a convention, not a constraint: a new call site opening an account at
//! some other index compiles fine, and the wallet silently starts deriving a DIFFERENT address —
//! money sent to the address the tray shows would land on a key the app no longer looks at.
//!
//! This module turns the convention into a declaration. [`ACTIVE_PROFILES`] is the ONE place the set
//! is stated; [`ActiveProfile`] is a [`ProfileIx`] that has been *checked* against it, and the
//! account-open funnel ([`open_or_enroll`](crate::account::lifecycle::open_or_enroll)) takes that
//! type rather than a bare index. Opening a wallet-bearing account at a non-active index is therefore
//! not a mistake to be caught in review — it does not typecheck.
//!
//! # HD is DEACTIVATED, not removed
//!
//! Nothing here deletes HD. `chia_bls::master_to_wallet_unhardened`, [`ProfileIx`], the per-profile
//! signers / DEKs / sealers in `dig-account` are all intact and still exercised at non-zero indices
//! (see [`crate::account::sealer`] and dig-account's own suite). Multi-address support returns by
//! adding to [`ACTIVE_PROFILES`] — never by restoring deleted code.

use dig_account::ProfileIx;

/// Every HD derivation index the wallet is active on.
///
/// **This is the single declaration** the whole app's single-address model rests on (#2236). To make
/// the wallet multi-address again, add indices HERE — and the build then HARD-STOPS with `E0080`
/// naming this ticket, so the change cannot happen by accident.
///
/// Be precise about what that stop does and does not give you, because the difference matters to
/// whoever widens this. It is ONE loud halt, not compiler-driven exhaustiveness: removing the
/// tripwire (which widening requires) leaves the crate compiling clean, because `ActiveProfile::SOLE`
/// still resolves to `ACTIVE_PROFILES[0]` and its callers keep silently using index 0. Measured, not
/// assumed (dig-app#111 review). So after removing the tripwire, grep `SOLE` — four call sites today
/// — and generalize each deliberately. The identity/sealing seams hardcode `ProfileIx::ROOT`
/// independently of this list and must be reviewed at the same time; they agree today and cannot
/// diverge without first tripping the halt.
///
/// It is `ProfileIx::ROOT` (index 0) — the index the user's existing address was derived at, so this
/// declaration is deliberately *descriptive of today*, not a renumbering.
pub const ACTIVE_PROFILES: &[ProfileIx] = &[ProfileIx::ROOT];

// A tripwire, not a limitation: `ActiveProfile::SOLE` and the callers that name it are only meaningful
// while the set has exactly one member. Widening `ACTIVE_PROFILES` trips this at COMPILE time and
// walks whoever does it to each seam that has to grow a loop. See dig_ecosystem#2236.
const _: () = assert!(
    ACTIVE_PROFILES.len() == 1,
    "the wallet is pinned to ONE derivation index (dig_ecosystem#2236); widening ACTIVE_PROFILES \
     means teaching `ActiveProfile::SOLE`'s callers to handle a set"
);

/// Whether `ix` is one of the [`ACTIVE_PROFILES`].
pub const fn is_active(ix: ProfileIx) -> bool {
    let mut i = 0;
    while i < ACTIVE_PROFILES.len() {
        if ACTIVE_PROFILES[i].0 == ix.0 {
            return true;
        }
        i += 1;
    }
    false
}

/// A [`ProfileIx`] proven to be in [`ACTIVE_PROFILES`] — the only kind of index a wallet-bearing
/// account may be opened at.
///
/// The type is the point: it cannot be constructed from an inactive index, so "the wallet derives at
/// an index the app does not watch" is unrepresentable rather than merely discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActiveProfile(ProfileIx);

impl ActiveProfile {
    /// The one active profile, while the app is single-address (#2236).
    pub const SOLE: Self = ActiveProfile(ACTIVE_PROFILES[0]);

    /// Check `ix` against [`ACTIVE_PROFILES`], or `None` if the wallet is not active on it.
    pub const fn new(ix: ProfileIx) -> Option<Self> {
        if is_active(ix) {
            Some(ActiveProfile(ix))
        } else {
            None
        }
    }

    /// The underlying index, for the `dig-account` APIs that take a bare [`ProfileIx`].
    pub const fn ix(self) -> ProfileIx {
        self.0
    }
}

impl From<ActiveProfile> for ProfileIx {
    fn from(active: ActiveProfile) -> Self {
        active.ix()
    }
}

impl std::fmt::Display for ActiveProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The active set is exactly ONE index, it is the index the user's address was already derived at,
    /// and the type refuses every other index.
    ///
    /// The rejection half is what makes this more than a transcription of the declaration: a
    /// [`ActiveProfile`] that accepted any index would leave the funnel's type signature decorative.
    #[test]
    fn the_active_derivation_set_is_exactly_one_index() {
        assert_eq!(1, ACTIVE_PROFILES.len(), "{ACTIVE_PROFILES:?}");
        assert_eq!(ProfileIx::ROOT, ACTIVE_PROFILES[0]);
        assert_eq!(ProfileIx::ROOT, ActiveProfile::SOLE.ix());

        assert_eq!(
            Some(ActiveProfile::SOLE),
            ActiveProfile::new(ProfileIx::ROOT)
        );
        for inactive in [1u32, 2, 7, 100, u32::MAX] {
            assert!(
                !is_active(ProfileIx(inactive)),
                "index {inactive} must not be active"
            );
            assert!(
                ActiveProfile::new(ProfileIx(inactive)).is_none(),
                "index {inactive} must not be constructible as active"
            );
        }
    }
}
