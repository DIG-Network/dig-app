//! What the app can honestly say about this account's **dig-profiles** — the list a person picks
//! from, whether a new one can be created, and what a switch is about to change
//! (dig_ecosystem#2403).
//!
//! # Why a reading and not a `Vec`
//!
//! Every real user has ZERO profiles today, because nothing can mint one. So *"this account has no
//! profiles"* is the common answer and it must be distinguishable from *"nobody has read the
//! registry yet"* and from *"the registry could not be read"* — three different facts that an empty
//! vector collapses into one. [`ProfilesReading`] is the same three-state shape
//! [`BalanceReading`](crate::wallet::overview::BalanceReading) and
//! [`HostedStoresReading`](crate::hosted_stores::HostedStoresReading) already use, for the same
//! reason: there is then no path that turns an unknown into an empty list.
//!
//! # Why creation is a value derived from the mint seam
//!
//! A profile is a DID singleton plus a store plus a seeded SMT, and creating one is a MINT. dig-app
//! already has exactly one place that answers whether this build can mint —
//! [`MintSeams::availability`](crate::account::chain_mint::MintSeams::availability), which the
//! start-up wizard's gate reads — and [`ProfileCreation::of`] is a **function of that value**. That
//! is deliberate and is the whole design of dig_ecosystem#2377: two independent checks are how a
//! surface comes to advertise a capability whose implementation refuses, which is the dead end
//! dig_ecosystem#1800 removed once already.
//!
//! [`ProfileCreation`] has no *possible* arm. That is not pessimism, it is the build: dig-account
//! 0.8's `ProfileMinter::mint` is `todo!()`, so no code path anywhere can mint a profile even on a
//! host whose chain transport is wired. An arm claiming otherwise would be a state nothing can
//! reach, which this crate has already decided is worse than no state at all
//! (`pane::state`'s epitaph for `Unwired`).

use dig_account::registry::{ProfileEntry, ProfileRegistry, ProfileVisibility};
use dig_account::ProfileIx;

use crate::account::chain_mint::MintAvailability;
use crate::account::profile_session::ProfileSession;

/// One profile as a list surface sees it: enough to tell it from its siblings, and nothing secret.
///
/// The three identifying fields travel TOGETHER rather than as parallel lists, so a surface cannot
/// pair one profile's index with another's DID — the same reason
/// [`ActiveSlot::Profile`](crate::account::active_profile::ActiveSlot::Profile) carries all three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRow {
    /// The HD index this profile derives at. Also its stable identity in every control that acts on
    /// it, because a label is optional and a DID is 60-odd characters.
    pub ix: ProfileIx,
    /// Its canonical `did:chia:…` string, recomputed by dig-account from the launcher id on load.
    pub did: String,
    /// The user's own name for it, when they gave one.
    pub label: Option<String>,
    /// Whether the user has hidden it from this host's lists. A LOCAL view preference: the profile
    /// is still on chain, still derivable and still spendable.
    pub hidden: bool,
    /// Whether it is the one profile the account is currently deriving at.
    pub active: bool,
}

impl ProfileRow {
    /// The row for `entry`, given which index the registry says is active.
    fn of_entry(entry: &ProfileEntry, active: Option<ProfileIx>) -> Self {
        Self {
            ix: entry.ix(),
            did: entry.anchor().did().to_string(),
            label: entry.label().map(str::to_owned),
            hidden: entry.visibility() == ProfileVisibility::HiddenFromLists,
            active: active == Some(entry.ix()),
        }
    }
}

/// Why no profile list could be read.
///
/// One variant per REMEDY, the rule [`HostedStoresUnknown`](crate::hosted_stores::HostedStoresUnknown)
/// states: the reason is the only thing that tells a person what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilesUnknown {
    /// The stored registry would not load — unparseable, or violating one of the four invariants
    /// dig-account re-checks on deserialize. Carries the loader's own words.
    ///
    /// This is the state [`crate::account::boot::profiles_for`] boots into. It MUST NOT read as an
    /// account with no profiles: the user may well have several, and telling them they have none is
    /// a claim about their identity that no read supports.
    Unreadable(String),
}

/// What the app knows about this account's profiles. **Three states, never collapsed.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilesReading {
    /// Nothing has read the registry yet. The state a window opened during boot is in.
    Pending,
    /// The registry answered. An EMPTY vector is a real answer — and today it is the only answer any
    /// production account can give.
    Known(Vec<ProfileRow>),
    /// No list could be read, and which thing was missing.
    Unknown(ProfilesUnknown),
}

impl Default for ProfilesReading {
    /// Before anything has been read the list is [`Pending`](Self::Pending) — not empty, and not a
    /// fault.
    fn default() -> Self {
        Self::Pending
    }
}

impl ProfilesReading {
    /// Read the list out of the app's live [`ProfileSession`].
    ///
    /// A session that failed to LOAD reports [`ProfilesUnknown::Unreadable`] rather than the empty
    /// registry it fell back to, which is what keeps "we could not read your profiles" from reaching
    /// a person as "you have none".
    ///
    /// Hidden profiles are INCLUDED, with [`ProfileRow::hidden`] set. Hiding is a list preference a
    /// person applied and must be able to undo, so the one surface that manages visibility is the
    /// one surface that has to be able to see a hidden profile — `registry.shown()` is for the
    /// pickers, not for this.
    pub fn of_session(session: &ProfileSession) -> Self {
        match session.unreadable_reason() {
            Some(why) => Self::Unknown(ProfilesUnknown::Unreadable(why.to_owned())),
            None => Self::Known(session.with_registry(Self::of_registry_rows)),
        }
    }

    /// The list a registry you already hold reads as — always an answer, because holding a registry
    /// IS the answer.
    ///
    /// Separate from [`of_session`](Self::of_session) so a caller that has a `ProfileRegistry` and
    /// no session — the screenshot gallery, and anything that later grows one — reaches the same
    /// projection rather than assembling [`ProfileRow`]s by hand. Hand-assembled rows are how a
    /// surface comes to show a DID that does not belong to its launcher id, which is the forgery
    /// dig-account's own anchor check exists to catch.
    pub fn of_registry(registry: &ProfileRegistry) -> Self {
        Self::Known(Self::of_registry_rows(registry))
    }

    /// Every profile in `registry`, hidden ones included, in index order.
    fn of_registry_rows(registry: &ProfileRegistry) -> Vec<ProfileRow> {
        let active = registry.active().map(|active| active.ix());
        let mut rows: Vec<ProfileRow> = registry
            .entries()
            .iter()
            .map(|entry| ProfileRow::of_entry(entry, active))
            .collect();
        // Index order, because that is the order they were minted in and the only order that does
        // not move a row under a person when they rename or hide one.
        rows.sort_by_key(|row| row.ix.0);
        rows
    }

    /// The rows, when there are any to draw. `None` in every state that is not an answer.
    pub fn rows(&self) -> Option<&[ProfileRow]> {
        match self {
            Self::Known(rows) => Some(rows),
            Self::Pending | Self::Unknown(_) => None,
        }
    }

    /// The row at `ix`, when the list has been read and holds one.
    pub fn row(&self, ix: ProfileIx) -> Option<&ProfileRow> {
        self.rows()?.iter().find(|row| row.ix == ix)
    }
}

/// Whether this build can create a profile — and if not, which missing piece stops it.
///
/// **There is no `Possible` arm**, and [`of`](Self::of) is the only constructor. See the module docs:
/// creating a profile is a mint, dig-account's profile minter is `todo!()`, and the arm a surface
/// would need in order to offer a create control does not exist for it to match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCreation {
    /// This build cannot read coins or push a bundle at all, so nothing here reaches the chain.
    /// The same fact the start-up wizard's gate reads, arrived at from the same value.
    NoChainTransport,
    /// The chain transport is wired and the profile MINT is still not implemented — dig-account
    /// 0.8's `ProfileMinter::mint` is `todo!()`. Distinct from
    /// [`NoChainTransport`](Self::NoChainTransport) because they are two different missing pieces
    /// and a person told the wrong one would go looking for a fault they do not have.
    NoProfileMinter,
}

impl Default for ProfileCreation {
    /// The build's own answer: [`NoChainTransport`](Self::NoChainTransport).
    ///
    /// Safe as a default precisely because there is no arm that OFFERS a create control — a view
    /// that never had this field filled cannot fall into claiming a capability. It matches what
    /// `mint_seams()` returns in the shipped binary, so a snapshot built without it renders the same
    /// surface as one built with it.
    fn default() -> Self {
        Self::NoChainTransport
    }
}

impl ProfileCreation {
    /// Derive creation's availability from the mint seam the wizard's gate reads.
    ///
    /// A **function of** [`MintAvailability`], never a second opinion about it. With no transport
    /// the transport is the honest answer, because it is the blocker a person would hit first; with
    /// one, the profile minter is what is still missing.
    pub fn of(mint: MintAvailability) -> Self {
        match mint {
            MintAvailability::NoChainTransport => Self::NoChainTransport,
            MintAvailability::Possible => Self::NoProfileMinter,
        }
    }
}

/// What making `ix` active would do — decided before anything is applied.
///
/// A switch changes the receive address, the per-profile DEK and the identity signing key, because
/// every one of those derives at the profile's HD index. That is a consequence a person has to be
/// told about **before** it happens: told afterwards, the first they know of it is money arriving
/// at an address they were not shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchPlan {
    /// `ix` is already the active profile, so there is nothing to change and nothing to disclose.
    AlreadyActive,
    /// The list has not been read, or holds no profile at `ix`. Refused rather than attempted: a
    /// switch to an index nobody vouched for is exactly what
    /// [`WalletSlot`](crate::account::active_profile::WalletSlot) has no bare constructor for.
    NotFound,
    /// The switch can go ahead, once the person has agreed to what it changes.
    Disclose {
        /// The profile being left, as it reads on the list.
        from: ProfileRow,
        /// The profile being moved to.
        to: ProfileRow,
    },
}

impl SwitchPlan {
    /// Plan a switch to `ix` against `reading`.
    ///
    /// Both ends are named, because the disclosure a person needs says which identity they are
    /// leaving as well as which they are arriving at.
    pub fn of(reading: &ProfilesReading, ix: ProfileIx) -> Self {
        let Some(rows) = reading.rows() else {
            return Self::NotFound;
        };
        let Some(to) = rows.iter().find(|row| row.ix == ix) else {
            return Self::NotFound;
        };
        if to.active {
            return Self::AlreadyActive;
        }
        match rows.iter().find(|row| row.active) {
            Some(from) => Self::Disclose {
                from: from.clone(),
                to: to.clone(),
            },
            // A list with no active row is an unprofiled account, which cannot hold a profile to
            // switch to either — so this is unreachable through `of_session`. Refused rather than
            // guessed at: inventing a `from` here would disclose a departure that is not happening.
            None => Self::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{expected_did, registry_with, session_with};

    /// **A registry that could not be read is never reported as an account with no profiles.**
    ///
    /// The headline honesty property, and the reason this is a reading rather than a `Vec`. The
    /// nearest wrong implementation is [`crate::account::boot::profiles_for`]'s own fallback — an
    /// EMPTY session — which is indistinguishable from a genuinely empty one at the type level and
    /// tells a user who may hold several profiles that they hold none.
    ///
    /// The control is the genuinely-empty account, which must still be told plainly that it has no
    /// profiles: without it, a reading that reported every state as unreadable would pass.
    #[test]
    fn an_unreadable_registry_is_not_an_account_with_no_profiles() {
        let broken = ProfilesReading::of_session(&ProfileSession::unreadable("the file is not JSON"));
        assert!(
            matches!(broken, ProfilesReading::Unknown(ProfilesUnknown::Unreadable(_))),
            "a registry that would not load came back as a list: {broken:?}"
        );
        assert_eq!(
            broken.rows(),
            None,
            "an unreadable registry offered rows, so a list surface would draw an empty table"
        );

        let empty = ProfilesReading::of_session(&ProfileSession::unprofiled());
        assert_eq!(
            empty.rows(),
            Some(&[][..]),
            "an account that really has no profiles must still be told so plainly"
        );
    }

    /// **Every profile reaches the list, hidden ones included, each carrying its own DID and
    /// visibility.**
    ///
    /// The fixture hides the MIDDLE profile and leaves the first and last shown, so an implementation
    /// that filtered through `registry.shown()` loses exactly one row — and one that reported every
    /// row as hidden, or none, disagrees with the fixture at two indices. A fixture hiding all or
    /// nothing could not tell those apart.
    #[test]
    fn every_profile_reaches_the_list_with_its_own_did_and_visibility() {
        let mut registry = registry_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(1), Some("work")),
            (ProfileIx(2), None),
        ]);
        registry
            .set_visibility(ProfileIx(1), ProfileVisibility::HiddenFromLists)
            .expect("a non-active profile can be hidden");

        let rows = ProfilesReading::of_registry(&registry)
            .rows()
            .expect("a registry always answers")
            .to_vec();

        assert_eq!(
            rows.iter().map(|row| row.ix).collect::<Vec<_>>(),
            vec![ProfileIx::ROOT, ProfileIx(1), ProfileIx(2)],
            "a hidden profile fell out of the one list that has to be able to unhide it"
        );
        assert_eq!(
            rows.iter().map(|row| row.hidden).collect::<Vec<_>>(),
            vec![false, true, false],
            "the visibilities are not the registry's own"
        );
        assert_eq!(
            rows.iter().map(|row| row.active).collect::<Vec<_>>(),
            vec![true, false, false],
            "exactly one row is the active one, and it is the registry's"
        );
        assert_eq!(
            rows.iter().map(|row| row.label.clone()).collect::<Vec<_>>(),
            vec![Some("home".to_owned()), Some("work".to_owned()), None]
        );
        for row in &rows {
            assert_eq!(
                row.did,
                expected_did(row.ix),
                "profile {} is listed under another profile's DID",
                row.ix
            );
        }
    }

    /// **The active row follows the registry, not the list's order.**
    ///
    /// Asserted after a switch to a NON-first profile, because an implementation that marked
    /// `rows[0]` active agrees with the registry on an untouched fixture and disagrees here.
    #[test]
    fn the_active_row_is_the_registrys_and_not_the_first_one() {
        let session = session_with(&[(ProfileIx::ROOT, Some("home")), (ProfileIx(3), Some("work"))]);
        let _ = session.switch_to(ProfileIx(3)).expect("a confirmed profile");

        let reading = ProfilesReading::of_session(&session);
        let active: Vec<ProfileIx> = reading
            .rows()
            .expect("a read list")
            .iter()
            .filter(|row| row.active)
            .map(|row| row.ix)
            .collect();

        assert_eq!(active, vec![ProfileIx(3)]);
        assert_eq!(
            reading.row(ProfileIx(3)).map(|row| row.did.clone()),
            Some(expected_did(ProfileIx(3)))
        );
    }

    /// **Creation's answer is a function of the mint seam the wizard reads, and it never says
    /// "possible".**
    ///
    /// Both `MintAvailability` values are exercised, so the derivation is falsifiable rather than a
    /// constant wearing a function's name: a build whose transport is wired must give a DIFFERENT
    /// answer from one whose is not, and neither answer may be one that offers a create control.
    #[test]
    fn creation_is_derived_from_the_mint_seam_and_is_never_possible() {
        assert_eq!(
            ProfileCreation::of(MintAvailability::NoChainTransport),
            ProfileCreation::NoChainTransport
        );
        assert_eq!(
            ProfileCreation::of(MintAvailability::Possible),
            ProfileCreation::NoProfileMinter,
            "a wired chain transport was read as a profile this build can mint, which no code path \
             in dig-account 0.8 can do"
        );
        assert_ne!(
            ProfileCreation::of(MintAvailability::NoChainTransport),
            ProfileCreation::of(MintAvailability::Possible),
            "creation gives the same answer whatever the mint seam says, so it is not derived from \
             it at all"
        );
    }

    /// **A switch discloses BOTH ends before it happens.**
    ///
    /// The property the user has to be told about, made checkable: a plan that named only the
    /// destination would leave a person unable to see which identity they are leaving, which is the
    /// half that carries the receive address their money currently arrives at.
    #[test]
    fn a_switch_names_the_profile_being_left_as_well_as_the_one_arrived_at() {
        let session = session_with(&[(ProfileIx::ROOT, Some("home")), (ProfileIx(1), Some("work"))]);
        let reading = ProfilesReading::of_session(&session);

        let SwitchPlan::Disclose { from, to } = SwitchPlan::of(&reading, ProfileIx(1)) else {
            panic!("a switch between two confirmed profiles was not planned");
        };
        assert_eq!(from.ix, ProfileIx::ROOT);
        assert_eq!(to.ix, ProfileIx(1));
        assert_ne!(
            from.did, to.did,
            "the two ends carry one DID, so the disclosure cannot show the identity changing"
        );
    }

    /// **Switching to the profile already in force is a no-op, and to an unknown one is refused.**
    ///
    /// Three actors on one fixture. `AlreadyActive` matters because a person who presses the row they
    /// are already on must not be shown a warning about a change that is not happening; `NotFound`
    /// matters because the alternative is asking dig-account to derive at an index nobody vouched
    /// for. The `Disclose` control is what stops a planner that refused everything from passing.
    #[test]
    fn a_switch_to_the_active_profile_changes_nothing_and_an_unknown_one_is_refused() {
        let session = session_with(&[(ProfileIx::ROOT, None), (ProfileIx(1), None)]);
        let reading = ProfilesReading::of_session(&session);

        assert_eq!(
            SwitchPlan::of(&reading, ProfileIx::ROOT),
            SwitchPlan::AlreadyActive
        );
        assert_eq!(SwitchPlan::of(&reading, ProfileIx(9)), SwitchPlan::NotFound);
        assert!(matches!(
            SwitchPlan::of(&reading, ProfileIx(1)),
            SwitchPlan::Disclose { .. }
        ));
    }

    /// **A list nobody has read yet plans no switch at all.**
    ///
    /// Pending and unreadable are both refusals here, and for the same reason: a plan built from an
    /// absent list would name a `from` and a `to` that no read supports.
    #[test]
    fn a_switch_cannot_be_planned_from_a_list_that_was_never_read() {
        assert_eq!(
            SwitchPlan::of(&ProfilesReading::Pending, ProfileIx::ROOT),
            SwitchPlan::NotFound
        );
        assert_eq!(
            SwitchPlan::of(
                &ProfilesReading::Unknown(ProfilesUnknown::Unreadable("bad JSON".to_owned())),
                ProfileIx::ROOT
            ),
            SwitchPlan::NotFound
        );
    }

    /// A reading that has not answered offers no rows, so nothing can draw a table from it.
    #[test]
    fn only_an_answered_reading_offers_rows() {
        assert_eq!(ProfilesReading::default(), ProfilesReading::Pending);
        assert_eq!(ProfilesReading::Pending.rows(), None);
        assert_eq!(ProfilesReading::Pending.row(ProfileIx::ROOT), None);
    }
}
