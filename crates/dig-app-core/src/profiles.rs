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
//! [`ProfileCreation`] has no *possible* arm. That is not pessimism, it is the build: this
//! workspace pins dig-account **0.11.3**, whose profile-mint ceremony is real, but the store half of
//! that ceremony walks a singleton lineage and
//! [`ControlChainSource`](crate::chain::ControlChainSource) cannot serve that read yet
//! (dig_ecosystem#2572). So a mint started on this build could be paid for and never finished. An
//! arm claiming otherwise would be a state nothing can reach, which this crate has already decided
//! is worse than no state at all (`pane::state`'s epitaph for `Unwired`).

use dig_account::registry::{ProfileEntry, ProfileRegistry, ProfileVisibility};
use dig_account::ProfileIx;

use crate::account::chain_mint::MintAvailability;
use crate::account::profile_mint::ProfileMintAvailability;
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
    /// How this profile is NAMED to a person — its own label, or its ordinal.
    ///
    /// # Never the DID, and never the raw index
    ///
    /// A `did:chia:…` string is 60-odd characters and would make every row label unreadable at the
    /// width the window actually opens at; the DID is drawn in the list itself, in the identifier
    /// face, beside a copy control, which is where a value nobody transcribes belongs.
    ///
    /// The fallback counts from ONE. `profile 0` is an HD index — an implementation detail a person
    /// has never been shown — and an unlabelled profile is entirely ordinary, because minting one
    /// does not ask for a name.
    ///
    /// One derivation for three surfaces: the row heading on the card, the verb labels the model
    /// builds, and the shell's switch confirmation. A row headed *"work"* above a button reading
    /// *"Use “home” for this account…"* is two names for one thing on one line.
    pub fn display_name(&self) -> String {
        match self.label.as_deref() {
            Some(label) => format!("“{label}”"),
            None => format!("profile {}", self.ix.0.saturating_add(1)),
        }
    }

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
#[non_exhaustive]
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
    /// Whether the registry itself could not be READ — distinct from every other reason a list is
    /// missing, because it is the only one that silently moves where money arrives.
    ///
    /// A host that cannot read its registry boots unprofiled and therefore derives at
    /// [`ProfileIx::ROOT`](dig_account::ProfileIx::ROOT). Everything downstream then agrees with
    /// itself — the wallet and the active profile are both ROOT, so no accessor refuses — while the
    /// address on screen is a different one from the profile the person was actually using. The
    /// Wallet surface reads this to say so.
    pub fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unknown(ProfilesUnknown::Unreadable(_)))
    }

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

/// Which missing piece stops a profile being created on this build.
///
/// **One variant per MISSING PIECE**, the rule [`ProfilesUnknown`] follows: the two are different
/// faults with different remedies, and a person told the wrong one goes looking for something that
/// is not broken.
///
/// Kept SEPARATE from [`ProfileCreation`] because *whether* creation is possible and *why it is not*
/// are different questions, asked by different code. Copy keys on this; a control keys on the
/// answer. That split is what makes the day this build can mint a change of BODIES rather than of
/// shapes — see [`ProfileCreation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreationBlocked {
    /// This build cannot read coins or push a bundle at all, so nothing here reaches the chain. The
    /// same fact the start-up wizard's gate reads, arrived at from the same value.
    NoChainTransport,
    /// The chain answers ordinary reads and cannot walk a singleton lineage, so a mint started here
    /// could never be finished.
    ///
    /// # The reason, stated against the code rather than against the previous comment
    ///
    /// The mint itself exists: this workspace pins dig-account **0.11.3**, whose
    /// `begin_profile_mint` / `advance_profile_mint` / `profile_mint_status` ceremony is real and has
    /// minted a profile on Chia mainnet. What is missing is one READ. Phase B
    /// (`advance_profile_mint` → `launch_store`) calls `dig_did::walk_did_lineage_to_tip`, whose
    /// first operation is `ChainSource::resolve_singleton_lineage`, and
    /// [`ControlChainSource`](crate::chain::ControlChainSource) answers that with `Unsupported`
    /// pending the canonical walk in a forthcoming `dig-chainsource-interface` release
    /// (dig_ecosystem#2572).
    ///
    /// So a build in this state can PUSH the DID half and can never launch the store — every user
    /// stranded at `ProfileMintStatus::DidConfirmedStoreNotLaunched`, which dig-account itself calls
    /// the state that costs money to get wrong. Withholding the offer is the cheaper error.
    ///
    /// Named to match [`ProfileMintSeams::NoLineageWalk`](crate::account::profile_mint::ProfileMintSeams::NoLineageWalk),
    /// which is where the fact is measured.
    NoLineageWalk,
}

impl CreationBlocked {
    /// Every reason, in one place.
    ///
    /// Surfaces that must be checked against ALL of them — the copy guards, the pane's rendering
    /// tests — read this rather than keeping their own array, because an array copied into three
    /// files is three places to forget a new variant. Adding one here is what makes those checks
    /// widen with it.
    pub const EVERY: [Self; 2] = [Self::NoChainTransport, Self::NoLineageWalk];
}

/// Whether this build can create a profile.
///
/// # There is no `Possible` arm YET, and this type is shaped so that adding one is a body change
///
/// The user's standing direction is that creating a profile MUST become real. It cannot be made real
/// here YET, and exactly ONE thing is now in the way (dig_ecosystem#2398): this workspace pins
/// dig-account **0.11.3**, whose profile-mint ceremony is real and mainnet-proven, and the store
/// half of that ceremony walks a singleton lineage that
/// [`ControlChainSource`](crate::chain::ControlChainSource) answers with `Unsupported` pending
/// a forthcoming `dig-chainsource-interface` release (dig_ecosystem#2572). Until that read lands,
/// a `Possible` arm
/// would be a claim this crate cannot honour — and dig_ecosystem#2377 measured exactly what that
/// costs: flipping one availability constant early opened an undismissible dead end AND a start-up
/// password window, **neither catchable by a test**, because both live in the binary.
///
/// So the arm is absent and the SHAPE is ready for it. Consumers ask
/// [`blocked`](Self::blocked) — an `Option`, whose `None` is already spelled *creation is possible* —
/// and render [`copy::cannot_create`] from the REASON. Nothing matches this enum exhaustively. The
/// day the lineage walk lands, the work is: add `Possible`, derive it from
/// [`ProfileMintSeams`](crate::account::profile_mint::ProfileMintSeams) — the three-armed gate that
/// already measures the fact — and give the one surface that draws a control its new branch. No
/// consumer's shape moves, and no sentence is rewritten.
///
/// # Why it is derived from the mint seam rather than asserted beside it
///
/// [`of`](Self::of) is a **function of** the [`MintAvailability`] the start-up wizard's gate reads.
/// Two independent answers to one question is how a surface comes to advertise a capability whose
/// implementation refuses — the dead end dig_ecosystem#1800 removed once already, and the drift
/// dig_ecosystem#2377 removed a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileCreation {
    /// **Nobody has asked the node yet.**
    ///
    /// Not a failure and not a capability — the absence of a reading. Distinct from
    /// [`Blocked`](Self::Blocked) because a blocker is a fact somebody measured, and rendering an
    /// unmeasured node as one names a cause nobody observed: a person whose node is merely stopped
    /// would be told *nothing is missing from your setup and there is nothing for you to do*, which
    /// is false and leaves them without the one action that would help (dig_ecosystem#2690).
    ///
    /// It withholds the offer exactly as a blocker does, so the safe direction is unchanged; what
    /// changes is what the surface SAYS while it waits. This is `BalanceReading`'s
    /// pending/known/unknown split, applied to a capability rather than an amount.
    Unknown,
    /// Both halves of the ceremony are reachable, so a profile really can be created here.
    ///
    /// Reachable ONLY from [`of_profile_mint`](Self::of_profile_mint) given a
    /// [`ProfileMintAvailability::Possible`], which in turn is reachable only from a
    /// [`ProfileMintSeams::Wired`](crate::account::profile_mint::ProfileMintSeams::Wired) — and that
    /// requires a live chain that answered BOTH a peak read and a singleton-lineage probe. There is
    /// no other constructor, so this arm cannot be asserted beside the capability; it can only be
    /// read off it.
    Possible,
    /// Creation cannot be attempted, and this is the piece that is missing.
    Blocked(CreationBlocked),
}

impl Default for ProfileCreation {
    /// [`Unknown`](Self::Unknown) — a field nobody filled has measured nothing.
    ///
    /// It used to be `Blocked(NoChainTransport)`, which was accurate only while the binary hardcoded
    /// that seam: it stated a definite cause on behalf of a reading that had never been taken, and
    /// went false the moment creation was fed from a node (dig_ecosystem#2690). `Unknown` withholds
    /// the offer just as firmly, so nothing about the safe direction rests on the change.
    fn default() -> Self {
        Self::Unknown
    }
}

impl ProfileCreation {
    /// Derive creation's availability from the mint seam the wizard's gate reads.
    ///
    /// With no transport the transport is the honest answer, because it is the blocker a person
    /// would hit first; with one, the singleton lineage walk is what is still missing.
    ///
    /// Takes the DID-only [`MintAvailability`] because that is what the shipped binary's
    /// `mint_seams()` produces. The three-armed
    /// [`ProfileMintSeams`](crate::account::profile_mint::ProfileMintSeams) measures the same facts
    /// more precisely and is what this will read from once a create control exists to gate.
    pub fn of(mint: MintAvailability) -> Self {
        Self::Blocked(match mint {
            MintAvailability::NoChainTransport => CreationBlocked::NoChainTransport,
            MintAvailability::Possible => CreationBlocked::NoLineageWalk,
        })
    }

    /// Derive creation from a whole-profile READING, which may not have been taken yet.
    ///
    /// The one place an unmeasured node lands, and the reason [`Unknown`](Self::Unknown) cannot be
    /// reached by accident: `None` means *nobody has asked*, and it is spelled here rather than
    /// inferred from an error, so a transport failure and an absent reading can never collapse into
    /// one another (dig_ecosystem#2690).
    ///
    /// Callers hold an `Option` because that is genuinely what a poller answers before its first
    /// probe returns — see
    /// [`NodeChainReadiness::observe`](crate::chain::readiness::NodeChainReadiness::observe).
    pub fn of_reading(mint: Option<ProfileMintAvailability>) -> Self {
        match mint {
            None => Self::Unknown,
            Some(mint) => Self::of_profile_mint(mint),
        }
    }

    /// Derive creation's availability from the WHOLE-PROFILE seam — the only place
    /// [`Possible`](Self::Possible) is ever constructed.
    ///
    /// [`of_reading`](Self::of_reading) can also answer `Possible`, but only by delegating here, so
    /// this stays the single door and the guard that watches it has one place to watch.
    ///
    /// # Why this exists beside [`of`](Self::of) rather than replacing it
    ///
    /// [`of`](Self::of) reads the DID-only [`MintAvailability`], which answers a narrower question:
    /// *can a DID be minted?* A profile is a DID **and** a store, and the store half needs a read the
    /// DID half does not. A seam that can mint a DID therefore says nothing about whether a profile
    /// can be completed, which is exactly why `of` can never return `Possible` and this can.
    ///
    /// The two are kept apart rather than collapsed because the first-run DID wizard genuinely asks
    /// the narrower question and its `MintingStep::Possible` unwritability is a proven security
    /// property built on it.
    pub fn of_profile_mint(mint: ProfileMintAvailability) -> Self {
        match mint {
            ProfileMintAvailability::Possible => Self::Possible,
            ProfileMintAvailability::NoLineageWalk => Self::Blocked(CreationBlocked::NoLineageWalk),
            ProfileMintAvailability::NoChainTransport => {
                Self::Blocked(CreationBlocked::NoChainTransport)
            }
        }
    }

    /// Which piece is missing, or `None` when there is no missing piece to name.
    ///
    /// # `None` answers for TWO arms, and neither of them means "possible"
    ///
    /// [`Possible`](Self::Possible) has nothing missing; [`Unknown`](Self::Unknown) has nothing
    /// measured. Both answer `None`, and `Unknown` is the [`Default`], so that answer is now the
    /// COMMON case rather than the unreachable one this doc used to promise.
    ///
    /// So never derive capability from it: `blocked().is_none()` reads a node nobody has spoken to
    /// as one a profile can be minted against, which is the fail-open direction on a path that
    /// spends real XCH. Ask [`is_possible`](Self::is_possible), which keys on the arm
    /// (dig_ecosystem#2690).
    pub fn blocked(self) -> Option<CreationBlocked> {
        match self {
            Self::Possible | Self::Unknown => None,
            Self::Blocked(why) => Some(why),
        }
    }

    /// Whether a profile can be created here.
    ///
    /// Keys on the ARM, never on `blocked().is_none()`. Those agreed while there were two arms and
    /// diverge now that there are three: [`Unknown`](Self::Unknown) has no reason to name, so a
    /// `blocked()`-derived answer would read *not blocked* as *possible* and open a create control
    /// against a node nobody has spoken to — fail-open on a path that spends real XCH
    /// (dig_ecosystem#2690).
    pub fn is_possible(self) -> bool {
        matches!(self, Self::Possible)
    }
}

/// What making `ix` active would do — decided before anything is applied.
///
/// A switch changes the per-profile DEK and the identity signing key at once, because both derive at
/// the profile's HD index. The receive address is the one that does NOT move with them: dig-account
/// 0.8 fixes an unlock's wallet index at open time (dig_ecosystem#2496), so the wallet stays on the
/// profile it was opened at until the account is re-opened, and DIG shows no address at all in the
/// meantime rather than the previous profile's.
///
/// All of that is a consequence a person has to be told about **before** it happens, and told
/// accurately: a disclosure promising the address changes sends somebody looking for a new one that
/// is not there, and invites them to keep handing out the old one believing it belongs to the
/// profile they are now on.
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

/// The sentences BOTH the window's profiles card and the shell's own notices say.
///
/// # Why these live here and not in the pane's copy module
///
/// The pane draws them on a card; the shell says them in a native notice when a person picks
/// `About DIG profiles…` from the tray, and again in the confirmation before a switch. Two surfaces
/// stating the same fact from two constants is exactly how the account state machine came to have
/// two sentence sets that drifted (dig_ecosystem#2357), and `copy::profiles` cannot be reached from
/// the binary anyway. Card titles, badge words and captions stay in the pane's copy module, because
/// only the pane has cards.
pub mod copy {
    use super::CreationBlocked;

    /// The title of the notice the explainer row opens.
    pub const ABOUT_TITLE: &str = "DIG — Profiles";
    /// Its heading.
    pub const ABOUT_HEADING: &str = "A profile is an on-chain identity for this account.";
    /// What a profile IS, said once, for every surface that has to explain it.
    pub const WHAT_A_PROFILE_IS: &str =
        "A profile is an on-chain identity — a DID and a store — that lets you publish, sign for an \
         app and be found by other people. One account can hold several and use one at a time.";

    /// Said while nobody has yet measured whether this node can service a profile mint.
    ///
    /// Names the READ, not an outcome, exactly as the card's list-pending sentence does — and for a
    /// sharper reason: every sentence in [`cannot_create`] ends *there is nothing for you to do*,
    /// which is the worst thing to tell somebody whose node is merely stopped. An unmeasured node and
    /// an unreachable one are different facts (dig_ecosystem#2690).
    ///
    /// Lives here, beside [`cannot_create`], because the window's card and the tray's About notice
    /// both read it — one sentence, so the two surfaces cannot come to describe different builds.
    pub const CHECKING_CREATION: &str =
        "DIG is still checking whether this computer can create a profile. Nothing here is settled until it has.";

    /// What the tray's About-profiles notice says about CREATING one, or `None` when there is no
    /// absence to explain.
    ///
    /// # Why this selection lives here rather than at the notice
    ///
    /// The notice is assembled in `dig-app/src/bin`, which no guard test can see
    /// (dig_ecosystem#2587) — and the selection is exactly the part worth guarding, because
    /// [`ProfileCreation::blocked`](super::ProfileCreation::blocked) answers `None` for **two**
    /// different arms. Reading that one
    /// `None` as *creation is possible* would silently drop the whole explanation for an UNMEASURED
    /// node, from a notice whose only job is to give one (dig_ecosystem#2690).
    ///
    /// Matching here makes the mapping exhaustive, testable, and impossible for the binary to get
    /// wrong: a new arm breaks this compile rather than quietly falling into a catch-all.
    pub fn about_creation(creation: super::ProfileCreation) -> Option<&'static str> {
        match creation {
            super::ProfileCreation::Unknown => Some(CHECKING_CREATION),
            super::ProfileCreation::Blocked(blocked) => Some(cannot_create(blocked)),
            // Creation is possible: the Account tab's card carries the control, and a notice cannot
            // explain an absence there is none of.
            super::ProfileCreation::Possible => None,
        }
    }

    /// Why a profile cannot be created on this build, one sentence per missing piece.
    ///
    /// An EXHAUSTIVE match on [`CreationBlocked`], which
    /// [`ProfileCreation::of`](super::ProfileCreation::of) derives from the mint seam the start-up
    /// wizard reads — so a card, a notice and that wizard cannot come to disagree about whether a
    /// mint is possible.
    ///
    /// # The wording is #1820's, and "optional" is the word it settled against
    ///
    /// A profile is REQUIRED for publishing, signing and messaging, and creating one is *not
    /// available in this version*. Calling it optional would tell a person they had chosen to go
    /// without something they have simply not been offered.
    pub fn cannot_create(blocked: CreationBlocked) -> &'static str {
        match blocked {
            CreationBlocked::NoChainTransport => {
                "Creating a profile mints a DID and a store on the Chia blockchain, and this \
                 version of DIG has no way to reach the chain to do it. It is required for \
                 publishing, signing for an app and messaging, and it is not available in this \
                 version. Nothing is missing from your setup and there is nothing for you to do — \
                 when it arrives, this card will offer it."
            }
            CreationBlocked::NoLineageWalk => {
                "This copy of DIG can reach the chain, and it cannot yet finish the second half of \
                 creating a profile — so starting one would spend XCH on something it could not \
                 complete. It is required for publishing, signing for an app and messaging, and it \
                 is not available in this version. Nothing is missing from your setup and there is \
                 nothing for you to do — when it arrives, this card will offer it."
            }
        }
    }

    /// The confirmation title shown before a switch is applied.
    pub const SWITCHING_TITLE: &str = "DIG — Switch profile";
    /// The affirming control. Names what it does.
    pub const SWITCHING_AFFIRM: &str = "Switch profile";
    /// The declining control.
    pub const SWITCHING_DECLINE: &str = "Stay on this one";

    /// The confirmation body shown before a switch is applied, naming both ends.
    ///
    /// Both are named because the disclosure a person needs says which identity they are LEAVING as
    /// well as which they are arriving at — the one they are leaving holds the address they have
    /// been handing out.
    pub fn switching(from: &str, to: &str) -> String {
        format!(
            "DIG will stop using {from} and start using {to}.\n\n\
             Your signing key changes with it. Your receive address does NOT change yet: your \
             wallet stays on {from} until you close DIG and open it again, so until then DIG shows \
             no receive address rather than {from}'s. Money already sent to {from}'s address stays \
             there. Nothing is spent and nothing is deleted."
        )
    }

    /// Said wherever a hide control appears, so the word "hide" cannot be read as "delete".
    ///
    /// The whole risk of the visibility control in one sentence. A profile is permanent on chain;
    /// this changes one computer's list.
    pub const HIDE_NOTE: &str =
        "Hiding a profile only takes it out of this computer's lists. It stays on the blockchain, \
         keeps its address and its funds, and you can show it here again at any time.";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{
        expected_did, registry_with, session_with,
    };

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
        let broken =
            ProfilesReading::of_session(&ProfileSession::unreadable("the file is not JSON"));
        assert!(
            matches!(
                broken,
                ProfilesReading::Unknown(ProfilesUnknown::Unreadable(_))
            ),
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
        let session = session_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(3), Some("work")),
        ]);
        let _ = session
            .switch_to(ProfileIx(3))
            .expect("a confirmed profile");

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

    /// **The shipped binary cannot open the profile-creation gate.**
    ///
    /// Makes impossible: the dig_ecosystem#2377 defect, in its exact original shape. That incident
    /// was one constant flipped in `src/bin/dig-app.rs` — a file no test can execute — which opened
    /// an undismissible dead end AND a start-up password window, neither catchable by a test.
    /// `ProfileCreation::Possible` now EXISTS, so that one-line flip is once again writable; the only
    /// thing standing between it and a shipped dead end is that the binary never reaches for it.
    ///
    /// So this reads the binary's SOURCE, which is the one way a test can see into those files at
    /// all. It reads the WHOLE crate, every `.rs` under `src/` at any depth, because the entry
    /// point is not the only place an offer could be assembled — the tray worker builds the
    /// snapshot the entry point paints, and a guard that watched only `src/bin/` would let the
    /// same flip through one directory over.
    ///
    /// Opening the gate now requires deleting this guard, which is a deliberate act in the diff
    /// rather than a line nobody notices.
    ///
    /// It is not a ban on ever opening it — it is a ban on opening it without also landing the create
    /// control, the verb and the wizard the arm implies. When those land, this test changes with
    /// them, and the change is the point.
    #[test]
    fn the_binary_cannot_open_the_profile_creation_gate() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("dig-app")
            .join("src");
        let sources = rust_sources_under(&src);

        for path in &sources {
            let source = std::fs::read_to_string(path).expect("a readable source file");
            let reached = openers_reached_in(&source);

            assert!(
                reached.is_empty(),
                "{} reaches for {reached:?}, which opens the profile-creation gate. The create \
                 control, the verb and the wizard must land in the SAME change (dig_ecosystem#2398)",
                path.display()
            );
        }

        // A walk that silently reached nothing would pass every assertion above. These pin the
        // REACH of the walk, not just its verdict: `bin/dig-app.rs` is where dig_ecosystem#2377
        // actually happened, and `tray_worker.rs` is where a tray snapshot — and so a creation
        // offer — would be assembled. A guard that scanned only one directory could satisfy the
        // openers check while never opening the other file, which is exactly how this guard read
        // for one revision.
        for reached in ["dig-app.rs", "tray_worker.rs"] {
            assert!(
                sources.iter().any(|p| p.ends_with(reached)),
                "the walk never reached `{reached}`, so it cannot speak for the binary crate; \
                 it read {} file(s): {sources:?}",
                sources.len()
            );
        }

        assert!(
            sources.len() > 1,
            "the guard read {} file(s), which cannot cover a crate of several modules",
            sources.len()
        );
    }

    /// The spellings that would open the profile-creation gate from the binary crate.
    ///
    /// `of_reading` is on the list even though it is the seam the wiring will eventually use, and
    /// FOR that reason: it answers [`ProfileCreation::Possible`] for
    /// `Some(ProfileMintAvailability::Possible)`, so one line reaching it in a file no test executes
    /// re-creates dig_ecosystem#2377 in its exact original shape. Landing the wiring therefore means
    /// editing this list in the same diff as the create control, which is the point of the guard.
    ///
    /// # The residual, stated rather than papered over
    ///
    /// This list is HAND-maintained, and nothing mechanical can complete it: a text scan cannot tell
    /// a function that CONSTRUCTS [`ProfileCreation::Possible`] from one that merely matches on it,
    /// which is most of this module. So any new public function that can answer `Possible` must be
    /// added here by hand — and dig_ecosystem#2690 is the proof that the step gets missed, because
    /// `of_reading` was added in that change and this list was not.
    ///
    /// What keeps the residual small is that
    /// [`of_profile_mint`](ProfileCreation::of_profile_mint) is the only place `Possible` is ever
    /// constructed; a new route has to go through it, so it is one name to watch rather than many.
    const CREATION_GATE_OPENERS: [&str; 3] =
        ["ProfileCreation::Possible", "of_profile_mint", "of_reading"];

    /// Which openers `source` reaches for OUTSIDE its comments.
    ///
    /// A doc comment naming a symbol is fine; a call is not — otherwise the module's own explanation
    /// of why the gate is shut would have to be deleted to keep the guard green.
    ///
    /// Split out from the guard so the PREDICATE can itself be exercised, by
    /// `the_gate_guard_catches_an_opener_and_tolerates_a_mention`. A name-scan passes identically
    /// when the crate is clean and when the scan can find nothing at all — a misspelt needle, a
    /// filter that eats every line, a list an arm was never added to — and this scan is the only
    /// thing standing between a one-line flip and a shipped dead end.
    fn openers_reached_in(source: &str) -> Vec<&'static str> {
        let code_only: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        CREATION_GATE_OPENERS
            .into_iter()
            .filter(|opener| code_only.contains(opener))
            .collect()
    }

    /// **The gate guard's scan really catches each opener, and really tolerates one merely named in
    /// a comment.**
    ///
    /// `the_binary_cannot_open_the_profile_creation_gate` passes today because the binary is clean,
    /// which is indistinguishable from passing because the scan can never find anything. This is the
    /// leg that tells those apart: every opener is planted in a source that plainly reaches for it,
    /// one at a time, and the scan must name it.
    ///
    /// The comment leg is the other direction, and it is not decoration: without it the honest fix
    /// for a tripped guard would be to delete the sentence explaining why the gate is shut.
    ///
    /// The last assertion pins the boundary — the call the shipped binary genuinely makes
    /// (`ProfileCreation::of`) must NOT read as an opener, or the guard would be unsatisfiable
    /// rather than protective, and the first person to hit it would delete it.
    #[test]
    fn the_gate_guard_catches_an_opener_and_tolerates_a_mention() {
        for opener in CREATION_GATE_OPENERS {
            assert_eq!(
                vec![opener],
                openers_reached_in(&format!("fn wire() {{ let _ = {opener}; }}")),
                "the scan missed `{opener}` in source that plainly reaches for it, so the guard \
                 built on it cannot speak for the binary crate"
            );

            assert!(
                openers_reached_in(&format!(
                    "// the gate stays shut, so nothing here calls {opener}\nfn wire() {{}}"
                ))
                .is_empty(),
                "`{opener}` named in a COMMENT tripped the scan, which would force the module's own \
                 explanation of the shut gate to be deleted to stay green"
            );
        }

        assert!(
            openers_reached_in("fn wire() { let _ = ProfileCreation::of(seam); }").is_empty(),
            "the call the shipped binary actually makes was read as an opener, which makes the \
             guard unsatisfiable rather than protective"
        );
    }

    /// Every `.rs` file in the binary crate, at any depth.
    ///
    /// The guard above is named for a property of the whole binary CRATE, so its predicate has to
    /// cover the whole crate: `src/bin/` holds the entry point, but the modules that assemble what
    /// the entry point paints — the tray worker, link and popup — live beside it in `src/`.
    fn rust_sources_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();

        for entry in std::fs::read_dir(dir).expect("a readable source directory") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                found.extend(rust_sources_under(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }

        found.sort();
        found
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
            ProfileCreation::of(MintAvailability::NoChainTransport).blocked(),
            Some(CreationBlocked::NoChainTransport)
        );
        assert_eq!(
            ProfileCreation::of(MintAvailability::Possible).blocked(),
            Some(CreationBlocked::NoLineageWalk),
            "a wired chain transport was read as a profile this build can mint, which no code path \
             in this build can finish, because the store half cannot walk a singleton lineage"
        );
        assert_ne!(
            ProfileCreation::of(MintAvailability::NoChainTransport),
            ProfileCreation::of(MintAvailability::Possible),
            "creation gives the same answer whatever the mint seam says, so it is not derived from \
             it at all"
        );

        // No build shipped so far can create a profile, and `is_possible` is the one place a future
        // control will ask. Asserted over BOTH seam values, so an arm added without wiring a real
        // minter fails here rather than shipping a control that refuses.
        //
        // This loop is the gate dig_ecosystem#2398 exists to open, and opening it is deliberately
        // expensive: it fails until creation is DERIVED from the seam, which cannot happen until a
        // control and its money ceremony exist to finish what an offer starts.
        for mint in [
            MintAvailability::NoChainTransport,
            MintAvailability::Possible,
        ] {
            let creation = ProfileCreation::of(mint);
            assert!(
                !creation.is_possible(),
                "{mint:?} was read as a build that can create a profile, and this shell has no \
                 control and no money ceremony to finish one — dig-account 0.11 can mint, so the \
                 missing half is here, not underneath"
            );
            assert!(creation.blocked().is_some());
        }
    }

    /// **A node nobody has measured is `Unknown` — never a measured absence, and never possible**
    /// (dig_ecosystem#2690).
    ///
    /// Makes impossible: telling a person whose dig-node is merely stopped that *this version of DIG
    /// has no way to reach the chain… nothing is missing from your setup and there is nothing for you
    /// to do*. That sentence is a claim about the BUILD, and the moment creation is fed from a node
    /// reading it becomes a claim about the NODE wearing the build's clothes — false, and it leaves
    /// the one person who could fix it with no action to take.
    ///
    /// # The two legs that make this load-bearing, not a transcription
    ///
    /// The `assert_ne!` is the fixture that distinguishes this from the nearest wrong
    /// implementation, which is the one that shipped: mapping an unmeasured reading onto
    /// `Blocked(NoChainTransport)` satisfies "withholds the offer" identically, so an assertion about
    /// withholding alone cannot see the defect at all.
    ///
    /// The `is_possible` leg pins the other direction. `Unknown` is not blocked FOR A REASON, so a
    /// `blocked()`-derived `is_possible` — which is what shipped — reads it as *creation is possible*
    /// and opens a create control against a node nobody has spoken to. That is the fail-open
    /// direction on a money path, and it is why `is_possible` must key on the arm.
    #[test]
    fn an_unmeasured_node_is_unknown_rather_than_a_measured_absence() {
        let unmeasured = ProfileCreation::of_reading(None);

        assert_eq!(ProfileCreation::Unknown, unmeasured);
        assert_ne!(
            ProfileCreation::Blocked(CreationBlocked::NoChainTransport),
            unmeasured,
            "an unmeasured node was reported with a definite cause, which puts a diagnostic on \
             screen that names something nobody observed"
        );
        assert_eq!(
            None,
            unmeasured.blocked(),
            "there is no reason to name, because no reading was taken"
        );
        assert!(
            !unmeasured.is_possible(),
            "an unmeasured node was read as one a profile can be minted against — the fail-open \
             direction on a path that spends real XCH"
        );

        // The default is the unmeasured state, because a view whose field was never filled has not
        // measured anything either.
        assert_eq!(ProfileCreation::Unknown, ProfileCreation::default());

        // Controls: a reading that WAS taken still maps to its own definite answer, in both
        // directions, or the arm above would be indistinguishable from a constant.
        assert_eq!(
            ProfileCreation::Possible,
            ProfileCreation::of_reading(Some(ProfileMintAvailability::Possible))
        );
        assert_eq!(
            ProfileCreation::Blocked(CreationBlocked::NoChainTransport),
            ProfileCreation::of_reading(Some(ProfileMintAvailability::NoChainTransport))
        );
        assert!(ProfileCreation::of_reading(Some(ProfileMintAvailability::Possible)).is_possible());
    }

    /// **The tray's About notice explains an absence for every arm that HAS one, and never invents
    /// a cause for a node nobody measured** (dig_ecosystem#2690).
    ///
    /// The binary assembles that notice, and `src/bin` is a file no guard test can read
    /// (dig_ecosystem#2587) — so the selection it delegates to is guarded here instead. Each leg
    /// varies one thing, and the `assert_ne!` is what makes it more than a transcription: an
    /// implementation that answered the unreachable-chain sentence for BOTH would satisfy every
    /// "is some" assertion and still be the exact defect.
    #[test]
    fn the_about_notice_explains_an_unmeasured_node_differently_from_an_unreachable_one() {
        let checking = copy::about_creation(ProfileCreation::Unknown);
        let unreachable =
            copy::about_creation(ProfileCreation::Blocked(CreationBlocked::NoChainTransport));

        assert_eq!(Some(copy::CHECKING_CREATION), checking);
        assert_eq!(
            Some(copy::cannot_create(CreationBlocked::NoChainTransport)),
            unreachable
        );
        assert_ne!(
            checking, unreachable,
            "an unmeasured node and an unreachable one were explained in the same words, which \
             tells somebody whose node is merely stopped that there is nothing for them to do"
        );

        // Every blocked arm gets its own sentence, so a new one cannot arrive unexplained.
        for blocked in CreationBlocked::EVERY {
            assert_eq!(
                Some(copy::cannot_create(blocked)),
                copy::about_creation(ProfileCreation::Blocked(blocked))
            );
        }

        assert_eq!(
            None,
            copy::about_creation(ProfileCreation::Possible),
            "a notice cannot explain an absence there is none of"
        );
    }

    /// **A switch discloses BOTH ends before it happens.**
    ///
    /// The property the user has to be told about, made checkable: a plan that named only the
    /// destination would leave a person unable to see which identity they are leaving, which is the
    /// half that carries the receive address their money currently arrives at.
    #[test]
    fn a_switch_names_the_profile_being_left_as_well_as_the_one_arrived_at() {
        let session = session_with(&[
            (ProfileIx::ROOT, Some("home")),
            (ProfileIx(1), Some("work")),
        ]);
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
