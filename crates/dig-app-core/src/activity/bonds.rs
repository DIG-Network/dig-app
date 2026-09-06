//! How much $DIG this node has locked in mirror coins — `control.mirror.bondStates`.
//!
//! The Activity tab's heading is the locked-collateral figure, and this module is where that figure
//! comes from. [`super::control`] answers *"what did the node spend"*; this answers *"what is still
//! tied up"*, and they are different questions on different methods.
//!
//! # Why this module exists at all, and what it replaces
//!
//! The heading used to print a total decoded from a `locked` key on `control.spends.list`. **No node
//! has ever sent that key** — `SpendsListResult` has no such field — so the total defaulted to zero
//! on every real read and the tab's only content read *"Nothing is locked up."* to operators holding
//! collateral against every store they serve. That claim shipped. It was deleted rather than
//! repaired, because a figure nobody measured is not a figure this surface may hold (dig-app#289).
//!
//! `control.mirror.bondStates` is the measurement, and it is now published (contract 0.27.0) and
//! served (dig-node `control.rs:944`). So the heading can state a number again — a read one.
//!
//! # The total is READ, never summed
//!
//! [`MirrorBondStatesResult::Known::locked_dig_base_units`] is node-computed, spans the WHOLE bond
//! set rather than the page in hand, and **includes coins being reclaimed**, whose money is still
//! locked until the reclaim confirms.
//!
//! Adding up the page would therefore be wrong three times over: it stops at the page boundary, it
//! drops reclaiming coins on the floor, and both errors point the same way — **downward**, showing
//! unspendable money as available. This module asks for the smallest page the contract allows and
//! reads the field, because the rows are not what it came for.
//!
//! # The unknown axis is the WHOLE answer, never a row
//!
//! Every [`MirrorBondState`](dig_node_control_interface::results::MirrorBondState) is a definite
//! statement, including the six that mean "no coin". A fact the node could not read makes the whole
//! result [`MirrorBondStatesResult::Unknown`] with a named reason. So there is no partial figure to
//! render and no arithmetic to do on a degraded answer — which is the property that keeps a
//! half-read set from surfacing as a small number.
//!
//! # Nothing privileged crosses here (§908)
//!
//! A read of this node's own bookkeeping and of public chain facts. No key, seed, signature or
//! bundle is in the request or the response, and knowing what is locked authorizes nothing.

use std::time::Duration;

use std::collections::BTreeMap;

use dig_node_control_interface::params::{MirrorBondStatesParams, MIRROR_BOND_STATES_MAX_LIMIT};
use dig_node_control_interface::results::{
    CollateralUnknownReason, MirrorBondEntry, MirrorBondKey, MirrorBondState,
    MirrorBondStatesResult, MirrorBondStatesUnknownReason, WalletOperatorAddressResult,
    WalletOperatorAddressUnavailableReason,
};
use dig_node_control_interface::traits::ControlCall;

use crate::amount::amount_with_unit;
use crate::control;
use crate::paging::{self, PageEnd};

use super::absence::ControlAbsence;
use crate::wallet::state::Asset;

/// How long the locked-collateral read may take before it is abandoned.
///
/// The same budget as the audit read for the same reason: this is a node-local answer over the
/// loopback, not a chain round trip, so a longer wait buys nothing but a frozen pane.
pub const BONDS_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The page size asked for.
///
/// **One row, deliberately.** The figure this module wants is `locked_dig_base_units`, which spans
/// the whole set regardless of the page, so a larger page would move more bytes to reach the same
/// number. The contract refuses a zero page size, so one is the floor.
const PAGE: u32 = 1;

/// What this app knows about the $DIG locked in mirror coins.
///
/// Three states, kept structurally apart for the reason the whole tab exists: a total nobody
/// measured must never be able to reach a renderer as a numeral.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LockedReading {
    /// Nobody has asked yet. The truth on a fresh boot, and deliberately not a zero.
    #[default]
    Pending,
    /// The node stated the figure.
    Known {
        /// $DIG locked across the WHOLE bond set, in DIG base units — the node's own total,
        /// including coins being reclaimed. Never a sum of rows.
        locked_dig_base_units: u64,
        /// The epoch in force when the node took this answer, one-based.
        epoch: u64,
    },
    /// The figure was not obtained, and this is which absence it was.
    Unknown(LockedUnknown),
}

/// Why a locked-collateral figure is missing.
///
/// The four transport-and-version absences are the same set [`super::ActivityUnknown`] draws, plus
/// the node's own "I cannot say" — which is a DIFFERENT thing from "I could not be asked" and gets
/// its own variant so the sentence can name the node's reason rather than invent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockedUnknown {
    /// No node is linked, so nobody was asked.
    NoNode,
    /// The node answered, and does not serve this method — it is too old to state the figure.
    NotSupported,
    /// The node refused the caller locally.
    Refused,
    /// The node answered something this app could not decode.
    Unreadable,
    /// The node was asked, answered, and says which fact it is missing.
    ///
    /// The most informative absence there is, and the reason it is not folded into
    /// [`Unreadable`](Self::Unreadable): a node that can name its own gap is working correctly, and
    /// telling its operator that DIG could not read the answer would point at the wrong thing.
    NodeCannotSay(MirrorBondStatesUnknownReason),
    /// The node answered with figures, but cannot say whose money they are about.
    ///
    /// A `Known` bond-states answer carries a wallet read ([`WalletOperatorAddressResult`])
    /// alongside its figures, and that read is a SEPARATE fact from the chain observation the
    /// figures came from — the node can answer the one and fault on the other. When it does, the
    /// figures are real but nameless, which this surface treats exactly like not having them: a
    /// number with no owner is not a number this tab may render (see the module's own invariant on
    /// [`LockedReading::heading`]). Distinct from [`Unreadable`](Self::Unreadable) because the node
    /// DID answer and DID decode — the fault is in what it knows about itself, not in the transport.
    /// See dig-app#360.
    FundingWalletUnreadable,
}

impl From<ControlAbsence> for LockedUnknown {
    /// The shared control-failure taxonomy, said in this surface's words.
    ///
    /// Exhaustive with **no wildcard arm**, deliberately: a fifth absence must be a build error
    /// here rather than folding into whichever neighbour a `_ =>` happened to point at. Note that
    /// [`NodeCannotSay`](Self::NodeCannotSay) is unreachable from here BY CONSTRUCTION and that is
    /// correct — it is not a failed call at all, but a node that answered and named its own gap, so
    /// it can only come from a successful decode in `locked_from`, which is private to this module.
    fn from(absence: ControlAbsence) -> Self {
        match absence {
            ControlAbsence::NoNode => Self::NoNode,
            ControlAbsence::NotSupported => Self::NotSupported,
            ControlAbsence::Refused => Self::Refused,
            ControlAbsence::Unreadable => Self::Unreadable,
        }
    }
}

impl LockedReading {
    /// The Activity tab's heading sentence.
    ///
    /// # It renders a numeral ONLY for [`Known`](Self::Known)
    ///
    /// Every other arm renders WORDS. That is the whole invariant of this surface: the previous
    /// heading printed a numeral for an answer nobody had, and no arrangement of wording undoes a
    /// figure a person has already read as their own money.
    ///
    /// A `Known` **zero** is a measured zero and says so plainly — the node was asked, and it holds
    /// nothing locked. That sentence is only honest because the absences above cannot reach it.
    pub fn heading(&self) -> String {
        match self {
            LockedReading::Pending => "Checking how much collateral is locked…".to_string(),
            LockedReading::Known {
                locked_dig_base_units: 0,
                ..
            } => "Nothing is locked up in collateral.".to_string(),
            LockedReading::Known {
                locked_dig_base_units,
                ..
            } => format!(
                "{} locked up as collateral.",
                amount_with_unit(Asset::DIG, *locked_dig_base_units)
            ),
            LockedReading::Unknown(why) => {
                format!("How much is locked up is not known — {}", why.reason())
            }
        }
    }
}

impl LockedUnknown {
    /// The clause naming why the figure is missing, in the second half of a sentence.
    ///
    /// Names the thing a person could act on where there is one, and says the node cannot tell where
    /// there is not — never "an error occurred", which tells the reader nothing and invites them to
    /// assume the figure is zero.
    pub fn reason(&self) -> &'static str {
        match self {
            LockedUnknown::NoNode => "start your node and DIG will ask it.",
            LockedUnknown::NotSupported => {
                "this node is too old to report its collateral. Update it."
            }
            LockedUnknown::Refused => "DIG could not authenticate to your node.",
            LockedUnknown::Unreadable => "your node said something DIG could not read.",
            LockedUnknown::FundingWalletUnreadable => {
                "your node cannot say which wallet its collateral figures are about."
            }
            LockedUnknown::NodeCannotSay(reason) => match reason {
                MirrorBondStatesUnknownReason::ServedSetUnknown => {
                    "your node cannot list the stores it serves."
                }
                MirrorBondStatesUnknownReason::ChainUnreadable => {
                    "your node cannot read the chain right now."
                }
                MirrorBondStatesUnknownReason::InFlightUnknown => {
                    "your node cannot see its own pending spends right now."
                }
                MirrorBondStatesUnknownReason::ProvenanceUnknown => {
                    "your node cannot tell which stores it advertises."
                }
            },
        }
    }
}

/// The method that reports the bond states.
///
/// Taken from the contract's own [`ControlCall`] impl, so the one method string in this module is
/// not one this app can spell wrong.
pub fn method() -> &'static str {
    <MirrorBondStatesParams as ControlCall>::METHOD.name()
}

/// Read the locked-collateral total from the node this machine is running.
///
/// Returns a [`LockedReading`] rather than a `Result`, so no caller can `unwrap_or_default()` an
/// outage into a zero — which on this surface is a claim about somebody's money.
///
/// The RAW call is used for the same reason [`super::control::read`] uses it: the typed helper
/// reports a decode failure as a transport error, which would render "start your node" about a node
/// that answered.
pub fn read(endpoint: Option<&str>, token: Option<&str>, timeout: Duration) -> LockedReading {
    let Some(endpoint) = endpoint else {
        return LockedReading::Unknown(LockedUnknown::NoNode);
    };
    match fetch_page(endpoint, token, timeout, None, PAGE) {
        Ok(result) => locked_from(result),
        Err(reason) => LockedReading::Unknown(reason),
    }
}

/// Fetch and decode exactly one page of `control.mirror.bondStates`.
///
/// Shared by [`read`] (which asks for one row to learn the aggregate total) and [`read_badges`]
/// (which walks every page to learn each store's own state) — one transport path, so a fix to how
/// a rejection classifies reaches both rather than needing a matching edit twice.
fn fetch_page(
    endpoint: &str,
    token: Option<&str>,
    timeout: Duration,
    after: Option<MirrorBondKey>,
    limit: u32,
) -> Result<MirrorBondStatesResult, LockedUnknown> {
    let params = serde_json::to_value(MirrorBondStatesParams {
        after,
        limit: Some(limit),
    })
    .expect("the contract params type is plain data and always serializes");
    match control::call_control_raw(endpoint, method(), params, token, timeout) {
        Ok(value) => serde_json::from_value::<MirrorBondStatesResult>(value)
            .map_err(|_| LockedUnknown::Unreadable),
        Err(failure) => Err(ControlAbsence::of(&failure).into()),
    }
}

/// Map the contract's answer onto this app's reading.
///
/// The `entries` are deliberately IGNORED. They describe one page; the figure describes the set.
fn locked_from(result: MirrorBondStatesResult) -> LockedReading {
    match result {
        MirrorBondStatesResult::Known {
            locked_dig_base_units,
            epoch,
            funding_wallet,
            ..
        } => match funding_wallet {
            // A fresh node with no operator wallet yet has no bonds either — an honest zero,
            // not a fault. Keep the measured figure.
            WalletOperatorAddressResult::Unavailable {
                reason: WalletOperatorAddressUnavailableReason::NotInitialized,
            }
            | WalletOperatorAddressResult::Known { .. } => LockedReading::Known {
                locked_dig_base_units,
                epoch,
            },
            // The node has an operator wallet but cannot read it right now — a real fault. The
            // figures are about money whose owner the node cannot currently name, so no numeral
            // may reach the renderer (dig-app#289's invariant, one layer up).
            WalletOperatorAddressResult::Unavailable {
                reason: WalletOperatorAddressUnavailableReason::Unreadable,
            } => LockedReading::Unknown(LockedUnknown::FundingWalletUnreadable),
        },
        MirrorBondStatesResult::Unknown { reason } => {
            LockedReading::Unknown(LockedUnknown::NodeCannotSay(reason))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Per-store bond badges (dig-app#388) — "which of MY capsules has a verified live unspent mirror
// coin on chain right now", one badge per store id on the Content tab's capsule table.
// ---------------------------------------------------------------------------------------------

/// How many pages of `control.mirror.bondStates` a badge walk may read before it gives up.
///
/// Sized generously rather than fitted to a measurement, the same posture
/// [`crate::wallet::coin_list::MAX_PAGES`] takes: at [`MIRROR_BOND_STATES_MAX_LIMIT`] entries per
/// page this covers many thousands of bonds, far more than any node's served set plausibly holds
/// today. A node that never says `complete` is a liveness bug this budget bounds, not a wait this
/// app should honour forever.
const BADGES_MAX_PAGES: usize = 64;

/// Turn the wire cursor into the one string [`crate::paging::walk`] can carry.
///
/// Both halves of a [`MirrorBondKey`] are lowercase 64-hex, which never contains `:`, so a single
/// delimiter round-trips losslessly. This function and [`decode_cursor`] are the only two places
/// that need to agree on the spelling, and both live here.
fn encode_cursor(key: &MirrorBondKey) -> String {
    format!("{}:{}", key.store_id, key.root)
}

/// The inverse of [`encode_cursor`].
///
/// `None` only for a string this module did not produce — which [`crate::paging::walk`] never
/// hands back, since the cursor it passes to `fetch` on page N+1 is always exactly the string page
/// N's [`PageEnd::More`] returned.
fn decode_cursor(cursor: &str) -> Option<MirrorBondKey> {
    let (store_id, root) = cursor.split_once(':')?;
    Some(MirrorBondKey {
        store_id: store_id.to_string(),
        root: root.to_string(),
    })
}

/// What this app can say about ONE store's mirror bond, reduced from every `(store, root)` entry
/// that names it.
///
/// # Why a store can carry more than one entry, and why that is not a conflict
///
/// A bond is keyed on `(store, root)`, never on the store alone — a publisher funds the LATEST
/// root and may be reclaiming an OLDER one at the same time, and both entries are true
/// simultaneously. This type answers the question a person actually has — *"is my store bonded
/// right now"* — by PRIORITISING the entry that answers it (see `rank`), never by
/// picking whichever one the node happened to sort first.
///
/// # The bonded badge is a CHAIN VERDICT, never local optimism
///
/// [`Self::Bonded`] may only be built from [`MirrorBondState::Bonded`] — the contract's own "a
/// coin bonding this pair is ON CHAIN" — never from a belief that a create was attempted. A create
/// this node merely submitted and has not seen confirmed decodes to [`Self::Pending`], which this
/// app renders as a DIFFERENT word specifically so it can never be mistaken for the badge that
/// means money is earning right now (dig-app#388).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorBondBadge {
    /// A verified, currently-unspent coin bonds this store for the epoch named — the ONLY state
    /// this app may show as the bonded badge.
    Bonded {
        /// The epoch this coin bonds, one-based.
        epoch: u64,
        /// What the coin locks, read from the coin itself, never from this epoch's price.
        amount_dig_base_units: u64,
    },
    /// A create has been submitted for this store and has not yet confirmed.
    ///
    /// **Not the bonded badge, and not a fault either.** The node believes it created a coin; the
    /// chain has not shown it yet, so this app has not verified it.
    Pending,
    /// A bonded coin is being reclaimed. The money is still locked until the reclaim confirms, so
    /// this is closer to [`Bonded`](Self::Bonded) than to no-coin-at-all — a badge that showed this
    /// as plain "not bonded" would report locked money as free.
    Reclaiming {
        /// The epoch the reclaiming coin bonds — often a previous one.
        epoch: u64,
        /// What it still locks, read from the coin.
        amount_dig_base_units: u64,
    },
    /// No coin, and why — one variant per REMEDY, never a rough catch-all.
    NotBonded(NotBondedReason),
}

/// Why a store has no live bond right now. See [`crate::collateral::node::CollateralUnknown`] for
/// the sibling taxonomy this deliberately does not reuse verbatim — that type's `remedy()` is
/// paragraph prose for the Collateral pane's caption, and a badge row needs one short clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotBondedReason {
    /// The wallet cannot cover this store's collateral. The genuine shortfall, and the only reason
    /// here a person should read as a call to fund the node.
    Unfunded {
        /// How many more DIG base units this bond alone needs.
        short_dig_base_units: u64,
    },
    /// The epoch's collateral price is not known yet, so no create can be priced. **Not** a
    /// shortfall — the wallet may be full.
    Deferred(CollateralUnknownReason),
    /// This node holds the capsule with relayed provenance and deliberately never advertises it.
    /// Nothing is wrong and nothing is owed.
    Withheld,
    /// Collateralisation is switched off for this node — every store reads this together, and it
    /// is the operator's own earlier decision, not a fault.
    Disabled,
    /// This node has nothing publishable to advertise, so no coin can be created for ANY store.
    /// Node-wide, and the contract requires a client to surface it as a fault: the switch is on
    /// and the node cannot honour it.
    Unadvertised,
}

impl MirrorBondBadge {
    /// Reduce every entry naming one store down to the single state that answers "is it bonded
    /// right now" — see the type's own docs for why more than one entry can exist and why that is
    /// not a conflict. `None` only when `states` was empty, which [`reduce_to_badges`] never calls
    /// this with.
    fn of_entries(states: impl IntoIterator<Item = MirrorBondState>) -> Option<Self> {
        let mut best: Option<Self> = None;
        for state in states {
            let candidate = Self::of_one(state);
            best = Some(match best {
                None => candidate,
                Some(existing) => existing.keep_better(candidate),
            });
        }
        best
    }

    /// One wire state, mapped without judgement — the judgement is [`rank`](Self::rank)'s, applied
    /// once every entry has a badge of its own.
    fn of_one(state: MirrorBondState) -> Self {
        match state {
            MirrorBondState::Bonded {
                epoch,
                amount_dig_base_units,
                ..
            } => Self::Bonded {
                epoch,
                amount_dig_base_units,
            },
            MirrorBondState::Pending => Self::Pending,
            MirrorBondState::Reclaiming {
                epoch,
                amount_dig_base_units,
                ..
            } => Self::Reclaiming {
                epoch,
                amount_dig_base_units,
            },
            MirrorBondState::Unfunded {
                short_dig_base_units,
            } => Self::NotBonded(NotBondedReason::Unfunded {
                short_dig_base_units,
            }),
            MirrorBondState::Deferred { reason } => {
                Self::NotBonded(NotBondedReason::Deferred(reason))
            }
            MirrorBondState::Withheld => Self::NotBonded(NotBondedReason::Withheld),
            MirrorBondState::Disabled => Self::NotBonded(NotBondedReason::Disabled),
            MirrorBondState::Unadvertised => Self::NotBonded(NotBondedReason::Unadvertised),
        }
    }

    /// This badge's priority — lower wins a tie against a sibling entry for the same store.
    ///
    /// Exhaustive on purpose: a rank is assigned to every arm explicitly, so a variant added later
    /// must be given one here rather than silently inheriting whichever number happens to be
    /// nearby in the match.
    fn rank(&self) -> u8 {
        match self {
            Self::Bonded { .. } => 0,
            Self::Pending => 1,
            Self::Reclaiming { .. } => 2,
            Self::NotBonded(NotBondedReason::Unfunded { .. }) => 3,
            Self::NotBonded(NotBondedReason::Deferred(_)) => 4,
            Self::NotBonded(NotBondedReason::Withheld) => 5,
            Self::NotBonded(NotBondedReason::Disabled) => 6,
            Self::NotBonded(NotBondedReason::Unadvertised) => 7,
        }
    }

    /// Keep whichever of `self`/`other` outranks the other — see [`rank`](Self::rank).
    fn keep_better(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }

    /// The one word the badge shows.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Bonded { .. } => "Bonded",
            Self::Pending => "Bond pending",
            Self::Reclaiming { .. } => "Being reclaimed",
            Self::NotBonded(reason) => reason.word(),
        }
    }
}

impl NotBondedReason {
    /// The short clause naming why there is no bond, for a single badge row.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Unfunded { .. } => "Not bonded — wallet is short",
            Self::Deferred(reason) => match reason {
                CollateralUnknownReason::NotCensused => "Not bonded — price not censused yet",
                CollateralUnknownReason::BehindFinalityDepth => {
                    "Not bonded — chain not settled yet"
                }
                CollateralUnknownReason::RecordUnreadable => "Not bonded — price unreadable",
                CollateralUnknownReason::NoChainSource => "Not bonded — no chain connection",
                CollateralUnknownReason::BalanceUnreadable => "Not bonded — wallet unreadable",
            },
            Self::Withheld => "Held, not advertised",
            Self::Disabled => "Collateral is off for this node",
            Self::Unadvertised => "Not bonded — no advertise URL",
        }
    }
}

/// Every store's mirror bond, as one page-walked answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondBadges {
    /// One reduced badge per store id this walk saw an entry for.
    ///
    /// A store id with NO key here was simply not covered by this answer — see
    /// [`complete`](Self::complete) for whether that is a measured absence (this store has nothing
    /// bonded and never has) or a walk that stopped short (nothing is known about it yet).
    pub by_store: BTreeMap<String, MirrorBondBadge>,
    /// Whether every page was walked, on the same terms as
    /// [`super::ActivityLedger::complete`](crate::activity::ActivityLedger::complete): `false`
    /// means a store missing from [`by_store`](Self::by_store) has not been reached yet and must
    /// not be reported as unbonded.
    pub complete: bool,
}

/// What this app knows about every store's mirror bond.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BondBadgesReading {
    /// Nobody has asked yet.
    #[default]
    Pending,
    /// The node answered — see [`BondBadges`] for what a missing store id means.
    Known(BondBadges),
    /// The walk could not produce even a partial answer, and this is which absence it was.
    Unknown(LockedUnknown),
}

impl BondBadgesReading {
    /// This store's badge, or `None` when this answer says nothing about it.
    pub fn badge_for(&self, store_id: &str) -> Option<&MirrorBondBadge> {
        match self {
            Self::Known(badges) => badges.by_store.get(store_id),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// Walk every page of `control.mirror.bondStates`, given a way to fetch one.
///
/// Split from [`read_badges`] so the reduction and the paging RULE are testable against a scripted
/// `fetch_page` and no socket — the same shape [`crate::paging`]'s own tests use, and the one that
/// lets a multi-page node be exercised without a real one.
fn read_badges_from_pages(
    mut fetch_page: impl FnMut(Option<MirrorBondKey>) -> Result<MirrorBondStatesResult, LockedUnknown>,
) -> BondBadgesReading {
    let walked = paging::walk(BADGES_MAX_PAGES, |cursor: Option<&str>| {
        let after = cursor.and_then(decode_cursor);
        match fetch_page(after) {
            Ok(MirrorBondStatesResult::Known {
                entries,
                complete,
                cursor,
                ..
            }) => Ok(paging::Page {
                items: entries,
                end: PageEnd::of_complete(complete, cursor.as_ref().map(encode_cursor).as_deref()),
            }),
            Ok(MirrorBondStatesResult::Unknown { reason }) => {
                Err(LockedUnknown::NodeCannotSay(reason))
            }
            Err(reason) => Err(reason),
        }
    });

    match walked {
        Ok(walk) => BondBadgesReading::Known(BondBadges {
            by_store: reduce_to_badges(walk.items),
            complete: walk.stop.is_whole(),
        }),
        Err(reason) => BondBadgesReading::Unknown(reason),
    }
}

/// Fold every entry into one badge per store id, keeping the highest-priority state a store's
/// entries carry (see [`MirrorBondBadge::of_entries`]).
fn reduce_to_badges(entries: Vec<MirrorBondEntry>) -> BTreeMap<String, MirrorBondBadge> {
    let mut grouped: BTreeMap<String, Vec<MirrorBondState>> = BTreeMap::new();
    for entry in entries {
        grouped.entry(entry.store_id).or_default().push(entry.state);
    }
    grouped
        .into_iter()
        .filter_map(|(store_id, states)| {
            MirrorBondBadge::of_entries(states).map(|badge| (store_id, badge))
        })
        .collect()
}

/// Read every store's mirror bond from the node this machine is running (dig-app#388).
///
/// Returns a [`BondBadgesReading`] rather than a `Result`, for the same reason [`read`] does: no
/// caller may turn an outage into "no bonds", which on this surface is a claim that a store nobody
/// asked about is unbonded.
pub fn read_badges(
    endpoint: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> BondBadgesReading {
    let Some(endpoint) = endpoint else {
        return BondBadgesReading::Unknown(LockedUnknown::NoNode);
    };
    read_badges_from_pages(|after| {
        fetch_page(
            endpoint,
            token,
            timeout,
            after,
            MIRROR_BOND_STATES_MAX_LIMIT,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlFailure;
    use dig_node_control_interface::error::ControlErrorCode;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};
    use dig_node_control_interface::results::{
        MirrorBondEntry, MirrorBondKey, MirrorBondState, MirrorBondStatesResult,
        WalletOperatorAddressResult,
    };

    /// A `known` answer whose PAGE disagrees with its TOTAL in both directions a wrong
    /// implementation could go.
    ///
    /// The fixture is built to distinguish the contract's figure from the nearest wrong
    /// implementation, which is *"add up the rows you were handed"*:
    ///
    /// * the page is INCOMPLETE (`complete: false`), so a summing client stops early;
    /// * the one row it carries is `Reclaiming`, which a client filtering for "still bonded" would
    ///   drop to zero even after summing;
    /// * the total is not any sum of the rows — 61 000 is neither 0 nor the row's 20 000.
    ///
    /// A test whose page happened to add up to the total would pass against every one of those
    /// wrong implementations.
    fn known_page_disagreeing_with_its_total() -> MirrorBondStatesResult {
        MirrorBondStatesResult::Known {
            entries: vec![MirrorBondEntry {
                store_id: "aa".repeat(32),
                root: "bb".repeat(32),
                state: MirrorBondState::Reclaiming {
                    coin_id: "cc".repeat(32),
                    epoch: 6,
                    amount_dig_base_units: 20_000,
                },
            }],
            complete: false,
            cursor: Some(MirrorBondKey {
                store_id: "aa".repeat(32),
                root: "bb".repeat(32),
            }),
            locked_dig_base_units: 61_000,
            epoch: 7,
            funding_wallet: WalletOperatorAddressResult::Known {
                address: "xch1".to_string() + &"q".repeat(58),
                puzzle_hash: "dd".repeat(32),
            },
        }
    }

    /// The figure is the node's whole-set total, never the page.
    ///
    /// This is the money-direction test: every wrong implementation available here under-reports,
    /// and under-reporting locked collateral shows unspendable $DIG as available.
    #[test]
    fn the_total_is_read_from_the_contract_not_summed_from_the_page() {
        assert_eq!(
            locked_from(known_page_disagreeing_with_its_total()),
            LockedReading::Known {
                locked_dig_base_units: 61_000,
                epoch: 7,
            }
        );
    }

    /// A `Known` chain-read result whose FUNDING WALLET is unreadable must never render a numeral.
    ///
    /// `funding_wallet` is read independently of the chain observation that produces
    /// `locked_dig_base_units` (dig-node `control.rs`), so a node can decode a `Known` result while
    /// itself faulting on naming its own operator wallet. Before this fix, `locked_from`'s wildcard
    /// `..` discarded `funding_wallet` entirely and rendered the figure regardless — a locked-DIG
    /// total about a wallet the node cannot name (dig-app#360).
    #[test]
    fn a_known_result_with_an_unreadable_funding_wallet_renders_no_numeral() {
        let result = MirrorBondStatesResult::Known {
            entries: vec![],
            complete: true,
            cursor: None,
            locked_dig_base_units: 61_000,
            epoch: 7,
            funding_wallet: WalletOperatorAddressResult::Unavailable {
                reason: WalletOperatorAddressUnavailableReason::Unreadable,
            },
        };
        let reading = locked_from(result);
        assert_eq!(
            reading,
            LockedReading::Unknown(LockedUnknown::FundingWalletUnreadable)
        );
        let heading = reading.heading();
        assert!(!heading.contains("61"), "{heading}");
        assert!(!heading.contains("Nothing is locked"), "{heading}");
    }

    /// A fresh node with no operator wallet yet still reports an honest measured zero (dig-app#289).
    ///
    /// `NotInitialized` is the "nothing is wrong yet" reason on the wallet-address contract — a
    /// node that has never run its autoseed setup has no bonds either, and this must NOT be
    /// confused with `Unreadable`'s real fault.
    #[test]
    fn a_fresh_node_with_no_operator_wallet_still_reports_a_known_zero() {
        let result = MirrorBondStatesResult::Known {
            entries: vec![],
            complete: true,
            cursor: None,
            locked_dig_base_units: 0,
            epoch: 1,
            funding_wallet: WalletOperatorAddressResult::Unavailable {
                reason: WalletOperatorAddressUnavailableReason::NotInitialized,
            },
        };
        let reading = locked_from(result);
        assert_eq!(
            reading,
            LockedReading::Known {
                locked_dig_base_units: 0,
                epoch: 1,
            }
        );
        assert_eq!(reading.heading(), "Nothing is locked up in collateral.");
    }

    /// $DIG is a CAT at three decimals, so 61 000 base units is 61 $DIG — not 61 000 of anything.
    #[test]
    fn the_heading_renders_base_units_as_whole_dig() {
        let heading = locked_from(known_page_disagreeing_with_its_total()).heading();
        assert!(heading.contains("61 $DIG"), "{heading}");
        assert!(!heading.contains("61000"), "{heading}");
        assert!(!heading.contains("61,000"), "{heading}");
    }

    /// A node that cannot say must not produce a numeral, whatever its reason.
    ///
    /// Swept over the contract's WHOLE reason set rather than one sample, because a match arm added
    /// later is exactly the kind of thing that acquires a default of zero.
    #[test]
    fn a_node_that_cannot_say_never_renders_a_figure() {
        for reason in MirrorBondStatesUnknownReason::ALL {
            let reading = locked_from(MirrorBondStatesResult::Unknown { reason: *reason });
            let heading = reading.heading();
            assert!(
                matches!(
                    reading,
                    LockedReading::Unknown(LockedUnknown::NodeCannotSay(_))
                ),
                "{reason:?} decoded as {reading:?}"
            );
            assert!(
                !heading.contains('0') && !heading.contains("Nothing is locked"),
                "{reason:?} rendered a figure: {heading}"
            );
        }
    }

    /// A MEASURED zero and an un-measured one are different sentences.
    ///
    /// Both are short and both mention nothing being locked, so the assertion is on the pair being
    /// DISTINCT rather than on either one's wording: the defect this guards is the two collapsing.
    #[test]
    fn a_measured_zero_reads_differently_from_an_unobtained_one() {
        let measured = LockedReading::Known {
            locked_dig_base_units: 0,
            epoch: 7,
        }
        .heading();
        let unobtained = LockedReading::Unknown(LockedUnknown::NoNode).heading();
        let pending = LockedReading::Pending.heading();

        assert_eq!(measured, "Nothing is locked up in collateral.");
        assert_ne!(measured, unobtained);
        assert_ne!(measured, pending);
        assert!(!unobtained.contains("Nothing is locked"), "{unobtained}");
        assert!(!pending.contains("Nothing is locked"), "{pending}");
    }

    /// The default reading is `Pending`, so a view built before any read cannot claim a zero.
    #[test]
    fn the_default_reading_has_measured_nothing() {
        assert_eq!(LockedReading::default(), LockedReading::Pending);
    }

    /// A control rejection carrying `code` in its stable symbol slot.
    fn rejected(code: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32601,
            message: "no".to_string(),
            data: ControlErrorData {
                code: code.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    /// An old node maps to its own absence, distinct from a node that answered zero.
    ///
    /// Exercised through the SHARED mapping plus this surface's conversion, which is the pair that
    /// actually runs. A test against a private copy of the mapping would keep passing if this
    /// surface stopped consuming the shared one (dig-app#329).
    #[test]
    fn a_node_without_the_method_is_too_old_rather_than_empty() {
        assert_eq!(
            LockedUnknown::from(ControlAbsence::of(&rejected(
                ControlErrorCode::MethodNotFound.name()
            ))),
            LockedUnknown::NotSupported
        );
        assert_eq!(
            LockedUnknown::from(ControlAbsence::of(&rejected("UNAUTHORIZED"))),
            LockedUnknown::Refused
        );
        assert_eq!(
            LockedUnknown::from(ControlAbsence::of(&rejected("SOMETHING_ELSE"))),
            LockedUnknown::Unreadable
        );
    }

    /// No two absences collapse onto one arm as they cross into this surface.
    ///
    /// The nearest wrong conversion is one that maps a pair of distinct absences to the same
    /// `LockedUnknown` — a `_ =>` arm added to silence a build error does exactly that, and every
    /// per-value assertion above still passes under it for the values it happens to name.
    #[test]
    fn distinct_absences_stay_distinct_on_this_surface() {
        let mapped: Vec<LockedUnknown> = ControlAbsence::ALL
            .into_iter()
            .map(LockedUnknown::from)
            .collect();
        for (i, a) in mapped.iter().enumerate() {
            for b in &mapped[i + 1..] {
                assert_ne!(
                    a, b,
                    "two control absences collapsed onto one locked-collateral reason"
                );
            }
        }
    }

    /// Every absence names something, so no arm can render an empty clause.
    #[test]
    fn every_absence_names_a_reason() {
        let mut absences = vec![
            LockedUnknown::NoNode,
            LockedUnknown::NotSupported,
            LockedUnknown::Refused,
            LockedUnknown::Unreadable,
            LockedUnknown::FundingWalletUnreadable,
        ];
        absences.extend(
            MirrorBondStatesUnknownReason::ALL
                .iter()
                .map(|r| LockedUnknown::NodeCannotSay(*r)),
        );
        for absence in absences {
            assert!(!absence.reason().is_empty(), "{absence:?}");
        }
    }

    /// The method string comes from the contract, so it is the one the node dispatches.
    #[test]
    fn the_method_is_the_contracts_own_name() {
        assert_eq!(method(), "control.mirror.bondStates");
    }

    // ---------------------------------------------------------------------------------------
    // Per-store bond badges (dig-app#388)
    // ---------------------------------------------------------------------------------------

    fn bonded(epoch: u64, amount: u64) -> MirrorBondState {
        MirrorBondState::Bonded {
            coin_id: "aa".repeat(32),
            epoch,
            amount_dig_base_units: amount,
        }
    }

    fn reclaiming(epoch: u64, amount: u64) -> MirrorBondState {
        MirrorBondState::Reclaiming {
            coin_id: "bb".repeat(32),
            epoch,
            amount_dig_base_units: amount,
        }
    }

    /// **A store's badge is the BEST state it carries, regardless of which order the entries
    /// arrive in.**
    ///
    /// A publisher funds the latest root and may be reclaiming an older one at the same time, so
    /// one store legitimately carries both a `Bonded` and a `Reclaiming` entry. The fixture is run
    /// TWICE, in both orders: a wrong implementation that simply kept "the last entry seen" or
    /// "the first entry seen" would pass in one order and fail in the other, so only the
    /// order-independent (priority-based) reduction passes both.
    #[test]
    fn a_store_carrying_both_a_bonded_and_a_reclaiming_root_reduces_to_bonded() {
        let forward = MirrorBondBadge::of_entries([bonded(9, 20_000), reclaiming(8, 15_000)]);
        let backward = MirrorBondBadge::of_entries([reclaiming(8, 15_000), bonded(9, 20_000)]);

        for badge in [forward, backward] {
            assert_eq!(
                badge,
                Some(MirrorBondBadge::Bonded {
                    epoch: 9,
                    amount_dig_base_units: 20_000,
                }),
                "a live bond outranks a reclaiming one, in either arrival order"
            );
        }
    }

    /// **`Pending` decodes to a DIFFERENT badge than `Bonded`, never the same one.**
    ///
    /// This is dig-app#388's own requirement stated as a test: a node that BELIEVES it created a
    /// coin must never render the badge that means a chain-verified live bond.
    #[test]
    fn a_pending_create_never_reduces_to_the_bonded_badge() {
        let badge = MirrorBondBadge::of_entries([MirrorBondState::Pending]);
        assert_eq!(badge, Some(MirrorBondBadge::Pending));
        assert_ne!(
            badge.unwrap().word(),
            MirrorBondBadge::Bonded {
                epoch: 1,
                amount_dig_base_units: 1
            }
            .word(),
            "a pending create must read as a different word than a verified bond"
        );
    }

    /// **`reduce_to_badges` groups by store id and does not cross-contaminate two stores.**
    ///
    /// Two stores, each with a state the OTHER store does not have, so a swap or an off-by-one in
    /// the grouping shows up as a wrong badge on a specific key rather than merely a wrong count.
    #[test]
    fn reduce_to_badges_keeps_each_store_to_its_own_entries() {
        let store_a = "aa".repeat(32);
        let store_b = "bb".repeat(32);
        let entries = vec![
            MirrorBondEntry {
                store_id: store_a.clone(),
                root: "11".repeat(32),
                state: bonded(5, 1_000),
            },
            MirrorBondEntry {
                store_id: store_b.clone(),
                root: "22".repeat(32),
                state: MirrorBondState::Unfunded {
                    short_dig_base_units: 500,
                },
            },
        ];

        let reduced = reduce_to_badges(entries);

        assert_eq!(
            reduced.get(&store_a),
            Some(&MirrorBondBadge::Bonded {
                epoch: 5,
                amount_dig_base_units: 1_000
            })
        );
        assert_eq!(
            reduced.get(&store_b),
            Some(&MirrorBondBadge::NotBonded(NotBondedReason::Unfunded {
                short_dig_base_units: 500
            }))
        );
    }

    /// A page-fetch cursor round-trips through [`encode_cursor`]/[`decode_cursor`] unchanged.
    #[test]
    fn a_cursor_round_trips_through_its_own_encoding() {
        let key = MirrorBondKey {
            store_id: "cc".repeat(32),
            root: "dd".repeat(32),
        };
        assert_eq!(decode_cursor(&encode_cursor(&key)), Some(key));
    }

    fn known_page(
        entries: Vec<MirrorBondEntry>,
        complete: bool,
        cursor: Option<MirrorBondKey>,
    ) -> MirrorBondStatesResult {
        MirrorBondStatesResult::Known {
            entries,
            complete,
            cursor,
            locked_dig_base_units: 0,
            epoch: 1,
            funding_wallet: WalletOperatorAddressResult::Known {
                address: "xch1".to_string() + &"q".repeat(58),
                puzzle_hash: "dd".repeat(32),
            },
        }
    }

    /// **A single complete page reads in one call and needs no cursor.**
    #[test]
    fn a_single_complete_page_reads_in_one_call() {
        let store = "ee".repeat(32);
        let mut calls = 0;
        let reading = read_badges_from_pages(|after| {
            calls += 1;
            assert_eq!(after, None, "the first call must ask for the first page");
            Ok(known_page(
                vec![MirrorBondEntry {
                    store_id: store.clone(),
                    root: "ff".repeat(32),
                    state: bonded(3, 7_000),
                }],
                true,
                None,
            ))
        });

        assert_eq!(calls, 1);
        let BondBadgesReading::Known(badges) = reading else {
            panic!("expected a Known answer: {reading:?}");
        };
        assert!(badges.complete);
        assert_eq!(
            badges.by_store.get(&store),
            Some(&MirrorBondBadge::Bonded {
                epoch: 3,
                amount_dig_base_units: 7_000
            })
        );
    }

    /// **A truncated node is walked across MORE THAN ONE call, and the second call resumes from
    /// the FIRST page's own cursor.**
    ///
    /// This is the test that actually exercises the cursor round trip end to end: a fixture where
    /// page one and page two name DIFFERENT stores catches an implementation that decoded the
    /// cursor wrong and silently re-served (or skipped) a page, because the wrong store would be
    /// missing rather than merely a wrong count.
    #[test]
    fn a_two_page_walk_resumes_from_the_first_pages_cursor() {
        let store_1 = "11".repeat(32);
        let store_2 = "22".repeat(32);
        let cursor_key = MirrorBondKey {
            store_id: store_1.clone(),
            root: "aa".repeat(32),
        };
        let mut calls: Vec<Option<MirrorBondKey>> = Vec::new();

        let reading = read_badges_from_pages(|after| {
            calls.push(after.clone());
            match after {
                None => Ok(known_page(
                    vec![MirrorBondEntry {
                        store_id: store_1.clone(),
                        root: "aa".repeat(32),
                        state: bonded(2, 4_000),
                    }],
                    false,
                    Some(cursor_key.clone()),
                )),
                Some(ref key) if *key == cursor_key => Ok(known_page(
                    vec![MirrorBondEntry {
                        store_id: store_2.clone(),
                        root: "bb".repeat(32),
                        state: reclaiming(1, 2_000),
                    }],
                    true,
                    None,
                )),
                other => panic!("resumed from the wrong cursor: {other:?}"),
            }
        });

        assert_eq!(calls.len(), 2, "the walk must ask for exactly two pages");
        let BondBadgesReading::Known(badges) = reading else {
            panic!("expected a Known answer: {reading:?}");
        };
        assert!(badges.complete);
        assert_eq!(
            badges.by_store.get(&store_1),
            Some(&MirrorBondBadge::Bonded {
                epoch: 2,
                amount_dig_base_units: 4_000
            }),
            "the first page's store must survive into the combined answer"
        );
        assert_eq!(
            badges.by_store.get(&store_2),
            Some(&MirrorBondBadge::Reclaiming {
                epoch: 1,
                amount_dig_base_units: 2_000
            }),
            "the second page's store must be reached at all"
        );
    }

    /// **A node that cannot say ANYTHING makes the whole walk `Unknown`, even after a good first
    /// page.**
    ///
    /// The contract's own posture on [`MirrorBondStatesResult::Unknown`] is whole-answer-or-nothing
    /// precisely so a partial list is never mistaken for a complete one; a walk that kept the first
    /// page's rows and merely flagged the second as missing would reintroduce exactly that
    /// ambiguity one layer up.
    #[test]
    fn an_unknown_page_discards_the_whole_walk_not_only_itself() {
        let mut calls = 0;
        let reading = read_badges_from_pages(|after| {
            calls += 1;
            match after {
                None => Ok(known_page(
                    vec![MirrorBondEntry {
                        store_id: "33".repeat(32),
                        root: "44".repeat(32),
                        state: bonded(1, 1_000),
                    }],
                    false,
                    Some(MirrorBondKey {
                        store_id: "33".repeat(32),
                        root: "44".repeat(32),
                    }),
                )),
                Some(_) => Ok(MirrorBondStatesResult::Unknown {
                    reason: MirrorBondStatesUnknownReason::ChainUnreadable,
                }),
            }
        });

        assert_eq!(calls, 2);
        assert_eq!(
            reading,
            BondBadgesReading::Unknown(LockedUnknown::NodeCannotSay(
                MirrorBondStatesUnknownReason::ChainUnreadable
            )),
            "a call-level unknown must not present as a partial Known: {reading:?}"
        );
    }

    /// **With no node there is nothing to ask, and the answer says so.**
    #[test]
    fn no_node_reports_no_node_without_calling_fetch() {
        assert_eq!(
            read_badges(None, None, BONDS_READ_TIMEOUT),
            BondBadgesReading::Unknown(LockedUnknown::NoNode)
        );
    }

    /// **Every `NotBondedReason` names a distinct, non-empty word** — the exhaustive-arm guard
    /// this codebase keeps everywhere a reason drives copy, so a reason added later cannot ship
    /// silently mute or silently identical to a neighbour.
    #[test]
    fn every_not_bonded_reason_names_a_distinct_word() {
        let reasons = [
            NotBondedReason::Unfunded {
                short_dig_base_units: 1,
            },
            NotBondedReason::Deferred(CollateralUnknownReason::NotCensused),
            NotBondedReason::Deferred(CollateralUnknownReason::BehindFinalityDepth),
            NotBondedReason::Deferred(CollateralUnknownReason::RecordUnreadable),
            NotBondedReason::Deferred(CollateralUnknownReason::NoChainSource),
            NotBondedReason::Deferred(CollateralUnknownReason::BalanceUnreadable),
            NotBondedReason::Withheld,
            NotBondedReason::Disabled,
            NotBondedReason::Unadvertised,
        ];
        let words: Vec<&str> = reasons.iter().map(NotBondedReason::word).collect();
        for (i, word) in words.iter().enumerate() {
            assert!(!word.is_empty(), "{:?}", reasons[i]);
            for (j, other) in words.iter().enumerate() {
                if i != j {
                    assert_ne!(word, other, "{:?} vs {:?}", reasons[i], reasons[j]);
                }
            }
        }
    }

    /// **The badge word for `Bonded` never appears on any `NotBonded` reason's word** — the
    /// specific confusion dig-app#388 exists to prevent, checked directly on the rendered text
    /// rather than only on the enum's shape.
    #[test]
    fn no_not_bonded_word_reads_as_bonded() {
        let bonded_word = MirrorBondBadge::Bonded {
            epoch: 1,
            amount_dig_base_units: 1,
        }
        .word();
        for reason in [
            NotBondedReason::Unfunded {
                short_dig_base_units: 1,
            },
            NotBondedReason::Withheld,
            NotBondedReason::Disabled,
            NotBondedReason::Unadvertised,
        ] {
            assert_ne!(reason.word(), bonded_word, "{reason:?}");
        }
    }
}
