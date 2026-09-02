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

use dig_node_control_interface::params::MirrorBondStatesParams;
use dig_node_control_interface::results::{MirrorBondStatesResult, MirrorBondStatesUnknownReason};
use dig_node_control_interface::traits::ControlCall;

use crate::amount::amount_with_unit;
use crate::control;

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
    let params = serde_json::to_value(MirrorBondStatesParams {
        after: None,
        limit: Some(PAGE),
    })
    .expect("the contract params type is plain data and always serializes");
    match control::call_control_raw(endpoint, method(), params, token, timeout) {
        Ok(value) => match serde_json::from_value::<MirrorBondStatesResult>(value) {
            Ok(result) => locked_from(result),
            Err(_) => LockedReading::Unknown(LockedUnknown::Unreadable),
        },
        Err(failure) => LockedReading::Unknown(ControlAbsence::of(&failure).into()),
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
            ..
        } => LockedReading::Known {
            locked_dig_base_units,
            epoch,
        },
        MirrorBondStatesResult::Unknown { reason } => {
            LockedReading::Unknown(LockedUnknown::NodeCannotSay(reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlFailure;
    use dig_node_control_interface::error::ControlErrorCode;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};
    use dig_node_control_interface::results::{
        MirrorBondEntry, MirrorBondKey, MirrorBondState, MirrorBondStatesResult,
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
}
