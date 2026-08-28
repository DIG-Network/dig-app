//! The collateral control-plane seam (dig-app#302): the epoch requirement and the safety margin,
//! read from and written to the NODE.
//!
//! # Why the margin is not stored here
//!
//! It used to be. `AgentConfig` held a `collateral: SafetyMargin` field, dig-app wrote it, and the
//! node kept its own copy in its own config — two writers of one setting, on a money path.
//!
//! That is a drift bug with a direction. The node is the process that actually posts the
//! collateral, so when the two copies disagree the node's is what a person's $DIG does and the
//! app's is what they were shown. A surface that displays a margin the node is not applying is
//! lying about money, and it would do so most convincingly right after the app wrote a value the
//! node declined.
//!
//! So there is exactly one copy, it lives in the node, and this module is the only way dig-app
//! touches it: [`read_margin`] to learn it, [`write_margin`] to change it. **Nothing in dig-app
//! caches the answer.** `.set` returns the margin now in force rather than echoing the request, so
//! even a write that was clamped leaves the app showing what the node applied.
//!
//! # Why the requirement is a reading and not a number
//!
//! The requirement is consensus-derived: every node computes it from the same chain census, and a
//! single differing DIG base unit forks the network. dig-app therefore never derives it — it asks,
//! and it is prepared to be told *no*.
//!
//! `control.collateral.requirement` makes that first-class: [`CollateralRequirementResult::Unknown`]
//! is a normal answer, not an error. A node that has not censused the epoch, or that is inside the
//! census finality depth, is working correctly and simply does not know yet. Every such answer —
//! together with every transport failure and every refusal — lands in
//! [`RequirementReading::Unknown`], which the surfaces render as *unknown* and which the funding
//! notification treats as **silence**. There is no path in this module that turns an unknown into a
//! zero.
//!
//! # Method-not-found is expected, not exceptional
//!
//! These three verbs are declared in `dig-node-control-interface` 0.23.0 and are being implemented
//! in the node separately. Until that ships, **every node in the world answers
//! `METHOD_NOT_FOUND`** — so [`CollateralUnknown::NodeCannotRead`] is the ordinary case on a real
//! machine today, and it names an upgrade as its remedy rather than reading as a fault.

use std::time::Duration;

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::{
    CollateralMarginGetParams, CollateralMarginSetParams, CollateralRequirementParams,
};
use dig_node_control_interface::results::{CollateralRequirementResult, CollateralUnknownReason};

use crate::collateral::SafetyMargin;
use crate::control::{self, ControlCallError, ControlFailure};

/// This epoch's requirement, exactly as one node reported it.
///
/// The census inputs travel with the figure because the contract carries them for that purpose: a
/// client holding only the number can say the price moved, and a client holding `stores`, `owners`,
/// `multiplier_micros` and `handicap_dig_base_units` can say **why**. That difference is what turns
/// an alarm into something an operator can weigh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRequirement {
    /// The epoch this requirement governs, one-based.
    pub epoch: u64,
    /// The collateral protocol version that computed this epoch. Carried because the model is
    /// versioned: a client that knows only the number cannot tell a disagreement from a rule change.
    pub protocol_version: u16,
    /// The per-store requirement in $DIG base units, **before** any local safety margin.
    pub required_per_store_dig_base_units: u64,
    /// Qualifying `(owner, store, root)` advertisements counted in the census — an advertisement
    /// count, never a node count.
    pub stores: u64,
    /// Distinct owner puzzle hashes across those advertisements. A surface showing it must say
    /// "collateralised owners"; it is neither a node count nor an operator count.
    pub owners: u64,
    /// The controller multiplier for the epoch, in millionths.
    pub multiplier_micros: u64,
    /// The small-network handicap applied for the epoch, in $DIG base units.
    pub handicap_dig_base_units: u64,
}

/// What the app knows about this epoch's requirement.
///
/// Three variants for the reason [`HostedStoresReading`](crate::hosted_stores::HostedStoresReading)
/// has three: a read in flight has made no claim, and a read that failed has made a different claim
/// again. Collapsing either into a number is how an unknown becomes a confident zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RequirementReading {
    /// A read is under way and nothing has failed. Naming a reason here would invent one.
    ///
    /// **The default**, because it is what every surface renders before its first read returns:
    /// `Pending` promises an answer is coming, where an `Unknown` would name a fault that has not
    /// happened.
    #[default]
    Pending,
    /// A node stated the requirement for an epoch.
    Known(EpochRequirement),
    /// No requirement is available, and which fact is missing.
    Unknown(CollateralUnknown),
}

impl RequirementReading {
    /// The per-store requirement when one is known, for the arithmetic that needs the bare number.
    ///
    /// Deliberately an `Option` at the point of USE rather than a field that is sometimes zero: a
    /// caller has to open it, and the compiler makes them say what happens when it is empty.
    #[must_use]
    pub fn per_store(&self) -> Option<u64> {
        match self {
            Self::Known(known) => Some(known.required_per_store_dig_base_units),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// What the app knows about the node's local safety margin.
///
/// The margin is a plain local preference, so — unlike the requirement — a node that answers at all
/// always has one. The three states are about the READ, not about the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MarginReading {
    /// A read is under way. **The default**, for the same reason
    /// [`RequirementReading::Pending`] is.
    #[default]
    Pending,
    /// The node reported the margin it is applying.
    Known(SafetyMargin),
    /// The margin could not be read, and why.
    Unknown(CollateralUnknown),
}

impl MarginReading {
    /// The margin when one was reported.
    ///
    /// **There is deliberately no "or the default" accessor.** A caller that cannot read the margin
    /// must say so, not substitute +1% — the whole point of moving the value to the node is that
    /// the app never shows a margin the node might not be applying.
    #[must_use]
    pub fn margin(&self) -> Option<SafetyMargin> {
        match self {
            Self::Known(margin) => Some(*margin),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// Why no collateral figure is available. **One variant per REMEDY**, never per rough category —
/// the reason is the only thing that tells a person whether to wait, upgrade, fix a permission, or
/// start their node.
///
/// The first four arms mirror [`CollateralUnknownReason`] from the contract, which the node uses to
/// say *"I am fine, I just do not know yet"*. The rest describe failures of the READ itself. Both
/// kinds are unknown and neither is ever rendered as a number, but they lead to different sentences.
#[cfg_attr(test, derive(strum::EnumIter))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollateralUnknown {
    /// The node has not censused the epoch yet. A wait, not a fault.
    NotCensused,
    /// The node is inside the census finality depth, so no final record exists yet. Also a wait.
    BehindFinalityDepth,
    /// The node holds a record for the epoch and could not read it.
    RecordUnreadable,
    /// The node has no chain source, so it cannot census at all. The remedy is the node's chain
    /// configuration, not this app.
    NoChainSource,
    /// No node is connected, so there is nothing to ask.
    NoNode,
    /// A node answered and does not serve this method. **The ordinary case today** — the verbs are
    /// declared in the 0.23.0 contract and the node side ships separately. The remedy is an upgrade.
    NodeCannotRead,
    /// A node answered and refused this app. The remedy is the control token, NOT an upgrade: these
    /// methods are token-gated, so a refusal is a permission fault on a capable node.
    Unauthorized,
    /// The socket opened and the read overran its budget. Kept apart from
    /// [`Unreachable`](Self::Unreachable) all the way to the sentence a person reads, because only
    /// `Unreachable` is evidence about whether a node exists.
    TimedOut(String),
    /// The node could not be reached for this read.
    Unreachable(String),
    /// The node refused for a reason we cannot classify; its own words are carried.
    ReadFailed(String),
}

impl CollateralUnknown {
    /// Every reason, for the tests and screenshots that must cover all of them.
    ///
    /// Hand-listed because three variants carry payloads and Rust cannot enumerate those, but
    /// asserted complete by `every_reason_is_in_all` — without which an eleventh reason would ship
    /// with no sentence of its own while every surface test stayed green.
    #[cfg(test)]
    pub(crate) fn all() -> Vec<Self> {
        vec![
            Self::NotCensused,
            Self::BehindFinalityDepth,
            Self::RecordUnreadable,
            Self::NoChainSource,
            Self::NoNode,
            Self::NodeCannotRead,
            Self::Unauthorized,
            Self::TimedOut("the read took longer than 10s".to_string()),
            Self::Unreachable("connection refused".to_string()),
            Self::ReadFailed("the node fell over".to_string()),
        ]
    }

    /// The node's own "I do not know yet" reason, mapped to ours.
    ///
    /// A total match rather than a catch-all, so a fifth reason added upstream is a compile error
    /// here instead of silently becoming whichever arm the wildcard pointed at.
    fn of_wire(reason: CollateralUnknownReason) -> Self {
        match reason {
            CollateralUnknownReason::NotCensused => Self::NotCensused,
            CollateralUnknownReason::BehindFinalityDepth => Self::BehindFinalityDepth,
            CollateralUnknownReason::RecordUnreadable => Self::RecordUnreadable,
            CollateralUnknownReason::NoChainSource => Self::NoChainSource,
        }
    }
}

/// The `data.code` symbols meaning "this build does not serve the method at all".
///
/// Taken from the contract crate rather than retyped, so a rename upstream is a compile error here
/// instead of a silently unmatched string.
const CANNOT_SERVE: &[&str] = &[
    ControlErrorCode::MethodNotFound.name(),
    ControlErrorCode::NotSupported.name(),
];

/// Turn a control-plane failure into the typed reason a surface renders from.
///
/// Keyed on the stable UPPER_SNAKE `data.code`, never on the human message — the contract states
/// explicitly that the message is not stable, so matching on its words would break on a reword.
fn classify(failure: ControlFailure) -> CollateralUnknown {
    match failure {
        ControlFailure::Transport(ControlCallError::Unreachable(detail)) => {
            CollateralUnknown::Unreachable(detail)
        }
        ControlFailure::Transport(ControlCallError::TimedOut(detail)) => {
            CollateralUnknown::TimedOut(detail)
        }
        // These methods are token-gated and dig-node refuses at the HTTP layer, before any JSON-RPC
        // error exists to carry a `data.code`. That is a permission fault with a real remedy, so it
        // must not fall through to "the read failed", which names none.
        ControlFailure::Transport(ControlCallError::HttpRefused {
            code: 401 | 403, ..
        }) => CollateralUnknown::Unauthorized,
        ControlFailure::Transport(e) => CollateralUnknown::ReadFailed(e.to_string()),
        ControlFailure::Rejected(e) if CANNOT_SERVE.contains(&e.data.code.as_str()) => {
            CollateralUnknown::NodeCannotRead
        }
        ControlFailure::Rejected(e) if e.data.code == ControlErrorCode::Unauthorized.name() => {
            CollateralUnknown::Unauthorized
        }
        ControlFailure::Rejected(e) => CollateralUnknown::ReadFailed(e.message),
    }
}

/// Read this epoch's collateral requirement from the node at `endpoint`, once.
///
/// The node's own `Unknown { reason }` and every failure of the read both produce
/// [`RequirementReading::Unknown`] — they differ in the sentence they name, never in whether a
/// number appears.
pub fn read_requirement(
    endpoint: &str,
    token: Option<&str>,
    timeout: Duration,
) -> RequirementReading {
    match control::call_control_result(endpoint, &CollateralRequirementParams {}, token, timeout) {
        Ok(CollateralRequirementResult::Known {
            epoch,
            protocol_version,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            handicap_dig_base_units,
        }) => RequirementReading::Known(EpochRequirement {
            epoch,
            protocol_version,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            handicap_dig_base_units,
        }),
        Ok(CollateralRequirementResult::Unknown { reason }) => {
            RequirementReading::Unknown(CollateralUnknown::of_wire(reason))
        }
        Err(failure) => RequirementReading::Unknown(classify(failure)),
    }
}

/// Read the node's local safety margin from the node at `endpoint`, once.
pub fn read_margin(endpoint: &str, token: Option<&str>, timeout: Duration) -> MarginReading {
    match control::call_control_result(endpoint, &CollateralMarginGetParams {}, token, timeout) {
        Ok(result) => MarginReading::Known(SafetyMargin::of_basis_points(result.margin_bp)),
        Err(failure) => MarginReading::Unknown(classify(failure)),
    }
}

/// Set the node's local safety margin, and report **the margin now in force**.
///
/// # Why this returns a reading rather than a `Result<(), _>`
///
/// `.set` answers with the margin the node applied, which need not be the one requested: the node
/// refuses a value above its own ceiling, and a request the app clamped differently would otherwise
/// leave the two surfaces disagreeing about a money setting. Returning the node's answer means the
/// chooser redraws from what the node holds — never from what was clicked. It is the same rule the
/// cache cap already follows, and the same rule the settings pane's config read-back followed when
/// the margin still lived in a file.
///
/// A failed write is [`MarginReading::Unknown`] and not a stale `Known`, so a press that did not
/// land can never leave a confident figure on screen.
pub fn write_margin(
    endpoint: &str,
    margin_bp: u64,
    token: Option<&str>,
    timeout: Duration,
) -> MarginReading {
    // Clamped through the app's own ceiling before the call, for the reason
    // `SafetyMargin::of_basis_points` clamps rather than rejects: a refused write leaves the node on
    // whatever it held, which is the LOWER posting, and that is the one direction a safety margin
    // must never fail in. The node clamps again on its side and its answer is what is displayed.
    let params = CollateralMarginSetParams {
        margin_bp: SafetyMargin::of_basis_points(margin_bp).margin_bp,
    };
    match control::call_control_result(endpoint, &params, token, timeout) {
        Ok(result) => MarginReading::Known(SafetyMargin::of_basis_points(result.margin_bp)),
        Err(failure) => MarginReading::Unknown(classify(failure)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};
    use strum::IntoEnumIterator;

    /// A node rejection carrying `symbol` as its stable `data.code`.
    fn rejected(symbol: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32601,
            message: "the node said something not worth matching on".to_string(),
            data: ControlErrorData {
                code: symbol.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    /// **Every reason has a place in `all()`**, so no variant ships without a sentence or a picture.
    #[test]
    fn every_reason_is_in_all() {
        let listed = CollateralUnknown::all();
        for reason in CollateralUnknown::iter() {
            assert!(
                listed
                    .iter()
                    .any(|held| std::mem::discriminant(held) == std::mem::discriminant(&reason)),
                "{reason:?} is a reason with no entry in all()"
            );
        }
    }

    /// **A node that does not serve the method names an UPGRADE, not a fault.**
    ///
    /// This is the ordinary answer from every node in the world until the server side ships, so
    /// getting it wrong would mislabel the normal case as a broken node. Both symbols are asserted
    /// because the contract publishes two ways of saying it and only one of them was ever seen in
    /// testing.
    #[test]
    fn an_unserved_method_reads_as_a_node_that_needs_upgrading() {
        for symbol in CANNOT_SERVE {
            assert_eq!(
                classify(rejected(symbol)),
                CollateralUnknown::NodeCannotRead,
                "{symbol} must name an upgrade"
            );
        }
    }

    /// **A permission fault is never reported as an incapable node**, at either layer it can arrive.
    ///
    /// dig-node gates these methods at the HTTP layer, so the 401 arrives as a TRANSPORT failure
    /// with no `data.code` at all — a classifier that only inspected rejections would file it under
    /// "the read failed" and name no remedy. The JSON-RPC form is asserted beside it so the pair
    /// fails if either path regresses.
    #[test]
    fn a_permission_fault_names_the_token_at_both_layers() {
        assert_eq!(
            classify(ControlFailure::Transport(ControlCallError::HttpRefused {
                code: 401,
                detail: "no control token".to_string(),
            })),
            CollateralUnknown::Unauthorized
        );
        assert_eq!(
            classify(ControlFailure::Transport(ControlCallError::HttpRefused {
                code: 403,
                detail: "wrong control token".to_string(),
            })),
            CollateralUnknown::Unauthorized
        );
        assert_eq!(
            classify(rejected(ControlErrorCode::Unauthorized.name())),
            CollateralUnknown::Unauthorized
        );
    }

    /// **A timeout and an unreachable node stay apart.**
    ///
    /// Only a refused connection is evidence about whether a node EXISTS; a node that accepted and
    /// then took too long is demonstrably there. Collapsing them would let a slow read be reported
    /// as "no node is running", which is a different sentence with a different remedy.
    #[test]
    fn a_timeout_is_not_an_absent_node() {
        assert_eq!(
            classify(ControlFailure::Transport(ControlCallError::TimedOut(
                "10s".to_string()
            ))),
            CollateralUnknown::TimedOut("10s".to_string())
        );
        assert_eq!(
            classify(ControlFailure::Transport(ControlCallError::Unreachable(
                "refused".to_string()
            ))),
            CollateralUnknown::Unreachable("refused".to_string())
        );
    }

    /// **An unclassifiable refusal carries the node's own words** rather than a generic sentence,
    /// and does NOT borrow another arm's remedy.
    #[test]
    fn an_unclassifiable_refusal_keeps_the_nodes_words() {
        let CollateralUnknown::ReadFailed(said) = classify(rejected("SOMETHING_NEW")) else {
            panic!("an unknown symbol is not any of the named remedies");
        };
        assert_eq!(said, "the node said something not worth matching on");
    }

    /// **Every "I do not know yet" reason from the node maps to its own arm.**
    ///
    /// Asserted over the contract's own `ALL` rather than a retyped list, so a reason added upstream
    /// fails here instead of being silently folded into a neighbour. The distinctness assertion is
    /// the load-bearing half: a mapping that returned `NotCensused` for all four would satisfy every
    /// "it is unknown" check elsewhere in this file.
    #[test]
    fn each_node_side_unknown_reason_maps_to_a_distinct_arm() {
        let mapped: Vec<CollateralUnknown> = CollateralUnknownReason::ALL
            .iter()
            .map(|&reason| CollateralUnknown::of_wire(reason))
            .collect();
        assert_eq!(mapped.len(), 4);
        for (i, left) in mapped.iter().enumerate() {
            for right in mapped.iter().skip(i + 1) {
                assert_ne!(left, right, "two node reasons collapsed into one arm");
            }
        }
        assert_eq!(
            CollateralUnknown::of_wire(CollateralUnknownReason::NotCensused),
            CollateralUnknown::NotCensused
        );
        assert_eq!(
            CollateralUnknown::of_wire(CollateralUnknownReason::NoChainSource),
            CollateralUnknown::NoChainSource
        );
    }

    /// **No reading exposes a number it was not given.**
    ///
    /// The accessors are the only way the arithmetic gets a figure, so this is the guard that keeps
    /// an unknown from becoming a zero one layer up. Pending is included deliberately: it is the
    /// state a surface sees first on every launch, and it is the one most likely to be treated as
    /// "nothing yet, so zero".
    #[test]
    fn neither_pending_nor_unknown_yields_a_figure() {
        assert_eq!(RequirementReading::Pending.per_store(), None);
        assert_eq!(MarginReading::Pending.margin(), None);
        for reason in CollateralUnknown::all() {
            assert_eq!(
                RequirementReading::Unknown(reason.clone()).per_store(),
                None,
                "{reason:?} produced a requirement"
            );
            assert_eq!(
                MarginReading::Unknown(reason.clone()).margin(),
                None,
                "{reason:?} produced a margin"
            );
        }
        // The control: a known reading DOES yield its figure, or the assertions above would hold for
        // an accessor that returned `None` unconditionally.
        assert_eq!(
            RequirementReading::Known(EpochRequirement {
                epoch: 7,
                protocol_version: 1,
                required_per_store_dig_base_units: 1_036,
                stores: 40,
                owners: 12,
                multiplier_micros: 1_000_000,
                handicap_dig_base_units: 3_952,
            })
            .per_store(),
            Some(1_036)
        );
        assert_eq!(
            MarginReading::Known(SafetyMargin { margin_bp: 500 }).margin(),
            Some(SafetyMargin { margin_bp: 500 })
        );
    }

    /// **A read that has not happened is Pending, never Unknown.**
    ///
    /// The default is what every surface renders before its first read returns, and the two states
    /// say different things: `Pending` promises an answer is coming, `Unknown` names a reason it is
    /// not. Defaulting to a reason would invent a fault on every launch.
    #[test]
    fn an_unasked_reading_defaults_to_pending() {
        assert_eq!(RequirementReading::default(), RequirementReading::Pending);
        assert_eq!(MarginReading::default(), MarginReading::Pending);
    }
}
