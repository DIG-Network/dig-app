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
    CollateralBufferParams, CollateralMarginGetParams, CollateralMarginSetParams,
    CollateralRequirementParams,
};
use dig_node_control_interface::results::{
    CollateralBufferResult, CollateralRequirementResult, CollateralUnknownReason,
};
pub use dig_node_control_interface::results::{
    CollateralBufferUnknownReason, CollateralFundingState,
};

use crate::amount::amount_with_unit;
use crate::collateral::SafetyMargin;
use crate::control::{self, ControlCallError, ControlFailure};
use crate::wallet::state::Asset;

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
/// The first five arms mirror [`CollateralUnknownReason`] from the contract, which the node uses to
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
    /// The node reads the chain fine, but cannot read its OWN $DIG balance, so it cannot tell
    /// whether it could fund what the epoch prices.
    ///
    /// **The one WALLET-shaped reason, and the only one whose remedy is not the census, the record
    /// or the chain.** It is emphatically NOT a shortfall: the node has no evidence of a gap, and
    /// rendering it as one would ask a person for money that would change nothing. Folding it into
    /// [`RecordUnreadable`](Self::RecordUnreadable) is the opposite misdirection - it sends that
    /// person to repair a census that is working. The contract forbids both collapses by name.
    BalanceUnreadable,
    /// No node is connected, so there is nothing to ask.
    NoNode,
    /// A node answered and does not serve this method. **The ordinary case today** — the verbs are
    /// declared in the 0.23.0 contract and the node side ships separately. The remedy is an upgrade.
    NodeCannotRead,
    /// A node DISPATCHED this method and refused this app. The remedy is the control token, NOT an
    /// upgrade: the refusal came from the method itself, so the node demonstrably serves it.
    ///
    /// Produced only from a JSON-RPC error carrying the `UNAUTHORIZED` `data.code`, which a node can
    /// only emit after routing the call — see [`RefusedBeforeDispatch`](Self::RefusedBeforeDispatch)
    /// for the refusal that carries no such proof.
    Unauthorized,
    /// A node refused at the HTTP layer, before any method was reached. **Two remedies are live and
    /// this app cannot tell which applies.**
    ///
    /// dig-node rejects an unauthorized request with 401/403 before dispatch, so the response is
    /// identical whether the token is wrong or the build simply does not serve the verb — and until
    /// the node side ships, not serving it is the ordinary case. Classifying this as
    /// [`Unauthorized`](Self::Unauthorized) named the token confidently and sent a person to check a
    /// credential that was never the problem.
    ///
    /// It is a separate variant rather than a softer sentence on the existing one because the two
    /// are genuinely different evidence: a dispatched refusal PROVES the method exists, and this one
    /// proves nothing. Shared with `control.collateral.margin.get` and
    /// `control.collateral.requirement`, which fail the same way for the same reason.
    RefusedBeforeDispatch,
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
    /// asserted complete by `every_reason_is_in_all` — without which a twelfth reason would ship
    /// with no sentence of its own while every surface test stayed green.
    #[cfg(test)]
    pub(crate) fn all() -> Vec<Self> {
        vec![
            Self::NotCensused,
            Self::BehindFinalityDepth,
            Self::RecordUnreadable,
            Self::NoChainSource,
            Self::BalanceUnreadable,
            Self::NoNode,
            Self::NodeCannotRead,
            Self::Unauthorized,
            Self::RefusedBeforeDispatch,
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
            CollateralUnknownReason::BalanceUnreadable => Self::BalanceUnreadable,
        }
    }

    /// The operator-facing sentence for this reason: what is missing, and where to look.
    ///
    /// One sentence per variant, exhaustively, because the type's whole premise is **one variant
    /// per REMEDY**. A map that answered "DIG could not read your node" for everything would make
    /// twelve distinct diagnoses indistinguishable at exactly the moment a person needs to act on
    /// one of them. The exhaustive match is also the tripwire: a twelfth reason added upstream
    /// fails to compile here rather than inheriting a neighbour's words.
    ///
    /// No sentence names a figure. These are the states in which this app has no number it was
    /// given, and inventing one on a surface about money is the defect this whole module avoids.
    #[must_use]
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::NotCensused => {
                "Your node has not censused this epoch yet, so it has nothing to answer from. \
                 This usually clears on its own."
            }
            Self::BehindFinalityDepth => {
                "The chain has not settled far enough for your node to commit to a figure yet. \
                 Wait for a few more blocks."
            }
            Self::RecordUnreadable => {
                "Your node holds this epoch's census record but could not read it back. \
                 Its census storage is the place to look."
            }
            Self::NoChainSource => {
                "Your node has no chain connection, so it cannot census at all. \
                 Point it at a chain source in the node's own configuration."
            }
            // Deliberately borrows nothing from the four above and nothing from a shortfall: the
            // node is healthy, the money may well be there, and the one thing that failed is a
            // wallet read.
            Self::BalanceUnreadable => {
                "Your node is healthy but cannot read its own $DIG balance, so it cannot tell \
                 whether it could cover this epoch. Nothing is known to be missing. \
                 Look at the node's wallet."
            }
            Self::NoNode => {
                "DIG is not connected to a node, so there is nothing to ask. \
                 Start your node, or point DIG at one in Settings."
            }
            Self::NodeCannotRead => {
                "Your node does not serve this reading. Updating it is the remedy."
            }
            Self::Unauthorized => {
                "Your node served this reading and refused DIG's request. \
                 Its control token is the thing to check."
            }
            Self::RefusedBeforeDispatch => {
                "Your node refused DIG's request before reaching the reading, which happens both \
                 when the control token is wrong and when the node is too old to serve it."
            }
            Self::TimedOut(_) => {
                "Your node did not answer in time. It may be busy, or the address DIG is using \
                 may not be the one it is listening on."
            }
            Self::Unreachable(_) => {
                "DIG could not reach your node at all. Check that it is running."
            }
            Self::ReadFailed(_) => {
                "Your node refused this reading without saying why, so DIG cannot name a remedy."
            }
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
        // error exists to carry a `data.code`. That is a real remedy and must not fall through to
        // "the read failed", which names none — but it is NOT evidence about the token specifically:
        // a build that does not serve the verb refuses identically, and that is the ordinary case
        // today. So it lands on the variant that names both, never on `Unauthorized`, which claims a
        // method was reached.
        ControlFailure::Transport(ControlCallError::HttpRefused {
            code: 401 | 403, ..
        }) => CollateralUnknown::RefusedBeforeDispatch,
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
    // must never fail in.
    //
    // The node does NOT clamp on its side -- it REFUSES an over-ceiling margin with
    // `-32602 INVALID_PARAMS` (`dig_node_control_interface::params::CollateralMarginSetParams::
    // validated`). Clamping here is therefore what keeps a legitimate request from being refused
    // over a bound the two surfaces share; it is not a second belt over a node-side clamp that does
    // not exist. The two ceilings are the same number, pinned by
    // `collateral::tests::the_app_ceiling_equals_the_control_plane_ceiling`, so this clamp can only
    // ever produce a value the node accepts. Whatever the node answers is what is displayed.
    let params = CollateralMarginSetParams {
        margin_bp: SafetyMargin::of_basis_points(margin_bp).margin_bp,
    };
    match control::call_control_result(endpoint, &params, token, timeout) {
        Ok(result) => MarginReading::Known(SafetyMargin::of_basis_points(result.margin_bp)),
        Err(failure) => MarginReading::Unknown(classify(failure)),
    }
}

/// The node's own recommended $DIG buffer and its funding position against it, exactly as one node
/// reported it.
///
/// **Every field is the node's.** Nothing here is derived, defaulted, or reconstructed by dig-app —
/// the buffer rests on the `(owner, store, root)` pairs THIS node serves, on its unreclaimed
/// transition overlap, and on a horizon it chose, none of which any client can see. A client that
/// assembled the figure from the census requirement and its own store count would produce a
/// strictly smaller number, and understating a funding warning is the failure direction that costs
/// an operator an epoch: they top up, believe they are covered, and are not.
///
/// The terms travel with the total so a surface can show its working, but
/// `recommended_buffer_dig_base_units` is the authoritative figure and the one `funding_state` was
/// decided against. **Never re-add the terms and prefer the sum** — the rounding lives in the
/// node's arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeBuffer {
    /// The epoch the underlying requirement governs, one-based.
    pub epoch: u64,
    /// The collateral protocol version that computed the epoch — a client holding only numbers
    /// cannot tell a disagreement from a rule change.
    pub protocol_version: u16,
    /// Where the node says it stands. **The node's verdict, never a threshold applied here.**
    pub funding_state: CollateralFundingState,
    /// The $DIG the node recommends holding, in base units. The authoritative figure.
    pub recommended_buffer_dig_base_units: u64,
    /// The spendable $DIG the node compared against that buffer, in base units. Carried so the
    /// verdict is checkable rather than merely assertive.
    pub spendable_dig_base_units: u64,
    /// Qualifying `(owner, store, root)` pairs THIS node serves — its own set, never the census
    /// advertisement count and never a length of dig-app's hosted-store list.
    pub pairs_served_by_this_node: u64,
    /// The epoch's per-store requirement in base units, before any margin.
    pub required_per_store_dig_base_units: u64,
    /// The local safety margin the node has in force.
    pub margin: SafetyMargin,
    /// Collateral still locked against positions the node has not yet reclaimed, in base units.
    /// **Not derivable client-side**, which is the first reason this read exists.
    pub overlap_dig_base_units: u64,
    /// The headroom included for the requirement escalating over [`horizon_epochs`](Self::horizon_epochs).
    pub escalation_headroom_dig_base_units: u64,
    /// How many future epochs that headroom covers. Never implied and never defaulted here: the
    /// same buffer over a different horizon is a different claim.
    pub horizon_epochs: u32,
    /// The compounded WORST-CASE escalation multiplier the node assumed, in millionths. A ceiling,
    /// not a forecast.
    pub escalation_ceiling_micros: u64,
}

impl NodeBuffer {
    /// The $DIG to add to reach the buffer the node recommends, in base units.
    ///
    /// The one subtraction in this module, and it is between two figures the NODE supplied against
    /// the NODE's own authoritative total. It is not an assembly of the buffer: no term is
    /// multiplied, no count is substituted, and no threshold is applied.
    ///
    /// Zero whenever the balance already meets the recommendation, so a surface can name a figure
    /// without first asking which state it is in.
    #[must_use]
    pub const fn add_dig_base_units(&self) -> u64 {
        self.recommended_buffer_dig_base_units
            .saturating_sub(self.spendable_dig_base_units)
    }

    /// The amount to add, as a person reads it — `"24.000 $DIG"`.
    #[must_use]
    pub fn add_with_unit(&self) -> String {
        amount_with_unit(Asset::DIG, self.add_dig_base_units())
    }
}

/// Why no buffer figure is available. **One variant per REMEDY**, and never a number.
///
/// Split in two because the two halves have genuinely different remedies. The node saying *"I
/// cannot enumerate my served set"* is a fact about the node's own bookkeeping; the read timing out
/// is a fact about the call. Collapsing them would answer a reclaim-state gap with "check your
/// connection".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferUnknown {
    /// A node answered and named which of its OWN facts is missing. Its taxonomy is taken from the
    /// contract rather than restated, so a fifth reason upstream is a compile error here.
    NodeCannotSay(CollateralBufferUnknownReason),
    /// The read itself produced no answer.
    ///
    /// Carries [`CollateralUnknown`] because a control call fails identically whichever collateral
    /// verb it names, and the sentences naming those remedies are written once. Only the arms
    /// `classify` produces occur here; the four census reasons belong to
    /// `control.collateral.requirement` and reach this type through
    /// [`NodeCannotSay`](Self::NodeCannotSay) instead, as `RequirementUnknown`.
    ReadFailed(CollateralUnknown),
}

/// What the app knows about the node's recommended buffer.
///
/// Three states for the reason [`RequirementReading`] has three: a read in flight has made no
/// claim, and a read that failed has made a different claim again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BufferReading {
    /// A read is under way and nothing has failed. **The default.**
    #[default]
    Pending,
    /// The node stated its buffer and its funding position.
    Known(NodeBuffer),
    /// No buffer is available, and which fact is missing.
    Unknown(BufferUnknown),
}

/// Read the node's recommended $DIG buffer and funding state from the node at `endpoint`, once.
///
/// **This is the whole of dig-app's answer to "how much $DIG should I hold".** There is no local
/// fallback and there must never be one: a fallback means a different number still reaches a person,
/// just less often and less predictably, and the honest output when a node cannot answer is
/// [`BufferReading::Unknown`], which shows no figure at all.
pub fn read_buffer(endpoint: &str, token: Option<&str>, timeout: Duration) -> BufferReading {
    match control::call_control_result(endpoint, &CollateralBufferParams {}, token, timeout) {
        Ok(CollateralBufferResult::Known {
            epoch,
            protocol_version,
            funding_state,
            recommended_buffer_dig_base_units,
            spendable_dig_base_units,
            pairs_served_by_this_node,
            required_per_store_dig_base_units,
            margin_bp,
            overlap_dig_base_units,
            escalation_headroom_dig_base_units,
            horizon_epochs,
            escalation_ceiling_micros,
        }) => BufferReading::Known(NodeBuffer {
            epoch,
            protocol_version,
            funding_state,
            recommended_buffer_dig_base_units,
            spendable_dig_base_units,
            pairs_served_by_this_node,
            required_per_store_dig_base_units,
            margin: SafetyMargin::of_basis_points(margin_bp),
            overlap_dig_base_units,
            escalation_headroom_dig_base_units,
            horizon_epochs,
            escalation_ceiling_micros,
        }),
        Ok(CollateralBufferResult::Unknown { reason }) => {
            BufferReading::Unknown(BufferUnknown::NodeCannotSay(reason))
        }
        Err(failure) => BufferReading::Unknown(BufferUnknown::ReadFailed(classify(failure))),
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

    /// **A refusal never falls through to "the read failed", and never claims more than it saw.**
    ///
    /// Two layers, two different pieces of evidence, and the whole point is that they are not the
    /// same claim:
    ///
    /// * a JSON-RPC `UNAUTHORIZED` was emitted BY the method, so the node demonstrably serves it and
    ///   the token is the remedy;
    /// * an HTTP 401/403 arrived before dispatch, so it is equally consistent with a build that does
    ///   not serve the verb at all — which is the ordinary case until the node side ships. Naming
    ///   the token here sends a person to check a credential that may never have been the problem.
    ///
    /// The `assert_ne!` is the load-bearing line. Both arms name a remedy, so an implementation that
    /// collapsed them back into one variant would still satisfy every "not `ReadFailed`" assertion
    /// below — only their DISTINCTNESS pins that the confident claim is no longer made from the
    /// weaker evidence.
    #[test]
    fn a_refusal_names_a_remedy_without_claiming_a_method_was_reached() {
        let before_dispatch = [401, 403].map(|code| {
            classify(ControlFailure::Transport(ControlCallError::HttpRefused {
                code,
                detail: "refused".to_string(),
            }))
        });
        for held in &before_dispatch {
            assert_eq!(held, &CollateralUnknown::RefusedBeforeDispatch);
        }

        let dispatched = classify(rejected(ControlErrorCode::Unauthorized.name()));
        assert_eq!(dispatched, CollateralUnknown::Unauthorized);

        assert_ne!(
            before_dispatch[0], dispatched,
            "a refusal that reached no method must not borrow the claim of one that did"
        );

        // And neither is a generic failure: both still name something to do.
        for held in [&before_dispatch[0], &before_dispatch[1], &dispatched] {
            assert!(
                !matches!(held, CollateralUnknown::ReadFailed(_)),
                "{held:?} must name a remedy, not fall through to the unclassified arm"
            );
        }
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
    /// the load-bearing half: a mapping that returned `NotCensused` for every reason would satisfy
    /// every "it is unknown" check elsewhere in this file.
    #[test]
    fn each_node_side_unknown_reason_maps_to_a_distinct_arm() {
        let mapped: Vec<CollateralUnknown> = CollateralUnknownReason::ALL
            .iter()
            .map(|&reason| CollateralUnknown::of_wire(reason))
            .collect();
        assert_eq!(
            mapped.len(),
            CollateralUnknownReason::ALL.len(),
            "every contract reason must be mapped"
        );
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

    /// **The unreadable-balance reason is its own arm, and its sentence blames neither the
    /// operator's funds nor their census.**
    ///
    /// The contract added this reason precisely because the four it already had all point a person
    /// at the census, the record, or the chain, while this one is about the node's WALLET. So the
    /// assertion is not merely "it maps somewhere distinct" — a distinct arm carrying
    /// `RecordUnreadable`'s words would satisfy that and still send an operator to repair a census
    /// that is working. The sentence itself is pinned in both directions: it must name the balance,
    /// and it must not borrow the vocabulary of a shortfall or of a census fault.
    ///
    /// The control is the sweep at the end: every OTHER variant keeps a sentence of its own, so a
    /// remedy map that returned one string for everything cannot pass.
    #[test]
    fn the_unreadable_balance_reason_names_the_wallet_and_neither_a_shortfall_nor_the_census() {
        let mapped = CollateralUnknown::of_wire(CollateralUnknownReason::BalanceUnreadable);
        assert_eq!(mapped, CollateralUnknown::BalanceUnreadable);

        let sentence = mapped.remedy().to_lowercase();
        assert!(
            sentence.contains("balance"),
            "the sentence must name the fact that is missing: {sentence}"
        );
        assert!(
            sentence.contains("wallet"),
            "the sentence must point at the wallet: {sentence}"
        );

        // Shortfall vocabulary. Every one of these would have a person send money that would
        // change nothing, which is the defect the variant exists to prevent.
        for shortfall in [
            "short",
            "add ",
            "top up",
            "not enough",
            "insufficient",
            "fund your",
        ] {
            assert!(
                !sentence.contains(shortfall),
                "the sentence must not read as a shortfall; found {shortfall:?} in {sentence}"
            );
        }

        // Census/record/chain vocabulary. These are the remedies of the OTHER four reasons, and
        // borrowing them is the misdirection the contract calls out by name.
        for census in ["census", "record", "chain"] {
            assert!(
                !sentence.contains(census),
                "the sentence must not point at the census; found {census:?} in {sentence}"
            );
        }

        // The control: the remedy map is not one string wearing twelve hats.
        let sentences: Vec<&'static str> = CollateralUnknown::all()
            .iter()
            .map(CollateralUnknown::remedy)
            .collect();
        for (i, left) in sentences.iter().enumerate() {
            for right in sentences.iter().skip(i + 1) {
                assert_ne!(left, right, "two reasons share one sentence");
            }
        }
    }

    /// **A well-formed node answer carrying the new reason decodes end to end, tag and all.**
    ///
    /// The distinctness tests above start from the already-decoded `CollateralUnknownReason`, so
    /// they would pass even if the wire token never reached the enum. This one starts from the
    /// bytes a node actually sends.
    ///
    /// It matters because serde rejects the ENCLOSING value on an unknown variant: before this
    /// adoption, `{"state":"unknown","reason":"balance_unreadable"}` failed to decode as a
    /// `CollateralRequirementResult` at all, so *"one reason I do not recognise"* became *"the whole
    /// answer is unreadable"* and the surface reported a broken read on a node that was answering
    /// correctly. The control is the second half: a genuinely unknown token must STILL be rejected,
    /// or this test would pass against a decoder that had been loosened rather than taught.
    #[test]
    fn a_wire_answer_naming_the_unreadable_balance_decodes_into_its_own_arm() {
        let decoded: CollateralRequirementResult = serde_json::from_value(serde_json::json!({
            "state": "unknown",
            "reason": "balance_unreadable",
        }))
        .expect("the 0.27.0 contract decodes its own reason");

        let CollateralRequirementResult::Unknown { reason } = decoded else {
            panic!("an unknown answer must not decode as a requirement");
        };
        assert_eq!(reason, CollateralUnknownReason::BalanceUnreadable);
        assert_eq!(
            CollateralUnknown::of_wire(reason),
            CollateralUnknown::BalanceUnreadable,
            "the decoded token must reach the arm that names the wallet"
        );

        // The control: the decoder was taught one token, not made permissive. A reason nobody
        // defines still fails, which is what keeps an invented token from landing on an arm.
        assert!(
            serde_json::from_value::<CollateralRequirementResult>(serde_json::json!({
                "state": "unknown",
                "reason": "wallet_on_fire",
            }))
            .is_err(),
            "an undefined reason must not decode"
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
