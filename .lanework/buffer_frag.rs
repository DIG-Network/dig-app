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
    /// [`classify`] produces occur here; the four census reasons belong to
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

