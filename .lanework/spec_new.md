### 3.7c Collateral runway and the low-funds notification (dig-app#306)

**The recommended $DIG buffer and the funding state are READ from the node, never derived by dig-app
(MUST).** Both come from `control.collateral.buffer`, which carries the recommended buffer in $DIG base
units, the node's funding verdict, the spendable balance it was decided against, the
`(owner, store, root)` pairs THIS node serves, the pre-margin per-store requirement, the margin in force
in basis points, the unreclaimed transition overlap, the escalation headroom, the horizon that headroom
covers, and the escalation ceiling assumed. dig-app renders that answer and computes no part of it.

**dig-app MUST NOT assemble a buffer from the epoch requirement and its own store list (MUST NOT), and
MUST NOT keep such a computation as a fallback.** Three terms make a client-side figure wrong, and all
three in the same direction:

- the **unreclaimed transition overlap** is a term of the buffer and no client can see reclaim state;
- a client's store list is keyed on `store_id` alone, so it is a strictly **under-counting** proxy for
  the node's `(owner, store, root)` pairs;
- the **escalation headroom** depends on a horizon the node chose, and escalation compounds, so the same
  buffer over a different horizon is a different claim.

Each understates the shortfall. An operator who tops up an understated figure believes they are covered
and is not, so a warning naming too small a number is worse than none. A fallback would mean the wrong
number still reaches a person, only less often and less predictably.

**The funding state is the node's verdict (MUST).** dig-app MUST NOT re-derive it from local thresholds.
Two clients thresholding the same numbers will eventually disagree, and the one that disagrees about a
funding warning is the one an operator acts on.

**Three readings, and only the node's two shortfall states may raise a notification (MUST).**

| reading | meaning | surface |
|---|---|---|
| `Known(buffer)` / `short_now` | cannot cover the current epoch; stores are already uncollateralised | notification |
| `Known(buffer)` / `dangerously_low` | covers now, cannot cover the next epoch at the escalation ceiling | notification |
| `Known(buffer)` / `below_recommended_buffer` | covered every epoch, with no cushion | readout only |
| `Known(buffer)` / `funded` | at or above the recommendation | silent |
| `Pending` | a read is in flight | readout only, no figure |
| `Unknown(reason)` | the node named a missing fact, or the read failed | readout only, no figure |

The announcing set MUST be exactly the states the contract's own `CollateralFundingState::is_shortfall`
names. dig-app MUST NOT restate that pair.

**`below_recommended_buffer` MUST NOT raise a notification (MUST NOT).** A healthy, funded node sits in
this state much of the time. A recurring alert there would be ignorable by construction, and a person
who learns to dismiss it has learned to dismiss the two states above it — which are the ones that cost
them money. It still carries a figure for the readout: the gap to the recommendation.

**A notification MUST name the amount to add (MUST).** The amount is the node's recommended buffer minus
the spendable balance the node reported, saturating at zero — a gap against the node's own authoritative
total, never a re-addition of its terms, whose rounding lives in the node's arithmetic. The body shows
the working the node sent: the pairs served, the recommendation, the horizon it covers, and the margin in
force. A bare "balance low" is an alarm; a figure is an action.

**The horizon MUST travel with the figure (MUST).** Escalation is bounded at +12.5% per epoch and
compounds, so a buffer quoted against an unstated horizon cannot be checked by anyone. dig-app MUST NOT
substitute a documented default for a horizon it failed to read.

**A notification MUST NOT fire on an unknown (MUST NOT).** A pending read, a failed read, and a node
answering `unknown` with its reason are all silent and carry no figure. A zero MUST NEVER be substituted:
on this surface a zero reads as *no buffer needed*, and an operator acting on it posts nothing and loses
the epoch.

**The copy MUST NOT imply content became unavailable (MUST NOT).** Nothing gates a read on collateral —
the node keeps serving every byte it served before. What is lost is discoverability and payment
eligibility: unseen and unpaid, not down.

**A click MUST reach the deposit surface**, via the `dig-app:deposit` route (dig-app#296), on any host
that can deliver an activation. The copy MUST stand alone without it, because a host that cannot route
one would otherwise show a dead end.

**Repetition MUST stop on a measured recovery, not on a clock (MUST).** The buffer is asked on every
tick, so funding the wallet ends the repetition on the next tick rather than after a timer runs down —
the rule `activity::funding::Reminder` already follows for the out-of-funds signal.
