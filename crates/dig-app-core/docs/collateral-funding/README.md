# The collateral funding readout, photographed (dig-app#306)

Real captures of the real renderer —
`cargo run -p dig-app-core --example pane_preview -- settings light 960 900 live healthy 0.36 <state>` —
grabbed with `PrintWindow(PW_RENDERFULLCONTENT)`, so the window is never brought to the foreground and
no input is driven at it.

The zoom is `0.36` because the Settings pane is longer than any window this display can open. Scrolling
to the card would mean driving synthetic input at it, and a committed screenshot must never be taken
that way (dig_ecosystem#2309) — so the content is scaled down instead and the whole pane is in frame.
Captured on a 200% display, so each file is 2432 px wide for a 960 logical-pixel window.

| File | State | What it shows |
|---|---|---|
| `funding-short-now.png` | `short_now` | The node cannot cover the current epoch. Every term is drawn: the verdict, the amount to add, the recommendation it is measured against, the spendable balance, the pairs served, the per-store requirement, the margin in force, and the horizon. |
| `funding-node-cannot-say.png` | `Unknown(NodeCannotSay)` | The node answered and named one of its own facts as missing. One line, a reason, **and no figure anywhere**. |

## What these two are evidence of

**That the readout exists at all.** `collateral::node::read_buffer` was correct and had **no consumer**:
`gitnexus impact` returned zero upstream callers, and nothing in the binary drove
`activity::funding::Reminder`. A reader nothing calls is indistinguishable, from outside, from a missing
feature — so the first thing these pictures prove is that a person can now see the answer.

**That an unknown shows no number.** The second capture is the load-bearing one. A version that fell
back to a computed buffer, or that defaulted an absent one to zero, would print a figure there — and on
this surface a zero reads as *no more $DIG needed*, on a node that may be uncollateralised. The card
says why instead, in the faint colour the pane reserves for the absence of a value.

**That the total rests on the node's served-pair count.** Visible in the first capture, in the
*Collateral safety margin* card below: `116.15 $DIG` locked in total is `5_050 x 23` base units, against
the **23** pairs the node reported two cards above. dig-app's own hosted-store list holds one entry in
this fixture. The list is keyed on `store_id`, so a store serving several owners is one entry and several
postings, and totalling entries would have printed `5.05` — the smaller figure, which is the direction
that costs an operator an epoch.

## Not photographed here

`dangerously_low`, `below_recommended_buffer`, `funded`, and the pending and read-failed states, each of
which the preview can open by name (`funding-dangerously-low`, `funding-below-buffer`, `funding-pending`,
`funding-node-cannot-say`, and `margin-unread` for a wholly unread node). They are pinned by tests rather
than by images: `settings::tests::the_funding_card_is_drawn_into_the_pane` paints the real pane and reads
its glyphs back, and `every_funding_state_is_drawn_and_no_unread_one_carries_a_figure` asserts every state
including the three that must carry no number.

The **notification** half of #306 is not photographed because it does not exist yet: `activity::runway`
produces a title, body and route that nothing dispatches, and the activity gate it needs is dig-app#312.
