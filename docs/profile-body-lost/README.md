# A profile whose content is unrecoverable (dig_ecosystem#3041)

The state a person reaches when the chain anchors a root and nothing holds its preimage — the
#3066 data-loss defect after the fact. Taken with:

```
cargo run -p dig-app-core --features gui --example pane_preview -- account light 820 1150 live body-lost 0.62
pwsh tools/capture-window.ps1 -ProcessName pane_preview -Out account-body-lost-light.png
```

No synthetic input was used to reach either picture; `body-lost` opens the pane directly into the
state (dig_ecosystem#2309).

| Capture | Shows |
| --- | --- |
| `account-body-lost-light.png` | The loss banner naming the real root, and the form immediately below it. |
| `account-body-lost-light-whole-card.png` | The whole card at 0.40 zoom, down to the publish row. |

## What these are evidence OF

Two defects on this card rendered correctly at the model and wrongly on screen, which is why it has
captures rather than only assertions.

1. **No reassurance under the loss banner.** The empty-state banner is drawn from
   `ProfileDraft::is_empty()`, and a `BodyLost` draft is always empty — so the card said *"Your
   profile is empty. Nothing has gone wrong"* directly beneath *"This profile's details are gone."*
   Neither picture contains that sentence.
2. **The publish row exists.** It is greyed here with *"Change something above and this becomes
   available"*, which is correct over a form nobody has typed into yet — the control is present and
   waiting, not withheld. Withholding it was what made the banner's invitation to publish a promise
   nothing could keep.

The physical pixel sizes are 2.5× the logical sizes above; this display scales at 250%.
