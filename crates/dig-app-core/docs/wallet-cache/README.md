# The Wallet and Cache panes

Real captures of the OS-drawn window. Re-shoot every one of them with:

```powershell
pwsh tools/shoot-wallet-cache.ps1
```

which drives `examples/pane_preview.rs` and `tools/capture-window.ps1`.

**Nothing is clicked.** The pane, its size, its theme and the machine state it is reporting on are
all ARGUMENTS to the preview, and the capture is `PrintWindow(PW_RENDERFULLCONTENT)` after
`SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`. That is not a
preference. The previous generation of these captures selected the tab by POSTING
`WM_LBUTTONDOWN` at it; one of those clicks did not land, the capture silently fell back to the
default tab, and a picture of the **Status** pane was committed as `cache-light-960x1180.png` and
described in this table as cards it did not contain. A capture that depends on input landing
eventually photographs whatever was on screen.

## What the numbers below mean

| Figure | What it is |
| --- | --- |
| Logical width | The width passed to the preview, in logical pixels — what the pane laid itself out for. |
| Zoom | egui's zoom factor. `1.0` unless a pane is taller than this display permits a window to be. |
| Physical | The PNG's own pixel dimensions, read back from the file after it was written. |

**Display scaling was 240 dpi (2.5×)** on the machine these were taken on, so a 960-logical-px pane
is 2400 px wide and the window adds a 32 px frame — 2432 px total, which is what the files measure.

**Heights are not claimed, because this display does not grant them.** A window manager silently
CLAMPS an inner size taller than the work area, so every capture asked for 1180 logical px of height
and was given about 995. That clamp is exactly why two earlier captures came out byte-identical
while claiming different sizes, and why file names here carry the width only. Where the pane is
taller than the window allows, the fix is the preview's `zoom` argument — not a bigger number that
will be ignored.

## Wallet

| File | Logical width | Zoom | Physical | What is in the image |
| --- | --- | --- | --- | --- |
| `wallet-light-960.png` | 960 | 1.0 | 2432 × 2488 | The whole pane, nothing cut. Receive leads: the QR, the address in mono beneath it, the scan caption, then the `Receive address` readout with its **Copy** control and the share warning. `What you hold` shows **12.5 $DIG** and **0.25 XCH** side by side. `Wallet actions` holds the one primary verb, `Copy my receive address`. `Sending` closes the pane with a `Not available yet` badge, the paragraph saying why there is no button, and the line that reading DIG content needs no wallet at all. |
| `wallet-dark-960.png` | 960 | 1.0 | 2432 × 2488 | The same pane, same figures, in dark. The QR keeps a white plate — a camera refuses a themed code — and the plate reads as a plate because the card behind it is themed. The primary verb carries its glow against the dark surface. |
| `wallet-light-480.png` | 480 | 1.0 | 1232 × 2338 | `SHELL_MIN`. The tab strip is the horizontal narrow-mode row across the top rather than the side rail. The address wraps to two mono lines both under the QR and in the readout; the readouts drop to ONE column, so `DIG token 12.5 $DIG` and `Chia 0.25 XCH` stack; **Copy** still sits beside the value it copies. The frame ends at the `Sending` card's heading — the pane continues below the window. |
| `wallet-light-pending.png` | 960 | 0.8 | 2432 × 2488 | A balance read in flight, the state on screen for the seconds a chain lookup takes. `What you hold` carries a `Balance` readout reading *"Reading your balance from your node. A balance is a blockchain lookup, so this usually takes a few seconds."* — **no numeral appears anywhere under that label.** Drawn at 0.8 so the whole pane, including the closing line of the `Sending` card, is in frame. |
| `wallet-light-timedout.png` | 960 | 0.8 | 2432 × 2488 | A node that connected and did not answer in time: *"Not known — your node did not answer in time. Nothing is wrong with your account, and the figure appears on its own once a read finishes…"* Deliberately not *"no node is running"*, which is the sentence a live user was wrongly shown (#2325). Again no numeral under `Balance`. |
| `wallet-light-locked.png` | 960 | 1.0 | 2432 × 2488 | A sealed account. `Receive` carries no code and no address, only the sentence saying the address is withheld rather than guessed while the keys are sealed. `Balance` reads *"Not known — your account is locked…"*. The tab's one verb is disabled AND relabelled `Copy my receive address (unlock first)`, so the reason travels with the control. The pane is short enough to fit at 1.0. |

## Cache

| File | Logical width | Zoom | Physical | What is in the image |
| --- | --- | --- | --- | --- |
| `cache-light-960.png` | 960 | 1.0 | 2432 × 2488 | The whole Cache pane — and the Cache pane, which is what this file failed to be before. `Disk used by cached content`: the **350 MiB** readout, the meter, and `350 MiB of 1 GiB used (34%)`. `Size limit`: the six presets with `1 GiB (default) — current` marked, wrapping to a second row with `Custom size…` and `About the cache and your privacy…` drawn as peers beside them, over the sentence warning that a lower limit deletes content. `Capsules mirrored here` is the `Not wired up` badge over the amber unwired banner. `Mirror another store` closes it: the `Store id` field, its 64-hex help line, and the refused `Mirror this store` button. |
| `cache-dark-960.png` | 960 | 1.0 | 2432 × 2488 | The same in dark: the meter's filled track, the amber banner against the dark card, and the input on `--surface-2`. |
| `cache-light-480.png` | 480 | 1.0 | 1232 × 2338 | `SHELL_MIN`. The tab strip is the narrow-mode row. The size presets wrap onto FOUR rows rather than running off the edge, and every one — including `About the cache and your privacy…` on its own row — stays whole and reachable. The frame ends just below the `Store id` label. |
| `cache-light-no-node.png` | 960 | 1.0 | 2432 × 2488 | No node connected. The model's own banner leads the pane: *"No node is connected, so the size limit cannot be read or changed."* The meter is gone, replaced by the sentence saying no node has reported a cache yet. The preset row collapses to two controls: a disabled `Change the size limit (connect a node first)…` carrying its reason in its label, and `About the cache and your privacy…`, which needs no node and stays live. |

## Two states these pictures cannot show

- **The capsule list with rows in it** — no longer true of the application, only of these files.
  `TrayView` carries the list as of #2330, and #2397 wired the card to it, so the `Not wired up`
  badge and the amber banner these pictures show are both gone; `PaneState::Unwired` no longer
  exists. The list with real rows is photographed from a running node in
  [`docs/gallery`](../../../../docs/gallery/README.md) — `content-live-960.png` and its 480
  counterpart. **The cache holding bytes while listing nothing** is still covered by tests in
  `pane/cache.rs` rather than by a photograph: it is the state that reads as a fault and is not one,
  and it needs a node in a condition this machine cannot arrange on demand.
- **The inline field error.** It needs typing, and these captures drive no input of any kind — which
  is the whole point of how they are taken. The rule it applies is `link::is_64_hex`, pinned from
  both sides in `pane/cache.rs`.
