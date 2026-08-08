# The Apps and Settings panes

Real captures of the OS-drawn window, taken with

```text
cargo run -p dig-app-core --features gui --example pane_preview -- settings light 960 1400 live
pwsh tools/capture-window.ps1 -ProcessName pane_preview -Out <file>.png
```

`PrintWindow(PW_RENDERFULLCONTENT)` after the capturing process declares
`SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`, and **no synthetic
input**: the preview takes the tab, the size, the theme and the beacon state as arguments, so
nothing has to be clicked to reach the picture. Every image below was looked at.

**Display scaling was 2.5×**, so each physical size is 2.5× its logical size plus the window frame
(32 px wide, 88 px tall).

| File | Logical | Physical | What it shows |
| --- | --- | --- | --- |
| `apps-light-960x640.png` | 960 × 640 | 2432 × 1688 | The default size: a card per registry app — name, what it is, and the model's own launch verb. No presence indicator, and the closing line saying how apps arrive. |
| `apps-dark-960x640.png` | 960 × 640 | 2432 × 1688 | The same pane in dark. Token parity; nothing hardcoded. |
| `apps-light-480x480.png` | 480 × 480 | 1232 × 1288 | `SHELL_MIN`. The strip is in narrow mode, the tagline wraps, the card keeps its padding. |
| `settings-light-960x640.png` | 960 × 640 | 2432 × 1688 | The default size: the updates group, its badge and figures, the elevation cost stated above the control. |
| `settings-light-960x1400.png` | 960 × 1400 | 2432 × 2488 | Far enough down to show the channel **dropdown** carrying the model's label — including the word `current`, which is a word and not a tick because this font stack has no U+2713 — and the top of the node-connection group. |
| `settings-dark-opted-out-960x1400.png` | 960 × 1400 | 2432 × 2488 | The machine whose daily schedule was REMOVED: `Updates off` although nothing is paused, `Daily check — Removed from this computer`, `Turn auto-update on`, and the downgrade caution stated above the chooser rather than at the prompt. |
| `settings-light-no-beacon-960x1400.png` | 960 × 1400 | 2432 × 2488 | The updater cannot be asked. The on/off control and the chooser are **gone**, not disabled; the explainer remains. Also the whole node-connection group and the top of the shortcut group. |
| `settings-light-480x480.png` | 480 × 480 | 1232 × 1288 | `SHELL_MIN`. The figures stack, the copy wraps, the control keeps its width. |

The Settings pane is taller than any window this display can hold, so no single capture shows all
three groups at once; the two 1400 px captures overlap to cover it.
