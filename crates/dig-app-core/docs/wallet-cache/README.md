# The Wallet and Cache panes

Real captures of the OS-drawn window, taken with
`cargo run -p dig-app-core --example wallet_cache_gallery -- <theme> <case>`, photographed with
`PrintWindow(PW_RENDERFULLCONTENT)` after
`SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`. No synthetic input: the
window is sized with `SetWindowPos` and the tab is selected by posting `WM_MOUSEMOVE` /
`WM_LBUTTONDOWN` / `WM_LBUTTONUP` to the window itself, so nothing takes the foreground away from
the surface being photographed.

**Display scaling was 240 dpi (2.5×)**, so every physical size below is 2.5× its logical size.

## Wallet

| File | Logical | Physical | What it shows |
| --- | --- | --- | --- |
| `wallet-light-960x1180.png` | 960 × 1180 | 2400 × 2950 | The whole pane: the receive card leading with the code, the address in mono with its copy control, the two balances, the tab's verb, and the Sending card that holds #2207's place with no control in it. |
| `wallet-dark-960x1180.png` | 960 × 1180 | 2400 × 2950 | The same pane in dark. The QR keeps its white plate deliberately — a camera refuses a themed code — and the plate reads as a plate because the card around it is themed. |
| `wallet-light-480x900.png` | 480 × 900 | 1200 × 2250 | `SHELL_MIN`. The tab strip is in narrow mode, the address wraps to two mono lines, the readouts drop to one column, and the copy control still sits beside its value. |
| `wallet-light-pending.png` | 960 × 900 | 2400 × 2250 | The state that is on screen for the 2.5–6 s a balance read takes: the figures are replaced by the sentence saying a read is under way. No numeral appears. |
| `wallet-light-timedout.png` | 960 × 900 | 2400 × 2250 | A node that connected and did not answer in time — deliberately not "no node is running", which is what a live user was wrongly told (#2325). |
| `wallet-light-locked.png` | 960 × 900 | 2400 × 2250 | A sealed account: no code, no figure, and both cards naming the remedy that actually applies. The tab's one verb is disabled and carries its reason in its label. |

## Cache

| File | Logical | Physical | What it shows |
| --- | --- | --- | --- |
| `cache-light-960x1180.png` | 960 × 1180 | 2400 × 2950 | The whole pane against the live grounding figures — a 10 GiB limit with 407 MiB in it — the size presets drawn as peers, the not-yet-wired capsule list, and the add-a-store form. |
| `cache-dark-960x1180.png` | 960 × 1180 | 2400 × 2950 | The same in dark: meter, amber unwired banner, and the field on `--surface-2`. |
| `cache-light-480x900.png` | 480 × 900 | 1200 × 2250 | `SHELL_MIN`. The presets wrap onto three rows rather than running off the edge; every one stays reachable. |
| `cache-light-no-node.png` | 960 × 900 | 2400 × 2250 | No node connected: the model's own error banner at the top, the meter replaced by the sentence saying nothing has reported a cache, and the one remaining, disabled, size verb. |

## Two states these pictures cannot show

- **The capsule list with rows in it**, and **the cache holding bytes while listing nothing** — the
  state that reads as a fault and is not one. `TrayView` carries no capsule list yet (#2330), so the
  card renders as `PaneState::Unwired` and both list states are covered by tests in `pane/cache.rs`
  rather than by a photograph. They appear here as soon as #2330 lands; nothing in the pane changes
  but the argument passed to `capsules_card`.
- **The inline field error.** It needs typing, and these captures drive no keyboard input. The rule it
  applies is `link::is_64_hex`, pinned from both sides in `pane/cache.rs`.

## One thing worth knowing before you re-shoot

At 960 × 640 the Wallet pane opens part-scrolled — the receive card's code is cut at the top —
because the pane is taller than that viewport. The captures above use a taller window so the top of
the pane is in frame. Whether that initial offset is the shell's own behaviour or an artefact of
posting mouse messages to select the tab is not established here; it is tracked rather than guessed
at.
