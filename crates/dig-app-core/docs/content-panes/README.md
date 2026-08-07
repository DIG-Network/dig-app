# The Status pane, on the content-pane design system

Real captures of the OS-drawn window (`cargo run -p dig-app-core --example shell_gallery -- light`),
photographed with `PrintWindow(PW_RENDERFULLCONTENT)` after
`SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`, no synthetic input.

**Display scaling was 240 dpi (2.5×)**, so every pixel size below is physical and the logical size is
2.5× smaller. The window was resized with `SetWindowPos` — a window-management call, not a click.

| File | Logical | Physical | What it shows |
| --- | --- | --- | --- |
| `status-light-960x640.png` | 960 × 640 | 2400 × 1600 | The default window size. Sidebar, two-column readouts, the cache meter, and the weighted action group. The log-folder button is above the fold. |
| `status-light-480x480.png` | 480 × 480 | 1200 × 1200 | `SHELL_MIN`, the narrowest the window can be dragged. The tab strip is in narrow mode and the readouts drop to one column. |
| `status-dark-960x640.png` | 960 × 640 | 2400 × 1600 | The same pane in the dark theme — token parity, no hardcoded surface. |
| `status-light-1200x790.png` | 1200 × 790 | 3000 × 1975 | Far enough down the pane to show the **unwired** card: the `Not wired up` badge and the amber banner denying that its figures are readings. |

The Status pane is taller than any of these windows; the rest — the sharing card's four explicitly
absent figures, and the receive card's scannable code — is reached by scrolling. This machine's
display could not photograph the whole pane in one frame, so the tail is not captured here.
