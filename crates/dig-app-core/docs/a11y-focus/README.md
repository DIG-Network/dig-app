# The keyboard focus ring on the shell chrome and sidebar

Real captures of the OS-drawn window, taken with

```text
cargo run -p dig-app-core --features gui --example shell_gallery -- light 999999 focus=close
pwsh tools/capture-window.ps1 -ProcessName shell_gallery -Out <file>.png
```

`PrintWindow(PW_RENDERFULLCONTENT)` after the capturing process declares
`SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`, and **no synthetic
input**: `shell_gallery`'s new `focus=<close|maximize|minimize|tab:<name>>` argument opens the real
app shell — chrome and sidebar included — with real keyboard focus already on the named control, via
`AppWindow::initial_focus`. Nothing is clicked or Tab-pressed to reach the control under review.
Every image below was looked at.

**Display scaling was 2.5×**, so each physical size is 2.5× its logical size plus the window frame
(32 px wide, 88 px tall).

| File | Logical | Physical | What it shows |
| --- | --- | --- | --- |
| `focus-close-light-960x640.png` | 960 × 640 | 2400 × 1600 | The titlebar's Close control, focused via `focus=close`, painted in the accent-purple ring `paint::focus_ring` draws for every focusable control (dig_ecosystem#2329). Light theme. |
| `focus-close-dark-960x640.png` | 960 × 640 | 2400 × 1600 | The same control and seam, in dark. Token parity; nothing hardcoded. |
| `focus-sidebar-tab-light-960x640.png` | 960 × 640 | 2400 × 1600 | A sidebar tab entry (Wallet), focused via `focus=tab:wallet` — the other half of dig_ecosystem#2329: the ring reaches the sidebar's own navigation rows, not only the titlebar. |

## The seam this required

`shell_gallery.rs` only draws the tab and theme it is given (dig_ecosystem#2326) — it never had a way
to reach a titlebar or sidebar control without a synthetic click or a real `Tab` keypress, both
forbidden for a committed capture. `examples/pane_preview.rs`, the sibling gallery, cannot reach these
controls at all: its own doc comment states it deliberately leaves out the shell's chrome.

The fix follows the precedent already in this crate — `AppWindow::initial_tab`, which exists so a
gallery can open on a tab that is not the first one. `AppWindow::initial_focus: Option<InitialFocus>`
is its sibling: `None` is the shipping behaviour (nothing focused, byte-for-byte what production
callers already get), and `Some(target)` puts real keyboard focus on that control before any input.

Applying it turned out to need one more step than `initial_tab` does. `request_focus` issued from the
`eframe::run_native` creator closure — before this viewport had ever run a frame — was measured to be
silently lost, and even a single re-issue on the shell's first real frame was measured to be lost too.
`ShellApp` instead holds the request as `pending_focus` and re-asserts it on every frame
(`ShellApp::frame`) until either it is confirmed or a real key or pointer event gives the person a
reason of their own to be elsewhere — see `confirm::gui::window::shell::tests::pending_focus_puts_real_focus_on_the_named_control_before_any_input`,
which pins this exact behaviour headlessly (and its sibling `no_pending_focus_means_no_control_is_focused_on_open`,
the `initial_tab`-shaped negative case).

`InitialFocus::id()` resolves each variant to the exact `egui::Id` the shell's own painters assign
(`paint::window_control_id`, `window_model::tab_element_id`) — never a hand-typed string that happens
to match today.
