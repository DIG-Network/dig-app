# The Settings tab, photographed (dig_ecosystem#2293)

Real captures of the real renderer — `cargo run -p dig-app-core --example shell_gallery -- light`,
grabbed with `PrintWindow(PW_RENDERFULLCONTENT)` so the window is never brought to the foreground and
no input is driven at it. The gallery's fixture reports no beacon (`update: None`), so every frame
here is the **could-not-be-asked** state.

Widths below are LOGICAL pixels, which is what `SHELL_MIN` and `NARROW_AT` are measured in. The
captures were taken on a 200% display, so each file is twice as wide in real pixels.

| File | Width | What it shows |
|---|---|---|
| `settings-light-desktop.png` | 1200 | The sidebar layout, with `Settings` last in the column. |
| `settings-light-755px.png` | 755 | Just under `NARROW_AT` (760): the sidebar has become the chip strip, and all seven chips fit on one row. |
| `settings-light-550px-wrapped.png` | 550 | The strip has wrapped onto a second row, which is where `Settings` now sits. |
| `settings-light-480px-minimum.png` | 480 | `SHELL_MIN`, the narrowest the window can be dragged. Two rows, `Settings` still selected and still clickable, and the content pane starts below the last row rather than under it. |

## What the two narrow frames are evidence of

A tab that exists must be reachable at every width the window allows. `panes::strip` used to draw
chips left to right and stop at the first one that would overflow, so a chip that did not fit was not
drawn at all — no scroll, no overflow menu, no route to it. On a 200% display that was already
dropping `Cache` at the minimum width with six tabs; adding `Settings` as the seventh made it visible
at ordinary widths too.

The strip now wraps onto as many rows as the chips need, and the split hands the content pane the
height the strip actually came to (dig_ecosystem#2309). Both frames above are that fix: the chips
occupy two rows, and nothing is hidden behind them.

This is pinned by tests, not by these images —
`panes::tests::every_tab_is_reachable_at_every_width_the_window_allows` drives the real `draw` and
clicks every chip, and
`panes::tests::the_shipping_tab_set_reaches_settings_at_the_smallest_window` does the same for the
tab set `window_model::build` actually emits.

## Not yet photographed

The **success** state — the on/off row and the two channel rows — needs a fixture reporting a beacon,
which lives in `examples/shell_gallery.rs`. Its content is pinned instead by
`window_model::tests::the_auto_update_controls_track_the_beacon_and_vanish_without_it` and
`exactly_one_channel_row_is_marked_current`.
