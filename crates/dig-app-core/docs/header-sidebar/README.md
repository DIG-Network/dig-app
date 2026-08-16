# The header and the sidebar readings (dig_ecosystem#3007)

Real captures of the shipping shell, taken with `examples/window_gallery.rs`:

```text
cargo run -p dig-app-core --features gui --example window_gallery -- \
    home light 960 640 unlocked docs/header-sidebar/chrome-unlocked-light-960x640.png
```

Every file here is 2x the logical size in its name, because `window_gallery` pins the scale rather
than taking it from the display.

## Why not `pane_preview`

`pane_preview` draws a pane and deliberately leaves the chrome out, and its window is built from
`ViewportBuilder::default()` — decorations ON, no icon. A capture taken through it therefore carries
an OS titlebar with native glyphs and eframe's placeholder letter-"e" icon, in the exact place this
ticket's header belongs. The first generation of these captures was taken that way, and the three
headline changes here — the DIG Mark, the Unlock control and the reworked glyph row — were
consequently evidenced by a picture of a window that never drew any of them. Those files are
replaced rather than kept beside these: every claim they carried is carried here by a capture of the
real chrome, and a titlebar-bearing pane shot sitting next to one would invite the same misreading a
second time.

`window_gallery` draws the shipping shell through its own paint path with decorations off, and reads
the framebuffer back with `ViewportCommand::Screenshot`. Nothing is clicked and nothing is
screen-grabbed.

## What each file shows

| File | Shows |
|---|---|
| `chrome-unlocked-{light,dark}-960x640.png` | The header: the DIG Mark, the wordmark, and the Minimize / Maximize / Close glyphs on one 10 px pixel-snapped square. All **eight** status readings in the bottom-justified column at the sidebar's foot. **No Unlock control** — the account is unlocked. |
| `chrome-locked-{light,dark}-960x640.png` | The same window with a **sealed** account: the **Unlock** control is present in the header, left of the glyph row, worded from the model's own enabled row. Paired with the file above, this is what shows the control disappears rather than merely existing. |
| `chrome-column-short-{light,dark}-960x480.png` | The window dragged to `SHELL_MIN` **height**. The two raw heights (`Chain height`, `Chia peer height`) are surrendered and the **six** diagnostic readings remain — the stated vertical budget, from the short side. |
| `chrome-unlocked-{light,dark}-480x480.png` | `SHELL_MIN` on both axes. There is no sidebar at this width, so the tabs move to a top strip and the readings take the band along the bottom of the window. |
| `chrome-locked-{light,dark}-480x480.png` | The narrow window with a sealed account: the Unlock control still fits beside the glyphs at the narrowest width a person can drag to. |

## What these captures do NOT evidence

Stated rather than left to be inferred, because a gallery that is silent about its gaps reads as
though it had none.

- **The `--danger` Close hover.** A hover needs a pointer, and this harness drives no synthetic
  input of any kind — deliberately, since a capture set up by driving input photographs whatever the
  pointer landed on. The danger tone is covered by the suite instead; it is not photographed here.
- **The Restore glyph.** It is drawn only while the window is maximised, and every capture here is
  taken at a size given as an argument. `Maximize` is what an un-maximised window offers, and it is
  what these show. Restore is reached by name in the suite.
- **The overscroll fix (dig_ecosystem#3009).** It is a property of dragging, so no still frame can
  carry it; the revert-proof on `a_pane_cannot_be_scrolled_past_its_last_row` is its evidence.
