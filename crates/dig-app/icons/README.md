# dig-app tray icon assets

The DIG brand mark, embedded in the `dig-app` binary and painted as its tray / menu-bar icon. Decoded
by [`src/brand.rs`](../src/brand.rs); mounted by `brand_icon` in
[`src/bin/dig-app.rs`](../src/bin/dig-app.rs).

## The mark

A magenta disc (`#C300B8`) carrying a white `D` (`#FFEDFF`) whose bowl shows the magenta ground through
it. RGBA8 with real alpha: the corners are fully transparent, so the tray paints a **disc, not a tile**.

That silhouette is what makes one asset work on both a light and a dark tray — the outermost visible
colour is magenta, never a light rectangle:

| pair | contrast |
| --- | --- |
| magenta ground vs a light tray (`#FFFFFF`) | 5.23:1 |
| magenta ground vs a dark tray (`#000000`) | 4.01:1 |
| white `D` vs the magenta ground | 4.69:1 |

No separate macOS template variant is needed.

## Provenance

`mark-32.png`/`mark-64.png` are copied **byte-identical** from the ecosystem's canonical Tauri icon
set in `dig-installer` (`gui/app/src-tauri/icons/`), per the reuse rule — the mark is not redrawn
here:

| file | source | sha256 |
| --- | --- | --- |
| `mark-32.png` | `dig-installer .../icons/32x32.png` | `713b15773e7ef3bd134962a2651fd354447007fa761db4484ace66095de0426f` |
| `mark-64.png` | `dig-installer .../icons/64x64.png` | `534b747565a796d964f261c0f8f235e90ff02a2126c67286203be60cd67d494b` |

The copy is deliberate: the artwork must live in this crate so the binary is self-contained, rather than
reaching across into another submodule at build or run time.

## The Windows icon resource lives at the repo root, not here (dig_ecosystem#2917)

This directory used to also carry `mark.ico`, the bytes handed to the **linker** by
[`build.rs`](../build.rs) through the encoder in [`build/res.rs`](../build/res.rs) so the executable
itself carries an icon. That `.ico` is now `assets/dig.ico` at the repo root — the ONE canonical,
byte-pinned icon every DIG binary across the ecosystem embeds (`scripts/check-icon.sh` makes drift
loud) — not a crate-local copy. `mark.ico` predated that cross-repo decision and carried six frames
(16/24/32/48/64/256) against the canonical ten (16/20/24/32/40/48/64/96/128/256), missing the
<=32px alpha hardening that stops the `D`'s counter bleeding shut at taskbar size.

It has to be embedded, because Windows attributes an unpackaged Win32 toast to the app's Start Menu
shortcut, and that shortcut draws whatever icon the executable it points at carries. Without this
resource, the notification, the taskbar, Explorer and Alt-Tab all fall back to the generic file icon
(#3076).

## Why these two PNG sizes

Each is the *nearest source* to a real tray paint size, because downscaling the 128px master collapses
the glyph's fine anti-aliasing into mush at tray dimensions.

| platform | paints at | asset |
| --- | --- | --- |
| Windows notification area | 16 logical px (32 device px at 200% DPI) | `mark-32.png` |
| macOS menu bar | 22pt (44 device px on Retina) | `mark-64.png` |
| Linux panel indicator | 22–32px | `mark-64.png` |

Only the platform's own mark reaches the shipped binary — the linker drops the unused const — so
carrying both costs no binary size on any single target.

## Known softness at 16px

The mark is soft-glow artwork, so at a true 16px the `D` is legible but not crisp; it is sharp at 32px
and above. Recovering crispness at 16px needs a purpose-drawn small-size variant with a harder edge (a
design task), not a different resampling filter — the glow already fills the canvas, so there is no
padding to trim back.
