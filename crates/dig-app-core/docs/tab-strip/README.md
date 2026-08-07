# The app window's tab strip, at three widths

Real captures of the OS-drawn window (`cargo run -p dig-app-core --example shell_gallery -- light`),
photographed with `PrintWindow(PW_RENDERFULLCONTENT)` on a 200 % display, so the pixel widths below
are physical and the logical width is half of each.

| File | Window | What it shows |
| --- | --- | --- |
| `sidebar-desktop.png` | 2400 px | Wide enough for the sidebar; the strip is not used. |
| `strip-one-row.png` | 1200 px | Narrow mode with all six chips on one row. |
| `strip-wrapped-at-shell-min.png` | 960 px | The window's own minimum. The chips need two rows, and `Cache` sits on the second one — before dig_ecosystem#2309 it was not drawn at all, and there was no way to reach that tab. |

`strip-wrapped-at-shell-min.png` is the picture the fix exists for: the content pane starts below the
last chip row rather than under it, and no tab is missing.
