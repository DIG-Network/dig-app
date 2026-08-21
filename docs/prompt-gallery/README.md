# The prompt gallery

Every window `dig-app` puts in front of a person, in both themes. Light is the default; dark is the
persisted opt-in.

| view | light | dark |
|---|---|---|
| Approve signing | [sign-light.png](sign-light.png) | [sign-dark.png](sign-dark.png) |
| Connect a dapp | [connect-light.png](connect-light.png) | [connect-dark.png](connect-dark.png) |
| Pair an extension | [pair-light.png](pair-light.png) | [pair-dark.png](pair-dark.png) |
| Reveal a secret | [reveal-light.png](reveal-light.png) | [reveal-dark.png](reveal-dark.png) |
| Notice | [notice-light.png](notice-light.png) | [notice-dark.png](notice-dark.png) |
| Retention claim | [claim-light.png](claim-light.png) | [claim-dark.png](claim-dark.png) |
| Destroy the account | [destroy-light.png](destroy-light.png) | [destroy-dark.png](destroy-dark.png) |
| Two-factor enrolment (QR) | [two-factor-qr-light.png](two-factor-qr-light.png) | [two-factor-qr-dark.png](two-factor-qr-dark.png) |
| Passphrase | [passphrase-light.png](passphrase-light.png) | [passphrase-dark.png](passphrase-dark.png) |
| Recovery phrase (typed on restore) | [recovery-phrase-light.png](recovery-phrase-light.png) | [recovery-phrase-dark.png](recovery-phrase-dark.png) |
| Recovery phrase (shown on enrolment) | [recovery-phrase-shown-light.png](recovery-phrase-shown-light.png) | [recovery-phrase-shown-dark.png](recovery-phrase-shown-dark.png) |

The last row is the tallest window the app draws, and it was the one view this gallery did not
photograph. That omission is why nobody saw that ten of its words and its whole warning were being
clipped away (dig_ecosystem#2038). A gallery that skips the view whose overflow matters is a gallery
of the easy cases — every view the window can draw belongs here.

## Regenerating

```
cargo test -p dig-app-core --lib -- --ignored --nocapture prompt_gallery
```

Writes to `DIG_PROMPT_SHOTS` (default `target/prompt-shots`). Copy the result over this directory.

The harness opens each REAL window and reads its framebuffer back with
`egui::ViewportCommand::Screenshot`, at a pinned scale so the files are the same picture on every
machine.

Each dialog is photographed at BOTH desktop scalings: the bare file name is 200% (retina) and the
`-100` suffix is 100% (dig_ecosystem#1832). They are inspected as a pair because they catch
different defects — a layout built and only ever seen at 2× hides the errors that appear when a
galley, an icon and a border each round to the nearest whole pixel differently.

The `dig://` launcher bar has ONE capture and that is deliberate. It is fixed at 720×176 and never
resizes to its content, so the harness — which can set the UI scale but cannot resize a window the
OS created at a fixed physical size — renders its 1× pass into the 2× framebuffer. The result is a
bar with a large empty region below its field: a picture of a window no host produces, which in a
gallery meant for inspection by eye is worse than no picture at all.

**Do not photograph these with a screenshot tool.** A GDI screen capture cannot see a hardware GL
surface: it returns the desktop behind the window, and for a decorated window it returns the DWM
title bar over a white client area. A perfectly-painted window photographs as blank
(dig_ecosystem#2038).
