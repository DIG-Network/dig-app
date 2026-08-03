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
| Recovery phrase | [recovery-phrase-light.png](recovery-phrase-light.png) | [recovery-phrase-dark.png](recovery-phrase-dark.png) |

## Regenerating

```
cargo test -p dig-app-core --lib -- --ignored --nocapture prompt_gallery
```

Writes to `DIG_PROMPT_SHOTS` (default `target/prompt-shots`). Copy the result over this directory.

The harness opens each REAL window and reads its framebuffer back with
`egui::ViewportCommand::Screenshot`, at a pinned 2× scale so the files are the same picture on every
machine.

**Do not photograph these with a screenshot tool.** A GDI screen capture cannot see a hardware GL
surface: it returns the desktop behind the window, and for a decorated window it returns the DWM
title bar over a white client area. A perfectly-painted window photographs as blank
(dig_ecosystem#2038).
