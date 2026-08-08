# The DIG app gallery

What this application actually looks like: every tab, in both themes, at both widths; every account
state the Account and Security panes can be in; and every screen of the first-run DID wizard.

Regenerate the whole set with one command:

```powershell
pwsh tools/shoot-gallery.ps1
```

## How to read the file names

| Pattern | What it is |
|---|---|
| `<tab>-<theme>-<width>.png` | a tab at 960 (the shipping width) or 480 (`SHELL_MIN`, the narrowest the window can be dragged to), on an unlocked account |
| `account-<state>.png` | the Account pane in one of the account states that is **not** the happy path |
| `security-<case>.png` | the Security pane where the account state or the second factor changes what it offers |
| `did-<screen>-<theme>.png` | one screen of the first-run DID wizard |

Every image is **2× the logical size in its name**, on every host — the render scale is pinned rather
than taken from the display, so two versions of the same view can be diffed.

## Why these captures can be trusted

Nothing is clicked and no window is dragged. Every axis that used to need input — which tab, which
theme, which size, which account state — is an argument to `window_gallery`, because a capture set up
by driving input photographs whatever the pointer landed on. That is not hypothetical: a committed
screenshot labelled "Cache" turned out to be the Status tab.

Nothing is screen-captured either. GDI (`PrintWindow`, `BitBlt`, most screenshot tools) is blind to a
hardware GL surface: it returns a black rectangle of exactly the right size, so the harness reports
success and the file looks plausible until somebody opens it. These pixels are read back from the
renderer's own framebuffer after the real frame is drawn.

## What is deliberately NOT here

A pane taller than the window scrolls, and these are captures of the window — so a tall pane is shown
cut off at the bottom edge, exactly as a person sees it. For a whole-pane view of one pane, use
`pane_preview`, which draws the pane without the shell's chrome.
