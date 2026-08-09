# The DIG app gallery

What this application actually looks like: every one of the five tabs, in both themes, at both
widths; every account state the Account pane can be in; and every screen of the first-run DID
wizard.

Regenerate the whole set with one command:

```powershell
pwsh tools/shoot-gallery.ps1
```

## How to read the file names

| Pattern | What it is |
|---|---|
| `<tab>-<theme>-<width>.png` | a tab at 960 (the shipping width) or 480 (`SHELL_MIN`, the narrowest the window can be dragged to), on an unlocked account |
| `account-<state>.png` | the Account pane in one of the account states that is **not** the happy path |
| `account-second-factor-on.png` | the Account pane with a second factor enrolled — the one control that appears and disappears with a setting rather than with the account's state |
| `did-<screen>-<theme>.png` | one screen of the first-run DID wizard |
| `<tab>-live-<width>.png` | the two node-backed cards filled from a **running local dig-node** rather than from the fixture — the Home tab's sharing card and the Content tab's hosted-store list |

### What `-live-` means, and what it costs

Every other image in this set is the same picture on every machine, because the view behind it is a
fixture. The `-live-` four are not: they carry what the node on the machine that shot them actually
reported — its store list, its capsule and pin counts, its uptime — so they show real readings and
they will differ between two hosts.

They therefore **need a running dig-node**, and are shot only when asked for:

```powershell
pwsh tools/shoot-gallery.ps1 -Live
```

`window_gallery --live` refuses and writes nothing when no node answers, rather than falling back to
the fixture. A file labelled live that was quietly synthetic is the same failure as the screenshot
labelled "Cache" that was the Status tab, and the harness will not produce one. Only the node's two
readings are live: every other field is the fixture's, so a live capture and its ordinary counterpart
differ in what the node reported and nothing else.

They are also taller than the rest, because both cards are the last thing on their tab and at 900 the
sharing card falls below the fold — a capture that cannot show the card it is evidence for is not
evidence.

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
