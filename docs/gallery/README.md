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
| `profiles-<fixture>-<width>.png` | the Account tab's profiles card with a list on it — see below |
| `did-<screen>-<theme>.png` | one screen of the first-run DID wizard |
| `<tab>-live-<width>.png` | the two node-backed cards filled from a **running local dig-node** rather than from the fixture — the Home tab's sharing card and the Content tab's hosted-store list |

### What `profiles-` means, and why it is a fixture

Every REAL account holds **zero** profiles, because nothing in this build can mint one — so the empty
state is what a live machine shows, and it is already in every `account-*` capture above. The three
`profiles-` fixtures are the states a list can only reach once minting exists: two profiles, one of
them hidden from this computer's lists, and the state a completed switch leaves behind.

They are **fixtures, and they do not show an end-to-end run.** The registries behind them are built
through `ProfileRegistry::from_json`, which is the same loader production reads a real registry with,
and dig-account re-checks all four of its invariants on the way in — so a fixture that gets past them
is one the shipping loader would also accept, and the DIDs in the pictures are recomputed from their
launcher ids rather than written by hand. What they prove is that the card renders these states
correctly. What they do not prove is that a profile has ever been minted, because none has.

They are shot to the pane's full height rather than the window's, for the same reason the live
captures are: the card sits below two others, and a capture that cannot show the controls it is
evidence for is not evidence.

### What `-live-` means, and what it costs

Every other image in this set is the same picture on every machine, because the view behind it is a
fixture. The `-live-` four are not: they carry what the node on the machine that shot them actually
reported — its store list, its capsule and pin counts, its uptime — so they show real readings and
they will differ between two hosts.

They therefore **need a running dig-node**, and are shot only when asked for:

```powershell
pwsh tools/shoot-gallery.ps1 -Live
```

**Know what you are publishing before you shoot them.** A `-live-` capture commits your machine's real
holding set — the store ids it has cached or pinned, their sizes, and your node's uptime — to a public
repository. None of that is secret: a node announces its holdings to the DHT by design, so anyone can
already learn who holds what. The residual is correlation, since intersecting the DHT providers of all
the ids in one image narrows to the machine that shot it. Nothing else about the host travels: the
account, address, DID and profile fields are the fixture's on every live capture, because `--live`
replaces only the four node readings and the round-trip test pins that. If your node holds something
you would rather not point at yourself, shoot these on a scratch node.

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
