# Content panes — the design system

The vocabulary a tab's content is written in, and the rules for using it. Code:
`crates/dig-app-core/src/confirm/gui/window/pane/`. Reference implementation: the **Status** tab,
`pane/status.rs`. Pictures: `crates/dig-app-core/docs/content-panes/`.

Read this before building a tab. It says what each component is *for* and, more usefully, when not
to reach for it.

---

## The one rule that is not about looks

**The rules stay single-sourced; the presentation vocabulary gets richer.**

Which verbs exist, and whether each is enabled, is decided once — by the group builders in
`tray_menu.rs`, composed into tabs by `window_model.rs`. A pane renders that decision. It may give a
decided verb more weight than the tray can: a prominent primary button with supporting copy where
the tray draws a row. It may not decide *for itself* whether the verb is offered or enabled.

> If you find yourself asking **"should this be shown?"** in rendering code, you have crossed the
> line. The model already answered — go read its answer.

Two things make this structural rather than a request:

- A pane receives `PaneFacts` (`pane/facts.rs`), a read-only projection of the same `TrayView` the
  model is built from. It carries **readings** — is the agent running, what did the node say, how
  full is the cache — and deliberately carries **no enablement** to re-derive.
- A pane receives the tab's `sections` already decided, and turns rows into buttons through one
  shared function, `pane::actions_in`.

The test for whether a fact belongs in `PaneFacts`: *could the tray show it as a row label without
deciding anything?* If yes it is a fact. If showing it requires answering "should this be offered",
it is a rule and it lives upstream.

## The second rule: a skeleton never implies a fact it does not have

Tabs ship as designed skeletons ahead of their node plumbing. A pane showing a plausible zero is
worse than an empty one, because a person cannot tell it apart from a reading.

Two mechanisms enforce this instead of a review checklist:

- **`Value` has no placeholder.** An absent figure is `Value::Unknown(reason)` — the sentence saying
  why, drawn in the unavailable colour. There is no variant a caller could put `0` or `—` in.
- **`PaneState::Unwired` is a state every pane must handle.** A card built ahead of its data says so
  in the pane, in plain words, with a badge for the glance and a banner for the sentence.

The unwired copy denies the reading rather than promising work. "Coming soon" is compatible with a
person believing the numbers above it; *"Nothing on this card is a reading from your computer"* is
not.

---

## The vocabulary

| Module | For | Do NOT use it for |
| --- | --- | --- |
| `flow` | The vertical cursor every block is placed through | Computing a `y` yourself. Blocks measure themselves; nothing reserves a guessed height |
| `text` | Four prose roles: `title`, `heading`, `body`, `caption` | Values — those are `data`. Picking a size or colour at a call site |
| `card` | Grouping related facts under a title | A single self-describing thing. Nesting past `card` → `panel`: three surfaces stop reading as grouping |
| `data` | `Readout`/`Value`, `meter`, `badge`/`Tone` | Prose. A `meter` for an unbounded count — it implies a ceiling that does not exist |
| `action` | Verbs, with primary/ghost/danger weight | Anything the model did not decide. Re-wording a label |
| `state` | The five pane states | A success banner — success shows itself by showing the content |
| `identity` | Values a person takes elsewhere: `copyable`, `scannable` | A value nobody transcribes |
| `copy` | Every string, named | A literal inside a paint call |
| `facts` | The readings a pane may display | Anything that decides a verb |

### Scales

Nothing picks a pixel or a hex. Spacing is `render::space` (hub's `--space-*`, a 4 px rhythm), type
is `render::size` (hub's `--text-*`), radii are `render::radius`, colour is `theme::Tokens`.

**`Tokens` is extended, not superseded.** It is a field-by-field mirror of `hub.dig.net`'s CSS custom
properties, kept that way so the two copies can be diffed by eye; a pane-specific palette would break
that and give the product two looks. What this layer adds on top is **roles** — `data::Tone` asks for
a meaning (`Bad`) rather than a colour (amber), so the meaning-to-token mapping lives in one place.

Two steps were added to the shared scales, both mirroring hub tokens that already existed there:
`space::S1` (4 px) and `size::LG` (18 px, a card's own title).

### Components you do not need to build

`paint.rs` already provides `card`, `panel`, `warning_panel`, `button`/`button_at`, `rule`, `qr`,
`brand_mark`, `inline_toggle`. Reuse them. `paint::button_at` is the absolute-rect form of the same
control the consent prompts use — a second button-drawing function would be a second button style.

---

## Notes that will save you an afternoon

**Do not theme a QR code.** `paint::qr` draws black modules on a white field in both themes, on
purpose: a camera reads contrast, and a dark-theme code in `--surface` on `--text` is one most phones
refuse. Theme the *frame* around it, never the code.

**A readout's layout depends on its value, and that is deliberate.** A short `Word` or `Measure`
sits beside its label on one line; an `Identifier` or an `Unknown` takes its own. Neither works for
both — an `xch1…` address beside a label gets whatever width is left, which at 480 px is not enough,
while "On" stacked under "Second factor" turns two words into two lines and makes a card of four
facts a screenful. The inline test is a real measurement of laid-out text, never a length in
characters: a character count is wrong the first time a translation is longer than its English.

**Panes scroll; they used to clamp.** Content taller than the pane is reached by scrolling. Do not
reintroduce a height clamp — a verb the model offers must be reachable, and silently not drawing the
bottom of a tab is the same defect as dropping a tab from the strip (#2309), one level down.

**Use `ui.scope_builder`, never `ui.new_child`, around a scroll area.** `new_child` does not advance
its parent, so the enclosing `Area`'s interact rect never grows to cover the pane — and `ScrollArea`
gates scrolling on the pointer being over it. The content still draws, so this fails silently: the
pane looks right and cannot be scrolled.

**One derivation of a row's element id.** Use `pane::row_element_id(label, occurrence)` via
`pane::actions_in`. The occurrence is the count of preceding rows with the same label, counted across
the whole **tab** — the Account tab draws `About on-chain DIDs…` twice from two sections, and a
per-section counter gives both occurrence zero, which egui reports as a duplicate id and which leaves
one of the two rows unclickable. Never put a pixel position in an id: the pane rebuilds every frame
and rows above it change height as text rewraps (#2074).

**Keep the first screen useful.** Status is tuned so its escape hatch — the log-folder button — is
above the fold at the default window size. If a card you add pushes the actions off the first screen,
the card is in the wrong order or is saying something twice.

---

## Every surface, at both widths

Every tab must work at `SHELL_MIN` (480 logical px) and at the default 960×640. Photograph both,
with `PrintWindow(PW_RENDERFULLCONTENT)` after `SetProcessDpiAwarenessContext(-4)`, no synthetic
input, and state the logical width and the display scaling — a screenshot without them is
unreproducible. Then run `professional-ui`'s ten-second scan over each one: edges, heading-to-content
gaps, sibling rhythm, alignment, overflow.

Do not pin new pixel thresholds in `window/` tests (#2320). The headless harness measures narrower
than the shipping window, and `drawn_text` reads pre-cull shapes so it cannot tell whether something
is actually visible. Assert geometry containment plus a real interaction, as
`every_verb_a_tab_offers_can_be_pressed_at_the_narrowest_width` does.
