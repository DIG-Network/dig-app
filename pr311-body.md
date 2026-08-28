**DO NOT MERGE — stays DRAFT until the round-3 gate returns.**

Epic: https://github.com/DIG-Network/dig_ecosystem/issues/3173

Closes #302
Refs #306

## Why #306 is `Refs` and not `Closes`

**#306 asks for a notification, and this PR delivers a readout.** `activity::runway` produces the
title, body and route, and nothing dispatches them — because the activity gate that #306 assumes
(hold until the person is at the keyboard, never at 03:00, coalesced, bounded, and saying **when** the
condition arose) does not exist in this repo under any name. `notify::run_notifier` has coalescing and
no input gate.

That gate is filed as **https://github.com/DIG-Network/dig-app/issues/312**, which #305 and #300 are
blocked on for the same reason. #306 needs two more things after this PR: a consumer for the
notification, and #312 to time it. A `Closes` keyword here would assert an end-to-end outcome the
wiring does not deliver.

`Closes #302` stands: there is no `collateral` field on `AgentConfig`, no surviving cache, the
upgrade path is tested in both directions, and the card redraws from the margin the node returned.

## What round 3 changed

### 1. `read_buffer` now has a consumer — the reason #306 was not delivered at all

`gitnexus impact read_buffer -d upstream` returned **`impactedCount: 0`**, and the binary's only
`Reminder` is `first_profile::ReminderFile`; `funding::Reminder` is driven from nowhere. A correct
reader that nothing calls is indistinguishable, from outside, from a missing feature — this is the
dead-control class, and parity with a thing that never worked is not delivery.

Settings gains a **funding card**, above the margin chooser it explains, drawing every state:

| state | what a person sees |
|---|---|
| `short_now` | **Short now**, the $DIG to add, and *"Not enough $DIG for this epoch — your stores are uncollateralised. They stay online and readable, but other nodes cannot find them and they earn nothing."* |
| `dangerously_low` | **Low for next epoch**, the $DIG to add, and *"there would not be enough if the requirement rose as far as it can next epoch"* — "could not", never "will not": the escalation figure is a ceiling the node assumed, not a forecast |
| `below_recommended_buffer` | **Covered, no cushion**, the gap to the recommendation, and a sentence that reads as covered. Deliberately not a warning: dressing a cushion as a shortfall is how the two real shortfalls stop being read |
| `funded` | **Funded**, and **no Add row at all** — "Add 0 $DIG" is a call to action against a state that needs none |
| **`Unknown` / `Pending`** | **one line, a reason, and no figure anywhere.** Three distinct reasons, because the remedies differ: waiting, the node's own bookkeeping, and the call itself |

Every state shows its working — pairs served, per-store requirement, margin in force, recommended
holding, spendable balance, and **the horizon from the payload**, never a constant here, because the
same buffer over a different horizon is a different claim.

**`below_recommended_buffer` remains a readout and never a notification.** `runway::title` still
returns `None` for it, and the card derives from the node's `funding_state` rather than any local
threshold.

### 2. `collateral::cost()` carried the same under-count — fixed here

`mod.rs:229` computed `posted_per_store x HostedStoresReading::len()`. `HostedStore` is keyed on
`store_id`, while the node posts per qualifying `(owner, store, root)` pair, so one store serving two
owners is one list entry and two postings. It now takes `pairs_served_by_this_node` from the buffer
payload.

This is the same wrong unit, shown to a person about money, one function away from the one round 2
fixed. Leaving it is how the next round finds it.

### 3. A pre-dispatch 401/403 no longer names the token confidently

dig-node refuses an unauthorized control request at the HTTP layer **before dispatch**, so the
response is identical whether the token is wrong or the build does not serve the verb — and until the
node side ships, not serving it is the ordinary case. Classifying it as `Unauthorized` sent a person
to check a credential that was never the problem.

Split into `RefusedBeforeDispatch` (names both remedies) and `Unauthorized` (only from a JSON-RPC
`UNAUTHORIZED` `data.code`, which a node can emit **only after routing the call**, and which therefore
proves the method exists). Pre-existing and shared with the two 0.23 verbs, which is why it is fixed at
the classifier rather than per-verb.

### 4. The screenshot harness — the blocker was real, and it is fixed

Round 2 produced seven plausible PNGs and deleted them, correctly: all three margin states were
byte-identical and `pane_preview` read *"DIG cannot read its settings file"*.

**The cause was a one-line defect in the harness, not the GPU.** `seed_collateral_preview` built its
session with `store: None`, which is the cannot-read-the-settings-file state, so **every settings card
drew a banner instead of its body** — no preview could ever photograph any card. `prefs::PreviewStore`
(in-memory, reads a default, drops writes) fixes it.

Two captures are committed under `crates/dig-app-core/docs/collateral-funding/`, taken with
`PrintWindow(PW_RENDERFULLCONTENT)` — no foreground steal, no synthetic input. The pane is longer than
any window this display can open and scrolling would mean driving input at it, so the content is scaled
to `0.36` and the whole pane is in frame.

The `short_now` capture is also visible evidence of the pair-count fix: the margin card below reads
**116.15 $DIG** locked in total, which is `5_050 x 23` base units against the **23** pairs shown two
cards above. The session's hosted-store list holds **one** entry; totalling entries would have printed
`5.05`.

## Blast radius checked — gitnexus, per worktree

The round-2 body said gitnexus was not used. It is now: the index was built **in this worktree** and
queried there (105 MB, deleted with `target/` per §1.6).

| symbol | impacted | risk | what it reaches |
|---|---|---|---|
| `collateral::cost` | 9 (7 direct) | **HIGH** | 1 process (`settings::draw`), 3 modules — all inside `dig-app-core` |
| `Session::from_store_through` | 11 (4 direct) | **HIGH** | 2 processes; reaches `examples/pane_preview.rs::main` |
| `margin_card` | 5 (1 direct) | LOW | `settings::draw` |
| `read_buffer` | **0** | LOW | **nothing — the defect this PR fixes** |
| `MarginCost` | 0 | LOW | — |

**WARNING — two HIGH-risk symbols were edited.** Both radii are wholly inside `dig-app-core`, which is
**not published to crates.io** (`index.crates.io` → 404), so no external build can break. Every
consumer of the changed signatures is a compile error, and `cargo check -p dig-app-core --all-targets`
is clean.

`CollateralPreview` (renamed from `MarginPreview`, since it now drives both cards) was renamed against
the **fully enumerated 6-site radius** from `impact` + grep, not by find-and-replace. `gitnexus rename`
is an MCP tool and is not in the CLI available here — stated rather than glossed.

`detect_changes()` is likewise MCP-only. The substitute is the diff itself: 15 files, confined to the
collateral seam, the settings pane, the preview harness, the SPEC and the new docs directory. No
`TrayView` change, so no repaint-gate risk.

## How it was verified

- `cargo test -p dig-app-core --lib` — **2570 passed, 0 failed, 6 ignored.**
- `cargo clippy -p dig-app-core --all-targets -- -D warnings` — clean.
- `cargo fmt --all --check` — clean.
- Four integration-test binaries fail to **link** with `STATUS_STACK_BUFFER_OVERRUN` on this host
  (`hd_derivation_varies_by_index` among them — files this PR does not touch). A pre-existing Windows
  linker flake, not a test failure; CI is the arbiter.

### Mutation proofs — every new test reverted individually

Committed first, so no revert could destroy uncommitted work. Tree asserted clean after each restore.

| mutation | result |
|---|---|
| `cost` counts `4` instead of the node's pair count | **4 tests fail** |
| a pending buffer renders as a zero recommendation | **1 fails** |
| the Add row is drawn unconditionally | **1 fails** |
| the horizon comes from a constant instead of the payload | **1 fails** |
| the three unknown reasons collapse into one | **1 fails** |
| **`funding_card` unwired from `draw()`** | **1 fails** — `the_funding_card_is_drawn_into_the_pane`, and **only** that one, confirming nothing before this round could have caught the missing consumer |

The placement fix is pinned with **two actors**: `painted()` seeds a **one-entry** hosted-store list
beside a node reporting **23** served pairs, and the drawn total is asserted to be the **larger**
figure. That pins the failure *direction* — understating money to be locked — rather than an
inequality, which a wrong count could satisfy either way.

A pre-existing guard also caught an omission of mine: `every_wrapped_sentence_is_reachable_by_the_whitespace_guard`
failed until the four new wrapped sentences were registered. Worth recording as a gate that works.

## Also in this PR

- **SPEC.md §3.7b** gains the pair-count rule (the total is `posted_per_store x pairs_served_by_this_node`,
  and MUST NOT fall back to a list length).
- **SPEC.md §3.7c** gains the readout surface, the show-your-working rule, the horizon-from-payload
  rule, the no-figure-when-unread rule, the pre-dispatch-refusal rule, and an explicit
  **"not yet delivered: the notification half"** paragraph naming #312.
- **Version 13.14.0 → 13.15.0** (minor). New user-facing capability, nothing taken away.
  `dig-app-core` is unpublished, so the renamed public item breaks no external build.

## Deferred, with reasons

- **`dig-constants` stays two minors behind.** `dig-account`, `dig-session`, `dig-tips` and
  `dig-wallet-backend` all still pin 0.11 at their own latest, so moving dig-app alone puts two
  `dig-constants` lines in one lock. Upstream release-first cascade, verified twice, not re-litigated.
- **No part of this has run against a node that serves these verbs**, because none exists yet.
  Shapes are conformant by construction (the contract's own types are used, so a mismatch is a compile
  error) and the absent-method path is the one exercised by tests; the round trip against a real
  implementation is unproven and is stated as such.
