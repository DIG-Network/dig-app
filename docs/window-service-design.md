## Design — the dig-app window service

Design only; no implementation yet, per the lock-the-shape-first instruction. Branch
`fix/window-manager-86` is open with a stub commit.

---

### 0. What the code actually says today (read, not assumed)

Files read in full or in their non-test span: `confirm/mod.rs` (1–1090), `confirm/gui/window.rs`
(1–1630), `confirm/gui/mod.rs`, `dig-app/src/tray_worker.rs`, and the tray event loop +
`dispatch` in `dig-app/src/bin/dig-app.rs` (1310–1521, 1598–1700, 2204–2216).

The pieces that each hold a fragment of "is a window open":

| holder | where | released by |
|---|---|---|
| `PROMPT_THREAD: OnceLock<Option<PromptThread>>` + its `Mutex<Sender<Job>>` | `window.rs:208` | never (by design) |
| `serve_with`'s `rx.recv()` loop, strictly one job at a time | `window.rs:398` | the return of `draw(job)` |
| `Job::over_by`, stamped at QUEUE time | `window.rs:193` | compared once, in `serve_with` |
| `Vigil { wake, over_by, complain_again_at }` under `&'static Mutex<Option<Vigil>>` | `window.rs:297` | `clear_vigil` on the return path |
| the watchdog thread | `window.rs:333` | — (nudges only) |
| `ask()`'s `recv_timeout(deadline + ANSWER_GRACE)` | `window.rs:1551` | the caller's own clock |
| `ActionWorker::busy: Arc<AtomicBool>` | `tray_worker.rs:43` | **the handler returning** (`:76`) |
| the tao pump's `menu.actions` map + `model` | `dig-app.rs:1449`, `:1504` | the pump ticking |

Eight owners. Six of the eight are released on a **return path**. That is the whole defect class in
one sentence: *every fragment of the state is freed by the thing that may never come back.*

---

### 1. Where the current wedge is, and the one thing I will not guess

The trace rules out more than it looks like it does. After `account::boot`'s ERROR:

- the user **saw** the "not unlocked" notice and dismissed it → `notify` → `show_notice` → `ask`
  → the prompt thread drew a window and the user answered it. The renderer worked.
- `Alt+Space` still draws a bar → the hotkey thread, the prompt thread and `run_native` are all
  still healthy *after* the wedge. The renderer is still working.
- #83's `busy`-latch WARN (`dig-app.rs:1477`) does **not** fire → `actions.submit` is never called
  with a latched worker.
- #83's unmapped-id WARN (`dig-app.rs:1455`) does **not** fire → `menu_events.try_recv()` is never
  reached with an unknown id.

Both WARNs live inside `while let Ok(event) = menu_events.try_recv()`, which lives inside the tao
callback. Neither firing means **the tao callback is not running**. The pump is blocked, and it is
blocked *below* the window stack — the window stack demonstrably still works.

What the pump does per tick that can block indefinitely, in order of suspicion:

1. `show_presence` → `tray.set_tooltip` / `tray.set_icon` → `Shell_NotifyIcon`, which is a
   `SendMessage` to `Shell_TrayWnd`. It has no timeout and is the classic Windows hang when the
   caller's input queue has been attached to, or the shell is waiting on, a foreground window on
   another thread. **A failed unlock is exactly the tick where this runs**: `attempt` moves
   `NotAttempted → Refused`, `view_eq` goes false, and `show_presence` fires for the first time in
   the session.
2. `repaint` → `render()` (muda menu construction) → `tray.set_menu`, same shell/USER32 surface.
3. a nested `TrackPopupMenu` modal loop that never unwinds because a background-thread window took
   the foreground while it was up — the prompt window is `always_on_top` + `with_active(true)`.

All three are the same shape: **a USER32/shell call made on the pump thread with no bound and no
record that it was entered.** I am not going to pick one from a log. The design's first artefact is
the instrument that names it (§4), because a fifth fix aimed at the wrong one of these three is
precisely the pattern that produced #69, #78, #83 and this.

The architecture below does not depend on which of the three it is.

---

### 2. The service

One new owner: **`WindowService`**, on its own thread (`dig-window-service`), reached through a
mailbox. Three actors, and the boundary between them is the point:

```
callers                    WindowService                 render thread
(tray worker, hotkey,      (owns ALL state, owns          (existing prompt thread —
 loopback tasks)            the clock, draws nothing)      a pure executor)
      |  open(req) -> Ticket      |                              |
      |-------------------------->|                              |
      |                           |-- Draw{epoch, screen} ------>|
      |                           |<- Created{epoch, ctx, hwnd} -|
      |                           |<- Answered{epoch, intent} ---|
      |<-- Terminal --------------|                              |
```

**Why a third thread, deliberately.** It must (a) have a clock that still runs when the pump is
blocked *and* when the renderer is blocked — so it can be on neither; (b) be reachable from the tokio
loopback tasks, the hotkey thread and the tray worker without any of them owning it; (c) outlive both.
A supervisor that shares the blocked thread cannot rescue it, and both candidate threads are ones we
have now watched block.

**It also watches the pump** (§4), rather than a fourth thread doing that. One clock, one place that
knows "which UI thread is not making progress" — a second half-owner of that question is the exact
shape being deleted.

---

### 3. What makes the wedge states unrepresentable

Five mechanisms, each closing one of the eight owners above.

**3.1 The service's state is a total enum it alone mutates.**

```rust
enum Occupancy {
    Vacant,
    Open   { epoch: Epoch, owner: WindowOwner, opened: Instant, deadline: Instant, sink: Sink },
    Derelict { epoch: Epoch, since: Instant },   // renderer did not report; no respawn is possible
}
```
No other module can name a variant (`pub(crate)` type, private field). "Is a window open" has
exactly one representation, and one writer.

**3.2 The service's own clock, not the return path, ends a window.** The service loop is
`mailbox.recv_timeout(time_until(deadline))`. When the deadline elapses the service performs the
transition and answers the caller itself. It needs nothing from the render thread to do so.
**A handler that never returns can no longer hold any state, because the state was never its to hold.**
This is the direct replacement for `busy` being cleared at `tray_worker.rs:76`.

**3.3 Terminal outcomes are constructor-restricted, so timeout cannot become approval.**

```rust
enum Terminal {
    Answered(WindowIntent),   // constructible ONLY from a render-thread report
    Expired,                  // the service's clock
    Abandoned,                // the service gave up on the renderer
    Undrawable,               // no renderer / creation failed
}
```
`Answered` carries the only value that can be `Approve`, and the service thread has no code path that
constructs it — it only *forwards* one that arrived tagged with the current epoch. The watchdog and
the deadline can emit `Expired`/`Abandoned` and nothing else. This makes "the watchdog manufactured
consent" a compile error rather than a test.

**3.4 Epochs make a stale window's answer inexpressible.** Every occupancy carries a monotonic
`Epoch`; every render-thread message carries the epoch it was issued for. `epoch != current` is
dropped at the mailbox. This subsumes `Job::over_by` (a wall-clock heuristic) with an identity check,
and kills the whole "a window opened for a caller who left" family — including the case `over_by`
does not cover, where a *previous* window finally answers after a new one is up.

**3.5 `Ticket` is an RAII guard.** The caller holds a `Ticket`; `Drop` posts `Released{epoch}`. A
caller that panics, unwinds or is cancelled releases without cooperating. Belt (guard) **and** braces
(3.2), because #78 showed that a deadline enforced by the thing it bounds is not a deadline.

**3.6 One route to a window, enforced structurally.** `eframe::run_native` is called from exactly one
private function, reachable only from the render thread's command loop; `Screen`/`Draw` are
constructible only from a `WindowRequest` the service validated. `BrandedWindow` and `BrandedInput`
become thin clients of the service and keep their public shape, so `NativeConfirmer` and every call
site are untouched. Backed by a source-scan test asserting exactly one `run_native` call site in the
crate — cheap, and the thing review has failed to hold four times.

**3.7 Reclaiming an abandoned window without a new event loop.** No respawn is attempted — winit's
process-global `EVENT_LOOP_CREATED` and eframe's thread-local cache make it a permanent silent
`Unavailable`, which is established by measurement and is preserved as a documented constraint.
Escalation, all initiated by the service:

1. `request_repaint` — the wake that also unlatches a winit-latched panic. This ordering is the
   #2074 finding and is carried over verbatim, now owned by the service rather than by `Vigil`.
2. `ViewportCommand::Close`.
3. **Windows only:** `PostMessage(hwnd, WM_CLOSE)`. The service learns the `HWND` in `Created`.
   This reaches a renderer that is pumping but not calling back — strictly more reach than an
   `egui::Context`, and it cannot manufacture consent because the outcome is `Abandoned`, recorded by
   the service, never read from the window.
4. Still nothing → `Occupancy::Derelict`. Subsequent opens are answered `Undrawable`
   **immediately and loudly**, not queued. That is the honest end state, and the difference from today
   is total: the rest of the app is not wedged, the caller gets a real refusal in milliseconds, and the
   log says restart DIG. Today the identical condition is a silent black hole.

---

### 4. The pump: never block, and never block silently

The reported wedge (§1) is not in the window stack, so the service alone does not fix it.

**4.1 The instrument, first.** A `PumpVigil`: the pump stamps a heartbeat at the top of each tick,
and stamps *entry and exit around each individually-named USER32/shell call*
(`set_tooltip`, `set_icon`, `set_menu`, `render`). The service thread watches it. A heartbeat older
than a few seconds logs ERROR naming **the outstanding call**, and keeps saying so on a backoff.
The reproduction is deterministic, so one run over the recipe names the culprit — and every future
member of this class names itself on first occurrence instead of costing a round.

**4.2 Then the fix, scoped to what it names.** Whichever of §1's three it is, the remedy is the same
shape: the pump makes no unbounded USER32/shell call. Surface mutations move behind a bounded,
off-pump path (a dedicated surface thread that owns the tray handle, or `SendMessageTimeout`
semantics where the API allows), so a hung shell costs a stale tooltip and never the pump. If it is
the `TrackPopupMenu` case, the fix is ordering the foreground steal against the modal loop, which the
service can do because it is the one thing that knows a prompt window is about to take the foreground.

**4.3 Inspectable state (requirement 5, the user's word is "unpredictable").** Every occupancy
transition logs at INFO with its epoch, owner and reason. The service answers a query with its whole
belief — occupancy, owner, opened-at, deadline, epoch, renderer health, pump health, and the last 8
transitions — and `Status and details…` shows it. The current surface can say nothing at all about
itself, which is why four investigations started from a user report rather than a log line.

---

### 5. Native behaviour on every window

Decision: **stay frameless and implement the native contract explicitly**, in one shared
`WindowChrome` used by `Chrome::Dialog` and `Chrome::Bar` alike. Turning OS decorations on would buy
drag/close/snap for free, but it puts an attacker-influenced title into a system-drawn title bar and
gives up the branded consent card that #2038 chose deliberately over a webview. So the contract is
implemented once, and *tested* once, instead of being special-cased per window as drag was in #81.

The contract, each item a named test:

- **Drag** — the existing header strip, generalised. `DRAG_HANDLE_SENSE`'s reasoning is preserved
  intact (`CLICK` retained so egui withholds the drag until the gesture cannot be a click;
  `FOCUSABLE` dropped so the strip is not the first tab stop on a consent dialog).
- **The phantom release.** winit posts a synthetic `WM_LBUTTONUP` at client `(0,0)` on
  `WM_EXITSIZEMOVE`, so *every* finished drag delivers a release into the window. `(0,0)` is inside
  the chrome, so the chrome **reserves `(0,0)` as inert** — today that is accidentally safe because
  the only chrome control (the theme toggle) is right-aligned, and a future left-aligned control
  would silently break it.
- **Close** — a real X affordance in the chrome, plus Esc, plus `WM_CLOSE`/Alt+F4. All three record
  the *same* refusal through the *same* path.
- **Focus and z-order** — always-on-top stays for the consent surface and is stated as a deliberate
  exception to "like every other window"; a consent window that can be buried is a worse defect.
- **Snap** — drag-to-edge via the platform's own handling of the move we already perform.
- **Multi-monitor** — open on the monitor holding the cursor/foreground window, clamped to that
  monitor's *work area*, not its bounds.
- **Per-DPI** — correct scale at creation and re-layout on DPI change; the existing
  `fit_to_content` / `SCREEN_SHARE` sizing runs against the target monitor's scale.
- **`Chrome::Bar` dismisses on blur; `Chrome::Dialog` never does** — now a property of the shared
  component, asserted over both chromes, rather than a per-site behaviour that a shared component
  could quietly level out.

---

### 6. A second open focuses and flags the first

Service-owned, and never silent:

- `open()` while `Open` returns `Busy { owner }` to the caller **immediately**. Not queued (a queue is
  what #2074 had to refuse late) and not dropped. The caller's action ends at once, so nothing latches.
- The service posts `Attend{epoch}`, which does three things at three different levels of reliability,
  deliberately layered:
  1. **In-window, unconditional:** the window draws an attention pulse (border/scrim) and a banner
     naming the action to finish. This is drawn *by the window itself*, so it works even when the OS
     refuses the foreground — **this is the answer to "what happens when focus is refused"**. The user
     always gets a visible change somewhere.
  2. **`FlashWindowEx` on the `HWND`** — the sanctioned Win32 primitive for exactly this, and the one
     the foreground lock does **not** refuse. Not `AttachThreadInput`, which was rejected before and
     stays rejected.
  3. **`ViewportCommand::Focus`** — best-effort, on top of the two above, never load-bearing.
- Plus a tray-side cue (tooltip/balloon) naming the open window, since a refused focus can leave it
  behind another app entirely.
- **The deadline is not reset** on attend, and **the window is not moved** — both stated in the type
  (`Attend` carries no deadline field, so resetting it is unrepresentable rather than merely
  forbidden), because a window that jumps under the cursor and renews itself is a click-through
  trainer on the consent surface.

---

### 7. Consent invariants — how each is preserved, and how it is proven

| invariant | preserved by | proven by |
|---|---|---|
| timeout can never become approval | §3.3 — `Expired` cannot carry an intent | a compile-level argument + a total-match test over `Terminal` |
| the watchdog cannot manufacture consent | §3.3 — the service has no `Answered` constructor | the same, plus a test driving abandonment to a refusal |
| `Chrome::Dialog` never dismisses on blur | §5 — a property of the shared chrome | asserted over **both** chromes |
| `refusal_is_default` at every `ClaimPrompt` site | untouched; #2098's guard kept and extended to any new site | the existing guard test |
| the drag region cannot activate an action control | §5 — sense unchanged, `(0,0)` reserved inert | a test injecting the synthetic `(0,0)` release after a drag |
| never blind-sign | untouched — `ConfirmContent::sign` short-circuit is above this layer | existing tests |

The service moves *where state lives*. It does not move `gated_consent`, the content composition, or
any fail-closed default — those stay in `confirm/mod.rs` exactly as they are.

---

### 8. Plan

Two PRs, one family, both mine, in this order:

- **PR-A (the live P0).** The pump instrument (§4.1) → run the deterministic recipe → the located
  fix (§4.2) → the service (§3) with `BrandedWindow`/`BrandedInput` rewired through it, `Attend`
  (§6), and the inspectable state (§4.3).
- **PR-B.** The native-window contract (§5) + the single-route enforcement (§3.6) + `SPEC.md`,
  `SYSTEM.md` and docs coherence.

**Acceptance is a real Windows process**, not a suite: the exact recipe (tray → Unlock → wrong
password → dismiss) leaves the tray fully usable, and an injected handler that never returns cannot
wedge the surface. Every guard gets its mutation applied with bytes verified changed on disk **and
the mutant confirmed to compile**, since a build failure reads identically to a passing suite.

**Open question I am carrying, not hiding:** §1's three candidates are unresolved and one run of the
instrument resolves them. If the answer turns out to be the `TrackPopupMenu` case, PR-A grows the
foreground-ordering work described in §4.2; the rest of the shape is unaffected either way.

---

### 9. 2026-08-04 — the shape was re-decided, and one premise of the new shape is FALSE

This section is appended rather than edited into the sections above, because the sections above are a
record of what was believed at the time and are still useful as that.

**The "window registry/service class" frame (§3) is dropped.** The replacement plan is three steps:
declare DPI awareness in a manifest (step 0), move the tray to its own tao thread with
`with_any_thread` and then DELETE the whack-a-mole layer that guards `TrackPopupMenu` (step 1), and
make a stranded phase unrepresentable (step 2). Steps 0 and 2 shipped in the PR carrying this file.

**Step 1 did not ship, because its stated rationale is falsified at source.**

The plan's four dependency facts were re-verified in the locked versions and all four HOLD:

| fact | verified at |
|---|---|
| `TrackPopupMenu` runs in `tray-icon`'s OWN window proc, not tao's | `tray-icon-0.23.1/src/platform_impl/windows/mod.rs:541-545` |
| `tray-icon` does not require the main thread on Windows/Linux | `tray-icon-0.23.1/src/lib.rs:17` |
| tao's main-thread gate is per-THREAD and `with_any_thread` disables it | `tao-0.30.8/src/platform_impl/windows/event_loop.rs:170-178`; `src/platform/windows.rs:106` |
| DPI awareness is set by whichever event loop is built first, behind a `Once` | `tao-0.30.8/.../event_loop.rs:180-182` -> `dpi.rs:20-26` |

A FIFTH fact, not in the plan, decides step 1:

> **`tray_icon::TrayIcon` is `Rc<RefCell<platform_impl::TrayIcon>>`** (`tray-icon-0.23.1/src/lib.rs:346`),
> and the crate declares no `unsafe impl Send` for it — the only one in the crate is for `WinIcon`
> (`platform_impl/windows/icon.rs:67`). The tray handle is therefore `!Send` and `!Sync`.

Everything that repaints the tray — `set_icon`, `set_tooltip`, `set_menu` — must run on the thread
that created it. The tick loop repaints. So the tick loop CANNOT be separated from the tray, and
moving the tray to its own thread moves the tick loop with it.

The consequence is the one that matters: after the move, an open `TrackPopupMenu` still stops the
tick, exactly as it does today. The plan's premise — *"a wedged `TrackPopupMenu` then blocks only the
tray thread; the main loop keeps ticking"* — does not hold, and with it the deletion rationale
(*"with the tray isolated these have no subject"*) does not hold either:

- `Phase::TrayMenu` still has a subject. Deleting it would make every ordinary menu-read of more than
  ten seconds an ERROR telling the user to restart DIG. That is the false-alarm regression 3.1b-lv
  exists to prevent, several times a day.
- `break_modal_menu` still has a subject. A wedged popup still ends the tray permanently; the rescue
  is still the only thing that ends it short of a restart.
- `claim_foreground` still has a subject, for the same reason.

Deleting them would not remove whack-a-mole; it would remove the only mitigation and leave the wedge.

**What the thread move is still worth, and what it needs first.** Freeing the main thread is real, but
its value is entirely in step 3 (the prompt host, whose `PROMPT_THREAD: OnceLock` sits behind winit's
per-PROCESS latch). Doing the topology change now, on a consent-bearing surface, with no present-tense
benefit and a rationale known to be wrong, is building on an unsettled shape.

**Recommendation for the next decider.** Re-scope step 1 as *"give the prompt host the main thread"*
rather than *"isolate the tray"*, and settle the two questions the `!Send` fact raises before any code
is written:

1. Does the tick keep the tray's thread (simple; the menu still stalls it; keep the mitigations), or
   is the repaint made message-driven so the tick can live elsewhere (a real redesign; only then does
   the deletion argument become available)?
2. With DPI now declared in the manifest, the ordering constraint that made step 0 a prerequisite is
   discharged — a second event loop can no longer change this process's awareness. That is the one
   part of the plan that step 0 has already made safe.
