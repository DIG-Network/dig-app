# dig-app

The **DIG user app** — the user's interaction with the DIG Network, and **the identity**.

A branded, per-user application that runs in the interactive user's session and owns everything
identity-specific: **key management**, **DID/profiles** (multi-profile, via `dig-identity`), the
**wallet**, per-user data (in the user's AppData, **encrypted at rest** to the user's key), and the
**CLI/RPC gateway** (`diga` + RPC clients route through the user app, which authenticates via the held
identity key and proxies to the engine).

It fronts the **`dig-node`** — the *identity-agnostic* background engine (P2P, content serve, chain
watch; holds only a machine/transport `peer_id`, no user identity/keys/data). The user app supplies the
user identity per-operation over local native IPC (Windows named pipe / macOS·Linux Unix domain socket
/ the node's identity-authenticated control channel); **the user key never enters the engine**.

Surfaces per OS: Windows system-tray · macOS menu-bar (`LSUIElement` launchd LaunchAgent) · Linux
AppIndicator tray (or systemd user service). **Degrades headless** — on a GUI-less host it's a per-user
identity agent + the `diga` CLI, no tray.

## Your DIG Account, from the tray

On a fresh install there is no account yet, and DIG does not create one behind your back — creating an
account means showing you a recovery phrase, and that should happen when you are ready for it. Open the
DIG menu from your system tray or menu bar and choose **Set up my DIG Account**. You are shown **24
words**, once, and asked to confirm you have written them down before the account is created.

Those 24 words ARE your account. The account itself is sealed to this machine (its unlock password lives
in your OS credential store), so the words are the only thing that can bring it back on a different
computer. Nobody, including DIG, can recover an account without them.

**Everything about your account is in the DIG app** — there is nothing you need a terminal for. The tray
menu keeps the four things you want in one click — whatever your account needs right now, **Open URL…**,
**Open App**, and **Quit DIG** — and **Open App** opens a window with the rest, arranged in tabs down the
left: Status, Account, Security, Wallet, Apps and Cache. How DIG is doing is shown by the tray ICON, by
its tooltip, and by **Status and details…** on the Home tab, which has the whole picture (including the
node's full diagnosis when something is wrong).

On a computer where DIG cannot open that window — macOS today, and Linux with no desktop session — the
tray menu keeps everything instead, so nothing is ever out of reach. If the window ever fails to open, the
full menu comes straight back.

From the app you can:

- **show your recovery phrase again**, behind your Windows Hello / Touch ID / system authentication
- **copy your DIG ID**, and lock the session
- **Restore from a recovery phrase** — DIG asks for your 24 words in a real window, hidden as you type with
  a *Show the words while I type* box when you want to check them
- on the **Account** tab: replace this account with a new one, replace it with an account from a
  recovery phrase, or remove it from this computer

Replacing or removing an account destroys the key it is sealed to, so DIG asks you to authenticate first —
and offers to show you the current account's 24 words before anything is lost. Those verbs are always
available: an account you cannot change is a trap, not a safeguard.

## Opening a DIG link — press Alt+Space anywhere

Reading DIG content needs no account, so it should cost one keystroke. Press **Alt+Space** from any
application and a bar floats up in the middle of your screen: paste a `chia://` or `urn:dig:chia:` link,
press Enter, and it opens in your browser served by your own DIG node. Escape closes it, and so does
clicking somewhere else. The same thing is in the tray menu as **Open URL…**, which shows the shortcut
beside it — one of the four rows that never leaves the tray, because reading content should never wait on
a window.

On Windows, Alt+Space normally opens the current window's Move / Size / Close menu, and while DIG is
running it opens the DIG bar instead. If you would rather keep the window menu, set your own chord in
`agent.json` beside DIG's other settings:

```json
{ "open_bar_shortcut": "Ctrl+Shift+Space" }
```

Any combination of `Ctrl`, `Alt`, `Shift` and `Win` plus a letter, a digit, `Space` or `F1`–`F24` works; at
least one modifier is required. If another application already owns your chord, DIG says so in **Status and
details…** and the tray's **Open URL…** goes on working.

An on-chain `did:chia:` DID is optional and costs XCH; DIG never mints one without you asking, and your
account, phrase and address all work fully without it.

If the tray icon never appears, DIG is probably running but unable to draw it — on Linux that is almost
always a missing `libayatana-appindicator3-1`. DIG logs that and prints the cause; install the library and
start DIG again.

Architecture + design: DIG-Network/dig_ecosystem#908 (epic). Boundary invariant: the node is the
identity-agnostic engine; dig-app is the identity + user interaction.

## Workspace layout

- `crates/dig-app-core` — the headless per-user identity-agent **library** (identity/keys/profiles/
  wallet/storage/IPC/gateway). All logic + test coverage lives here.
- `crates/dig-app` — the thin binaries: `dig-app` (the branded tray/menu-bar agent shell) and `diga`
  (the DIG user CLI).

## Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo llvm-cov nextest --workspace --fail-under-lines 80   # the CI coverage gate
```

## Linux: which binary to run

The tray shell is drawn with GTK 3 / AppIndicator, so the default `dig-app` build links the GTK 3
runtime — eight shared libraries a desktop session already has and a **server or cloud image does
not**. A missing library is fatal in the dynamic linker, before `main`, so the shell's own headless
degradation cannot rescue it: the process just exits 127. Two Linux assets therefore ship per release:

| Asset | Links | Run it when |
| --- | --- | --- |
| `dig-app-<ver>-linux-x64` | GTK 3 runtime | a desktop session is present (gives you the tray) |
| `dig-app-<ver>-linux-x64-headless` | libc only | no desktop — server, container, cloud image |

`ldd ./dig-app-<ver>-linux-x64 | grep 'not found'` names anything the tray build is missing; on
Debian/Ubuntu `libgtk-3-0t64` supplies it. The tray build does **not** depend on `libxdo`
(dig_ecosystem#1753) — nothing in the menu uses X11 keystroke synthesis.

Under Wayland the tray works through the GTK Wayland backend; only the unused libxdo capability was
X11-specific.

## Spec & status

`SPEC.md` is the normative contract (the identity split, the IPC contract, NC-2/NC-3, release
engineering). U1 (this work) ships the spec + the gated scaffold + the apps-repo release pipeline
(nightlies + manual stable, uniform with dig-node); the identity/keys/profiles/session subsystems are
implemented by later work units (see the SPEC appendix). Architecture + DAG: DIG-Network/dig_ecosystem#908.
