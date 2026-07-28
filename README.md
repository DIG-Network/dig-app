# dig-app

The **DIG user app** — the user's interaction with the DIG Network, and **the identity**.

A branded, per-user application that runs in the interactive user's session and owns everything
identity-specific: **key management**, **DID/profiles** (multi-profile, via `dig-identity`), the
**wallet**, per-user data (in the user's AppData, **encrypted at rest** to the user's key), and the
**CLI/RPC gateway** (`dign` + RPC clients route through the user app, which authenticates via the held
identity key and proxies to the engine).

It fronts the **`dig-node`** — the *identity-agnostic* background engine (P2P, content serve, chain
watch; holds only a machine/transport `peer_id`, no user identity/keys/data). The user app supplies the
user identity per-operation over local native IPC (Windows named pipe / macOS·Linux Unix domain socket
/ the node's identity-authenticated control channel); **the user key never enters the engine**.

Surfaces per OS: Windows system-tray · macOS menu-bar (`LSUIElement` launchd LaunchAgent) · Linux
AppIndicator tray (or systemd user service). **Degrades headless** — on a GUI-less host it's a per-user
identity agent + the `dign` CLI, no tray.

## Your DIG Account, from the tray

On a fresh install there is no account yet, and DIG does not create one behind your back — creating an
account means showing you a recovery phrase, and that should happen when you are ready for it. Open the
DIG menu from your system tray or menu bar and choose **Set up my DIG Account**. You are shown **24
words**, once, and asked to confirm you have written them down before the account is created.

Those 24 words ARE your account. The account itself is sealed to this machine (its unlock password lives
in your OS credential store), so the words are the only thing that can bring it back on a different
computer. Nobody, including DIG, can recover an account without them.

The tray menu also lets you see your account state, **show your recovery phrase again** (behind your
Windows Hello / Touch ID / system authentication), copy your DIG ID, lock the session, and open the log
folder.

To bring an account back on another computer:

```bash
dign account restore   # asks for your 24 words, without showing them
dign account status    # what account this machine has, and whether it has a phrase
```

An on-chain `did:chia:` DID is optional and costs XCH; DIG never mints one without you asking, and your
account, phrase and address all work fully without it.

If the tray icon never appears, DIG is probably running but unable to draw it — on Linux that is almost
always a missing `libayatana-appindicator3-1`. DIG logs that and prints the cause; meanwhile `dign` still
works.

Architecture + design: DIG-Network/dig_ecosystem#908 (epic). Boundary invariant: the node is the
identity-agnostic engine; dig-app is the identity + user interaction.

## Workspace layout

- `crates/dig-app-core` — the headless per-user identity-agent **library** (identity/keys/profiles/
  wallet/storage/IPC/gateway). All logic + test coverage lives here.
- `crates/dig-app` — the thin binaries: `dig-app` (the branded tray/menu-bar agent shell) and `dign`
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
