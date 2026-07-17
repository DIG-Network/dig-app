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

## Spec & status

`SPEC.md` is the normative contract (the identity split, the IPC contract, NC-2/NC-3, release
engineering). U1 (this work) ships the spec + the gated scaffold + the apps-repo release pipeline
(nightlies + manual stable, uniform with dig-node); the identity/keys/profiles/session subsystems are
implemented by later work units (see the SPEC appendix). Architecture + DAG: DIG-Network/dig_ecosystem#908.
