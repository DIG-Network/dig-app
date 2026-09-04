# Contributing to dig-app

`dig-app` is the DIG user app: the user's interaction with the DIG Network, and **the identity**. It
owns everything identity-specific — key management, DID/profiles, the wallet, and per-user data
encrypted at rest — and fronts the identity-agnostic `dig-node` engine over local IPC. Because this
repo holds custody code (keys, signing, spends), read this before opening a PR.

## Reporting an issue

File at [DIG-Network/dig-app/issues](https://github.com/DIG-Network/dig-app/issues) with what you
observed, what you expected, and steps to reproduce.

This repo has no `SECURITY.md` yet. For anything touching key handling, signing, or a spend path,
please still avoid posting exploit details in a public issue — open a minimal report describing the
class of problem and we'll follow up for specifics.

## Prerequisites

- [Rust](https://rustup.rs), pinned to **1.98.1** via `rust-toolchain.toml` (`rustup`/`cargo` pick it
  up automatically), with the `clippy`, `rustfmt`, and `llvm-tools-preview` components.
- No `wasm32` target is needed — this workspace has no embedded-wasm build step.
- **Linux**: the default `tray` feature links GTK. Install its dev headers before building:

  ```sh
  sudo apt-get update && sudo apt-get install -y libgtk-3-dev
  ```

  (Runtime only needs the shared library, e.g. Debian/Ubuntu's `libgtk-3-0t64`; the `libxdo` capability
  `tray-icon` would otherwise pull in is explicitly disabled, since a `DT_NEEDED` entry on `libxdo.so.3`
  broke the shipped binary on stock Ubuntu.) If the tray icon never appears at runtime, it's almost
  always a missing `libayatana-appindicator3-1`.
- **Windows**: the branded prompt GUI uses `egui`/`eframe`/`winit` (not a webview), and the tray uses
  `tray-icon` + `tao`. Windows Hello confirmation is native FFI in `dig-app-core`; no extra SDK install
  is needed beyond a normal Rust/MSVC toolchain.
- **macOS**: same `egui` GUI stack; Touch ID confirmation is native FFI in `dig-app-core`.

## Build & test

```sh
# build the whole workspace
cargo build --workspace

# run the full test suite
cargo test --workspace
```

Chain-touching logic is tested against an in-memory `MockChainSource` (see `dig-app-core`'s tests) —
no live network is needed to run the suite. `dig-app`/`diga` are thin GUI/CLI shells over
`dig-app-core`, where the identity/wallet/spend logic and its test coverage actually live.

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); run them locally first.

**Format:**

```sh
cargo fmt --all -- --check
```

**Clippy** (all features, including the Linux `tray` GTK stack — install `libgtk-3-dev` first):

```sh
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

**Headless build** — the `--no-default-features` release configuration is a separate required job,
since it isn't covered by the `--all-features` clippy run above:

```sh
cargo clippy --no-default-features --locked --package dig-app --bin dig-app -- -D warnings
cargo test --no-default-features --locked --package dig-app --lib
```

**Tests + coverage** (>=80% lines, gated) — run under `cargo-llvm-cov` + `cargo-nextest`, excluding the
thin `dig-app`/`diga` binary shells from the line-coverage floor (the logic lives in `dig-app-core`):

```sh
cargo llvm-cov nextest --workspace --all-features --locked \
  --ignore-filename-regex '(dig-app[/\\]src[/\\]bin|diga[/\\]src)[/\\]' \
  --fail-under-lines 80 --retries 2

# doctests aren't run by nextest — run them explicitly
cargo test --doc --workspace --all-features
```

**Doc-link hygiene** (gated on the two highest-value stable lints, not blanket `-D warnings`):

```sh
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" \
  cargo doc --no-deps --workspace --all-features
```

**Two Python-based guards** (no Rust build needed) also run in CI and are worth checking locally:

```sh
python3 scripts/check-phase-stamps.py .      # every lifecycle Phase has a non-test production stamp
python3 scripts/check-scratch-paths.py .     # no lane-scratch file (.lane/, LANE-*.md, ...) is tracked
```

**Windows and macOS**: a separate `native-backends` CI job builds, lints, and tests `dig-app-core` (and
on Windows, the `dig-app` shell with the `tray` feature) on both platforms, since the native Windows
Hello / Touch ID confirmers only compile on their own OS. If you touch `src/confirm/windows.rs` or
`src/confirm/macos.rs`, that job is the one that actually exercises your change.

## PR conventions

- **Conventional Commits**, commitlint-enforced (`.github/workflows/commitlint.yml`): `type(scope):
  summary`, where `type` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
  `ci`, `chore`, `revert`. A breaking change appends `!` and/or a `BREAKING CHANGE:` footer.
- **Bump the workspace version** in the root `Cargo.toml` (`[workspace.package].version`) as part of
  every PR — `ensure-version-increment.yml` fails a PR whose version doesn't increase over `main`.
  `fix` → patch, `feat` → minor, a breaking change → major.
- `main` is protected: every required check must be green and every review thread (including any
  GHAS/CodeQL comment) resolved before a squash-merge.
- **Releases are nightly-by-default.** A midnight-UTC cron on `main` cuts the rolling `nightly`
  pre-release automatically. A stable `vX.Y.Z` tag is cut **only** by a manual
  `workflow_dispatch(channel: stable | both)` on `.github/workflows/nightly-release.yml` — the
  scheduled cron run is gated to skip the stable job entirely
  (`github.event_name == 'workflow_dispatch' && (inputs.channel == 'stable' || inputs.channel ==
  'both')`), so merging to `main` never ships a stable release by itself.

## Where things live

| Crate | Responsibility |
|---|---|
| `dig-app-core` | The identity-agent core: key management, DID/profiles, wallet, encrypted per-user AppData, identity-authenticated engine IPC, the CLI/RPC gateway logic, and the native Windows Hello / Touch ID confirmers |
| `dig-app` | The branded per-user tray/menu-bar shell (Windows tray, macOS menu-bar, Linux AppIndicator), fronting the identity-agnostic `dig-node` engine |
| `diga` | The user CLI: the identity front door that routes commands through the `dig-app` gateway |

`dig-app-core` holds the logic and its test coverage; `dig-app`/`diga` are thin GUI/CLI shells over it.
