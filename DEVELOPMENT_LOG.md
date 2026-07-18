
## SIGN-1: APP-SIGN loopback transport + pairing (#950)

- **Thin async transport over a sync security core.** The loopback server (`loopback/mod.rs`,
  tokio-tungstenite) only moves bytes + applies the WS-upgrade guard; all security logic — the auth
  gate, the pairing handshake, the error taxonomy — lives in the *synchronous* `loopback/dispatch.rs`
  `FrameRouter` + `pairing.rs`. That split is why the crypto-critical paths are exhaustively unit-tested
  without binding a socket, and the one async round-trip test drives `serve_connection` over an
  in-memory `tokio::io::duplex` (no real port) with a crafted `Host`/`Origin` handshake — non-flaky.
- **Verify MAC before nonce, and never advance the ledger on failure.** `PairingStore::verify_frame`
  checks the HMAC (constant-time `Mac::verify_slice`) *first*, then the monotonic nonce, and mutates
  `last_nonce` ONLY on full success. A forged/replayed frame therefore can neither pass nor perturb the
  counter — a bad-MAC frame at a huge nonce can't poison the ledger and lock out honest frames.
- **`canonical_json` is a cross-repo byte contract.** The per-frame MAC binds `canonical_json(params)`,
  so dig-app and the extension (SIGN-4) MUST derive identical bytes. Pinned in SPEC §5.6.3: keys sorted
  at every level, no whitespace, escaped scalars (so a raw `0x00` never collides with the `0x00` field
  separators in `canonical_frame_bytes`). serde_json's default `Map` is a `BTreeMap` (already sorted),
  but the canonicalizer rebuilds explicitly so it never depends on a `preserve_order` feature flag.
- **The channel token is not sign authority.** The 32-byte CSPRNG token only gates channel access; the
  terminal `NativeConfirmer` (SIGN-3) binds every sign. SIGN-1 ships only the fail-closed
  `HeadlessConfirmer` (returns `Unavailable` → `SIGN_NO_CONFIRMER`), so a headless build never acts.

## APP-6: form-factor shell residual (in progress)

Verifying U3 tray/headless shell + adding the residual per-user autostart artifacts (macOS
LaunchAgent, Linux systemd user unit) called out in SPEC §4. Tracked under epic #908.

## SIGN-3: per-OS native confirmer (#950)

The three OS confirmers reduce to one shared, unit-tested policy (`confirm::gated_consent`): a
`ForegroundWindow` shows the decoded tx, then a `BiometricVerifier` re-authenticates; approve iff
both succeed, everything else fails closed. Each backend only implements those two thin adapters —
so the security logic lives in ONE place and can't drift per platform.

Sharp edges that cost time here:
- **Cross-platform dead-code:** `WindowIntent::{Timeout,Unavailable}` are only CONSTRUCTED by the
  Linux backend (dialog `--timeout`, missing helper); the modal Windows/macOS dialogs never produce
  them, so clippy `-D warnings` flags them dead on those hosts. Fix = `#[allow(dead_code)]` on those
  variants (a legitimately cross-platform enum), not restructuring.
- **Can't cross-`cargo check` the non-host backends from a dev box:** chia's C deps (blst,
  blake2b-rs) need a target C toolchain (`x86_64-linux-gnu-gcc`, apple clang) that a plain
  `rustup target add` doesn't provide. The reliable gate is NATIVE CI runners — the `native-backends`
  job on `windows-latest` + `macos-latest` compiles/lints/tests the per-OS files (ubuntu CI only ever
  builds the Linux `#[cfg]`). Verify objc2/windows API shapes against the crate source in the cargo
  registry cache before pushing a backend you can't compile locally.
- **Biometric ≠ vault passphrase.** The confirm biometric is OS user re-auth (Windows Hello / Touch
  ID / polkit, each with its own password fallback) — user presence + device-owner identity. The DIG
  key unlock is separate (keystore/dispatch). Keeping the confirmer free of key material keeps its
  boundary clean.
