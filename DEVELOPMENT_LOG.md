
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
