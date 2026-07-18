# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.13.0] - Unreleased

### Fixed

- **Close the `dign sign` identity-key signing oracle (SIGN-2 audit finding, dig_ecosystem#959).**
  The local `dign sign` gateway path (`gateway/local.rs`) signed the RAW caller message with the
  slot-0x0010 identity key — no domain tag, no confirm — so a caller could obtain a signature
  byte-identical to a confirm-gated `DIGNET-SIGN-v1` spend or a `DIGNET-SESSION-v1` session attach (a
  cross-protocol signing oracle). `dign sign` now (1) signs the domain-separated
  `DIGNET-USER-SIGN-v1 ‖ message` (a third distinct purpose tag, in `session.rs::user_sign_message`),
  never the raw bytes, so its signature can never be replayed in another context; and (2) funnels
  through the terminal `NativeConfirmer` — the same human gate as the §5.3 engine and §5.6 dapp sign
  paths — returning the new `DENIED` error code when not human-approved, so no local process signs
  silently. `LocalIdentity` has no production impl yet, so this was a latent contract bug fixed before
  the real signer is wired. SPEC §3.5 documents the construction.

## [0.10.0] - Unreleased

### Added

- **APP-SIGN loopback transport + pairing + auth foundation (SIGN-1, epic #908, #950).** The
  browser-reachable identity channel dig-app exposes for the extension: a loopback WebSocket server
  binding `[::1]:9779` (IPv6-first) and `127.0.0.1:9779`, guarding every upgrade with the `Host`
  allowlist + pinned-`Origin` check (anti-DNS-rebinding, SPEC §5.6.2); the `pair.begin` handshake that
  mints a 32-byte CSPRNG channel token and seals the pairing record DIGOP1 per-profile (NC-2); and
  per-frame authentication — a constant-time HMAC-SHA256 over the canonical frame bytes plus a
  strictly-monotonic nonce (replay barred; a bad MAC never perturbs the ledger, SPEC §5.6.3). Ships
  the `NativeConfirmer` seam (the sole authorization to pair/connect/sign) with a fail-closed headless
  stub; `connect.request`/`sign.request` are transport-only stubs returning the honest §5.6.7 code —
  the dapp whitelist (SIGN-2) and per-OS native confirm (SIGN-3) build on this foundation. SPEC §5.6.3
  now pins `canonical_json` as a normative byte-for-byte form — object keys sorted by Unicode
  codepoint (not UTF-16 code-unit) order and no floating-point params — so the extension (SIGN-4)
  matches. The in-memory channel secret and its serialized record are zeroized on drop, parity with
  the identity-key at-rest handling.

## [0.9.1] - Unreleased

### Added

- **APP-SIGN paired-loopback signing contract (SPEC §5.6, #950).** New normative SPEC section
  freezing the extension ↔ dig-app paired-loopback identity channel: the WebSocket loopback transport
  (`ws://127.0.0.1:9779`, Host/Origin/token-guarded), the one-time pairing handshake, the dapp
  connect/whitelist protocol, the domain-separated `sign` request/response (reusing `DIGNET-SIGN-v1`),
  the decoded-transaction display requirement, the layered threat model (SPEC §7 addition), and the
  error-code taxonomy. Documentation only — the byte-identical cross-repo contract the per-OS
  confirm lanes and the extension consumer build against.

## [0.9.0] - Unreleased

### Added

- **Structured logging via the shared `dig-logging` building block (APP-5, epic #908, #934).** The
  `dig-app` tray/headless shell and the `dign` CLI now install the same dual-sink subscriber every
  other DIG binary uses (`dig-node`/`dig-dns`/`dig-updater`) — a rolling daily JSONL file in the
  per-OS machine log dir plus compact human text on `stderr`, behind one reloadable `EnvFilter` — so
  a field report finally has a trace of what the identity agent did. `dig-app-core` gained no new
  dependency (it emits through `tracing` only, exactly like `dig-node-core`); the binary shells own
  installing the subscriber.
- **Log-level discipline across the identity-agent core.** Lifecycle events (session attach/detach,
  profile create/select/re-unlock-on-boot, identity seal/unlock, gateway routing) are now `INFO`;
  per-request/per-frame detail (gateway route-classification, RPC dispatch) is `DEBUG`; every
  auth/deny/failure path (a denied `sign` callback, a failed unlock, a duplicate/invalid DID, a
  rejected profile select, a failed engine proxy call) is `WARN`. A never-log regression suite
  (`crates/dig-app-core/tests/never_log.rs`) captures real emitted records and asserts a passphrase
  can never reach a log field, mirroring the dig-node #553 guarantee.

## [0.8.0] - Unreleased

### Added

- **`dign` CLI + gateway routing (U7).** The DIG user CLI is now its own `dign` binary crate
  (migrated from dig-node, SPEC §3.5), a thin IPC client of the running dig-app. The new
  `dig_app_core::gateway` module is the routing core: it classifies every command as served LOCALLY
  with the held user identity (`profiles` / `wallet` / `sign`) or PROXIED to the engine (`info` /
  `config` / `cache` / `stores` / `sync` / `subscriptions` / `peers` / `pair` / `open`), and
  dispatches over three seams — `EngineProxy` (the session-forwarded `control.*` call, byte-faithful
  to the engine control surface), `LocalIdentity` (the local identity ops), and `LinkOpener` (opens a
  validated DIG link; only `chia://` / `urn:dig:chia:` are accepted). Every command offers `--json`
  output + a `--help` discovery surface, and failures carry a stable `ErrorCode` (symbolic name +
  numeric exit code) whose envelope matches the engine CLI. The per-user IPC session client lands
  with U6; until then `dign` reports a catalogued `NOT_CONNECTED`.

## [0.7.0] - Unreleased

### Added

- **Cross-session profile persistence (U6).** A profile's identity is now persisted **sealed at
  rest** (U4 `ProfileVault`: DIGOP1 under the user's root unlock, in per-user AppData — NC-2/NC-3) at
  creation, and a new boot path (`ProfileManager::unlock_all`) re-derives every profile's identity
  from its sealed material once the user unlocks. So a restarted app reopens all of its profiles'
  sealed data — closing the U5 gap where a generated identity lived only in the in-memory session and
  vanished on exit. The new `IdentityStore` collaborator + `VaultFactory` seam bridge the on-disk
  vault to the shared `UnlockedIdentities` session; cross-profile isolation stays cryptographic and
  is proven to hold across a restart + re-unlock. Both the sealed identity blob and the profile
  registry are written through the shared `crate::storage::write_durably` crash-safe helper (F-4).

### Changed / Fixed (U5 triple-gate follow-ups)

- **F-1 — a duplicate DID can no longer clobber an existing profile.** Provisioning is now
  side-effect-free: it returns the generated identity to the manager, which validates + dedup-checks
  the DID BEFORE persisting or unlocking it. A duplicate/invalid DID is a pure no-op (its secret
  material is dropped + zeroized), never overwriting a live profile's in-session identity or sealed
  data. Profile creation is now all-or-nothing (rolls the identity back if a later step fails).
- **F-3 — decrypted profile data is zeroized.** `ProfileSealer::open` returns the plaintext in a
  `Zeroizing` buffer, so a profile's decrypted content is scrubbed from memory on drop rather than
  lingering in freed heap.
- **DidMinter seam wired; on-chain mint held on #771.** The production provisioner composes cleanly
  around the `DidMinter` seam via `HeldDidMinter`, which fails loudly until dig-identity #771 ships
  the mint spend builder — so a released build cannot appear to mint a DID it cannot anchor.

## [0.6.0] - Unreleased

### Added

- **Identity-authenticated engine session (U6, security-critical).** The new `session` module
  implements the app side of the per-user IPC channel to the identity-agnostic engine (`SPEC.md`
  §5.3): the `control.session.begin` → `attach` challenge/response handshake (the app signs a
  domain-separated challenge, `DIGNET-SESSION-v1` ‖ nonce ‖ profile DID, with the in-memory Ed25519
  identity key), `control.session.detach`, and re-attach after a dropped pipe or engine restart. The
  engine→app `sign` callback signs engine-initiated operations — over a domain-separated,
  length-prefixed message (`DIGNET-SIGN-v1` ‖ len16(payload_type) ‖ payload_type ‖ payload), never
  the raw payload, so a signature can never be replayed across purposes — in process behind a
  mandatory `SignPolicy` custody gate, and returns only the signature + public key. The private key
  never crosses the boundary. IPC frames are size-capped and the callback loop is bounded against a
  hostile local engine. Multi-session aware (one session per active profile) via `SessionRegistry`.
  The signing seam (`SessionSigner`) and the newline-delimited JSON-RPC transport (`FrameTransport`
  / `LineTransport`) keep the protocol logic pure and fully unit-tested.

## [0.5.0] - Unreleased

### Added

- **Per-user autostart artifacts (form-factor shell residual, epic #908).** `dig-app`'s
  `autostart` module renders + installs the two residual per-user autostart mechanisms called out
  in SPEC §4: a macOS `launchd` LaunchAgent plist (`~/Library/LaunchAgents`) and a Linux systemd
  **user** unit (`$XDG_CONFIG_HOME/systemd/user`, falling back to `~/.config/systemd/user`).
  Windows autostart remains dig-installer's job (U8); this closes the macOS/Linux residual so the
  shell can start itself at login on every desktop OS the SPEC promises.
- **Profiles (U5, multi-DID).** The `profiles` module implements multi-profile identity management:
  create (provision a `did:chia:` DID + keys, then seal the profile's initial data), select the
  active profile, list profiles, and edit persona metadata. Each profile's secret-bearing state is
  DIGOP1-sealed at rest under its own per-profile DEK in its own AppData directory, so profiles are
  cryptographically isolated (NC-2/NC-3). Profile metadata maps onto the canonical `dig-identity`
  (#771) sparse-merkle-tree of standard slots — the format is consumed, never reinvented.
- **Real U4 sealing wired in.** The production `ProfileSealer` is `KeystoreSealer`: it seals each
  profile's blobs with U4's DIGOP1 under a DEK HKDF-derived from that profile's own identity key, so
  cross-profile isolation holds by the cipher (profile A's blob is undecryptable with profile B's
  DEK). The production `ProfileProvisioner` is `KeygenProvisioner` (U4 key generation + a
  wallet/engine `DidMinter` seam for the on-chain DID mint).
- **Crash-safe registry writes.** The plaintext profile registry — the only pointer to every
  profile's directory — is now written atomically and durably (temp file + fsync + rename), so a
  crash mid-save can never strand a profile's sealed data.
