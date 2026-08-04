## #1931 — the identity.* capability class, and the money-derivation drift the dig-account 0.3 bump surfaced

- **DIGCHAT1 is a cross-repo BYTE contract, so pin it against the OTHER implementation, not a round-trip.**
  dig-app's `identity.seal` must emit bytes dig-chat's normative `conformance.ts` emits. A Rust
  round-trip (seal→unseal) proves internal consistency and nothing about parity. The load-bearing test
  runs the TypeScript reference under `@noble/*` on a fixed fixture (all-`0xb0` recipient secret,
  all-`0x0e` ephemeral, all-`0x11` nonce), captures the exact envelope hex, and pins it as a golden
  literal `seal_with` must reproduce. A wrong HKDF salt/info, an endian slip, a different AAD, or an
  X25519 clamp mismatch all move that literal — which is the point. The X25519 basepoint mult and the
  DH agree byte-for-byte between `x25519-dalek` v2 and `@noble/curves` because both are standard RFC 7748.
- **Two authorization axes, kept structurally separate.** `sign.request` (money) stays gated ONLY by
  `PairingScope::may_sign`; `identity.*` is gated ONLY by a per-pairing granted `CapabilitySet`. The
  split lives in one `permits()` match, and the KNOWN-but-ungranted identity method (→ `CAP_NOT_GRANTED`)
  is distinguished from an UNKNOWN method (→ `-32601`) by `Capability::is_identity_method`. The
  load-bearing test grants ONLY `identity.attest`, then asserts `identity.seal` → `CAP_NOT_GRANTED` while
  `identity.teleport` → `-32601`; breaking the capability line fails the former but not an outcome-only
  "returns error" assertion, which is why the two error shapes are asserted separately.
- **`profile_sign` is shared, so an attestation MUST be domain-separated.** The `0x0010` BLS identity key
  signs session-attach challenges and `dign sign` too. `identity.attest` therefore signs
  `DIGATTEST1\0 ‖ sealing_pubkey`, and the test proves the tag is PRESENT by asserting the signature
  verifies over `(DST ‖ pubkey)` and does NOT verify over the bare pubkey — a placement proof, not an
  outcome proof.
- **A two-minor dependency bump propagates a BEHAVIOUR change through the whole foundation.** Adopting
  dig-account 0.3.0 forced dig-session 0.4→0.5 (to unify `UnlockedMasterSeed`/`StaticSecret` to one type
  — two majors of the same crate do NOT unify and the compiler says "multiple different versions of
  crate dig_session"). dig-session 0.5 renamed `SEED_LEN`→`ENTROPY_LEN` (same value, 32) and, with
  dig-account 0.3's #1759, switched the money key derivation to the STANDARD BIP-39-expanded 64-byte
  master seed (Sage-compatible). Consequence: any TEST that derives a wallet key/address from the raw
  32-byte entropy is now the STALE side — three money-path tests fail (a changed golden address; a spend
  whose locally-derived change output no longer returns to the wallet → the exfiltration guard fires).
  The production wiring is unaffected (dig-app injects dig-account's signer); only test REFERENCE
  derivations + two frozen golden constants drifted. This is money-path work, kept out of the identity
  unit deliberately.

## #1773 — presentation is a contract, and only a live window proves it

- **A working code path can still be the wrong UI, and no unit test could have said so.** Every dig-app
  confirm window was drawn `MB_OKCANCEL | MB_ICONWARNING` on Windows, so all eleven informational tray
  messages arrived as a warning triangle with a Cancel that no caller reads. Every path involved was
  correct; the defect was the presentation, and it was found by looking at a screenshot. The lesson is
  where the classification lives: `Presentation` is now part of `ConfirmContent`, decided once where the
  content is composed and unit-tested, so a per-OS backend cannot style a notice as an alarm.
- **Classify per call site — a blanket conversion destroys a real decision.** The two enrolment retention
  screens look like notices and are not: refusing either abandons setup. They needed a THIRD seam
  (`confirm_claim`: two choices, no biometric, fail-closed by default) rather than being swept into either
  existing one. A mutation that flattened every window to one button was caught by three tests; a mutation
  that routed the retention screens back through `show_notice` was caught by exactly ONE, because the
  returned `RetentionDecision` is identical either way — only the SEAM changes. Assert the seam.
- **Probing the live Win32 dialog is cheap, scriptable, and better evidence than a screenshot.**
  `EnumWindows` for class `#32770` owned by the process, then `EnumChildWindows` for `Button` children:
  their COUNT and `GetDlgCtrlID` answer "one button or two" exactly, and the `Static` child's text is the
  full body. `PrintWindow` renders the window to a bitmap even when the desktop is LOCKED, where
  `CopyFromScreen` captures only wallpaper — which is what a headless-ish agent session usually has. Note
  `$pid` is read-only in PowerShell, so the out-param needs another name.
- **A dismissed `MB_OK` notice returns `IDOK`,** so `show_notice` still reports `Approve` and callers keep
  distinguishing "the user saw it" from "no window could be drawn". Verified by `BM_CLICK` on the live
  button and reading the process's stdout, not from the docs.
- **A carefully-written message that cannot print is worse than none.** The DID explainer became
  unreachable the moment its row was correctly disabled. The fix was not to re-enable a control that
  cannot act but to change what the row PROMISES — an explanation, which it can always deliver — and to
  delete the minting action outright so its absence is structural.

## #1752 — the recovery phrase, and what a tray can and cannot do

- **`dig_session::SEED_LEN` is 32, and a 24-word BIP-39 phrase carries exactly 32 bytes of entropy — so
  the entropy IS the master seed.** That identity is what makes the phrase to seed mapping a lossless
  bijection and lets a restore reach the same identity with zero stored state. **But it is NOT the Chia
  derivation**: Chia wallets go phrase → 64-byte PBKDF2 seed → `SecretKey::from_seed`, so the SAME phrase
  gives a DIFFERENT address in Sage than in DIG. Making them agree means widening `SEED_LEN` to 64 in
  `dig-session` (a `10-primitives` crate), cascading through `dig-account` and `dig-wallet-backend`, and
  breaking at-rest compatibility for every enrolled account. Do not "fix" this casually.
- **`dig-account` deliberately never returns the master seed.** `UnlockedAccount` hands out capability
  handles only, and `AccountStore`'s blob-key prefix (`"account."`) is a private const. So dig-app cannot
  re-derive an enrolled account's words, and re-implementing the prefix app-side would be a copied
  canonical value waiting to drift. The app therefore keeps its own copy of the phrase, sealed under the
  ROOT profile's DEK, which adds no new exposure class (the phrase and the seed are one secret in two
  encodings, under one unlock). The cleaner answer — a `recovery_seed()` accessor on `UnlockedAccount` —
  is a release-first `dig-account` change, and would additionally let a LEGACY (phrase-less) account be
  rendered as words without destroying it.
- **The unlock password is machine-generated and lives in the OS credential store.** So the sealed blob is
  openable on exactly one machine, and the phrase is not a convenience — it is the ONLY thing that
  survives losing the machine. This is why a phrase-less account is genuinely unrecoverable and must be
  labelled that way rather than treated as merely "older".
- **A tray menu has no text field.** The OS gives a tray only menu items and message boxes, so 24 words of
  typed input cannot be taken there. Restore therefore lives in `dign account restore` (echo suppressed)
  and the tray hands over the exact command instead of offering a dead end.
- **A unit test on the CONTENT passed while the RENDERER was untouched.** The notice window's two-button
  sentence was fixed in `ConfirmContent`, its test went green — and the live Windows window still said
  *"Choose OK to I have written these down, or Cancel to reject."*, because the `windows.rs` patch had
  silently failed to apply and nothing tested the composition. Reading the real window out of the running
  process is what caught it: `Get-Process <name> | Select MainWindowTitle` gives the title, and
  `System.Windows.Automation` (UIAutomationClient) walks the descendants and dumps the full body text of a
  live modal. That is a genuine machine check for a native window, and on a session with no visible
  desktop it works where a screen capture returns black.
- **A `MessageBoxW` cannot relabel its buttons**, so it must spell the choice out in the body — and one
  template cannot serve both an authorization ("Choose OK to Sign") and an acknowledgement, whose button
  label is a first-person claim. macOS/Linux put the label on the button and need no such sentence.

## #1548 — live money path: authorize-before-sign + #908 on-wire enforcement (slice C)

- **authorize()==Ok is necessary but NOT sufficient — the confirm ceremony is a SECOND, independent
  gate.** The money path (`account::money::MoneyPath`) runs summarize → `SpendAuthorizer::authorize`
  → (for every tier above `AutoSend`) `AuthProvider::confirm_spend` → sign, in that fixed order. A
  `RequireAuth`-class spend (Vault, or over-allowance Confirm) that the authorizer ALLOWS but the
  confirm ceremony DECLINES/skips is refused, and the money signer is never even built (the #1522
  gate note). Only a within-allowance `AutoSend` may skip the ceremony.
- **Re-read the residency at SIGN time, not once up front.** The signer is drawn from the shared
  `AccountResidency` AFTER the (async) confirm ceremony returns, so a lock landing DURING the confirm
  dialog fails the sign closed — no snapshot escape. The residency is the SAME lockable seed home the
  identity signer reads, so one `lock_all()` relocks BOTH money and identity signing.
- **The #908 on-wire test is only possible because the money key derivation is byte-contracted.**
  dig-app's `wallet::signing::WalletKey::from_seed(seed)` reproduces dig-account's canonical money key
  at `ProfileIx::ROOT` (`master_to_wallet_unhardened(seed,0).derive_synthetic()`), proven in
  `wallet_key_byte_contract.rs`. That lets the test derive the money secret + DEK INDEPENDENTLY from a
  known seed and assert they never appear (raw or hex) in the serialized `control.wallet.*` wire bytes,
  while the signed bundle does. Model-A's whole point: only signed bytes cross the dig-app→dig-node IPC.
- **The money signer refuses an unhinted non-change output (exfiltration guard).** A real test send
  must HINT the recipient coin (`ctx.hint`) and return change to the wallet's own puzzle hash; a bare
  `create_coin(recipient, amount, Memos::None)` reads as a possible drain and dig-account fails it
  closed with `SpendValidationFailed: a non-recipient output does not return to this wallet`.

## #1547 — master-HD custody switchover: the DEK migration decision (CLEAN CUTOVER)

- **The two custody roots are not reconcilable, so migration is a clean cutover.** The retired model
  sealed each profile under a DEK derived from an INDEPENDENTLY-RANDOM per-profile BLS identity scalar
  (`keystore/secrets.rs`: `version(0x02) || scalar`, HKDF-SHA256(DEK_SALT, IDENTITY_IKM_VERSION||scalar,
  PROFILE_DEK_LABEL)). The master-HD model (`dig-account`) derives every profile's scalar FROM one
  account master seed at a profile index. A byte-identical DEK across the two is therefore
  **cryptographically impossible** — no master seed can be found that derives a pre-existing random
  scalar — so a "re-enrol the scalar onto a seed index" migration cannot preserve the at-rest DEK; it
  would require reading old data with the old scalar and RE-SEALING under the new seed-derived DEK (a
  data migration, not byte-identical). dig-app is PRE-RELEASE (NullConnector stub engine, U-milestone
  WIP, §3.7 no production users), so the decision is a clean cutover: old per-profile-scalar identities
  are abandoned, a fresh master-seed account is enrolled on first boot. The sealing CONTAINER (DIGOP1)
  and the DEK derivation CONTRACT (HKDF + the `dig-constants` salt/version/label/len) are PRESERVED —
  only the seed SOURCE changed — so this is a root swap, not a format break.
- **Live-view capabilities beat snapshot capabilities for lockability.** `dig_account::UnlockedAccount::signer`
  returns a `ProfileSigner` that captures its OWN `Arc<seed>`; injecting that snapshot would make a tray
  lock cosmetic (the running signer keeps its seed). dig-account itself DEFERS wiring idle-relock onto
  the capability lifecycle (its `unlocked` docs / SPEC §4.1). The harness closes the gap with
  `AccountResidency`: it owns the sole `UnlockedAccount` behind a shared lock and hands out live-view
  signer + sealer that re-read the account per operation and fail closed once locked — so `lock_all()`
  relocks the running paths without depending on the deferred crate feature.
- **Zero-prompt unlock = OS-credential-store password + file-backed sealed seed.** The
  `CredentialCeremony` generates + persists a 256-bit account password in the OS credential store on
  first run and fetches it thereafter, so dig-account unlocks the master seed with no prompt on
  Windows/macOS. This SPLITS the password (credential store) from the ciphertext (file backend) — a
  strict improvement over the retired vault that co-located both in one entry.


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

## APP-SIGN tray-wiring — going live + cross-restart replay (SIGN, #958/#956)

Turning the SIGN-1/2/3 seams into a running server is `sign_service::build_router` + `serve_blocking`
(assemble over the active profile → restore sealed state → serve), called from the tray shell's
`start_sign_service`. The shell gate is fail-closed: it starts ONLY on a desktop session (Tray form
factor) with an unlocked active profile. Zero-prompt unlock is Windows/macOS-only (OS credential
store `RootUnlock::OsKeychain`); Linux needs a passphrase UX not yet wired, so the channel defers
there rather than start keyless.

Sharp edges that cost time here:
- **The router used to DISCARD `sealed_record`.** `PairingStore::pair`/`WhitelistStore::grant` compute
  the sealed bytes, but `FrameRouter` dropped them — nothing survived a restart. The fix is a
  `SealedRecordStore` seam (default `NullSealedStore`, production `FileSealedStore`) the router persists
  through on grant/revoke, plus `FrameRouter::restore()` on boot. Added via a `with_persistence(...)`
  builder so the SIGN-1/2 unit tests (which construct the router without persistence) keep compiling.
- **Cross-restart replay (#956) — PARTIAL: normal-restart replay is closed; the rollback/swap variants
  are not.** `restore_sealed` re-inserts a pairing with `last_nonce: None`, so a captured pre-restart
  frame would replay. The nonce is a monotonic COUNTER (not key material), so it persists in a small
  PLAINTEXT `nonces.json` written on each accepted frame — cheap, unlike a per-frame Argon2 re-seal — and
  the router re-seeds it on boot via `PairingStore::seed_last_nonce` (only ever RAISES the mark). Two
  load-bearing subtleties: (a) **fail-closed** — a restored pairing with NO persisted mark is DROPPED
  (require re-pair), never restored with an empty ledger that accepts any nonce (that empty-ledger case
  fully reopens the window). (b) **`nonces.json` is UNauthenticated** — nothing MACs or seals it (do NOT
  claim MAC coverage). A same-user attacker with AppData write can reset/roll-back/swap it, reopening a
  channel-layer replay window; that residual is backstopped ONLY by the native-confirm re-gate (every
  replayed sign still needs a fresh biometric). Folding the mark INTO the sealed, MAC'd pairing record is
  the robust closure and stays open as #956's remaining work.
- **Locked-profile sign must be a `LOCKED` error, not an ok zero-sig.** `ProfileSessionSigner::sign` is
  infallible (returns an all-zero non-verifying signature when locked), so `handle_sign` must NOT frame
  its output blindly — it uses the fallible `SessionSigner::try_sign` and emits `SignErrorCode::Locked`
  on `None`, never a success envelope carrying zeros.
- **Custody-preserving signer.** The loopback signs with the active profile's `0x0010` key via
  `ProfileSessionSigner`, which delegates to `UnlockedIdentities::sign(did, msg)` — the key never leaves
  the session. A locked profile yields an all-zero (non-verifying) signature, never a forgery.
- **Windows MAX_PATH:** building under the deep agent-worktree path trips libz-sys's CMake (260-char
  limit). Build with a short `CARGO_TARGET_DIR` (e.g. `C:\dt`).

## #1530/#1549 custody switchover — old-path retirement (zero residue), the FINAL slice

- **The live custody root is `account::residency::AccountResidency` (master-HD), full stop.** After the
  #1530 switchover the retired per-profile-identity path is GONE: `profiles/` (UnlockedIdentities,
  ProfileSessionSigner, KeystoreSealer, ProfileManager, IdentityStore, DidMinter, …), `keystore/{secrets,
  vault}` (IdentitySecrets, ProfileVault), `wallet/{signing,spend}` (WalletKey + local spend builders),
  and `onboarding` were deleted. What survived was RELOCATED, not kept in place: the sealing seam
  `ProfileSealer`/`SealError` -> top-level `crate::sealer`; `did_hash` -> `crate::storage`; `ProfileRef`
  -> `crate::agent`. `keystore` was trimmed to ONLY the OS credential-store seam
  (CredentialStore/OsCredentialStore/KeystoreError) — the zero-prompt password source the account boot
  reads; everything crypto now lives in `dig-account`.
- **Isolation moved from the DID string to the DEK (per ProfileIx).** The old `KeystoreSealer` derived a
  DEK per-DID from an in-memory identity; the new `AccountSealer` is bound to ONE profile DEK
  (`profile_dek(seed, ix)`) at construction — the `profile_did` argument is advisory. So cross-profile
  isolation tests now use DISTINCT DEKs (distinct labels / profile indices), NOT distinct DID strings.
  A shared `#[cfg(test)] test_support` module gives every test one way to build the two seams
  (`test_sealer(label)` = a per-label-DEK AccountSealer; `test_residency()` = an enrolled unlocked
  residency whose `.signer(ROOT)` is the live-view SessionSigner). Same label -> same DEK (a "restart"
  re-opens a sealed blob); different label -> AEAD-rejected (isolation).
- **`dig_account::WalletKey` is the public test builder for spends.** The deleted dig-app `WalletKey` was
  byte-identical to `dig_account::WalletKey` (from_seed/public_key/puzzle_hash/address); tests that build
  a real coin spend for the residency's money signer now use `dig_account::WalletKey` directly (takes
  `&[u8]`, not `[u8;32]`). The obsolete dig-app-WalletKey byte-contract integration test was dropped —
  the golden now lives inside dig-account.
- **Money-send has NO live surface yet.** MoneyPath is fully constructed over AccountResidency at library
  level, but nothing invokes `authorize_and_sign` on the live path: the tray menu is lock/quit only, and
  the loopback APP-SIGN `payload_type="spend"` returns an identity ATTESTATION signature over the
  DIGNET-SIGN-v1 callback message (NOT a `sign_coin_spends` aggregate SpendBundle). Routing loopback-spend
  through MoneyPath would change that wire semantics — a cross-repo (ext/dig-node) contract change — so it
  is a deliberate SHAPE decision left for a decider, not built speculatively (§1.10).

## dig-app ⇄ dig-node: the transport in the SPEC was not the transport that exists (#949, 3.0.0)

- **dig-node has no named pipe and no Unix domain socket.** `SPEC.md` §5.1, `crate::ipc`, and ticket
  #949 all described the app↔engine channel as a per-user OS pipe (`\.\pipe\dignetwork-<USER>`) /
  UDS (`<RUNTIME_DIR>/dignetwork.sock`), with the engine half deferred to "U6". Verified against
  dig-node v0.64.0 `origin/main`: `git grep -iE 'NamedPipe|UnixListener|dignetwork\.sock'` across the
  whole repo matches only unrelated *service-name* strings. That listener was never built, so
  `NullConnector` was not a temporary stub over an almost-ready seam — it stood in front of a
  transport with no other end.
- **What dig-node actually answers** (`dig-node-service/src/server.rs::serve_with_shutdown`): JSON-RPC
  2.0 over loopback HTTP, `POST /`, gated by an `X-Dig-Control-Token` header. Up to three listeners
  for the ONE surface: `127.0.0.1:9778` (always on, fatal if it cannot bind), `[::1]:9778`
  (best-effort IPv6 twin), and `127.0.0.2:80` for bare `http://dig.local` (best-effort).
- **`dig.local` is on port 80, NOT `DIG_NODE_PORT`.** `dig_constants::DIG_LOCAL_HOST`'s own doc says a
  client "tries `dig.local` (on `DIG_NODE_PORT`)", but the node binds `127.0.0.2:80` for that name and
  nothing on `127.0.0.2:9778`. A client that appends the high port to `dig.local` silently loses the
  whole first §5.3 tier. Default the port from the URL SCHEME, never from the node's high port.
- **`rpc.dig.net` is not a control tier.** §5.3's fourth tier is a *content-read* fallback: the public
  gateway dispatches no `control.*` and could not hold this machine's local control token, so probing
  it for node status can only mislead. The control ladder ends at `localhost`.
- **A node that REFUSES is a different fault from no node.** The remedies diverge completely (a
  token/permission fault on a running node vs nothing installed or running), so the disconnected
  reason distinguishes them and names the control token when that is the cause. Collapsing both into
  "not connected" sends a person hunting the wrong thing.
- **`dig-node-control-interface` mirrors the node faithfully but nothing enforces it.** Its
  `results::StatusResult` is field-for-field what `control.rs::status` emits (checked by hand). Yet
  dig-node does NOT depend on the crate — `git grep dig-node-control-interface` in dig-node returns
  nothing — so the "cannot drift" property the crate claims is currently one-sided: only clients read
  it. It also does not carry the `X-Dig-Control-Token` header name (it is transport-agnostic), so each
  client re-declares that constant.
- **A test double parked in a blocking `accept` HANGS the suite when nobody dials it.** Found while
  proving a ladder test load-bearing: reverting the fall-through made the test hang, not fail — which
  reports nothing and would stall CI. A one-shot fake server MUST unblock its own `accept` on drop.
- **A machine with a real dig-node installed breaks env-based fixtures.** Tests that pointed
  `DIG_NODE_STATE_DIR` at a temp dir still found the REAL `C:\ProgramData\DigNode\control-token`
  through the later default candidates, so "no token here" assertions passed a real token. Make the
  lookup take an explicit candidate list and assert on that, rather than mutating global env and
  hoping the machine is clean.

## The Linux tray does not fade — it PANICS (dig_ecosystem#1756, measured 2026-07-28)

Measured against pristine `ubuntu:24.04` in a container, with a release `dig-app` built inside it.

- **The dlopened indicator library panics; it does not return an error.** With GTK installed and
  `libayatana-appindicator3-1` absent, `libappindicator-sys-0.9.0/src/lib.rs:41` panics
  (*"Failed to load ayatana-appindicator3 or appindicator3 dynamic library"*) and the process DIES. The
  long-standing assumption — recorded in `SPEC.md` and in the shell's own comments — was that a missing
  indicator yields a *running* process with no icon. It does not. A panic unwinds past the `Result` the
  whole degrade path is written around, so `tray_unavailable_advice` and its two unit tests were dead
  code on the one platform they were written for: green tests, perfect message, unreachable. Mounting is
  now wrapped in `catch_unwind` (`dig_app::tray_render::mount_or_degrade`).
- **`ldd` names ALL missing link-time libraries; the loader names only the FIRST.** The `tray` build
  needs **seven**: `libgtk-3.so.0`, `libgdk-3.so.0`, `libgdk_pixbuf-2.0.so.0`, `libcairo.so.2`,
  `libglib-2.0.so.0`, `libgobject-2.0.so.0`, `libgio-2.0.so.0`. Running the binary reports only
  `libgdk-3.so.0`, so fixing them one at a time looks like a fresh regression on every attempt — the
  same trap the earlier libxdo hunt fell into. Four packages cover all seven: `libgtk-3-0t64`,
  `libgdk-pixbuf-2.0-0`, `libcairo2`, `libglib2.0-0t64` (verified: installing them leaves `ldd` clean).
  Note the Ubuntu 24.04 `t64` suffixes — `libgtk-3-0` and `libglib2.0-0` are the wrong names there.
- **A dlopened dependency is invisible to `ldd`.** The indicator library never appears in `ldd` output or
  `DT_NEEDED`, so a dependency audit based on `ldd` alone will always miss it. It has to be listed by
  hand, alongside the runtime *executables* the tray shells out to (`xclip` for the clipboard,
  `xdg-open` for the log folder).
- **Reproducing this needs a DISPLAY, not just a container.** Without one, `FormFactor::detect` returns
  `Headless` and the tray is never attempted, so the bug hides. `Xvfb :99` + `DISPLAY=:99` is what makes
  it appear.

## The global shortcut (dig_ecosystem#1839)

- **`Alt+Space` is not free on Windows — it opens the focused window's system menu** (Move / Size /
  Minimize / Close), and has since Windows 3.x. A successful `RegisterHotKey(NULL, id, MOD_ALT, VK_SPACE)`
  takes precedence and suppresses that menu **globally**, for every application, for the app's whole
  lifetime. Claiming it is a real trade, taken with precedent (PowerToys Run ships the same default) and
  disclosed in `Status` — not a free win.
- **`MOD_NOREPEAT` is not optional.** Without it, holding the chord down delivers `WM_HOTKEY` at the
  keyboard auto-repeat rate, which opens one bar per tick.
- **`WM_HOTKEY` from `RegisterHotKey(NULL, …)` is a THREAD message with no window**, posted to the queue
  of the thread that registered it. It cannot reach a window procedure, so a shortcut cannot be handled by
  adding a case to an existing `wnd_proc`, and depending on tao to surface it would be depending on tao
  forwarding a message it has no reason to. A dedicated thread with its own `GetMessageW` loop is the
  shape. Windows releases a thread's hotkeys when the thread ends, so process exit frees the chord.
- **`WS_CAPTION` is `WS_BORDER | WS_DLGFRAME`, so `style & WS_CAPTION != 0` does NOT mean "has a caption".**
  A frameless window that deliberately keeps `WS_BORDER` for its edge trips that test. The assertion has to
  be against the FULL mask. This cost a red test on the first run and would otherwise have been a screenshot
  bug.
- **A locked desktop makes `SendInput` succeed and deliver nothing.** The call returns the full event count
  — it queued them — but a locked session's input goes to the Winlogon desktop, so a global-hotkey test
  synthesizing its own keystroke times out looking exactly like a broken shortcut. Rule out the lock before
  believing that failure.

## The wallet's receive address and balance (dig_ecosystem#1850)

- **dig-app has NO chain source for a balance today, and the reason is one level down.**
  `dig-node-control-interface` 0.2.0's method catalog carries no `control.wallet.*` entry, and the
  `WalletEngine` seam has no production implementation — so a node can be running, reachable and healthy
  and still be unable to answer "what do I hold?". That is why the wallet window distinguishes *no node*
  from *a node that does not serve wallet reads*: the two look identical from the app and call for
  completely different things from the user. Adding a balance read means adding the method to the node's
  published contract first (release-first), not reaching for a chain from the app.
- **An address that is merely `xch1`-shaped proves nothing.** Every wrong derivation — the wrong profile
  index, a dropped `.derive_synthetic()`, a seed one bit out — produces a perfectly well-formed address
  that receives nothing recoverable. The check that has teeth is a SECOND derivation, in-test, from
  `chia-bls` + `chia-puzzle-types` + a locally-written bech32m encoder, plus a frozen literal. The encoder
  is worth writing by hand: it makes the bech32m half independent of the `chia-wallet-sdk` `Address` type
  that produced the value under test.
- **Bech32 vs bech32m is a checksum constant, and both encode the same payload.** The two differ only in
  the final XOR (`1` vs `0x2bc830a3`), so a wrong-variant address has an identical body and six different
  trailing characters — invisible by eye. When reproducing an address vector out of tree, check the
  constant before concluding the derivation drifted.
- **A `PrintWindow` capture of a Win32 dialog can silently drop later-drawn text.** Photographing the
  wallet window with `PrintWindow(hwnd, dc, PW_RENDERFULLCONTENT)` showed the first two paragraphs and an
  empty slab where the rest belonged — indistinguishable from the body-clipping bug #49 fixed. A
  DPI-aware `CopyFromScreen` over the same window rect showed the whole thing. Make the capturing process
  DPI-aware (`SetProcessDpiAwarenessContext(-4)`) or its screen coordinates are scaled and it photographs
  the wrong rectangle.

## The tray Wallet submenu, and "one variant per REMEDY" (dig_ecosystem#1841)

- **A reason enum must be keyed on the REMEDY, not on the situation.** `AddressUnavailable` had three
  variants for six account states, so `Unsupported`, `NeedsPassword` and `Unopenable` all fell through to
  `Locked` and every one of them read *"Unlock it and it appears here"* — advice a host with no credential
  store cannot follow, that names a password the user has never chosen, and that for an unopenable account
  points at the very operation that already failed. The collapse survived because each state's text was
  *plausible*; what exposed it was writing the state→clause table as a test and finding two rows that had
  to differ. When a "why not" enum has fewer variants than the states feeding it, the shortfall is
  where the wrong advice lives.
- **The no-numeral rule needs re-proving at every layer that renders.** `balance_line` (the window) had
  it; the new menu row needed it again, because rendering is where an `Unknown` becomes a `0`. The menu
  label deliberately does NOT reuse the window's sentences or interpolate a `ReadFailed` detail: that
  string is unbounded, comes from outside the crate, and can itself contain digits — three ways for a
  menu row to lie or blow out. The test that has teeth feeds a `ReadFailed("HTTP 503 after 30s")` and
  asserts the label contains no ASCII digit at all.
- **Native menus cannot be built in-process on this stack, so `examples/tray_gallery.rs` IS the
  screenshot.** It rendered only five of the six account states — missing exactly `NeedsPassword` and
  `Unopenable`, the two whose remedy differs from `Locked`, which is why the wrong wording above went
  unseen for so long. A gallery that omits a state is not evidence about that state; keep it exhaustive
  over the enum rather than over the states someone happened to think of.
- **The repo's gated `cargo doc` can fail locally while CI is green.** CI uses
  `dtolnay/rust-toolchain@stable` (unpinned) with `RUSTDOCFLAGS=-D warnings`; rustc 1.96.1 fires
  `redundant_explicit_links` on two `account/boot.rs` links that are on `main`, so
  `cargo doc --no-deps --workspace --all-features` fails on a newer local toolchain and passes on CI's
  older one. A local rustdoc failure in files your branch never touched is this, not your change —
  check `git show origin/main:<file>` before chasing it. Tracked as dig_ecosystem#2056.

## A `STATIC` clips a run it cannot wrap, and text can arrive with holes in it (dig_ecosystem#1849)

Two distinct silent-text failures, both invisible to `contains(...)` assertions and both found only in a
photograph. They are worth writing down together because they look identical on screen — a sentence that
is wrong in a way no test noticed.

**1. A `STATIC` wraps at SPACES, and clips what it cannot wrap.** Give it a 130-character `otpauth://`
URI and there is no wrap opportunity, so it draws one line and silently discards the rest — no error, no
ellipsis, no return value. This is the same family as the recovery-phrase window that showed ten of
twenty-four words (#49), and it is the reason `provisioning_uri` was DELETED rather than drawn in #1840.
The height estimate cannot save it: the estimate divides a character count by a line width and correctly
concludes the text needs three lines; the control simply refuses to use them.

The fix is `break_long_runs` in `confirm::windows_input` — insert breaks inside any whitespace-free run
longer than a line, leaving prose alone. The sharp edge is that fixing it is only HALF a fix: measuring
the broken text while drawing the raw text reproduces the clip exactly, and no assertion about heights
can see the difference. So the `Layout` now carries the body's TEXT as well as its height, and the
drawing code takes both from there — the pair is unrepresentable apart, which is the same reasoning that
already put the control positions and the total height on one struct.

**2. A string literal can acquire a run of spaces mid-sentence.** Rust's `\`-at-end-of-line continuation
strips the following indentation, so a hand-written literal is fine — but a literal written by ANY tool
that treats the backslash as its own line continuation (a Python heredoc doing string surgery on a source
file, for one) keeps the indentation, and ships `"Or add it by hand —          choose to add…"`. Every
substring assertion still matches. This has now happened three times in `dig-app-core`; the destroy
window's copy uses `concat!` for exactly this reason.

`no_screens_copy_carries_a_hole_mid_sentence` is the cheap guard: walk everything a journey showed, skip
the deliberately column-aligned code blocks (identified by carrying no lower-case letters), and refuse
any prose line containing three consecutive spaces. Worse than prose is a URI: the same mangling turned
a demo `otpauth://` string into one with spaces in it, which still encoded into a square that LOOKS
exactly like a QR code and that no authenticator can parse.

**How a QR is actually verified.** Not by looking at it. Render the window, screenshot the REAL pixels
(the capturing process must be per-monitor DPI-aware, or Windows virtualises 3840x2400 down to 1536x960
and the modules blur into each other — you then measure your screenshotter, not your window), and decode
with an implementation that is not the encoder. Degrading the capture first — perspective warp, downscale,
Gaussian blur, lossy JPEG — approximates the camera path, which is the one that matters: a QR that
decodes from a pristine bitmap and not from a photograph is the exact failure worth catching.

## A GDI screen capture is BLIND to a hardware GL surface (dig_ecosystem#2038)

`Graphics.CopyFromScreen` / `BitBlt` of the screen DC returns whatever is UNDERNEATH a window whose
client area is a composited GL surface. A perfectly-painted egui window photographs as the desktop
behind it. `PrintWindow`, `PW_RENDERFULLCONTENT` and `CAPTUREBLT` do not help.

This cost the #2038 port its entire verification phase — the window was read as "opens but never
paints" for a long time. **Every direct health probe said the window was fine** the whole time:
`IsWindowVisible` true, `IsIconic` false, DWM `CLOAKED` 0, not layered, correct physical rect,
`WindowFromPoint` at its centre returning its own handle, `IsHungAppWindow` false, ~17 fps.

The control that settles it in ten minutes: draw a TRIVIAL window — solid colour, one label — and
photograph it the same way. It photographs identically blank, which indicts the capture, not the
renderer.

Two bisections along the way were also artefacts of the capture: `with_decorations(false)` and
`with_transparent(true)` appear to change the outcome, but only because they change what NON-GL chrome
the capture can see. And a DPI-UNAWARE probe reports a 2.5×-scaled 1550×1400 window as 620×560, which
reads as "wrong size" stacked on top of "blank" — set `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)`
in any probe.

**Read the framebuffer instead:** `egui::ViewportCommand::Screenshot` for the real on-screen window,
and for CI a headless pass over the renderer's own output with no window at all. Same lesson as the QR
entry above — screenshot the REAL pixels, or you are measuring your screenshotter.

## Deleting a run of tests can silently disable the NEXT one (dig_ecosystem#2038)

Removing several `#[test]` blocks from one module took the `#[test]` attribute belonging to the test
that FOLLOWED each deleted block, three times over. The functions survived, still full of assertions,
and simply stopped running. One of them pinned polkit's exit code to an outcome including both
fail-closed arms — the Linux half of the authorization gate. It read like a live guard on the spend
path and was inert.

**Nothing in the normal toolchain flags this.** A `#[test]`-less private fn inside a `#[cfg(test)]`
module is just an unused fn. It surfaces only as `dead_code`, and only on a host that compiles the
file at all — this one was `cfg(target_os = "linux")`, so no Windows or macOS build ever saw it. It
finally appeared as four lines inside an already-red CI job.

**When deleting a run of tests, diff the `#[test]` COUNT before and after.** `grep -c '#\[test\]'` is
the whole check. A passing suite proves nothing here: the suite got SMALLER and stayed green, which is
exactly what a deletion is supposed to look like.

## `winit` on Windows does not destroy a window in `Drop` — it posts a message (dig_ecosystem#2038)

`winit::window::Window::drop` on Windows does NOT call `DestroyWindow`. A window may only be destroyed
by the thread that created it, so Drop does `PostMessageW(hwnd, "Winit::DestroyMsg")` and leaves the
real destruction to the window procedure (winit 0.30 `windows/window.rs:1113`, handled at
`windows/event_loop.rs:2445`). **The destruction therefore needs the event loop to still be pumping.**

eframe's `run_and_return` path drops the window AFTER `run_app_on_demand` has already returned. In a
normal eframe app the process exits next and nobody notices. In a long-lived app that opens windows on
a worker thread and then goes back to `rx.recv()`, nothing on that thread ever dispatches the posted
message: **the window stays on screen, always on top, with a dead message pump — which is exactly what
Windows renders as "not responding".** The app has already moved on; the frozen window is all the user
can see.

The tell is that only the LAST window sticks. Each new `run_native` pumps the queue and disposes of the
PREVIOUS window's deferred destroy, so a sequence of prompts looks fine right up until the final one.
The fix is one call: drain the thread's message queue after `run_native` returns.

Diagnosing it: `Get-Process.Responding` is measured on `MainWindowHandle`, so it reports on whichever
thread owns the frontmost window, not on the app. Windows' Wait Chain Traversal API
(`OpenThreadWaitChainSession`/`GetThreadWaitChain`) returned a bare blocked node with no chain, which
correctly RULED OUT a `SendMessage`/critical-section deadlock and pointed away from an hour of
cross-thread theories. What actually settled it was `eprintln!` tracing through `draw`/`serve`: the
trace showed `run_native returned` and the answer delivered while `EnumWindows` still listed the
window as visible.

## `ViewportCommand::Close` comes BACK as an input event, one frame later (dig_ecosystem#2038)

`ctx.send_viewport_cmd(ViewportCommand::Close)` does not close anything by itself. egui-winit turns it
into a `ViewportEvent::Close` (`egui-winit` `lib.rs:1352`) that arrives in the NEXT frame's raw input,
which is what eframe reads to decide to exit (`epi_integration.rs:270`). So the window keeps running
frames after you ask it to close, and **any handler that treats `close_requested()` as "the user
dismissed me" fires on your own close command.**

In the prompt window that meant a click on Sign recorded `Approve` and then had it overwritten with
`Deny` one frame later, by the window's own teardown. Every affirmative in the app answered Deny, and
786 tests at 93.85% coverage all passed, because the suite drove the pure `Screen` model and read
glyphs back — never the frame that carries the close event.

**Latch the first answer.** Whatever else a teardown frame does, it must not be able to change what the
human said. And when testing a window, synthesise that close frame explicitly: it is a real frame the
real loop runs, and it is where this class of bug lives.

## A scrollbar is not automatically an affordance (dig_ecosystem#2038)

Wrapping the clipped body in an `egui::ScrollArea` made the hidden two-thirds of a 24-word recovery
phrase *reachable* and the regression test *pass* — and the reshot gallery still showed a window that
stops at word 14 beside a 2 px grey hairline. A person transcribing a phrase onto paper writes down
what they can see and clicks the affirmative. **Reachable is the test's bar; visible is the user's.**

Two changes, not one: let the window GROW to what its content needs (bounded by `MAX_HEIGHT` and 90%
of `ViewportInfo::monitor_size`, falling back to the creation height when no monitor is reported, which
is also what keeps the headless overflow tests meaningful), and make the bar solid and wide for the
displays where growing is not enough. Look at the picture after the test goes green.

## `winit` allows ONE event loop per PROCESS, so the prompt thread can never be replaced (dig_ecosystem#2074)

`EventLoopBuilder::build()` opens with `if EVENT_LOOP_CREATED.swap(true, Relaxed) { return
Err(RecreationAttempt) }` — a **process-global** `AtomicBool` (winit 0.30.13 `src/event_loop.rs:69`,
`:118`) reset nowhere outside the web backend. Sequential windows work only because eframe caches the
loop it built in **thread-local** storage and re-enters it via `run_app_on_demand` (`eframe` 0.31.1
`src/native/run.rs:51`, gated on `NativeOptions::run_and_return`, default `true`).

Both halves matter, and they point the same way:

- Same thread, one window after another: fine. Measured — three real `run_native` calls in a row on one
  spawned thread all returned `Ok`, including one straight after a panic inside a frame.
- A NEW thread: never. Its thread-local cache is empty, so it asks winit for a loop and is told
  `RecreationAttempt` for the life of the process.

So **"detect the dead prompt thread and respawn it" cannot work** — it would look like a recovery and be
a permanent silent `Unavailable`. The only available strategy is to make the thread unkillable
(`catch_unwind` per job) and to report loudly if it dies anyway. The same rule is why the crate's
real-window tests must each be run in their OWN process: `cargo test` gives every `#[test]` its own
thread, so two of them cannot both open a window.

## A panic inside a winit event handler is SWALLOWED, not raised (dig_ecosystem#2074)

`EventLoopRunner::catch_unwind` (winit 0.30.13 `windows/event_loop/runner.rs:170`) stores the payload
and — this is the part that bites — **short-circuits every later call while a payload is stored**, so
the application callback is silently never invoked again. The payload is only re-raised from
`dispatch_peeked_messages` (`event_loop.rs:423`), *after* a successful `DispatchMessageW`. A panic on a
path that then finds an empty queue leaves a loop that still pumps messages, still answers `WM_NULL`,
and never delivers another event to the app: a window frozen on its last frame that cannot be answered
and never returns. Do not assume a panic in a frame will surface as a crash, or even as a stuck thread
you can see.

## `Responding = False` on the dig-app tray process is a RED HERRING (dig_ecosystem#2074)

`.NET Process.Responding` sends `WM_NULL` to `MainWindowHandle`, which is the first VISIBLE, unowned,
top-level window of the process. winit's own 13×13 helper — class **`Winit Thread Event Target`** — is
all three, and it appears the moment the first prompt is ever drawn and then outlives every prompt.
Between prompts the prompt thread parks in `rx.recv()` and pumps nothing, so that window stops
answering and the whole process reads as "not responding" forever.

Verified on the affected machine: `Responding=True` on a freshly started dig-app, `False` from the first
prompt onward, with **no consent window on screen**. Enumerate the process's windows by class before
reading anything into `Responding`.

## Diagnosing a GUI from a DPI-UNAWARE shell reports coordinates that do not exist (dig_ecosystem#2074)

PowerShell is `DPI_AWARENESS_UNAWARE` (0); the prompt window is `PER_MONITOR_AWARE` (2) at 240 DPI. So
`GetWindowRect` came back as `(98,98)-(718,421)` for a window that visibly occupied `(244,244)-(1794,1052)`
— a 2.5× disagreement that reads exactly like a rendering bug and is not one. `SetThreadDpiAwarenessContext(-4)`
on the probing thread makes every measurement agree with the screen.

Two other traps in the same session, both of which produced confident wrong conclusions:

- `mouse_event(MOUSEEVENTF_ABSOLUTE | LEFTDOWN, 0, 0, …)` clicks at **screen (0,0)**, not at the cursor:
  the absolute flag means `dx`/`dy` are normalised 0–65535 coordinates, not "ignored". Use the plain
  `LEFTDOWN`/`LEFTUP` flags after `SetCursorPos`.
- A background tray agent's window often opens WITHOUT foreground (`GetForegroundWindow() != hwnd`), so
  injected keystrokes go somewhere else entirely. Check foreground before concluding "the window ignores
  the keyboard".

A prompt that self-dismissed at exactly its 300 s deadline is proof the frame loop was alive the whole
time — which is worth measuring before theorising about a stalled loop.

## Never point a `git checkout --`-based mutation harness at UNCOMMITTED work (dig_ecosystem#2074)

The falsification script restored each mutation with `git checkout -- <file>`, which happily reverted an
hour of uncommitted fixes on its very first `restore`, and then reported the mutations as "survived"
because their anchors no longer existed. Commit the baseline first, and make the harness verify each
mutation actually applied — a silently no-op'd edit reports a green run as a passing falsification.

Also: classify a mutation run by looking for `FAILED` **before** grepping for `^error`, because cargo
ends every failing test run with `error: test failed, to rerun pass …`.

## A bulk "safe default" is unsafe wherever BOTH controls act (dig_ecosystem#2074)

Flipping every `ClaimPrompt` to `refusal_is_default: true` — right for "I have written these 24 words
down" — silently inverted the safe side of the first-run route fork, where **declining generates and
seals a new master seed**. One line of prompt-kind reasoning put a brand-new account one bare Enter
away, behind a control the branded window still labelled "Cancel".

The rule is not a property of the prompt KIND, it is a property of what each ANSWER DOES. `SPEC.md`
§3.2 already said "classified per call site, never applied in bulk"; the code inherited a default
instead, so the compiler never asked. Making the field REQUIRED on `ClaimPrompt` is what turns that
sentence into something a reviewer cannot skip: every call site now has to state which side is safe,
and the diff shows all ten of them.

Corollary worth keeping: a control that takes an irreversible action must not wear the backend's
generic word for refusing. The refusing label now comes from the CONTENT when it supplies one.

## An unbounded message drain on Windows is not obviously bounded (dig_ecosystem#2074)

`drain_pending` looked safely terminating — `PeekMessage` removes what it returns, so the queue only
shrinks. It does not. The flush runs after winit's `reset_runner()`, when `should_buffer()` is true and
winit's own `WM_PAINT` handler RE-INVALIDATES the window on every paint (winit 0.30.13
`windows/event_loop.rs:1276`), so the queue refills as fast as it drains. A harness of winit's exact
shape dispatched **330,021 `WM_PAINT`s in 5 s without terminating**.

What keeps it latent is an undocumented scheduling rule: `WM_PAINT` is synthesised and low-priority, so
the `PostMessageW` destroy that `winit::Window::drop` sends is always returned first and the loop ends
on iteration 1. That is a fine reason to expect it to work and a terrible thing to depend on, on the
single thread the whole consent surface runs on. Bounded at 8192 — two orders of magnitude above any
real teardown, and structurally terminating.

## Clearing a "busy" flag after the call is not the same as clearing it on the way out

The hotkey worker's `busy` flag was reset by a statement after `on_press()`. A panic skips statements.
Measured on the unguarded version: after one panicking press, five further presses reached the handler
**zero** times — the flag latched, and every later press short-circuited before it could even notice
the worker was dead. The panic guard fixes the thread; only a drop guard fixes the flag, and it keeps
fixing it if someone later moves the guard.
