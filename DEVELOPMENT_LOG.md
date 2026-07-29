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

## A seal is only as strong as who holds its key (dig_ecosystem#1817, 2026-07-29)

The account master seed was DIGOP1-sealed with AES-256-GCM under a 256-bit Argon2id-stretched password.
Every part of that sentence is good, and the whole thing protected nothing a local attacker had to work
for, because **dig-app generated the password itself and filed it in the OS credential store**. The
credential store releases its entries to the logged-in session with no prompt, so any code running as the
user could fetch the password and open the seed without a single interaction. The tray's `Unlock…` item
opened an account the machine had already opened.

- **"Encrypted at rest" and "protected at rest" are different claims, and the difference is custody of the
  key.** The audit trail here is worth keeping: the SPEC had *correctly* recorded that the DIGOP1 sealing
  was "defense-in-depth UNDER that ACL, NOT an independent second secret", and had filed splitting the
  password away from the ciphertext as a follow-up. The honest description was written down and the
  conclusion — that there was no user-known secret protecting custody anywhere — was still not drawn for
  several releases. A correct description of a weakness is not a mitigation of it.
- **A lock that can re-open itself is not a lock.** The idle auto-lock, `Lock now` and the OS screen-lock
  hook all worked exactly as designed: they dropped the residency's key material. The sign-path re-auth
  gate then re-unlocked zero-prompt from the same credential store, so the very next signature silently
  re-derived everything that had just been dropped. Three lock mechanisms, one re-auth, net effect zero.
  When auditing a lock, follow what happens on the NEXT operation, not what the lock itself does.
- **The abstraction was already there and unused.** `account/auth.rs` had defined `AuthCeremony` as "the
  thing that actually renders the OS-native password/TOTP/passkey prompt" from the beginning, and v4.0.0
  had shipped a masked, revealable, `Zeroizing` native input window for typing recovery phrases. The fix
  was to connect two things that already existed. Before building a prompt, check whether the seam and
  the window are already sitting in the tree.
- **Making the boot path take the ceremony as a PARAMETER is what makes the guarantee real.** The property
  wanted is "no path from process start reaches a seed without a user". Asserting that with tests alone is
  weak, because the assertion lives next to the code it constrains. Making `start_sign_service` require a
  `BootedAccount` it cannot construct, where the only producers of one require an `AuthCeremony`, hands the
  guarantee to the compiler. The remaining hole — `main` simply CALLING an unlock at startup — is the one
  a type cannot close, and needed a source-reading test (`tests/starts_locked.rs`) because `main` has no
  runtime seam. That is the second time in this repo that a custody property in a `bin` target had zero
  coverage; the first cost a destroy-authorization inversion that stayed green.
- **Re-sealing is possible precisely while the old key is still available.** The migration off the
  machine-held password only works on a machine that still HAS it, which means the window for a graceful
  in-place re-seal is open exactly until someone "cleans up" the credential entry. It re-enrols from the
  vaulted recovery phrase, so the seed — and therefore the identity key, the addresses, the per-profile
  DEKs and every already-sealed blob — survives unchanged. Ship the migration in the same release that
  removes the old path, or the graceful path stops existing.
- **`dign account status` was warning users about a danger they did not have.** It reported the DIG ID and
  recoverability by attempting an unlock, and on failure fell through to `recoverable: false` — which
  renders "WARNING: it has NO recovery phrase". So a merely-locked account with a perfectly good phrase
  was told the opposite. A default that stands in for "unknown" will eventually be read as a fact; make
  unknown its own value, or do not report the field.
- **`discard_account` was deleting the wrong credential key.** It removed the bare account id while the
  ceremony had written `"<account>.master-password"`, so destroying an account left the machine-held
  password behind in Credential Manager forever. Two places computing a key format, one of them by hand.
