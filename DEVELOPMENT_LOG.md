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
