# dig-app — SPEC

Normative specification for the **DIG user app / identity hub**. This is the authoritative contract
an independent implementation could be built against: what dig-app IS, what it holds, how it relates
to the DIG Node engine, and the wire/format/security properties both sides MUST honour. It is not a
README or a roadmap.

Layering (per the ecosystem contract): this `SPEC.md` is dig-app's own contract; the superproject
`SYSTEM.md` is the cross-repo interaction map; the `normative-contract` skill holds the ecosystem
MUST-DO ledger (NC-*). Where they touch a shared contract they MUST agree. The governing design and
work-unit DAG live in epic [dig_ecosystem#908].

Requirement keywords **MUST / MUST NOT / SHOULD / MAY** are used in the RFC 2119 sense.

---

## 1. The boundary invariant

> **The DIG Node (SYSTEM service) is the identity-agnostic background engine. The dig-app (user app)
> is the user's interaction with that engine — and it IS the user identity.**

Two components, one machine:

- **The engine (dig-node, a SYSTEM/daemon service)** does the shared machine work: P2P networking,
  content serve, chain watch, and the content cache. It MUST hold **no** user identity, user keys,
  wallet, DID, profiles, or per-user data. It keeps exactly one identity — a machine **transport
  peer-identity** — so it can be a network peer while running headless at boot.
- **dig-app (a per-user application)** owns everything identity-specific and runs **as the interactive
  user**: key management, DID/profiles, the wallet, per-user data (in the user's AppData, encrypted at
  rest), the UI, and the CLI/RPC gateway.

Everything else in this spec sits under this split. The invariant is testable: a conformant engine
build MUST contain no code path that stores or receives a user private key (§10 lists the regression
tests that assert this).

---

## 2. The identity split

The DIG Node historically conflated two distinct identities. dig-app exists to split them:

| Identity | Nature | Home | Used for |
|---|---|---|---|
| **Transport peer-identity** | machine / network, per-install | the engine, machine-level store (SYSTEM/Admin-only DACL) | mTLS P2P `peer_id`, relay reservation, being a network peer headless at boot |
| **User identity** | per-user, per-profile | dig-app, the user's AppData, sealed to the user key | signing spends, writing profile SMT slots, authenticating a request as a DID, §21 authenticated sync |

### 2.1 Transport peer-identity (engine-side)

The engine's peer-identity is the machine credential `peer_id = SHA-256(TLS SPKI DER)` — the same
peer-id model the peer-comms layer uses ecosystem-wide (a canonical shared contract). It is derived
from a machine transport seed, NOT from any user's key. It stays in the engine and dig-app MUST NEVER
hold it. It is what lets the engine serve + peer with no user logged in.

### 2.2 User identity (dig-app-side)

The user identity is a **DID** (a `did:chia:` singleton, per `dig-identity` [dig_ecosystem#771]) plus
its keys: the signing key (dig-identity slot `0x0010`) and the encryption key (slot `0x0011`, the
X25519 IK used for end-to-end sealing), plus the wallet and the profile's data. It lives only in
dig-app, sealed at rest to the user key.

### 2.3 How the two relate — the user key never enters the engine

The user identity is supplied **per-operation** over the identity-authenticated IPC (§5). The private
key MUST NOT cross into the engine. Three mechanisms cover every case:

1. **dig-app-originated signature** (sign a spend, write a profile SMT slot) — dig-app builds the
   payload (via the canonical wasm spend builders / chip35 delegation for profile writes), signs with
   the in-memory unlocked user key, and hands the **finished signed bytes** to the engine to
   broadcast/relay. The engine sees only signed bytes.
2. **Engine-initiated signature** (e.g. a §21 authenticated-sync handshake the engine must answer) —
   the engine cannot sign; it issues a **`sign` callback** over the IPC (the concrete contract is
   §5.3) to the attached dig-app, which signs and returns the signature. The engine composes the
   request with the returned signature. No key crosses.
3. **DID-authenticated request** — dig-app mints a short-lived DID-signed capability/token and
   attaches it to the request it proxies; for the node-class mTLS path (§7) the channel presents
   dig-app's per-profile client cert. The engine validates nothing that requires the private key.

**Net rule:** the engine is a *consumer of signatures* and a *relay of signed/authed requests*; the
user private key never leaves the dig-app process.

---

## 3. dig-app responsibilities

### 3.1 Key management

dig-app is the sole holder of the user's private keys. Keys are sealed at rest with **dig-keystore
DIGOP1** (AES-256-GCM + Argon2id) — never hand-rolled — under a three-level hierarchy rooted at the
user's key:

1. **Bootstrap unlock** — a DIGOP1 password. On Windows/macOS it is held in the per-application OS
   keychain (Windows Credential Manager / macOS Keychain), released by the login session; a
   passphrase prompt is the fallback. On Linux it is a user passphrase (the keyutils keyring is not a
   safe custody store — §3.1). Opens the active profile's sealed identity blob.
2. **Root** — the unlocked profile identity key.
3. **Per-profile DEK** — HKDF-derived from the identity, sealing every other per-profile blob.
   Profiles MUST NOT share a DEK.

Signing happens in-process (§2.3). Identity rotation re-derives the DEK and re-seals all of that
profile's blobs in one transaction (DIGOP1 is versioned; a store-version header drives migration).

**Identity keys.** A profile's identity is the two `dig-identity` standard keys: an **Ed25519**
signing key (slot `0x0010`) and an **X25519** encryption key (slot `0x0011`). Both are generated
from the OS CSPRNG, held in memory only while unlocked, and zeroized on drop. Their at-rest form is
a fixed 64-byte layout `signing_seed(32) || encryption_scalar(32)` that DIGOP1 seals; the private
material is serialized nowhere else.

**Domain-separation invariant (MUST).** Every signature the slot `0x0010` identity key produces MUST
carry a unique per-purpose ASCII domain-separation tag as the first bytes of the signed message; no
purpose ever signs un-prefixed caller/peer bytes. Distinct purposes MUST use distinct tags (e.g.
`DIGNET-SESSION-v1` for the session-attach challenge §5.3, `DIGNET-SIGN-v1` for the engine `sign`
callback §5.3). This makes a signature minted for one purpose provably non-verifiable for any other,
closing cross-protocol signing oracles (a signature obtained for purpose A cannot be replayed as a
valid signature for purpose B — including an attach challenge, a spend hash, or an SMT write). Each
verifier reconstructs the identical tagged byte string; the construction is byte-identical across the
app and every counterpart (the engine, a reimplementation).

**At-rest storage precedence (bootstrap unlock).** The precedence is PLATFORM-DEPENDENT, because an
OS credential store is only a safe custody primary where its access gate is per-application:

1. **OS credential store (primary on Windows + macOS ONLY)** — Windows Credential Manager · macOS
   Keychain, reached through the `keyring` crate. The sealed blob and a freshly-generated 256-bit
   random unlock password are stored together in ONE credential entry, so password rotation is a
   single atomic overwrite. The login session releases the entry with no prompt. On these platforms
   the store enforces a **per-application access ACL** — that ACL is the actual access control. The
   DIGOP1 sealing is defense-in-depth UNDER that ACL, NOT an independent second secret: because the
   unlock password rides in the same entry as the ciphertext, an attacker who defeats the ACL and
   dumps the entry obtains both and can open the blob (splitting the password away from the
   ciphertext is a separate follow-up hardening — §7). Fallback to the sealed file (below) if the
   store is unavailable.
2. **Sealed file (primary on Linux; fallback elsewhere)** — the sealed blob is a file
   (`identity.digop1`) in the profile's AppData directory (home-directory-ACL'd to the owning user,
   mode `0600`), written durably and atomically (temp file → fsync → rename → parent-dir fsync) and
   opened with a user-supplied passphrase (Argon2id); the passphrase is never persisted. This is the
   **primary on Linux**: the kernel keyutils session keyring is deliberately NOT used there because
   it is readable by any same-UID process in the session (it has no per-application ACL, so a
   same-UID background process could harvest the key) AND it is non-persistent across reboot/logout
   (a plain reboot would destroy the only copy of a random, no-mnemonic identity — data loss). The
   passphrase-sealed file is persistent, home-ACL'd, and — needing a user passphrase — not
   harvestable by a background same-UID process. It is also the fallback anywhere the OS credential
   store is unusable (a headless server, a minimal container).

The precedence is detected once at vault-open time. Unlock **fails closed**: a wrong passphrase, a
tampered blob, or a foreign key yields an opaque error that never distinguishes the cause and never
produces partial plaintext.

### 3.2 Profiles (multi-DID)

A **profile** is `{ DID (did:chia singleton), keys (signing 0x0010 + encryption 0x0011), paired
chip35 DataLayer store, local data (config / subscriptions / wallet / prefs) }`. The on-chain identity
is the dig-identity #771 DID paired with a chip35 store via the store `description` field; profile
fields are standard SMT slots. dig-app supports **multiple profiles** with exactly one **active
profile** selected at a time; it creates (mint DID + paired store via chip35 delegation), selects,
edits (write SMT slots), and reads profiles — always through `dig-identity`, never a reinvented
format (release-first: the format ships in dig-identity, then dig-app consumes it).

On disk the profile set splits into three tiers per profile: a **plaintext registry**
(`<brand-dir>/profiles/registry.json` — the active-profile pointer plus a non-secret record per
profile: its DID, its two public keys, the paired store id, and a cached display name) so the app
can list profiles and restore the active one *before any profile is unlocked*; a **sealed identity
blob** (`<brand-dir>/profiles/<did-hash>/identity.digop1`, or the OS credential store — the profile's
private key material, DIGOP1-sealed under the user's root unlock, §3.1); and a **sealed per-profile
data blob** (`<brand-dir>/profiles/<did-hash>/identity.seal` — the persona metadata cache,
subscriptions, and per-profile prefs), DIGOP1-sealed under that profile's own DEK. Every per-profile
data blob is sealed with the owning profile's key and no other, so opening one profile's blob under a
different profile's DEK MUST fail — profiles are cryptographically isolated on disk. Because each
profile's DEK is HKDF-derived from that profile's own freshly generated identity key (§3.1), the
isolation holds by the cipher, not by directory layout, and MUST continue to hold after a restart +
re-unlock (below). The registry is the sole pointer to every profile's directory, so it MUST be
written durably and atomically (temp file → fsync → rename), the same way the sealed blobs are (§3.1);
a torn write can never strand a profile's data.

**Cross-session persistence + boot re-unlock.** Each profile's identity is persisted **sealed at
rest** (via the §3.1 vault) at creation, so a restarted app can recover it. On boot, after the user
supplies the root unlock, the app re-derives every profile's identity from its sealed material and
holds it in the in-memory session, making that profile's DEK — and therefore its sealed data —
available again. A profile whose identity is not unlocked this session is *locked*: its data cannot
be opened (fail-closed). Before the root unlock, only the plaintext registry is readable (list +
restore-active); no sealed data opens.

**Creation ordering (security-critical).** Provisioning an identity (mint DID + generate keys) MUST
be free of side effects: it neither persists nor unlocks the identity. The manager validates the
minted DID (canonical + not already owned) and only THEN commits it — seals it at rest and registers
it unlocked. So a duplicate or invalid DID can never clobber an existing profile's live in-session
identity or its sealed data; a rejected DID drops the freshly generated secret material untouched
(zeroized). If a later creation step fails, the just-committed identity is rolled back (sealed
material removed + session locked) so no half-created profile is left behind. Decrypted profile data
is returned in a zeroizing buffer, so a profile's plaintext content is scrubbed from memory after use.

dig-app never *retains* a private key while doing this: provisioned secret material passes straight
through the manager into the sealing/persistence layer (§3.1); minting the DID + generating the keys
is delegated to the keystore + wallet/engine, and the on-chain DID mint itself remains a seam gated on
dig-identity #771. Editing a profile updates the sealed metadata and recomputes the canonical
dig-identity SMT root; broadcasting that root on-chain (chip35 delegation) is a wallet/engine operation.

### 3.3 Wallet

The wallet is user-identity state and lives in dig-app (migrated out of the engine). It is a
**focused host**, not a port of the engine's wallet tree: it holds the wallet key, builds and signs
spends locally, caches the per-profile wallet view, and delegates network I/O to the engine.

**Wallet key.** A profile's wallet key is a Chia BLS key rooted at a 32-byte seed. The on-chain
spending key is the canonical Chia standard wallet child —
`master_to_wallet_unhardened(master, 0).derive_synthetic()` — whose public half curries the standard
puzzle; that puzzle's tree hash is the wallet's `xch1…` receive address. The key is held in memory
only while the profile is unlocked, and its seed is the ONLY serialized form — always DIGOP1-sealed
(§3.4) before it touches disk. The seed is never exposed to callers and never crosses the IPC
boundary to the engine.

**Spend building — chip35 only.** Every `$DIG` spend bundle is constructed by the canonical chip35
spend builder (`chip35_dl_coin::build_dig_store_payment`); dig-app MUST NOT hand-roll a spend bundle.
The per-capsule DIG payment pays the dynamic, USD-pegged amount (an input, never a hardcoded
constant) to the canonical DIG treasury (`DIG_TREASURY_INNER_PUZZLE_HASH`, reused byte-identical from
chip35 — never a placeholder). Minting a store is free of `$DIG`; only a capsule (commit) pays.

**Local signing.** The unsigned coin spends are signed **in-process** with the synthetic wallet key
against the Chia mainnet `AGG_SIG_ME` constants (the `chia-wallet-sdk` signer extracts each required
signature and the wallet aggregates them). The finished `SpendBundle` — **signed bytes only** — is
serialized to hex and handed to the engine to broadcast. The engine never receives the wallet private
key (the same custody boundary as the §2.3 session `sign` callback). A required signature for a key
the wallet does not hold is skipped, so an incomplete bundle fails closed at the network rather than
being silently forged.

**Wallet state at rest.** The per-profile wallet view — receive addresses and the last-known
spendable coins (per asset) used for display + coin selection between chain reads — is DIGOP1-sealed
under that profile's own DEK (§3.4), in the profile's directory (`wallet-state.seal`), alongside the
separately-sealed key seed (`wallet-key.seal`). Both are cryptographically isolated per profile: one
profile's DEK cannot open another's wallet blobs (fail-closed). The `.dig` content cache is NOT
wallet data and is exempt from sealing (§3.4).

**Engine seam — the `control.wallet.*` contract (NODE-1, [dig_ecosystem#910]).** The two things the
wallet cannot do itself — broadcasting a signed bundle and reading chain state — cross the §5.3 IPC
session as a small, **byte-identical cross-repo method set the engine implements** (the same
contract-first pattern as the §5.3 session methods). The engine's chain access is chia-query-backed
(the canonical coinset layer):

- `control.wallet.broadcast` — `{ signed_bundle_hex }` → `{ accepted, transaction_id? }`. The engine
  forwards the signed bundle to the network and reports mempool acceptance; it sees only signed bytes.
- `control.wallet.coins` — `{ address, asset }` → `{ coins: [{ coin_id, asset, amount }] }`. The
  address's spendable coins for the asset.
- `control.wallet.balance` — `{ address, asset }` → `{ balance }`. The address's spendable balance in
  the asset's base unit.

`asset` is the lowercase wire enum `"xch" | "dig"`. dig-app depends only on the `WalletEngine` trait
seam, so it compiles + tests standalone; the real IPC-session transport (the §5.3 `SessionClient`)
drops in as the production implementation without touching the wallet logic.

[dig_ecosystem#910]: https://github.com/DIG-Network/dig_ecosystem/issues/910

### 3.4 Per-user data at rest (NC-2 / NC-3)

All user-facing data lives in the interactive user's per-OS application-data directory, in a
per-profile subdirectory keyed by the profile's DID, sealed at rest to the user key:

| OS | Brand data directory |
|---|---|
| Windows | `%LOCALAPPDATA%\DigNetwork` |
| macOS | `~/Library/Application Support/DigNetwork` |
| Linux | `$XDG_DATA_HOME/dignetwork` (config under `$XDG_CONFIG_HOME`) |

Per-profile layout: `<brand-dir>/profiles/<did-hash>/…`, ACL/mode `0600` to the owning user.
Sealed contents: the DID identity keys, wallet state, subscriptions, user config/prefs (the §5.3
upstream/custom-node setting, the auto-tip preference), and profile metadata (a local cache of the
dig-identity SMT). This satisfies **NC-3** (data in the user's AppData) and **NC-2** (encrypted at
rest to the user key) — see the `normative-contract` skill.

**`.dig` content-cache exemption (§5.1 of the ecosystem contract).** The on-chain-anchored public
content cache is NOT dig-app data and NOT sealed: the engine owns it in an explicit **machine** cache
directory (plaintext, SYSTEM-write-restricted). It is public content, permanently readable, so it is
exempt from at-rest encryption. Only identity / wallet / subscriptions / config / profile-metadata
are sealed under §3.4.

### 3.5 CLI / RPC gateway (`dign`)

`dign` is the **DIG user CLI, owned by dig-app** (migrated from dig-node; there is no separate
`diga`). A user runs `dign`; it talks to the running dig-app (their identity/session), which
authenticates the caller and either serves the request locally with the user keys (sign / profile /
wallet) or proxies engine work over the authenticated session. The user/identity/control subcommands
(info/config/cache/stores/sync/subscriptions/peers/pair/open + wallet/profiles/sign) live here.

The `dig-node` binary retains **only** machine service-lifecycle subcommands
(install/start/stop/status/uninstall/run-service) — the identity-agnostic engine admin surface. It
MUST NOT carry user/identity subcommands.

Machine-friendly (per the ecosystem agent-friendly baseline): `dign` MUST offer `--json` output
beside human output, a discovery surface (`--help`/`--help-json`), and deterministic catalogued error
codes.

`dign` is its OWN binary crate (a thin IPC client); the routing lives in `dig_app_core::gateway`,
which the running dig-app hosts. The gateway classifies every command as `Route::UserApp` (served
locally with the held user identity — profiles / wallet / sign) or `Route::Engine` (proxied to the
engine), and dispatches over three seams: `EngineProxy` (forwards the canonical `control.*` call over
the session), `LocalIdentity` (serves the local identity ops), and `LinkOpener` (validates + opens a
DIG link — only `chia://` / `urn:dig:chia:` are accepted, the security boundary). Failures carry a
stable `ErrorCode` (symbolic name + numeric exit code); the `--json` envelopes match the engine CLI's
shape so the DIG command line is one consistent surface.

---

## 4. Form factors

dig-app is a **headless per-user agent core** with an **optional GUI tray shell** layered on top. The
agent core (identity/keys/profiles/IPC/gateway) is the real component; the tray is a desktop
affordance. On a GUI-less host the app runs as the agent core + the `dign` CLI, with no tray.

| OS | Engine (service) | dig-app shell | dig-app autostart (per user) |
|---|---|---|---|
| Windows | Windows Service / LocalSystem | system-tray shell | per-user logon autostart |
| macOS | launchd **daemon** (`/Library/LaunchDaemons`, root) | menu-bar `LSUIElement` | launchd **LaunchAgent** (`~/Library/LaunchAgents`) |
| Linux | systemd **system** service | AppIndicator / StatusNotifier tray | XDG `~/.config/autostart/*.desktop` OR a systemd **user** service |

**Headless degrade (MUST):** when no desktop session is available (a Linux server, headless
Windows/macOS Server), dig-app runs as the agent core + `dign` only; the tray is not mounted. The
form-factor decision is a single point (`dig_app_core::form_factor`).

**Autostart artifacts:** the macOS LaunchAgent plist and the Linux systemd user unit are rendered
and installed by `dig_app::autostart` (`crates/dig-app/src/autostart.rs`) — pure content generation
+ path resolution, unit-tested without a real service manager; loading the unit
(`launchctl`/`systemctl --user`) is the installer's/first-run helper's job. Windows per-user logon
autostart is dig-installer's own packaging concern (U8) and is out of this crate's scope.

**Multi-user (MUST):** one engine daemon serves the whole machine; **each logged-in user runs their
own dig-app instance** with its own profiles/keys. The engine holds no per-user state, so it keeps a
map of attached sessions keyed by profile; content serve is profile-agnostic (public); authenticated
sync, subscriptions, and signing run per-attached-session. Fast-user-switching and concurrent sessions
MUST work — there is no single "active machine profile."

---

## 5. The user-app ↔ engine IPC contract

dig-app and the engine communicate over a **per-user, OS-native local channel**, carrying an
**identity-authenticated session**. This supersedes the SYSTEM-minted control-token model
([dig_ecosystem#856] Family B).

### 5.1 Transport

| OS | Channel | Address |
|---|---|---|
| Windows | named pipe (per-user namespace) | `\\.\pipe\dignetwork-<USER>` |
| macOS / Linux | Unix domain socket | `<RUNTIME_DIR>/dignetwork.sock` (`$XDG_RUNTIME_DIR` on Linux) |

The channel MUST be **per-user and ACL-scoped to the owning user** — tighter than loopback TCP — and
the OS peer credential additionally binds the connecting identity. The channel is **bidirectional**,
carrying **newline-delimited JSON-RPC 2.0 frames** over the engine's existing `control.*` dispatch:
this is a **transport swap only** — the `control.*` protocol shape is unchanged. The pre-existing
loopback-TCP `control.*` channel STAYS for the MV3 browser extension, which cannot speak pipes.
IPv6-first (ecosystem §5.2) is N/A here — the channel is a local pipe / UDS, not a network socket.

The concrete request/response shapes below are the normative contract that the app-side (dig-app,
APP work units) and the engine-side (dig-node, `control.session.*` + the `sign` callback) both build
against. All frames are JSON-RPC 2.0; `params`/`result` fields use the names and encodings given.

### 5.2 Session authentication

dig-app authenticates to the engine by **proving possession of the active profile's identity key** —
a signed-challenge handshake — NOT a static token file. No client can attach a `profile_did` it
cannot sign for. The handshake is three methods (§5.3), and the engine opens an in-memory session
only after it verifies the signature against the DID's own on-record signing key.

The signed-challenge scheme is the baseline because the per-user pipe/socket ACL and the OS peer
credential already authenticate the *channel*; the handshake additionally binds the *profile
identity*. An **mTLS variant** — the app presents a client cert keyed by the profile identity —
is an equivalent alternative where a cert-authenticated channel is preferred.

### 5.3 Session methods (the concrete contract)

Built on the existing `control.*` dispatch. The full handshake proves the caller holds the active
profile's slot `0x0010` signing key before any session opens.

1. **`control.session.begin`** (app → engine) — params: `profile_did`, `signing_pubkey_hex` (the
   claimed slot `0x0010` signing key). Engine returns `nonce_b64` (32 random bytes, base64) and a
   `session_candidate` (uuid) naming this pending handshake.

2. **App signs the challenge.** The app produces an Ed25519 signature, using the in-memory slot
   `0x0010` key, over the byte string:

   ```
   "DIGNET-SESSION-v1" || nonce || profile_did
   ```

   (the ASCII domain tag, the raw 32 nonce bytes decoded from `nonce_b64`, and the `profile_did`
   bytes, concatenated in that order).

3. **`control.session.attach`** (app → engine) — params: `session_candidate`, `signature_b64`, and
   `profile { did, subscriptions, config_digest }`. The engine:
   - resolves the `profile_did`'s slot `0x0010` signing key via the **dig-identity READ path**;
   - **REQUIRES** that resolved key to equal the `signing_pubkey_hex` presented in `begin` (a client
     cannot substitute a key it controls for the DID's real key);
   - verifies `signature_b64` over the challenge of step 2 against that key;
   - on success opens an in-memory session and returns `session_id` + `engine_capabilities`.

   No client can attach a DID it cannot sign for. A failed key match or signature ⇒ a JSON-RPC error
   and no session.

4. **`control.session.detach`** (app → engine) — params: `session_id`. Logout / profile switch /
   exit; the engine drops the in-memory session context.

**`sign` callback** (engine → dig-app, over the same connection) — params: `session_id`, `op_id`,
`payload_type`, `payload_b64`, `context`. The engine requests a signature for an engine-initiated
operation (§2.3 case 2). dig-app **policy-checks** the request, then signs — **NOT** the raw
`payload_b64` bytes, but the domain-separated, length-prefixed message:

```
"DIGNET-SIGN-v1" || len16(payload_type) || payload_type || payload
```

(the ASCII `DIGNET-SIGN-v1` tag, the big-endian `u16` byte length of `payload_type`, the
`payload_type` bytes, then the raw `payload` decoded from `payload_b64`). The `len16` prefix makes
the `payload_type || payload` boundary unambiguous; the `DIGNET-SIGN-v1` tag (distinct from the
`DIGNET-SESSION-v1` attach-challenge tag) is what enforces the §3 domain-separation invariant — a
malicious engine cannot choose a `payload` whose signature verifies as an attach challenge (or any
other identity-key signature). The engine reconstructs this identical byte string to verify. dig-app
returns `signature_b64` (over that message) + `pubkey_hex`; **the engine NEVER receives the private
key.** A denied request, a `payload_type` longer than `u16::MAX`, an un-decodable payload, a timeout,
or a user-deny ⇒ a JSON-RPC error; `op_id` correlates the request with its response.

**Multi-session.** The engine keeps a map `session_id → { profile_did, pubkey, subscriptions }`.
Concurrent sessions for different users coexist; a `sign` callback routes to the connection that owns
its `session_id`.

### 5.4 Client → node resolution ladder

dig-app is **tier-0** of the ecosystem client→node ladder (§5.3 of the ecosystem contract): a client
resolves the local dig-app first, then the engine directly (`dig.local` → `localhost`, public reads
only), then `rpc.dig.net`. An explicitly-configured node still overrides the ladder entirely.
Node-class clients dial over mTLS (§7); a user-facing custom-node setting MUST be exposed (persisted
in the sealed config).

### 5.5 End-to-end seal scope on the IPC channel

The local pipe / socket is **not** an intermediary-terminated channel to a remote recipient, so its
own frames are **not** end-to-end sealed — the per-user channel ACL (§5.1) is sufficient. The
ecosystem §5.4 seal-to-recipient rule (NC-1) applies to **recipient-directed content** (chat, email)
that the engine RELAYS onward: dig-app seals such content to the recipient's dig-identity encryption
key (slot `0x0011`) **before** handing the bytes to the engine, so the engine and any downstream
relay see only ciphertext. Sealing is the app's responsibility, never the engine's.

### 5.6 The extension ↔ dig-app paired-loopback signing channel (APP-SIGN)

The §5.3 pipe/UDS session is the ENGINE's path to dig-app. Browsers cannot speak that channel, so a
**second, browser-reachable front door** exists for the identity path: a web dapp reaches dig-app
**through the DIG browser extension**, which relays over a paired loopback WebSocket. This is the
identity channel (connect / sign); it is distinct from the extension ↔ dig-node **content** channel
(`chia://` resolution), which is unrelated and untouched.

This section is the byte-level contract the extension (SIGN-4) and any in-process browser equivalent
build against. It reuses — never re-derives — the §3 domain-separation invariant, the `DIGNET-SIGN-v1`
construction (§5.3, `session.rs::sign_callback_message`), and the §5.3 `SignPolicy` custody seam.

#### 5.6.1 Topology and trust model

```
web dapp ──(window.chia provider)──▶ DIG browser extension ──(paired ws://127.0.0.1:9779)──▶ dig-app
   (untrusted origin)                 (trusted-once mediator)          (holds keys; native confirm; signs)
```

The authorization is **layered**; no single layer is sufficient, and the transport is explicitly NOT
the authorization:

1. **Loopback is reachable by any local process** (including malware running as the user). The
   loopback-only bind, the Host-header allowlist, the `Origin` pin, and the per-frame pairing-token
   MAC only narrow **who may talk on the channel** — they are NOT permission to sign.
2. **The paired extension is a trusted-once MEDIATOR, not an authority.** Pairing (a one-time native
   confirm, §5.6.3) makes exactly one extension a recognized relay. The extension supplies the dapp's
   **true committed tab origin** (browser-supplied, unspoofable by the page) and MAY REQUEST a connect
   or a sign on the dapp's behalf. It can **never approve** either. dig-app trusts exactly this one
   paired client on the loopback surface — not every local process — which is what closes the "loopback
   cannot authenticate the caller" gap.
3. **The OS-native confirm + biometric is the ONLY authorization to sign** (and to first-connect a
   dapp). Every sign — and every un-whitelisted connect — raises a real OS-drawn foreground window
   owned by the dig-app tray process, showing the human-decoded transaction plus the vouched origin;
   the user authenticates via Windows Hello / macOS Touch ID / Linux polkit-or-fprintd, with a
   passphrase fallback everywhere. There is **no auto-approve and no bypass**. The user private key
   never leaves the dig-app process (§5.6.6).

**Headless degrade (MUST).** The loopback identity endpoint is hosted by the tray shell, which holds
the desktop session. On a host with no desktop session (§4 headless degrade) the endpoint MUST fail
closed: it either does not bind, or every `sign`/first-connect request returns `SIGN_NO_CONFIRMER`
(§5.6.7). A headless build MUST NOT sign without a native confirm.

#### 5.6.2 Transport

| Property | Value |
|---|---|
| Protocol | WebSocket (`ws://`) over loopback TCP |
| Address | `127.0.0.1:9779` (IPv4 loopback) and `[::1]:9779` (IPv6 loopback) |
| Bind | loopback interfaces ONLY — never `0.0.0.0` / a routable address |
| Frames | JSON-RPC 2.0 text frames (one JSON-RPC message per WS message) |
| Directionality | bidirectional — the async native-confirm outcome is pushed back on the same socket |

WebSocket (not plain HTTP request/response) is REQUIRED because the native-confirm outcome arrives
seconds later and dig-app pushes it back without the client polling; it also matches the existing
extension ↔ dig-node WS pattern, and the extension MV3 manifest already CSP-allows `ws://127.0.0.1:*`
and `ws://[::1]:*` in `connect-src`.

`9779` is the canonical dig-app **identity** loopback port. It is distinct from the dig-node control
port `9778` and the node dual-transport ports `9257`/`9778`; it carries identity/signing only, never
content. (Recorded in the `canonical` skill + `SYSTEM.md` ports.)

**Per-connection guards (all MUST hold, checked before any frame is honoured):**

- **Bind loopback-only** — the listener binds `127.0.0.1` and `[::1]` exclusively.
- **Host-header allowlist (anti-DNS-rebinding)** — the WS upgrade `Host` MUST be exactly one of
  `127.0.0.1:9779`, `[::1]:9779`, or `localhost:9779`; any other value ⇒ the upgrade is rejected
  (403, connection closed). This is the same guard the dig-node control server uses.
- **`Origin` pin** — the WS upgrade `Origin` MUST equal `chrome-extension://<pinned-ext-id>` (the
  pinned DIG extension id; `SYSTEM.md`/canonical hold the value). A missing or mismatched `Origin` ⇒
  the upgrade is rejected. (Browsers set `Origin` on a WS handshake and a page cannot forge another
  extension's id.)
- **Pairing-token MAC** — after pairing (§5.6.3) every request frame carries an `auth` object the
  server verifies before dispatch (§5.6.3). An unpaired or MAC-invalid frame ⇒ `AUTH_REQUIRED` /
  `AUTH_BAD_MAC` and no side effect.

**App not running.** A refused connection to `127.0.0.1:9779` means dig-app is not running; the
extension MUST surface a deep-link to launch/install dig-app rather than failing silently.

#### 5.6.3 Extension ↔ dig-app pairing handshake

Pairing establishes the one trusted mediator ONCE, like pairing a hardware device. It is a native
confirm, never silent.

1. **`pair.begin`** (extension → app) — params: `{ ext_id, ext_label?, requested_at }`. The app
   verifies `ext_id` equals the pinned extension id (matching the `Origin` guard), then raises a
   native modal: *"Pair this browser extension with your DIG identity?"* gated on the user's
   biometric/passphrase. On approve the app:
   - generates a **32-byte CSPRNG channel token** (the `channel_secret`),
   - persists a pairing record — `{ pairing_id (uuid), ext_id, channel_secret, created_at }` — sealed
     at rest with DIGOP1 under the active profile (§3.1, NC-2), and
   - returns `{ pairing_id, channel_token_b64 }` (`channel_token_b64` = base64 of the 32-byte secret).
   On deny/timeout ⇒ `PAIR_DENIED` / `PAIR_TIMEOUT` and no record.
2. **Token storage.** The extension stores `{ pairing_id, channel_token_b64 }` in `chrome.storage.local`.
   The token grants **channel access only** — it is never sign authority (the terminal native confirm
   still binds every sign).
3. **Per-frame authentication.** Every subsequent request frame (`connect.request`, `sign.request`,
   `session.*`) carries:

   ```
   "auth": { "pairing_id": <uuid>, "nonce": <u64>, "mac_b64": <base64> }
   ```

   where `mac_b64 = base64( HMAC-SHA256( channel_secret, canonical_frame_bytes ) )` and
   `canonical_frame_bytes = utf8( nonce_decimal ) ‖ 0x00 ‖ utf8(method) ‖ 0x00 ‖ canonical_json(params) )`.
   `nonce` is a **strictly monotonic** per-pairing `u64` (the app rejects any `nonce` ≤ the last
   accepted one), which bars replay. The app looks up `channel_secret` by `pairing_id`, recomputes the
   MAC, and rejects a mismatch (`AUTH_BAD_MAC`) or a non-increasing nonce (`AUTH_REPLAY`) before any
   dispatch. The MAC is verified in **constant time**; a MAC failure never advances the nonce ledger
   (a forged or replayed frame can neither pass nor perturb the monotonic counter).

   **`canonical_json` (normative — both sides MUST match byte-for-byte).** `canonical_json(params)` is
   the UTF-8 JSON serialization of `params` where:
   - every object's keys are sorted by **Unicode scalar value (codepoint) order** at EVERY nesting
     level — equivalently, the lexicographic order of the keys' UTF-8 byte sequences. This is **NOT**
     UTF-16 code-unit order; the two DIVERGE for supplementary-plane characters (a JS implementation
     MUST NOT use the default `Array.prototype.sort()`, which compares UTF-16 code units — it MUST sort
     by codepoint to match);
   - there is NO insignificant whitespace (no spaces after `:` or `,`); arrays keep their element order;
   - each scalar (string, boolean, null, integer) uses the standard compact JSON rendering with control
     characters escaped. **`params` MUST NOT contain a JSON floating-point number** (only integers,
     strings, booleans, null, arrays, objects) — float rendering diverges across implementations
     (Rust `ryu` vs the ECMAScript `Number.prototype.toString` algorithm), which would break the MAC;
     an amount is carried as an integer (mojos) or a decimal string, never a float.

   Because control characters are escaped, a raw `0x00` can never appear inside `canonical_json`, so it
   cannot collide with the `0x00` field separators in `canonical_frame_bytes`. The extension (SIGN-4)
   and dig-app derive identical bytes from equal `params`, regardless of the key order the transport
   delivered.
4. **Revocation.** dig-app exposes an "unpair" surface (lists paired extensions); unpairing deletes
   the sealed pairing record, after which every frame from that `pairing_id` fails `AUTH_REQUIRED`.

The pairing token is defense-in-depth on the channel, not the sign gate. Token theft (by a same-user
attacker who can already read `chrome.storage.local` or the sealed record) still cannot produce a
signature without the human at the native biometric prompt (§5.6.5).

#### 5.6.4 dapp connect / whitelist protocol

Before a dapp origin may request a sign, it MUST be connected (whitelisted) for the active profile.

- **`connect.request`** (extension → app) — params:
  `{ origin, dapp_name?, dapp_icon_url?, requested_permissions? }`. `origin` is the dapp's TRUE
  committed tab origin, supplied by the extension (browser-sourced). If `(origin, active_profile)` is
  already whitelisted, the app MAY return the connection handle without a modal (convenience). Otherwise
  the app raises a native modal — *"`<origin>` wants to connect to your DIG identity"* — listing the
  requested scope, gated on Allow/Deny. On Allow the app persists a **whitelist entry**
  `{ origin, profile_did, granted_permissions, connected_at }`, DIGOP1-sealed per profile (NC-2), and
  returns `{ granted: true, profile_did, addresses[], pubkeys[] }` per the `window.chia` connect
  contract. On Deny/timeout ⇒ `CONNECT_DENIED` / `CONNECT_TIMEOUT`.
- **Sign gating.** A `sign.request` whose `origin` is NOT whitelisted for the active profile ⇒
  `CONNECT_REQUIRED` (the extension MUST run `connect.request` first). Whitelisting is connect-time
  convenience memory only; it NEVER waives the per-sign native confirm (§5.6.5). A "sign without
  per-transaction prompt" scope, if ever offered at connect, MUST default OFF and be clearly labelled
  dangerous.
- **`connect.revoke`** (extension → app) and a dig-app UI surface both delete a whitelist entry; a
  revoked origin returns to `CONNECT_REQUIRED`.

#### 5.6.5 sign request

- **`sign.request`** (extension → app) — params:
  `{ origin, payload_type, payload_b64, context? }`.
  - `origin` — the vouched dapp origin (MUST be whitelisted, §5.6.4).
  - `payload_type` — an ASCII tag naming what is being signed; it selects the decoder + the allowlist
    and is bound into the signed message. The shipped allowlist is `spend` (a Chia spend bundle);
    additional types (e.g. `chip35.smt-write`) are added together with their decoder.
  - `payload_b64` — base64 of the **exact bytes that are signed**, which are ALSO the exact bytes the
    decoder renders — display binds to what is signed, so no separate hint can disagree with the
    signed payload (the display-vs-signed signing-oracle gap is closed by construction). For
    `payload_type = "spend"` the bytes are the streamable `SpendBundle`.
  - `context?` — optional engine/extension-supplied context; advisory only, never a substitute for the
    decode.
- **Decoded-transaction display (MUST).** The confirm window MUST present the transaction in **human
  terms**, never raw-bytes-only, decoded from the signed `payload_b64` itself: for a `spend`, the
  `CREATE_COIN` outputs (each recipient rendered as a bech32m `xch1…` address + its amount in mojos)
  and the fee (`total_input − total_created`), via the canonical Chia decode path (`chia-sdk-types`
  `run_puzzle` + `Condition` parsing; DID ops via `chia-wallet-sdk` per canonical). The window also
  shows the vouched `origin` and that the request arrived *via the paired extension*.
- **Allowlist (MUST fail closed).** `payload_type` MUST be on the known-decoder allowlist. An unknown
  `payload_type` ⇒ `SIGN_UNKNOWN_TYPE`; a known type whose payload does not decode ⇒ `SIGN_BAD_PAYLOAD`.
  dig-app MUST NEVER present "sign these opaque bytes?" — a blind-sign request is refused. The
  connect gate runs BEFORE the decode: an un-whitelisted `origin` ⇒ `CONNECT_REQUIRED` regardless of
  the payload (the origin is never revealed to the decoder or the key until it is connected).
- **Native confirm + biometric.** The app raises the OS foreground confirm window and requires an
  explicit biometric/passphrase action: **Windows Hello** (WinRT `UserConsentVerifier`) / **macOS Touch
  ID** (`LocalAuthentication` `LAContext`) / **Linux** (polkit `pkcheck` against the action
  `net.dignetwork.dig-app.authorize`, or fprintd via PAM), passphrase fallback everywhere. If the active
  profile is locked, this action doubles as the §3.1 vault unlock (one user action authorizes and
  unlocks).
- **Confirmer selection + the two-step gate (implementation contract).** `confirm::native_confirmer()`
  selects the per-OS backend when the host has an interactive desktop session and the fail-closed
  headless confirmer otherwise. Every backend is the SAME two-step gate over the shared, unit-tested
  policy: (1) a foreground window shows the origin-bound heading + the decoded transaction and takes an
  approve/cancel choice; (2) on approve, the OS authenticator re-authenticates the user
  (biometric, with the platform's own PIN/password as the built-in fallback). A signature is authorized
  ONLY when BOTH succeed; a dismissed window, a cancelled/failed/unavailable authenticator, or a missing
  authenticator all fail closed to the matching §5.6.7 code. The biometric step proves *user presence +
  device-owner identity*; it is distinct from the vault passphrase (the key unlock stays in the keystore
  path). **Never blind-sign (defense-in-depth):** a sign prompt whose `decoded_tx` is absent is denied
  WITHOUT raising a window, independently of the §5.6.5 dispatch allowlist.
- **Domain-separated signing (MUST — reuse, do not re-derive).** On approval the app signs, with the
  in-memory slot `0x0010` key, NOT `payload_b64` but the §5.3 domain-separated message:

  ```
  "DIGNET-SIGN-v1" ‖ len16(payload_type) ‖ payload_type ‖ payload
  ```

  (constructed by `session.rs::sign_callback_message`; `len16` = big-endian `u16` byte length of
  `payload_type`). This is the identical construction the engine `sign` callback uses, so a signature
  minted here is bound to its `payload_type` and cannot be replayed as a session attach (§5.3), a
  differently-typed spend, or any other `0x0010` signature (§3 domain-separation invariant).
- **Response.** `{ signature_b64, pubkey_hex }` — the 64-byte detached Ed25519 signature over the
  message above, and the signing public key. **Only the signature returns; the private key never
  leaves dig-app.** A deny/timeout/decoder-failure ⇒ the matching §5.6.7 error. The JSON-RPC `id`
  correlates the response with its request across the async confirm.

#### 5.6.6 Key custody (this path)

Identical to §2.3 / §5.3: dig-app signs in-process with the in-memory unlocked slot `0x0010` key and
returns only the signature. Both callers — the §5.3 engine `sign` callback AND this loopback
`sign.request` — funnel through **one** `SignPolicy` custody gate (§5.3), so there is a single sign
authorization point with no divergence: the production policy is the native-confirm policy; the
`AllowAll`/`DenyAll` policies (`session.rs`) remain test doubles only.

#### 5.6.7 Error-code taxonomy

Stable symbolic codes returned as JSON-RPC errors (the extension keys UX off these, not off prose):

| Code | Meaning |
|---|---|
| `AUTH_REQUIRED` | no valid pairing for this frame (unpaired / revoked) |
| `AUTH_BAD_MAC` | pairing-token MAC verification failed |
| `AUTH_REPLAY` | frame nonce not strictly greater than the last accepted |
| `PAIR_DENIED` / `PAIR_TIMEOUT` | user denied / did not answer the pairing confirm |
| `CONNECT_REQUIRED` | the `origin` is not whitelisted for the active profile |
| `CONNECT_DENIED` / `CONNECT_TIMEOUT` | user denied / did not answer the connect modal |
| `SIGN_DENIED` / `SIGN_TIMEOUT` | user denied / did not answer the sign confirm |
| `SIGN_UNKNOWN_TYPE` | `payload_type` not on the decoder allowlist (blind-sign refused) |
| `SIGN_BAD_PAYLOAD` | known type, but the payload did not decode for display |
| `SIGN_NO_CONFIRMER` | no desktop session — native confirm unavailable (headless fail-closed) |
| `LOCKED` | the active profile could not be unlocked (wrong passphrase / failed biometric) |

This taxonomy is the byte-identical cross-repo contract the **extension** (SIGN-4) and any in-process
browser equivalent build against; the wire frames (§5.6.2–5.6.5) and codes above MUST match on both
sides.

---

## 6. NC compliance (the MUST-DO ledger)

dig-app is the component that satisfies these ecosystem MUST-DO items (see the `normative-contract`
skill; some are CLAUDE.md §5 hard rules):

- **NC-2 — at-rest encryption to the user key.** Every per-profile blob (§3.4) is DIGOP1-sealed under
  a per-profile DEK rooted at the unlocked user key. The `.dig` content cache is **exempt** (§3.4,
  ecosystem §5.1: public, on-chain-anchored, permanently readable).
- **NC-3 — user AppData.** All user data lives in the interactive user's AppData (§3.4 table), never
  in a machine/SYSTEM profile. Because dig-app runs AS the user, there is no cross-profile write and
  no systemprofile ambiguity.

When a work unit satisfies an NC item, it MUST update that item's "Satisfied by" link in the
`normative-contract` skill in the same unit of work.

---

## 7. Security properties

- **Transport = mTLS for node-class clients.** dig-app (and `dign`, and any filesystem client holding
  a DIG identity key) connects to a node over mTLS, presenting a client cert derived from the profile
  identity key (§5.3 ecosystem contract). Applies to all three ladder tiers.
- **End-to-end sealing on directed channels.** Any message dig-app sends to an intended recipient over
  a channel an intermediary could terminate MUST be sealed to the recipient's dig-identity encryption
  key (slot `0x0011`) *on top of* mTLS (ecosystem §5.4). mTLS authenticates the pipe; the payload is
  sealed so a relay/intermediary sees only ciphertext.
- **Threat model (summary).**
  - A non-admin user U2 cannot read U1's data — U1's per-profile AppData is ACL'd to U1, the
    pipe/socket ACL is per-user, and the engine opens a session only for a profile the caller can
    sign for.
  - **At-rest theft of a raw disk artifact yields only DIGOP1 ciphertext** — the sealed file's bytes
    are ciphertext, and its passphrase is never persisted. On the Windows/macOS OS-store path the
    access control is the store's per-application ACL: defeating that ACL and dumping the entry yields
    the blob AND its co-located unlock password together (so that path relies on the OS ACL, not on
    the password being a separate secret; splitting them is a follow-up hardening). On Linux the
    custody primary is the passphrase-sealed file, so at-rest theft there yields ciphertext whose
    passphrase the attacker does not hold.
  - Engine/service compromise does not yield user keys — the engine never holds them. Worst case, a
    SYSTEM attacker abuses an *attached* session's proxied capabilities while that user is logged in;
    it cannot exfiltrate the key or act for a logged-out profile.
  - **Accepted (out of scope):** malware running AS U1 can drive dig-app / read U1's decrypted
    in-memory data; a live-session SYSTEM compromise sees that session's in-memory key while attached.
    These are the-user-is-the-user / SYSTEM-dominates cases.

### 7.1 The paired-loopback signing channel (§5.6)

The loopback identity endpoint is a wallet-drain surface, so its authorization is layered (§5.6.1) and
the native confirm is the terminal, un-bypassable gate. Threats and their mitigations:

| Threat | Mitigation |
|---|---|
| **Auto-sign** — a local process silently drives a sign | The native confirm + biometric is mandatory on every sign (the production `SignPolicy`; no default-allow); loopback-only bind + Host/`Origin`/token-MAC guards reject an unpaired caller. |
| **Clickjack / spoofed confirm** — the page overlays or synthesizes a click on the confirm | The confirm is a real OS-drawn foreground window owned by the tray process, outside the browser DOM; it requires an explicit biometric/passphrase action (not an injectable keypress) and is rate-limited. |
| **Blind-sign / cross-protocol oracle** | Sign ONLY the domain-separated `DIGNET-SIGN-v1` message (§5.6.5), never raw bytes; unknown/undecodable `payload_type` ⇒ refuse (`SIGN_UNKNOWN_TYPE`/`SIGN_BAD_PAYLOAD`); the decoded tx is displayed. |
| **Origin spoof** — loopback cannot authenticate the caller | The extension supplies the browser-committed true origin over the paired channel; only the one paired extension is trusted; the confirm shows the vouched origin. |
| **DNS-rebinding** | Loopback bind + strict `Host` allowlist + `Origin` pin (§5.6.2). |
| **Rogue extension self-pairs** | Pairing is a one-time native confirm gated on biometric; the `Origin`/`ext_id` is pinned to the DIG extension id; no silent self-pair. |
| **Token theft / replay** | 32-byte CSPRNG channel token, sealed at rest (DIGOP1) + in `chrome.storage.local`; every frame is HMAC'd over a strictly-monotonic nonce (bars replay); the token grants channel access only — the terminal native confirm still binds every sign; revocable via unpair. |

**Accepted (out of scope), in addition to §7's cases:**
- A **compromised paired extension** can send truthful-looking requests with arbitrary payloads, and
  could lie about the origin — it is trusted-once to vouch for origin. It still cannot sign without the
  human confirm; the mitigation is fully decoding the tx + showing "via paired extension" so the human
  catches a mismatch.
- A user who **physically approves a malicious prompt** at the biometric gate. dig-app defends against
  silent/auto sign, not against a user who reads the decoded tx + origin and approves anyway.

---

## 8. Public API surface (crate `dig-app-core`)

dig-app-core is the identity-agent library; the `dig-app` and `dign` binaries are thin shells over it.
The U1 skeleton fixes the module boundaries + the small set of pure helpers the architecture needs
day one; the security-critical subsystems are implemented by later work units to this spec.

| Module | Responsibility | Status |
|---|---|---|
| `identity` | the two-identity model (`IdentityKind`: transport-peer vs user) | U1 (types) |
| `form_factor` | tray-vs-headless detection (`FormFactor::detect`) | U1 |
| `storage` | per-OS AppData layout (`brand_data_dir`, `profile_dir`) — NC-2/NC-3 | U1 (paths) |
| `ipc` | per-user IPC endpoint resolution (`channel_endpoint`) | U1 (addressing) |
| `environment` | resolved per-user host facts (`AppEnvironment`) all boot decisions derive from | U3 |
| `config` | the agent's non-secret on-disk runtime settings (`AgentConfig`, AppData; plaintext pre-U4) | U3 |
| `engine` | engine connection state + reachability probe (`EngineConnector`, `EngineState`) | U3 (probe; real session U6) |
| `shutdown` | the cooperative shutdown latch (`Shutdown`) that stops the run loop promptly | U3 |
| `agent` | the per-user agent lifecycle: start/stop, reconcile run loop, live `AgentStatus` | U3 |
| `keystore` | hold / unlock / sign; DIGOP1 sealing; rotation; OS-credential-store primary + sealed-file fallback | U4 |
| `profiles` | multi-DID create/select/list/edit via dig-identity; per-profile sealed AppData | U5 |
| `wallet` | per-profile wallet host | post-U5 (stub) |
| `gateway` | route each command (local vs proxy-to-engine) + dispatch over the `EngineProxy` / `LocalIdentity` / `LinkOpener` seams; catalogued `ErrorCode` + `--json` envelopes | U7 |

The `dig-app` binary is the tray / menu-bar shell over the `agent` core (Windows system tray · macOS
menu-bar · Linux AppIndicator) and **degrades headless** (§4) when no display is present or the tray
cannot mount; the tray is the crate's default `tray` feature, so a headless build omits the desktop
stack entirely. U3 delivers `environment`/`config`/`engine`/`shutdown`/`agent` + the shell; the
agent reaches the engine through the `EngineConnector` seam so U6 slots in the real
identity-authenticated session without reshaping the run loop.

The engine-side of the IPC contract (the `control.session.*` methods + the `sign` callback) is
implemented in the dig-node repo (U2/U6), not here.

---

## 9. Release engineering

dig-app is a `modules/apps` repo and follows the ecosystem **nightlies** release model (CLAUDE.md
§3.6-A), uniform with dig-node:

- **Nightly (the only automatic tag):** a midnight-UTC cron cuts one pre-release per night — a dated
  `nightly-YYYYMMDD` + a rolling `nightly` (keep-14 retention), built from `main` HEAD with a
  synthesized `X.Y.Z-nightly.YYYYMMDD.<shortsha>` version. The cron NEVER cuts a stable tag.
- **Nightly test-gate (dig_ecosystem#906):** the nightly build+publish depends on a test-gate job
  (full test suite + the >=80% coverage gate); no nightly ships unless it is green.
- **Stable (manual only):** a `vX.Y.Z` tag is cut only by a manual `workflow_dispatch (channel:
  stable|both)` on `main`; it never auto-cuts. `force` refuses to move a *published* tag onto a
  different commit (same-commit re-cut / bare-tag repair only, fail-closed on a transient lookup
  error).
- **Artifacts:** for every supported OS/arch, both first-class binaries — `dig-app` (tray/agent
  shell) and `dign` (CLI) — under the canonical stem `<bin>-<ver>-<os>-<arch>[.exe]`. Richer OS
  packages (Windows tray installer / macOS `.pkg` / Linux `.deb`) are produced by the dig-installer
  wiring (a separate work unit) consuming these binaries.
- **Tags via `RELEASE_TOKEN`** (a classic PAT), not `GITHUB_TOKEN` — a `GITHUB_TOKEN`-pushed tag does
  not trigger the deploy-on-tag workflow, and the changelog commit must pass branch protection. The
  full release-gate set (fmt, clippy `-D warnings`, tests + coverage >=80%, build, commitlint,
  version-increment) is required on every PR.

---

## 9a. Logging — structured JSONL file + human stderr (#934)

dig-app adopts the shared `dig-logging` building block (`dig-logging` crate, `dig_ecosystem` #547),
so its sink layout, JSONL schema, log directory, rotation, level control, and correlation ids are
byte-identical to every other DIG service binary (`dig-node` SPEC §20 is the sibling contract).
`dig-logging`'s own `SPEC.md` is normative for the shared mechanics; this section records what
dig-app MUST do.

- **Where the subscriber is installed.** `dig-app-core` depends on ONLY `tracing` (the facade) —
  never `dig-logging` — mirroring the `dig-node-core`/`dig-node-service` split, so the identity-agent
  library stays subscriber-agnostic. The `dig-app` tray/headless shell installs the shared subscriber
  once, at the top of `main`, as run context `service` (it is a long-lived per-user background
  agent, not a one-shot invocation) and holds the guard for the process lifetime. `dign` — a
  short-lived CLI — installs it as run context `cli` at the top of its own `main`, resolving the
  SAME per-user log directory `dig-app` writes to (`dig-logging` SPEC §3), so the two processes'
  records interleave in one place. A logging-install failure is reported on stderr and swallowed —
  it MUST NOT stop the agent from starting.
- **Levels — used by MEANING, not uniformly.** `error!` a broken invariant; `warn!` a denied `sign`
  callback, a failed unlock, a rejected profile create/select (duplicate/invalid DID, not found), or
  a failed engine-proxy call; `info!` sparse lifecycle (agent starting, engine endpoint resolved,
  session attach/detach, identity sealed/unlocked/removed, profile created/selected, boot re-unlock
  complete); `debug!` per-command routing (the gateway's local-vs-engine classification, `dign`'s
  dispatch). The default filter is `dig-logging`'s noise-trimmed `info`.
- **Never-log at source.** No secret — a passphrase, a raw identity/session key, a `sign` callback's
  raw payload or produced signature, a sealed blob — is EVER passed to a `tracing` field or message,
  at any level. Only public/opaque handles are logged: a DID (already public on-chain), a `did_hash`
  (a one-way, non-reversible profile handle), a `session_id`/`op_id`, an `UnlockSource` variant, and
  catalogued `ErrorCode`s. This is enforced by a never-log regression suite
  (`crates/dig-app-core/tests/never_log.rs`) that captures real emitted records with a sentinel
  passphrase live in scope and asserts it never appears — mirroring the dig-node #553 guarantee.

---

## 10. Conformance tests

A conformant implementation MUST include tests asserting:

1. **Identity split** — the engine holds no user key (no code path stores/receives a user private
   key); the transport peer-identity stays engine-side.
2. **At-rest ciphertext** — every sealed per-profile blob is DIGOP1 ciphertext on disk; the `.dig`
   cache is plaintext in the machine cache dir.
3. **Cross-user denial** — U2 cannot read U1's AppData nor attach U1's profile.
4. **Per-OS AppData layout** — `brand_data_dir` resolves the correct directory per OS; per-profile
   subdirs are isolated by DID hash.
5. **IPC addressing** — `channel_endpoint` yields the correct per-user named pipe / socket path;
   distinct users get distinct endpoints.
6. **Headless degrade** — no display ⇒ `FormFactor::Headless` (no tray); a display ⇒ `Tray`.
7. **Signing-through-dig-app** — an engine-initiated `sign` callback (§5.3) is answered by dig-app and
   the key never crosses the IPC boundary.
8. **Multi-user concurrent sessions** — two attached sessions for different profiles coexist, each
   with its own `session_id` in the engine's session map (§5.3), and a `sign` callback routes to the
   owning connection.
9. **Never-log at source** — a captured, real emitted-record test proves a passphrase live in scope
   during a vault create/unlock never reaches a logged field or message (§9a).

U1 ships tests (4), (5), (6) and the `IdentityKind` predicate for (1); the remaining tests land with
the work units that implement their subsystems.

---

## Appendix — work-unit map (epic dig_ecosystem#908)

| WU | Deliverable |
|---|---|
| **U1** (this repo, spec + scaffold) | this `SPEC.md` + the gated Cargo workspace + apps-repo release pipeline |
| U2 | engine minimization (dig-node): machine content-cache + bootstrap config; move user identity OUT, retain transport peer-identity |
| U3 | dig-app agent core + tray shell |
| U4 | key management (hold/unlock/sign, DIGOP1, rotation) — security-critical |
| U5 | profiles (multi-DID via dig-identity) — security-critical |
| U6 | identity-authed session IPC + sign-callback + multi-session + headless — security-critical |
| U7 | CLI/RPC gateway (`dign` + RPC route through dig-app) |
| U8 | dig-installer wiring (engine daemon + per-user agent autostart) |
| U9 | migration of the legacy single-identity install into a sealed default profile |
| U10 | coherence: SYSTEM.md + canonical + docs.dig.net + runbooks + NC "Satisfied by" links + regression tests |

[dig_ecosystem#908]: https://github.com/DIG-Network/dig_ecosystem/issues/908
[dig_ecosystem#771]: https://github.com/DIG-Network/dig_ecosystem/issues/771
[dig_ecosystem#856]: https://github.com/DIG-Network/dig_ecosystem/issues/856
[dig_ecosystem#906]: https://github.com/DIG-Network/dig_ecosystem/issues/906
[dig_ecosystem#950]: https://github.com/DIG-Network/dig_ecosystem/issues/950
