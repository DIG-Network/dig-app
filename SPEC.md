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

On disk the profile set splits into two tiers: a **plaintext registry** (`<brand-dir>/profiles/registry.json`
— the active-profile pointer plus a non-secret record per profile: its DID, its two public keys, the
paired store id, and a cached display name) so the app can list profiles and restore the active one
*before any profile is unlocked*; and a **sealed per-profile blob**
(`<brand-dir>/profiles/<did-hash>/identity.seal` — the persona metadata cache, subscriptions, and
per-profile prefs), DIGOP1-sealed under that profile's own DEK. Every per-profile secret blob is sealed
with the owning profile's key and no other, so opening one profile's blob under a different profile's
DEK MUST fail — profiles are cryptographically isolated on disk. Because each profile's DEK is
HKDF-derived from that profile's own freshly generated identity key (§3.1), the isolation holds by the
cipher, not by directory layout. The registry is the sole pointer to every profile's directory, so it
MUST be written durably and atomically (temp file → fsync → rename), the same way the sealed identity
blob is (§3.1); a torn write can never strand a profile's data. dig-app holds no private key while doing
this: sealing is delegated to the key-management layer (§3.1), and minting the DID + generating the keys
is delegated to the keystore + wallet/engine. Editing a profile updates the sealed metadata and
recomputes the canonical dig-identity SMT root; broadcasting that root on-chain (chip35 delegation) is a
wallet/engine operation.

### 3.3 Wallet

The wallet is user-identity state and lives in dig-app (migrated out of the engine). Spend bundles
are built via the canonical wasm spend builders / chip35 delegation and **signed locally**; the
finished bundle is handed to the engine to broadcast. Wallet state is DIGOP1-sealed per profile.

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
| `gateway` | authenticate callers + route (local vs proxy-to-engine) | U7 (stub) |

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
