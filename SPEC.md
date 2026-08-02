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
its single identity key: the **BLS12-381 G1 identity key** (dig-identity slot `0x0010`, the v2 key
model), which both **signs** (BLS G2 AugScheme) and is the **seal DH key** (G1 ECDH for end-to-end
sealing) — there is no separate encryption key (the v1 X25519 slot `0x0011` is retired). Plus the
wallet and the profile's data. It lives only in dig-app, sealed at rest to the user key.

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
account master seed:

1. **Bootstrap unlock** — a DIGOP1 password. On Windows/macOS it is held in the per-application OS
   keychain (Windows Credential Manager / macOS Keychain), released by the login session with no
   prompt; a passphrase prompt is the fallback. On Linux it is a user passphrase (the keyutils keyring
   is not a safe custody store — §3.1). It opens the account's sealed **master seed** — the sole
   at-rest secret.
2. **Master seed** — the unlocked account root. Every profile's identity key AND its DEK are derived
   from it at that profile's HD index (`ProfileIx`); no per-profile secret is stored.
3. **Per-profile DEK** — HKDF-derived from the profile's derived identity, sealing every other
   per-profile blob. Profiles MUST NOT share a DEK.

**Custody root: the master-HD account (`dig-account`).** The custody object model — enrol/unlock,
the keystore crypto, per-profile identity signing + DEK derivation, and the wallet money path — is
owned by the **`dig-account`** crate and consumed here (never re-implemented). The at-rest ROOT is a
SINGLE account **master seed**, sealed in a per-user file backend under a **user-chosen password**
(§3.2a), and from which every profile's
identity key AND its DEK are derived at that profile's HD index (`ProfileIx`). This REPLACES the
retired model in which each profile held an independently-generated random identity scalar. The
sealing container (DIGOP1) and the DEK derivation contract (HKDF-SHA256 over `DEK_SALT` /
`IDENTITY_IKM_VERSION` / `PROFILE_DEK_LABEL`, from `dig-constants`) are UNCHANGED — only the seed
SOURCE moved (random-per-profile → master-seed-at-index). The unlocked account is housed in a
harness-side lockable RESIDENCY that hands out live-view signer + sealer capabilities: a session lock
(idle timeout / lock-now / OS screen lock) drops the residency and thereby relocks the running sign +
seal paths at once. **Migration is a clean pre-release cutover** (§ back-compat): because a master
seed cannot reproduce a pre-existing random per-profile scalar, no byte-identical DEK exists to carry
an old at-rest profile onto a seed index — and dig-app is pre-release with no persisted users, so old
per-profile-scalar identities are abandoned rather than migrated. The master seed is NOT drawn
directly from the CSPRNG: it is the entropy of a 24-word BIP-39 **recovery phrase** (§3.1a), which is
what makes an account portable. The on-chain profile DID mint is a later phase; until it lands a
profile is identified by its seed-derived identity public key, and minting is NEVER automatic (§3.1b).

Signing happens in-process (§2.3). Identity rotation re-derives the DEK and re-seals all of that
profile's blobs in one transaction (DIGOP1 is versioned; a store-version header drives migration).

**Identity key.** A profile's identity is ONE `dig-identity` standard key: the **BLS12-381 G1**
identity key (slot `0x0010`, the v2 key model). The single 48-byte compressed G1 public key's private
scalar does BOTH jobs — it signs (BLS G2 AugScheme) and is the DH key for end-to-end sealing (G1
ECDH via `dig_identity::g1_dh`) — so the v1 X25519 encryption slot `0x0011` is retired. The scalar is
**derived, never stored**: `dig-account` derives it from the unlocked master seed at the profile's HD
index (`ProfileIx`) on demand, holds it in memory only while the account is unlocked, and zeroizes it
on relock. The ONLY at-rest secret is the account master seed, DIGOP1-sealed by `dig-account`; no
per-profile identity scalar is serialized. A legacy v1 (Ed25519+X25519) identity is non-convertible to
the v2 key model and is re-provisioned, never reinterpreted (§ back-compat is a clean pre-release
cutover).

**Domain-separation invariant (MUST).** Every signature the slot `0x0010` identity key produces MUST
carry a unique per-purpose ASCII domain-separation tag as the first bytes of the signed message; no
purpose ever signs un-prefixed caller/peer bytes. Distinct purposes MUST use distinct tags (e.g.
`DIGNET-SESSION-v1` for the session-attach challenge §5.3, `DIGNET-SIGN-v1` for the engine `sign`
callback §5.3, `DIGNET-USER-SIGN-v1` for the local `dign sign` §3.5). This makes a signature minted
for one purpose provably non-verifiable for any other,
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
   (a plain reboot would destroy the only copy of the sealed seed, and the machine-held unlock password with it — see §3.1a: the recovery phrase, not the sealed blob, is what survives losing a machine). The
   passphrase-sealed file is persistent, home-ACL'd, and — needing a user passphrase — not
   harvestable by a background same-UID process. It is also the fallback anywhere the OS credential
   store is unusable (a headless server, a minimal container).

The precedence is detected once at vault-open time. Unlock **fails closed**: a wrong passphrase, a
tampered blob, or a foreign key yields an opaque error that never distinguishes the cause and never
produces partial plaintext.

### 3.1a The recovery phrase (normative)

An account's master seed MUST be the entropy of a **24-word BIP-39 mnemonic**, the account's *recovery
phrase*. The phrase is the ONE portable custody root: the sealed seed blob is openable only on the
machine whose credential store holds its unlock password (§3.1), so the words are the only thing a user
can carry to a new machine.

- **Mapping.** A 24-word phrase carries exactly 32 bytes of entropy, which IS the `SEED_LEN` master
  seed, taken verbatim. Phrase to seed is therefore a lossless bijection, and a restore reaches the
  identical identity, wallet key and per-profile DEK with no stored state whatsoever.
- **NOT the Chia mnemonic derivation.** Chia wallets map a phrase to a key through the 64-byte PBKDF2
  seed of BIP-39 §5. DIG uses the entropy directly, so the SAME phrase yields a DIFFERENT address in a
  Chia wallet than in DIG. A DIG recovery phrase MUST NOT be presented to the user as importable into a
  Chia wallet, nor a Chia wallet's phrase as importable here.
- **Enrolment order (MUST).** A first run MUST: generate the phrase, display it once, obtain an explicit
  confirmation that the user has retained it, and only then enrol. A declined or unshowable phrase MUST
  leave NOTHING enrolled; an implementation MUST NOT create an account whose phrase was never seen.
- **Re-reveal (MUST).** An enrolled account MUST be able to display its phrase again, gated on BOTH the
  account being unlocked AND a fresh OS re-authentication, and the gate MUST run BEFORE the phrase is
  decrypted. The phrase is stored for this purpose sealed under the ROOT profile's DEK.
- **Restore (MUST).** An account MUST be restorable from its phrase alone on a host with no prior state,
  reachable BOTH at first run (§3.2b) and from the tray. Restoring MUST refuse when an account already
  exists, rather than overwriting a custody root.
- **Backup (MUST).** An enrolled account MUST be able to back up its phrase — copy it to the clipboard,
  and optionally save it to a plain `.txt` file (`account::journey::back_up_phrase`). A backup is gated
  IDENTICALLY to a re-reveal (unlock AND a fresh OS re-authentication, the gate running BEFORE the phrase
  is decrypted) AND is preceded by a stark, destination-specific warning that the words will sit in the
  clear where any app or person with access can take the account; refusing the warning MUST decrypt
  nothing. The words MUST flow only through the zeroizing path — wiped after the single delivery — and
  MUST NOT be logged; the egress MUST NOT retain them. After a clipboard copy the shell SHOULD schedule
  a best-effort auto-clear (`CLIPBOARD_CLEAR_DELAY`, ~45s): it clears the clipboard only if it still
  holds the copied bytes, matched by a retained SHA-256 fingerprint — NEVER the plaintext, which stays
  wiped. This reduces, not eliminates, exposure (clipboard history/sync may retain a copy), and the
  warning copy MUST disclose it honestly.
- **Handling (MUST).** The phrase MUST NOT be logged, serialized, transmitted, or written anywhere but
  its sealed vault. It is held in zeroizing memory, redacted in debug output, and reaches only an
  OS-owned foreground window.
- **Accounts enrolled without a phrase.** An account whose seed predates this section has NO phrase and
  its words CANNOT be reconstructed. Such an account MUST be reported to the user as unrecoverable, and
  MUST NOT be silently re-enrolled: replacing it destroys its identity, address and sealed data, so it
  requires an explicit, separately-confirmed user action.

### 3.1b On-chain DID minting (normative)

Minting a profile's `did:chia:` DID is a real Chia mainnet transaction that spends real funds. It is
therefore **never automatic**: an implementation MUST NOT mint a DID during enrolment, boot, or any flow
the user did not explicitly initiate for that purpose, and MUST show the cost before spending. A DID is the bedrock of a DIG Account and is a REQUIRED step, not an optional
extra: an implementation MUST NOT describe an account without one as complete, and MUST NOT tell the user
their account "fully works without a DID". Until one is minted a profile is identified by its
seed-derived identity public key (§3.1), and the account is reported as
`AccountCompleteness::WalletOnly` — a wallet that holds funds, signs and reads content, but is not the
finished article.

The reported DID state MUST rest on evidence that a DID was actually minted on chain. A locally-written
value that merely has DID-shaped text in it — a profile reference, a config entry — MUST NOT be reported as
an on-chain DID, because doing so tells the user they have a published, verifiable identity they do not
have.

**Current state:** minting is not implemented, so no profile can have a DID and there is no tray action that
mints — the menu offers an EXPLANATION of what a DID is and costs instead (§3.1c). The absence is
structural: no `TrayAction` mints, so it cannot be re-enabled by accident.

Because that absence is universal and permanent for this version, "no DID yet" MUST NOT be modelled as an
`AccountState` (§3.1c): every account on every host would sit in it for ever, with no control that could
ever leave it, which would make the lock states lie. It is reported as completeness
(`account::journey::AccountCompleteness`) — a fact about the account — and the first-run flow (§3.2b)
names the DID as the remaining REQUIRED step while stating plainly that it cannot be taken yet.

### 3.1c The tray account surface (normative)

The tray is the only surface a person has on a fresh install, so it MUST expose the whole account
journey, not merely lock and quit. The menu is built from ONE pure model (`dig_app_core::tray_menu`) so
these rules are testable independently of any desktop.

**A menu item is an ACTION (MUST).** A native menu offers only clickable items, separators and submenus, so
read-only text can be rendered ONLY as a disabled item — and a disabled item means *"something you cannot do
right now"*. Using disabled items as labels therefore tells every new user the application is broken. The
menu MUST NOT contain a row whose only purpose is to display text; the model has no variant that could
(`MenuRow` is a separator, an action or a submenu).

State lives on the tray's other two surfaces plus one window, all three built from the SAME snapshot as the
menu so they can never disagree:

| what the user needs to know | where it MUST live |
|---|---|
| connected / locked / not-set-up / starting | the tray ICON, as a distinguishable per-state image |
| the one-line summary | the tray TOOLTIP, bounded and visibly marked when cut |
| everything, in full and untruncated | a `Status and details…` window, enabled in EVERY state |

The ICON MUST NOT be the only signal for a state: the tooltip MUST name the same state in words, so a user
who cannot distinguish the icons — or whose theme flattens them — still has the fact (§6.6).

The menu MUST offer actions to: show the status details, set up an account, restore from a recovery phrase,
unlock, lock now, reveal the recovery phrase, back up the recovery phrase (copy it to the clipboard, and
save it to a file — §3.1a Backup, offered only on an unlocked recoverable account), copy the DIG ID, copy
the receive address, show the wallet,
replace the account (with a new one, or with one from a recovery phrase), remove the account, explain an
account that cannot be opened, explain the on-chain DID, open the log folder, and quit.

**The Wallet surface (MUST).** The Wallet submenu offers the receive address and a wallet window, and
nothing that moves money — no tray action spends, so the absence of `Send` is structural rather than an
`enabled: false` (§3.3, the money path). Binding rules:

- The copied address MUST be the account's derived `xch1…` money address (§3.3's wallet key), never the
  profile's identity public key. Funds sent to a well-formed address for the wrong key are unrecoverable,
  so the derivation MUST be pinned against an independent derivation of the same seed.
- A receive address is PUBLIC, so a state that merely WITHHOLDS the key — locked, or never given a
  password — MUST still show the row, disabled, with its label naming that state's own remedy. Where no
  address can exist at all — no account, or an account that cannot be opened — the row MUST be omitted and
  the wallet window MUST explain the situation.
- **A balance that could not be read MUST NOT be rendered as a zero.** The surface MUST distinguish a
  balance READ from a chain source (where `0` means nothing is held) from one that is UNKNOWN, and every
  unknown MUST name which thing is missing — no address, no node, a node that does not serve wallet reads,
  a source still syncing, or a read that failed. Showing a zero for an unreadable balance is how a person
  concludes their funds are gone, and is forbidden.

The account has SIX user-visible states, and an implementation MUST distinguish all of them: this host cannot
hold an account · no account yet · locked · **cannot be opened** · unlocked · unlocked with no recovery
phrase. The fourth is the one most easily and most damagingly collapsed into "locked" — see the rule below.
The top level MUST stay short; rare and destructive verbs belong in a submenu, not beside `Lock now`.

Minting an on-chain DID is deliberately NOT among them: no implementation exists (§3.1b), so the menu
offers an EXPLANATION of what a DID is and costs, and there is no tray action that mints — the absence is
structural, not an `enabled: false` that a later change could flip on by accident.

Binding rules:

- **Boot MUST NOT enrol.** Creating an account displays a recovery phrase, and a phrase window that
  appears unbidden at login is a window people dismiss. An account is created only by an explicit user
  action, so a host with no account boots to a tray offering to set one up.
- **Account management MUST be reachable in EVERY state (MUST).** Creating an account, replacing the one
  that is here (with a new account, or with one restored from a recovery phrase), and removing it MUST all be
  reachable whenever the host can hold an account — never gated on there being no account. Gating them on
  absence is the defect this rule exists to forbid: on a measured install with an account that had no
  recovery phrase, set-up, restore and reveal were all disabled and the one live row explained that the
  remedy was a new account, which nothing could create. A user MUST NOT have to edit files to change which
  account is on their computer.
  Each verb is gated on its REAL precondition, which is whether an account EXISTS — that decides whether the
  verb creates or REPLACES, and therefore what its label must say. A verb with nothing to act on (removing an
  account on a host that has none) is OMITTED, not disabled.
- **A destructive account verb MUST be authorized, not merely confirmed (MUST).** Replacing or removing an
  account discards its master seed and makes everything sealed under it unreadable. Each MUST therefore go
  through the same two-step AUTHORIZATION gate as a signature — a foreground window naming the irreversible
  loss, then an OS re-authentication (§5.6.1) — and MUST NOT be drawn as a notice (one button, no decision)
  or as a claim (two buttons, no biometric). Before the point of no return the flow MUST offer to display the
  account's recovery phrase where one exists, and where a replacement phrase is being supplied it MUST be
  collected and validated BEFORE anything is destroyed. The verb's own LABEL MUST say "Replace" or "Remove",
  and it MUST NOT be the default or an accidental path.
- **Never trap the user.** "Quit" and the log folder MUST be enabled in EVERY state, including when the
  account is unsupported, absent, locked, or broken. No state may leave the menu with nothing actionable.
- **Say the true state.** An account with no recovery phrase MUST be labelled as such in the account
  status line AND offered the explainer, and MUST NOT be shown an inert "show my recovery phrase" item.
  An action whose precondition is unmet is shown DISABLED rather than hidden, so the capability's
  existence is discoverable — **but only when the label can say WHY.** A disabled row with no reason in it
  is a small unexplained mystery; where there is no reason worth printing, the row MUST be omitted instead.
  A disabled row MUST also sit beside an ENABLED row that resolves it, so no state is a dead end. Five rows
  currently qualify: setting up an account on a host with no per-application credential store, plus
  revealing the recovery phrase and copying the receive address in each of the two states that withhold key
  material — locked (remedy: `Unlock…`) and never-given-a-password (remedy: `Set a password…`). A disabled
  row's label MUST name the remedy that state actually has: offering "unlock first" to an account that has
  never had a password names a control that cannot help.
- **Every ENABLED item MUST be able to perform what its label says (MUST).** This is the strong form of the
  rule above, and it binds two cases that are easy to get wrong:
  - A capability that does not EXIST YET is either absent or shown DISABLED **with the reason in its
    label**. It MUST NOT be enabled and handled by a dialog that apologises for the feature's absence: an
    enabled control that cannot act reads as a broken application, which is worse than an honest gap.
  - **No row may defer to a terminal (MUST).** A tray menu having no text field is a property of the tray
    API, not a reason to hand the user off: an input need is met by raising a native input window from the
    tray (§3.1d). A row labelled "(in a terminal)" is not an acceptable end state even though it is honest,
    and on a host where another component owns the `dign` name on the shared bin directory it hands the user
    the WRONG TOOL. No label may name a terminal, a console or a command to run.
- **No menu action may run on the tray's event loop (MUST).** Menu handlers open windows, wait for the OS
  authenticator, wait for the agent to stop, and wait on child processes; a handler running on the event
  loop makes every one of those a frozen tray, and the biometric case a permanent deadlock. Actions
  therefore run on a worker, and the loop hands one off without waiting. It follows that:
  - **Exactly ONE action runs at a time**, and an action chosen while another is in flight is REFUSED, not
    queued: two clicks at a tray must never open two destroy flows, and an impatient second click is
    answered by the dialog already on screen.
  - **The tray stays live while a dialog is open** — its icon, tooltip and menu keep working — and reading
    the session for a repaint MUST NOT wait on the action holding it; a repaint is skipped instead.
  - **Only the event loop may exit the app.** A quit handler reports its decision back to the loop.
  - **A handler that panics costs one action, not the tray**, and MUST NOT be read as a request to quit.
- **The TOOLTIP MUST be bounded, and bounding MUST NOT lose information (MUST).** The Windows notification
  area truncates its tooltip silently, so an unbounded one is cut at an arbitrary point with no sign anything
  is missing. The tooltip MUST therefore be bounded to a single-line budget and visibly marked when cut, and
  the full text MUST be reachable through the always-enabled `Status and details…` window. This matters most
  for the node connection line, whose disconnected reasons are deliberately verbose and actionable — a real
  one names the token file to create and the reinstall to run, and runs to hundreds of characters, which no
  menu row or tooltip could ever hold. The details window MUST read the state LIVE at the moment it is
  requested, not replay the snapshot the menu was built from, so a node that came up while the menu was open
  is reported as connected.
- **Read the lock state from the KEYS, never from the session (MUST).** A session deliberately outlives
  its key material — lock-now and the idle auto-lock drop the keys and keep the session so the sign path
  can re-unlock into it. The reported state MUST therefore be derived from whether key material is held
  RIGHT NOW; a session with no keys is `Locked`, identically to a not-yet-unlocked account, so the way
  back in (`Unlock…`) is the same. Inferring "unlocked" from the session's existence reports a lock that
  is not there and offers no route out of it.
- **An account that cannot be OPENED is `Unopenable`, never `Locked` (MUST).** These are different
  situations and MUST NOT be collapsed: a locked account has a way back in (`Unlock…`), and an unopenable one
  does not, so reporting it as locked offers a control that is guaranteed to fail and says nothing about why.
  The distinction is not hypothetical — every Windows/macOS host that has run dig-app auto-enrols the default
  account at first boot, so legacy raw-seed blobs exist in the field, and a custody model that can no longer
  read them leaves such an account WEDGED: it neither unlocks nor re-enrols at the same id. An implementation
  MUST therefore carry a multi-state at-rest fact (no account / present / present-but-unopenable /
  present-under-a-machine-password) rather than a boolean, and the tray MUST name the state on the surfaces a person looks at — the icon, the tooltip and
  the details window — never only in a log record. Reducing this to a log line costs the user signing
  permanently and silently, which is the defect the state exists to prevent.
  - **The state offers the remedy, and nothing else.** `Unopenable` MUST offer an explainer naming the
    situation and the exact menu path to replacing the account, and MUST NOT offer `Unlock…` (it is what
    already failed) or the recovery-phrase reveal (its vault is sealed under the same unreadable key). The
    replace and remove verbs MUST be enabled, because this is the state a user most needs to escape.
- **An account with no USER password is `NeedsPassword`, never `Locked` (MUST).** An account still sealed
  under a machine-generated password (§3.2a) opens perfectly well — which is precisely the problem — so it
  is not `Unopenable`; and offering `Unlock…` would ask for a password its owner has never chosen, so it is
  not `Locked` either. The one honest offer is to SET a password, and the state that produces that offer
  MUST exist. In this state the tray MUST NOT offer `Unlock…`, MUST NOT enable the recovery-phrase reveal,
  and MUST offer the re-seal (§3.2a) as the top-level contextual row.
  - **The state is STICKY until an open SUCCEEDS.** It MUST NOT clear on a repaint tick, or the tray flickers
    back to reporting a lock that cannot be lifted. It MUST be cleared at exactly one place — the moment a
    live session exists — and the no-account case MUST be evaluated BEFORE it, so a successful removal reports
    "not set up yet" rather than a stale unopenable.
  - **Reaching the state MUST delete nothing (MUST).** Detecting an unopenable account, reporting it, and
    showing its explainer MUST leave the sealed blob, the credential-store entry and any sealed artifacts
    exactly as they were — the only path that removes them stays the authorized destroy (§3.1c above). The
    explainer's copy promises the user precisely this ("Nothing has been changed or deleted"), so the promise
    is a contract, not an implementation detail that may be refactored away.
- **Price before the click.** An action that spends funds MUST name the cost in its LABEL, not only in a
  confirmation dialog (§3.1b).
- **A tray that cannot mount MUST report itself.** On Linux the indicator library is dlopened, so a
  missing library is discovered at run time rather than at link time. The shell MUST log the failure and
  print the likely cause plus the remedy, because an invisible tray is otherwise indistinguishable from a
  broken application. The message MUST NOT point at `dign` as the way in: on a host where another component
  owns that name on the shared bin directory it names the wrong tool.
- **A tray that cannot mount MUST NOT take the agent down with it (MUST).** Mounting MUST be guarded
  against a PANIC, not merely against an error return. This is not defensive padding: the Linux
  indicator binding panics inside its `dlopen` when the library is absent
  (`libappindicator-sys`: *"Failed to load ayatana-appindicator3 or appindicator3 dynamic library"*),
  and a panic unwinds past any `Result` the degrade path is written around. Unguarded, a host that is
  merely missing a desktop package loses the tray, the agent, the headless fallback AND the advice
  message — the worst outcome available, from the most common cause. The panic's reason MUST survive into
  the reported cause, because it names the exact libraries that were tried.
- **Every LINK-time desktop dependency MUST be satisfied by packaging, not by advice.** A missing
  link-time library stops the binary before `main`, so no in-app message can help. On a pristine
  `ubuntu:24.04` the `tray` build requires seven such libraries — `libgtk-3.so.0`, `libgdk-3.so.0`,
  `libgdk_pixbuf-2.0.so.0`, `libcairo.so.2`, `libglib-2.0.so.0`, `libgobject-2.0.so.0`,
  `libgio-2.0.so.0` — supplied on Debian/Ubuntu by `libgtk-3-0t64`, `libgdk-pixbuf-2.0-0`, `libcairo2`
  and `libglib2.0-0t64`. Packaging MUST declare the whole set: the dynamic loader reports only the FIRST
  unresolved library, so fixing them one at a time reads as a fresh regression on each attempt. The
  dlopened indicator (`libayatana-appindicator3-1` / `libappindicator-gtk3`) is additionally required for
  the icon to appear, and is NOT visible to `ldd`.
- **The shell binary MUST declare the platform's GUI subsystem (MUST).** On Windows the PE optional header
  MUST report `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2). At `WINDOWS_CUI` (3) the OS allocates a console for a tray
  application: a console window appears at every launch AND the tray's lifetime becomes tied to it, so
  closing that window kills the agent. This binds the tray shell only — a service or CLI binary is correctly
  subsystem 3. The claim MUST be gated by a check that PARSES the produced binary's header, because it rests
  on one attribute that a refactor can drop while everything still builds and runs.
  A GUI-subsystem process has NO CONSOLE, so the informational CLI paths (`--version`, `--help`) MUST attach
  to their launcher's console before printing. That attachment MUST NOT re-point a standard handle that was
  already INHERITED: a redirected stdout is how the update beacon health-probes this component (§4), and
  overwriting it sends the version line to a console nobody is reading.
- **The tray icon MUST be the DIG brand mark, carried inside the binary.** The mark is embedded as PNG
  artwork and decoded to RGBA at mount time; the shell MUST NOT read it from disk or from another
  component's files, so any `dig-app` binary shows the right icon however it was packaged. The shell
  SHOULD embed the artwork size closest to the host's tray paint size rather than downscaling a large
  master, which loses the glyph at tray dimensions.
- **A brand mark that fails to decode MUST NOT prevent the tray from mounting.** The icon is decoration;
  decoding is fallible and its failure MUST be logged and then tolerated, leaving a working, fully
  actionable tray without a picture. A user whose agent refused to start over artwork would be far worse
  served than one whose tray is briefly unlabelled.

### 3.1c-i The global shortcut to the URN bar (normative)

While the tray is mounted on a desktop OS, dig-app MUST offer a **global keyboard shortcut that opens a
floating URN bar** — one keystroke from anywhere to "paste a DIG link and go", because reading content is
the product's core function and needs no account.

- **The bar MUST reach the SAME open path as the tray's `Open URL…` row.** Node check, then
  `validate_open_link`, then the node serve-URL mapping, then the browser, in that order. The scheme
  allowlist is a security boundary (store content is attacker-controlled), so there MUST NOT be a second
  copy of it: the two entry points differ ONLY in how the window is presented.
- **The bar is a PRESENTATION of the native input window (§3.1d), not a second window stack.** Frameless,
  always on top, centred horizontally and placed above the vertical centre, with an enlarged field. It
  MUST be dismissible by Escape AND by losing focus — it has no close box, so a bar that outlived a click
  elsewhere would be a window the user cannot get rid of without answering it.
- **The default chord is `Alt+Space`, and it MUST be user-configurable and persisted.** On Windows this
  DISPLACES the system window menu for as long as dig-app runs; the app MUST disclose that in its status
  surface rather than leaving the user to discover it.
- **A chord MUST include at least one modifier.** A bare key registered globally stops that key working in
  every application on the desktop, so a modifier-less setting MUST be refused with a reason.
- **Registration failure MUST degrade, never fail startup.** A chord another application already holds, an
  unparseable setting, or a platform with no global-shortcut mechanism MUST each be reported in the status
  surface with its reason, leaving the tray route working unchanged.
- **A live shortcut MUST be discoverable** from the tray's own `Open URL…` row; a shortcut that did NOT
  register MUST NOT be advertised anywhere, since a chord the menu promises and the OS refused is a lie the
  user acts on.

Platform reach: Windows registers the chord today. macOS (a global event monitor, which requires the user
to grant Accessibility permission) and Linux (where a Wayland compositor owns shortcuts and may not offer
a global grab at all) report the unsupported state rather than claiming a chord that would silently do
nothing.

### 3.1c-ii The node cache-size surface (normative)

The tray MUST expose the node's content-cache size cap as a control a person can view and change, built
from the same pure model as the rest of the menu (`dig_app_core::tray_menu` + `dig_app_core::cache`) so
these rules are testable without a desktop. The cap defaults to **1 GiB** (1024³ bytes); the node floors
any lower request at **64 MiB**.

- **Show usage AGAINST the cap, not the cap alone (MUST).** The control MUST surface both how much of the
  cache is in use and the cap it is measured against (e.g. `Cache — 350 MiB of 1 GiB used`). A cap with no
  consumption figure is not actionable. The figures come from the node's `control.status` snapshot; they
  MUST NOT be invented when no node is connected. Because a menu item is an ACTION (§3.1c), the usage MUST
  NOT be a display-only disabled row — it rides on an actionable row (the submenu parent) and the full
  figures also appear in the `Status and details…` window.
- **Persist ONLY through the node (MUST).** A new cap MUST be applied via the node's `control.cache.setCap`
  control method. dig-app MUST NOT write the node's `config.json` directly — the node holds a cross-process
  lock over it, and a second writer could corrupt a concurrent node write. The value shown as applied MUST
  be the cap the node ECHOES, which may differ from the request (the node floors sub-64-MiB values).
- **No restart (MUST).** The node reads the cap dynamically, so a change takes effect immediately; the copy
  MUST NOT tell the user to restart.
- **Validate, and confirm eviction BEFORE it happens (MUST).** A zero or absurd value MUST be rejected with
  a reason that names the bound. A new cap BELOW current usage forces the node to evict cached content, so
  the flow MUST warn and require an explicit confirmation (a claim — two choices, no biometric) before
  applying it — the user learns of the loss before, not after.
- **Every state the user did not choose ends visibly (MUST, §6.4 four async states).** The cap is applied
  over a live node connection, which can be absent or can fail. A node that is down, and a node that refuses
  the change, MUST each end in a notice — the control MUST NOT be a silent no-op for an outcome the user did
  not choose. Declining the eviction confirmation is NOT such an outcome: the confirmation dialog has already
  named the consequence and the user has chosen not to proceed, so the flow returns quietly, consistent with
  every other cancel path in the app — a fresh notice there would be redundant, not informative.
- **Honest copy (MUST, §6.0).** The cache is the operator's read-history cover, not merely a disk knob:
  raising the cap increases privacy cover and network contribution, lowering it reduces them, and below
  512 MiB the node's tier-0 relevancy caching is disabled. Sizes are binary (1 GiB = 1024³) and the copy
  MUST say so, so the displayed number matches the stored bytes. The copy MUST NOT present lowering the cap
  as free of a privacy cost.

### 3.1d Native input, modals and prompts (normative)

**Whenever dig-app needs input from the user it MUST use the platform's native input box, modal or
prompt** — Windows and macOS both provide one, and the app already owns the native-confirm plumbing
(§5.6.1) these extend. This covers the recovery phrase on restore, any password or passphrase entry, the
retention confirmation, and every future field.

Two shapes are explicitly NOT acceptable substitutes: dropping the user to a terminal command, and an
in-app or web-rendered text field. A tray menu itself has no text field — that is a property of the tray
API, not a reason to hand the user off — so an input need is met by raising a native dialog from the tray,
not by printing a command for them to run.

Binding rules, which matter more for an input control than for a notice:

- **A window MUST offer exactly the choices its caller reads (MUST).** Every prompt is classified, at the
  point its content is composed, as one of two kinds, and the classification — not the per-OS backend —
  decides its presentation:
  - a **notice** is informational: nothing downstream branches on the answer, so it MUST be drawn with ONE
    dismiss button and an INFORMATIONAL icon, and MUST NOT carry a sentence describing a second button;
  - a **decision** (an authorization, or a claim the user makes about the world) MUST be drawn with two
    labelled choices, and MAY carry the warning icon, because refusing has a real cost.

  A second button nobody reads asks the user to make a decision that does not exist, and a warning icon on
  a success ("your DIG ID is on the clipboard") reads as an error they must resolve. Both are defects.

  **A window whose affirmative is IRREVERSIBLE MUST pre-select the refusal (MUST).** Both platform dialogs
  default to their first button, so a focused destroy window would confirm the destruction of key material on
  a bare Enter/Return. The destroy window therefore pre-selects Cancel (`MB_DEFBUTTON2`; the Return key
  equivalent moved onto Cancel on macOS). Ordinary authorizations — a sign, a pairing, a connect — keep the
  affirmative as their default: the user just asked for the action, and refusing costs only a retry.

  This MUST be classified per call site, never applied in bulk: the enrolment retention screens ARE
  decisions — refusing either abandons setup — so converting every window to a notice would destroy a real
  user choice, and drawing every window as a decision is the defect being ruled out. A backend that cannot
  present a decision MUST fail closed (report it could not ask) rather than assume the affirmative.
- **Cancel MUST always work — wherever there IS a Cancel.** An unescapable modal on a background tray agent
  is the worst available failure mode (§3.1c, never trap the user). For a decision, dismissal MUST be a
  first-class outcome and MUST leave nothing half-created. A notice's single button is itself the escape,
  and closing its window MUST be equivalent to pressing it.
- **Entered secrets MUST go straight into the zeroizing path.** Typed key material (a recovery phrase, a
  passphrase) MUST be moved into its `Zeroizing`/`RecoveryPhrase` home and MUST NOT be left in a control
  buffer, a window title, a process argument, or any log record. The never-log gate covers the restore
  path, not only enrolment.
- **Echo policy is a deliberate decision, stated here.** A recovery phrase on RESTORE is entered
  **masked**, matching `dign account restore`'s suppressed echo: the words already exist on paper, so
  shoulder-surfing is the live risk and a typo is recoverable by retrying (a wrong phrase cannot silently
  damage anything — restore refuses when an account exists, and a bad checksum is rejected outright,
  §3.1a). Because 24 words typed entirely blind cannot be checked, the phrase prompt MUST offer an explicit
  reveal-while-typing affordance — masked by default, deliberately un-maskable — rather than defaulting to
  clear text. Where a backend cannot offer that control, masked entry still wins: the default is never
  relaxed to compensate for a missing affordance.
- **A rejected phrase MUST be re-asked with the REASON, within a bound (MUST).** A mistyped word is the
  normal case, and a window that closes on the first mistake and leaves the user to find the menu item again
  is a surface people abandon. The prompt MUST re-ask, MUST state what was wrong ("that is 23 words, not
  24"), and MUST stop after a bounded number of attempts with a message saying nothing was changed — bounded
  so a backend that answers instantly cannot spin windows forever. A CANCEL is NOT a rejected phrase and
  MUST NOT be re-asked, and a backend that could not draw the window at all MUST be treated as a refusal,
  never as an empty answer.
- **The words a user types are DIG's, not a Chia wallet's (MUST).** Both the restore prompt and the setup
  screen MUST state that a DIG recovery phrase is not a Chia wallet phrase and vice versa, because DIG
  will accept a Sage phrase and silently build a different, empty account from it (§3.1a).

**Current state:** implemented on all three platforms. Windows draws a registered-class window with an
`EDIT` control plus the reveal checkbox — the same window class it draws every consent prompt with, with the
field omitted; macOS uses an `NSAlert` with a text-field accessory view; Linux drives `zenity --entry` /
`kdialog`. A subprocess input helper is
explicitly REJECTED: it would need a verify-the-helper-is-ours check, or a `PATH` impostor harvests recovery
phrases, so every backend draws its window IN-PROCESS.

The destroy window's pre-selected refusal is honoured on Windows (the refusing button holds the focus and
carries `BS_DEFPUSHBUTTON`) and macOS (the Return key equivalent moves to Cancel). The Linux dialog helpers offer no equivalent, which is currently unreachable
rather than a gap — Linux has no per-application credential store, so it is always the unsupported-host state
and no destroy window can be drawn there. A Linux credential store MUST NOT land without addressing it.

Platform limits, recorded rather than papered over: Win32 ignores `ES_PASSWORD` on a multiline `EDIT`, so a
maskable field is single-line and scrolls horizontally; and the reveal-while-typing control exists only on
Windows — neither Linux dialog helper offers one, and an `NSAlert` accessory would need a custom view
hierarchy for it — so on macOS and Linux the phrase field is masked with no un-mask control, which is the
direction §3.1d requires a backend to fail in.

### 3.1e The second factor — authenticator codes (normative)

An account MAY additionally be protected by a **TOTP second factor**: a code from an authenticator app on
a device other than this computer.

**What it is for, and what it is not.** Verifying a code requires the shared secret to be present
locally, so an attacker who can already unlock the account can in principle read that secret and mint
codes. The second factor is therefore NOT protection against full local compromise, and an
implementation MUST NOT present it as such. What it raises the bar against is a shoulder-surfed, guessed,
phished or reused unlock credential; an unattended unlocked machine; and someone who knows the password
but does not have the phone. The platform biometric (§3.1d) is already a factor, but it is bound to THIS
machine and THIS logon session — the authenticator is not, and that difference is the whole justification.
The enrolment UI MUST state both halves of this in the user's own words.

- **Algorithm (MUST).** RFC 6238 TOTP: HMAC-SHA1, a 160-bit secret, a 30-second step, 6 digits, and a
  tolerance of ±1 step. These are the parameters every shipping authenticator implements; a
  conformant implementation reproduces RFC 6238 Appendix B's published vectors.
- **Single use (MUST).** A step MUST be accepted at most once. An implementation records the most
  recently accepted step and refuses any step at or before it, so a code read off a screen cannot be
  replayed for the remainder of its window.
- **Bounded challenge attempts (MUST).** The challenge that guards the destructive verbs MUST bound
  wrong-code attempts with a PERSISTENT, escalating rate limit, so a 6-digit code (~3-in-10^6 live per
  attempt) cannot be brute-forced by an attacker at an unlocked machine. The bound state — a
  consecutive-failure count and a next-allowed-attempt instant — MUST ride the sealed enrolment record,
  NOT the challenge window, so closing and reopening the window does not reset it, and it cannot be
  cleared by deleting a file the attacker can write. A wrong RECOVERY code MUST advance the same bound as
  a wrong TOTP code. The counter MUST increment on every failed challenge and reset on any accepted code.
  A small number of consecutive failures (RECOMMENDED three) is absorbed with no delay so an owner's
  mistyping is not punished; past that, each further failure imposes an escalating required delay
  (RECOMMENDED exponential backoff from a few seconds, capped at ~15 minutes). It MUST be a rate limit,
  NOT a permanent lockout — a hard lockout is a denial-of-service against the account's own owner and
  forces a recovery-code fallback they may not have.
  - **Surface the wait before prompting (SHOULD).** When a throttle is already in force, the challenge
    SHOULD tell the user how long to wait BEFORE drawing the code-input window, rather than accepting a
    full code and only then refusing it — the pre-check is a read-only inspection of the throttle timer
    that reveals nothing about whether a code would be correct, records no failure, does not advance the
    clock anchor, and fails closed on a locked or unreadable record. It does not replace the post-judge
    rate-limit result, which remains the backstop for a throttle that arms during the flow.
  - **Clock-tamper resistance (MUST).** The next-allowed-attempt instant is persisted, and the
    implementation MUST persist the greatest instant it has observed and treat any wall clock reading
    EARLIER than that anchor as frozen at the anchor — a clock rolled backwards MUST NOT shorten a
    throttle nor let a captured code be replayed at its original window. Residual assumption: an attacker
    who can move the clock FORWARD at will already holds the root-level control this factor's threat model
    (full local compromise) explicitly does not defend against; the bound only ever raises the bar for the
    unlocked-machine attacker it is for.
- **Enrolment order (MUST).** Enrolment MUST: explain what the factor does and does not protect,
  generate a secret, present it so it can be transferred to an authenticator, **require a correct code
  to be verified before anything is stored**, issue recovery codes, and obtain an explicit claim that
  they were saved.
  Every screen MUST be escapable, and any exit before the final store MUST leave NOTHING enrolled — a
  flow that enrols before verifying is how a user is locked out by the feature meant to protect them.
- **Presenting the secret (MUST).** Enrolment MUST show the secret as the base32 key, grouped for
  transcription, on every platform. A platform whose window can draw an image MUST ALSO show a QR code
  of the `otpauth://totp/` provisioning URI, and MUST say so in the copy — a window that offers a scan
  and draws no square reads as broken. The QR is an ADDITION and MUST NOT replace the key: it is
  unreadable to a screen-reader user, to a user whose authenticator runs on the same machine, and to a
  camera that will not focus.
  - The provisioning URI's label MUST be the issuer ALONE, carrying no account, profile or DID, so
    nothing identifying the account reaches a phone's screen or its cloud backup. Its `digits` and
    `period` MUST agree with the parameters above.
  - The URI MUST NOT be logged, written to a file, placed on the clipboard by default, or retained
    beyond the window that shows it — it carries the secret in the clear, as do the QR's own modules.
  - The QR MUST be rendered at a whole number of pixels per module and MUST scale with the display, so
    it stays resolvable by a camera at every DPI. It MUST carry a quiet zone of at least four modules
    and MUST be drawn on an explicitly light field rather than on whatever the window background is.
- **Recovery codes (MUST).** Enrolment MUST issue single-use recovery codes, display them exactly once,
  and take a claim-you-saved-them confirmation. They MUST be stored so the app cannot re-display them
  (a salted digest per code) and MUST be marked spent on use. Without them, a lost device is a lost
  account, which this app cannot undo.
- **At rest (MUST).** The enrolment record is sealed under the ROOT profile's DEK through the same
  DIGOP1 container as the phrase vault (§3.4), inside a domain-separated versioned envelope so a blob
  from another vault cannot be read as an enrolment. Neither the secret nor a recovery code may be
  logged, transmitted, or written anywhere but that record.
- **What it gates (MUST).** At minimum, the DESTRUCTIVE account verbs — replacing and removing the
  account. Ordinary reads and signatures stay on the platform biometric: a factor demanded for
  everything is a factor users turn off. Whether the enrolment exists MUST be determined WITHOUT
  unlocking the account, so locking first cannot walk around the gate.
- **Turning it off (MUST).** Disabling MUST run the same authorization gate as a signature (a foreground
  window naming what is weakened, then an OS re-authentication). It MUST NOT additionally require a
  code: requiring the factor to remove the factor turns a lost phone plus lost codes into an account
  that can never be replaced or removed on this computer. Disabling MUST work while the account is
  LOCKED or unopenable, for the same reason — it deletes the record rather than reading it.
- **Account removal (MUST).** Discarding an account MUST remove its enrolment record. A leftover would
  make the next account report a factor it cannot satisfy, blocking every destructive verb with no way
  out.

### 3.2 Profiles and the Accounts registry

A **profile** is one HD identity within the account: `{ HD index (`ProfileIx`), derived BLS12-381 G1
identity key (slot `0x0010`), derived per-profile DEK, local data (config / subscriptions / wallet /
prefs) }`. Every profile's identity key AND its DEK are DERIVED from the single account master seed at
the profile's index (§3.1) — a profile holds no independently-stored secret. `ProfileIx::ROOT` is the
default profile the boot opens.

**The on-chain DID is a later phase.** A profile's public on-chain identity is a `did:chia:` singleton
paired with a chip35 DataLayer store (via `dig-identity` [dig_ecosystem#771]); minting it is owned by
`dig-account`'s `ProfileMinter` (phase 2) and is NOT yet wired. Until it lands, a profile is identified
by its **seed-derived identity public key**, not a minted DID, and dig-app MUST NOT fake a mint.

**The Accounts registry.** Which accounts exist, which ONE is the default, and which is currently
active is tracked app-side by `account::registry::AccountRegistry`, keyed by an app-local `AccountId`
— an opaque handle, NOT a DID and NOT derived from key material, so relabelling an account never
disturbs its custody root. Invariants, enforced at every mutation:

- **Exactly one default over a non-empty registry.** The first account registered becomes the default;
  removing the default promotes the next in insertion order; removing the last clears it. Never zero
  defaults over a non-empty registry, never two.
- **At most one active account.** Removing the active account clears the slot; it does NOT auto-promote
  (activation is a deliberate user action, unlike the always-present default).

The registry holds only the always-holdable **locked** `AccountSession` handle and never touches key
material; unlocking a session yields a transient `UnlockedAccount` the caller owns for the duration of
a signing ceremony.

**Cross-session persistence + boot re-unlock.** The account master seed is persisted **sealed at
rest** (§3.1) at enrolment, so a restarted app recovers it. On boot the app enrols-or-unlocks the
account (§3.2a): a first run generates + seals a fresh master seed; every later boot unlocks it. Once
unlocked, every profile's identity + DEK is re-derived from the seed at its index on demand — no
per-profile material is separately persisted or re-derived. A **locked** account exposes NO profile
identity or DEK (fail-closed): its sealed per-profile data cannot be opened until the account unlocks.

**Per-profile isolation (by the cipher).** Each profile's DEK is HKDF-derived from that profile's own
seed-derived identity (§3.1), so opening one profile's sealed data blob under a different profile's DEK
MUST fail — profiles are cryptographically isolated by the cipher, not by directory layout, and the
isolation holds across a restart + re-unlock. Decrypted profile data is returned in a zeroizing buffer,
so plaintext content is scrubbed from memory after use.

### 3.2a Unlock / enroll account lifecycle

The account is the custody root; the app turns "a brand directory" into "a live, lockable unlocked
account" through ONE boot primitive (`account::lifecycle::open_or_enroll`, assembled by
`account::boot`):

- **First run** (no sealed seed blob exists) — collect the unlock factors through the OS-native
  ceremony, gate them on the injected `AuthPolicy` (fail-closed on refusal), generate a fresh master
  seed from the OS CSPRNG, and `enroll` it DIGOP1-sealed under the collected password — returning the
  account already unlocked.
- **Returning boot** (the seed blob exists) — build a locked `AccountSession` and `unlock` it through
  the SAME injected ceremony + policy, recovering the enrolled seed and yielding the live
  `UnlockedAccount`. A returning unlock re-derives the identical master-seed-derived identity key.

**The unlock password MUST be supplied by the user (MUST).** It is typed into the app's own native
masked window (§3.1d, `account::password`) and exists nowhere else — not on disk, not in the OS
credential store, not in a log. An implementation MUST NOT source it from any store the logged-in user's
own code can read, and MUST NOT keep such a path as a fallback: a fallback needing no password defeats
the requirement entirely. A new password is typed TWICE and must be at least 10 characters (counted as
CHARACTERS, not bytes); an unlock is asked once, and a wrong answer fails the seal.

**The app MUST start LOCKED.** Nothing unlocks at start-up. The account opens only when the user asks
(the tray's `Unlock…`) or when a signature needs it, and the APP-SIGN loopback channel refuses while
locked rather than serving from a seed it has no business holding unprompted.

**Migration off the machine-generated password (MUST).** Accounts sealed by earlier versions under a
machine-generated credential-store password are reported as `AccountState::NeedsPassword` (§3.1c) — not
as `Locked`, which would offer an `Unlock…` asking for a password its owner never chose. The remedy is an
in-place re-seal (`account::migration`): open with the old password, read the master seed back out of the
account's own recovery-phrase vault, re-seal that SAME seed under the chosen password, and only then
delete the credential entry. The seed is preserved, so the identity, address, phrase and sealed data all
survive. Every failure arm MUST leave the account exactly as it was; an account with no vaulted phrase
CANNOT be re-sealed and MUST be left intact and working, with the replace path named — never deleted to
satisfy this rule.

Linux — and any host with no window stack for the prompt — DEFERS the account paths entirely: the boot
yields no residency and the signing channel stays down until a Linux unlock UX lands
(dig_ecosystem#962).

The unlocked account is never held as a snapshot: it lives in the shared, lockable
`account::residency::AccountResidency` (§3.6) — a single `Arc<Mutex<Option<UnlockedAccount>>>` that
hands out LIVE-VIEW signer + sealer capabilities re-reading the account on every operation. A session
lock (idle timeout / lock-now / OS screen lock) drops the residency (`lock_all`), which relocks BOTH
the identity sign path AND the money path at once — there is no lock that leaves a running capability
able to sign. The private key never crosses this boundary (#908, Model A): the harness collects a
password, `dig-account` seals/unlocks the seed, and callers receive only capability handles.

Fail-closed everywhere: any ceremony, policy, or keystore error — a wrong password, a cancelled prompt,
a tampered blob, a policy refusal — aborts with NO unlocked account and no partial key material.

### 3.2b First run (normative)

An account exists ONLY because a user asked for one. An implementation MUST NOT auto-enrol an account at
boot, at install, or on any path the user did not initiate — a silently created account is one whose
recovery phrase nobody has seen.

The first-run flow (`account::journey::first_run_wizard`), reached from the tray's
`Set up my DIG Account…` row, is ordered so nothing becomes load-bearing before the words are written
down:

1. **Orient** — a two-choice screen stating what will happen. Refusing creates nothing; this is the
   flow's one cancel point.
2. **Choose the route (MUST).** A first run MUST let the user CREATE a new account OR IMPORT an existing
   one from its recovery phrase — a stranger who already holds a DIG phrase MUST be able to restore at
   first run, not only via the tray's replace-account path. The choice is a real either/or claim.
   - **Create** — generate the 24-word BIP-39 phrase, show it, take the retention claim, ask the user to
     CHOOSE a password, and seal the seed under it.
   - **Import** — collect the 24 words through the native input gate (§3.1d — masked, re-asking on a bad
     phrase, refusing a Chia wallet phrase), then re-derive and seal that account. The TYPED phrase MUST
     reach the enrol step unchanged (the same-identity guarantee, §3.1a).

   Any refusal at any point leaves the host untouched (§3.1a, §3.2a).
3. **Fund** — show the account's OWN derived receiving address. It is SHOWN, not awaited: the flow is a
   chain of OS-owned modal windows (§3.1d) and a modal cannot poll a chain, so an implementation MUST NOT
   present a "waiting for funds" screen it cannot actually be waiting on.
4. **DID** — name the on-chain DID as the remaining REQUIRED step (§3.1b) and state plainly that minting
   is not available in this version. It MUST NOT present a control that appears to mint.

Both routes end on the SAME fund + DID screens (`show_account_ready`) so they cannot drift. Every step
MUST be escapable without half-creating an account. Reading content is NOT gated on any of
this: `Open URL…` stays enabled in every account state (§6.0 — consumption is never gated on custody).

### 3.3 Wallet

The wallet is user-identity state and lives in dig-app (migrated out of the engine). It is a
**focused host**, not a port of the engine's wallet tree: it caches the per-profile wallet view
(addresses / coins / balance / history, sealed at rest, §3.4), delegates network I/O to the engine,
and signs money through the master-HD custody path — the wallet host itself holds NO key material.

**Wallet key.** A profile's wallet key is the canonical Chia standard wallet child of the ACCOUNT
master seed at the profile's HD index —
`master_to_wallet_unhardened(master, ix).derive_synthetic()` — whose public half curries the standard
puzzle; that puzzle's tree hash is the wallet's `xch1…` receive address. The key is owned by
`dig-account` and derived on demand from the unlocked account by the money path
(`account::money::MoneyPath` over the `AccountResidency`); it is never stored per profile, never
exposed to callers, and never crosses the IPC boundary to the engine.

**Reading the wallet (normative).** The account's receive address is derived LIVE from the unlocked
account (`AccountResidency::receiving_address`) and MUST fail closed — no address — once the account
locks, so no surface can hand out an address read from key material a lock was meant to drop. A balance
MUST be reported only when a chain source actually answered; otherwise the reading is UNKNOWN and carries
the reason (no address · no node · a node without wallet reads · still syncing · the read failed). A
partial read — one asset answered, another failed — is NOT a balance and MUST be reported as unknown,
because showing the half that succeeded states a total the wallet does not have.

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

**Authorize before sign (the live money path, master-HD / Model A).** A spend MUST pass a fail-closed
gate, in this fixed order, before any signature is produced: (1) **summarize** — the recipients + fee
are independently re-derived from the coin spends (never a caller's claim) and classified into a
`SpendTier` (`AutoSend` | `Confirm` | `Vault`) under the profile's `CustodyPolicy`; (2) **authorize** —
the injected `SpendAuthorizer` rules on the summary (programmatic limits/allowlists); (3) **confirm
ceremony** — for every tier ABOVE `AutoSend` (i.e. `Confirm` and the clawback `Vault` — the
`RequireAuth` class) the injected `AuthProvider::confirm_spend` MUST run and return `Approve`. An
authorizer `Ok` is NOT sufficient on its own: a `RequireAuth`-class spend that skips or is declined at
the confirm ceremony is REFUSED, and the money signer is never even built. The signer is drawn from the
shared, lockable account residency and re-read at sign time, so a lock (lock-now / idle timeout / OS
screen lock) that lands during the confirm dialog fails the sign closed. The residency is the SAME
lockable seed home the identity signer reads — a locked account refuses to sign money AND identity.

**No user key on the wire (#908).** The seed and every money/identity secret derived from it stay owned
by the account crate; the money signer holds the key inside its vetted core and exposes signing only.
What crosses the dig-app→dig-node IPC boundary is exclusively the signed `SpendBundle` (money path) and
the profile-signed bytes + public key (identity path) — never seed, money secret, or per-profile DEK, in
raw or hex form. This is asserted at the wire-byte level (the `no_user_key_on_wire` conformance test).

**Wallet state at rest.** The per-profile wallet view — receive addresses, the last-known spendable
coins (per asset) used for display + coin selection between chain reads, and the outbound spend
history — is DIGOP1-sealed under that profile's own DEK (§3.4), in the profile's directory
(`wallet-state.seal`), alongside the separately-sealed key seed (`wallet-key.seal`). Both are
cryptographically isolated per profile: one profile's DEK cannot open another's wallet blobs
(fail-closed). The `.dig` content cache is NOT wallet data and is exempt from sealing (§3.4).

**Spend history.** Each outbound spend the wallet broadcasts is recorded as a `SpendRecord` —
recipient address, asset, amount, broadcast time, and the transaction id — appended oldest-first to
the wallet state's history. It carries **public metadata only** (never key material, never the bundle
bytes), so exposing it never crosses the custody boundary. The wallet host exposes read accessors
over it — the distinct recent recipients (most-recent first) and the total sent per asset — as the
substrate for the connected-wallet UX (address-book suggestions, adaptive spend-confirm friction).

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

Layout: the account master seed is DIGOP1-sealed by `dig-account` under `<brand-dir>/account/`; each
profile's data lives under `<brand-dir>/profiles/<profile-hash>/…`, ACL/mode `0600` to the owning
user. Sealed contents: the account master seed (the sole at-rest key material — every profile identity
key + DEK derives from it, §3.1), wallet state, subscriptions, user config/prefs (the §5.3
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

**`dign account` is served in-process, NOT through the gateway (normative).** The `account status`
and `account restore` verbs act directly on this machine's account store and MUST work with no running
dig-app, because both matter precisely when there is no account for the app to serve. They resolve the
per-user directory through the SAME host resolution the tray shell uses, so the CLI and the app can never
address different directories. `account restore` MUST read the phrase with terminal echo suppressed, MUST
refuse when an account already exists (§3.1a), and MUST NOT accept the phrase from a non-terminal stdin
(a piped phrase lands in shell history). No `account` verb ever prints the phrase to stdout, including
under `--json`.

The `dig-node` binary retains **only** machine service-lifecycle subcommands
(install/start/stop/status/uninstall/run-service) — the identity-agnostic engine admin surface. It
MUST NOT carry user/identity subcommands.

Machine-friendly (per the ecosystem agent-friendly baseline): `dign` MUST offer `--json` output
beside human output, a discovery surface (`--help`/`--help-json`), and deterministic catalogued error
codes.

`dign` is its OWN binary crate (a thin IPC client); the routing lives in `dig_app_core::gateway`,
which the running dig-app hosts. The gateway classifies every command as `Route::UserApp` (served
locally with the held user identity — profiles / wallet / sign) or `Route::Engine` (proxied to the
engine), and dispatches over four seams: `EngineProxy` (forwards the canonical `control.*` call over
the session), `LocalIdentity` (serves the local identity ops), `LinkOpener` (validates + opens a
DIG link — only `chia://` / `urn:dig:chia:` are accepted, the security boundary), and the
`NativeConfirmer` (§5.6.1) that gates `dign sign`. Failures carry a stable `ErrorCode` (symbolic name
+ numeric exit code); the `--json` envelopes match the engine CLI's shape so the DIG command line is
one consistent surface.

**`dign sign` — domain-separated + confirm-gated (MUST, custody).** The local `sign` command holds the
custody key, so it enforces the two invariants every 0x0010 signing path enforces:

- **Domain separation.** It signs the length-unambiguous message

  ```text
  "DIGNET-USER-SIGN-v1" ‖ message
  ```

  (the `USER_SIGN_DOMAIN` tag ‖ the caller's message; `message` is the single trailing field, so no
  length prefix is required for an unambiguous parse), **never the raw `message` bytes**. This is a
  THIRD purpose tag, distinct from `DIGNET-SESSION-v1` (§5.3 session attach) and `DIGNET-SIGN-v1` (§5.3
  engine callback / §5.6.5 dapp sign). Because the tags differ at a fixed leading position, a
  `dign sign` signature can NEVER be replayed as a session attach or a spend/callback authorization,
  even when the caller crafts `message` to look like one of those bodies — closing the cross-protocol
  signing oracle (§3 domain-separation invariant).
- **Confirm gate.** `dign sign` funnels through the same terminal `NativeConfirmer` (§5.6.1) the engine
  (§5.3) and dapp (§5.6.5) sign paths use, so no local process obtains an identity-key signature
  without an explicit human approval. A declined / timed-out / no-confirmer (headless) outcome returns
  the `DENIED` error code and never touches the key.

### 3.6 Session lock (idle · OS-screen-lock · lock-now · tiered re-auth)

An unlocked profile keeps its data-encryption key (DEK) resident in the in-memory session (§3.1).
dig-app MUST drop that DEK — re-sealing the session — on any of three triggers, so key material never
outlives the user's presence at the machine:

1. **Idle auto-lock.** After a configurable idle window with no noted activity
   (`DEFAULT_IDLE_TIMEOUT` = 5 minutes) the session locks. The shell drives the check from its refresh
   tick; noting activity resets the window.
2. **OS screen lock.** When the OS session/screen locks, the session locks. The platform event is
   observed natively per OS — Windows `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK` (via
   `WTSRegisterSessionNotification`) and macOS `com.apple.screenIsLocked` (distributed notification) —
   behind a single `ScreenLockSource` seam. The Linux logind lock signal is deferred with the Linux
   unlock UX (dig_ecosystem#962); until then Linux relies on idle auto-lock + lock-now.
3. **One-tap lock-now.** An explicit lock action (a tray item) locks IMMEDIATELY, with NO confirmation
   prompt.

All three drop the SAME key material: every unlocked profile DEK, via a whole-session lock.

**Tiered re-authentication (MUST — frictionless consumption, §6.0).** A lock gates the KEY, not
content. Reading/browsing DIG content never touches the identity key, so a lock MUST NOT interrupt or
prompt a read. Only the NEXT **signing** operation after a lock re-authenticates (biometric /
passphrase, via the §3.1 unlock path); the lock exposes a `reauth_required` predicate that ONLY the
signing paths consult. Once a re-unlock succeeds the owed re-auth clears and the idle window restarts.

The lifecycle is a pure, seamed controller (`session_lock::SessionLock` over a `SessionKeys` DEK-drop
seam — implemented by the master-HD `account::residency::AccountResidency` — and a `MonotonicClock`),
so every trigger + the tiered
re-auth is unit-tested without a real keystore or OS; the native `ScreenLockSource` listeners are thin
adapters validated behind the seam.

The tray shell drives one `SessionLock` over the SAME live session the APP-SIGN signer holds (so a
lock the tray triggers is the lock the signer sees): the "Lock now" menu item calls `lock_now`, the
refresh tick calls `poll_idle` (interaction notes activity), and the `ScreenLockSource` callback —
wrapped so a panic cannot unwind across the OS `extern "system"` boundary — calls `on_screen_locked`.
The `sign.request` path consults the lock through a `SignReauthGate` immediately before it signs: when
a re-auth is owed it re-unlocks ONLY the signing (active) profile's identity — never every profile's
DEK — via the §3.1 single-profile unlock path, so the re-auth restores the smallest key residency that
authorizes the sign and leaves all other profiles locked. On failure it refuses the sign with `LOCKED`
rather than signing on a dropped key. Reads never consult the gate.

### 3.7 Event-driven wallet UI + funds notifications

dig-app does NOT poll wallet state; it SUBSCRIBES to the engine's wallet event stream and drives its
UI reactively (the "event-driven, poll only on a gap" contract). The event taxonomy — `WalletEvent`,
`EventKind`, `Cursor`/`EmittedEvent`, and the `CatchUp`/`filter_events` shape — is the CANONICAL
`dig-events-protocol` contract, imported and never re-declared; the engine (dig-node, via
`dig-wallet-backend`) emits it and dig-app consumes a FILTERED view (an `EnumSet<EventKind>` chosen
per surface).

The `events` module holds three transport-injected seams and the driver over them:

- **`EventFeed`** — the live stream (server-push over the §5 IPC session in production; scripted in
  tests). Each read is a `FeedItem`: a filter-matching `Event`, a `Lagged` signal (the subscriber fell
  behind or reconnected), or `Closed`. Gap detection is a TRANSPORT concern — never derived from cursor
  arithmetic, since a kind filter makes live cursors legitimately non-contiguous.
- **`CatchUp`** — the backfill half (the canonical trait), called ONCE after a `Lagged` with the last
  `Cursor` to recover the missed range, then live resumes.
- **`EventSink`** — where recognized events land: the reactive `WalletView` and the notification
  pipeline are sinks; the driver fans each event to all sinks.

**Cursor + recovery.** Cursors are 1-based monotonic; `Cursor(0)` is the seen-nothing sentinel. On a
`Lagged`, the driver calls `catch_up(cursor, EnumSet::all())` (ALL kinds, so cursors are contiguous for
exact gap detection), then reconciles: if the earliest retained cursor is `> since.next()`, the missed
range began before the engine's bounded in-memory catch-up window (4096 events; #1118 adds SQLite
backing for longer ranges) → **unrecoverable gap** → the driver signals `EventSink::resync` and the
sinks discard incremental state and re-read authoritatively (graceful degrade, never a crash);
otherwise it delivers the filter-matching subset and resumes. Live events are deduped by cursor so a
backfill/live overlap after a gap delivers each event once.

**Reactive view (`events::WalletView`).** An `EventSink` that folds the stream into a cheap, cloneable
`WalletSnapshot` (sync lifecycle, chain tip, glanceable received/sent tallies, a `balances_dirty`
flag) the tray shell and `dign` CLI OBSERVE via a shared handle — the same pattern as
`agent::SharedStatus`. Events say *when* to refresh; the authoritative balance comes from the §3.3
wallet read seam when `balances_dirty` is set.

**Funds notifications (`notify`, #970).** A `NotifyingSink` taps `FundsReceived`/`FundsSent` and feeds
a debounced coalescer: every funds event within a short trailing window merges into ONE native OS toast
(a burst of 3 receives → one "Received 3 payments: X total"), rendered through a per-OS `NativeNotifier`
(Linux `notify-send`, macOS `osascript`; a logging fallback elsewhere — native WinRT toast is a
follow-up). Amounts + asset labels are honest ($DIG vs XCH vs a short CAT id) and a notification NEVER
carries a key, seed, or address. It is passive, dismissible, and opt-out — it never gates a read
(§6.0/§6.1). This path holds no key and touches no custody surface.

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
+ path resolution, unit-tested without a real service manager. Windows per-user logon autostart is
dig-installer's own packaging concern (U8) and is out of this crate's scope.

These renderers are a LIBRARY surface that nothing in this crate calls: in a real install the artifacts
are written by dig-installer's byte-identical `src/autostart.rs`, and LOADED by its launch step
(`launchctl bootstrap` / `systemctl --user enable --now`, dig-installer SPEC §1.11a). Writing the
artifact starts nothing on its own — a written-but-unloaded systemd user unit is `inactive` and
`disabled` — so a reimplementation MUST NOT treat "the artifact exists" as "dig-app starts at login".

**Single instance per user (MUST):** at most ONE dig-app runs per user at a time. Three launchers start
it without being asked — the installer when it completes, the OS at login, and a user double-clicking the
binary because no tray icon is visible — so a duplicate launch is the normal case and MUST be absorbed,
not treated as an error. On startup dig-app MUST take an exclusive OS lock on `<brand_dir>/dig-app.lock`
(`dig_app_core::single_instance`) and, when another live process holds it, MUST exit 0 without mounting a
tray, starting an agent, or touching the profile directory.

The lock MUST be held by an open file DESCRIPTOR, so the kernel releases it however the process dies:
`flock(LOCK_EX | LOCK_NB)` on unix, an open with share mode zero on Windows. The lock FILE persists
between runs and its presence MUST NOT be read as "an instance is running" — a crashed instance must
never lock a user out of their own agent. The lock is scoped to the brand directory, so two accounts on
one machine are two legitimate instances (§ Multi-user below). The APP-SIGN port MUST NOT be used as the
guard: the app boots with the account locked, so no listener exists during the window a login autostart
fires in. A brand directory that cannot be resolved or locked MUST start anyway — that is a host problem,
not evidence of a second instance, and failing closed would leave the user with no agent at all.

**Multi-user (MUST):** one engine daemon serves the whole machine; **each logged-in user runs their
own dig-app instance** with its own profiles/keys. The engine holds no per-user state, so it keeps a
map of attached sessions keyed by profile; content serve is profile-agnostic (public); authenticated
sync, subscriptions, and signing run per-attached-session. Fast-user-switching and concurrent sessions
MUST work — there is no single "active machine profile."

---

## 5. The user-app ↔ engine IPC contract

This section specifies **two** transports, and a reimplementation MUST NOT confuse them:

- **§5.1.0 — the LIVE transport.** dig-app reaches the engine over the engine's **loopback HTTP
  JSON-RPC control plane**, authorized by the **`X-Dig-Control-Token` header**. This is what a
  conformant dig-app implements today, and the control token is **NORMATIVE, not superseded**.
- **§5.1.1 + §§5.2–5.3 — the SPECIFIED-BUT-UNBUILT transport.** A **per-user, OS-native local
  channel** (named pipe / UDS) carrying an **identity-authenticated session**. **No engine answers it**
  — dig-node carries no pipe or UDS listener — so every requirement stated for it is a forward
  contract, binding only once that listener exists.

The identity-authenticated session is what would supersede the SYSTEM-minted control-token model
([dig_ecosystem#856] Family B) — **when it is built**. Until then it supersedes nothing: an
implementation that treats the control token as obsolete cannot talk to a real engine at all.

Everything below §5.1.1 (session authentication §5.2, the session methods §5.3, the `sign` callback)
describes that unbuilt channel unless it explicitly says otherwise.

### 5.1 Transport

#### 5.1.0 The transport dig-app uses TODAY: loopback HTTP JSON-RPC (normative)

dig-app reaches a running dig-node over the **loopback HTTP JSON-RPC control plane the node serves**:
`POST /` with a JSON-RPC 2.0 body naming a `control.*` method, authorized by the
`X-Dig-Control-Token` header. dig-app MUST resolve the endpoint by the ecosystem §5.3 ladder, first
responder wins:

| Order | Endpoint | Notes |
|---|---|---|
| 1 | the user's configured endpoint | Wins outright and is tried ALONE — never fall through to a different node. |
| 2 | `http://dig.local` | Port **80**, not `DIG_NODE_PORT`: the node's bare-`dig.local` listener binds `127.0.0.2:80`. |
| 3 | `http://localhost:9778` (`DIG_NODE_PORT`) | The node's always-on loopback listener, dual-stack (`127.0.0.1` + `[::1]`). |

`https://rpc.dig.net` MUST NOT be a tier for the control plane: it is the anonymous public read tier
and dispatches no `control.*` method, so probing it can only mislead.

The control token MUST be read from where dig-node writes it (`<state-dir>/control-token`, with
`DIG_NODE_STATE_DIR` honoured first, then the machine-wide state dir, then the legacy per-user dir).
dig-app MUST NOT mint a control token — a token the node does not know authorizes nothing.

A node that ANSWERS but refuses MUST be reported distinctly from no node at all: the remedies differ
(a token/permission fault on a running node vs nothing installed or running).

The method names, params/result types and error taxonomy MUST come from the published
`dig-node-control-interface` crate, never a hand-copied catalog.

#### 5.1.1 The per-user OS channel (SPECIFIED, NOT YET IMPLEMENTED)

The addressing below is the specified per-user OS channel. **No engine answers it today** — dig-node
carries no named-pipe or Unix-domain-socket listener — so it is a forward contract both sides must
agree on if that listener is built, not a transport dig-app dials.

| OS | Channel | Address |
|---|---|---|
| Windows | named pipe (per-user namespace) | `\\.\pipe\dignetwork-<USER>` |
| macOS / Linux | Unix domain socket | `<RUNTIME_DIR>/dignetwork.sock` (`$XDG_RUNTIME_DIR` on Linux) |

Were it built, the channel MUST be **per-user and ACL-scoped to the owning user** — tighter than
loopback TCP — and the OS peer credential would additionally bind the connecting identity. It is
**bidirectional**, carrying **newline-delimited JSON-RPC 2.0 frames** over the engine's existing
`control.*` dispatch: for that channel this would be a **transport swap only**, leaving the `control.*`
protocol shape unchanged.

The loopback-TCP `control.*` channel is **not** a legacy path that merely "stays for the MV3 browser
extension": it is the channel **dig-app itself uses** (§5.1.0), alongside the extension. Consequently
IPv6-first (ecosystem §5.2) is **NOT** N/A to dig-app — it is required, because §5.1.0 dials real
network sockets: a §5.1.0 client MUST prefer the IPv6 loopback (`[::1]`) among a host's resolved
addresses before IPv4, since the engine's IPv6 listener is best-effort and `localhost` resolves to
both families. IPv6-first would be N/A only to the §5.1.1 pipe / UDS channel, which is not a network
socket.

The concrete request/response shapes below are the normative contract that the app-side (dig-app,
APP work units) and the engine-side (dig-node, `control.session.*` + the `sign` callback) both build
against. All frames are JSON-RPC 2.0; `params`/`result` fields use the names and encodings given.

**Single source of truth — the `dig-ipc-protocol` crate.** This contract is NOT hand-rolled in
dig-app. The domain-separated message builders (`challenge_message`, `sign_callback_message`,
`user_sign_message`), the `control.session.*` / `sign` wire types, the frame bounds, the seam traits
(`SessionSigner`, `SignPolicy`, `FrameTransport`), the generic app-side `SessionClient` role-half, and
the `verify_signature` engine primitive are all owned by the canonical [`dig-ipc-protocol`] crate
(dig_ecosystem#1074) and re-exported from `dig-app-core::session`. dig-node (#1080) consumes the SAME
crate for the engine half, so the two ends cannot drift. The loopback sign seam (`sign_service.rs`)
takes its identity `SessionSigner` by INJECTION, so the concrete signer is a caller choice: the
custody path uses the master-HD `account::residency::ResidencySigner` — a live-view wrapper over
`dig_account::ProfileSigner` that fails closed the instant the account is locked, implementing the same
`dig-ipc-protocol::SessionSigner`. dig-app supplies the production decode-then-native-confirm
`NativeConfirmSignPolicy` (`sign_policy.rs`). References to `session.rs::…` builders below denote the
re-exports of the canonical crate.

[`dig-ipc-protocol`]: https://crates.io/crates/dig-ipc-protocol

### 5.2 Session authentication

dig-app authenticates to the engine by **proving possession of the active profile's identity key** —
a signed-challenge handshake — NOT a static token file. No client can attach a `profile_did` it
cannot sign for. The handshake is three methods (§5.3), and the engine opens an in-memory session
only after it verifies the signature against the DID's own on-record signing key.

The signed-challenge scheme is the baseline because the §5.1.1 per-user pipe/socket ACL and the OS
peer credential already authenticate the *channel*; the handshake additionally binds the *profile
identity*. **That premise is specific to §5.1.1 and does NOT transfer to §5.1.0**: a loopback TCP
port has no per-user ACL and is reachable by any local user, so on the live transport it is the
**control token** (a file whose own ACL is the access control) that authenticates the caller — not the
channel. An **mTLS variant** — the app presents a client cert keyed by the profile identity —
is an equivalent alternative where a cert-authenticated channel is preferred.

### 5.3 Session methods (the concrete contract)

Built on the existing `control.*` dispatch. The full handshake proves the caller holds the active
profile's slot `0x0010` signing key before any session opens.

1. **`control.session.begin`** (app → engine) — params: `profile_did`, `signing_pubkey_hex` (the
   claimed slot `0x0010` signing key). Engine returns `nonce_b64` (32 random bytes, base64) and a
   `session_candidate` (uuid) naming this pending handshake.

2. **App signs the challenge.** The app produces a 96-byte BLS12-381 G2 AugScheme signature, using
   the in-memory slot `0x0010` key, over the byte string:

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

**Two distinct ladders, both derived from ecosystem §5.3 — do not conflate them.** This section is the
**content-read** ladder, in which dig-app is tier-0 *for other clients*. dig-app's own **control-plane**
ladder — how it finds the engine to ask `control.*` — is §5.1.0, and it deliberately ends at
`localhost` with no `rpc.dig.net` tier, because the public gateway dispatches no `control.*` and cannot
hold this machine's local control token.

dig-app is **tier-0** of the ecosystem client→node ladder (§5.3 of the ecosystem contract): a client
resolves the local dig-app first, then the engine directly (`dig.local` → `localhost`, public reads
only), then `rpc.dig.net`. An explicitly-configured node still overrides the ladder entirely.
Node-class clients dial over mTLS (§7); a user-facing custom-node setting MUST be exposed (persisted
in the sealed config).

### 5.5 End-to-end seal scope on the IPC channel

Neither local channel is an intermediary-terminated channel to a remote recipient — loopback bytes
never leave the host, and a pipe / UDS has no network hop at all — so their own frames are **not**
end-to-end sealed. The sufficient control differs by transport, and only one of them is an ACL on the
channel: for §5.1.1 it is the per-user channel ACL; for the live §5.1.0 transport it is the
**loopback-only bind plus the control token**, because a loopback port carries no per-user ACL. The
ecosystem §5.4 seal-to-recipient rule (NC-1) applies to **recipient-directed content** (chat, email)
that the engine RELAYS onward: dig-app seals such content to the recipient's dig-identity BLS G1
identity key (slot `0x0010`, via G1-DHKEM) **before** handing the bytes to the engine, so the engine
and any downstream relay see only ciphertext. Sealing is the app's responsibility, never the engine's.

### 5.6 The extension ↔ dig-app paired-loopback signing channel (APP-SIGN)

The §5.3 session over the §5.1.1 pipe/UDS channel is the ENGINE's path to dig-app *once that channel
exists*; dig-app's own path to the engine today is §5.1.0. Browsers can speak neither, so a
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
- **`Origin` admission (the anti-web-page boundary).** The WS upgrade `Origin` MUST be one of:
  - `chrome-extension://<pinned-ext-id>` — a pinned DIG extension (`SYSTEM.md`/canonical hold the
    values); this caller MAY pair without a code (§5.6.3);
  - any browser-extension origin — a scheme of `chrome-extension://`, `moz-extension://`,
    `safari-web-extension://` or `ms-browser-extension://` followed by a non-empty id. A page cannot
    forge one, so a THIRD-PARTY extension reaches the channel and MUST then pair with a code (§5.6.3a);
  - **absent** — a native local client. A browser ALWAYS attaches `Origin` to a WS handshake, so its
    absence establishes the caller is not a page. This caller MUST also pair with a code.

  Every other value ⇒ the upgrade is rejected (403, connection closed). In particular every `http`/
  `https` origin that is not pinned, and the literal `null` (which browsers send for sandboxed and
  `file://` documents), MUST be rejected: no website ever reaches this channel, with or without a
  pairing code. Admission to the channel is NOT authorization to act — pairing and the per-frame MAC
  are.
- **Pairing-token MAC** — after pairing (§5.6.3) every request frame carries an `auth` object the
  server verifies before dispatch (§5.6.3). An unpaired or MAC-invalid frame ⇒ `AUTH_REQUIRED` /
  `AUTH_BAD_MAC` and no side effect.

**App not running.** A refused connection to `127.0.0.1:9779` means dig-app is not running; the
extension MUST surface a deep-link to launch/install dig-app rather than failing silently.

#### 5.6.3 Extension ↔ dig-app pairing handshake

Pairing establishes the one trusted mediator ONCE, like pairing a hardware device. It is a native
confirm, never silent.

1. **`pair.begin`** (extension → app) — params: `{ ext_id, ext_label?, requested_at, pairing_code? }`.
   The app verifies `ext_id` equals a pinned extension id (matching the `Origin` guard) — a caller
   whose `ext_id` is NOT pinned MUST instead redeem a `pairing_code` (§5.6.3a) — then raises a
   native modal: *"Pair this browser extension with your DIG identity?"* gated on the user's
   biometric/passphrase. On approve the app:
   - generates a **32-byte CSPRNG channel token** (the `channel_secret`),
   - persists a pairing record — `{ pairing_id (uuid), ext_id, channel_secret, created_at }` — sealed
     at rest with DIGOP1 under the active profile (§3.1, NC-2), and
   - returns `{ pairing_id, channel_token_b64, may_sign }` (`channel_token_b64` = base64 of the
     32-byte secret; `may_sign` states the granted scope, §5.6.3a).
   On deny/timeout ⇒ `PAIR_DENIED` / `PAIR_TIMEOUT` and no record.

   The sealed record additionally carries `label` (the caller's self-declared `ext_label`, UNTRUSTED and
   display-only) and `scope` (§5.6.3a). Both are OPTIONAL in the sealed form: a record written before
   they existed MUST still open, and MUST restore with `scope = dig-extension`.
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
5. **Restart durability + cross-restart replay.** The sealed pairing record persists to the active
   profile's AppData (NC-3) and is restored on boot, so a paired extension keeps working across a
   dig-app restart without re-pairing. The per-pairing nonce high-water mark is persisted ALONGSIDE the
   record — a **plaintext, UNauthenticated** monotonic counter (`nonces.json`); nothing MACs or seals
   it. On boot the restored ledger is re-seeded from it, and the mark only ever RISES, so an ordinary
   restart cannot replay a captured frame (the restored ledger rejects any `nonce ≤` the last one
   accepted pre-restart). **Fail-closed on a missing mark:** a restored pairing with NO persisted mark
   (a deleted/absent ledger, or a pairing that never authenticated a frame) is DROPPED — requiring a
   fresh re-pair — rather than restored with an empty ledger that would accept any nonce.
   **Threat limit (honest):** because the ledger is unauthenticated, a same-user attacker with write
   access to the profile's AppData can reset / roll back / swap it, reopening a replay window at the
   channel layer. That residual is mitigated ONLY by the terminal native confirm — every replayed
   `sign.request` still requires a fresh biometric/passphrase confirm (§5.6.5), so no signature is
   produced without a human at the gate. Binding the high-water mark INTO the sealed, MAC'd pairing
   record (so it cannot be reset/rolled-back/swapped) is the robust closure and remains outstanding
   (dig_ecosystem#956).

The pairing token is defense-in-depth on the channel, not the sign gate. Token theft (by a same-user
attacker who can already read `chrome.storage.local` or the sealed record) still cannot produce a
signature without the human at the native biometric prompt (§5.6.5).

#### 5.6.3a Pairing an app DIG does not ship — the pairing CODE

The pinned `ext_id` is the trust anchor of §5.6.3, and a third party has none. A **pairing code**
replaces the pin for such callers. It is therefore the only thing between an arbitrary local process
and the user's identity agent, and all of the following are normative.

**Direction.** dig-app MUST generate the code and display it to the USER, who carries it to the app.
An app MUST NOT be able to propose a code, and MUST NOT be able to cause a code to exist. Only a
user-initiated tray action issues one.

**Shape.** A code is 8 symbols of Crockford base32 (the digits and the uppercase letters excluding
`I`, `L`, `O`, `U`), drawn uniformly from a CSPRNG with no modulo bias — a space of 32^8 = 2^40. It is
displayed grouped as `XXXX-XXXX`. On redemption the candidate is normalized before comparison:
uppercased, `I`/`L` folded to `1`, `O` folded to `0`, and every character outside the alphabet
discarded. The comparison MUST be constant-time.

**Bounds (all three MUST hold).**
- **Single-use** — a redeemed code is destroyed.
- **Time-bounded** — a code expires 120 seconds after issue. It remains redeemable AT that bound and
  MUST NOT be redeemable one second past it. An expired code is destroyed by the attempt that finds it,
  and expiry MUST NOT consume an attempt.
- **Attempt-bounded** — 5 wrong guesses DESTROY the code. Refusing only the sixth attempt is NOT
  conformant: after the budget is spent even the CORRECT code MUST fail, so the only way forward is a
  new code. An attacker therefore gets at most 5 guesses at one 2^40 secret per code a human issues:
  P(success) ≤ 5/2^40 ≈ 4.5 × 10^-12.

**At most one code is outstanding.** Issuing replaces any previous code, which is immediately dead.

**Order of checks.** The code MUST be redeemed BEFORE the native pairing confirm is raised, so a caller
with no valid code is refused having drawn no window at all. A pairing the user then DECLINES still
spends the code.

**One error, no oracle.** Every code failure — absent, wrong, expired, already used, budget exhausted —
MUST return the single code `PAIR_CODE_REJECTED`. Distinguishing them would tell a caller whether a
human is mid-pairing.

**Scope.** A pairing carries a `scope`:

| `scope` | Granted by | May call |
|---|---|---|
| `dig-extension` | a pinned `ext_id` | the control plane + `sign.request` |
| `third-party` | a redeemed pairing code | the control plane, NOT `sign.request` |

`scope` gates the MONEY method (`sign.request`) only. It is orthogonal to the `identity.*` capability
set (§5.6.8), which gates the sealing methods independently — a pairing of EITHER scope may hold
identity capabilities, and neither scope implies them. A frame is authenticated FIRST and its
authority checked SECOND, against the pairing it actually authenticated as — never against anything
the frame claimed. A `sign.request` from a `third-party` pairing, or an ungranted `identity.*` method
from any pairing, ⇒ `CAP_NOT_GRANTED`. Both `scope` and the capability set MUST survive sealing and
restart.

**Management + revocation.** dig-app MUST offer the user a surface listing every paired app — its
`ext_id`, its untrusted `label`, its scope, when it was paired, and when it last authenticated a frame
— and MUST let the user revoke any of them. `last_seen` MUST advance ONLY on a frame that
authenticated. Revocation MUST take effect on the revoked app's NEXT FRAME, on the connection it
already holds (`AUTH_REQUIRED`); deleting only the at-rest record is NOT conformant. The at-rest record
and its nonce high-water mark MUST be deleted too, so the revocation survives a restart.

**The pinned path is unchanged.** A pinned `ext_id` still pairs with no code and still signs. Making
the pin optional so one branch could serve both callers is a REGRESSION, not a simplification.

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
  contract. `addresses[]` is the active profile's wallet receive addresses (`xch1…`, first is the
  primary/change), loaded from the sealed wallet state; `pubkeys[]` is the profile's identity signing
  public key. Only this public data crosses the handle — never key material. A profile with no saved
  wallet state yet returns an empty `addresses[]` (the channel is still fully usable). On Deny/timeout
  ⇒ `CONNECT_DENIED` / `CONNECT_TIMEOUT`. The sealed whitelist entry persists
  to the profile's AppData and is restored on boot (a connected dapp survives a restart); `connect.revoke`
  deletes the at-rest record, so the revocation is durable too.
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
- **The authenticator MUST NOT run on the caller's UI thread.** A backend whose OS authenticator blocks
  the calling thread MUST run it on a separate thread and wait for the outcome, leaving the calling
  thread free to service its event loop; on Windows the caller pumps its message queue between polls.
  A UI thread blocked inside the authenticator is a deadlock, because the platform needs that thread to
  raise its prompt. The wait MUST be bounded: an authenticator that has not answered within the deadline
  yields `Unavailable`. No outcome delivered late, no failed thread, and no lost result may be treated as
  a success — an approval requires a `Verified` delivered within the deadline, and nothing else.
- **Plain-language summary (default view, MUST derive from the signed bytes).** The confirm body leads
  with a plain-language, XCH-denominated summary of the decoded spend — one line per created output
  (`Send <amount> XCH to <recipient>`, recipients shown in full) plus the network fee — with the precise
  mojo-level decode kept below under a `Details:` section. The summary is rendered ENTIRELY from the
  `DecodedTx` the policy produced from the exact bytes that will be signed (there is no second decode
  source), and it lists EVERY output the decode enumerated (never a lossy subset), so the human sees the
  full effect they authorize. It is plain text and adds no markup (the per-OS confirmers neutralize
  markup-significant characters). A net-effect preview (what leaves vs returns from local coin state) is
  a future addition gated on the engine's coin-state.
- **Non-XCH assets MUST fail closed — never a fabricated amount (MUST).** A `payload_type = "spend"`
  bundle may spend a CAT (e.g. $DIG — 3 decimals, `1 $DIG = 1000 CAT-mojos`) or an unrecognized puzzle;
  its `CREATE_COIN` amounts are NOT XCH mojos and its recipients are NOT plain XCH addresses. The
  decoder classifies each coin spend by its outer puzzle (recognizing ONLY the canonical standard-p2
  mod hash as native XCH) and enumerates XCH amounts/`xch1…` recipients ONLY for native-XCH spends. When
  any spent coin is non-XCH, the transaction is flagged (`DecodedTx::all_inputs_native_xch = false`), the
  XCH fee is suppressed, and the summary shows an explicit warning ("Non-XCH asset (e.g. a CAT / $DIG
  token) — its amount and recipient CANNOT be verified in this view…") instead of a number. Rendering a
  CAT amount with the XCH divisor would show a CONFIDENTLY-FALSE figure (a million-$DIG drain reading as
  dust XCH), so the summary MUST NEVER do so. Full $DIG-aware rendering (recognize the canonical DIG
  asset id; show `$DIG` + the correct 3-decimal amount + the CAT-wrapped address) is a follow-up CAT
  decoder that will replace the warning for recognized assets.
- **Domain-separated signing (MUST — reuse, do not re-derive).** On approval the app signs, with the
  in-memory slot `0x0010` key, NOT `payload_b64` but the §5.3 domain-separated message:

  ```
  "DIGNET-SIGN-v1" ‖ len16(payload_type) ‖ payload_type ‖ payload
  ```

  (constructed by `session.rs::sign_callback_message`; `len16` = big-endian `u16` byte length of
  `payload_type`). This is the identical construction the engine `sign` callback uses, so a signature
  minted here is bound to its `payload_type` and cannot be replayed as a session attach (§5.3), a
  differently-typed spend, or any other `0x0010` signature (§3 domain-separation invariant).
- **Response.** `{ signature_b64, pubkey_hex }` — the 96-byte detached BLS12-381 G2 signature over the
  message above, and the 48-byte G1 signing public key. **Only the signature returns; the private key never
  leaves dig-app.** A deny/timeout/decoder-failure ⇒ the matching §5.6.7 error. The JSON-RPC `id`
  correlates the response with its request across the async confirm.

#### 5.6.6 Key custody (this path)

Identical to §2.3 / §5.3: dig-app signs in-process with the in-memory unlocked slot `0x0010` key and
returns only the signature. Both callers — the §5.3 engine `sign` callback AND this loopback
`sign.request` — funnel through **one** `SignPolicy` custody gate (§5.3), so there is a single sign
authorization point with no divergence: the production policy is the native-confirm policy; the
`AllowAll`/`DenyAll` policies (`session.rs`) remain test doubles only.

#### 5.6.8 The `identity.*` capability class (end-to-end message sealing)

The `identity.*` methods are a SEPARATE capability axis from the money `sign.request` boundary
(dig_ecosystem#1931/#1913). They let a paired app — dig-chat is the first — reach the profile's
X25519 **sealing** keypair to send and open `DIGCHAT1` end-to-end-encrypted messages (NC-1), WITHOUT
ever obtaining the spend/identity signing power. The separation is structural, not advisory:

- **Two independent gates.** `sign.request` is gated ONLY by the pairing `PairingScope` (§5.6.3a) —
  a pinned DIG extension. `identity.attest` / `identity.seal` / `identity.unseal` are gated ONLY by a
  per-pairing **granted capability set**. A pairing MAY hold every identity capability and a
  non-signing scope; an identity grant can NEVER open `sign.request`. A KNOWN identity method a
  pairing was not granted ⇒ `CAP_NOT_GRANTED`; a method that does not exist ⇒ `-32601` (they are
  distinct).
- **Granting.** `pair.begin` MAY carry `requested_capabilities: string[]`; the app grants the
  recognized `identity.*` names (unknown names dropped) and echoes the result as
  `granted_capabilities` in the `pair.begin` result. The set is stored on the sealed pairing record
  and is `serde(default)` — a record sealed before this class existed opens as the EMPTY set,
  refusing every `identity.*` method (§5.1 back-compat). The set MUST survive sealing and restart.

**`identity.attest`** (params `{}`) → `{ did, sealing_public_key_b64, attestation_b64 }`.
`sealing_public_key_b64` is the 32-byte X25519 sealing public key (base64). The sealing keypair is
DERIVED deterministically from the account master seed (dig-account
`profile_sealing_key`/`profile_sealing_public_key`), so a restored profile reproduces the identical
key and every message sealed to it stays openable forever (§5.1). `attestation_b64` is the BLS
`0x0010` identity key's signature over

```text
DIGATTEST1_DST ‖ sealing_public_key      where DIGATTEST1_DST = 0x44 49 47 41 54 54 45 53 54 31 00  ("DIGATTEST1\0")
```

The `DIGATTEST1\0` domain-separation prefix is MANDATORY: the identity signer signs raw bytes and is
shared with session-attach and `dign sign`, so the prefix is what stops an attestation signature
being replayed as a session or spend message. `identity.attest` takes no per-call confirm and no
connect gate — the capability grant at pair time IS the authorization, and it is the probe a client
uses to reach a `connected` state.

**`identity.seal`** (params `{ recipient_did, recipient_sealing_public_key_b64, plaintext_b64 }`) →
`{ envelope_b64 }`. Seals the plaintext into a `DIGCHAT1` envelope (below) addressed to the
recipient's sealing key. DIGCHAT1 suite 1 is a **sealed-box**: it gives confidentiality to the
recipient but does NOT authenticate the sender. This profile's DID is carried as `sender_did` and
bound into the AEAD AAD for transit-integrity — a relay cannot re-address the envelope — but the AAD
binding does NOT authenticate the sender to any key: anyone holding the recipient's published sealing
key can seal with any `sender_did`. It is therefore an UNVERIFIED claim. Sender authentication is
tracked as DIGCHAT1 suite 2 (#1940). A fresh random ephemeral key + nonce are drawn per call. The
plaintext MUST NOT be retained.

**`identity.unseal`** (params `{ envelope_b64 }`) → `{ sender_did, plaintext_b64 }`. Opens an envelope
addressed to this profile with the profile's sealing SECRET. `sender_did` is the sender DID carried in
the envelope header — an UNVERIFIED claim under suite 1 (see the seal note). A locked
profile ⇒ `LOCKED`; a well-formed envelope that does not authenticate (wrong recipient,
tampered/re-addressed header, corrupted body) ⇒ `UNSEAL_FAILED`; malformed input ⇒
`IDENTITY_BAD_REQUEST`.

##### The `DIGCHAT1` envelope (byte contract, big-endian)

This is byte-identical to dig-chat's normative reference (`src/main/identity/envelope.ts` +
`conformance.ts`, dig-chat SPEC §4). A message one side seals the other MUST open.

```text
offset  size  field
  0      8    magic       "DIGCHAT1"  (44 49 47 43 48 41 54 31)
  8      1    version     0x01
  9      1    suite       0x01 = X25519 / HKDF-SHA256 / XChaCha20-Poly1305
 10      2    sender_did_len       u16
 12      n    sender_did           UTF-8   (1..=512 bytes)
  …      2    recipient_did_len    u16
  …      m    recipient_did        UTF-8   (1..=512 bytes)
  …     32    epk                  X25519 ephemeral public key
  …     24    nonce                XChaCha20-Poly1305 nonce
  …      4    ct_len               u32
  …      k    ciphertext           AEAD output, 16-byte tag included
```

- **Suite 1.** Key agreement X25519 (ephemeral-static). Key derivation HKDF-SHA256 with
  `salt = "DIGCHAT1"` (the 8 magic bytes), `info = "DIGCHAT1 suite1 message key"`, `L = 32`, and
  `IKM = shared_secret ‖ epk ‖ recipient_sealing_public_key`. AEAD XChaCha20-Poly1305, 24-byte nonce
  drawn at random.
- **Associated data** = `magic ‖ version ‖ suite ‖ sender_did_len ‖ sender_did ‖ recipient_did_len ‖
  recipient_did ‖ epk`. Binding the DIDs + epk means a relay that re-addresses or replays an envelope
  under a different header produces a decryption failure, not a delivered message.
- **Bounds.** A DID is 1..=512 bytes; the plaintext is at most **49,152 bytes (48 KiB)**, chosen so a
  sealed envelope with two maximal DIDs fits inside the DIG peer layer's 64 KiB decoded-frame ceiling.
  A decoder MUST check every length against the bytes remaining before reading, and MUST reject
  trailing bytes, a non-UTF-8 DID, an unknown version, and an unknown suite.
- The two DIDs and the epk travel in the clear (a relay must read them to route); **message content
  is never visible to a relay**. No primitive is hand-rolled (NC-1).

#### 5.6.7 Error-code taxonomy

Stable symbolic codes returned as JSON-RPC errors (the extension keys UX off these, not off prose):

| Code | Meaning |
|---|---|
| `AUTH_REQUIRED` | no valid pairing for this frame (unpaired / revoked) |
| `AUTH_BAD_MAC` | pairing-token MAC verification failed |
| `AUTH_REPLAY` | frame nonce not strictly greater than the last accepted |
| `PAIR_DENIED` / `PAIR_TIMEOUT` | user denied / did not answer the pairing confirm |
| `PAIR_CODE_REJECTED` | an unpinned caller offered no pairing code, or one that was wrong, expired, already used, or past its attempt budget (§5.6.3a) — ONE code for all of those, deliberately |
| `CONNECT_REQUIRED` | the `origin` is not whitelisted for the active profile |
| `CONNECT_DENIED` / `CONNECT_TIMEOUT` | user denied / did not answer the connect modal |
| `SIGN_DENIED` / `SIGN_TIMEOUT` | user denied / did not answer the sign confirm |
| `SIGN_UNKNOWN_TYPE` | `payload_type` not on the decoder allowlist (blind-sign refused) |
| `SIGN_BAD_PAYLOAD` | known type, but the payload did not decode for display |
| `SIGN_NO_CONFIRMER` | no desktop session — native confirm unavailable (headless fail-closed) |
| `LOCKED` | the active profile could not be unlocked (wrong passphrase / failed biometric) |
| `CAP_NOT_GRANTED` | the frame authenticated, but the pairing does not hold the capability that gates that method — a `third-party` pairing reaching `sign.request` (§5.6.3a), or a pairing reaching an `identity.*` method it was not granted (§5.6.8) |
| `IDENTITY_BAD_REQUEST` | an `identity.*` request was malformed: missing/oversized field, a `payload`/`envelope` that was not valid base64, or a sealing key of the wrong length (§5.6.8) |
| `UNSEAL_FAILED` | an `identity.unseal` envelope decoded but did not authenticate under this profile's sealing key — wrong recipient, tampered/re-addressed header, or corrupted body (§5.6.8) |

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

- **Transport = mTLS for node-class clients — on the surfaces that offer it.** dig-app (and `dign`,
  and any filesystem client holding a DIG identity key) presents a client cert derived from the profile
  identity key (§5.3 ecosystem contract) on every node surface that accepts one.
  **The CONTROL plane is not currently one of them.** The engine's mTLS listener serves the
  **wallet** (Sage-parity) surface only; `control.*` is dispatched on the plain loopback HTTP
  listeners and is authorized by the **control token** (§5.1.0). So a conformant dig-app reaches
  `control.*` over plain loopback HTTP + token, and MUST NOT be read as requiring mTLS there — that
  requirement is unsatisfiable against a real engine today. Stating it unconditionally is what would
  make this document contradict §5.1.0. Gate any hard mTLS requirement on the engine exposing a
  control surface that accepts a client cert.
- **End-to-end sealing on directed channels.** Any message dig-app sends to an intended recipient over
  a channel an intermediary could terminate MUST be sealed to the recipient's dig-identity BLS G1
  identity key (slot `0x0010`, G1-DHKEM) *on top of* whatever transport authentication that channel
  has (ecosystem §5.4). The transport authenticates and encrypts the *channel*; the payload is sealed
  independently, so a relay or any other intermediary that terminates the channel sees only ciphertext.
  The seal is therefore never waived because a transport happens to be mTLS — or because it happens to
  be loopback.
- **Threat model (summary).**
  - A non-admin user U2 cannot read U1's data — U1's per-profile AppData is ACL'd to U1, and (on
    §5.1.1) the pipe/socket ACL is per-user with the engine opening a session only for a profile the
    caller can sign for. **On the live §5.1.0 transport the channel contributes no such separation**:
    the engine's loopback control port is reachable by any local user, so the boundary is the
    **control-token file's ACL** — a user who cannot read that file cannot drive `control.*`. The
    engine deliberately refuses a foreign-owned token file rather than trusting it.
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
  - **The second factor (§3.1e) does not change that boundary, and MUST NOT be described as if it
    did.** Its secret is verified locally, so an attacker at the-user-is-the-user level can read it.
    What it adds is a factor on ANOTHER DEVICE for the destructive verbs, which is what makes a
    shoulder-surfed unlock credential or an unattended unlocked machine insufficient to destroy an
    account.

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
| `ipc` | per-user OS channel address resolution (`channel_endpoint`) — §5.1.1, addressing only; nothing answers it yet | U1 (addressing) |
| `control` | the LIVE loopback dig-node control client (§5.1.0): §5.3 endpoint ladder, control-token discovery, one blocking JSON-RPC exchange, typed `control.status` | #949 |
| `environment` | resolved per-user host facts (`AppEnvironment`) all boot decisions derive from | U3 |
| `config` | the agent's non-secret on-disk runtime settings (`AgentConfig`, AppData; plaintext pre-U4) | U3 |
| `engine` | the node link the status surface renders: `EngineState` (connected-with-snapshot / disconnected-with-reason) + the live `NodeConnector` over `control` (`NullConnector` is a test double only) | #949 |
| `shutdown` | the cooperative shutdown latch (`Shutdown`) that stops the run loop promptly | U3 |
| `agent` | the per-user agent lifecycle: start/stop, reconcile run loop, live `AgentStatus` | U3 |
| `keystore` | hold / unlock / sign; DIGOP1 sealing; rotation; OS-credential-store primary + sealed-file fallback | U4 |
| `account` | master-HD custody harness (SECURITY-CRITICAL, 2.0.0): [`registry`] (default/active account tracking), [`residency`] (live, lockable unlocked-account home with fail-closed [`ResidencySigner`]/[`ResidencySealer`]), [`money`] (authorize-before-sign [`SpendSummary`] gate + signing), [`sealer`] (profile DEK derivation), [`ceremony`]/[`auth`]/[`lifecycle`] (confirmation/enrollment/lifecycle) | 2.0.0 |
| `wallet` | per-profile wallet state (address/coins/balance, DIGOP1-sealed per-profile), engine broadcast seam (`WalletEngine`), signed bundle encoding | U5 |
| `events` | event-driven wallet UI seam: `EventFeed`/`EventSink` + `EventDriver` (cursor/filter, `catch_up` backfill, graceful resync) + reactive `WalletView` (§3.7) | #1008 |
| `notify` | debounced native funds-activity notifications off the event stream (§3.7, #970) | #970 |
| `gateway` | route each command (local vs proxy-to-engine) + dispatch over the `EngineProxy` / `LocalIdentity` / `LinkOpener` seams; catalogued `ErrorCode` + `--json` envelopes | U7 |

The `dig-app` binary is the tray / menu-bar shell over the `agent` core (Windows system tray · macOS
menu-bar · Linux AppIndicator) and **degrades headless** (§4) when no display is present or the tray
cannot mount; the tray is the crate's default `tray` feature, so a headless build omits the desktop
stack entirely. U3 delivers `environment`/`config`/`engine`/`shutdown`/`agent` + the shell; the
agent reaches a node through the `EngineConnector` seam, whose production implementation
(`NodeConnector`, #949) probes the §5.3 ladder each tick and publishes the node's own
`control.status` snapshot, so the tray and the headless log both show real node state.

The engine-side of the IPC contract (the `control.session.*` methods + the `sign` callback) is
implemented in the dig-node repo (U2/U6), not here.

### 8.1 The `--version` contract (normative)

**Every dig-app binary — `dig-app` and `dign` — MUST answer `--version`.** This is not a convenience: it is
the interface the ecosystem's update beacon uses to health-gate an installed component, by spawning
`<binary> --version` and reading its output. A binary that ignores the flag does not fail loudly — it does
whatever it would have done with no arguments and prints nothing the probe can read, so the beacon
concludes the install is unverifiable and keeps reinstalling it.

The contract the probe imposes:

- **`--version` MUST write to STDOUT and exit 0.** A non-zero exit is discarded, and stderr is not read.
- **The last whitespace-separated token of the FIRST line MUST be a bare `MAJOR.MINOR.PATCH`** (an
  optional `v` prefix is accepted). Extra dot-segments, a pre-release suffix, or any trailing text after
  the number makes the version unparseable. The conventional form is `"<binary-name> <semver>"`.
- **The version MUST be read from the crate metadata**, never written out as a literal, so a release bump
  cannot leave the binary reporting a stale number.
- **`--version` MUST have no side effects.** It MUST NOT start the agent, mount a tray, open a signing
  channel, or create log files — an update check runs it routinely, and on every installed component.
- `-V` MUST be accepted as its short form, and `--version` MUST win over any other argument on the line,
  so the probe is answerable regardless of what else a launcher passes.

`--help`/`-h` MUST likewise print to stdout and exit 0 without side effects, and MUST name both ways into
the app: the tray menu for a person at a desktop, and `dign` for a terminal.

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
5. **Node connection (§5.1.0)** — the control-plane ladder is walked in order, a configured endpoint
   is tried alone, `http://dig.local` resolves from the URL scheme rather than the node's high port,
   the IPv6 loopback is preferred over IPv4, the control token is read from dig-node's own state-dir
   candidates, a live node's `control.status` round-trips over a REAL socket, and a node that answers
   but refuses is reported distinctly from no node at all (`control`, `engine`).
6. **IPC addressing (§5.1.1)** — `channel_endpoint` yields the correct per-user named pipe / socket
   path; distinct users get distinct endpoints. Addressing only — nothing answers it yet.
7. **Headless degrade** — no display ⇒ `FormFactor::Headless` (no tray); a display ⇒ `Tray`.
8. **Signing-through-dig-app** — an engine-initiated `sign` callback (§5.3) is answered by dig-app and
   the key never crosses the IPC boundary.
9. **Multi-user concurrent sessions** — two attached sessions for different profiles coexist, each
   with its own `session_id` in the engine's session map (§5.3), and a `sign` callback routes to the
   owning connection.
10. **Never-log at source** — a captured, real emitted-record test proves a passphrase live in scope
    during a vault create/unlock never reaches a logged field or message (§9a).

U1 ships tests (4), (6), (7) and the `IdentityKind` predicate for (1); (5) ships with the live
control client (#949); the remaining tests land with the work units that implement their subsystems.

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
