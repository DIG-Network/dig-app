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
(idle timeout / lock-now) drops the residency and thereby relocks the running sign +
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
callback §5.3, `DIGNET-USER-SIGN-v1` for the local `diga sign` §3.5). This makes a signature minted
for one purpose provably non-verifiable for any other,
closing cross-protocol signing oracles (a signature obtained for purpose A cannot be replayed as a
valid signature for purpose B — including an attach challenge, a spend hash, or an SMT write). Each
verifier reconstructs the identical tagged byte string; the construction is byte-identical across the
app and every counterpart (the engine, a reimplementation).

**At-rest storage (bootstrap unlock).** The account master seed MUST be held as a DIGOP1 blob sealed
under **Argon2id over a password the USER chooses**, in a per-user file backend
(`<brand-dir>/account/account.<id>.dks`), written durably and atomically (temp file → fsync → rename →
parent-dir fsync) and ACL'd to the owning user (mode `0600` where POSIX modes apply). There is ONE
custody primary on every platform, and this is it.

**The password MUST NOT be persisted — not on disk, not in an OS credential store, not in a log.** It is
collected at unlock from the person, in the app's own native masked window (§3.2a, dig_ecosystem#1817).
That separation is the whole guarantee: an attacker who dumps the sealed blob obtains Argon2id-hardened
ciphertext and nothing that opens it, because the two never live beside each other.

- **There is NO storage precedence and NO fallback tier.** Earlier revisions of this section specified an
  OS-credential-store primary on Windows/macOS with a sealed-file fallback, and described the two as a
  detected-once precedence. That model is RETIRED and MUST NOT be implemented: it kept a
  machine-generated password in the credential entry beside the ciphertext, so any code running as the
  logged-in user could open the account and no user-known secret protected custody at all. No boot,
  unlock or sign path may source a password from an OS credential store. An implementation that offers a
  password-less unlock path has reinstated the retired model, whatever it stores it in.
- **The OS credential store is a MIGRATION-ONLY seam** (Windows/macOS; Linux never used one — the kernel
  keyutils session keyring is readable by any same-UID process and does not survive a reboot). Its two
  permitted uses are: reading a retired machine password ONCE to re-seal the same seed under a password
  the user chooses (§3.2a), and deleting a leftover entry when an account is discarded. A host whose
  credential backend is unavailable therefore loses NOTHING — there is no fallback to reach, because
  there is nothing here custody depends on.
- **Linux** has no account paths yet: it has no window stack for the password prompt, so account boot
  defers rather than enrolling something it cannot ask to unlock (dig_ecosystem#962).

Unlock **fails closed**: a wrong password, a tampered blob, or a foreign key yields an error that never
produces partial plaintext. It MUST, however, be distinguishable at the TRAY from a blob this build
cannot read at all — see §3.1c, where only the latter may report `Unopenable`.

### 3.1a The recovery phrase (normative)

An account's master seed MUST be the entropy of a **24-word BIP-39 mnemonic**, the account's *recovery
phrase*. The phrase is the ONE portable custody root: a sealed seed blob copied to another machine is
inert without the password its owner chose (§3.1), and a blob whose password is forgotten is
unrecoverable, so the words are the only thing a user can carry to a new machine — or back from a lost
one.

- **Mapping.** A 24-word phrase carries exactly 32 bytes of entropy, and that entropy is what DIG
  stores AT REST (`dig_session::ENTROPY_LEN` = 32). It is NOT the master seed. At derive time it is
  expanded to the 64-byte BIP-39 master seed (`dig_session::MASTER_SEED_LEN` = 64) by
  `Mnemonic::to_seed("")` — standard BIP-39 §5 PBKDF2 with the empty passphrase Chia uses. Phrase to
  entropy remains a lossless bijection, so a restore reaches the identical identity, wallet key and
  per-profile DEK with no stored state whatsoever.
- **This IS the Chia mnemonic derivation (MUST stay so).** Because the expansion is BIP-39 §5 with an
  empty passphrase, a DIG recovery phrase reproduces byte-identical addresses in Sage, in
  `chia-blockchain`, or in any conforming Chia wallet — and a Chia wallet's phrase restores the same
  account here. An implementation MUST NOT derive from the raw entropy, and MUST NOT use a non-empty
  BIP-39 passphrase; either silently forks every address from every standard client.

  Pinned by a frozen golden vector in `dig-session/tests/chia_conformance.rs`: `abandon` ×23 + `art`
  at wallet index 0 yields `xch16grurcglcwcv6arjarr720yd9wqhp9gkx3k8h25lhwg8pl7vl6ysuax0gy`,
  cross-checked against `chia-blockchain` 2.5.6.

  **Two different things are called a "master seed", which is what made the earlier text wrong.**
  `RecoveryPhrase::master_seed` (this crate) returns the 32-byte ENTROPY; `UnlockedMasterSeed::master_seed`
  (dig-session) returns the expanded 64 bytes. Reading the first as the second is how this section came
  to assert the opposite of what the code does, and a custody review acting on that near-fixed a
  correct money path (dig_ecosystem#1759).
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
- **Backup destination (MUST).** A file backup MUST ask the user where to write, through the platform's
  own save dialog (`secret_file::picker`), defaulting the name to `dig-recovery-phrase.txt`. Dismissing
  that dialog MUST abandon the write and be reported as a refusal — an implementation MUST NOT redirect
  the words to a default path the user has just declined. Where no dialog can be raised (a headless host,
  or a desktop with no dialog helper) the implementation MUST fall back to `dig-recovery-phrase.txt` in
  the user's home directory rather than lose the capability, and where even that directory is unknown it
  MUST report failure rather than invent a path. A fixed, predictable destination is not acceptable as
  the primary behaviour: it is a path another local process can watch for, and it denies the user a
  removable or encrypted volume of their own.
- **Backup file permissions (MUST).** The file MUST be restricted to its owner **at creation** — there
  MUST be no interval in which the plaintext seed exists on disk at a wider permission, including when an
  existing file at that path is being replaced. On Unix this is mode `0600`, supplied to `open(2)` and
  re-applied while the file is truncated and empty. **On Windows it MUST be an explicit, PROTECTED DACL
  holding a single access-allowed entry for the calling user's SID**; inheriting the profile directory's
  ACL is NOT sufficient, because that grants the local Administrators group and SYSTEM — and therefore
  every service, backup agent and indexer holding those tokens — full access to the account's custody
  root. Mode bits have no meaning on Windows, so a `set_permissions` call there satisfies nothing. A
  failure to restrict the file MUST be reported as a failed backup; an implementation MUST NOT write the
  words and then report success because only the permission step failed, and MUST NOT report success for a
  file whose restriction did not actually take effect — a platform whose permission call can succeed
  without changing anything (a `chmod` on a filesystem that stores no mode) MUST therefore be verified
  after the fact, not assumed. (`secret_file::write_owner_only`.)
- **Volumes that cannot store permissions (normative, and deliberately asymmetric).** A user-chosen
  destination may be a filesystem with no access control at all — a FAT/exFAT removable disk, which is a
  destination the save picker exists to enable.
  - **On Windows** the write MUST proceed there. The volume is identified by its own reported
    capabilities (the absence of persistent-ACL support), NOT by inference from a failed permission call,
    and not by filesystem name — the same capability is absent on some network redirectors and
    user-space filesystems, and all of them are handled alike. Nothing is downgraded, because such a
    volume grants everyone everything by design, and the confirmation window's standing disclosure that
    the file is plaintext and readable by anyone who can reach it is what makes proceeding honest.
  - **On Unix** such a destination MUST instead be a FAILED backup. The equivalent capability question
    has no portable spelling, so an implementation refuses rather than guessing. This asymmetry is
    intentional and is recorded here so it reads as a decision rather than an oversight; closing it
    requires answering the capability question on Unix properly.
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

The DID wizard MUST open when the app starts and this computer has an enrolled account with no minted
DID, at the wizard's DID step (`account::journey::startup_wizard`). Two refusals are normative, and
neither may be relaxed:

- It MUST NOT open on a host that cannot complete a mint. A blocking window whose only forward control
  cannot work has no way out but the close button, on every launch, for every account. Availability is
  reported as `account::chain_mint::MintAvailability`; a wallet with no FUNDS is NOT this case and MUST
  still reach the wizard, because the funding step is what tells that person what to do.
- It MUST NOT open on a computer with no account. Reading DIG content needs no account, no wallet and
  no DID (§3.1c), and answering "no DID was minted" with an unrequested account-creation flow at every
  launch would break that.

**Current state:** the mint itself is implemented and proven. `dig-account` 0.6.0 exposes
`UnlockedAccount::profile_minter`, and `account::chain_mint::ChainMint` drives `begin_did_mint` →
`mint_status` end to end through a Chia consensus validator. The minter is derived from the residency
per call and never retained, so a mint observes lock-now and the idle timeout
exactly as the money signer does.

The chain TRANSPORT now exists. `dig-node-control-interface` 0.10 declares five OPEN chain reads plus
the token-gated push, dig-node 0.110.0 serves them, and `chain::ControlChainSource` /
`chain::ControlSpendPublisher` implement `dig_chainsource_interface::ChainSource` and
`dig_account::mint::SpendPublisher` over them. Those two types MUST obey the three-valued rule below;
in particular a failed read MUST NOT become `Ok(None)` or an empty `Vec`, because on `coin_spend`
an absence means *unspent or unknown*, which a caller reads as safe to spend.

**A PRESENT coin MAY be believed from any answering tier; an ABSENCE MAY be believed only from a tier
reporting `synced: true` — and today that rule is ENFORCED on exactly one read (normative).** Every
`control.wallet.*` result discloses the tier that answered it (`source` / `synced` / `peak_height`). A
tier that is behind can only be BEHIND, never ahead, so existence is positive evidence it cannot
fabricate — but emptiness is the one answer a stale replica produces indistinguishably from the chain
itself.

`coin_records_by_puzzle_hash` (`control.wallet.coins`) MUST return a `ChainReadError` naming the tier
when an EMPTY answer arrives with `synced: false`; a non-empty answer MUST be returned unchanged
whatever the tier. That read is scoped to an address, so dig-node answers it from its own database and
`synced: true` is routinely obtained. Enforcing it there stops `select_funding_coin` reporting
`InsufficientFunds { available: 0 }` against a wallet the user can see has money in it.

`coin_record` (`control.wallet.coinById`) and `coin_records_by_parent` (`control.wallet.coinsByParent`)
MUST NOT enforce it, and MUST return an unsynced absence as an answer. This is a deliberate, documented
and temporary narrowing whose cause is producer-side: dig-node's
`crates/dig-wallet/src/sage/routing.rs:31-40` routes any read NOT scoped to the wallet
(`scoped_to_wallet = false`) to the fallback tier whatever its own sync state, and the reply then
carries the local database's flag (`rpc.rs:577`) though the database did not answer. Measured against
dig-node 0.118.1 while synced at peak 9148856 with five chia peers, `coinById` reported
`source: "fallback", synced: false, peak_height: null` **both for an absent coin and for a coin that
node's own database held**. A guard there is therefore not strict but permanently on, and permanently
on closes profile creation on every healthy machine: `ChainReadiness::probe` proves a source can walk a
lineage by resolving an all-zero launcher id — one chosen because it names no coin, so `Ok(None)` is
the proof — and that walk's first read is `coin_record`. Guarded, `ProfileMintAvailability::Possible`
is unreachable and no profile can ever be created. When dig-node's routing lets these reads report a
real sync state, the rule MUST be extended to cover them.

**A mint verdict of FAILURE MUST NOT be drawn from an unwarranted absence (MUST).** Because
`coin_record` cannot carry a warrant, `dig_account::ProfileMinter::mint_status` — which concludes
*"the funding coin was spent by a different spend; this mint can never confirm"* from a DID coin read
as absent beside a spent funding coin — can reach that conclusion for a mint that CONFIRMED. The
remedy is on the CONCLUSION rather than on the read, because guarding the read only converts the false
failure into a false *"the chain could not be reached"*.

A chain source therefore discloses an `AbsenceWarrant`: `Warranted` when the tier that answered its
most recent read reported `synced: true`, and `Withheld` otherwise — including before any read has
been answered. `ChainMint::look` MUST report `MintStatus::Failed` as `Sighting::Rejected` ONLY against
a `Warranted` source, and MUST otherwise report `Sighting::Unreachable`. `Confirmed` needs no warrant:
it rests on a coin being PRESENT, which a behind replica cannot fabricate.

The warrant MUST NOT be modelled as an `Option`, a boolean, or anything else that an unwrapping caller
collapses back into absence. Being wrong in the unknown direction is survivable — an unknown mint is
waited on, and a wrongly-rejected one is mourned while its identity sits on chain and its XCH is
spent. A surface MUST render an unresolved mint status as *unknown / still checking*, never as a
failure and never as blocked.

### 3.1d Whole-profile minting (normative)

A DID is never minted alone. A **dig-profile** is a DID singleton PLUS a dig-store launched from that
DID's coin, and an implementation MUST treat the pair as one ceremony: the state in which the DID is
confirmed and the store is not (`dig_account::mint::ProfileMintStatus::DidConfirmedStoreNotLaunched`)
is funds committed, an identity on chain, and no profile.

**The capability gate has three states, not two.** An implementation MUST distinguish *cannot reach
the chain* from *can reach the chain and cannot finish the ceremony*, and MUST offer profile creation
only in the third state, where both halves are reachable
(`account::profile_mint::ProfileMintSeams`). The second state is reached whenever
`ChainSource::resolve_singleton_lineage` cannot be serviced, because the store half re-derives the
DID's puzzle material by walking that lineage. Offering a mint there spends real XCH on a ceremony
that cannot complete, which is worse than offering nothing.

The three states MUST be distinguished by asking REACHABILITY before CAPABILITY: a peak read first,
then the lineage probe. Once the walk is genuinely served, an unreachable node fails the walk probe
too, so a single probe reports every stopped node as a build that cannot finish a mint — which sends
the user to wait for a release when the remedy is to start their node.

Availability MUST be READ OFF the seams rather than asserted beside them: obtaining a mint and
reporting that minting is possible MUST be the same value, so the two cannot drift. The check MUST be
a live probe of the source, and every failure of that probe — unsupported, timeout, depth bound,
reveal-size bound, transport — MUST withhold the offer. **No lineage-walk failure may be reported as
an absent lineage**, because on a mint path "the lineage ends here" reads as *safe to spend*.

**The journal write is not optional.** `begin_profile_mint` records its reservation BEFORE pushing and
retains it when the chain is unreachable, since the bundle may yet be included. An implementation
MUST persist the registry between the mutation and its return
(`account::profile_session::ProfileSession::with_journal`) and MUST NOT roll the registry back when
that write fails: a journal entry naming a pushed bundle is the only local record of a spend that is
already on the network. A mint that succeeded against a failed write MUST be reported as its own
outcome, distinct from a failed mint, because the remedy differs — the second invites a retry and the
first must forbid one.

A reserved profile index MUST remain reserved across a restart, so a second mint at that index is
refused rather than paid for twice.

**An implementation MUST NOT declare a mint dead on elapsed time.** It MAY report how many blocks have
passed since the push, and MUST NOT derive a verdict from that number. Death MAY be reported only on
chain evidence — the funding coin observably consumed by another spend while the coin this bundle
would have created does not exist — and a chain that could not answer MUST read as unknown, never as
dead and never as waiting (`account::profile_mint::MintLiveness`). The asymmetry is the reason: a mint
wrongly called dead leads the user to mint again, after which the original confirms and they have paid
twice and own an orphan DID.

**The creation surface MUST collect the profile's content BEFORE the ceremony starts, and the mint
MUST seed the store with it.** The store singleton is launched at the seed's root
(`dig_account::mint::ProfileSeed`), so content collected before the mint is committed by the store's
FIRST generation; collecting it afterwards costs a second chain write for the same result. The rules:

- Every field MUST be optional. An empty seed is a valid whole profile, and an implementation MUST
  NOT require any value in order to mint.
- An empty seed MUST still be the schema-stamped profile (`Profile::with_schema_v2`), never a
  literally empty tree — an empty tree's root is all zeros, which `dig-social-profile` refuses as an
  anchor because a bare five-byte body verifies against it.
- A collected value MUST reach the slot the schema gives it, through ONE field-to-slot mapping shared
  with the editor (`profile_edit::field::ProfileField::slot`). In particular an image the person
  chooses is a data URL and MUST be written to the INLINE slots `0x0020`/`0x0021`, never to the
  `dig://` reference slots `0x0003`/`0x0004`.
- Every value MUST be validated with the editor's own rules BEFORE the ceremony begins — the
  canonical bech32m decode for a payment address, the accepted data-URL shape for an image, and the
  per-slot and whole-body size ceilings. At mint time a refused value is money already committed.
- The seed is a pure function of its slots and MUST remain so, since a resumed mint rebuilds the same
  commitment from it without having journalled a root. An implementation that resumes a ceremony
  ACROSS A RESTART MUST persist the collected seed beside the mint journal; one that does not resume
  across a restart MUST say so to the person rather than rebuild from an empty form.

**No API may return a DID it has not seen confirmed.** A create entry point MUST return what was
reserved — the profile index and the DID coin id this host computed — and MUST NOT return, print or
otherwise report a `did:chia:` string before an on-chain confirmation
(`gateway::local::PendingProfileCreation`). A CLI create path MUST NOT block for the mint's duration.

`chain::ControlChainSource::coin_records_by_parent` MUST page `control.wallet.coinsByParent` to
exhaustion, resuming only from the `cursor` the previous page returned, terminating only on
`complete: true` — never on a short page — and MUST fail rather than return a prefix when its own page
bound (`chain::MAX_CHILD_PAGES`) is reached. It MUST also refuse a page carrying more rows than the
limit it asked for (`chain::CHILD_PAGE_SIZE`), because the page bound's guarantee is stated in rows,
and it MUST record freshness only from a walk that COMPLETED — freshness answers whether a coin is
really unspent, so a value left by a walk that later failed answers it from a read that errored.

`chain::ControlChainSource::coin_records_by_puzzle_hash` is specified by the trait over ALL coins
paying to a puzzle hash, but `control.wallet.coins` is scoped to ONE asset. This implementation reads
**XCH only**, and MUST be understood as such: a puzzle hash holding only $DIG CAT coins answers an
empty `Vec`, which on that trait means *no matching coins*. The narrowing is permitted only while the
sole caller selects XCH funding coins; the address it derives likewise uses the mainnet `"xch"` HRP
unconditionally. Because `control.wallet.coins` MUST echo the concrete asset it was scoped to, the
client MUST verify each returned record's asset and treat any other value — including an absent one —
as a malformed answer rather than an XCH coin.

`chain::ControlSpendPublisher` MUST classify a mempool refusal as `PushOutcome::AlreadyInMempool` only
when the reason is exactly the duplicate token `ALREADY_INCLUDING_TRANSACTION`. `rejection` is
free-form prose the control contract does not pin to a vocabulary, so a substring match would let a
hostile node have a refusal reported as a success; every other refusal, including `MEMPOOL_CONFLICT`,
is a `PushOutcome::Rejected` whose remedy is a rebuild. A reply asserting both acceptance and a
refusal MUST NOT be read as an acceptance.

`chain::ControlChainSource::resolve_singleton_lineage` MUST delegate to
`dig_chainsource_interface::walk_singleton_lineage` and MUST NOT be hand-rolled
here — a coin's puzzle hash is attacker-chosen, so a second implementation of singleton
authentication is a second forgery surface. It MUST use the PLAIN variant, whose default
`WalkBounds` carry both denial-of-service guards — the canonical `MAX_LINEAGE_DEPTH` hop cap and the
`DEFAULT_WALK_BUDGET` wall-clock budget — so a provider inherits them rather than restating them; the
`_bounded` and `_within` variants exist for tests that exercise a guard over a short chain.

Every `LineageWalkError` MUST become an error, and each MUST keep its own REMEDY. A failed source read
passes through unmodified; a budget overrun is a retry, not an accusation that the node lied; and a
refusal for reveal SIZE or lineage DEPTH is neither a retry nor a corruption report
(`chain::ChainReadError::Unusable`) — a consumer that cannot tell *too big* from *corrupt* cannot tell
a hostile peer from a heavy one.

`dig_did::walk_did_lineage_to_tip` calls that read, and `ProfileMinter::advance_profile_mint` calls
it in turn to launch the profile's store, so a profile mint cannot complete without it. A mint pushed
on a transport that cannot finish phase B leaves funds committed, an identity on chain, and no
profile, permanently.

The read is now served, so that is no longer what withholds a mint. What withholds it is WIRING: the
shell constructs no `chain::ControlChainSource` and no publisher, so it still supplies
`account::chain_mint::MintSeams::NoChainTransport`, the startup gate correctly draws nothing, and no
`TrayAction` mints. An implementation MUST NOT report profile creation as possible until a create
control, its verb and its wizard exist to complete the ceremony — offering the capability without the
flow is the dead end dig_ecosystem#1800 removed and dig_ecosystem#2377 measured.

**The gate and the minter MUST be one value (MUST).** Availability is READ OFF `MintSeams`
(`MintSeams::availability`), never asserted beside it. A build that reports a mint as possible
therefore holds a real minter by construction, and no single edit can open the wizard while leaving it
uncompletable.

Because that is still the state for every account on this version, "no DID yet" MUST NOT be modelled as
an `AccountState` (§3.1c): every account on every host would sit in it, with no control that could leave
it, which would make the lock states lie. It is reported as completeness
(`account::journey::AccountCompleteness`) — a fact about the account — and the first-run flow (§3.2b)
names the DID as the remaining REQUIRED step.

### 3.1b-lv Every loop the user waits on MUST be watched from outside itself (normative)

The shell runs two loops a user can be frozen out by, and they freeze them out of different things.
The **state loop** owns every deadline the app owes a person — the clipboard timeout, the idle
auto-lock, the dispatch of a menu click. The **render loop** owns the native objects — the tray icon
and tooltip via `Shell_NotifyIcon`, the menu via `set_menu` — each an unbounded `SendMessage` to the
Windows shell. Either can stop running. Four reported recurrences (#69, #78, #83, dig-app#86)
produced **no log line at all**, because every diagnostic a loop has runs inside that loop: a loop
that has stopped iterating cannot report that it has stopped iterating.

- **A liveness stamp MUST be written from inside the loop and read from a thread that is not the loop.**
  A watcher sharing the watched thread observes nothing.
- **EVERY loop that can freeze a user out MUST carry its own stamp, and moving work between loops MUST
  move the instrument with it.** Watching one loop and not the other reproduces the original silence
  for whatever the unwatched loop owns. This is a MUST about the *work*, not about a fixed list of
  threads: dig-app#97 was created by relocating the native calls to the render loop while the watchdog
  went on observing the thread they had left, so a render loop wedged in `Shell_NotifyIcon` against a
  hung shell froze the tray permanently and silently.

  A single observer thread MAY read every stamp, and SHOULD: its whole qualification is being none of
  the watched loops, which one thread satisfies for all of them. Loops MUST NOT watch each other —
  that makes the loss of one loop the loss of the report about it.
- **The stamp MUST carry a PHASE naming where the loop is**, including a named value for *"blocked
  somewhere this shell does not measure"*. An instrument that spans only the loop's own calls reports
  a clean bill of health for every block upstream of them — which is where the block actually was the
  one time this was chased to ground.
- **A phase's tolerance MUST be measured against what that phase IS.** Every phase that names code
  is code that should return in microseconds, so one tolerance governs all of them. This is a MUST
  about matching the bound to the phase, not a licence for a single constant: the moment a phase names
  something a PERSON is doing, it MUST NOT be held to a bound written for code.

  The tray's context menu is such a phase. It is no longer a phase of the state loop (§3.1b-tp), but
  it did not stop existing — it moved, and it is now indistinguishable from the render loop's idle
  state, since `TrackPopupMenu` runs its nested modal loop inside the platform's dispatch. That phase
  MUST therefore be EXEMPT from any bound rather than given a long one: there is no duration after
  which a menu a person has not closed becomes a fault, and the previous attempt at naming one — two
  minutes — is what dig-app#93 reported. The exemption's price MUST be stated where the exemption is:
  a render loop blocked in dispatch for some reason that is not a menu is also not reported, so the
  reportable class is a native call the loop itself makes.

  A phase MUST NOT carry a longer private tolerance than its neighbours without naming a
  human-paced subject for it. One phase quietly twelve times more patient than the rest is how a
  wedge came to be first reported at 120 seconds under a ten-second bound.
- **A phase MUST be stamped by production code, not only by tests.** A phase no live path can reach is
  a diagnostic contract the shell does not actually offer, and a test ranging over it reads as broader
  coverage than it is — dig-app#97 found two such phases surviving a relocation, still asserted over
  by a bound test that could not fail on them.
- **A report MUST name the loop that stalled, its real consequence and its real remedy.** These differ:
  a state loop that will not come back needs DIG restarting; a render loop wedged in the Windows shell
  does not, and telling the reader otherwise sends them round a loop of their own. A user-facing ERROR
  that is confidently wrong about the fix is worse than no line at all.
- **A phase MUST NOT be able to outlive what it names.** Every phase a guard restores to MUST be
  either a fixed resting value or a phase held by a guard that is still alive — never a value read back
  out of the shared stamp. Every phase is now written from inside a guard, so none can be stranded;
  the rule binds the API regardless, because it is what keeps that true for the next phase added.

  This MUST is stated at the level of the API, not of its call sites, because a rule enforced only by
  review has already failed once: `Heartbeat::enter` captured its restore target from the stamp, so the
  first tick after ONE tray click adopted the menu's phase and every later tick re-adopted it. The
  phase — and with it the menu's two-minute tolerance instead of the general ten seconds — was pinned
  for the life of an otherwise healthy process, which is why dig-app#93's first ERROR arrived at
  120 seconds. A build MUST make the stranded state unrepresentable rather than merely undocumented.
- **A continuing stall MUST keep being reported** on a backoff, and MUST NOT latch after one line: the
  permanent case is the one that matters most, and latching silences exactly it. A stall that ENDS MUST
  be reported once, with its duration.
- **The watcher observes and reports, and recovers nothing.** It MUST NOT poke any phase: a shell
  call that will return or will not, and a block in platform dispatch we cannot name, offer nothing
  safe to do, and a watchdog that acts on them has a second way to be wrong. Recovery belongs to the
  window service.

  It held ONE exception — breaking a tray menu still up past its bound — granted because breaking a
  menu selects nothing and because the thread that would otherwise clear it was the stuck one. That
  exception is REVOKED with the condition that earned it: the tray no longer shares a thread with
  this loop (§3.1b-tp), so a menu that will not dismiss no longer stalls the state loop with it. That
  is narrower than it sounds and MUST NOT be read as "costs the user only the menu": the tray menu is
  the ONLY route to every action this application has, so an undismissable menu is an unusable
  application from the seat of the person using it. It is bounded, not benign (§3.1b-tp).
- **What is watched is decided by the PHASE, not by the thread.** Watching a state that harms nobody
  produces a diagnostic that is loudly wrong in a common case, which is the failure the tolerance rule
  above also exists to prevent — but scoping the watch to a whole thread to avoid that is what
  dig-app#97 caught, because the render loop parks in a menu *and* wedges in the shell, and only one
  of those is a fault. Both loops are watched; the exemption lives on the one phase that names a
  person waiting.

### 3.1b-tp The tray context menu MUST be dismissable before it is tracked (normative)

The tray menu is drawn by `TrackPopupMenu`, a nested modal message loop inside the tray window proc
inside the platform event loop. While it is up, NOTHING else on that thread runs.

- **No state a user is waiting on MAY live on the thread that draws the tray.** This is the primary
  requirement, and the one that bounds the harm of everything below it. While the two shared a
  thread, a menu that never dismissed was not a dead menu but a dead application — no clipboard
  timeout, no idle auto-lock, no status poll, no diagnostics, permanently and in silence
  (dig-app#86).

  The tray's handle cannot be what moves: `tray_icon::TrayIcon` is an `Rc<RefCell<..>>` with no
  `unsafe impl Send`, so its three surfaces are pinned to the thread that built it — which MUST be
  the main thread, because macOS requires it. So the STATE moves, and the seam MUST carry data
  rather than handles.
- **The producer MUST NOT wait for the renderer, ever.** Not "usually not": no lock may be held
  across a draw, and the cost of posting a frame MUST be the same whether the renderer is idle or
  parked in a modal menu. A producer that can be delayed by the renderer has not been separated
  from it.
- **A pending frame MUST be a complete picture, and a newer one MUST replace an uncollected older
  one.** Replacing is what keeps a wedged menu from costing three hundred stale redraws when it
  closes; completeness is what makes replacing safe, since a partial frame would discard whatever
  the frame it replaced was carrying.

A popup tracked without foreground rights cannot be dismissed by clicking away, by Escape, or by
anything else — measured, holding the loop 180 s and indefinitely thereafter (MSDN Q135788).

- **The process MUST take the foreground immediately before the popup is tracked**, at the last point
  its own code runs, and MUST report a refusal at ERROR naming what it predicts — that is the moment
  the wedge becomes reachable, and the line a later investigation will search for.
- **The implementation MUST identify which input edge the library tracks on, and claim there.** The
  edge is a property of the library, not a constant: `tray-icon` 0.19.3 tracked on button-DOWN and
  0.23.1 tracks on button-UP. Claiming at any other edge does not satisfy the bullet above, however
  close it looks — an attempt one edge early is a useful EXTRA try and is never the required one.
- **An edge that opens no menu MUST stay silent.** A refusal only predicts an undismissable popup
  where a popup follows; predicting one on a middle click, or at an edge the library does not track
  on, is a false alarm on the surface whose whole purpose is to be believed.
- **Both halves of Q135788 are required.** `SetForegroundWindow` *before* the track is what makes the
  menu dismissable; `PostMessage(WM_NULL)` *after* finalises the task switch for the next one. Neither
  alone is sufficient, and the second without the first fixes nothing.
- **The foreground claim MUST be DECLINED while a consent surface is on screen.** `WM_USER_TRAYICON`
  is an ordinary window message, so any process running as this user can post one and drive this
  path (dig-app#91). A prompt that loses focus mid-read is a prompt the user may re-focus and answer
  having lost their place; a menu that opens without foreground rights is a menu they click twice.
  The lesser harm is chosen deliberately.
- **A tray click whose timestamp does not sit beside a real system input event MUST NOT produce a
  foreground claim.** The comparison MUST be a MODULAR distance in both directions: the tick counter
  wraps, and the system's last-input tick can legitimately be NEWER than the message, because moving
  the mouse after releasing the button is itself input.

  This MUST NOT be described as a bound, and MUST NOT be sized as though it were one. It stops
  UNSOPHISTICATED forgeries only. Two limits, both unconditional: it gates just this process's own
  claim — `tray-icon` makes its own `SetForegroundWindow` call, which no rule here can reach — and the
  evidence it reads is the same-user `GetLastInputInfo` counter, which any process at this integrity
  level refreshes with one `SendInput` call carrying a zero-delta `MOUSEEVENTF_MOVE`, invisibly, on an
  idle machine (measured: last-input age 5,454,546 ms → 63 ms). A deliberate attacker therefore pays
  one extra Win32 call and this rule contributes nothing.

  The tolerance MUST NOT be tightened in response: the attacker controls the value being compared, so
  a shorter window declines genuine clicks under load without excluding a single forgery. The rule
  stays because it costs nothing and removes the free case. **The only remedy that bounds this is
  refuse-to-track**, immediately below. An earlier revision of this section said that remedy required
  the window service; it does not, and it is now implemented.

- **A popup MUST NOT be tracked where there is EVIDENCE this process does not hold the foreground.**
  An undismissable menu is strictly worse than an absent one: an absent menu can be clicked again, and
  an undismissable one can never be anything again. Two outcomes are such evidence — a claim that was
  MADE and REFUSED, and a decline taken because a consent surface already owns the foreground (which
  is reachable with no attacker at all, by clicking the tray during a platform credential prompt).
  A decline for want of recent input is NOT: a real click can outrun the tolerance under load, and
  refusing a genuine menu costs more than the forged one it would also refuse. A missing tray window
  is not either — there is nothing to protect and nothing to suppress through.

  **What this bounds MUST be stated precisely: it bounds tracks this process can predict, not the
  lever above.** `tray-icon` makes its own `SetForegroundWindow` call that no rule here can reach, so
  a forged click arriving with manufactured input evidence still reaches a track. Anyone sizing
  further work MUST NOT read this rule as closing that lever.
- **Only a claim that SUCCEEDED may clear a standing suppression.** Re-enabling the menu is not the
  same act as permitting this click: it discards an earlier refusal. Doing that on a path where the
  process never established its foreground rights disarms the guard at the moment it is most needed.
- **A suppression MUST be per-click and MUST NOT be sticky.** A menu that stops appearing forever is
  its own outage. Eligibility MUST be re-tested on the following click and the menu restored the
  moment a claim succeeds, so the user'''s entire remedy is to click again.
- **A suppressed menu MUST be reported to the user, not only to the log.** A menu that silently does
  not appear trades one baffling state for another, and the person holding the mouse is not reading
  the log.
- **The enforcement MUST fail towards tracking.** Whatever mechanism suppresses the popup, the
  consequence of it not taking effect MUST be that the menu is tracked — the behaviour of every build
  before this rule existed. A guard whose failure mode is the status quo needs no second guard behind
  it; one that could fail towards a worse state would.

  Bounded honestly: nothing on this path selects a menu item or answers a prompt, and the consent
  decline above — which reads this process's own state rather than an attacker-writable counter — is
  not bypassable this way. This is a nuisance lever, not an authorization bypass.
- **A DECLINED claim MUST NOT be reported as a REFUSED one.** A refusal warns that a menu may wedge;
  a decline is the process choosing correctly. Reporting the second at the first's severity teaches
  the reader to skip the one line that means something.
- **The right rule is refuse-to-track rather than track-hopefully**, and reaching it requires owning
  the popup rather than delegating it to a library. Until the window service owns it, the earlier
  foreground attempt only WIDENS the window in which rights may be held — it is the same call the
  library already makes, one input edge sooner.

  There is no longer a rescue for a popup tracked anyway. Breaking one used to be the difference
  between a lost menu and a lost process; with the state tick on its own thread it would be the
  difference between a lost menu and a lost menu, and it never worked in any case — a posted message
  returning `Ok` means enqueued, which is not an effect. **This MUST NOT be described as closed**: an
  undismissable popup is still possible, it is now merely local, and the trigger that causes the
  foreground refusal in the field is still NOT identified.

### 3.1b-dp DPI awareness MUST be declared, not acquired (normative)

Windows fixes a process's DPI awareness at the first call that sets it and ignores every later one. It
MUST therefore be a property of the BUILD, declared in the application manifest, rather than a side
effect of which surface the user reached first.

- **The shipped Windows binary MUST carry an embedded manifest declaring per-monitor v2 awareness**, on
  both spellings: `<dpiAwareness>PerMonitorV2</dpiAwareness>` for 1703 and later, and
  `<dpiAware>true/pm</dpiAware>` for hosts that read only the older element. A bare
  `<dpiAware>true</dpiAware>` is SYSTEM awareness and MUST NOT be used: it looks correct in a summary
  and gives the whole desktop one scale factor chosen at logon.
- **The manifest MUST be embedded in the binary's resources**, not shipped beside it, so no installer
  step can separate the two.
- **The manifest MUST request `asInvoker`** and MUST NOT request `requireAdministrator`,
  `highestAvailable`, or `uiAccess`. dig-app guards custody actions with its own consent windows and
  has nothing to do as an administrator; an elevated process also cannot be sent input by the
  unelevated desktop it lives on.
- **A build that cannot embed the manifest MUST say so**, not skip in silence — a silent skip returns
  the process to deciding its awareness by event-loop construction order.

Rationale (dig-app#87). Before this, awareness came from whichever event loop was constructed first:
tao sets `PER_MONITOR_AWARE_V2` from `EventLoop::new`, winit from its own, each behind a process-wide
`Once`; a headless build constructed neither. The issue's premise — that dig-app is DPI-unaware — was
wrong, and the truth was worse: it was CONDITIONALLY aware. The hand-built consent windows COMPENSATE
for awareness by reading the monitor's real DPI and scaling themselves, so on a path where the process
turned out unaware Windows scaled them as well and the two multiplied.

### 3.1c The tray and app-window account surface (normative)

A person MUST be able to reach the whole account journey — not merely lock and quit — from the surfaces
this app puts in front of them. There are two, and which of them carries the journey depends on one
capability.

**The window-host capability (MUST).** An implementation MUST determine, at runtime, whether it can open
the app window on this host, and MUST carry the answer as DATA on the same snapshot the menu is built
from — never as a compile-time target test, because a host with no display server is in exactly the
condition macOS is in and both MUST be treated identically. The answer MUST start from a cheap static
probe and MUST degrade to *unavailable* on an OBSERVED failure to open the window, restoring the full
menu. A capability that is only probed lets a host promise a window, fail to draw it, and leave a person
with a short menu and no route to the escape hatches.

- **Where a window can be opened**, the tray menu is TRIMMED to four rows — the one thing this account
  needs right now, open a URN, open the app window, and quit — and the rest of the journey lives in the
  window. The trim is permitted ONLY under the reachability rule below.
- **Where no window can be opened**, the tray MUST carry the WHOLE journey, exactly as enumerated below,
  because it is then the only surface a person has. It MUST NOT offer to open a window it cannot open.

**Reachability (MUST).** For every account state and every host, every action offered on a host with no
window MUST be reachable on a host with one — from the trimmed tray, from the window, or as the content
of a window tab that renders that action's own material in place of a row. This MUST be asserted as a
test over the whole state space, not argued in prose: it is the only thing standing between the trim and
a person with no route to *explain an account that cannot be opened*, *the missing-phrase explainer*, or
*remove the account*.

Both surfaces are built from ONE pure model (`dig_app_core::tray_menu` for the rules and the menu,
`dig_app_core::window_model` for the window's arrangement of the same rows) so these rules are testable
independently of any desktop, and so the two surfaces cannot disagree about what a verb means, whether it
is offered, or what its label says.

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

The SURFACES TOGETHER MUST offer actions to: show the status details, set up an account, restore from a
recovery phrase, unlock, lock now, reveal the recovery phrase, back up the recovery phrase (copy it to the
clipboard, and save it to a file — §3.1a Backup, offered only on an unlocked recoverable account), copy
the DIG ID, copy the receive address, show the wallet, replace the account (with a new one, or with one
from a recovery phrase), remove the account, explain an account that cannot be opened, explain the
on-chain DID, open the log folder, and quit. On a host with no window the TRAY MENU MUST offer all of
them; on a host with one, the four trimmed rows plus the window MUST, which the reachability rule above
turns into a machine check.

**The four rows that never move (MUST).** Whatever else is trimmed, the tray MUST keep: the one thing
this account needs right now, opening a URN, opening the app window, and quitting. Each is there because
putting it behind the window breaks something specific — first-run setup and every way back into a wedged
account would be behind a window a new user has no reason to open; reading content is what the product is
FOR and MUST NOT wait on a window (§6.0); the window row is the route to everything else; and a tray app
that cannot be quit from the tray is a trap. The first of the four is POLYMORPHIC — its verb is set up,
unlock, set a password, explain, or lock now, decided by the account's state — so the ROW is fixed while
the ACTION is not, and it is never empty.

**The Wallet surface (MUST).** The Wallet submenu offers the receive address, the balance reading, and a
wallet window, and nothing that moves money — no tray action spends, so the absence of `Send` is
structural rather than an `enabled: false` (§3.3, the money path). Binding rules:

- The copied address MUST be the account's derived `xch1…` money address (§3.3's wallet key), never the
  profile's identity public key. Funds sent to a well-formed address for the wrong key are unrecoverable,
  so the derivation MUST be pinned against an independent derivation of the same seed.
- A receive address is PUBLIC, so a state that merely WITHHOLDS the key — locked, or never given a
  password — MUST still show the row, disabled, with its label naming that state's own remedy. Where no
  address can exist at all — no account, or an account that cannot be opened — the row MUST be omitted and
  the wallet window MUST explain the situation.
- **A balance that could not be read MUST NOT be rendered as a zero.** The surface MUST distinguish a
  balance READ from a chain source (where `0` means nothing is held) from one that is UNKNOWN, and every
  unknown MUST name which thing is missing — no address, no node DIG could reach, a node that did not
  answer in time, a node that does not serve wallet reads, a node with no live chain source to read from,
  a source still syncing, or a read that failed. A read still IN FLIGHT is none of those: it MUST be
  carried as its own PENDING state, because nothing has failed and naming a reason would invent one. Showing a
  zero for an unreadable balance is how a person
  concludes their funds are gone, and is forbidden. This holds on the MENU ROW as well as in the window: a
  glanced-at numeral is where the mistaken conclusion is cheapest to reach.
- **The balance MUST be READ, never merely linked to, on whichever surface carries the wallet.** "What do
  I hold?" is half of what a wallet is for, so the answer MUST NOT sit behind a further click from the
  wallet surface the person has already reached. On a host with no window that surface is the Wallet
  SUBMENU, and the reading (or the short reason) MUST be the LABEL of an enabled row there, which opens
  the window holding the full reason. On a host with a window it is the Wallet TAB, and the reading MUST
  be the tab's own heading — page content, not a row, because "open the wallet window" is meaningless
  inside the wallet window. Either way the no-account case says there is nothing to show rather than
  presenting a lone explainer, and a greyed balance is forbidden for the reason all greyed rows are.
- **On the Wallet TAB the balance MUST come before the tab's controls, and the address MAY be
  disclosed.** The reading is the first content on the tab and is set at the display size, so the
  question the tab exists to answer is what a glance lands on. The receive address and its scannable
  code MAY sit behind a `Receive` control rather than being drawn permanently — an address is wanted
  for seconds at a time, and a code drawn permanently above the balance inverts the tab's own
  hierarchy. Two rules bind that disclosure: the control MUST state, in place, the reason it is
  refused when no address can be shown; and the tab MUST offer exactly ONE way to copy the address at
  any moment — so a closed disclosure MUST retain the menu's copy row, and an open one MUST drop it
  rather than offer the same verb twice. A payment already in flight is NOT subject to any
  disclosure: it MUST be drawn whether or not its card was opened.
- **A close control MUST appear exactly where pressing it would visibly close the card, and nowhere
  else.** One rule, and both of its edges are defects that have shipped.
  - A card a person disclosed MUST carry a close control **of its own**, at every width, whenever
    nothing else is holding the card on screen. The control that opened it is NOT sufficient: the
    disclosure survives a state change, so a verb refused after its card was opened would otherwise
    leave a card nothing on the surface can close.
  - A card that is on screen because a payment is IN FLIGHT MUST NOT offer to dismiss it — **whether
    or not it was also disclosed.** This is not a rule about which reason drew the card: since
    nothing on the send path clears a disclosure, the ordinary path is in-flight AND disclosed, and
    a control drawn there would clear the disclosure while the card stayed exactly where it was. A
    close control that fails to close anything is the same defect as one that hides money in motion,
    and an implementation MUST NOT draw one.
  A person may never reach a state where money is moving and the surface says nothing about it, nor a
  state where a control appears to do something and does not.
- **A row MUST NOT name a remedy the user's state cannot perform.** "Unlock first" is correct for a locked
  account, meaningless on a host that cannot hold an account, wrong for an account that has never been
  given a password, and actively misleading for one that cannot be opened — where unlocking is precisely
  what failed. An implementation MUST therefore carry one reason per REMEDY rather than one per rough
  category, and MUST distinguish all six account states in both the menu label and the window prose.
- **An unlocked account whose address derivation itself fails MUST NOT be told to unlock**
  (dig_ecosystem#2059). This is a SEVENTH, orthogonal fault distinct from the six account states above: the
  account is genuinely unlocked, so "unlock it" names a remedy the user has already performed. An
  implementation MUST read the account's unlock state and its address derivation from a SINGLE observation
  of the same underlying lock — never as two separate reads — because a lock landing BETWEEN two separate
  reads (an idle relock, `Lock now`) makes an ordinary lock indistinguishable from this fault, and would
  alarm a user who merely locked their account with wording meant for a genuine defect.
- **An upstream error string MUST NOT be interpolated into a menu label.** It is unbounded and its
  contents are not this application's; the row states that the read failed and the window states what the
  source said.

The account has SIX user-visible states, and an implementation MUST distinguish all of them: this host cannot
hold an account · no account yet · locked · **cannot be opened** · unlocked · unlocked with no recovery
phrase. The fourth is the one most easily and most damagingly collapsed into "locked" — see the rule below.
The tray's top level MUST stay short; rare and destructive verbs belong in a submenu or a window tab,
never beside `Lock now`.

Minting an on-chain DID is deliberately NOT among them: this build has no chain transport to mint over
(§3.1b), so the menu offers an EXPLANATION of what a DID is and costs, and there is no tray action that
mints — the absence is structural, not an `enabled: false` that a later change could flip on by
accident.

Binding rules:

- **An identity-bearing verb MUST be gated on a DID EXISTING (MUST).** Publishing, signing for an app
  and sending a directed message put the user's identity on what they do, and `account::did::Allowance`
  is the ONE policy that rules on them. Every surface offering such a verb MUST consult it; a policy no
  surface asks turns *"a DID is required"* into a rule the app states and does not apply. Pairing is one
  of those surfaces, because every capability a pairing can grant is identity-bearing
  (`identity.attest` / `identity.seal` / `identity.unseal`).
  A refused verb MUST be offered with a label naming the REMEDY, not withheld silently and not greyed
  bare.

  **The pairing gate binds at the WIRE and not only in the menu, and it narrows the CAPABILITIES
  rather than refusing the pairing (MUST).** `pair.begin` MUST consult the same policy and MUST grant
  an EMPTY identity capability set while no DID exists — including on the pinned-extension path,
  which never passes through the tray and would otherwise be granted identity capabilities on its
  `ext_id` alone. It MUST NOT refuse the handshake itself: a pairing also carries a money
  `PairingScope`, which needs a WALLET and never a DID, so refusing the whole pairing would block a
  legitimate `sign.request`-only app on a precondition it does not need. A pairing whose identity set
  was emptied this way MUST remain recoverable — re-pairing once a DID exists, and revocation, are
  both reachable.

  This is a CONTRACT requirement rather than the only line of defence, and an implementation MUST NOT
  read it as the sole guarantee: `identity.attest` and `identity.seal` independently refuse with
  `LOCKED` whenever no profile DID can be read, so the identity verbs fail closed downstream even if a
  capability were granted in error. Both layers are required — the door because a rule the app states
  must be a rule the app applies, and the downstream refusal because the DID is read LIVE and can
  disappear after any grant. Where the gate cannot ANSWER — no DID read, or a reading that has not completed — it MUST refuse
  rather than pass: a gate is not permitted to be weakest exactly when it knows least.
  Two things MUST remain ungated: READING content, which needs no account, wallet or DID at all, and
  holding funds; and REVOKING an existing pairing, because gating the way out is a trap.
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
- **Past the point of no return, no window may assert the account is intact (MUST).** Once the discard has
  run, every message the flow can still draw MUST come from the code that KNOWS custody is gone. A step
  reused from a pre-removal flow — a first-run setup wizard reached as a replacement enrolment — MUST NOT
  draw its own failure window, because that window's copy is written for a host whose account was never
  touched. Concretely: an enrolment step MUST report WHY it failed to its caller and say nothing itself,
  and the caller MUST choose the words. A verdict a caller synthesises rather than receives is
  non-conforming, because it makes the honest copy for the real condition unreachable.
- **An enrolment failure whose cause is the account FOLDER MUST name the folder, not a retry (MUST).**
  The keystore root is validated on WRITE only, so an unusable root — a link, or a location that cannot be
  kept private to its owner — is first observed by the replacement enrolment, after the previous account is
  already gone. The message MUST state that this host now has no account, MUST name what is wrong with the
  folder and where to read the detail, and MUST NOT invite another attempt at the same folder. Where the
  flow HOLDS the replacement recovery phrase it MUST additionally say those words are still valid; where it
  does not, it MUST NOT claim they are.
- **Never trap the user.** "Quit" and the log folder MUST be enabled in EVERY state, including when the
  account is unsupported, absent, locked, or broken. No state may leave the menu with nothing actionable.
- **Say the true state.** An account with no recovery phrase MUST be labelled as such in the account
  status line AND offered the explainer, and MUST NOT be shown an inert "show my recovery phrase" item.
  An action whose precondition is unmet is shown DISABLED rather than hidden, so the capability's
  existence is discoverable — **but only when the label can say WHY.** A disabled row with no reason in it
  is a small unexplained mystery; where there is no reason worth printing, the row MUST be omitted instead.
  A disabled row MUST also sit beside an ENABLED row that resolves it, so no state is a dead end. Five rows
  currently qualify: setting up an account on a host whose OS has no account support yet (Linux — §3.1), plus
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
    and naming a command sends a person to a console to fix a tray that will not draw. No label may name a
    terminal, a console or a command to run — including this app's own `diga`.
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
  The distinction is not hypothetical — dig-app USED to auto-enrol the default account at first boot on
  every Windows/macOS host (it no longer does — §3.2a: an account exists only because a user asked), so
  legacy raw-seed blobs exist in the field, and a custody model that can no longer
  read them leaves such an account WEDGED: it neither unlocks nor re-enrols at the same id. An implementation
  MUST therefore carry a multi-state at-rest fact (no account / present / present-but-unopenable /
  present-under-a-machine-password) rather than a boolean, and the tray MUST name the state on the surfaces a person looks at — the icon, the tooltip and
  the details window — never only in a log record. Reducing this to a log line costs the user signing
  permanently and silently, which is the defect the state exists to prevent.
  - **Only an ATTEMPT that hit an unreadable SEAL may reach it (MUST).** The at-rest fact MUST be derived
    from the outcome of an actual attempt to open the account — never from the absence of a live session.
    The app boots with the account locked and attempts no unlock at start-up (§3.2a), so "there is no
    session" is the ordinary state of every fresh process and means only that nobody has unlocked yet;
    reading it as a failure reports every launch as an unreadable account and points its owner at the
    destructive remedy. An implementation MUST carry at least three attempt outcomes — not attempted,
    refused, unreadable — and:
    - **not attempted** and **refused** MUST both report `Locked`. A cancelled prompt, a password that
      did not open the seal, and a host that could not draw the window are all RETRYABLE, and `Unlock…`
      MUST remain the offered way in; the app MUST say what happened without implying the account is lost.
    - **unreadable** — and only it — MUST report `Unopenable`. It means the sealed blob cannot be read by
      this build at all (a legacy raw-seed account, or a seed-envelope/keystore format from a later
      version), so no password can open it. Any failure an implementation cannot positively identify as
      unreadable MUST be treated as refused, because the cost of the two mistakes is not symmetric: one
      offers a retry that will not work, the other offers to destroy a working account.
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
  broken application. The message MUST NOT point at a CLI as the way in: `dign` is
  dig-node's binary and names the wrong tool outright, and `diga` — this app's own CLI — still sends a
  person to a console to fix a tray that will not draw.
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

### 3.1c-0 The app window (normative)

Where the host can open one (§3.1c), the app window carries the twenty-five verbs the tray no longer
shows, plus the surfaces that were never on the tray at all (auto-update, §3.1c-iii). It is arranged by `dig_app_core::window_model` from the SAME group builders the tray menu composes,
so no rule about which rows exist or whether they are enabled is decided twice.

- **It is a tab surface, not a second product.** Tabs are listed in a sidebar, which becomes a strip of
  chips when the window is too narrow for a column; the selected tab's sections fill the rest. The window
  MUST reuse the consent windows' own palette, type and chrome, because a person who has just been shown a
  DIG consent prompt MUST be able to recognise this as the same application.
- **The tab set is exactly `Home · Account · Wallet · Content · Settings` (MUST).** Each names a
  destination a person can hold in mind, not an implementation area: `Content` is what this computer keeps
  on disk for the network (never "Cache", which is jargon §6.1 requires abstracting), and `Account` carries
  BOTH what the account is and how it is protected, because "is my account safe" and "I want a different
  account" is a distinction between cards rather than between destinations. Splitting them cost two
  parallel per-state sentence sets over one state machine, which is what the next rule now forbids.
- **One account state, one sentence (MUST).** Exactly ONE per-state sentence set describes the account
  anywhere in the window, chosen by an exhaustive match over the account's state. A second set — however
  well tested against itself — is two surfaces free to tell a reader different things about one state, and
  it MUST be provable by test that only one exists, not merely that each is internally consistent.
- **The window carries persistent status readings on EVERY tab, OUT of the reading path (MUST).** Whether
  the background agent is running and whether a node is reachable MUST be legible from every tab, because
  both explain what the rest of the window is showing — an unreachable node is frequently the reason a
  balance reads "not known", and a person MUST NOT have to change tabs to learn it. The readings state each
  in a glance, MUST NOT sense a click (a reading that responds to one is a control), and MUST take their
  readings from the same projection the panes read, so they and a pane can never describe one machine
  differently. They MUST NOT be drawn ABOVE the content: where the window has a sidebar they sit at the
  FOOT of it, bottom-justified, and where it does not they take a band along the BOTTOM of the window.
- **When there is not room for every reading, the readings are DROPPED in a stated order, never truncated
  or shrunk (MUST).** The order is most-explanatory first, and whether the agent is running and whether it
  has a node MUST be the last two surrendered. The same order MUST govern both layouts, so the two cannot
  come to disagree about which reading matters least. A reading MUST NOT be drawn clipped, at a reduced
  size, or behind a scrollbar: an ambient readout a person has to interact with has lost the property that
  justified showing it everywhere.
- **A verb that unblocks the whole window MAY be promoted into the chrome, and MUST be quoted from the
  model (MUST).** The way back into a sealed account is reachable from every tab, not only from the tab
  that owns it. Where the chrome offers such a verb it MUST take the model's own enabled row — its action
  and its exact words — so the chrome cannot offer a verb the panes do not, or word it differently; it MUST
  disappear when the model stops offering it; it MUST NOT be drawn disabled, because the chrome has no room
  to say why; and it MUST NOT become a gate — nothing is scrimmed, every tab stays reachable, and reading
  content still requires no account. It MUST carry an accessible NAME on the same terms as the window
  controls, and the drag strip MUST be derived so that it cannot overlap it.
- **The header MUST draw the brand's own mark, not an approximation of it (MUST).** The mark is a checked-in
  asset, shared byte-for-byte with the window icon and the tray so the three cannot show different marks. A
  decode failure MUST cost the header its picture and nothing else.
- **A content pane MUST NOT scroll past its own content (MUST).** The scroll extent is the height the pane
  MEASURED this frame, so a person who scrolls to the end is looking at the end of the content rather than
  at blank space, and a pane whose height changes between frames — a loading state resolving, a sheet
  opening — MUST have its extent follow in the same frame. A pane shorter than its viewport MUST NOT
  scroll at all.
- **The readings state the chain replica and a SEPARATE peer count per network (MUST).** dig-node belongs to
  two networks — the DIG content network and the Chia network — and they MUST report a count for each,
  each labelled with the network it is about. It MUST NOT report one combined figure and MUST NOT add the
  two together: a person shown a single count cannot tell which network is healthy, and the two answers
  routinely differ.
- **The replica's own peak height and the peak its Chia peers announced MUST be reported as TWO separate
  labelled readings (MUST).** A light client's peers sit above the replica while it catches up; that gap is
  the ordinary state and MUST NOT be rendered as a fault. The two heights MUST NOT be averaged, reconciled,
  or drawn as one figure: the only thing the pair says is the distance between them, so collapsing them to
  one erases the reading.
- **`subscription_peer_count` MUST NOT be reported as, or summed with, the Chia peer count (MUST).** It is
  at most one by design and is not a measure of network reach. The two failures are distinct and both are
  forbidden: REPORTING it as the Chia peer count is what made a node holding five Chia peers report one,
  and SUMMING the two would report that same node as holding six.
- **A reading nobody could take MUST be drawn as nothing, never as a zero (MUST).** A peer count is
  rendered only from a node's own answer. An unasked node, an unreachable one, and a node that cannot
  observe the count are three states that MUST be distinguishable from an observed `0`, and none of them
  may be rendered as one — a fabricated zero is a fault report shaped exactly like a real outage.
- **A chain replica that has reached no height MUST NOT be described as syncing (MUST).** The node's phase
  alone does not license the claim: on a default install the phase is `syncing` permanently, because
  discovered peers are denied write authority and the replica's peak stays null (dig_ecosystem#2568). The
  surface MUST therefore derive its word from the phase AND the height together, and MUST say only what is
  true of both a permanently-stuck replica and one in its first seconds — it MUST NOT guess between them,
  because the wire cannot distinguish them.
- **The strip MUST drop readings it cannot fit rather than overflow or clip (MUST).** It stays one line at
  every width down to the window's minimum. Readings are ordered most-explanatory-first and the strip stops
  at the first that will not fit; the agent and node readings MUST always survive. This is permitted only
  because nothing in the strip is a control and every fact it carries is also reachable in full on a tab.
- **The declared tab set and the emitted tab set MUST agree (MUST).** Every declared tab is emitted in
  every view, and the enumeration the guards sweep MUST be derived from the tab type rather than
  hand-written: a hand-written list admits a tab that compiles, is absent from the list, and so escapes
  every sweep written over it.
- **Every emitted tab MUST be clickable at every width the window allows (MUST).** The chip strip WRAPS
  onto as many rows as the tabs need and the content pane begins below the last row; the strip MUST NOT
  omit, clip out of the window, or overlap a chip, at any width down to the window's own minimum. A label
  too wide for one row is truncated with an ellipsis and stays clickable. An undrawn tab is not a degraded
  tab — the strip is that tab's only route, so dropping it removes the feature.
- **A tab is emitted only if it renders something (MUST).** There is no greyed tab: a tab a person cannot
  open is a route removed, and every tab that could plausibly be greyed is the sole route to something. A
  tab with nothing to show is not drawn at all.
- **A row that cannot be used is DISABLED and says why (MUST).** Never hidden, and never re-worded by the
  window — the label is the same one the tray would show, and it MUST name the remedy that state actually
  has (§3.1c). A disabled row MUST NOT be clickable.
- **Every tab answers all four async questions (MUST, §6.4).** Success, still-loading, could-not-be-read,
  and nothing-to-do MUST each be expressible and MUST be decided in the model rather than by the renderer,
  so each is testable. The three that are not plain success MUST be complete sentences, and the two that
  report a PROBLEM MUST name the remedy.
- **The selection MUST survive a repaint (MUST).** The window rebuilds from a snapshot a poll rewrites on
  a timer the user cannot see; a selection recomputed per frame would move under someone reading a tab. A
  selection whose tab stops being emitted MUST fall back to one that is, never to nothing.
- **A window row MUST dispatch exactly as a tray click does (MUST).** The same action type, the same
  single worker, the same one-at-a-time refusal — so a window row and a tray click can never open two
  destroy flows at once. A row MUST NOT run a blocking prompt inline: the window is drawn on the one
  prompt thread, so doing so would block that thread inside its own frame waiting on the queue that frame
  owns, which is a deadlock with no timeout.
- **Opening the window MUST return as soon as the request is queued (MUST)**, never when the window
  closes — a handler held for the window's lifetime would refuse every later action, including quit.
  Asking again while it is open MUST bring the existing window forward rather than opening a second.
- **The window opens no second window (MUST).** Every surface the app has — confirms, notices, reveals,
  text inputs, status and the About pages — MUST be drawn INSIDE the app window while it is open, as a
  modal layer, never as another top-level window. A prompt raised while the app window is CLOSED is the
  exception and MUST keep its own window (below): a request from a dapp MUST NOT force the whole app open.
- **The window itself is NOT a consent surface.** It MUST NOT be always-on-top, MUST NOT carry a deadline,
  and MUST NOT count as a raised consent surface while it is showing no prompt — counting it would suppress
  the tray's foreground claim for as long as somebody left the window open.
- **The window MUST be watched for a wedged frame loop, and forced closed only for that (MUST).** Having no
  deadline is not the same as being unwatched. The window is drawn on the one prompt thread, so a frame loop
  that stops running holds that thread and every later consent prompt in the process is refused unseen for
  the life of the process. An implementation MUST therefore watch the window from OUTSIDE its frame loop on
  whether frames are still running, and once no frame has run for a bounded interval it MUST attempt to
  close it and MUST record that it did so — the interval short enough that a prompt queued just before the
  wedge is still answerable within its own deadline. The ATTEMPT is what is required, not the outcome: a
  loop that hangs before it is constructed exposes no handle to nudge, and there the record is the whole of
  what any implementation can deliver. It MUST NOT force a window that is still drawing, however long it
  has been open, and MUST require the silence to be observed twice a full interval apart, because a machine
  resuming from suspend presents one long silence in a process where nothing is wrong.
- **Admitting an in-window prompt MUST bring the window forward (MUST).** A standalone prompt is
  always-on-top and asks for the keyboard; both are claims against the DESKTOP, and drawing the prompt
  inside the app window does not inherit either. The window MUST therefore be raised and focused when a
  prompt is admitted into it — otherwise a request arriving while the window sits behind another
  application is never seen, and is refused on its deadline. A prompt REFUSED without being drawn MUST
  NOT raise the window: there is nothing to show.
- **An in-window prompt IS a consent surface, for as long as it is up (MUST).** It MUST count as raised
  from the moment it is admitted until it is answered, expired or settled — not merely for the span of a
  frame — so a tray click cannot take the foreground from a person part-way through reading or typing.
- **While a prompt is up the rest of the window MUST be inert (MUST).** Dimmed, taking no clicks anywhere
  in it including the chrome, not resizable, and the modal MUST be the only thing that can be interacted
  with. Exactly one prompt MAY be up at a time, so a second can never obscure what is being authorised.
- **An undecorated window MUST draw every window control it denies the platform (MUST).** The app window
  has no OS titlebar, so minimize, maximize and close exist only if the window draws them. All three MUST
  be present and reachable, the maximize control MUST also RESTORE — labelled with the action it will
  perform, never with the state it is in — and the header MUST answer a double-click by toggling maximize.
  A window that can be maximized and not un-maximized, or moved and not minimized, is the trap the
  never-trap rule forbids in a smaller shape. The controls MAY be drawn as icons, and where they are, each
  one MUST carry an accessible NAME — the same word for assistive technology, for a hover, and for
  whatever addresses it in a test — because an unnamed glyph is a control a screen reader cannot announce
  and a harness cannot reach. An icon control's hit area MUST NOT be smaller than the labelled control it
  replaced. The slots MUST be disjoint and the drag strip MUST be derived so that it cannot overlap a
  control's hit area: a strip that swallows Close leaves a window with no way out.
- **An unexpressed theme preference MUST follow the HOST (MUST).** Nothing stored and light-was-chosen
  are DIFFERENT facts and MUST NOT share a representation: a window opened with no stored preference MUST
  paint the host's own light/dark setting, and MUST fall back to light only where the host does not
  report one. An explicit stored choice MUST outrank the host in every case, including a host that
  disagrees with it. A file whose contents are not a theme this app wrote MUST read as *no preference*,
  not as a deliberate choice of the default — otherwise a corrupt file silently pins a person to a theme
  nobody chose, behind a toggle that appears to work.
- **The theme is a SETTING, not a window control (MUST).** The choice between the light and dark themes
  MUST be operated from the Settings tab, alongside the other persisted preferences, and MUST NOT occupy a
  slot in the window chrome — those slots act on the window, while a theme outlives it and applies to every
  window the app draws. Wherever it is operated, the preference MUST have exactly ONE writer, so a stored
  theme and a painted theme cannot disagree and a person's choice cannot appear to take and then revert.
- **Text the window displays MUST be selectable (MUST).** Addresses, DIDs, coin ids, store ids and error
  text are useless uncopied and dangerous retyped, so selectability MUST be a property of the drawing path
  every readout goes through rather than an annotation on individual call sites — a per-site opt-in leaves
  the next readout dead. Where a copy control already exists it MUST remain: selection is the floor.
- **An in-window prompt MUST NOT address the host's viewport itself.** It MUST NOT ask to close, focus,
  move or resize the app window, and closing the app window MUST NOT be read as the person's answer.
  In particular it MUST offer no drag handle: the viewport a drag moves is the app window, and the shell
  is resizable, so a header drag would carry the whole application across the desktop or snap it to an
  edge with a live prompt inside it. Raising the window on admission is the HOST's act, not the prompt's.
- **The modal MUST be answerable by pointer (MUST).** Its controls MUST sit in a layer strictly above the
  scrim; a consent surface a person can read and cannot click is one they cannot refuse — and since Escape
  and the deadline both resolve a confirm to a refusal, one that silently refuses everything.
- **A prompt MUST NOT author an answer from a pass in which it was not presented (MUST).** Sharing the
  host's input stream means a keystroke aimed at the app window arrives at a prompt admitted in the same
  frame, and the first layout pass of a new modal is invisible by construction. The keyboard and the
  self-dismissal deadline MUST therefore be inert until a pass that really put the prompt on screen.
- **An affirmative MUST require a gesture begun after the surface could be read (MUST, BOTH hosts).**
  Prompts are raised in sequence — an unlock, then the operation it unlocked — and the pre-focused control
  of a signing prompt is the affirmative, so a gesture aimed at one prompt MUST NOT be able to answer the
  next. The rule binds both hosts and is met differently in each, because the two differ in what their
  input stream remembers:
  - **In-window**, where the prompt shares the host's input stream, an operating-system key-repeat — the
    system repeating a key the person is holding — MUST NOT activate the focused control.
  - **Standalone**, where each prompt owns its input stream and that stream cannot have observed the key
    going down, the repeat test alone is not sufficient and MUST NOT be relied on: the first press a new
    window sees is indistinguishable from a fresh one. The affirmative MUST additionally be withheld until
    the surface has been continuously readable — focused, and painted — for a bounded interval long enough
    to contain the operating system's repeat interval. Time during which the windowing system reports the
    viewport unfocused MUST NOT count. The same interval MUST gate an affirmative POINTER press, because
    prompts open at the same coordinates and the second press of a double-click otherwise lands on the
    next prompt's affirmative.
  Refusal is unaffected on both hosts and MUST stay immediate: Escape, the host close, the deadline and a
  press on the refusing control MUST all resolve on the first painted frame. Nothing in this rule may
  author an answer — it may only withhold one, and a withheld gesture is simply made again.
- **The URN launcher (§3.1c-i) keeps its own presentation in-window (MUST).** It MUST be drawn at the
  launcher's size, placed high rather than centred, and dismissible by clicking away from it — which
  in-window means clicking the scrimmed rest of the window. That gesture MUST NOT dismiss any consent
  dialog. Both hosts MUST take the size from one shared mapping, so a launcher cannot be drawn as a dialog
  in one of them.
- **Teardown MUST fail closed (MUST).** Closing the window, or dismissing the modal, over a prompt nobody
  answered MUST answer it unavailable — never an approval, and never a dropped reply that leaves the
  caller waiting out its timeout. An answer the person DID give MUST survive teardown unchanged.
- **A prompt raised while the window is CLOSED keeps its own window**, with its always-on-top posture and
  its deadline unchanged. Both hosts MUST paint the prompt through the same code, so what a person reads
  before approving something does not depend on which one drew it.

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

### 3.1c-iii The auto-update surface (normative)

The app window MUST carry a **Settings** tab holding an **auto-update** group, built from the same pure
model as every other surface (`dig_app_core::tray_menu` + `dig_app_core::auto_update`) so these rules are
testable without a desktop.

- **The beacon is the authority (MUST).** Auto-update is performed by `dig-updater`, which consults its own
  `config.json` in an Admin/SYSTEM-only directory before every pass and returns without touching the
  network when it says paused. dig-app MUST NOT write that file, disable the scheduled task or unit, or
  keep a parallel switch of its own that anything reads as the setting. A change MUST be made by running
  the beacon's own commands — `pause`, `resume`, `channel set <token>`, `schedule install` — and the state
  SHOWN MUST come from the beacon's unprivileged status mirror (`status --json`), never from dig-app's
  remembered preference.
- **Auto-update is ON by default (MUST).** A machine on which no one has expressed a preference updates
  itself. An `agent.json` written before the preference existed MUST load as ENABLED; a `#[serde(default)]`
  bool, which yields `false`, is not a conforming implementation of this rule.
- **"On" MUST mean the machine actually updates itself (MUST, dig_ecosystem#2324).** The status mirror
  reports two independent facts that each stop updates: `paused`, and `schedule_opted_out` — the daily
  schedule DELIBERATELY removed by `schedule uninstall`, recorded as a privileged-owned sentinel. A surface
  MUST derive "on" from BOTH; reading `paused` alone reports an opted-out host as up to date. The remedy
  MUST match the cause: `resume` clears a pause and does NOT re-arm a removed schedule, so a host reporting
  `schedule_opted_out` MUST be offered `schedule install` instead. Running `resume` there exits zero having
  changed nothing, and reporting that as a saved setting is a false success notice. An absent
  `schedule_opted_out` field MUST read as `false`, since a beacon predating the sentinel cannot have one.
- **The beacon MUST NOT be spawned per repaint (MUST, dig_ecosystem#2311).** Reading the mirror means
  spawning a subprocess, and the surfaces that show it rebuild about twice a second. An implementation MUST
  hold the reading across repaints and re-read on its own cadence (`BEACON_REFRESH`, 5s), and MUST re-read
  immediately after a change is applied rather than showing the pre-change position until the interval
  lapses. On Windows every such spawn MUST set `CREATE_NO_WINDOW`: dig-app is a GUI-subsystem process and
  `dig-updater` is a console binary, so without it Windows paints a console window per call.
- **The elevation command MUST contain no run-time value (MUST, dig_ecosystem#2325).** The Windows route
  passes PowerShell source to `-Command`, so any value spliced into that string is offered to a tokenizer.
  The beacon's path and every argument MUST instead travel in the elevator's environment block, and the
  command string MUST refer to them only as `$env:` variables whose names are generated from an index.
  Escaping MUST NOT be relied on in their place: PowerShell terminates a single-quoted literal on any of
  FIVE codepoints (U+0027, U+2018, U+2019, U+201A, U+201B), all legal in NTFS, so a quote-doubling escape
  truncated the `-FilePath` and executed the tail — unelevated, because `Start-Process` had already failed
  and `-Verb RunAs` never ran. Conformance MUST be asserted as an ABSENCE (no fragment of the path appears
  in the command string), paired with an assertion that the value still arrives unmodified by the other
  route; an instrument that models PowerShell's quoting rules can share the escape's blind spot.
- **The state shown MUST be the state observed (MUST, §6.4).** Where the beacon cannot be asked — not
  installed, or unwilling to answer — the group MUST say so and MUST NOT draw an on/off control or a
  channel selection. A switch position no one reported is a lie about the machine's configuration. The
  explainer MUST remain reachable in that state, so the surface is never a dead end (§3.1c).
- **The channel choice MUST show which channel is in force**, marked with a WORD and not a glyph (the
  window's font stack has no U+2713). Both channels MUST be offered; the two feeds are
  `https://updates.dig.net/v1/stable/manifest.json` and `/v1/nightly/manifest.json`.
- **A channel switch MUST be confirmed before it is applied (MUST).** Each channel is an independent trust
  context with its own rollback floor, so a switch cannot rewind the floor of the channel being left — but
  leaving nightly CAN move installed components back to an older stable release, because nightly is usually
  ahead. The user MUST be told that the version can go DOWN, and MUST agree, before the change is made.
  Declining returns quietly (§3.1c-ii).
- **The elevation cost MUST be stated in the control's own label (MUST).** Writing the beacon's config
  requires Administrator/root on every platform DIG ships on. The row MUST say so before it is clicked; a
  cost revealed only at the prompt is a surprise. READING the state MUST never require elevation.
- **A platform with no elevation route MUST refuse and explain (MUST).** Where the host offers no way for a
  desktop app to request elevation that DIG will use, the change MUST NOT be attempted; the notice MUST
  name the equivalent terminal command so the setting stays reachable. A declined elevation prompt MUST
  read as "nothing was changed", not as a DIG fault, and MUST NOT update the remembered preference.
- **The auto-update group is a WINDOW surface, not a tray one.** The tray's top level MUST stay short
  (§3.1c), and this group is not one of the verbs that earns a spine row. Hosts with no window
  (`WindowHost::Unavailable`) also have no elevation route, so the beacon's own CLI is the conforming
  interface there.

### 3.1c-v Reporting a chain write (normative, dig_ecosystem#2995)

Every write dig-app makes to the chain — a profile mint, a store launch, a send — MUST be visible while it
happens, and MUST be described in terms of what the chain has actually proved.

- **A chain write MUST NOT run on the thread that paints (MUST).** A mainnet ceremony takes minutes, and a
  window that stops repainting for its duration is indistinguishable from a crashed program. The
  implementation MUST perform the write on a worker and MUST NOT block a painting thread on its completion,
  because the reported progress is worth nothing on a thread that cannot draw it.
- **A broadcast MUST NOT be reported as a confirmation (MUST).** A pushed bundle is an acceptance into a
  mempool; a confirmation MUST come from a chain sighting and MUST carry the height it was seen at. The
  surface MUST say, in words and not only in structure, that a pushed transaction is not yet confirmed, and
  MUST show the id a person can look it up by. Colour MUST NOT say more than the words do — a broadcast
  MUST NOT be coloured as a success.
- **A multi-bundle ceremony MUST NOT be reported as finished by one bundle (MUST).** Creating a profile
  confirms a DID and only then launches a store, so it reaches a genuine chain-proved confirmation halfway
  through. That confirmation MUST be shown as the fact it is AND MUST NOT settle the ceremony.
- **A write MUST raise the surface by itself, and no write site may opt in (MUST, dig_ecosystem#3075).**
  The surface MUST be defined once and MUST observe the transaction feed, so that a write started anywhere
  raises it. A write site MUST NOT construct, receive or show the surface, so that a site added later
  cannot omit it.
- **The surface MUST be a modal, and it MUST keep painting (MUST, dig_ecosystem#3075).** While an
  unsettled write is in flight the surface MUST scrim the window and MUST show indeterminate progress that
  advances on wall-clock time, so that a stopped process is visibly stopped. Every frame that draws it MUST
  request the next one. It MUST NOT perform or wait on the write itself.
- **The surface MUST be dismissible, and dismissing MUST NOT touch the transaction (MUST).** Dismissal MUST
  be available at every moment, by both a keyboard escape and a control, and MUST leave the write running
  and reachable — a compact indicator MUST remain, carrying the live stage. The surface MUST NOT close
  itself before the write settles, and the implementation MUST NOT forget a write that has not settled.
- **A ceremony's position MUST be stated only as far as it is known (MUST, dig_ecosystem#3075).** Where a
  write is one of several, the surface MUST say which step is in flight and whether more follow. It MUST
  NOT state a total, which no publisher declares.
- **The surface MUST hold no authoritative copy of anything (MUST, dig_ecosystem#3066).** It MUST read the
  feed and nothing else; durable data MUST already be on disk before a bundle is pushed.
- **Every state MUST offer an action, and a failure MUST name a next step (MUST).** Where an interrupted
  ceremony cannot be resumed, the failure MUST say so and MUST tell the person what NOT to do, rather than
  implying a retry that would pay twice.
- **A cost MUST be stated wherever money moves, and an unmeasured cost MUST be silent (MUST).** A fee or an
  amount that was never measured MUST NOT render as zero, which is a claim that the transaction is free.

### 3.1c-vi Editing a profile (normative, dig_ecosystem#2993)

dig-app MUST let a person change everything their dig-profile publishes about them, and MUST do so without
ever leaving the profile committed to content nobody holds.

**The editable set.** The editor MUST offer exactly the named standard slots — display name, bio, avatar
image, banner image, pronouns, location, links and XCH address — and MUST NOT offer the schema-version slot,
the key slots, or any custom or encrypted slot. The two image fields MUST be the INLINE data-URL slots
(`0x0020`, `0x0021`), never the `dig://` reference slots (`0x0003`, `0x0004`): the bytes ride in the profile
body, and writing them where readers dereference a URI publishes an image no client can show.

**Three acts, and they MUST NOT collapse into two.** Setting a slot, REMOVING a slot, and leaving it alone
are different edits. A field emptied that held a value MUST commit a removal; a field emptied that held
nothing MUST commit nothing, because a spend that removes an absent slot pays for no change; a field typed
back to its committed value MUST commit nothing.

**Reading MUST be verified, and its states MUST be distinct (MUST).** The profile MUST be read through
a seam that verifies the body against the root the CHAIN anchors, and the surface MUST distinguish: a read in
flight, a profile that answered and holds nothing, a store under which NOTHING has ever been published, a
body that CONTRADICTS the anchored root, a read that failed, and a profile with values. A profile
holding nothing is a STATE and MUST NOT be drawn as a fault. A read that FAILED MUST NOT be drawn as an empty
profile and MUST NOT offer an editable form — an edit computed against a profile the app could not see would
commit a body missing everything it already held. A failed read MUST offer a retry.

**The profile read MUST be RATE-bounded, not merely de-duplicated (MUST).** The pane asks for a refresh on
every frame and has no cadence of its own, so the service MUST hold reads to at most one per `READ_INTERVAL`
(**15 s**, under one Chia block), timed from the START of a read. Preventing only CONCURRENT reads is
insufficient: an in-flight guard clears the instant a read returns, so reads run back to back at frame rate,
and each is a singleton lineage walk plus a `coinById`. That MUST NOT happen — it exhausts dig-node's wallet
rate limiter, after which the app permanently denies itself the read it needs. It follows that a read
REFUSED for rate limiting MUST NOT be retried immediately; only a person's explicit retry MAY read sooner.

**Only a failed read MAY offer a retry (MUST).** A store with nothing published and a body that contradicts
the chain are settled answers: asking again cannot produce content nobody wrote, and cannot make a
contradicted body agree with the chain. Each MUST be given its own sentence naming its own remedy, and
neither MUST be worded as a fault of the node or the network. Neither MUST offer an editable form.

**A missing body MUST be rebuilt from the mint seed when it VERIFIES, and MUST NOT be published otherwise
(MUST).** A profile minted before dig-account 0.16.0 anchors a root whose body was computed and discarded, so
nothing holds its preimage. Because the seed is deterministic (`ProfileSeed::root()` is defined over the same
constructor as `ProfileSeed::body_bytes()`), the implementation MUST, on finding the store holds nothing,
rebuild the body from the seed this app mints from and compare it against the root the CHAIN anchors. On a
match it MUST store the bytes via `control.profile.putBody` and serve the read from them; this path writes no
chain state and spends nothing. On a mismatch it MUST publish nothing and MUST report the store as holding
nothing published — a body that does not verify belongs to a different seed, and publishing it would serve
content the chain contradicts.

**The bytes a commit returns MUST be persisted (MUST).** A commit yields a status AND the canonical body
bytes the new root commits to. The implementation MUST store those bytes — via `control.profile.putBody` on
the local node — and MUST read them back at the root they were stored under before reporting the edit as
done. A store that accepts a body and does not hold it MUST fail the commit. This is the one failure with no
error of its own: the root reaches the chain, nothing holds its preimage, the profile becomes unreadable
permanently, and every layer reports success.

**The bytes MUST be written to local durable storage BEFORE the spend is pushed (MUST).** The node accepts a
body only at the store's CONFIRMED on-chain root, so between the push and the confirmation the new root is
committed permanently while its preimage exists only in the running process. The implementation MUST
therefore compute the body the edit will publish, and persist `(store_id, root, body)` to a local pending
file, BEFORE anything is signed or pushed. A write performed only after the commit returns, or only when
`putBody` is refused, does NOT satisfy this: it is absent for exactly the crash it exists to survive.

The pending file MUST live in the per-profile AppData directory and MUST be sealed at rest to the user's key
(NC-2 / NC-3). It MUST be drained — every entry re-offered to `control.profile.putBody` — at the next launch,
and an entry MUST be removed ONLY after `control.profile.getBody` returns those exact
bytes at that root; a successful `putBody` alone MUST NOT clear it. An edit whose outcome is UNKNOWN (an
unanswered chain) MUST keep its entry; only an outcome proving nothing reached a mempool may drop it.

Where the body must be predicted rather than obtained from the commit, the implementation MUST compare the
predicted root against the root the commit returns and MUST discard a prediction the commit contradicts, in
the same call that made it.

**A body that is UNRECOVERABLE MUST be named as lost, and MUST still be offered the form (MUST,
dig_ecosystem#3041).** When the node answers `body_b64: null` at the store's confirmed root and no seed this
app mints from rebuilds to that root, the root was produced by a real edit whose bytes exist nowhere. The
implementation MUST distinguish that state from *nothing has ever been published*, which reaches the surface
through the identical node answer, and MUST NOT describe it with the unpublished wording — a person whose
content was destroyed MUST NOT be told that nothing has gone wrong. The sentence MUST name the root, MUST
NOT offer a retry, and MUST name the one remedy that exists: publishing a fresh body.

The implementation MUST therefore offer the editing form over this state, with EMPTY fields, even though no
read succeeded. This is the sole exception to the rule that a failed read withholds the form, and it holds
only because there is nothing left to overwrite. The surface MUST NOT draw the resulting empty form as an
unfilled profile: the loss MUST be stated above the fields, so the form reads as a re-entry rather than as
the person's own values. Publishing from it MUST satisfy every rule above, the pending-file write
before the spend included.

Publishing from it MUST NOT be routed through the DELTA edit operation. A delta reads the published body
before it can apply a change, so over a body that is gone it fails inside the very call carrying out the
remedy, and the person is returned to the state they started in. The implementation MUST use an operation
that writes a whole body without reading one (`ProfileEditor::publish_profile`, dig-account ≥ 0.18), and MUST
route to it ONLY from the unrecoverable state: a profile that READ MUST take the delta path, because a fresh
publish replaces the whole body and would delete every slot the form does not carry. The body written to the
pending file before the spend MUST be built by the same constructor the publish uses, so the copy kept is the
preimage of the root the chain confirms.

**A failed publish MUST say whether any XCH was spent (MUST).** Publishing spends real XCH, so a failure
MUST state, alongside what went wrong, that nothing was sent and nothing was spent — and MUST state it ONLY
on outcomes that PROVE no bundle reached a mempool. An outcome whose fate is unknown (an unanswered chain, a
failed persist) MUST NOT be given that sentence: it would invite a second spend over a first that may still
confirm.

The 1-mojo singleton amount and the previous content MUST NOT be promised back by any wording.

**A failed persist MUST be reported as an edit that HAPPENED (MUST).** It occurs after a successful push, so
the surface MUST say both true things — the change was sent, and the content is not stored on the node — and
MUST NOT offer the form again as though nothing had happened. It MUST also say whether a local copy was
kept: a promise to retry that the implementation cannot keep is the most damaging sentence the editor can
say, so the two cases MUST be distinguished by fact and not assumed.

**Size MUST be refused before the form is filled in (MUST).** A body has two ceilings — 1,400,000 bytes for
any one slot and 4 MiB for the whole body — and both MUST be checked against the projected body as a person
edits, not only when the body is assembled. The check MUST account for the slots the editor does not show,
and MUST subtract what a replaced slot costs today rather than only adding what its replacement costs.

**Whether editing is OFFERED MUST be read off the seams (MUST).** An unmeasured build MUST withhold the
offer exactly as a blocked one does, and MUST NOT name a cause nobody observed. A blocked build MUST name
which piece is missing — no chain transport, no profile, or a locked account — with the remedy for it.

- **There MUST be exactly ONE set of seams, and the offer MUST be read off the set the app SAVES through
  (MUST).** A surface MUST NOT construct a second seam value to answer the offer question. Two expressions of
  one capability disagree eventually, and the way they disagree is a Save control drawn by a surface with
  nothing behind it.
- **A seam set MUST be installed whole or not at all (MUST).** Chain reads, the push, and the body store are
  one capability: a build that can spend but cannot persist MUST report no chain transport rather than
  offering a control that commits a root whose content it cannot keep.
- **Whether the account is unlocked MUST be decided by the same predicate the seam signs under (MUST).** A
  surface that asks a second way can offer Save to an account that has since relocked.

**Naming the store MUST NOT require a chain read (MUST).** The store a profile lives in is fixed when the
seam is built. Obtaining it MUST NOT perform a node round trip, because the caller that needs it is the
commit path and that path is entered from the thread that paints.

**The commit MUST obey §3.1c-v.** It MUST run off the painting thread, it MUST be reported through the same
transaction surface every other chain write uses, and a pushed edit's root — a PREDICTION — MUST NOT be
rendered as confirmed. Only a height the chain reported may be drawn as a confirmation. A watch that gives up
MUST say the change may still confirm and MUST tell the person not to publish again while it might.

**§908 is unchanged.** The node never signs. The edit is built and signed in dig-app under the unlocked
account; the node reads chain, stores the body, and pushes an already-signed bundle.

### 3.1c-vii Viewing another person's profile (normative, dig_ecosystem#3008)

dig-app MUST let a person look at a dig-profile that is not their own, and MUST NOT present any part of it
as more certain than it is.

**The identifier.** The surface MUST accept a dig-store singleton launcher id as 64 hexadecimal characters,
with or without a `0x` prefix, in either case, and MUST tolerate surrounding whitespace: each is the same 32
bytes, and refusing one spelling refuses a correct answer for how it arrived. It MUST recognise a
`did:chia:` string as a DID and MUST report that DIG cannot resolve one to its store — nothing on chain
indexes a DID back to the store launched from its coin, so this is a missing capability
(dig_ecosystem#2392) and MUST NOT be reported as a malformed identifier or as an absent profile. An
identifier of the wrong LENGTH MUST be distinguished from one that is not an identifier at all.

**The read MUST be chain-anchored (MUST).** The root MUST come from chain bytes: the store's singleton
lineage is walked to its tip and the tip's creating spend is re-parsed for the store metadata. The body MUST
be accepted only against that root, by the same acceptance dig-node applies to a synced body
(`VerifiedBody::open(.., AnchoredRoot::from_chain_read(root))`). A body that does not rebuild to the anchored
root MUST NOT be rendered, with or without a caveat.

**The states MUST be distinct (MUST).** The surface MUST distinguish, in words a person can act on:

1. **Nothing looked up.** It MUST claim nothing about any store.
2. **No such profile.** The chain answered and there is no live dig-store at that id.
3. **Root anchored, body not held.** The chain anchors a root and this node does not have the content it
   commits to. This MUST be said explicitly and MUST NOT be drawn as a profile with blank fields, nor as a
   profile that publishes nothing: those are the claims dig_ecosystem#3041 records as having been made about
   a real user's own profile, which was anchored with `body_b64: NULL`.
4. **Body held and verified.** The published fields and images are rendered.

Two further answers MUST NOT be folded into those four. A lookup that could not be MADE — no chain, no node,
no control token — MUST say so and MUST NOT be reported as an absent profile, because the two have opposite
remedies and only one of them concerns the identifier that was typed. Bytes held at the anchored root that do
not rebuild to it MUST be named as unusable.

**The anchored root MUST be shown for every state that read one (MUST).** Including — especially — the
missing-body state and the unverifiable-content state: the root is the only value with which a person can
check the claim, and a sentence without it is the reassuring generic one that caused #3041.

**A field the body does not publish MUST NOT be drawn as an empty value.** Absence and an empty published
value are different facts about a person.

**Rendering MUST reuse the profile surfaces that already exist.** The image well and the field vocabulary the
editor draws are the same ones here; a second way to draw a profile is a second thing to keep true.

**This surface spends nothing and signs nothing.** It requires no unlocked account and no profile of one's
own, and it MUST remain available to a person who has neither.

### 3.1c-iv The settings the window WRITES (normative)

Beside the auto-update group — which dig-app may only ask the beacon to change (§3.1c-iii) — the Settings
tab MUST expose the two `agent.json` fields a person otherwise has to hand-edit: the **node address**
(`node_url`, the ecosystem §5.3 override, whose exposure §5.4 already requires) and the **global shortcut**
(`open_bar_shortcut`, §3.1c-i). These are values, not verbs; they are written by the pane itself rather than
dispatched as menu actions.

- **A write MUST be read back, and what is SHOWN MUST be what was read (MUST).** After storing a setting the
  implementation MUST re-read the file and display that result. This is §3.1c-iii's rule generalised: a
  write that reported success and did not land MUST leave the previous value on screen, never the typed one.
- **A refused value MUST NOT reach the file, and the reason MUST name the remedy (MUST).** Validation MUST
  use the same parsers the agent runs at start-up (`hotkey::Hotkey::parse` for a chord), so a value the pane
  accepts is a value that will work. A read that fails MUST refuse the write rather than replacing an
  unreadable config with defaults, which would silently discard fields this surface does not edit.
- **What DIG will actually use MUST be shown, derived from the code that will use it (MUST).** The effective
  node address is `control::endpoint_ladder`'s own answer, so the sentence cannot drift from the behaviour,
  and a bare `host:port` is displayed as the `http://host:port` that will be dialled.
- **Clearing MUST always be offered and MUST work from an invalid value (MUST).** An empty field means "DIG
  chooses" and MUST remove the setting rather than storing an empty string. The control that clears it MUST
  NOT validate the current text first, or a person who typed an address DIG refuses would have no way out
  (§6.1, never trap the user).
- **The cost MUST be stated before the control (MUST).** A saved node address and a saved chord both take
  effect at the next start, and the default chord displaces the Windows window menu (§3.1c-i); both MUST be
  said in the surface rather than discovered afterwards.
- **A host with no readable settings file MUST say so INSTEAD of drawing the form (MUST).** The same rule as
  an unreachable beacon: a control that cannot take effect MUST NOT be drawn, disabled or otherwise.
- **A connection test, where offered, MUST make the agent's own request** (`control.fetch_status` over the
  §5.1.0 ladder) and MUST report the endpoint that answered or every candidate's reason for not answering.
  It MUST NOT block the frame, and its answer MUST be withdrawn when the address is edited.

**The Apps surface (MUST, dig_ecosystem#2101).** The menu MUST offer an **Apps** submenu grouping the other
DIG apps this install can open, so a sibling app (Chat today; dig-email, dig-video-chat to follow — §5.4) is
reachable from the one surface a person has on a fresh install. Binding rules:

- **Data-driven (MUST).** The submenu MUST be built from a registry, so adding an app is a data row, not a
  new menu action or a new `TrayAction` variant. ONE action (`TrayAction::LaunchApp`) carries the app's
  identity; the registry (`dig_app_core::apps::APPS`) holds each app's display name and installed-binary
  identity. The submenu offers exactly one enabled launch row per registry entry, in registry order.
- **Never a silent no-op (MUST, §6.1).** Clicking an app row MUST always do something visible. Presence is
  a per-entry check for the app's installed binary as a SIBLING of dig-app in the shared bin dir (the
  canonical install root, where every component lands). When the binary is present the app is launched;
  when it is absent the user MUST be shown an honest notice — never nothing, and never a greyed dead end.
- **Honest copy (MUST, §6.0).** dig-chat is not yet packaged or carried by the installer, so the absent
  case is the only reachable one today. Its notice MUST NOT fabricate an install or "run X" step the user
  cannot satisfy; it states that the app is coming and will appear in this menu on its own once it ships.
- **A launch runs off the prompt thread with no identity on argv (MUST).** The app is spawned as a detached
  child — never on the single-threaded prompt thread (#78) — with NO arguments; identity, keys and pairing
  material MUST NOT be placed on the child's command line, because pairing is the launched app's own job
  (§5.4). The launch-vs-notice decision is a pure function (`dig_app_core::apps::plan_launch`) so both
  outcomes are tested without spawning a process or drawing a window.
- **The window's app launcher MAY state presence, and ONLY from an observed fact (MUST).** The launcher is
  a group on the **Home** tab, not a tab of its own — a dedicated tab for a single card advertises
  emptiness. It renders one card
  per registry entry — the display name, the registry's one-line description, and the model's launch row
  unchanged — and a card MUST NOT re-word the model's label. It MAY additionally show an **"Installed"**
  chip, but only when the snapshot carries an actual observation. Presence is therefore a THREE-state
  reading in the view (`dig_app_core::apps::AppPresence`), and the rendering of each state is normative:
  - `Known(apps)` containing this app — the chip MAY be drawn;
  - `Known(apps)` NOT containing this app — the chip MUST be omitted, and the card MUST NOT be greyed or
    made a dead end; the row stays enabled and the click path still ends in the §3.1c honest notice, which
    is the only surface that has re-checked presence at the moment it matters;
  - `Unknown` — the chip MUST be omitted and MUST NOT be rendered as "not installed". Nobody looked, so
    "not installed" would be a claim about the user's machine that nothing checked. This is the whole
    reason the reading is three-state rather than a list.

  What the chip asserts is bounded by what the check tests: a name in the shared bin dir is a file
  (`is_file`), not a verified executable, so the chip means *this install has that app's binary beside it*
  and MUST NOT be worded as a stronger guarantee. Presence is still re-checked inside the click, and the
  chip is never the authority for whether a launch succeeds — a file can vanish between the observation and
  the click, and only the notice path speaks to that.

  The launcher MUST still say how apps arrive (alongside DIG, with nothing to download), because the chip
  answers "is it here yet" and not "how does it get here". A per-app version MUST NOT be shown: no source
  for one exists that does not mean spawning every app to ask.

### 3.1c-v The hosted-store reading (normative)

The window's cache surface MUST be able to name the stores this node holds, rather than only their count.
The list comes from the node's **`control.hostedStores.list`** control method — `{}` →
`{ stores: [{ store_id, pinned, capsule_count, total_bytes, … }] }` — read over the endpoint the §5.1.0
ladder resolved. dig-app distils each entry (`dig_app_core::hosted_stores::HostedStore`) rather than
carrying the contract type verbatim: the wire entry also carries every cached capsule with a
last-used timestamp that moves whenever content is served, and a snapshot compared field-by-field on every
tick MUST NOT contain a field that changes while nothing visibly does. A surface needing per-capsule detail
asks `control.hostedStores.status` for the one store a person opened.

- **A list that could not be read MUST NOT be rendered as an empty list (MUST).** The reading is
  three-state (`HostedStoresReading`): `Pending` — a read is under way and nothing has failed;
  `Known(vec![])` — the node ANSWERED and holds nothing; `Unknown(reason)` — nobody answered. Only
  `Known(vec![])` may be drawn as "this node is hosting nothing". Collapsing a failed read into an empty
  list is the class of defect [dig_ecosystem#2325] fixed for the balance — a slow node reported as an
  absent one — and the empty variant MUST be constructible only from a node's actual answer.
- **The reason MUST be derived from the node's own reply, keyed on the stable `data.code` symbol** and
  never on the human message, which is not contract-stable. One variant per REMEDY: no node connected, a
  node that does not serve the method, a refusal, a timeout, an unreachable node, and an unclassifiable
  refusal carrying the node's own words. A timeout and an unreachable node MUST stay distinct all the way
  to the sentence a person reads, because only the latter is evidence about whether a node exists.
- **`401`/`403` from this method is `Unauthorized`, NEVER "this node cannot read" (MUST).** Unlike
  `control.wallet.balance` (§3.3), which is served as an OPEN read, `control.hostedStores.list` is
  **token-gated**, and dig-node refuses at the HTTP layer — before any JSON-RPC error exists to carry a
  `data.code`. The HTTP status is therefore a fact that MUST be carried as one, not recovered by parsing a
  string that also contains the node's own message. The two classifications name two different remedies:
  `Unauthorized` means *this app cannot read the node's control token* and is fixed by the token, while a
  method-not-served refusal (`METHOD_NOT_FOUND` / `NOT_SUPPORTED`) means *this build is too old* and is
  fixed by an upgrade. Reporting one as the other sends a person to change something that cannot help.
- **The read MUST be throttled independently of the repaint rate (MUST).** A snapshot is taken twice a
  second and this is a node round trip. A reading is reused for **30 s** (`REFRESH_INTERVAL`) before the
  node is asked again — longer than the balance's interval because a store joins or leaves the cache when
  content is fetched or evicted, not on a chain's schedule.
- **ONE read may take 10 s (`STORES_READ_TIMEOUT`), and this MUST NOT be the §5.1.0 probe budget (MUST).**
  Those budgets answer different questions: a probe budget bounds how long one tier may take to prove it is
  alive before the ladder falls through, while this read walks the node's on-disk cache index, so a large
  cache on slow storage can legitimately take seconds. An implementation that reuses the probe budget fails
  every read on such a machine. Past the budget the read is abandoned AND said to have been abandoned.
- **The read MUST NOT block the surface that asks for it (MUST).** A repaint-driven caller receives an
  answer immediately — `Pending`, or the reading already held — while at most ONE read is in flight, so a
  slow node is asked once however many repaints happen while it thinks.
- **A refresh MUST NOT blank a list already being read (MUST).** While a FIRST read is in flight the answer
  is `Pending`; a refresh of a list already held answers with that list until the new answer arrives.
- **A reading MUST NOT outlive the node it describes (MUST).** A store list is a property of ONE node, so a
  reading taken from one endpoint MUST NOT be answered for another, and the held reading MUST be dropped
  when no node is connected — otherwise the surface reports stores the current node does not hold.

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

  **A bare Enter MUST activate whichever control does less (MUST).** Both platform dialogs default to
  their first button, so a focused destroy window would confirm the destruction of key material on a bare
  Enter/Return. The destroy window therefore pre-selects Cancel (`MB_DEFBUTTON2`; the Return key
  equivalent moved onto Cancel on macOS). The same reasoning binds a **security-weakening** window and a
  **claim** — a window asking the user to assert something is TRUE ("I have written these 24 words
  down") — because nobody asks to be shown their recovery phrase, and a reflexive Enter would record that
  the seed is safely written down on behalf of somebody holding nothing. Ordinary authorizations — a
  sign, a pairing, a connect — keep the affirmative: the user just asked for the action, and refusing
  costs only a retry.

  The test is what each ANSWER DOES, never what KIND of window it is. Where BOTH controls act, "pre-select
  the refusal" is not merely unhelpful, it is the dangerous choice: on the first-run route fork, declining
  "Import my recovery phrase" GENERATES AND SEALS A NEW MASTER SEED, so that window keeps its affirmative
  as the default because importing creates nothing until 24 words are typed. **A control that takes an
  irreversible action MUST NOT be labelled with the backend's generic word for refusing** ("Cancel"); it
  MUST be named for what it does, and a prompt MUST be able to supply that name.

  This MUST be classified per call site, never applied in bulk — and the type system SHOULD force that
  choice rather than leaving a default to be inherited, because a blanket rule applied to a prompt kind is
  exactly how the route fork came to pre-select the control that creates an account. The enrolment
  retention screens ARE decisions — refusing either abandons setup — so converting every window to a notice would destroy a real
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
  **masked**, matching `diga account restore`'s suppressed echo: the words already exist on paper, so
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
- **Everything a window is given MUST be reachable on every display (MUST).** A prompt MUST NOT hide any
  part of its content: where the content is taller than the window, the body MUST scroll, and no display
  size or scale factor may leave text drawn outside the clip with no way to reach it. Silent truncation is
  a custody defect, not a layout one — a 24-word recovery phrase clipped at word 14 produces an account
  nobody can restore, and a decoded transaction clipped at its last output authorises a spend the user
  never saw.
- **Every prompt MUST have a deadline, and reaching it MUST refuse (MUST).** A window nobody answers MUST
  dismiss itself and report a timeout — never an approval, and never nothing. Prompts are serialised onto
  one renderer, so an unbounded window is not one stuck caller: it holds every LATER consent window,
  including the unlock and the destroy confirm, for the life of the process. A caller blocked on a window
  MUST also bound its own wait, so a wedged renderer cannot wedge the caller either.
- **The deadline MUST be enforced from outside the window's own frame loop (MUST).** A deadline checked
  only while drawing is no bound at all: a frame loop that stops running never reaches the check, and the
  window then holds the single renderer indefinitely. An implementation MUST have some agent OUTSIDE that
  loop that can, at the deadline, wake the window and require it to close. Forcing a window closed MUST
  resolve to the same refusal the window's own expiry produces, and MUST NOT be able to produce an
  approval.
- **The renderer MUST survive any single prompt (MUST).** A prompt that panics, fails to open, or is
  abandoned by its caller MUST cost exactly one refused prompt. The serialising loop MUST catch it,
  release any window the platform deferred destroying, answer that caller the fail-closed way, and go on
  to the next prompt. This is not defence in depth: the renderer is the whole consent surface, so a loop
  that exits leaves a process in which nothing can be approved, denied, unlocked or destroyed again.
- **A renderer that cannot be restarted MUST NOT be treated as replaceable (MUST).** Where the windowing
  toolkit permits one event loop per PROCESS, a replacement renderer thread can never obtain one, and
  "detect the dead thread and respawn it" is a silent permanent failure wearing the costume of a recovery.
  Such an implementation MUST make the renderer unkillable instead, and MUST report a renderer that died
  anyway as an operator-visible error naming the remedy (restart the app).
- **A window MUST ask for the keyboard it tells the user to use (MUST).** A consent window that opens
  without keyboard focus has no escape at all when it is also undecorated and always-on-top: there is no
  close button, it cannot be put behind anything, and Escape goes to whichever window does hold the
  keyboard — while the window's own body may be telling the user to press Escape. Requesting activation
  at window CREATION is not enough on a platform whose foreground lock refuses a background agent; the
  window MUST also request focus once it exists. It MUST NOT re-request on every frame, which takes the
  foreground back off whatever the user switched to. Where the platform refuses, the window MUST remain
  answerable by pointer and MUST still resolve on its own deadline.
- **A prompt MUST NOT be drawn for a caller that has already given up (MUST).** Prompts are serialised, so
  one wedged window parks every later prompt; their callers time out and are refused, but the queued work
  survives. Opening those windows afterwards shows real consent surfaces — real origins, real payloads —
  for operations refused minutes earlier, and re-occupies the renderer for each. A queued prompt MUST
  carry its caller's absolute expiry and MUST be refused WITHOUT being drawn once past it.
- **Every non-answer MUST be logged (MUST).** A prompt that could not be shown, was never answered, or was
  refused because the renderer is gone MUST leave a log record identifying the prompt and the reason. A
  consent surface that stops working silently is one only a user can discover.
- **The FIRST answer a window records is the one it reports (MUST).** Closing a window is asynchronous —
  the frames between "the user clicked" and "the window is gone" MUST NOT be able to change what was
  answered. A window that recorded nothing MUST still resolve to a refusal.
- **A window MUST be destroyed when it is answered (MUST).** A prompt that returns its answer while its
  window is still on screen leaves an always-on-top surface whose event loop has stopped — indistinguishable
  to the user from a crashed application, and impossible to dismiss. Where the windowing system defers
  destruction to the event loop, the backend MUST run that destruction to completion before it reports.
- **Nothing typed into a masked field may outlive it (MUST).** A masked control masks what is DRAWN; a
  backend MUST also ensure the toolkit is not retaining its own copies (undo history, autofill, a
  clipboard shadow) beyond the frame. Where the toolkit exposes no way to wipe such a copy, the backend
  MUST at least bound its lifetime to the frame and MUST say so — this reduces exposure rather than
  eliminating it.
- **An undecorated prompt window MUST be movable, and MUST NOT be movable by its controls (MUST).** A
  consent window sits above everything and cannot be put behind anything, so one that cannot be moved
  covers the very thing the user is reading in order to decide; an undecorated window offers the platform
  no titlebar to move it by. A backend MUST therefore expose a drag affordance in its OWN chrome, and MUST
  hand the resulting gesture to the window manager rather than repositioning the window itself frame by
  frame. The platform gesture is what supplies edge snapping, monitor boundaries and per-display scale
  transitions; a hand-driven reposition reimplements none of them and fights the compositor at exactly the
  moment a frameless surface is known to lose its content. The draggable region MUST exclude every
  control, and the action row in particular: hit testing resolves a press-and-move separately from a
  click, so a drag region merely layered BENEATH a click-only button still captures the gesture — the
  affirmative control would then travel out from under a cursor already committed to pressing it, and
  depth cannot prevent that, only geometry can. Moving a window MUST NOT change what it reports, MUST NOT
  dismiss it, and MUST leave its focus, its always-on-top placement, its Escape path and its deadline
  exactly as they were. Where a window's position can be influenced by a CALLER, it MUST be clamped to the
  visible work area, so a hostile origin cannot place a consent window off-screen or beneath another.

**Current state:** Windows and Linux draw the **branded prompt window** — one renderer, in-process,
shared by every consent and input prompt, in hub.dig.net's visual language, with the field, the masking
and the reveal-while-typing control (dig_ecosystem#2038). macOS still uses an `NSAlert` with a text-field
accessory view, deferred with its reason in dig_ecosystem#2047.

A subprocess input helper is explicitly REJECTED: it would need a verify-the-helper-is-ours check, or a
`PATH` impostor harvests recovery phrases, so every backend draws its window IN-PROCESS. Since #2038 that
is no longer a rule a backend could break by accident — the Linux `zenity`/`kdialog` path, the only one
that ever shelled out, is deleted, and with it the "neither helper is installed, so there is no consent
window" failure mode.

The rendered text is PLAIN by construction. The branded window rasterises glyphs, so a hostile
attacker-supplied value cannot be interpreted as markup and cannot forge UI inside a real consent window;
there is no escaping step to omit at a new call site, because there is no markup parser to escape for.

That guarantee covers INTERPRETATION, not COMPOSITION, and the two are different attacks. A
caller-supplied **display name** — a dapp's `dapp_name`, an extension's `ext_label` — is drawn INTO a
heading sentence the app speaks in its own voice, so whatever it can add to that sentence the user reads
as the app's own words. A name of `"Chia Wallet (chia.net) wants to connect to your DIG
identity

Verified by DIG"` yields a heading whose FIRST line is a complete and entirely false
sentence, with the true origin displaced onto a later line — and it uses no markup, so the plain-text
guarantee above cannot see it.

Every caller-supplied string composed into app-voiced text MUST therefore be neutralised first. That
is the display **name**, and equally the **origin**: an origin arrives as unvalidated free-form text
off the loopback wire, and a connect that forges its heading is additionally SEALED into the
whitelist and replayed atop every later signing window.

Neutralisation collapses to a single space each of the three layout forgeries, which are distinct and
must all be covered:

1. **line breaks and control characters**, which add lines;
2. **bidirectional overrides**, which reorder the displayed run while adding no character and no line,
   so a line-count check cannot see them;
3. **zero-width and other invisible format characters** (U+200B–U+200F, U+061C, U+2060, U+FEFF), which
   are neither whitespace nor control characters, and which pad the length budget while drawing
   nothing — so the WALLET'S OWN truncation can be made to land on an attacker-chosen boundary.

Whitespace runs then collapse and the result is length-capped. **A clipped string MUST carry its clip
marker in the text itself**, not merely in a returned flag: a silently truncated string is
indistinguishable from a short one, which is the whole of forgery 3, and a marker a caller can drop by
ignoring a return value is how that defect shipped once already. A string left with no visible content
MUST fall back to explicit words rather than render blank. Ordinary strings — accents, apostrophes,
dashes, CJK — pass through unchanged.

There MUST be exactly ONE implementation of this. Three independent ones existed, and they disagreed:
the same hostile string forged different windows differently, and only one of the three covered
forgeries 2 and 3.

This is the exact opposite rule from the one governing a **decoded transaction**, and the distinction is
load-bearing: the decoded transaction is what the signature covers, so it is shown VERBATIM — neither
interpreted nor escaped nor collapsed — in its own field. Chrome must never be able to speak; the signed
subject must never be altered.

The destroy window's pre-selected refusal is honoured on Windows and Linux (the refusing control holds the
opening focus and the focus ring) and on macOS (the Return key equivalent moves to Cancel).

A dialog prompt is MOVABLE: pressing its header strip hands the move to the window manager, so the
window follows the pointer with the platform's own behaviour for monitor boundaries and per-display
scale. The strip is the chrome bar minus the theme toggle and a dead zone in front of it, and its lower
edge is clamped so that it can never reach the action row at any window height. A finished move
cannot press a control for a reason that does not depend on that geometry: the handle senses CLICK
as well as drag, so the move is withheld until the gesture has already been disqualified from
resolving as a click, and the release that ends it therefore cannot resolve as one wherever it
lands. The geometry is the backstop. Only a primary-button press moves a window, and the handle
takes no keyboard focus. Moving a window
changes nothing else about it — its answer, its focus, its always-on-top placement, its Escape path
and its deadline are all unaffected. Edge snapping does not apply, because the platform reserves it
for resizable windows and these are sized to their content. The launcher bar is deliberately not
movable: it dismisses itself on blur, and a move that blurred it would make it vanish mid-gesture.

The branded window honours both `InputStyle` presentations (dig_ecosystem#2054). An `InputStyle::Dialog`
is the titled, framed, content-sized card every account journey uses. An `InputStyle::Bar` is the
frameless Spotlight-style launcher: wider than a dialog, a fixed short height, placed high on the screen
(centred horizontally, `monitor_height / 5` from the top), with an oversized field and at most a single
hint line and no consent chrome. A bar is dismissed by Escape OR by losing focus, and either dismissal
reports `InputOutcome::Cancelled`, never an approval. A consent window (`Screen::confirm`) is ALWAYS a
dialog and NEVER dismisses on blur — the launcher's dismiss-on-blur is structurally unreachable for any
window asking the user to authorise something.

Platform limits, recorded rather than papered over: on macOS an `NSAlert` accessory would need a custom
view hierarchy for a reveal-while-typing control, so the phrase field there is masked with no un-mask
control — the direction §3.1d requires a backend to fail in. macOS also draws every input as a dialog: an
`NSAlert` cannot be made frameless, so `InputStyle::Bar` is honoured on Windows and Linux (the branded
window) but not on macOS, tracked in dig_ecosystem#2047.

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
    - **Forward direction — a monotonic/trusted-time basis was evaluated and is deliberately NOT adopted.**
      No operating-system monotonic clock survives a reboot (Linux `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`,
      Windows `GetTickCount64`/`QueryUnbiasedInterruptTime`, macOS `mach_continuous_time` all reset at
      boot), yet the bound MUST persist across reboot — so no monotonic reference bridges the shutdown gap
      that the wall clock, which the forward attacker controls, otherwise fills. Crediting only a bounded
      elapsed per observation would instead punish the HONEST owner who waits out a long backoff and then
      makes a single attempt (the full wall-delta clamps to the ceiling and tells them to keep waiting) —
      the very denial-of-service against the owner the rate limit is designed to avoid. A network
      trusted-time source is blockable and spoofable by the same privileged attacker and adds an offline
      failure mode. The operative bounds therefore remain the PERSISTENT escalating failure counter and
      the platform authorization seam (§3.1d); the wall-clock deadline with the backward-only anchor is
      retained by design, not by omission.
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

**Exactly one profile is ACTIVE, and the app stores no copy of which (MUST).** The single storage
location is `dig_account::ProfileRegistry`, whose scalar `active: Option<ProfileIx>` cannot represent
a set of size two — so "exactly one" is structural rather than asserted. dig-app holds ONE
`account::profile_session::ProfileSession` over it (`Arc<RwLock<..>>`), and every derivation seam
re-reads the index PER OPERATION. A handle that stored the index MUST NOT exist: `ResidencySigner`
and `ResidencySealer` carry no index field, so a switch cannot half-land across a handle the
switching code cannot reach.

`ActiveSlot` is the reading — `Unprofiled` when nothing is minted (deriving at `ProfileIx::ROOT`), or
the active profile's index, DID and label. An account with no confirmed profile has NO DID, and every
identity surface MUST say so rather than render the root signing public key as an identity.

**An index crosses an API boundary only as a vouched-for type (MUST).** `account::lifecycle::open_or_enroll`
takes a `WalletSlot`, constructible only as the bootstrap or from the registry's own `ActiveProfile`
borrow; a new mint takes a `MintTarget`, constructible only from `ProfileRegistry::next_free_ix`. A
bare `ProfileIx` MUST NOT typecheck at either, so a wallet cannot be opened, nor a profile minted, at
an index nothing vouched for.

**An exhausted account is offered NO target (MUST).** `ProfileRegistry::next_free_ix` answers
`Option<ProfileIx>`, and `None` — no free index remains — MUST propagate as an absent `MintTarget`.
A host MUST NOT substitute any index in its place: every index it could substitute is one that may
already hold a profile, which the registry then refuses as a duplicate, permanently, from durable
state.

**A mint the account cannot RECORD MUST be refused at the door (MUST).** `ProfileMintDoor` reports
the account's own refusals as `MintRefusal`, and `begin`, `advance`, `status`, `liveness` and
`record` MUST each obtain their target through that check rather than beside it. The refusals, in
precedence order:

| refusal | condition | surface reason |
|---|---|---|
| `RegistryUnreadable` | the session's registry failed to load and it is running on an in-memory store | `CreationBlocked::RegistryUnreadable` |
| `IndexesExhausted` | no free profile index remains | `CreationBlocked::IndexesExhausted` |
| `FundingElsewhere` | the paying index and the target index differ | `CreationBlocked::FundingElsewhere` |

`RegistryUnreadable` ranks first because it is the only one whose cost is unrecoverable: a mint
there spends real XCH and creates a permanent on-chain identity whose sole record is in memory, so
the paid DID is absent after a restart. A surface MUST NOT offer creation in that state.

**A surface MUST NOT assert that a build cannot mint (MUST).** Every sentence about whether a
profile or a DID can be created MUST be derived from a measured reading — `ProfileCreation`, itself
a function of the mint seam — and never from a constant. An unmeasured reading renders as unmeasured
(`ProfileCreation::Unknown`), never as a named cause.

**Funding and target are distinct indices (MUST).** A mint is paid for by one profile's wallet and
creates a profile at another index. They coincide only for an account's first profile, and a host
that collapses them funds a mint from the new profile's empty wallet.

**A switch MUST be disclosed and MUST NOT half-land.** Every profile-scoped derivation seam MUST
re-read the active index per operation rather than capture it — the identity signer, the per-profile
sealer, the DID the sealed stores tag records with, the directory those records are written to, and
the DID the connect handle advertises. No DERIVATION seam is rebuilt on a switch, because none holds a
copy to rebuild: the sign-service router is moved onto a serving thread for the process lifetime and no
switching code can reach it, so "rebuild it" is not a contract any consumer could satisfy. The one kind
of state that unavoidably IS a copy — the live authorization maps — is scoped per profile instead (see
below), which needs no reach. A switch
that cannot be PERSISTED MUST be rolled back in memory, or the receive address silently reverts at
the next start.

**The advertised signing key MUST be read from the signer that will sign.** The connect handle's
`pubkeys` is derived from the router's own identity signer at the moment it answers, not carried
alongside it, so the key advertised is the key that will sign. The DID beside it is a separate read,
so the two naming one profile is a property of reading them adjacently, not an invariant a switch
cannot break; a single acquisition serving both is what would make it one.

**A profile-scoped seam with no active profile MUST fail closed, never substitute a placeholder.** A
locked account has no DID and no directory: the sealed stores refuse to seal, the connect handle is
refused with `LOCKED` rather than returned with a null DID, and the at-rest store persists nothing.

**Skipping a WRITE fails closed; skipping a REMOVAL does not, and MUST be reported.** The two
directions of at-rest persistence are not symmetric. A write that no directory can receive is
dropped, and the user simply ends up with less access than they granted. A REMOVAL that no directory
can receive leaves the sealed record in place, restore re-reads it at the next start, and the caller
has already been told the grant is gone — so `connect.revoke` MUST refuse with `LOCKED` rather than
answer `revoked: true`, and the tray MUST NOT promise a revoke lasts past a restart unless the record
was actually deleted.

**The authorization maps MUST answer for the profile now active, not the one that granted.** The
pairing store and the connect whitelist are built once and read by a router on a serving thread no
switching code reaches, so each record carries the DID it was granted under and every lookup — the
connect gate, the sign gate, the tray's list, and both revokes — MUST ignore a record belonging to
another profile. A grant made under one profile that still authorizes under another would skip the
connect ceremony and hand the caller the NEW profile's DID, addresses and signing key; and a revoke
taken under the wrong profile would delete a record in the active profile's directory while dropping
another profile's live entry, which lasts only until the next start.

**`ProfileSwitched` is `#[must_use]` to force DISCLOSURE, not a rebuild.** A switch changes what a
person's identity is and where their money will arrive, so a consumer MUST tell them; the attribute
is what stops that being dropped silently.

**The receive address MUST NOT be claimed to move with the switch.** `dig-account` fixes an unlock's
wallet index at open time and exposes no `wallet_ops_at` (dig_ecosystem#2496), so after a switch the
wallet can only answer for the profile just left. Every money accessor — including
`observe_receiving_address`, the one the tray renders — MUST refuse rather than answer, the surface
MUST show no address rather than the previous profile's, and the disclosure MUST say the address has
not moved yet.

**Two artifacts are account-scoped and MUST NOT follow the switch:** the 24-word recovery phrase and
the second factor. The phrase is the account's custody root and the second factor gates unlock, which
happens before any profile is active; sealing either under a per-profile DEK would make it unreadable
exactly when it is needed. The profile DIRECTORY, by contrast, MUST follow the switch — sharing one
directory across profiles puts one profile's sealed stores beside another's under a DEK that cannot
open them.

**A spend confirmed under one profile MUST NOT be signed under another.** The confirm ceremony names
a profile; the active slot MUST be re-checked immediately before signing and the spend failed closed
if it moved.

#### 3.2-m The profile-management surface (normative, dig_ecosystem#2403)

The Account tab carries the account's profile list and its controls. Four controls are specified, and
one of them is specified as ABSENT.

**The list is a three-state READING, never a `Vec` (MUST).** `profiles::ProfilesReading` separates
*nobody has read the registry yet* (`Pending`) from *the registry answered and holds nothing*
(`Known(vec![])`) from *the registry would not load* (`Unknown`). Every production account today
answers `Known(vec![])`, because nothing can mint — so a surface that collapsed these would state the
common case about all three. A session that failed to LOAD MUST report `Unknown`, not the empty
registry it fell back to: an account whose registry will not load may hold several profiles, and
telling that person they hold none is a claim no read supports.

**Each listed profile MUST show the root the chain anchors, and MUST NOT show any other root
(MUST).** The store id is permanent and names the singleton for life; the ROOT changes on every
publish and is what says which body the chain currently points at, so a card naming only the store id
can present a profile whose published content is missing as entirely healthy.
`profiles::RootReading` carries the value, is labelled on screen as what the CHAIN holds, and has four
states: nothing has been read yet, a chain-read root, a store that has never published, and a read
that failed with its reason. `RootReading::Anchored` is `#[non_exhaustive]`, so only `dig-app-core` may
construct one, and within that crate `RootReading::of_read` — which takes the result of a verified
chain read — is its only constructor. A root this app merely PREDICTS, such as the one a commit
carries before confirmation, therefore cannot be named as anchored by any surface outside the crate,
and is not named as anchored by any inside it. The compiler enforces the first half; the second is a
convention, because `ProfileSnapshot` is constructible and a caller who assembles one around a
predicted root would be believed by `of_read`. A profile whose body is unrecoverable still shows its
anchored root, matching the re-entry sentence the editor draws for the same root (§3.1c).

**A root MUST be recorded only against the profile it was read for.** The app holds one profile-edit
seam, bound to the ACTIVE profile, so `ProfilesReading::with_active_root` applies the answer to that
row alone and every other row stays *not read yet*. Attributing one profile's root to a sibling would
be the same forgery the anchor check prevents for the DID and the store id, over the value a person is
most likely to check against a block explorer.

**Hidden profiles MUST be listed by this surface.** Visibility is a LOCAL preference and the surface
that sets it is the surface that must be able to unset it. `registry.shown()` is for pickers.

**Creating a profile MUST NOT be offered while no code path can mint one, and the absence MUST be
structural.** No `TrayAction` in this shell creates a profile, so "this build cannot create one" is a
property of the code rather than of an `enabled` flag. `profiles::ProfileCreation` is a FUNCTION of
the `MintAvailability` the start-up wizard's gate reads (§3.1b) — never a second opinion about it —
and it has no *possible* arm while `dig-account`'s `ProfileMinter::mint` is `todo!()`. The surface
states which piece is missing, in the §3.1b wording: the profile is REQUIRED and creating one is
*not available in this version*, never "optional".

**Creation MUST become real, and the type is shaped for it (normative sequencing).** The absence
above is a statement about this build, not a design position: creating a profile is required product
functionality, blocked on `dig-account` publishing its mint. Consumers therefore MUST ask
`ProfileCreation::blocked()` — an `Option` whose `None` already means *creation is possible* — and
MUST NOT match the enum exhaustively, so adding the `Possible` arm is a change of bodies rather than
of shapes. Two rules bind whoever adds it:

- **The create step MUST be the same ceremony first run drives (§3.2b).** One implementation, reached
  from both places. A second implementation of a flow that spends real XCH is how the two drift.
- **A pushed mint is NOT a created profile.** `mint_status` distinguishes confirmed from awaiting
  from failed, and the surface MUST carry all three; a profile is recorded ONLY from evidence of an
  actual on-chain mint (§3.1b). Reporting success from a submission rather than a confirmation makes
  every identity surface assert a falsehood about the chain.

**Hiding MUST NOT be described as deleting.** A minted profile is a `did:chia:` singleton and a store
on chain, both permanent. Copy on this surface MUST NOT say delete, remove, erase or destroy, MUST
state that a hidden profile remains on chain, and MUST leave a way back to it.

**Deleting a profile MUST melt BOTH of its singletons, and MUST be offered for EVERY profile —
including the active one.** A profile is a DID singleton and a dig-store singleton. Ending it spends
both with `(51 () -113)` so neither lineage has a successor. DIG MUST build that deletion through
`dig_account::melt::ProfileMelter::melt_profile`, which places both melts in ONE bundle gated to
exactly two spends whose coin ids equal the two tips it resolved — so a half-deleted profile is not a
state this app can produce. DIG MUST NOT hand-roll a melt spend, and MUST NOT offer deletion of one
singleton alone.

- **The consent surface MUST NAME what is destroyed (NC-14).** A value delta is not consent: both
  amounts together are 2 mojos, which sits inside any sane allowance and would be spent without a
  person ever seeing it. The confirmation MUST name the profile, its `did:chia:` identifier and its
  store launcher id, MUST state that every reference to that identity stops resolving everywhere and
  cannot be re-created, and MUST be escapable with refusal as the default answer.
- **The description a person consents to MUST derive from the SAME built and gated plan that gets
  signed.** `preview_deletion` performs every read and every refusal `melt_profile` performs and
  stops one statement before the signature. DIG MUST NOT compute a second description beside it.
- **The 1-mojo amounts MUST be described as spent, never refunded.** The singleton top layer permits
  exactly one odd-amount `CREATE_COIN` and the melt condition occupies it, so a refund is
  unexpressible rather than unimplemented. No copy may promise it back.
- **Copy MUST NOT claim published content is erased.** Peers hold profile bodies keyed on
  `(store_id, root)`. Melting ends the chain record; it reaches no copy anybody already has.
- **A deletion MUST NOT be reported from a push.** Only a chain read proving BOTH coins spent may be
  drawn as deleted (`melt_status`). A pushed-but-unproved melt MUST say the outcome is unknown and
  MUST advise waiting rather than retrying, because a second attempt while the first is in a mempool
  spends twice.
- **The seam MUST be aimed by the profile the person named.** A melt seam is bound to one profile at
  construction; DIG MUST build it from the index the pressed control carried and MUST NOT act on the
  profile that happened to be active.
- **A confirmed deletion MUST be recorded locally in the SAME step that proved it**
  (`ProfileRegistry::record_melted`). The entry is marked ended rather than removed, so the account
  can still say what it used to be. When the deleted profile was ACTIVE the slot MUST move to the
  lowest-indexed remaining live profile, or be cleared when none remains; DIG MUST NOT leave the
  wallet deriving at a profile whose singletons are gone. A height of 0 MUST be refused, because 0 is
  what an unconfirmed read looks like.
- **An ENDED profile MUST NOT be listed.** The profile list projects `ProfileRegistry::live()`, never
  `entries()` — dig-account keeps an ended entry so a host *can* render what an account used to be,
  and a list whose rows carry a delete verb MUST NOT. Listing a melted profile asserts a fact about
  the chain that is false, and offering its delete control again names a destruction that has already
  happened. Hidden profiles MUST still be listed, carrying their visibility: hiding is a local
  preference the person can undo, and the surface that manages it is the one that must see it.
- **A deletion that cannot be AIMED MUST say which fact stopped it.** No account, no node, no such
  profile and an already-ended profile are four different facts with four different remedies
  (`profile_melt::MeltUnaimed`). DIG MUST NOT report any of them as a node failure: for a profile the
  person has already successfully deleted, "DIG could not reach your node … nothing was deleted" is
  false in every clause and offers a remedy that can never work.
- **The ceremony MUST run off the painting thread** and report into the one transaction sheet every
  other chain write uses (§3.2b), never a second progress display.

**A switch MUST be disclosed BEFORE it is applied, naming both ends.** The per-profile DEK and the
identity signing key change immediately at the switch; the disclosure names the profile being LEFT
as well as the one arrived at. The receive address does NOT move at switch time — `dig-account` fixes
the wallet index at open time and exposes no `wallet_ops_at` (dig_ecosystem#2496), so after a switch
the wallet can only answer for the profile just left; DIG MUST show no address in the meantime rather
than the previous profile's. The standing statement is drawn where the choice is made; the
confirmation repeats it with both profiles named, and refusal is the default answer.

**The active profile MUST NOT be offered a hide control**, because `dig-account` refuses to hide it
(`ActiveProfileCannotBeHidden`), and `set_active` on a hidden profile un-hides it. Together these
make "a hidden active profile shows an empty list while the wallet derives there" unrepresentable
rather than merely guarded against; the surface states why the control is absent and names the way
round it.

**A LOCKED account MUST still list its profiles.** The registry holds no key material — which is why
it is stored in plaintext — so reporting `Pending` while sealed would leave the list saying "still
reading" for as long as the account stayed locked.

**Persistence.** The registry is stored at `<brand_dir>/profiles/registry.json` in PLAINTEXT, written
through the crash-safe temp-write→fsync→rename idiom. It holds no secret, and sealing it would make
an account's profile list unreadable while LOCKED — defeating the property the registry exists for.

HD derivation is **active and dynamic**: the unhardened wallet path, the hardened identity path,
`ProfileIx`, and the per-profile signer / DEK / sealing-key plumbing MUST keep deriving correctly and
DISTINCTLY at every index.

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
lock (idle timeout / lock-now) drops the residency (`lock_all`), which relocks BOTH
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
3. **Fund** — show the account's OWN derived receiving address, THREE ways: as the window's one mono
   identifier, as a scannable code where the confirmer draws one (`NativeConfirmer::draws_qr`), and on
   the clipboard via a control on the same screen. A code alone is NOT sufficient: the person most
   likely to be funding is doing so from a wallet on the SAME computer and cannot scan their own
   screen. The code MUST be drawn black-on-white in either theme (§3.1d) and MUST NOT be offered on a
   host that will not draw it, since the copy would then point at a picture that is not there. Funding
   is SHOWN, not awaited: the flow is a chain of OS-owned modal windows (§3.1d) and a modal cannot poll
   a chain, so an implementation MUST NOT present a "waiting for funds" screen it cannot be waiting on.
4. **DID** — offer the mint, naming what it costs, with the refusal PRE-SELECTED (affirming spends real
   XCH). The offer IS the approval: affirming it pushes the spend with nothing further shown, so the
   offer and every screen before it MUST NOT promise a later cost screen or a second approval. On a
   build that cannot mint (§3.1b), name the on-chain DID as the remaining REQUIRED step and state
   plainly that minting is not available in this version; it MUST NOT present a control that appears to
   mint.
   - **One paid mint per minter (MUST).** A `DidMinter` that has already pushed MUST refuse a second
     `submit` rather than paying a second fee: the second push would also overwrite the pending mint,
     making the FIRST unobservable — money spent and no DID ever recorded.
   - **An observer answers only about the spend it is asked about (MUST).** `look(spend_id)` MUST
     report `Unreachable` unless `spend_id` names the mint that observer itself pushed.
5. **Wait** — where a mint WAS submitted, watch the chain (`account::mint::await_confirmation`). The
   wait MUST report what is being waited for and HOW LONG it has been waiting, and MUST offer a way to
   stop that does not cancel the spend. It MUST end in one of four distinct, honest outcomes —
   confirmed, rejected by the chain, still pending, or the chain unreachable — and MUST NOT present an
   indefinite indicator that can neither fail nor time out.

Both routes end on the SAME fund + DID steps (`finish_the_identity`) so they cannot drift. Every step
MUST be escapable without half-creating an account. Reading content is NOT gated on any of
this: `Open URL…` stays enabled in every account state (§6.0 — consumption is never gated on custody).

**What gates the wizard (normative).** It runs when the account has NO DID — not when it has no
account (`account::journey::wizard_needed`). A wallet enrolled by an earlier version therefore still
reaches the fund and DID steps, entering at step 3. A DID is read ONLY from a
`account::did::DidRecord`, which cannot exist without a `MintEvidence` carrying a confirmation height,
so no key, address or locally-written DID-shaped string can satisfy the gate (§3.1b).

**What the absence of a DID gates (normative).** It gates the surfaces that BEAR the user's identity —
publishing, signing for an app, messaging (`account::did::Capability`) — and NOTHING else. Reading
content and holding funds MUST remain available with no account and no DID, so the wizard MUST NOT be
made an unconditional wall: a user who declines it keeps a usable app.

**Success requires evidence (normative).** A submitted spend is NOT a minted DID. An implementation
MUST NOT record a DID, report an identity as ready, or show a success screen from a submission — only
from a chain sighting that confirms it, and the evidence from that sighting is what is recorded.

#### 3.2-n The zero-profile funding watch (normative, dig_ecosystem#2950)

An account holding no profiles is prompted, automatically, to fund its wallet for its first one.

**When it is raised (MUST).** Only when the profile registry ANSWERED and holds nothing, a whole
profile can really be minted here (`profiles::ProfileCreation::is_possible`, derived from a live node
probe — an unmeasured node withholds exactly as a measured blocker does), and the prompt is not
deferred. Raising it writes the next-prompt time, so every way out of the window — the decline
control, Escape, the frame close, a crash — yields the same cadence: **once per `REMINDER_INTERVAL`
(24 h), persisted, until a profile exists.**

**It is a watch (MUST).** While open, the window re-reads the balance each time its confirm deadline
elapses and redraws with the CURRENT shortfall. A deadline expiry MUST continue the watch; only an
explicit refusal (or a host with no confirmer) ends it.

**An unmeasured balance MUST NOT draw a deposit window.** A shortfall is a subtraction, and
`MintFunds::Unmeasured` carries no figure to subtract from. An unmeasured reading MUST force one
interval-bypassing read (`wallet::node::NodeBalance::read_now`) before anything is drawn; only a
balance still unmeasured after that may draw a window, and that window MUST state the reading's own
reason and MUST NOT state a shortfall or a zero.

**The deposit watch MUST be bounded in total, not only when unattended.** Re-drawing the window holds
the shell's single action slot, so the watch MUST end after a bounded number of drawings
(`DEPOSIT_DRAWINGS_MAX`) however they were answered, in addition to the tighter bound on CONSECUTIVE
self-dismissals (`DEPOSIT_SELF_DISMISSALS_WATCHED`). A press of "Recheck balance" MUST reset the
consecutive bound — it exists to end an unattended watch — and MUST NOT reset the total, which is what
bounds a watch somebody keeps answering.

**The deposit window states three figures, in XCH (MUST).** What a profile costs, what the wallet
holds, and what is still needed — so nobody has to divide by 10^12 or subtract to know how much to
send. All three MUST be rendered by the crate's single mojos-to-XCH conversion, exactly (never
rounded, and never rounded up): 20,002 mojos is `0.000000020002 XCH`, and a nonzero requirement MUST
NOT render as `0 XCH`. The balance figure MUST come from the `FundingStep::Deposit` the decision was
made from, so only a MEASURED balance can ever be stated; the unmeasured window states no balance at
all, not even zero.

**Every other money figure in the same flow MUST use that same conversion and unit.** The recheck
answer's shortfall, the unknown-balance window's cost and the wallet-can-pay window's cost MUST be
stated in XCH, never in mojos: they describe the same quantities as the deposit window, and a flow
that answers in a second unit contradicts itself about a price.

**Sufficiency is hysteretic (MUST).** Once a balance has been seen to cover the cost, the flow MUST
NOT return to a deposit window (`FundingLatch`) — the ceremony re-checks and refuses honestly, whereas
the opposite error asks a funded person to send money twice. The threshold is `>= cost`.

**The recheck control MUST answer (MUST).** It is rate-limited to `RECHECK_THROTTLE` (5 s), and each
of its four outcomes — throttled, still short, could not measure, can pay — MUST produce a visible
answer naming the moment of the read. Silence is prohibited.

**Nothing on this path spends (MUST).** The prompt states a cost and shows a receiving address. This
version has no creation ceremony behind it: on a sufficient balance the flow MUST say the wallet can
pay, repeat the cost, and state that nothing was spent — and MUST NOT report a creation, or borrow the
DID-only first-run wizard, which would mint a DID without its store (§3.1d).

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
gate before any signature is produced, and the gate is `dig-account`'s concrete `PolicyAuthorizer` —
NOT an interface the host supplies. dig-app MUST NOT define its own authorizer; the crate's
`SpendApproval` constructor is `pub(crate)`, so that gate is mechanically the only thing that can
permit a spend. The order is fixed: (1) **rule** — `PolicyAuthorizer::authorize_op` re-parses and
summarizes the coin spends ITSELF (the caller supplies bytes, never a description), classifies them
into a `SpendTier` (`AutoSend` | `Confirm` | `Vault`) under the profile's `CustodyPolicy`, and returns
a `SpendRuling`. A structural refusal — a vault outflow to anyone but the profile's own hot wallet, a
value no configured limit can bound — is terminal and no ceremony may overturn it. (2) **confirm
ceremony** — `SpendRuling::RequiresConfirmation` carries a `PendingApproval`, and
`PendingApproval::confirm_with` is the ONLY route from it to a signable approval; it runs
`AuthProvider::confirm_spend` and a decline is terminal. Every tier above `AutoSend`, and every spend
whose intent is `SpendOpClass::Undeclared`, reaches this ceremony. (3) **sign** —
`MoneySigner::sign_approved` takes the `SpendApproval` BY VALUE. The approval owns the exact coin
spends the gate judged and the summary the user was shown, so what is displayed and what is signed are
two borrows of one value; the approval is neither `Clone` nor `Copy`, so re-use is a compile error
rather than a runtime replay check.

The custody policy MUST be fixed when the gate is constructed, from the host's persisted user
configuration — never accepted alongside a spend, or a caller could raise its own limit on the way
through. The host MUST hold exactly ONE `PolicyAuthorizer` per profile for the unlock's lifetime: the
rolling period cap's ledger lives inside it, so a gate built per request would start each call with an
empty ledger and silently turn a period cap into N per-transaction limits.

**The prompt budget.** The gate raises at most `AutoSendPolicy::max_confirmations_per_period`
confirmation ceremonies within any `period_seconds` window; past that, a spend that would have
escalated is refused as indeterminate rather than prompted. The bound exists because every spend the
policy will not auto-approve escalates to a person, and an out-of-process request is always
`Undeclared` and therefore always escalates — so an unbounded prompt rate is an attack on the user's
attention rather than on the policy. The bound is on the COUNT of prompts, never on whether a prompt
may be shown: its default MUST be non-zero, since zero would make a confirmable spend unspendable.

`dig-account` has no notion of a request's ORIGIN, so it bounds only the TOTAL. Its `SPEC.md` §6.4
places the other half on the host: **a host that serves multiple origins MUST additionally bound
prompts per origin.** dig-app serves exactly one origin today — every caller of the money path is
in-process — so the crate's total bound is sufficient. dig-app MUST take on the per-origin bound
before any surface that can be reached from outside the process (the loopback dapp seam) is allowed to
reach `authorize_and_sign`; otherwise one origin can exhaust the whole budget and deny every other.

A caller declares a spend's intent as a `SpendOpClass`. Only an in-process caller that BUILT the spend
may declare one truthfully; anything arriving from outside the process (a dapp, an IPC peer) MUST pass
`Undeclared`, which can never auto-approve and is routed to the human instead.

The signer is drawn from the shared, lockable account residency and built AFTER the ceremony, so a lock
(lock-now / idle timeout) that lands while the confirm window is open fails the sign
closed. The residency is the SAME lockable seed home the identity signer reads — a locked account
refuses to sign money AND identity.

A lock MUST **revoke**, not merely stop re-issuing. A money signer obtained while unlocked holds its
own reference to the live seed, so dropping the unlocked account leaves those bytes resident and that
signer able to produce real signatures while the host reports itself locked. Locking therefore calls
`UnlockedAccount::lock`, which revokes the unlock's shared liveness token; every capability derived
from that unlock observes the revocation before acting and refuses afterwards. The property is
strictly stronger than "a locked account issues no new signer", and it is the one that binds a
capability already handed out.

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

**In-flight coin reservation.** Every coin selection in this process — an XCH transfer, a CAT
transfer, a DID mint and a profile mint — MUST be measured against ONE reservation set, obtained from
`wallet::reservations::shared()`. Selection and reservation are one step: a coin selected for a
built-but-unconfirmed spend is held, so a second build in the same window cannot choose it. While a
bundle sits in a mempool the chain still reports its inputs unspent, which is the window this closes.

A reservation is BOOKKEEPING. It carries no key, authorizes nothing, and never reduces a reported
BALANCE — a held coin is still the user's money. A build blocked by reservations MUST report that the
coins are busy, and MUST NOT report insufficient funds: the two send a person to opposite places.

**dig-node owns the reservation truth.** When a node table is installed
(`wallet::reservations::install`), every conflict decision is the node's, so two processes serving one
wallet cannot select the same coin. Until one is installed the scope is this process only — the
`dig-account` default — and no surface may claim otherwise (`wallet::reservations::is_cross_process`).

**The fail direction is REFUSE.** An unreachable, slow or unparseable node MUST surface as
`ReservationError::Unavailable` and refuse the build. It MUST NOT surface as an empty held set,
which is indistinguishable at the call site from a healthy wallet and silently restores the
double-select, and it MUST NOT surface as a conflict, which is a claim about a specific coin.

**A node error is classified by its stable SYMBOL, never by its numeric code or band.** The numbers
are not stable across contract versions and the `-3204x` band carries no single disposition:
`WALLET_COINS_RESERVED` is a WAIT, `WALLET_RESERVATIONS_UNAVAILABLE` is an UNKNOWN, and
`WALLET_NODE_SPEND_DISABLED` is TERMINAL — and the first and last were both spelled `-32044` in
successive versions of the contract. A client keyed off the number would retry forever against a
refusal no retry can fix.

**A node that serves no reservation table narrows the scope; it does not refuse.**
`METHOD_NOT_FOUND` / `NOT_SUPPORTED` is a CAPABILITY answer, not an outage: no retry conjures a
method that does not exist, so refusing would leave every send on every pre-contract node
permanently unable to build. The store falls back to the process-local table — exactly
`dig-account`'s own default scope — latches that decision for the session, and reports it through
`is_degraded()`. An OUTAGE MUST NOT degrade the scope, or one dropped connection would silently
drop the cross-process guarantee.

**The refusal a node actually sends carries no `data` field, and MUST still classify.** A node
answers an unresolved method with a bare `{"code":-32601,"message":"…"}`; the contract's
`ControlError.data` is required, so a strict decode rejects that response as malformed and it
arrives as a TRANSPORT failure. A client that classifies only well-formed refusals therefore never
reaches the capability answer at all, and the fallback above — though implemented — never fires,
leaving every send permanently refused. The decode MUST tolerate an absent `data` and recover the
symbol from the numeric code.

**A handle MUST resolve only against the table that issued it, and handle numbers MUST be unique
across both.** A client that keeps two reservation tables — the node-backed one and the
process-local fallback — MUST NOT let either mint the handles it hands out independently: two
tables numbering from zero produce the same handle value twice, and a release then frees a
reservation its caller does not own, which re-opens the double-select. Every issued handle MUST
come from a single allocator, and the client MUST record which table issued each one. Routing a
release by the client's CURRENT mode is insufficient: a handle issued while the node served the
methods is still outstanding after the fallback, and must still resolve as the node's.

**A `reserve` whose reply is lost MUST be recovered, not left to the TTL.** The call is a
non-idempotent POST under a timeout: the node can take the coins and the reply can still be lost,
leaving a hold the client has no handle for and stranding a coin on every attempt. After a reserve
that failed WITHOUT an answer, the client MUST read the held set, group its rows by
`reservation_id`, and release each hold whose coin set EQUALS the set it requested — which is why
`reservations.held` reports a `reservation_id` per row and why a client MUST NOT discard it.

**Recovery MUST be by whole hold and by exact set, never per coin.** `reserve` is all-or-none over
exactly the requested coins, so a hold the client lost covers exactly what it asked for; any other
hold belongs to somebody else. A client that releases a hold merely because it shares a coin with
the request will, on a lost CONFLICT, free the very hold it conflicted with, and one shared coin
will free a foreign multi-coin hold entirely. The residual — a foreign hold over exactly the
requested set, taken inside the recovery window — is accepted, since the alternative strands the
user's own coin on every attempt.

**The lifetime that governs is the one the node APPLIED.** The node clamps the requested TTL and
returns what it granted; the client MUST record that and MUST NOT keep its own number, or it will
believe coins are held after they have become selectable again.

**Release is owed on every outcome.** A reservation is released when its spend is known settled or
known dead; `dig-account`'s guard releases on every abandoned path. A release that does not reach the
node MUST be retried rather than forgotten — an unreleased reservation is a wallet locked out of its
own funds. The 300 s TTL is the backstop for a lost process and MUST NOT be shortened to compensate
for a lost release, which would trade a visible lockout for an invisible double-select.

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

- `control.wallet.broadcast` — `{ signed_bundle_hex }` → `{ accepted, transaction_id?, rejection? }`.
  The engine forwards the signed bundle to the network and reports mempool acceptance; it sees only
  signed bytes. A mempool that LOOKED at the bundle and refused it is a successful call carrying
  `accepted: false` and a `rejection` reason — failing to REACH a mempool is an error instead, because
  the remedies are opposite. The method is TOKEN-GATED, so an authorization refusal on it means the
  control token is missing and MUST NOT be reported as an out-of-date node (which is what the same
  refusal means on the two open reads).
- `control.wallet.coins` — `{ address, asset }` → `{ coins: [{ coin_id, asset, amount }] }`. The
  address's spendable coins for the asset. The node's reply is a strict SUPERSET (it also carries the
  parent, the puzzle hash and the created/spent heights) and dig-app keeps the three fields above. An
  EMPTY list is an ANSWER — the address holds nothing — and every failure to consult a chain MUST be an
  error instead; returning an empty list for an unreachable chain would tell somebody who holds funds
  that they hold none. Served as an OPEN read.
- `control.wallet.balance` — `{ address, asset }` → `{ balance, as_of }`. The address's spendable
  balance in the asset's base unit, with the provenance that figure is true AS OF. The node's reply is
  a strict SUPERSET of that shape; dig-app reads `balance`, `source` and `peak_height`.
  - dig-app MUST NOT refuse a figure for carrying `synced: false`. A light client trails the chain tip
    permanently, so that rule withholds the balance essentially always. A behind figure MUST instead be
    shown together with what it is true as of.
  - `source: "db"` with a `peak_height` MUST be reported as the node's own replica AS OF that height.
  - `source: "db"` with NO `peak_height` MUST be an UNKNOWN, never a figure: that replica has synced
    nothing, so its `balance: 0` is no data rather than no money.
  - `source: "fallback"` MUST be shown as a third party's number and MUST NOT be given an as-of height,
    which such an answer does not carry.
  - `source: "db"` with `synced: false` and `balance: 0` MUST be an UNKNOWN, whether or not a
    `peak_height` is present. A replica that has not finished its first sync cannot distinguish "this
    address holds nothing" from "I have not read this address yet", and a dated zero states the first
    with a precision that reads as corroboration. A `synced: true` zero IS a fact and MUST render as
    `0`.
  - An ABSENT `source` MUST be reported as an undisclosed provenance and MUST NOT be assumed to be a
    tier.

**Saying that a node is still syncing (MUST).** Every surface that shows a balance MUST show, BESIDE
the figure, whether the node is still catching up — the tray row, the Wallet pane and the window
sentence alike. A reading is treated as LEVEL with the chain when the node reported `synced: true`, or
when its `peak_height` has reached the peak the node's peers announced; where neither is known it MUST
NOT be presented as current. A level reading MUST carry NO syncing indicator: an indicator that never
comes off is one a person learns to ignore. A `fallback` reading MUST carry the indicator — the oracle
answered because the replica has not reached the address yet — while its FIGURE MUST NOT be described
as out of date, the oracle being at the chain tip.

**Reading the balance for real (MUST).** dig-app MUST obtain the balance by ASKING a node, never by
asserting an outcome it did not test:

- The reading MUST come from a `control.wallet.balance` call against the endpoint the §5.3 ladder
  resolved. The method is served as an OPEN read, so the call MUST be made whether or not a control
  token is readable on this machine.
- The reason an unknown carries MUST be derived from the node's own reply, keyed on the stable
  `data.code` symbol and never on the human message: `METHOD_NOT_FOUND` / `NOT_SUPPORTED` /
  `UNAUTHORIZED` mean this build does not serve the read; `WALLET_NOT_SYNCED` means it is catching up;
  `WALLET_NO_CHAIN_SOURCE` means it serves the read but has no chain to read from. Those three MUST NOT
  be collapsed into one another — they call for an upgrade, a wait, and a node connection respectively.
- **`WALLET_NOT_SYNCED` MUST be narrowed before it is spoken (MUST).** The symbol covers at least three
  situations whose remedies differ, and dig-app MUST tell them apart from the node's own sync payload —
  `peak_height` against `chia_peer_peak_height`, and the MEASURED `watched_addresses` — together with
  whether this app's keys are enrolled (below):
  - the replica trails the peak its Chia peers announced → it is genuinely catching up, and waiting is
    the remedy;
  - `watched_addresses` is a measured `0` → the node follows none of this account's addresses, so it
    holds no record of this account's coins and the remedy is ENROLMENT, not waiting. This reading is
    answered from the watched count BEFORE either height is consulted, so the sentence shown for it
    MUST NOT assert that the node is caught up (nor that it is behind) — a first run that is genuinely
    still syncing with nothing enrolled reaches it too;
  - the same, with this app's keys already accepted by the node → the node begins following them at its
    next start, and there is nothing to do.
  An UNRESOLVED `watched_addresses` (`null`, not a measured zero) licenses none of these narrower
  claims and MUST fall back to the unnarrowed reason. A balance the node SERVED — including a zero —
  MUST NOT be re-explained by any of them: a measured zero is a fact.

**Enrolling the account's addresses (MUST).** A node follows only the keys it has been asked to follow,
so dig-app MUST register its account's WALLET public keys with the node over `control.wallet.watch`:

- The key registered MUST be the **synthetic** wallet public key — the same key whose
  `StandardArgs::curry_tree_hash` is the address dig-app displays. dig-node curries an enrolled key
  DIRECTLY, so any other key of the account makes it follow an address the user does not hold, with no
  error reported anywhere.
- The wire form is lowercase 96-hex, unprefixed.
- Enrolment MUST be a RECONCILIATION against `control.wallet.watched`, not a fire-and-forget: the app
  MUST NOT assume a node remembers, and MUST re-assert against a node that was restarted or replaced.
  Both methods are TOKEN-GATED — they answer with, or mutate, the node's own key set.
- Registration MUST NOT block the surface that drives it, and MUST NOT be reported as enrolment until
  the node has answered.
- **A FAILED exchange MUST be retried after a bounded interval (MUST).** The expected failure is a node
  that was slow at startup, and an implementation that remembers a failure for the life of the process
  leaves the account unenrolled for the whole session while the surface tells its owner that DIG
  registers addresses while unlocked. The memo MUST expire rather than be cleared: clearing it makes
  the repaint rate the retry rate. A SUCCESS is not re-asked on a timer — only a change of endpoint or
  of key set invalidates it.
- No secret material crosses this boundary: a public key confers watching, never spending (§908).
- The read MUST be throttled independently of the repaint rate, because the tray snapshot is taken on
  every repaint and a balance is a rate-limited chain read.
- **The read's timeout MUST be sized for a chain round-trip and MUST NOT be the §5.3 ladder's probe
  budget.** Those budgets answer different questions: a probe budget bounds how long one tier may take to
  prove it is alive before the ladder falls through, while a balance may be served from a public chain
  source and has been measured at 2.5–6 s against a healthy node. An implementation that reuses the probe
  budget fails every read on such a machine.
- **The read MUST NOT block the surface that asks for it.** A repaint-driven caller MUST receive an
  answer immediately — the PENDING state, or the reading already held for that address — while at most
  ONE read per address is in flight.
- **A read that overran its budget MUST NOT be reported as an absent node.** The connection succeeded, so
  the only supportable statement is that this call did not finish; a timeout, a node still syncing, and a
  ladder that reached nothing are three distinct states with three distinct sentences. Where nothing was
  reached at all, the surface MUST describe the app's failure to REACH a node rather than assert that
  none is running.
- dig-app MUST NOT enable, or require the user to enable, any node-side flag that arms spending in order
  to obtain a read-only balance.

**Rendering an amount MUST be asset-aware (MUST).** Every balance on the wire is an integer in the
asset's OWN base unit, and assets do not agree on scale: native XCH carries **12** decimal places
(mojos), while $DIG is a CAT and carries **3** — `1 $DIG = 1000 base units`. A surface MUST divide by
`10^decimals` **of the asset the figure belongs to**, and MUST obtain that figure from the asset
rather than from a per-surface constant. A single asset-agnostic divisor renders one of the two assets
wrong by a factor of 10^9 — silently, and with the full confidence of a plain numeral — which is the
defect [dig_ecosystem#2295] fixed after it shipped in v5.31.0. dig-app satisfies this with ONE
formatter (`dig_app_core::amount`) that every money surface calls; a second implementation of this
arithmetic is a defect regardless of whether it is currently correct.

**An UNKNOWN precision MUST NOT be rendered as a whole-coin figure (MUST).** dig-app knows the decimal
places of exactly two assets — native XCH and $DIG — and knows nothing about a CAT it has only been
told the asset id of. Three decimal places is the Chia CAT *convention*, not a rule, so applying it to
an unnamed token is a GUESS used as a divisor. `dig_app_core::amount::decimals` therefore answers
`Option<u32>` and a surface holding `None` MUST render the raw base-unit integer **together with the
words stating that is what it is** (`1500 base units of a628c1…832913`), never a bare numeral. A typed
amount for such a token is read as whole base units for the same reason, and a typed decimal point is
REFUSED rather than scaled by an assumed power of ten.

**The `asset` wire form (MUST).** `asset` is `"xch"`, `"dig"`, or `{"cat":"<64-hex asset id>"}`.
dig-app's `Asset` is `dig-node-control-interface`'s own type, RE-EXPORTED rather than restated, so the
byte-identical contract with the node is a compile-time fact rather than two implementations that
agree today. The type has exactly **two cases** — `Xch` and `Cat(AssetId)` — and $DIG is the associated
constant `Asset::DIG`, never a third case: a `Dig` variant beside `Cat(DIG_ASSET_ID)` would give $DIG
two INEQUAL spellings, and every balance, coin and history filter is an `asset == asset` comparison, so
a wallet holding coins under both spellings would sum one and report it as the whole balance. Both bare
tokens MUST still be ACCEPTED and `"dig"` MUST still be EMITTED for $DIG, so that a node or a sealed
`wallet-state.seal` written before the widening keeps working in both directions; `{"cat":"<the $DIG
asset id>"}` MUST normalize to the same value as `"dig"`.

**Which assets are read (MUST).** `control.wallet.balance` and `control.wallet.coins` are each scoped
to ONE named asset and there is NO method that enumerates what an address holds, so dig-app can read
the balance of any CAT it can NAME and cannot discover one it has never heard of. XCH and $DIG are read
unconditionally; every other token is read because the user added it to `WalletState::watched`. A token
nobody added is ABSENT from the wallet surface and MUST NOT be rendered as a zero holding.

dig-app depends only on the `WalletEngine` trait seam, so it compiles + tests standalone; the real
IPC-session transport (the §5.3 `SessionClient`) drops in as the production implementation without
touching the wallet logic.

[dig_ecosystem#910]: https://github.com/DIG-Network/dig_ecosystem/issues/910
[dig_ecosystem#2295]: https://github.com/DIG-Network/dig_ecosystem/issues/2295

#### 3.3a Sending money (normative)

A send travels in exactly this order, and `dig_app_core::wallet::send` is the only implementation of
it: **build** the unsigned spends (`dig_account::WalletOps::build_transfer`, reached through
`AccountResidency::build_transfer` so a locked account builds nothing) → **sign** through the custody
gate (`account::money::MoneyPath::authorize_and_sign`, op class `SmallSend`) → **anchor** by reading
the chain peak (`TransferPlan::pushed_now`) → **push** the SIGNED bundle
(`chain::ControlSpendPublisher`).

- The anchoring peak MUST be read AFTER the signature and immediately BEFORE the push. Read earlier it
  is stale by however long the human took; read later it is worthless. It is the only height a
  back-dated confirmation can contradict.
- A peak that cannot be read MUST refuse the push. Anchoring at `0` is FORBIDDEN — every height is at
  or above genesis, so a zero anchor makes the back-dating check vacuous.
- A send MUST report success only from a `TransferStatus::Confirmed`, which `dig-account` constructs
  solely from a buried chain record. An accepted push is an acceptance, not a payment, and dig-app MUST
  NOT define any value of its own meaning "sent" or "succeeded".
- A failed push MUST be classified by whether the bundle could be in a mempool
  (`chain::PublishFailure::may_have_reached_a_mempool`), and the two classes MUST NOT be merged. A push
  refused locally, or ANSWERED by the node declining to serve or to authorize it, provably never left:
  it is a plain failure, and the send surface MUST come back. A push that went unanswered or timed out
  has an UNKNOWN outcome: the caller MUST poll the pending transfer, and rebuilding it can pay the
  recipient twice. Where it is not knowable which class a failure belongs to, it MUST be treated as
  UNKNOWN — an over-cautious wait costs time, an over-confident failure can cost the money twice.
- A transfer whose push no mempool ACCEPTED MUST NOT be promoted out of the unknown state by polling.
  `TransferStatus::Awaiting` is the identical answer a never-broadcast bundle produces, so it
  establishes nothing about an unjudged transfer; only `Confirmed` and `Failed` are chain verdicts.
- A pending transfer is remembered **for the lifetime of the process and no longer**. It lives in
  `wallet::sending::SendHolder`'s memory and is not persisted, so a restart forgets it. The payment
  coin id is what makes the transfer watchable afterwards, by this app or by anyone with a block
  explorer, and the surface MUST say so wherever it asks the user to keep waiting (§3.3b).
- At most one send per profile may be in flight, enforced by `SendHolder::begin`: claiming the send slot
  and moving to `Signing` happen under ONE lock, and a send MUST be refused outright while the slot is
  held. It is NOT structural — `SendSession::send` consuming its session constrains only that value, and
  the production path builds a fresh session per attempt. It MUST NOT be delegated to the pane, the
  published view, or the tray's action worker: no view is published while the ceremony holds the
  session, so the drawn form is stale for the whole of it.
- A send that fails part-way, including by PANIC, MUST release the send slot. A claimed slot that is
  never released leaves the surface permanently unable to send for a payment that does not exist.
- The custody gate MUST be held for the lifetime of an unlock, not built per send. The rolling window
  behind `AutoSendPolicy::max_confirmations_per_period` lives inside the `PolicyAuthorizer` the
  `MoneyPath` holds, so a gate built per request starts each one with an empty ledger and its ceiling
  can never be reached. The gate MUST be rebuilt when the receive address it rules against changes,
  since that address is what the vault outflow rule compares a payee to.
- There is NO retry or fee bump. A future one MUST use `WalletOps::build_transfer_replacing`, which
  reuses the original inputs; a rebuilt transfer at a higher fee can select a different input set, and
  two bundles spending disjoint inputs can both confirm.
- The fee is a FIXED constant (`wallet::send::DEFAULT_SEND_FEE_MOJOS`) displayed to the user, never an
  estimate. What the confirm ceremony shows is exactly what is paid.
- Every send reaches the human. The production custody policy is `Hot { auto_send_limit: 0 }` with the
  default deny-everything `AutoSendPolicy`; raising the allowance above zero is what would let a
  payment leave with no confirmation.

##### Sending `$DIG` (a CAT)

A `$DIG` send travels the SAME order — build, sign, push — through
`dig_account::WalletOps::build_dig_transfer` (reached through `AccountResidency::build_dig_transfer`)
and `SendSession::send_dig`. It differs in exactly three respects, and each difference is normative.

- The builder MUST be `dig-account`'s. Constructing a CAT spend in dig-app is FORBIDDEN, as is
  addressing a payment to a curried CAT puzzle hash: a `$DIG` payment is addressed to the recipient's
  ordinary `xch` destination and the builder is what wraps it.
- The fee MUST be denominated and displayed in XCH. Chia charges fees in native mojos and a CAT cannot
  pay its own, so a wallet holding `$DIG` and no XCH cannot send at a non-zero fee. That state MUST be
  reported as a missing FEE coin and MUST NOT be reported as a `$DIG` shortfall — the two send a person
  to opposite remedies.
- There is **no anchoring peak read and no confirmation**. `dig-account` 0.16 ships a `$DIG` transfer
  builder and no watcher: there is no `PendingCatTransfer`, no `cat_transfer_status`, and no buried
  chain record a `ConfirmedCatTransfer` could be constructed from. Therefore:
  - dig-app MUST NOT report a `$DIG` payment as confirmed, settled or arrived, by any route. The
    accepted push yields `SendProgress::Broadcast`, which states the acceptance and the limitation and
    claims nothing further.
  - The reference carried MUST be the accepted BUNDLE id and MUST be labelled as such. A `$DIG` payment
    coin id is not computable without spend introspection, and a bundle id under a "payment coin" label
    would present a submission's name as evidence about money.
  - `Broadcast` MUST NOT be in flight. The only escape from an in-flight state requires acknowledging a
    payment coin id, which a `$DIG` send does not have, so an in-flight `Broadcast` would close the send
    form for the life of the process with no escape.
  - An UNANSWERED `$DIG` push (`SendError::PushUnwatchable`) MUST NOT be reported as a failure. It MUST
    reach `Abandoned`, which reopens the form behind a warning to check before sending again, and it
    MUST NOT be reported as `Unknown`, which offers a coin id to watch that does not exist.

#### 3.3a2 Taking a Chia offer (normative)

The Wallet tab reads and takes Chia offers. `dig-offers` is the ONLY offer authority: dig-app MUST
NOT decode, summarize, assemble or combine offer bytes itself.

- **What is shown MUST derive from the parser, on the bytes that would be broadcast.** A
  `wallet::offer::ReviewedOffer` owns an `offer1…` string and the `dig_offers::summarize` of that same
  string; `ReviewedOffer::read` MUST be its only constructor. The take path MUST be handed that value
  — never a separately-carried offer string — so the terms displayed and the swap settled cannot
  diverge.
- **Both sides MUST be named (NC-14).** The surface states what arrives and what leaves as two
  labelled lists, in the taker's direction: `summarize().offered` is what the taker RECEIVES and
  `.requested` is what the taker PAYS. A single net figure MUST NOT be shown — a take changes
  ownership, and a difference describes the act while hiding half of it.
  - The custody ceremony's re-derived summary can only show the PAID side: the received leg returns to
    the taker's own change address and is dropped as change, and the settlement commitment nets out
    within the bundle. The confirm prompt MUST therefore ALSO carry a **trade narrative** — see
    §3.3a4 — so both sides are named where consent is actually given, not only on the card.
- **The order MUST be: refuse, build, sign, combine, push.** `wallet::offer::take_permitted_by` refuses
  a `CustodyPolicy::Vault` profile BEFORE a spend is built, because dig-account denies a vault outflow
  to the settlement puzzle by name; the refusal MUST reach the control as a stated reason, never a
  bare disabled control and never a failure at signing time. Then `dig_offers::take_build`,
  `MoneyPath::authorize_and_sign`, `dig_offers::take_combine`, and the node's push.
- **Every take is authorized as `SpendOpClass::Undeclared`**, which can never auto-approve, so a take
  always reaches the human. A swap is irreversible and moves assets no mojo allowance can weigh, so
  there is no configured bound under which approving one unattended would be honest.
- **One take at a time**, refused structurally. A second take of the same offer while the first is
  settling can only fail, after a person has confirmed it.
- **A broadcast MUST NOT be reported as a settled swap.** `TakeProgress::Broadcast` states that a node
  accepted the bundle and names it; whether the swap settled is a chain read, and the centralized
  progress modal — raised by ANY broadcast, with no caller opt-in — is what follows it.
- **A funding read that FAILED MUST NOT be read as an empty wallet** (`TakeError::FundsUnreadable`).
  An unanswered read has made no claim about the money.
- XCH-funded takes only: a CAT-funded take needs each coin's lineage proof, which the coins read does
  not carry.

#### 3.3a2b Loading an offer from a dropped file (normative)

An offer may be LOADED by dragging its file onto the Offers card, as an alternative to pasting.

- **A drop MUST load, and MUST NOT take.** The only effect of letting a file go over the card is that
  its contents reach the offer field. Every subsequent step — the summary, the both-sides reading, the
  confirm gate, the push — is the paste path unchanged, and taking still requires the take control to
  be pressed. No drop may reach a spend.
- **A dropped file's contents MUST be judged by the paste path's parser.** The drop path MUST NOT
  decide whether text is an offer; it produces text and hands it to `ReviewedOffer::read`, which is
  the only constructor (§3.3a2). The drop path therefore accepts NOTHING the paste path would refuse.
- **The drop path's own refusals MUST be narrower than paste, and MUST be stated.** It MAY refuse a
  directory, an unreadable file, a file that is not valid UTF-8, an empty one, and one larger than
  1 MiB — each answered in words naming the FILE and the fault. A drop that is silently ignored MUST
  NOT occur: it is indistinguishable from an application that did not notice the gesture.
- **Several files at once MUST be refused rather than resolved.** Reading the first would choose which
  trade a person is about to be shown.
- **A drop MUST be claimed by the card the pointer is over.** The pane holds several cards, and a drop
  meant for another one MUST NOT be answered by this one.
- **The affordance MUST be stated and MUST show where a drop will land.** The field's help line names
  both routes; while a file is over the card, that line says what letting go will do and does not do,
  and the card is outlined.

#### 3.3a3 Making and cancelling a Chia offer (normative)

The Wallet tab also MAKES offers and CANCELS them. `dig-offers` remains the only offer authority:
dig-app MUST NOT hand-roll a spend bundle for either.

**Making.**

- **The order MUST be: refuse, build, sign, assemble.** `wallet::making::make_permitted_by` refuses a
  `CustodyPolicy::Vault` profile BEFORE a spend is built, with the SAME sentence the take path uses —
  it is one rule (a vault may pay only its own hot wallet) and two wordings would read as two limits.
  Then `dig_offers::make_build`, `MoneyPath::authorize_and_sign`, `dig_offers::make_assemble`.
- **`make_build` and `make_assemble` MUST run in ONE `SpendContext`.** A requested leg carries
  allocator-relative pointers that exist only in the context that created them.
- **A make MUST NOT broadcast, and MUST NOT be reported as a completed trade.** Nothing is sent: the
  signed maker half lives inside the offer string and reaches a mempool only when somebody takes it.
  So no progress modal is raised, `MakeProgress::Made` is worded as *ready to share*, and the surface
  MUST state that what the maker gives is committed NOW while what they asked for arrives only if
  somebody takes it.
- **The made `offer1…` string MUST be shown in full with a copy affordance.** An offer nobody can lift
  off the screen is an offer that was not made.
- **The offered side is XCH only**; the requested side MAY be XCH or a CAT. A CAT-offered coin needs a
  lineage proof the app's coin read does not carry, and an NFT leg needs the NFT parsed in the build
  context. The surface MUST state the limit rather than offer a control that fails at build time.
- **One make at a time**, refused structurally: two makes select the same funding coins.

**Cancelling.**

- **Cancelling is DESTRUCTIVE and MUST be NAMED as such (NC-14, dig_ecosystem#3079).** A cancellation
  re-spends the offer's still-unspent offered coins to the maker, which makes the outstanding
  `offer1…` string unfillable, permanently. A value delta is not consent: the reclaim pays the maker's
  own address, so every re-derived figure reads as a self-payment and the destroyed thing appears in
  no number at all. Both the card and the confirm prompt MUST state that the shared string stops
  working and that it cannot be undone.
- **A cancellation MUST NOT be reported as a cancelled offer.** It races any taker's settlement, so
  `CancelProgress::Broadcast` states only that a node accepted the reclaim, and the surface MUST say
  the race exists.
- **A vault profile MUST NOT be refused a cancellation.** The reclaim pays the maker's own hot wallet,
  which is precisely what the vault rule permits; refusing would strand the money.
- **The cancel control MAY be offered on any readable offer.** Whether an offer's coins are still this
  wallet's to reclaim is a chain question the card does not answer, and a silently withheld capability
  reads as a missing feature. The refusal, when it comes, MUST be `dig-offers`' own reason.
- **One cancellation at a time**, refused structurally.

#### 3.3a4 The trade narrative on the confirm prompt (normative, dig_ecosystem#3109)

A swap has two legs and dig-account's re-derived `SpendSummary` can only see one of them. Every offer
operation MUST therefore stage a `account::narrative::TradeNarrative` before asking for a signature.

- **The narrative MUST name BOTH sides and the ACT**, in the user's own units, and MUST state an
  empty side explicitly ("Nothing") rather than omitting the heading.
- **It MUST be printed BESIDE the re-derived figures, never instead of them.** The recipients and fee
  dig-account derived from the bytes being signed MUST still appear, under their own heading, so a
  narrative that ever disagreed with the bytes can be caught against them on the same screen.
- **It MUST be built from the value the surface displayed and the builder consumed** — the parsed
  `ReviewedOffer` or the checked `MakeDraft` — never from a second reading of the offer.
- **It MUST NOT outlive its operation.** `NarrativeSlot::set` returns a guard that clears the slot on
  drop, so a later, unrelated spend cannot inherit the last operation's story.
- **An ordinary send MUST carry no narrative.** Its recipients ARE the act, and an added
  "You receive: Nothing" would read as though something were missing from a complete payment.
- **A cancellation's narrative MUST read the offer in the MAKER's direction.** `OfferTerms` is the
  taker's view, so what the offer would have DELIVERED is what the maker reclaims. Reading it the
  other way would promise a person the side they were asking for — money they never had.

#### 3.3b The send surface (normative)

The Wallet tab offers the send, and `dig_app_core::wallet::sending` is the only place that decides
anything about it. The pane draws that module's answers and returns an intent
(`TrayAction::Send`, or `TrayAction::ReleaseUnknownSend` for the escape below); the shell forwards
the intent and performs the send.

- The ASSET is chosen on the form and MUST be carried as part of the validated intent
  (`sending::SendIntent`), never beside it. There MUST be no representation in which the amount and the
  builder disagree about which asset is moving.
- An amount MUST be read to the DECIMAL PLACES of the asset in force — twelve for XCH, three for `$DIG`
  — and every sentence about it MUST name that asset's ticker. A refusal quoting the wrong ticker sends
  a person to acquire the wrong token.
- An affordability check MUST weigh a payment against the holding it actually spends: `$DIG` against
  the `$DIG` balance and its fee against the XCH balance, as two separate comparisons. Summing them is
  FORBIDDEN — they are different units and the total means nothing.
- An activity row MUST be labelled with the asset that was sent (`sending::sent_record`). A fixed asset
  label is FORBIDDEN.

- A typed amount MUST be converted to base units by `amount::parse_asset_amount`, the exact inverse of
  `amount::format_asset_amount`. The conversion MUST be integer arithmetic on the digits: a binary
  float cannot represent XCH's twelve decimal places, and a rounding error here misstates money at the
  moment a person authorises it. An amount with more decimal places than the asset carries MUST be
  refused, never truncated.
- Every figure the send surface shows — the amount, the fee, and anything echoed back in the confirm
  ceremony — MUST be rendered through `crate::amount`. A base-unit integer beside a ticker is
  FORBIDDEN.
- A destination MUST reach a `TransferRequest` through `dig_account::PayableDestination::from_address`,
  which refuses any prefix but `xch`. Reconstructing one from a puzzle hash via `from_derived` on the
  send path is FORBIDDEN: it bypasses the check that stops a `txch` address burning the funds.
- **Send** MUST be refused, with the condition stated on screen, when the account is sealed, when a
  send is in flight, when either field is unusable, or when the amount plus the fee exceeds a MEASURED
  balance. A balance nobody has read MUST NOT refuse a send — that would invent the figure.
- The nine states of `SendProgress` — `Idle`, `Signing`, `Pending`, `Broadcast`, `Unknown`,
  `Confirmed`, `Failed`, `Abandoned` and `Released` — MUST each be rendered as themselves where they
  are reached. `Awaiting` MUST NOT be shown as success,
  and an unanswered push MUST be shown as an UNKNOWN outcome to keep watching — never as a failure,
  since rebuilding it can pay the recipient twice. (`Signing` is not currently reachable on screen: the
  action worker holds the session for the whole ceremony and the tray publishes no view while it does,
  so the window keeps drawing the state from before the send. In that window a second press is
  refused by `SendHolder::begin`'s compare-and-set and is dropped without feedback — nothing
  is built, signed or pushed, and the first send is undisturbed. The surface corrects itself
  when the tray republishes and the in-flight state becomes visible.)
- A send abandoned by a PANIC MUST be reported as `Abandoned` and MUST NOT claim that no money moved.
  A panic establishes only that this app stopped; it establishes nothing about whether the bundle left
  the machine. `Abandoned` MUST NOT be `Unknown` either: `Unknown` holds the form shut and offers a
  payment coin id to watch, and a panic produces no coin id, so the form MUST reopen and the sentence
  MUST send the person to check before sending again.
- A send whose fate is UNKNOWN MUST offer an escape, and the escape MUST be a claim the USER makes.
  Releasing the form MUST require the user to acknowledge the payment coin id exactly
  (`sending::ReleaseDraft::assess`; a prefix or a near-miss MUST be refused), and MUST produce
  `Released`, which asserts nothing about the money. The app MUST NOT decide on its own that an
  unjudged transfer is dead, and a transfer that resolved before the release is applied MUST keep its
  chain verdict.
- A `Confirmed` or `Failed` verdict MUST carry the source it was read from (`sending::VerdictSource`,
  from `ControlChainSource::last_freshness`) and the surface MUST show it, because the send path asks
  the same node it pushed to. A verdict decided locally before any chain read MUST stay `Local` and
  MUST NOT be re-attributed by a later poll.
- `Failed` MUST distinguish its two producers. Reached before any broadcast, the surface MAY state that
  no money has moved. Reached from a proof of death AFTER a push — a source coin observed spent while
  the payment coin is absent — it MUST NOT state that, and it MUST show the payment coin id.
- Wherever the surface asks the user to keep waiting rather than to send again, it MUST tell them to
  keep the payment coin id, because the app forgets the transfer when the process ends (§3.3a). Every
  state that HAS a payment coin id MUST display it.
- The state MUST live in `TrayView` and be compared by `TrayView::renders_same_as`; otherwise a send
  moves through every state behind a window that never repaints.

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

### 3.5 CLI / RPC gateway (`diga`)

`diga` is the **DIG user CLI, owned by dig-app** (migrated from dig-node). It is DISTINCT from
`dign`, which remains **dig-node's** CLI and is not shipped by this repo; the two names never collide
on a shared bin directory. A user runs `diga`; it talks to the running dig-app (their identity/session), which
authenticates the caller and either serves the request locally with the user keys (sign / profile /
wallet) or proxies engine work over the authenticated session. The user/identity/control subcommands
(info/config/cache/stores/sync/subscriptions/peers/pair/open + wallet/profiles/sign) live here.

**`diga account` is served in-process, NOT through the gateway (normative).** The `account status`
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

Machine-friendly (per the ecosystem agent-friendly baseline): `diga` MUST offer `--json` output
beside human output, a discovery surface (`--help`/`--help-json`), and deterministic catalogued error
codes.

`diga` is its OWN binary crate (a thin IPC client); the routing lives in `dig_app_core::gateway`,
which the running dig-app hosts. The gateway classifies every command as `Route::UserApp` (served
locally with the held user identity — profiles / wallet / sign) or `Route::Engine` (proxied to the
engine), and dispatches over four seams: `EngineProxy` (forwards the canonical `control.*` call over
the session), `LocalIdentity` (serves the local identity ops), `LinkOpener` (validates + opens a
DIG link — only `chia://` / `urn:dig:chia:` are accepted, the security boundary), and the
`NativeConfirmer` (§5.6.1) that gates `diga sign`. Failures carry a stable `ErrorCode` (symbolic name
+ numeric exit code); the `--json` envelopes match the engine CLI's shape so the DIG command line is
one consistent surface.

**Two transports, one control contract (normative, [dig_ecosystem#2019]).** The node's `control.*`
surface is reached by TWO transports that MUST stay byte-identical on the wire: the `diga` gateway's
`EngineProxy` (this section) and the tray shell's direct loopback client (`dig_app_core::control`,
§5.1.0). Both name the SAME method set and param shapes defined once in the shared
`dig-node-control-interface` catalog (`ControlMethod` + the typed params). The tray shell is bound to
that catalog at compile time (it builds requests from the typed `ControlCall`s), and so is the gateway:
every engine-routed command MUST resolve its call from a typed contract params struct, taking the
method name from that struct's bound `ControlMethod` and the params from the crate's own encoder. A
hand-written method string or param object is a second copy of a published contract and MUST NOT be
introduced — a rename of `SetCapParams::cap_bytes` is then a compile error in both transports rather
than a silent divergence in one. A conformance test additionally asserts every gateway method resolves
in the catalog and its params byte-match the typed serialization. The two node-only peer verbs
`control.peers.setBan` / `control.peers.setPoolConfig` are served by dig-node's own method list and are
not yet promoted into the shared catalog; they are the ONLY permitted untyped calls, and the test pins
that exact exception.

**`diga sign` — domain-separated + confirm-gated (MUST, custody).** The local `sign` command holds the
custody key, so it enforces the two invariants every 0x0010 signing path enforces:

- **Domain separation.** It signs the length-unambiguous message

  ```text
  "DIGNET-USER-SIGN-v1" ‖ message
  ```

  (the `USER_SIGN_DOMAIN` tag ‖ the caller's message; `message` is the single trailing field, so no
  length prefix is required for an unambiguous parse), **never the raw `message` bytes**. This is a
  THIRD purpose tag, distinct from `DIGNET-SESSION-v1` (§5.3 session attach) and `DIGNET-SIGN-v1` (§5.3
  engine callback / §5.6.5 dapp sign). Because the tags differ at a fixed leading position, a
  `diga sign` signature can NEVER be replayed as a session attach or a spend/callback authorization,
  even when the caller crafts `message` to look like one of those bodies — closing the cross-protocol
  signing oracle (§3 domain-separation invariant).
- **Confirm gate.** `diga sign` funnels through the same terminal `NativeConfirmer` (§5.6.1) the engine
  (§5.3) and dapp (§5.6.5) sign paths use, so no local process obtains an identity-key signature
  without an explicit human approval. A declined / timed-out / no-confirmer (headless) outcome returns
  the `DENIED` error code and never touches the key.

#### 3.5.1 The `diga` ↔ dig-app session lane (normative)

`diga` and dig-app are separately shipped binaries, so the channel between them is a wire contract.
This subsection defines it at the level an independent `diga` could be built against. It is DISTINCT
from the app-to-engine channel of §5.1.0 / §5: that lane carries `control.*` to the node, this one
carries a user's CLI request to their own running app.

**Endpoint resolution.** The lane's address is derived per OS, never configured:

| OS | Address |
| --- | --- |
| Windows | the named pipe `\\.\pipe\dignetwork-cli-<user>` |
| macOS, Linux | the Unix socket `cli-session.sock` inside the per-user brand data directory |

The Windows address is per-USER by construction: the user name is part of the pipe name, so two
signed-in users on one machine address different lanes and cannot collide. Both forms MUST resolve
through the same per-user host resolution the tray shell uses, so the CLI and the app can never
address different directories.

**The permission model.** The endpoint MUST be reachable only by the owning user:

- **Unix** — the socket is mode `0600` inside a `0700` directory. Both are restated after the bind
  rather than inherited, because the bind honours the process umask. The mode is load-bearing rather
  than decorative: Unix checks write permission on the socket inode at connect time.
- **Windows** — the pipe is created under an explicit, PROTECTED, owner-only DACL: exactly one
  access-allowed entry, for the calling user's SID. A NULL security descriptor MUST NOT be used —
  it grants `FILE_GENERIC_READ` to both `Everyone` and `ANONYMOUS LOGON`, so any local user could
  read the lane. Inheritance MUST be severed, or inherited entries merge back in.
- **Windows, name ownership** — a pipe name belongs to whoever creates its first instance and becomes
  unowned again when the last instance closes. The server MUST create the first instance at BIND with
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name already owned by another process fails the bind loudly
  BEFORE the session token is published, and MUST hold an unconnected instance continuously
  thereafter, so the name is never free between conversations. A client MUST open with
  `SECURITY_IDENTIFICATION`, which lets the server identify it but never impersonate it.

**The session secret.** A SECOND boundary, independent of the permissions of the endpoint, because
the two fail differently: an ACL mistake is silent and total, while a failed proof is a refusal the app
can log.

- 32 bytes of OS CSPRNG output, carried and stored as lowercase hex.
- Minted FRESH on every app start. It is a session credential, not a stored secret: an app that is
  not running has no session to authorize.
- Published to `cli-session.token` in the same per-user directory, owner-only (`0600` on Unix), and
  created owner-only rather than tightened afterwards — there MUST be no window in which it sits on
  disk readable by another user.
- Published only AFTER the endpoint bind succeeds, so a failed start never leaves a credential on
  disk for a lane nothing is serving.
- **The secret itself MUST NOT be transmitted on the lane, in either direction.** Each half proves
  knowledge of it with a MAC, per the mutual handshake below.

**The mutual handshake (normative, both directions).** The address of the endpoint is derived from the
login name and creating a named pipe or a socket requires no privilege, so a successful connect does
NOT establish that the peer is dig-app: any local principal that claims the name first — a second
local account, or a low-integrity same-user sandbox — can serve the lane. Authenticating only the
CLIENT is therefore insufficient. Both of the following MUST hold:

- **The server MUST authenticate the client**, so a local principal that cannot read the secret file
  cannot use the lane.
- **The client MUST authenticate the server BEFORE it sends anything beyond a nonce**, so a principal
  holding the endpoint can neither harvest a credential nor dictate what `diga` prints. A client that
  presented the secret to an unauthenticated peer would lose it in the same round trip, and would then
  print an attacker-chosen answer — including a wallet receive address.

The proof is `HMAC-SHA-256`, keyed on the lowercase-hex session secret, over
`context || 0x00 || client_nonce_hex || server_nonce_hex`, rendered as lowercase hex. Each nonce is 32
bytes of CSPRNG output in lowercase hex. A client nonce of any other width MUST be refused by the
server with `USAGE`; a server nonce of any other width MUST be refused by the client with `DENIED`,
because on that side a malformed nonce is not a usage mistake but a peer failing to prove it is
dig-app. The context strings are:

| Direction | Context |
| --- | --- |
| server proves itself | `dignetwork/cli-session/v1/server-proof` |
| client proves itself | `dignetwork/cli-session/v1/client-proof` |

Both nonces enter both MACs, so neither half can pin the transcript alone, and the two contexts mean
one direction's proof can never be replayed as the other's. The version in each context binds a MAC to
this protocol, so it cannot be replayed into a later one keyed on the same secret. Every MAC comparison
MUST be constant time; a `==` would leak, through timing, how many leading characters a forged MAC got
right.

**A bind refused because the endpoint is already held is an ATTACK INDICATOR.** `ERROR_ACCESS_DENIED`
on Windows or `AddrInUse` on Unix means another principal holds a name only this app may legitimately
hold. The app MUST distinguish that from an ordinary unavailable channel, and MUST surface it where an
operator can see it rather than only in a debug log. It MUST NOT become a startup trap: reading DIG
content never requires a working CLI lane.

**The frame contract.** Newline-delimited JSON, one JSON-RPC 2.0 envelope per line, `jsonrpc` always
the string `"2.0"`. Two methods exist:

| Method | Params | Result | Meaning |
| --- | --- | --- | --- |
| `control.session.challenge` | `{ "client_nonce_hex": <string> }` | `{ "server_nonce_hex": <string>, "server_proof_hex": <string> }` | the app proves it holds the session secret |
| `control.session.attach` | `{ "client_proof_hex": <string> }` | — | the client proves it holds the session secret |
| `gateway.dispatch` | `{ "command": <Command> }` | — | run one gateway command |

A response carries `id` and **exactly one** of `result` or `error`. A frame carrying NEITHER is a
protocol violation, not a success — a reader MUST refuse it rather than treat an absent `error` as
an empty result.

**The sequence.** `control.session.challenge`, then `control.session.attach`, then any number of
`gateway.dispatch`, on one connection, in that order.

- An `attach` with no preceding `challenge` on the same connection MUST be refused with `DENIED`:
  there is no transcript to verify it against, and accepting one would open a session the server never
  proved itself on.
- A dispatch on an unattached session is refused with `DENIED` and MUST NOT reach the gateway — the
  command does not run and is not partially applied.
- A FAILED attach does not open the session: a wrong proof leaves the connection unattached, so a
  later dispatch on it is refused too.
- A client whose verification of `server_proof_hex` fails MUST abandon the connection with `DENIED`
  and MUST NOT send an attach, a dispatch, or anything else on it. It MUST NOT render any value the
  peer supplied.
- **The client MUST NOT be ABLE to render any part of a challenge answer.** The two handshake hex
  values are the only content it may take from that frame; the answer's human summary, any further
  result field, and — on the `error` channel of the same frame — the peer's `message`, its `hint` and
  its choice of `code` MUST all be discarded before any of them can reach a rendering surface. The
  `code` matters as much as the prose: the CLI's process exit status is derived from it, so a peer that
  chose `OK` would make a refused command report success. This is a structural requirement, not a
  per-field one: an implementation MUST make peer-authored content from a pre-attach frame
  unrepresentable in the value the client carries forward, because enforcing it channel by channel
  leaves the next channel open. A refusal caused by the peer MAY name the catalogued code CLASS it
  answered with, because that name comes from the reader's own closed catalogue rather than from the
  wire.
- An unreadable frame is answered with `USAGE` rather than dropped, because a silent drop hangs the
  client on a read that never returns.

**Read deadlines (MUST).** Every leg of this lane on which one half waits for bytes the other half
chooses to send MUST be bounded. A peer that completes the accept and then never writes is neither a
crash nor a refusal, and without a bound it is indistinguishable from work still in progress: the
waiting side stops forever, with no error and nothing to report. The endpoint address is derived from
the login name and needs no privilege to claim, so that peer need not be the app and need not be
hostile — a wedged process holding the endpoint produces the same silence.

- The bound MUST be per FRAME and ABSOLUTE, spanning the whole frame including any framed-length read
  within it. A bound re-armed on each read of the underlying channel bounds only that read, and a peer
  that dribbles bytes without completing a frame defeats it.
- The bound MUST be enforced BELOW the frame buffer, so it can never expire on a frame whose bytes
  have already arrived.
- The CLIENT MUST bound the handshake legs (`control.session.challenge` and `control.session.attach`)
  more tightly than the dispatch leg: a handshake answer is computed from the app's own memory and
  reaches neither disk nor network, whereas a dispatch answer may consult the node.
- The SERVER MUST bound each frame it awaits from a client. Service is serial, so an attached client
  that stops speaking would otherwise hold the only conversation slot for the life of the app and make
  every other invocation on the machine report that the app is not running.
- The CONNECT leg MUST be bounded too, on every platform where the transport can block on the peer,
  and the exemption is per PLATFORM rather than a property of unix sockets in general:
  - **Windows** — exempt. The listener always holds an unconnected pipe instance, so an open finds one
    waiting or fails at once.
  - **Darwin** — exempt. A connect whose listener's accept queue is full is refused with
    `ECONNREFUSED` rather than queued.
  - **Linux** — NOT exempt, and MUST arm `SO_SNDTIMEO` before it dials. `unix_stream_connect` tests
    `unix_recvq_full` and, for a BLOCKING socket, waits in `unix_wait_for_peer` bounded by
    `sk_sndtimeo`, which defaults to `MAX_SCHEDULE_TIMEOUT`; `EAGAIN` is returned only for a
    NON-blocking socket. A process that claims the endpoint, calls `listen`, and never accepts
    therefore stops the client one leg earlier than the silent holder above, and with no error at all.
  - An expired connect MUST be reported as a HELD endpoint, per the clause below. A REFUSED connect
    MUST NOT be: a refusal genuinely means the app is not running, and that remedy is the correct one.
- **A timeout MUST be reported as a HELD endpoint, not as an absent app.** The two are different
  diagnoses with different remedies, and "could not connect" is false of a peer that accepted. The code
  reported is `NOT_CONNECTED` — a peer that will not speak is, for every purpose a caller has, as
  unusable as an absent one — but the message MUST say that the endpoint was held and answered nothing,
  and MUST name the leg the wait was given up on.

**Error codes.** `ErrorCode` serializes as its stable UPPER_SNAKE symbol, so the wire, the `--json`
envelope and the documented catalogue are one thing rather than three spellings.

**What is served on this lane today.** The lane is real but the surface behind it is partial, and the
distinction is normative because a refusal hint promises a remedy:

- **Answered on the lane** — `profiles list` and `profiles default` in its no-argument show form.
- **Answered WITHOUT the lane** — every `account` verb, which `diga` serves in-process against this
  machine's account store and which therefore works with no running dig-app (§3.5). A refusal hint MAY
  name `account status` as a remedy for that reason, but it is not traffic on this channel.
- **Refused, on purpose** — `profiles create` is `DENIED` (minting a profile spends XCH and is
  confirmed in the app, never in a background lane); `profiles select` and the argument form of
  `profiles default` are `LOCKED` registry writes; `wallet address` and `wallet balance` are `LOCKED`
  until the account is unlocked, both because they derive from the master seed. `wallet balance` MUST
  be refused rather than answered with `0`, which is indistinguishable from an empty wallet.
- **Proxied to the node** — every engine-routed verb (`info`, `config`, `cache`, `stores`, `sync`,
  `subscriptions`, `peers`, `pair`) is carried to the running dig-node over the loopback control
  plane and answered with the NODE's own result. The proxy resolves the §5.3 endpoint ladder, so a
  configured node endpoint wins outright. When no node answers on any tier the verb reports
  `NOT_CONNECTED` naming what was tried; a node that DECLINES reports `ENGINE_ERROR` carrying the
  node's own message, and an unusable control token reports `ENGINE_ERROR` naming the HTTP status —
  the three MUST stay distinguishable, because they have three different remedies.

**The proxy MUST forward only methods the gateway's own router can produce (normative).** The node's
control surface is wider than the router's — it includes `control.wallet.coinSpend` and the
key-enrolment methods — and the proxy is handed a method NAME, so an ungated proxy would be a
general-purpose tunnel from `diga` into the node rather than the tail of a routing decision. Any other
method MUST be `DENIED` without being dialled. Together with `diga sign` being `DENIED` locally
(§5.6.1), this is what keeps the [dig_ecosystem#908] custody boundary intact from both sides.

**Only an UNREACHABLE tier may fall through to the next (normative).** Half of what the proxy carries
mutates node state (`cache clear`, `stores pin`, `sync trigger`, `subscriptions add`), so a tier that
accepted a call and then refused or timed out may already have acted on it. Re-sending to a later tier
could apply the same mutation twice. A refused connection is the only outcome that is evidence nothing
happened.

A refusal hint on this lane MUST name only VERBS that answer, never a command FAMILY: a family
includes its refusing members, so naming one sends a person from one honest refusal into another.


### 3.6 Session lock (lock-now · 24-hour idle · process exit · tiered re-auth)

An unlocked profile keeps its data-encryption key (DEK) resident in the in-memory session (§3.1).
Once a session is unlocked it MUST stay unlocked until one of exactly three things happens, and no
others:

1. **One-tap lock-now.** An explicit lock action (a tray item) locks IMMEDIATELY, with NO confirmation
   prompt. Because the idle window is a full day, this is the only IMMEDIATE lock available to a
   person short of quitting the app, so it MUST remain offered at the TOP level of the tray menu
   whenever the account is unlocked — never demoted into a submenu.
2. **24 hours with no USER activity.** After an idle window with no noted activity
   (`DEFAULT_IDLE_TIMEOUT` = 24 hours) the session locks. The shell drives the check from its refresh
   tick; noting activity resets the window.
3. **The app was closed and reopened.** Structural rather than a code path: the DEK lives only in the
   in-memory residency, so process exit drops it and a fresh process starts LOCKED. An implementation
   MUST NOT persist an unlocked session across a restart.

**What counts as activity (MUST).** Only USER interaction notes activity — a tray/window menu click,
and an already-authorised sign passing through the re-auth gate. Background work MUST NEVER note
activity: not the refresh tick, not status polls, not repaints, not node reads, not notifications. A
content read is not evidence of a person at the machine, and an idle clock fed by the app's own work
never elapses, which would make the window dead code that merely resembles a control. The refresh tick
therefore only READS the clock (`poll_idle`) and never feeds it.

**Rationale for the 24-hour window.** It governs how often a person retypes a password to authorise
their OWN LOCAL actions, not whether a remote party can act for them: the node never holds the user's
key and signing is local and per-operation, so the window widens only the unattended-machine exposure
on a device the user already controls. It is a MAXIMUM, not a promise of liveness — nothing keeps the
process alive to honour it, and an app closed at hour 3 has already lost its session under rule 3.

**Locking the OS screen is NOT a trigger.** A person who locks their machine to step away has not
asked dig-app to forget their session, and re-locking behind that is friction with no custody benefit.
No platform screen-lock listener may be wired; a source-scanning regression test enforces the absence.

All three triggers drop the SAME key material: every unlocked profile DEK, via a whole-session lock.

**Tiered re-authentication (MUST — frictionless consumption, §6.0).** A lock gates the KEY, not
content. Reading/browsing DIG content never touches the identity key, so a lock MUST NOT interrupt or
prompt a read. Only the NEXT **signing** operation after a lock re-authenticates (biometric /
passphrase, via the §3.1 unlock path); the lock exposes a `reauth_required` predicate that ONLY the
signing paths consult. Once a re-unlock succeeds the owed re-auth clears and the idle window restarts.

The lifecycle is a pure, seamed controller (`session_lock::SessionLock` over a `SessionKeys` DEK-drop
seam — implemented by the master-HD `account::residency::AccountResidency` — and a `MonotonicClock`),
so every trigger + the tiered
re-auth is unit-tested without a real keystore or OS.

The tray shell drives one `SessionLock` over the SAME live session the APP-SIGN signer holds (so a
lock the tray triggers is the lock the signer sees): the "Lock now" menu item calls `lock_now`, the
refresh tick calls `poll_idle`, and a tray interaction notes activity.
The `sign.request` path consults the lock through a `SignReauthGate` immediately before it signs: when
a re-auth is owed it re-unlocks ONLY the signing (active) profile's identity — never every profile's
DEK — via the §3.1 single-profile unlock path, so the re-auth restores the smallest key residency that
authorizes the sign and leaves all other profiles locked. On failure it refuses the sign with `LOCKED`
rather than signing on a dropped key. Reads never consult the gate.

### 3.7 Event-driven wallet UI + funds notifications

The `events` module below is the SUBSCRIBE half — the "event-driven, poll only on a gap" contract —
and it is a seam awaiting a producer: no `EventFeed` implementation ships today, because dig-node
pushes no confirmed funds event. What ships is §3.7a's confirmed-arrival watch, which POLLS. The
paragraphs here describe the contract the app consumes when that stream exists; they are not a
description of a running subscription. The event taxonomy — `WalletEvent`,
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
flag) the tray shell and `diga` CLI OBSERVE via a shared handle — the same pattern as
`agent::SharedStatus`. Events say *when* to refresh; the authoritative balance comes from the §3.3
wallet read seam when `balances_dirty` is set.

**Funds notifications (`notify`, #970).** A `NotifyingSink` taps `FundsReceived`/`FundsSent` and feeds
a debounced coalescer: every funds event within a short trailing window merges into ONE native OS toast
(a burst of 3 receives → one "Received 3 payments: X total"). Amounts + asset labels are honest ($DIG
vs XCH vs a short CAT id — never a guessed ticker) and a notification NEVER carries a key, seed, or
address. It is passive, dismissible, and opt-out (§6.0/§6.1) — it never gates a read. This path holds
no key and touches no custody surface. The sink half awaits the event stream above; the RENDER half
(`Notification`, `NativeNotifier`, the coalescer) is what §3.7a drives today.

**Native notification backends.** `native_notifier()` selects the host's:

| OS | API |
|---|---|
| Linux | `notify-send` (libnotify), args passed separately so text cannot inject a command |
| macOS | `osascript -e 'display notification …'`, both fields escaped for the AppleScript literal |
| Windows | `Windows.UI.Notifications.ToastNotificationManager` (WinRT), payload built as escaped `ToastGeneric` XML |
| other | `LoggingNotifier` |

Windows is the one platform with no notification command to shell out to, so it is the one called
in-process. An UNPACKAGED Win32 process has no package identity, so a toast has nothing to be
attributed to and is DROPPED SILENTLY — `Show` still returns success. dig-app therefore registers an
AppUserModelID, **`DIGNetwork.DIG`**, on a per-user Start Menu shortcut
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\DIG.lnk`, carrying `System.AppUserModel.ID`).
That id is CANONICAL: Windows keys the
user's per-app notification permissions on it, so changing it discards choices the user has already
made. Registration happens at start-up (`notify::prepare_host()`), not at the first toast — the shell
resolves the id through an index over the Start Menu that the creating process does not see, so a
toast raised in the same run as the shortcut is created does not appear.

The shortcut is REPAIRED, not merely created: a shortcut whose icon does not already name the running
executable is rewritten, so a machine carrying an earlier build's iconless shortcut gets the DIG Mark
rather than the generic file icon (#3076). `prepare_host()` is the ONLY path that writes it —
delivering a toast MUST NOT — and a process whose own executable lives inside a cargo `target/` build
directory MUST decline to write it at all, because the next rebuild deletes that executable and leaves
the shortcut dangling. The test is the executable's PATH, not the presence of cargo's environment: a
binary run straight out of `target\debug\` exports no `CARGO*` and MUST still be refused. An executable
that cannot be identified MUST be ALLOWED, because a false refusal leaves the installed app without its
AppUserModelID and silently stops every notification. A cargo TEST binary reaching the writer is a defect
and fails the suite rather than modifying the developer's machine.

### 3.7a Confirmed-arrival notifications (`arrivals`, #2548)

**dig-node decides what an arrival is; dig-app decides what to say and when to stop saying it.** The
node keeps a durable arrival ledger and serves it on a cursor (`control.wallet.arrivals`); `arrivals`
is a client of that cursor and forms no opinion of its own about whether money arrived.

That division is normative, not stylistic. Telling a payment from the user's own CHANGE requires the
coin's PARENT, and a parent is spent the moment it produces change — so `control.wallet.coins`, which
lists UNSPENT coins only, structurally cannot answer the question. dig-app MUST NOT re-derive the
judgement from it. An implementation that did was measured announcing `Received 8.999 XCH` for a
transaction in which the user SENT money.

**The seam.** `ArrivalSource::arrivals_since(after_seq)` yields an `ArrivalPage`
(`arrivals`, `cursor`, `latest`). `watch::ControlPlaneSource` implements it over
`control.wallet.arrivals`, an OPEN token-less read of the node's own local replica. A future push
transport implements the same trait and nothing above it changes.

**What `arrivals` is responsible for.** Exactly one property: *each recorded arrival is announced at
most once, on this machine*.

| Failure | What forbids it |
|---|---|
| installing dig-app against a node with a ledger toasts its whole history | an `ArrivalCursor` with no position ADOPTS the node's `latest` in silence |
| a restart re-announces | the cursor is persisted (`arrival-record.json`, written whole via a rename) before anything is drawn |
| the client resumes past an arrival it never saw | the cursor advances to `page.cursor` — the last row RECEIVED — and never to `latest`, which the node reads after the page |
| a node whose ledger was rebuilt replays old toasts | the cursor never moves backwards, AND the coin id — not the `seq` — decides announcing |
| an amount the client cannot read becomes a wrong figure | `amount` crosses the wire as a decimal string and an unparseable one is refused, never defaulted |

**De-duplication is by coin id, not by `seq` (#2959).** `arrivals.seq` is `AUTOINCREMENT` in the
node's database: a per-database ordinal, not a property of the coin, stable only while that one
`wallet.sqlite` survives. A rebuilt, restored or replaced node database renumbers every arrival, so a
client keyed on `seq` alone re-announces money it has already reported — and a notification that money
arrived is a claim about money. dig-app therefore MUST keep the cursor as the PAGING instrument and
make the coin id the ANNOUNCING one.

The record (`ArrivalAnnouncer`, persisted whole as `arrival-record.json`) holds the cursor together
with the coin ids already announced. An arrival is announced only when the cursor passes it AND its
coin id is unknown to that record. The set is bounded to the most recent **512** coin ids by insertion
order; every eviction raises `pruned_below_height` to the evicted coin's `confirmed_height`, and an
arrival at or below that horizon is treated as ALREADY ANNOUNCED. Pruning therefore cannot resurrect an
old notification.

**The record fails closed in the opposite direction from an empty set.** An absent or unparseable coin
set MUST be read as *already announced*, never as *nothing announced yet*: it is an ADOPT state, in
which the next page is suppressed entirely and that page's highest `confirmed_height` becomes the
horizon. This mirrors an unread `ArrivalCursor`, which announces nothing and jumps to `page.latest`.
Reading it as an empty set would announce the node's whole ledger on a single corrupt file — the exact
defect the record exists to prevent. The cursor and the coin set share ONE file for the same reason: a
cursor that survived a lost coin set would page past arrivals the set could no longer recognise.

A sweep drains pages until the node has nothing more (bounded per sweep; the remainder is picked up by
the next sweep, because the cursor advanced over exactly what was read), saves the cursor, and only
then draws ONE coalesced toast. Saving before drawing is deliberate: a crash between them costs a
toast, and the other order costs a duplicate claim about money.

**Assets.** The node's `asset_id` is passed through verbatim, so `$DIG` is named from
`dig_constants::DIG_ASSET_ID` and any other CAT the node attributed is shown by its own short id —
never relabelled, and never rendered with another asset's divisor.

**Preference.** `AgentConfig.notifications.funds_received`, defaulting to ON — including for an
`agent.json` written before the field existed. It is turned off in the Settings tab, and it gates the
TOAST, never the cursor: the cursor keeps advancing while notifications are off, so turning them back
on does not replay everything received in between.

**A payment that arrives while dig-app is CLOSED is announced when it next opens.** The node records
it whenever the node is running, so closing the window delays the toast rather than losing it. What is
genuinely not covered is an arrival while the NODE is stopped: it is recorded by the catch-up that
follows, and is an arrival unless that catch-up is the wallet's first (see dig-node's
`sage::arrivals` arrival baseline). The Settings card states this in the user's words.

**Custody (§908).** The one input is a cursor position, over a token-less read of the node's own
replica. Nothing on this path holds, derives or uses a key, nothing on it can spend, and there is no
oracle leg — polling it discloses nothing off-machine.

### 3.8 Profile-image intake (#3010)

Every image a person attaches to a profile is **normalised, never stored as offered**. The bytes
recorded in a profile SMT slot are the base64 of the **resized** encoding; the original is discarded.

**Normalisation.** The image is scaled to fit within **500x500** with its aspect ratio unchanged —
a fit-within, never a fill or a crop, so a 1000x500 image becomes 500x250 and neither dimension
exceeds 500. An image already inside the box is left at its own size: upscaling adds bytes and no
information. No image is refused for being too large in the *output* sense; the bound is a
normalisation.

**Accepted formats.** PNG and JPEG, and nothing else. The format is determined by **sniffing the
bytes**; a declared MIME type is advisory on every path and attacker-chosen on the received one.
`image/svg+xml` is refused by name — an SVG is a script-bearing document, not a bitmap. The decoder
build links no other format, so a format outside this pair cannot be parsed at all.

**Bounded decode (SECURITY-CRITICAL).** The size bound is on the output; the attack is on the input.
Resizing requires decoding, and a decompression bomb is a small file declaring dimensions that
allocate gigabytes before any pixel is resized — so intake MUST refuse on the **header**, before a
pixel buffer is allocated, against a per-side limit, a **total-pixel** cap (not implied by the side
limits) and an input-length cap. `image::Limits::max_alloc` is documented as non-strict and MUST NOT
be relied on alone; the strict `max_image_width`/`max_image_height` pair carries the decoder-side
half of the bound.

Two profiles, and one MUST NOT be used for the other:

| Profile | Per side | Total pixels | Input bytes | Applies to |
|---|---|---|---|---|
| `LOCAL_PICK` | 8192 | 8192 x 8192 | 256 MiB | a file the user browsed to or dragged in |
| `RECEIVED` | 512 | 512 x 512 | 4 MiB | an image inside a body from an untrusted peer |

The received profile is tight *because* of the normalisation rule: a conforming writer never emits
more than 500 on a side, so anything larger did not come from one. Verified content is not safe
content — a body that hashes correctly to the on-chain root can still carry a hostile image.

**Output codec, which the size budget depends on.** PNG when any resized pixel is less than fully
opaque, JPEG quality 85 otherwise — decided from the resized pixels, not from the source's colour
type. This pins the worst case at a 500x500 RGBA PNG (≈1,000,200 bytes, ≈1,333,600 base64) and any
deviation from it invalidates the slot-size budget derived from that number.

**Refusals.** Each is stated in the user's terms — an unsupported file names what is supported, an
over-bound file states the dimensions it declared and the limit. A raw decoder error is never
surfaced.

**Custody (§908).** Pure bytes-to-bytes. Nothing on this path holds, derives or uses a key.

---

## 4. Form factors

dig-app is a **headless per-user agent core** with an **optional GUI tray shell** layered on top. The
agent core (identity/keys/profiles/IPC/gateway) is the real component; the tray is a desktop
affordance. On a GUI-less host the app runs as the agent core + the `diga` CLI, with no tray.

| OS | Engine (service) | dig-app shell | dig-app autostart (per user) |
|---|---|---|---|
| Windows | Windows Service / LocalSystem | system-tray shell | per-user logon autostart |
| macOS | launchd **daemon** (`/Library/LaunchDaemons`, root) | menu-bar `LSUIElement` | launchd **LaunchAgent** (`~/Library/LaunchAgents`) |
| Linux | systemd **system** service | AppIndicator / StatusNotifier tray | XDG `~/.config/autostart/*.desktop` OR a systemd **user** service |

**Headless degrade (MUST):** when no desktop session is available (a Linux server, headless
Windows/macOS Server), dig-app runs as the agent core + `diga` only; the tray is not mounted. The
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

   The active profile MUST be read BEFORE the confirm is raised and MUST still be active when the
   record is written; if it changed in between, the node MUST mint no token and answer `PAIR_DENIED`.
   The confirm names the app and not a profile, so its answer authorizes only the profile whose owner
   read it.

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

`scope` gates the ATTESTATION method (`sign.request`) only, and `sign.request` is NOT a money method
(§5.6.5). **`scope` grants no spend power whatsoever.** The power to move money is `spend.request`
(§5.6.10), which is gated ONLY by an explicit per-pairing `spend.request` capability grant and is
implied by NOTHING — not by `scope`, not by a pinned `ext_id`, and not by any `identity.*`
capability. A `dig-extension` pairing that was granted no capabilities therefore may attest and MUST
NOT spend, which is exactly the authority every pairing sealed before §5.6.10 existed carries.

`scope` is likewise orthogonal to the `identity.*` capability set (§5.6.8), which gates the sealing
methods independently — a pairing of EITHER scope may hold identity capabilities, and neither scope
implies them. A frame is authenticated FIRST and its
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
  wallet state yet returns an empty `addresses[]` (the channel is still fully usable) — and because
  an empty `addresses[]` carries exactly that meaning, a FAILED read of the sealed wallet state MUST
  NOT be memoized as one. The derivation cache MUST remember only a completed read; a read that could
  not open the blob (the DEK having moved under it — an idle lock or a profile switch) falls through
  so the next read retries. On Deny/timeout
  ⇒ `CONNECT_DENIED` / `CONNECT_TIMEOUT`, as is a profile switch landing between the confirm and
  the grant (the consent belongs to the profile that was active when the modal was read, so no entry
  is recorded for either profile). The sealed whitelist entry persists
  to the profile's AppData and is restored on boot (a connected dapp survives a restart); `connect.revoke`
  deletes the at-rest record, so the revocation is durable too.
- **Sign gating.** A `sign.request` whose `origin` is NOT whitelisted for the active profile ⇒
  `CONNECT_REQUIRED` (the extension MUST run `connect.request` first). Whitelisting is connect-time
  convenience memory only; it NEVER waives the per-sign native confirm (§5.6.5). A "sign without
  per-transaction prompt" scope, if ever offered at connect, MUST default OFF and be clearly labelled
  dangerous.
- **`connect.revoke`** (extension → app) and a dig-app UI surface both delete a whitelist entry; a
  revoked origin returns to `CONNECT_REQUIRED`.

#### 5.6.5 sign request — a typed identity ATTESTATION, never a payment

**`sign.request` cannot move a mojo, and MUST NOT be described anywhere as the money capability.**
What it returns is a detached BLS G2 signature made with the slot `0x0010` IDENTITY key over the
domain-separated message `"DIGNET-SIGN-v1" ‖ len16(payload_type) ‖ payload_type ‖ payload` (below).
That construction exists precisely so the signature cannot be replayed as a session attach, as a
differently-typed spend, or as any other `0x0010` signature — and it is therefore **not an
`AGG_SIG_ME` and can never appear in a broadcastable `SpendBundle`**. No Chia consensus rule accepts
it.

`payload_type = "spend"` names WHAT IS BEING ATTESTED TO, not an act of payment: the caller receives
an attestation over a spend bundle's bytes and no signed bundle. **The method that produces a
broadcast-ready signed `SpendBundle` is `spend.request` (§5.6.10).** The two are separate methods
under separate authorization, and neither implies the other.

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
  full effect they authorize. It is plain text and adds no markup, and nothing downstream interprets any
  — the prompt window rasterises glyphs, so there is no markup parser to neutralize characters for
  (dig_ecosystem#2038). A net-effect preview (what leaves vs returns from local coin state) is
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

The `identity.*` methods are a SEPARATE capability axis from the `sign.request` attestation boundary
(dig_ecosystem#1931/#1913) and from the `spend.request` money boundary (§5.6.10). They let a paired app
— dig-chat is the first — reach the profile's X25519 **sealing** keypair to send and open `DIGCHAT1`
end-to-end-encrypted messages (NC-1), WITHOUT ever obtaining the identity signing power and WITHOUT
obtaining any spend power. The separation is structural, not advisory:

- **Three independent gates.** `sign.request` is gated ONLY by the pairing `PairingScope` (§5.6.3a) —
  a pinned DIG extension. `spend.request` is gated ONLY by the explicit `spend.request` capability
  grant (§5.6.10). `identity.attest` / `identity.seal` / `identity.unseal` are gated ONLY by a
  per-pairing **granted capability set**. A pairing MAY hold every identity capability and a
  non-signing scope; an identity grant can NEVER open `sign.request`. A KNOWN identity method a
  pairing was not granted ⇒ `CAP_NOT_GRANTED`; a method that does not exist ⇒ `-32601` (they are
  distinct).
- **Granting.** `pair.begin` MAY carry `requested_capabilities: string[]`; the app grants the
  recognized `identity.*` names (unknown names dropped) and echoes the result as
  `granted_capabilities` in the `pair.begin` result. The set is stored on the sealed pairing record
  and is `serde(default)` — a record sealed before this class existed opens as the EMPTY set,
  refusing every `identity.*` method (§5.1 back-compat). The set MUST survive sealing and restart.
- **The DID precondition is live, and MUST NOT be frozen into the record.** An identity capability is
  in effect only while the profile holds a DID, so the set stored on the record is the set the app
  REQUESTED and the DID condition is evaluated afresh on `pair.begin` (for the echo) and on every
  `identity.*` frame (for the gate), through the one `Allowance` policy. A pairing established before
  a DID exists therefore holds its requested capabilities the moment one is minted, on the same
  channel, with no re-pair (dig-app#232); a capability that was never requested is never granted by a
  later mint. The `granted_capabilities` echo reports what is in effect AT PAIR TIME and MAY later
  understate what the pairing holds. This is the door only: `identity.attest`/`identity.seal` MUST
  still refuse with `LOCKED` when no DID can be read.

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
shared with session-attach and `diga sign`, so the prefix is what stops an attestation signature
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

#### 5.6.9 `control.request` — proxied node availability reads

A connected dapp MAY ask dig-app to forward a **narrow, enumerated** set of `control.*` calls to the
node it is attached to, over the same channel it pairs and signs on. This exists so a dapp needs one
transport rather than a second, independent connection to the node.

**Request** — `method: "control.request"`, params:

```json
{ "origin": "https://dapp.example", "method": "control.status", "params": {} }
```

`origin` is the §5.6.4 origin gate. `method` is the canonical `control.*` name; `params` is passed
to the node untouched.

**The result is NOT.** The node's reply is **projected** before it reaches the caller: the values are
the node's own, but only the fields tabulated below are returned, and everything else the node sent
is dropped. See the projection rules below — they are normative, and an implementation that
forwards the node's result object whole reintroduces the disclosure this section exists to prevent.

**Three gates apply, in this order, and the order is normative:**

1. **Authentication.** The frame MUST carry a valid pairing auth (§5.6.3), like every non-pairing
   frame. An unauthenticated frame is `AUTH_REQUIRED` and learns nothing further.
2. **Connect.** `origin` MUST already be whitelisted for the active profile (§5.6.4), else
   `CONNECT_REQUIRED`. This is checked **before the node is dialled** — an unconnected origin MUST
   NOT cause any call to reach the node, so a refusal cannot be used to make the app act as an
   unauthenticated relay.
3. **Method allow-list.** `method` MUST appear in the dapp-reachable set below. Anything else is
   `ENGINE_REFUSED` and MUST NOT be dialled. This gate MUST be enforced at the dispatch layer, not
   delegated to whichever engine implementation is attached.

**The dapp-reachable set is EXACTLY the following methods, each projected to EXACTLY the listed
response fields:**

| Method | Fields a dapp receives | Answers |
|---|---|---|
| `control.status` | `running`, `protocol` | is a node reachable, and can this dapp speak to it |
| `control.hostedStores.status` | `store_id`, `pinned`, `capsule_count` | is this store available from this node |

**A method name alone MUST NOT be treated as the boundary.** The gate filters the method that
*enters*; the node's response *leaves*, and a method name cannot express "this response minus these
fields". Concretely: `control.status` returns a `StatusResult` whose `cache` field is the **same
`CacheView` type `control.cache.get` returns**, so an implementation that excludes `control.cache.get`
by name while admitting `control.status` hands a dapp the identical bytes and has excluded nothing.

Implementations MUST therefore **project** each response — rebuild it from the permitted fields —
rather than forwarding it whole.

**The projection MUST be built up, never stripped down.** It MUST start from an empty object and copy
in the permitted fields, and MUST NOT take the node's response and remove disallowed ones. The node
control interface gains fields over time; under a strip-down rule every new field would reach dapp
origins from the moment the node is upgraded, silently. A permitted field the node did not send MUST
be absent rather than defaulted.

A method outside this set MUST have no projection, so an unrecognised response is withheld rather
than passed through whole.

**What each projection deliberately withholds, and why:**

- `control.status` — **`cache`** (its `dir` is an absolute path embedding the OS account name on every
  desktop OS), **`upstream`** and **`addr`** (the user's own configuration), **`hosted_store_count`**,
  **`cached_capsule_count`**, **`pinned_store_count`** (the size of their collection), and
  **`version`** / **`commit`** / **`uptime_secs`** (build fingerprinting).
- `control.hostedStores.status` — **`capsules[]`**, whose `last_used_unix_ms` is a timestamped record
  of what the user has been **reading**, over store ids that are public and therefore guessable; and
  **`total_bytes`**.

`control.sync.status` is deliberately NOT in this set. It is node-wide and carries no store id, so it
cannot answer "is this store synced" at all, while its `pinned_total` / `pinned_synced` report the
size of the user's pinned collection. `control.hostedStores.status` answers the real question.

**This set is deliberately NOT the set the local `diga` CLI may reach**, and implementations MUST NOT
conflate them. The CLI's set bounds a different principal — the user operating their own machine from
their own terminal — and it admits `control.pairing.approve`, `control.pairing.revoke`,
`control.config.setUpstream`, `control.peers.setBan`, `control.cache.clear`,
`control.hostedStores.unpin` and `control.sync.trigger`. Granting those to a remote origin would mean
**a single connect click let a dapp approve a pairing on the user's node.** An allow-list is only
sound for the principal it was drawn for.

Two classes are excluded, and both MUST stay excluded — **at the field level, not the method level**:

- **Every mutation.** A connect click consents to a dapp *talking to* the node, never to it changing
  the node's pairings, config, peer bans, cache, pins, subscriptions or sync schedule.
- **Everything that ENUMERATES the user** — the set of stores they host, follow or pin, how much
  they store, what they have read and when, their upstream, their cache location, and their peer
  graph. A connect click is not consent to inventory someone's setup.

  The distinction is enumeration versus a single answer. `control.hostedStores.status` returns
  `pinned` for **one store the caller named**, which answers the availability question it already
  asked and reveals nothing it did not. What stays excluded is the *listing* — `hostedStores.list`,
  `listSubscriptions`, `pairing.list`, and the `pinned_store_count` / `hosted_store_count` /
  `cached_capsule_count` totals — because those answer a question nobody asked.

The pairing SCOPE does not gate this method; the connect gate plus the projected allow-list above are
what authorize it. That is sound **only because** what reaches a dapp is confined to the fields
tabulated above — it is not a general statement that engine calls are harmless, and widening either
the method set or any field list without revisiting this sentence would make it false.

`origin` is read from the params rather than from the pairing, because a `PairingAuthority` carries
a scope and capabilities but no origin. This is the same shape `sign.request` uses (§5.6.5), and it
means a caller can only name an origin a human has already consented to.

**Custody.** This path signs nothing and MUST NOT reach any signing seam. Nothing seed-derived
crosses it in either direction.
#### 5.6.10 spend request — the money boundary

`spend.request` is the ONE loopback method that can move a user's money. It returns a **broadcast-ready
signed `SpendBundle`** and, if asked, publishes it. It is a different power from `sign.request`
(§5.6.5), which returns a typed identity attestation no consensus rule accepts, and the two are
separate methods under separate authorization so that neither can be mistaken for the other
(dig_ecosystem#1552).

**Why a new METHOD and not a new `payload_type`.** The payload is the streamable `SpendBundle` in both
cases. What differs is the response shape, the signing key, and the authorization tier — a method
distinction, not a payload one. One method returning two incompatible result shapes chosen by a request
field would let a caller written against `sign.request` parse a spend response as a *missing*
`signature_b64` rather than as an error. A new method fails cleanly with `-32601` on an older peer,
which is the only version negotiation this wire has.

- **Authorization (MUST).** `spend.request` is gated ONLY by an explicit per-pairing `spend.request`
  capability grant, requested through `pair.begin`'s `requested_capabilities` and echoed in
  `granted_capabilities` (§5.6.8's grant mechanism, one capability set). It is implied by NOTHING:
  not by `scope`/`may_sign`, not by a pinned `ext_id`, and not by any `identity.*` capability. A
  pairing holding `sign.request` and no grant ⇒ `CAP_NOT_GRANTED`. The set is `serde(default)`, so
  every pairing sealed before this method existed opens WITHOUT it (§5.1 back-compat) — which is the
  safe direction and the reason the grant is not folded into `scope`.
- **The pairing confirm MUST name the money power** when `spend.request` is among the requested
  capabilities. The grant happens on that screen, so that screen states it, and states that every
  individual payment is still confirmed separately. A pairing NOT asking for it MUST NOT carry the
  warning.
- **Params.** `{ origin, payload_type, payload_b64, broadcast? }` — the same payload discipline as
  §5.6.5, so one decoder serves both.
  - `origin` — the vouched dapp origin. MUST be whitelisted (§5.6.4), and the gate MUST run FIRST,
    before any other field is read.
  - `payload_type` — MUST be `"spend"`. Anything else ⇒ `SIGN_UNKNOWN_TYPE`.
  - `payload_b64` — base64 of the **unsigned** streamable `SpendBundle`. Only its `coin_spends` are
    taken: **any signature the caller supplied is DISCARDED**, so a caller can neither contribute to
    nor pin any part of the aggregate signature.
  - `broadcast?` — boolean, **default `false`**. An absent field, an older caller, or a caller that
    simply omitted it gets the signed bytes back and NO broadcast.
- **Gate order (MUST, and it is load-bearing).** connect gate → params → `payload_type` allowlist →
  base64 → decode-for-display → **session-lock re-auth gate** → **the connect gate AGAIN** → the money
  path. The re-check after the re-auth is REQUIRED: the re-auth is a state TRANSITION that unlocks into
  whichever profile is active by the time it runs, and a profile switch needs no unlock to get there,
  so everything decided before it was decided about a different profile than the one about to hold the
  money key.
- **Blind-spend refused (MUST fail closed).** A payload that does not decode into human terms
  (§5.6.5's decoder, unmodified) is refused BEFORE the money path is reached — `SIGN_UNKNOWN_TYPE` or
  `SIGN_BAD_PAYLOAD`, the same two codes `sign.request` uses. Rendering is a precondition of spending,
  not merely of displaying.
- **One confirm, and it is the stronger one (MUST).** The single human confirm is the money path's
  ceremony, which renders recipients, amounts and fee that `dig-account` re-derived INDEPENDENTLY from
  the coin spends. The §5.6.5 decode runs for refusal only and MUST NOT raise a second window:
  confirm-fatigue is a bypass.
- **The op class is `Undeclared` (MUST).** The spend was built outside this process, so no caller can
  truthfully declare what it is for. `Undeclared` can never auto-approve and always routes to the
  human, however permissive `AutoSendPolicy` is. A caller MUST NOT be able to state the op class.
- **The confirm copy MUST be honest about the ACT.** A person approving "sign this" and a person
  approving "sign and send this" are agreeing to different things. When `broadcast` is true the confirm
  MUST say the app will broadcast; when false it MUST say the app will NOT, and MUST NOT leave the
  person believing the payment is thereby stopped — the app receiving the bytes can broadcast them.
- **Result.** `{ bundle_b64, bundle_id, push }`.
  - `bundle_b64` — base64 of the streamable **signed** `SpendBundle`, the same encoding the request
    carried unsigned.
  - `bundle_id` — the bundle's id, hex. A name, never a receipt.
  - `push` — **exactly one of `"not_broadcast"` | `"pending"` | `"unknown"`.**

| `push` | Means |
|---|---|
| `not_broadcast` | no mempool holds this bundle. Either `broadcast` was false, or it was true and the push provably never left — against the caller's own `broadcast: true` the word reads unambiguously as "we tried, nothing received it", and the caller MAY try again |
| `pending` | a mempool accepted the bundle, or already held it. An ACCEPTANCE, not a payment |
| `unknown` | the push left and nothing ruled on it. **The bundle MAY be in a mempool.** The caller MUST NOT rebuild and resend — a second bundle over fresh inputs can pay the recipient twice |

  **There is no `"sent"` and no `"confirmed"`, and there MUST NOT be.** Money is settled when the chain
  says so and not before; a wire word claiming otherwise invites a caller to tell its user something
  the app cannot know.

- **`broadcast: false` means the publisher is NOT CALLED.** Not called and told to skip, not called
  and its answer discarded — not called.
- **A mempool that RULED against the bundle ⇒ `SPEND_REFUSED`** carrying the mempool's reason, never a
  `push` word: the bundle is dead, so all three words would name a journey it is not on.
- **Errors.** The §5.6.7 set, plus `SPEND_REFUSED`. `LOCKED` = the account is locked and an unlock
  would help; `SIGN_DENIED` = the human declined and asking again later is reasonable; `SPEND_REFUSED`
  = the app refused structurally and an identical retry cannot change it; `SIGN_NO_CONFIRMER` = no
  wallet is wired or no ceremony could be raised — never a decline attributed to a user who was never
  asked. **No error response may carry a bundle.**
- **Custody (§908, MUST).** Signing happens IN-PROCESS, in `dig-account`'s money signer under its
  `CustodyScope`. What crosses the loopback is a signed bundle; what crosses to the node is a signed
  bundle. **The node is asked to sign nothing at any point.**

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
| `CAP_NOT_GRANTED` | the frame authenticated, but the pairing does not hold the capability that gates that method — a `third-party` pairing reaching `sign.request` (§5.6.3a), a pairing reaching `spend.request` without the `spend.request` grant (§5.6.10), or a pairing reaching an `identity.*` method it was not granted (§5.6.8) |
| `IDENTITY_BAD_REQUEST` | an `identity.*` request was malformed: missing/oversized field, a `payload`/`envelope` that was not valid base64, or a sealing key of the wrong length (§5.6.8) |
| `UNSEAL_FAILED` | an `identity.unseal` envelope decoded but did not authenticate under this profile's sealing key — wrong recipient, tampered/re-addressed header, or corrupted body (§5.6.8) |
| `ENGINE_UNAVAILABLE` | a `control.request` could not reach a node: none is running, or this app has no engine attached (§5.6.9) |
| `ENGINE_REFUSED` | a `control.request` reached a node and the node refused it, OR the app declined to proxy the method at all (§5.6.9) |
| `RATE_LIMITED` | the caller exceeded the channel's call-volume bound (§5.6.11). Its own code, because answering a throttled `control.request` with `ENGINE_UNAVAILABLE` would tell a caller its user has no node running, which is false. The ONLY code on this channel for which retrying the identical request unchanged is the correct response |
| `SPEND_REFUSED` | a `spend.request` was refused STRUCTURALLY by the money path (§5.6.10): the custody gate refused it outright, the active profile moved during the confirm ceremony, custody is a vault this app cannot honour, or signing failed. Nothing was signed and nothing was sent. Distinct from `SIGN_DENIED`, which is the user declining — repeating an identical `SPEND_REFUSED` request cannot change the answer |

**On `ENGINE_REFUSED` vs `ENGINE_UNAVAILABLE`.** These two codes DO let a caller distinguish a method
the app will proxy from one it will not: an unreachable node yields `ENGINE_UNAVAILABLE` only for a
method that passed the allow-list, while a rejected method yields `ENGINE_REFUSED` regardless. That
distinction is **deliberate and not a leak** — the dapp-reachable set is published in §5.6.9, so it is
not a secret, and the two conditions send a caller to opposite remedies: start a node, versus stop
asking for this method. An earlier revision of this table claimed one code covered both cases so that
a caller could not probe the set; that claim was false, and stating a security property the codes do
not have is worse than not claiming one.

This taxonomy is the byte-identical cross-repo contract the **extension** (SIGN-4) and any in-process
browser equivalent build against; the wire frames (§5.6.2–5.6.5, §5.6.8, §5.6.9, §5.6.10) and codes
above MUST match on both sides. §5.6.11 bounds the VOLUME of those frames rather than defining one.

The list is every subsection of §5.6 that defines a frame. §5.6.1 (topology), §5.6.6 (key custody) and
this subsection state properties rather than frames, and are the only ones deliberately absent.

#### 5.6.11 Call-volume bound (dig-app#277)

Every method on the channel is subject to one call-volume bound. The bound is applied **after the
frame is authenticated and before anything is done on its behalf** — before the capability check of
§5.6.3a and before any method is dispatched.

A caller over its bound MUST receive `RATE_LIMITED` (§5.6.7) and the frame MUST NOT be dispatched. In
particular a throttled `control.request` MUST NOT reach the node: `control.request` turns one inbound
loopback frame into one outbound call to dig-node, so a bound applied to the RESPONSE would reduce
what the caller learns while leaving the node doing the work.

**Two budgets are charged, and either may refuse. BOTH are scoped to the authenticated pairing.**

| Budget | Key | Burst | Sustained |
|---|---|---|---|
| pairing | `pairing_id` | 60 frames | 60 / minute |
| origin | `(pairing_id, origin)` | 30 frames | 30 / minute |

The pairing budget is charged first, then the `(pairing, origin)` budget when the method carries an
`origin`. A frame refused by the pairing budget MUST NOT be charged to the origin budget.

**The origin budget MUST NOT be keyed on the `origin` alone.** The `origin` field is supplied by the
caller and is not authenticated at this point (§5.6.9): a caller may name any origin, including one it
has never connected to and one belonging to another caller. A budget keyed on that value alone is a
resource shared between mutually untrusting principals, and any caller can exhaust it on another
caller's behalf — a pairing holding no capabilities at all, whose every frame is refused
`CAP_NOT_GRANTED`, could otherwise deny a victim's first legitimate request on the victim's own
consented origin. Requiring the origin to be whitelisted first does NOT remedy this, because the
victim's origin is the whitelisted one. Keying on the pair gives every budget exactly one possible
spender.

An implementation MUST bound the length of an `origin` it will key a budget on, and MUST reject an
over-length value rather than truncating it — truncation maps distinct origins onto one budget, which
reinstates the shared-resource defect. A rejected origin is charged to its pairing only.

**These are per-ACTOR bounds, not per-OPERATION bounds.** One pairing's budget is shared across every
method it calls; fifty `identity.unseal` calls leave ten of that minute for `control.request`. Stated
explicitly because "N per minute" is ambiguous for a caller holding several connected origins.

Consequently the origin budget is a SUB-bound of the pairing budget rather than an independent one: it
limits how much of a single pairing's allowance may be spent on any one origin, and says nothing about
one origin reached through several pairings. That is deliberate — a bound spanning pairings is
necessarily a bound one pairing can exhaust against another.

`RATE_LIMITED` MUST NOT indicate WHICH budget was exceeded. A caller told the difference could map the
boundary between an origin and the pairing carrying it.

Budget is earned back continuously rather than reset on a window boundary, so a caller cannot spend a
full allowance at the end of one window and another at the start of the next.

### 5.7 The WalletConnect v2 channel (dig-app#225)

dig-app speaks the wallet half of **WalletConnect v2**, at parity with Sage, so a dapp written
against a Chia WalletConnect wallet can reach a DIG identity. The channel is reached from the tray
only, and terminates entirely inside dig-app.

**The custody boundary is unchanged and is the governing rule (§1, dig_ecosystem#908): the identity
key never leaves the dig-app process and nothing WalletConnect-shaped is ever sent to the engine.**
The engine reads chain and pushes already-signed bundles; it plays no part in this channel.

#### 5.7.1 Pairing

The user pastes a `wc:` URI. It MUST be v2 and MUST parse exactly:

```
wc:<topic>@2?relay-protocol=<protocol>&symKey=<64 hex>[&expiryTimestamp=<unix seconds>]
```

- `topic` MUST be 32 bytes of **lowercase** hex. The topic is string-compared against the relay echo,
  so a case-folded topic subscribes to something whose replies never match.
- `symKey` MUST be exactly 32 bytes of hex. A short key MUST be REFUSED, never padded.
- A `wc:` string of any other version MUST be refused as an unsupported version, distinctly from a
  malformed one — the dapp is out of date, and the person did nothing wrong.
- `expiryTimestamp` is advisory; an unreadable value MUST NOT fail the pairing.

#### 5.7.2 Envelopes

Every relay payload is base64 (**standard alphabet, padded**) over:

| type | layout | used for |
|---|---|---|
| `0` | `00 ‖ iv[12] ‖ sealed` | any message on a topic whose symmetric key both peers already hold |
| `1` | `01 ‖ senderPublicKey[32] ‖ iv[12] ‖ sealed` | the `wc_sessionPropose` response only |

`sealed` is ChaCha20-Poly1305 over the plaintext, with `iv` as the **12-byte** nonce (not the 24-byte
extended form) and an **empty AAD**. The nonce MUST be drawn afresh per envelope from a CSPRNG.

**The envelope header is therefore NOT authenticated.** The type byte, the sender public key and the
nonce all sit outside the AEAD. Implementations MUST NOT derive a key from the header's
`senderPublicKey`; the authenticated source for a peer key is the one inside the decrypted plaintext.
A flipped type byte MUST fail closed rather than reinterpret the layout.

A topic is `sha256(key)`, lowercase hex. The session key is
`HKDF-SHA256(ikm = X25519(self, peer), salt = none, info = empty, 32)` — no salt and no info, fixed by
interoperability rather than chosen.

#### 5.7.3 Relay

The relay is an **untrusted intermediary** that sees topics and ciphertext only. The wallet dials
`<relay-url>/?projectId=<id>&auth=<jwt>` and speaks `irn_subscribe`, `irn_publish` and inbound
`irn_subscription`, acknowledging every delivery it does not consume.

- The auth JWT is `EdDSA` over an ed25519 `did:key` issuer, valid one hour. The key MUST be
  **ephemeral per connection**: a persistent one would let a relay operator link a returning wallet
  for no benefit.
- A `projectId` is REQUIRED by every relay and is supplied by no part of the pairing string. A build
  without one MUST say so plainly and name the remedy; it MUST NOT offer a control that cannot work.
- The read path MUST bound message and frame size **at the websocket**, so an oversized frame is
  refused while being read rather than after it has been assembled in memory.

#### 5.7.4 Session lifecycle

1. subscribe to the pairing topic; read `wc_sessionPropose`;
2. **put the proposal to the person** — the consent window states that the dapp's name and address are
   the dapp's own claims and that DIG cannot verify them;
3. on approval: answer on the pairing topic as a **type-1** envelope carrying the wallet public key,
   subscribe the derived session topic, then publish `wc_sessionSettle` on it;
4. on refusal: answer with a JSON-RPC error so the dapp stops waiting.

The settled session records the methods it settled, and **that stored list — never the wallet's
current capability set — governs what the dapp may later call**, so a wallet upgrade cannot widen an
already-settled session. Settled methods are the INTERSECTION of what the dapp asked for and what the
wallet implements; methods asked for and not granted MUST be disclosed at connect time.

Sessions carry a `SESSION_TTL_SECS` (7 days) expiry and a settled-method list, and the single-use
pairing key is never persisted.

**What ships today: a settled session lives for the run of the app and no longer.** The tray holds one
client for the process lifetime, so a session survives between menu actions — a client rebuilt per
action would report an empty list immediately after a successful connect — but nothing is written to
disk, so closing DIG ends every WalletConnect session. The relay socket is released between journeys;
the sessions are not.

**At-rest persistence is specified and NOT yet wired, and this paragraph says so on purpose.** The
`WcSessionStore` type implements the intended contract — DIGOP1-sealed under the active profile's DEK
(NC-2) including the symmetric key, sealed before anything goes live, and scoped so a session of
another profile is never listed, used, or restored — and its behaviour is covered by tests. It has no
production constructor. Until it is wired, an implementation MUST NOT claim NC-2 coverage for
WalletConnect sessions, and a reader MUST NOT take the type's existence as evidence that sealing
runs.

#### 5.7.5 Methods

The wallet advertises exactly what it implements, so a dapp learns the truth once, at connect:

| method | effect | consent |
|---|---|---|
| `chip0002_connect` | handshake, returns `true` | none |
| `chip0002_chainId` | the CAIP-2 chain id | none |
| `chip0002_getPublicKeys` | the profile identity signing key | none |
| `chia_getCurrentAddress` | the receive address, or `null` when none is derived | none |
| `chip0002_signMessage` | a detached signature over the message | **per request** |

Events: `accountsChanged`, `chainChanged`.

**Spend-bearing and offer methods are deliberately ABSENT and MUST NOT be advertised** until they can
be honoured. A method advertised but unhonoured is worse than one a dapp can see is missing, because
the dapp has already told the person their transaction is on its way.

#### 5.7.6 Signing

Signing MUST go through the same in-process signer and the same native confirm window as every other
signature in the app. Per request, in this order:

1. refuse a method that is not advertised;
2. refuse a method **this session** did not settle;
3. parse;
4. raise the native confirm — **the session grant is permission to ASK, never permission to sign**;
5. re-authorise through the session lock;
6. re-check the session grant, because step 5 is a state transition that unlocks into whichever
   profile is active by the time it runs;
7. sign fallibly — a locked signer MUST yield an error, never a success envelope carrying an empty or
   bogus signature.

The signed bytes MUST be the domain-separated, length-prefixed
`sign_callback_message("walletconnect:chip0002_signMessage", payload)` — **never the dapp's raw
bytes**. Signing arbitrary attacker-chosen bytes with the identity key is a signing oracle; the
transport-specific tag additionally prevents a WalletConnect signature being replayed as a loopback
one, though both use the same key and construction.

Dapp-supplied text drawn on a consent window MUST have its whitespace collapsed and its length
capped. The window's renderer draws glyphs literally, so this is not about markup — it is about
LAYOUT, which a hostile string can still forge into what looks like the wallet's own chrome. This is
the same requirement stated for every consent heading in §5.6.1, and it is discharged by the single
shared neutralisation named there. The WalletConnect surface is in scope for it precisely because it
needs no pairing and no extension: a remote dapp's self-declared url and name reach a signing window
on an ordinary session.

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

- **Transport = mTLS for node-class clients — on the surfaces that offer it.** dig-app (and `diga`,
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

dig-app-core is the identity-agent library; the `dig-app` and `diga` binaries are thin shells over it.
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
| `keystore` | hold / unlock / sign; DIGOP1 sealing; rotation; plus the RETIRED OS-credential-store seam, kept for migration only — it is NOT a custody primary and no boot, unlock or sign path reads a password from it (§3.2a), and there is no sealed-file fallback | U4 |
| `account` | master-HD custody harness (SECURITY-CRITICAL, 2.0.0): [`registry`] (default/active account tracking), [`residency`] (live, lockable unlocked-account home with fail-closed [`ResidencySigner`]/[`ResidencySealer`]), [`money`] (authorize-before-sign [`SpendSummary`] gate + signing), [`sealer`] (profile DEK derivation), [`ceremony`]/[`auth`]/[`lifecycle`] (confirmation/enrollment/lifecycle) | 2.0.0 |
| `wallet` | per-profile wallet state (address/coins/balance, DIGOP1-sealed per-profile), engine broadcast seam (`WalletEngine`), signed bundle encoding | U5 |
| `events` | event-driven wallet UI seam: `EventFeed`/`EventSink` + `EventDriver` (cursor/filter, `catch_up` backfill, graceful resync) + reactive `WalletView` (§3.7) | #1008 |
| `notify` | debounced native funds-activity notifications off the event stream (§3.7, #970) | #970 |
| `profile_image` | profile-image intake (#3010): bounded decode, fit-within-500x500 resize, PNG/JPEG re-encode, base64 data URL — outside the `gui` feature, pure bytes-to-bytes | #3010 |
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

**Every dig-app binary — `dig-app` and `diga` — MUST answer `--version`.** This is not a convenience: it is
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
the app: the tray menu for a person at a desktop, and `diga` for a terminal.

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
  shell) and `diga` (CLI) — under the canonical stem `<bin>-<ver>-<os>-<arch>[.exe]`. Richer OS
  packages (Windows tray installer / macOS `.pkg` / Linux `.deb`) are produced by the dig-installer
  wiring (a separate work unit) consuming these binaries.
- **The supported OS/arch set (MUST)** is `windows-x64`, `macos-x64`, `macos-arm64`, `linux-x64` and
  `linux-arm64`. Both Linux arches additionally publish a **headless** `dig-app` variant, stemmed
  `dig-app-<ver>-linux-<arch>-headless`: the same shell built `--no-default-features`, linking no
  desktop stack at all. That variant exists because the tray build hard-links GTK 3, and a missing
  library kills a process in the dynamic loader — before `main` — so the shell's own headless
  degradation (§4) can never be reached on a server image that lacks GTK. `diga` has no headless
  variant; it links no desktop stack in either configuration.
- **A Linux arm64 artifact MUST be proved by EXECUTION, not by a successful compile (MUST).** Each
  published `linux-arm64` binary is run on a native arm64 host before the release attaches it — the
  headless `dig-app` and `diga` against a base image carrying no desktop libraries, and the tray
  `dig-app` against one carrying the GTK 3 runtime. A binary that builds but does not start is worse
  than a published absence, because an absence is at least honest about what the user can install.
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
  agent, not a one-shot invocation) and holds the guard for the process lifetime. `diga` — a
  short-lived CLI — installs it as run context `cli` at the top of its own `main`, resolving the
  SAME per-user log directory `dig-app` writes to (`dig-logging` SPEC §3), so the two processes'
  records interleave in one place. A logging-install failure is reported on stderr and swallowed —
  it MUST NOT stop the agent from starting.
- **Levels — used by MEANING, not uniformly.** `error!` a broken invariant; `warn!` a denied `sign`
  callback, a failed unlock, a rejected profile create/select (duplicate/invalid DID, not found), or
  a failed engine-proxy call; `info!` sparse lifecycle (agent starting, engine endpoint resolved,
  session attach/detach, identity sealed/unlocked/removed, profile created/selected, boot re-unlock
  complete); `debug!` per-command routing (the gateway's local-vs-engine classification, `diga`'s
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
| U7 | CLI/RPC gateway (`diga` + RPC route through dig-app) |
| U8 | dig-installer wiring (engine daemon + per-user agent autostart) |
| U9 | migration of the legacy single-identity install into a sealed default profile |
| U10 | coherence: SYSTEM.md + canonical + docs.dig.net + runbooks + NC "Satisfied by" links + regression tests |

[dig_ecosystem#908]: https://github.com/DIG-Network/dig_ecosystem/issues/908
[dig_ecosystem#771]: https://github.com/DIG-Network/dig_ecosystem/issues/771
[dig_ecosystem#856]: https://github.com/DIG-Network/dig_ecosystem/issues/856
[dig_ecosystem#906]: https://github.com/DIG-Network/dig_ecosystem/issues/906
[dig_ecosystem#950]: https://github.com/DIG-Network/dig_ecosystem/issues/950
