# dig-node-control-interface — normative specification

This document is the authoritative contract for the client ⇄ dig-node **control interface**: how a
client (the CLI `dign`, the browser extension, dig-app, hub) controls and queries a running dig-node.
An independent reimplementation of either side MUST conform to this specification byte-for-byte. Where
this document and the code disagree, the conformance KATs in `src/kats.rs` are the tie-breaker.

Layering: this file is the repo's own contract; the cross-repo interaction map is the superproject
`SYSTEM.md`; the session/transport envelope this catalog rides over is `dig-ipc-protocol`'s `SPEC.md`;
the node↔node peer wire is `dig-rpc-protocol`'s `SPEC.md`. All MUST agree.

## 1. Scope and boundary

`dig-node-control-interface` owns the **client↔node CONTROL method catalog**: the method names,
parameter/result types, and error taxonomy for controlling and querying a running dig-node — status,
configuration, cache, hosted/pinned stores, §21 whole-store sync, the peer network, subscription
lifecycle, the auto-update beacon, live log level, and the control-token pairing handshake.

It does **not** own:
- the node↔node peer wire (dig-rpc-protocol's PublicRead + Peer tiers), or
- the local session/signing handshake and transport a client authenticates over (dig-ipc-protocol).

This crate is transport-agnostic: the same method catalog is carried over the dig-ipc-protocol local
session, or over loopback-mTLS + a signed control token for clients reached via HTTP/WebSocket
(CLAUDE.md §5.3). Consumers select the transport; this crate defines only the payload contract that
rides over it.

## 2. Roles and trust boundary

- **Client:** a user-facing surface (CLI, extension, app, hub) that wants to control or query a
  running dig-node. Authenticates over whichever transport is in play before issuing control calls.
- **Node (server):** the identity-agnostic engine dispatching control calls against its live state
  (config, cache, peer table, subscriptions).

### 2.1 Authorization

- Every `control.*` method is **token-gated** EXCEPT the open surface, which is whatever the §4
  method table marks `no` in its Token column — that table is authoritative and this sentence must
  never restate it as a count. Today it is the pairing bootstrap (`pairing.request`,
  `pairing.poll`), the wallet chain reads (`control.wallet.balance` / `.coins` / `.coinById` / `.coinSpend` /
  `.coinsByParent` /
  `.peak` / `.syncStatus`), which need only public chain data, and `control.peerCounts`, which
  discloses three integers about this node's own connectivity. For every other method the caller MUST
  present the node's local control token
  as the `X-Dig-Control-Token` request header (preferred) or a `params._control_token` field. The
  token is a 64-hex value the node mints at first run into its machine-wide state dir with a
  restrictive ACL; possession of the on-disk token is authorization. A call without a valid token MUST
  be rejected with `UNAUTHORIZED` (-32030). Token comparison MUST be constant-time.
- The two **pairing-bootstrap** methods `pairing.request` / `pairing.poll` are **OPEN** (no token), so
  a token-less client (e.g. an MV3 extension that cannot read a local file) can obtain a scoped token
  after local operator approval.
- The **MASTER** control token specifically, never a scoped paired token, is required by every
  method whose effect OUTLIVES the token that invoked it. A paired controller can drive ordinary
  mutations, but anything it could still be holding after `control.pairing.revoke` — the remedy for
  a compromised paired app — is outside its tier. Two groups qualify:
  - the three **pairing-administration** methods (`control.pairing.list` / `.approve` / `.revoke`):
    a paired controller MUST NOT mint more tokens or revoke itself;
  - the two **trusted-Chia-peer mutations** (`control.chiaPeers.add` / `.remove`): `add` writes a
    standing peer entry that is believed WITHOUT corroboration, revocation does not remove it, and
    after the call the caller no longer needs the token at all. `control.chiaPeers.list` is a read
    and stays on the ordinary tier.

## 3. Envelope

Requests and responses are JSON-RPC 2.0.

- **Request:** `{"jsonrpc":"2.0","id":<id>,"method":<name>,"params":<object>}`. `id` is a number,
  string, or null and MUST be echoed on the response. `params` is always an object (`{}` for a
  no-parameter method).
- **Success response:** `{"jsonrpc":"2.0","id":<id>,"result":<value>}` (no `error` key).
- **Error response:** `{"jsonrpc":"2.0","id":<id>,"error":{"code":<int>,"message":<str>,"data":{"code":<SYMBOL>,"origin":<str>}}}`
  (no `result` key). A client MUST branch on `error.data.code` (the stable UPPER_SNAKE symbol), never
  on the human `message`.

## 4. Method catalog

Method names are stable wire contract. `Auth` = requires the control token; `Master` = requires the
master token specifically; `Routing` = how the node resolves it (`owned` by the service shell,
`delegated` to the engine, `open` bootstrap).

| Method | Auth | Routing | Params | Result |
|---|---|---|---|---|
| `control.status` | yes | owned | — | `StatusResult` |
| `control.config.get` | yes | owned | — | `ConfigResult` |
| `control.config.setUpstream` | yes | owned | `{upstream:string}` | `{upstream, requires_restart}` |
| `control.log.setLevel` | yes | owned | `{filter:string}` | `{filter}` |
| `control.cache.get` | yes | owned | — | `CacheView` |
| `control.cache.setCap` | yes | owned | `{cap_bytes:u64}` | `{cap_bytes}` (floored 64 MiB) |
| `control.cache.clear` | yes | owned | — | `{cleared:true}` |
| `control.hostedStores.list` | yes | owned | — | `{stores:[HostedStore]}` |
| `control.hostedStores.pin` | yes | owned | `{store:"storeId[:root]"}` | `{store_id, root, pinned, fetch}` |
| `control.hostedStores.unpin` | yes | owned | `{store}` | `{store_id, unpinned, evicted_capsules}` |
| `control.hostedStores.status` | yes | owned | `{store}` | `{store_id, pinned, capsule_count, total_bytes, capsules}` |
| `control.capsule.fetch` | yes | owned | `{store, root}` | `{store, root, status}` (`"started"`\|`"already_cached"`\|`"unavailable"`) |
| `control.sync.status` | yes | owned | — | `{available, method, pinned_total, pinned_synced, whole_store_trigger_supported}` |
| `control.sync.trigger` | yes | owned | `{store:"storeId:root"}` | `{store_id, root, status, size_bytes, served_root}` |
| `control.updater.status` | yes | owned | — | (proxied beacon status) |
| `control.updater.setChannel` | yes | owned | `{channel:string}` | (proxied) |
| `control.updater.pause` | yes | owned | `{until?:u64}` | (proxied) |
| `control.updater.resume` | yes | owned | — | (proxied) |
| `control.updater.checkNow` | yes | owned | — | (proxied) |
| `control.pairing.list` | master | owned | — | (pending + issued tokens) |
| `control.pairing.approve` | master | owned | `{pairing_id:string}` | `{approved, client_name, token_id}` |
| `control.pairing.revoke` | master | owned | `{token_id:string}` | `{revoked, token_id}` |
| `control.peerStatus` | yes | delegated | — | (peer-pool snapshot; each peer entry carries `software`) |
| `control.peerCounts` | no | delegated | — | `{dig_peer_count:u32\|null, chia_peer_count:u32\|null, known_dig_peer_count:u32\|null}` |
| `control.peers.connect` | yes | delegated | `{peer:string}` | `{connected, peer_id}` |
| `control.peers.disconnect` | yes | delegated | `{peer:string}` | `{disconnected, peer_id}` |
| `control.chiaPeers.add` | master | owned | `{ip:string}` | `{added, ip, port, corroboration_bypassed, notice:string}` |
| `control.chiaPeers.list` | yes | owned | none | `{peers:[{ip,port,peak_height:u32\|null,user_managed,banned}]}` |
| `control.chiaPeers.remove` | master | owned | `{ip:string, ban?:bool}` | `{outcome:"removed"\|"no_such_peer", ip, banned}` |
| `control.subscribe` | yes | delegated | `{store_id:string, kind?:"capsule"\|"profile"}` | `{subscribed, added, store_id, kind}` |
| `control.unsubscribe` | yes | delegated | `{store_id:string}` | `{subscribed, removed, store_id}` |
| `control.listSubscriptions` | yes | delegated | — | `{subscriptions:[string], count}` |
| `control.wallet.balance` | no | delegated | `{address:string, asset:Asset}` | `{balance, pending, source, synced, peak_height}` |
| `control.wallet.coins` | no | delegated | `{address:string, asset:Asset}` | `WalletCoinsResult` |
| `control.wallet.coinById` | no | delegated | `{coin_id:string}` | `WalletCoinByIdResult` |
| `control.wallet.coinSpend` | no | delegated | `{coin_id:string}` | `WalletCoinSpendResult` |
| `control.wallet.coinsByParent` | no | delegated | `{parent_coin_id:string, after_coin_id?:string, limit?:u32}` | `WalletCoinsByParentResult` |
| `control.wallet.arrivals` | yes | delegated | `{after_seq:u64=0, limit?:u32}` | `WalletArrivalsResult` |
| `control.wallet.peak` | no | delegated | — | `{peak_height:u32\|null, synced:bool}` |
| `control.wallet.syncStatus` | no | delegated | — | `{phase:"not_started"\|"syncing"\|"synced"\|"no_wallet_enrolled"\|"wallet_not_unlocked", peak_height:u32\|null, chia_peer_count:u32\|null, watched_addresses:u32\|null, subscription_peer_count:u32\|null, chia_peer_peak_height:u32\|null}` |
| `control.wallet.broadcast` | yes | delegated | `{signed_bundle_hex:string}` | `WalletBroadcastResult` |
| `control.wallet.watch` | yes | delegated | `{public_keys:[string]}` (each lowercase 96-hex, `0x` accepted) | `{added:u32, watched:u32}` |
| `control.wallet.unwatch` | yes | delegated | `{public_keys:[string]}` | `{removed:u32, watched:u32}` |
| `control.wallet.watched` | yes | delegated | — | `{public_keys:[string]}` |
| `control.wallet.reservations.held` | yes | delegated | — | `{reserved:[ReservedCoin], as_of_unix:u64}` |
| `control.wallet.reservations.reserve` | yes | delegated | `{coin_ids:[string], ttl_secs?:u64}` | `{reservation_id, coin_ids, expires_at_unix, ttl_secs}` |
| `control.wallet.reservations.release` | yes | delegated | `{reservation_id:string}` | `{released:bool, coin_ids:[string]}` |
| `control.spends.list` | yes | owned | `{since_ms?:u64, until_ms?:u64, store_id?:string, kind?:string, status?:string, after_id?:string, limit?:u32}` | `{spends:[AutomatedSpend], complete:bool, cursor:string\|null, unreadable_lines:u32}` |
| `control.collateral.requirement` | yes | owned | — | `CollateralRequirementResult` (`{state:"known", epoch, protocol_version, required_per_store_dig_base_units, stores, owners, multiplier_micros, handicap_dig_base_units}` \| `{state:"unknown", reason}`) |
| `control.collateral.margin.get` | yes | owned | — | `{margin_bp:u64}` |
| `control.collateral.margin.set` | yes | owned | `{margin_bp:u64}` | `{margin_bp:u64}` |
| `control.collateral.buffer` | yes | owned | — | `CollateralBufferResult` (`{state:"known", epoch, protocol_version, funding_state, recommended_buffer_dig_base_units, spendable_dig_base_units, pairs_served_by_this_node, required_per_store_dig_base_units, margin_bp, overlap_dig_base_units, escalation_headroom_dig_base_units, horizon_epochs, escalation_ceiling_micros}` \| `{state:"unknown", reason}`) |
| `control.profile.putBody` | yes | delegated | `{store_id:string, root:string, body_b64:string}` | `{stored, store_id, root, body_bytes}` |
| `control.profile.getBody` | yes | delegated | `{store_id:string, root:string}` | `{store_id, root, body_b64:string\|null, body_bytes}` |
| `pairing.request` | no | open | `{client_name:string}` | `{pairing_id, pairing_code, expires_ms}` |
| `pairing.poll` | no | open | `{pairing_id:string}` | `{status, token?}` |

### Trusted Chia peers

A trusted Chia peer BYPASSES CORROBORATION. A conforming node treats dialled Chia peers as
untrusted and believes a chain answer only when several independently-queried peers agree
(NC-12); a peer added through `control.chiaPeers.add` is exempted from that agreement and is
believed on its own. An implementation MUST state that cost where a person adds one, and MUST
serve `control.chiaPeers.*` from the SAME peer store its wallet replica reads -- a second peer
list would let the trusted set and the consulted set drift apart silently.

The trust NC-12 authorises is the operator declaring a node THEIR OWN. Every surface an
implementation offers MUST say that, and MUST NOT widen it to a node the operator merely vouches
for: the entry carries unbounded authority over the wallet replica precisely because the operator
controls both ends, which is false of somebody else's node.

`control.chiaPeers.add` and `control.chiaPeers.remove` REQUIRE THE MASTER TOKEN. A paired token
MUST NOT reach them. `add` writes standing authority that outlives the token that wrote it --
after the call the caller no longer needs the token, and `control.pairing.revoke` removes the token
but not the peer entry, so a paired token able to call `add` escapes the remedy for a compromised
paired app. `control.chiaPeers.list` is a read that confers nothing and stays on the ordinary
token tier.

`ip` is a BARE IP LITERAL in canonical form: `IpAddr` display -- dotted-quad for v4, and for v6 the
RFC 5952 lowercase maximally-compressed form, without brackets and without a zone id. A node MUST
canonicalise on the way in, MUST reject anything that is not an IP literal (a hostname, an empty
string, `ip:port`, a CIDR block, a bracketed form), and MUST match `add`, `remove` and `list`
against that one form -- otherwise an operator who spells an address two ways un-trusts nothing.
When an address and a port are joined, v6 MUST be bracketed: `::1` and `8444` written as
`::1:8444` is a DIFFERENT valid address, so the mistake survives validation.

`control.chiaPeers.remove` MUST report whether it removed anything. `outcome` is `"removed"` when a
matching entry existed and `"no_such_peer"` when nothing matched; a client MUST surface the second
as a failure to act. `remove` is the only way to un-trust a peer, so a success it cannot withhold
is a lie about whether a privileged action took effect.

`corroboration_bypassed` reports the RESULTING trust state, not the request: a node MUST report
`false` where the entry did not end up trusted. `notice` carries the node's own warning text and
MUST be non-empty, MUST name the corroboration bypass, and is rendered verbatim -- it exists so a
client quotes the node rather than restating the cost and drifting from it.

A ban is exact-match on one address, local to this node, persisted until removed, bounded at 256
entries (oldest evicted on overflow), enumerated by `control.chiaPeers.list` as `banned: true`, and
cleared by `remove` with `ban: false`. Clearing a ban that way MUST NOT grant trust; `add` also
un-bans, but it confers the bypass, so it MUST NOT be the only route back.

The wallet CHAIN READS (`control.wallet.balance` / `.coins` / `.coinById` / `.coinSpend` /
`.coinsByParent` / `.peak` /
`.syncStatus`)
are served WITHOUT a control token, because each needs only public chain data — an address or a coin
id, never a seed, a key, or a signature. `control.peerCounts` is open for a second reason: it
discloses three integers about this node's own connectivity and no address, endpoint or secret. The
`Token` column above is authoritative; the open set is deliberately named here rather than counted,
so that adding a method cannot leave a stale number behind. Five wallet methods are token-gated.
`control.wallet.broadcast` puts bytes on the network. `control.wallet.watch` / `.unwatch` aim what
this node follows, so they are mutations. `control.wallet.watched` and `control.wallet.arrivals` are
reads and are gated all the same, because each takes nothing from the caller and so answers with this
node's OWN state — the enrolled keys, or the watched puzzle hashes and the receive history behind
them. `control.wallet.arrivals` takes only a cursor,
so its answer names this node's OWN watched puzzle hashes and the receive history behind them: the
chain facts are public, the association between this node and those addresses is not. Membership of
the open set turns on WHO NAMES THE ADDRESS, not on whether the data is on chain. That difference is normative for clients, because the two refusals demand
opposite remedies — see §4.2.

### 4.1 Result field definitions

- **`StatusResult`**: `{running:bool, service:string, version:string, commit:string, protocol:string,
  uptime_secs:u64, addr:string, upstream:string, cache:CacheView, hosted_store_count:u64,
  cached_capsule_count:u64, pinned_store_count:u64, sync:{available:bool}}`.
- **`ConfigResult`**: `{addr:string, port:string, upstream:string, upstream_override:string|null,
  cache_dir:string, cache_shared:bool, config_path:string, sync_available:bool}`.
  `upstream_override` MUST be present as `null` when unset (never omitted).
- **`CacheView`**: `{cap_bytes:u64, used_bytes:u64, dir:string, shared:bool}`.
- **`HostedStore`**: `{store_id:string, pinned:bool, capsule_count:u64, total_bytes:u64,
  capsules:[CapsuleEntry]}`.
- **`CapsuleEntry`**: `{capsule:"storeId:root", root:string, size_bytes:u64, last_used_unix_ms:u64}`.
- **`pairing.poll` token**: the `token` field MUST be omitted while `status` is not `approved`, and
  present exactly once after approval.
- **`Asset`** — the asset a wallet read is denominated in. Exactly three wire forms are valid:

  | Form | JSON | Meaning |
  |---|---|---|
  | XCH token | `"xch"` | Native Chia, denominated in mojos. |
  | $DIG token | `"dig"` | The $DIG CAT, asset id `a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81`. |
  | CAT by asset id | `{"cat":"<64-hex>"}` | Any CAT, named by its asset id (TAIL hash). |

  The asset id is lowercase 64-hex, unprefixed, on the wire. A `0x` prefix and uppercase digits MUST
  be ACCEPTED on input and normalized away; neither MUST ever be emitted. Any other string, an object
  with any other or additional key, and a hex string of any other length MUST be REJECTED — an
  unrecognized asset MUST NOT be defaulted to XCH or to $DIG.

  **$DIG has exactly one identity.** `"dig"` and `{"cat":"a406…2f81"}` MUST denote the SAME asset and
  MUST compare equal. An implementation MUST NOT model $DIG as a value distinct from its own asset
  id: were the two inequal, a balance or coin list filtered by one spelling would silently omit the
  holdings carrying the other, reporting part of a balance as though it were all of it.

  **$DIG MUST still be EMITTED as `"dig"`**, not as its tagged form. `"xch"` and `"dig"` are the only
  forms a node or client built before asset ids were nameable understands, so emitting the tagged
  form for $DIG would break that compatibility direction. The tagged form is for every OTHER CAT.

  Consumers MUST model this as a two-case type — native XCH, or a CAT identified by asset id — with
  $DIG a named constant of the CAT case rather than a third case.

- **`WalletCoinsResult`**: `{coins:[WalletCoinRecord], source:"db"|"fallback"|null, synced:bool,
  peak_height:u32|null}`. `source`/`synced`/`peak_height` carry exactly the meanings defined for
  `WalletBalanceResult` below. `coins` MUST list the address's spendable coins for the requested
  asset (XCH coins sit AT the puzzle hash; CAT coins are HINTED to it).

  `coins:[]` MUST mean the node consulted a chain and the address holds nothing. A node that could
  NOT consult a chain MUST return the matching §5 wallet error instead — never an empty list. This
  is normative and not a quality-of-implementation note: an empty list on an unreachable chain tells
  a holder of funds that they hold nothing, and a spend built on that answer refuses with a
  shortfall that is not true.
- **`WalletCoinRecord`**: `{coin_id:string, asset:Asset|null, amount:u64,
  parent_coin_info:string, puzzle_hash:string, created_height:u32|null, spent_height:u32|null}`. All
  hashes are lowercase 64-hex, unprefixed. `created_height:null` means the coin is known only from
  the mempool; `spent_height:null` means unspent. The first three fields are a strict SUPERSET of
  dig-app's frozen `CoinRecord`.

  `asset:null` MUST mean THE READ DID NOT CLASSIFY THE COIN. It MUST NOT be read as "no asset" and
  MUST NOT be defaulted to XCH. A singleton, a CAT and a plain XCH coin are indistinguishable from a
  coin id alone — telling them apart requires inspecting the puzzle, which a coin-record read does
  not do. `control.wallet.coins` MUST report the concrete asset it was SCOPED to and MUST NOT emit
  `asset:null`: dig-app's frozen `CoinRecord` requires a non-null asset there, so `null` is a hard
  deserialization failure, not a degraded read. `control.wallet.coinById` and `control.wallet.coinsByParent` MUST report `null`: neither a coin id
  nor a parent id scopes a read to an asset.
- **`WalletCoinByIdResult`**: `{coin:WalletCoinRecord|null, source:"db"|"fallback"|null, synced:bool,
  peak_height:u32|null}`. ONE coin, named by its own id, SPENT OR UNSPENT.

  `coin:null` MUST mean the node consulted a chain and it holds no coin with that id. A node that
  could NOT consult a chain MUST return the matching §5 wallet error instead — never `coin:null`.
  These MUST NOT be collapsed: the first says stop waiting, the second says retry the read. A caller
  that conflates them reports a mint whose coin does not exist as pending forever, with the funds
  already spent.

  The `coin` key MUST be present on every response; `null` is a verdict and MUST NOT be conveyed by
  omitting the field.

  `coin_id` MUST be lowercase 64-hex; a `0x` prefix MUST be accepted on input and MUST NOT be
  emitted. Any other value MUST be refused as `-32602 INVALID_PARAMS` BEFORE any chain is consulted,
  so that an unanswerable question never wears the shape of an answer. There is no `asset`
  parameter: a coin id is not asset-scoped.

  `source` names which tier answered, and every freshness field describes THAT tier, exactly as for
  `WalletBalanceResult` below: a `"fallback"` answer MUST report `synced:false` and
  `peak_height:null`; a `"db"` answer means the node's own replica answered and MUST report
  `synced:true` and that replica's peak. A caller needing a height to bound a confirmation against
  reads `control.wallet.peak`.

  **A node MUST NOT answer `coin:null` from a view that could not have held the coin.** A replica
  that is not caught up, or a local index that is address-scoped rather than a full chain view, has
  not established absence — only its own inability to see. Such a node MUST return `-32040
  WALLET_NO_CHAIN_SOURCE` or `-32042 WALLET_READ_FAILED`. This is normative and load-bearing: the two
  coins this method exists to observe are a created coin sitting at no wallet address and a funding
  coin already spent, both of which an address-scoped view is GUARANTEED to miss, so a `coin:null`
  from one would report a mint that really happened as never having happened, with the funds gone.
  `-32041 WALLET_NOT_SYNCED` is not used here — it names a wallet-scoped branch this method does not
  have — but a node that is not synced still MUST NOT manufacture a negative answer; it errors.

  This method is how a pushed spend becomes OBSERVABLE. `control.wallet.broadcast`'s `accepted:true`
  reports mempool admission only; only a buried confirmation of the created coin is evidence.
  `control.wallet.coins` cannot supply it — it answers by ADDRESS and lists UNSPENT coins only, so it
  sees neither a created coin sitting at no wallet address nor a funding coin the spend consumed.
- **`WalletCoinSpend`**: `{coin:WalletCoinRecord, puzzle_reveal:string, solution:string}`. The chia
  `CoinSpend` in this contract's wire form: the coin that was consumed plus the two programs that
  consumed it, each lowercase hex of its serialized CLVM.

  `puzzle_reveal` MUST tree-hash to `coin.puzzle_hash`. A reveal is supplied by a PEER and a peer can
  lie, so the claim is deliberately self-checking: a node MUST verify it and MUST fail closed with a
  §5 wallet error — never return a spend carrying an unverified reveal — when the hashes disagree or
  the reveal does not parse. A caller MAY re-derive the same check from the two fields it is handed.

  `coin.spent_height` MUST be non-null. A spend exists only because the coin was spent, so a spend
  reporting an unspent coin is a contradiction.
- **`WalletCoinSpendResult`**: `{spend:WalletCoinSpend|null, source:"db"|"fallback"|null,
  synced:bool, peak_height:u32|null}`. THE SPEND that spent one coin, named by that coin's own id.
  A spend has no id of its own on chain, so `coin_id` names the SPENT COIN and takes the identical
  form and validation `control.wallet.coinById` takes.

  `spend:null` MUST mean the node consulted a chain and it holds no spend of that coin. Absence has
  TWO legitimate causes — the coin is UNSPENT, or the chain holds no such coin — and this method
  deliberately does not distinguish them; a caller needing to MUST ask `control.wallet.coinById`,
  whose `coin:null` separates them.

  A node that could NOT consult a chain MUST return the matching §5 wallet error instead — never
  `spend:null`. This is the money-critical distinction in the whole family: a caller following a
  singleton forward reads "no spend" as *this is the current tip* and stops walking, so a failure
  disguised as absence makes a superseded coin look like the tip and the spend built against it is
  invalid. The rule barring a negative answer from a view that could not have held the subject
  (stated for `WalletCoinByIdResult` above) applies here unchanged.

  The `spend` key MUST be present on every response; `null` is a verdict and MUST NOT be conveyed by
  omitting the field.

  `source` and the freshness fields follow the same tier rule as every other wallet read.
- **`WalletCoinsByParentResult`**: `{coins:[WalletCoinRecord], complete:bool, cursor:string|null,
  source:"db"|"fallback"|null, synced:bool, peak_height:u32|null}`. One PAGE of the DIRECT children
  created by spending one coin, named by that parent's coin id.

  Exactly ONE HOP. The list is what the named parent's spend created and nothing further: not a
  lineage, not a subtree, not transitive. A node MUST NOT recurse — an unbounded server-side walk
  over caller-supplied input is work the caller cannot bound, and a partial walk returned as a
  complete one is a lineage with a silent hole in it. A caller composes a lineage from repeated
  single hops.

  `coins:[]` MUST mean the node consulted a chain and that parent created no children it knows of,
  typically because the parent is unspent. A node that could NOT consult a chain MUST return the
  matching §5 wallet error instead — never an empty list. A caller walking a singleton forward reads
  an empty list as *this is the tip*.

  Every record MUST report `asset:null`: naming a coin by its parent classifies nothing.

  **The answer is BOUNDED and PAGED.** This is the only open wallet read whose cardinality is
  unbounded — every other returns a single record or is already paged — and there is NO request rate
  limiting on the control plane, so this bound is the only limit on the work a token-less caller can
  ask for. On the fallback tier the node forwards the caller's identifier to a third-party coinset
  oracle, so an unbounded page is unbounded work against another party's service.

  `limit` MUST be between 1 and `COINS_BY_PARENT_MAX_LIMIT` (1000); an omitted `limit` means
  `COINS_BY_PARENT_DEFAULT_LIMIT` (100). An out-of-range or zero `limit` MUST be REFUSED as `-32602
  INVALID_PARAMS` and MUST NOT be clamped — a caller resumes from a page boundary, so a silently
  shrunk page returns a cursor for a position the caller never asked about. (This deliberately
  differs from `control.wallet.arrivals`, where a node MAY clamp: that read's cursor is a ledger
  position the node owns, whereas this one's is a row the caller was handed.) `0` is refused
  separately: a page that holds nothing never makes progress. The maximum is derived from
  dig-ipc-protocol's `MAX_FRAME_BYTES` (1 MiB) — a worst-case `WalletCoinRecord` is ~350 bytes, so
  1000 records is ~350 KB, about a third of the frame, leaving headroom for the envelope.

  `complete` MUST state whether the page carries the LAST child. A node MUST NOT report
  `complete:true` on a page it truncated. A caller MUST NOT infer completeness from the page length:
  a node may return a short page for its own reasons, and a child set that is an exact multiple of
  the page size makes the final full page indistinguishable from a truncated one. This is normative
  and load-bearing — a caller walking a lineage reads "no more children" as the end of a branch, so a
  truncated page that looks whole presents a partial lineage as a complete one.

  `cursor` MUST be the `coin_id` of the LAST record actually returned, or `null` for an empty page,
  and the key MUST always be present. A caller resumes by passing it as `after_coin_id`. There is
  deliberately no chain-head marker on this type to resume from by mistake.

  A node MUST return children in ASCENDING `coin_id` order and MUST keep that order stable across the
  pages of one walk; `after_coin_id` means strictly after that id in that order. Without a fixed
  order a cursor names no position and a walk silently repeats and skips children. Coin ids are
  fixed-length lowercase hex, so ascending lexicographic and ascending 32-byte numeric order are the
  same order.

  The parameter is spelled `parent_coin_id`, NOT `coin_id`. The coin named is the one being asked
  ABOUT and is never the coin returned; a shared field name would make a recursive reading of the
  method plausible from the request alone.
- **`WalletPeakResult`**: `{peak_height:u32|null, synced:bool}`. The node's chain peak, independent
  of any address. `peak_height:null` means the node tracks NO height — it MUST NOT be read as height
  zero, which every block is trivially above. A caller bounding a claimed confirmation MUST treat
  `null` as unknown and fail closed.

  `synced` here reports ONLY that the replica's initial catch-up completed; it MUST NOT be read as
  "the wallet is caught up AND connected", which is `WalletSyncStatusResult.phase == "synced"` and
  is strictly stronger. Neither is a freshness guarantee.
- **`PeerCountsResult`**: `{dig_peer_count:u32|null, chia_peer_count:u32|null,
  known_dig_peer_count:u32|null}`. How many peers this node holds on EACH network, and how many DIG
  peers it knows of. The two networks are unrelated and their counts move independently.

  `dig_peer_count` MUST be the count of peers on the DIG content/gossip network (port 9445) — the
  node's `connected_peers`, the same figure `control.peerStatus` reports. `chia_peer_count` MUST be
  the count of CHIA full-node peers the wallet's chain sync holds, and MUST be the SAME observation
  `WalletSyncStatusResult.chia_peer_count` reports: a conforming node MUST serve both from ONE
  source, and the two MUST agree within a single node's view.

  Neither field may be named `peers`, `connected_peers` or `peer_count`. A name that does not state
  its network forces a consumer to know which number it is holding, and a consumer that guesses
  wrong fails SILENTLY — a plausible integer in a right-looking place.

  For each count, `0` MUST mean the node observed that network and found nothing connected, and
  `null` MUST mean the node cannot observe the count. A network that is not running is UNKNOWN and
  MUST NOT be reported as `0`, which would assert that nothing is connected to a network never asked.

  `control.peerStatus`'s `relay.peer_count` counts peers connected to THE RELAY, not to this node.
  It is frequently the only non-zero number on a node connected to nothing, and it is NEVER the
  answer to "how many peers does this node have" — `dig_peer_count` is.

  `known_dig_peer_count` MUST be the number of DIG peers this node has LEARNED OF — the size of its
  own discovered-peer address book — whether or not it is connected to them. It exists so that a
  client can tell a REACHABILITY fault (`dig_peer_count: 0` beside a large known count) apart from a
  DISCOVERY fault (`0` beside `0`); those have different remedies and, before this field, rendered
  as the same zero. It MUST NOT be derived from `dig_peer_count`.

  `known_dig_peer_count` is ONE node's local view and is therefore a LOWER BOUND. It MUST NOT be
  presented, by the node or by any client, as the size of the DIG network or as a total peer count:
  it omits every peer this node has not been introduced to, every peer reachable only through a
  relay it does not use, and every address book entry evicted under the node's own bucket limits.
  Two healthy nodes on one network will report different values and neither is wrong. A client MUST
  label it as known/discovered peers.

  `known_dig_peer_count >= dig_peer_count` normally holds, but is NOT an invariant a client may rely
  on: the two are sampled from separate structures and may invert transiently during pool churn.

  The field is OPTIONAL on the wire. A node predating it omits it, and a consumer MUST decode that
  omission as `null` (UNKNOWN) rather than rejecting the payload or defaulting it to `0`.
- **`WalletSyncStatusResult`**: `{phase:"not_started"|"syncing"|"synced"|"no_wallet_enrolled"|
  "wallet_not_unlocked", peak_height:u32|null, chia_peer_count:u32|null, watched_addresses:u32|null,
  subscription_peer_count:u32|null, chia_peer_peak_height:u32|null}`.
  Whether the node's WALLET CHAIN replica is being kept current, how far it has got, how many CHIA
  full-node peers its sync is using, and how many addresses it is actually following. This is NOT
  `control.sync.status`, which reports §21 DIG store sync and is unrelated.

  A conforming node MUST emit one of the five tokens above, spelled exactly. `"synced"` MUST require BOTH that
  the initial catch-up completed AND that at least one Chia peer connection is live at the time of
  the read; a wallet that caught up earlier and has since lost every peer MUST report `"syncing"`.
  `"synced"` is therefore STRICTLY STRONGER than `WalletPeakResult.synced`, which reflects only the
  completed-catch-up flag: `"synced"` implies that flag, the flag does not imply `"synced"`. A
  boolean MUST NOT be substituted for the named phases — "never started" and "synced at height 0"
  are different facts and MUST NOT render the same.

  `peak_height` MUST be the node's OWN replica's height, or `null` when it has none. It MUST NOT
  fall back to the coinset oracle, which `control.wallet.peak` deliberately does: that method answers
  what height the chain is at, this field answers how far this replica has got, and an oracle's
  number here would report a caller's own progress using a height the replica never reached.
  `null` MUST NOT be read as height zero.

  `chia_peer_count` counts CHIA FULL-NODE peers the wallet's chain sync is connected to. `0` is an
  OBSERVED zero and is not itself a phase: a running sync connected to nothing reports `"syncing"`
  with `0`, which a consumer SHOULD render as "syncing — no peers". `null` means the node cannot
  observe the count and licenses no claim about connectivity. This count is NOT the DIG
  gossip/content peer count from `control.peerStatus` (`connected_peers` / `relay_peer_count`); the
  two are unrelated numbers, and a surface labelling either one bare "peers" beside a wallet sync
  status asserts something false. A caller wanting both networks' counts reads
  `control.peerCounts`, whose `chia_peer_count` is this same observation under the same key and MUST
  agree with it. The field is duplicated across the two methods rather than moved, because
  `chia_peer_count:0` beside `"syncing"` is the honest "syncing — no peers" state and a phase
  separated from its count reads as a contradiction; a DIG content-network count, by contrast, is not
  a wallet fact and MUST NOT be added here for symmetry.

  **The two idle phases.** A sync with no addresses to follow MUST report which of two situations it
  is in, because they are opposite claims. `"no_wallet_enrolled"` MUST mean no wallet is enrolled on
  the node: there is nothing to watch, the state is correct and complete, and a consumer MAY present
  it as settled. `"wallet_not_unlocked"` MUST mean a wallet IS enrolled but the node holds no
  addresses derived for it, so the user's coins are being followed by nothing; a consumer MUST NOT
  render it as synced, settled, or up to date, and MUST NOT present a balance read under it as
  complete. A node MUST NOT emit a single token covering both, and MUST NOT report either as
  `"synced"`. The common cause of `"wallet_not_unlocked"` is that address derivation needs key
  material unavailable while the wallet is locked and nothing back-fills it until unlock, which makes
  it the ordinary state after a restart — the token names the OBSERVATION (no addresses held), not
  the lock, because a manifest that never carried the keys reaches the same state unlocked.

  `watched_addresses` MUST be the number of addresses the sync is actually following. `0` is an
  OBSERVED zero; `null` MUST mean the node did not report the number and MUST NOT be rendered as
  zero. It is the second fact that makes an idle sync readable: `0` beside `"no_wallet_enrolled"` is
  a complete picture, `0` beside `"wallet_not_unlocked"` is a wallet nobody is following. A node MUST
  NOT emit `{phase:"synced", watched_addresses:0}` — a sync following no addresses has caught nothing
  up — and a consumer meeting that pair SHOULD trust the count, which is the narrower claim.

  `subscription_peer_count` counts peers the REPLICA's own subscription supervisor is writing
  through. The supervisor holds AT MOST ONE such peer by design, so this is a 0-or-1 fact about
  whether the replica is currently being fed — NEVER a measure of network reach, and it MUST NOT be
  summed with `chia_peer_count`. Before dig_ecosystem#2806, `chia_peer_count` on this method
  incorrectly carried this narrower number, so a node with five wallet-sync peers reported
  `chia_peer_count:1`; the two fields now exist side by side so a conforming node reports both
  observations distinctly. `null` means no supervisor is attached at all.

  `chia_peer_peak_height` is the peak height this node's OWN Chia peers have ANNOUNCED — distinct
  from `peak_height` (the replica's own progress) and from any oracle reading. `null` MUST be used
  until at least one peer has reported a height; a conforming node MUST NOT report `0` as a stand-in
  for unobserved, since `0` is itself a real height a peer could announce.

  Both fields are OPTIONAL on the wire. A node predating them omits both keys, and a consumer MUST
  decode that omission as `null` rather than rejecting the payload or defaulting either to `0`.

  **An UNKNOWN token MUST NOT fail the response.** A consumer MUST accept any string in `phase` and
  represent one outside the five tokens as an explicit unrecognised value carrying the token
  verbatim, never as a deserialization error and never coerced onto a known phase. A closed token set
  is what turned one added phase into a total read failure in every consumer built against an older
  contract (dig_ecosystem#2609); a coercion onto `"synced"` or `"syncing"` would be worse still,
  converting that outage into a confident false statement about the user's funds. A consumer MUST
  render an unrecognised phase as unknown and MUST NOT infer progress, completion, or a trustworthy
  balance from it. Symmetrically, a consumer MUST tolerate a payload that OMITS any of the three
  count fields, reading each absence as unreported rather than zero, so a node predating a field
  stays readable.

  A phase value MUST NOT report itself as unrecognised while spelling itself as a known token.
  Decoding any phase's own wire spelling MUST return that same phase. An implementation that lets a
  caller attach an arbitrary spelling to its unrecognised representation reintroduces the defect this
  tolerance exists to remove — a value that calls itself unknown locally and arrives at the far side
  as `"synced"` — and MUST make that state unconstructible rather than merely discouraged.

  **Which phases may be presented as SETTLED.** Exactly two: `"synced"` and `"no_wallet_enrolled"`.
  A consumer MUST NOT present `"not_started"`, `"syncing"`, `"wallet_not_unlocked"`, or an
  unrecognised token as settled, complete, or nothing-to-do. `"wallet_not_unlocked"` is the one that
  invites the mistake, because it is idle and looks like `"no_wallet_enrolled"` from inside the sync
  loop while meaning the opposite.

  **Rendering an unrecognised token.** The token is untrusted node-supplied text and MUST be escaped
  before it reaches a terminal, a log, or a UI. A node emitting `"\u{1b}[2K\rsynced"` otherwise
  turns a consumer's `unknown phase: <token>` line into one that reads `synced`, because the escape
  sequence erases the prefix; a right-to-left override does the same to a label. A consumer MUST
  bound the rendered length as well: nothing caps the token on the wire, because rejecting an
  over-long one would reintroduce the fail-closed parse. The raw bytes remain available for RELAYING
  a payload on unchanged, which is the only use that needs them.

  **Emission ordering.** Tolerance protects consumers built against a LATER contract than the node;
  it cannot protect one built against an EARLIER contract, because the tolerance lives in the
  consumer. A node MUST NOT emit `"no_wallet_enrolled"` or `"wallet_not_unlocked"` until the
  consumers it serves are known to be at this contract version or later. dig-node and its clients
  update independently on a user's machine, so a node that adopts the new tokens ahead of its
  installed clients reproduces the total-parse-failure this revision fixes, on every one of them.
  The same rule binds every future token: **the contract may grow a phase at any time; a node may
  only emit it once its consumer floor has caught up.**

  `"synced"` MUST NOT be read as a guarantee that the replica's data is FRESH. A live connection to
  a stalled or lagging peer satisfies the predicate while the replica goes stale; the phase reports
  that catch-up finished and a peer is attached, i.e. that nothing KNOWN is preventing the replica
  from being kept current.

  **Field combinations.** `{phase:"synced", peak_height:null}` MUST NOT be emitted: a node records
  its peak before it marks the initial catch-up complete, so a completed catch-up always has a
  height behind it, and the pair describes a state no conforming node can be in.

  `{phase:"not_started", peak_height:<n>}` is NOT a contradiction and MUST be permitted. The height
  is persisted in the wallet database while the phase describes whether a sync is running IN THIS
  PROCESS, so a node that synced earlier and has just RESTARTED reports this pair truthfully: here
  is the height I reached, and no sync is running right now. A node MUST NOT suppress the height or
  fabricate a phase to avoid emitting it. `{phase:"not_started", peak_height:null}` is equally
  legitimate and means a wallet that has never synced.

  The height reported is the height of the LAST EXISTING block the peer view reported
  (`NewPeakWallet.height` / `RespondPuzzleState.height` from a real full node). This surface performs
  no confirmation-depth arithmetic; a consumer computing depth MUST floor its own input rather than
  assume a convention, because `peak_height` means the NEXT height on a simulator and the last
  existing block on a full node.
- **`WalletBroadcastResult`**: `{accepted:bool, transaction_id:string|null, rejection:string|null}`.
  The node pushes an ALREADY-SIGNED bundle; it MUST NOT sign, and MUST NOT accept any parameter it
  could sign with (§4.3).

  A mempool that examined the bundle and refused it is a SUCCESSFUL call reporting
  `accepted:false` with a `rejection` reason. Failing to REACH a mempool MUST be a §5 error instead.
  These MUST NOT be collapsed: the first says build a different bundle, the second says retry this
  one. `accepted:true` reports mempool admission ONLY — it is NOT evidence that anything reached a
  block, and a caller MUST NOT record an outcome from it. Only a buried confirmation of the created
  coin is evidence.
- **`WalletBalanceResult`**: `{balance:u64, pending:u64, source:"db"|"fallback"|null, synced:bool,
  peak_height:u32|null}`. A
  READ-only chain read over the loopback control plane — it reports state, never moves funds. `balance`
  is the CONFIRMED spendable amount in the asset's base unit (mojos for XCH, base units for DIG);
  `pending` is incoming-unconfirmed.

  `source` names the TIER that produced the figures, and every freshness field describes THAT tier:
  `"db"` is the node's own chain replica (`synced:true`, `peak_height` = the replica's peak);
  `"fallback"` is a third-party coinset HTTP oracle, which MUST report `synced:false` and
  `peak_height:null` however caught-up the node's own replica is, because the replica neither
  produced that figure nor bounds its freshness. A `"fallback"` answer also means the queried address
  WAS DISCLOSED off-node. `source` is ABSENT/`null` only from a node predating tier disclosure — a
  third state meaning "tier unknown", never a defaulted tier; consumers MUST NOT treat it as either.
  `synced:false` means the figures are STALE or fallback-served; `peak_height` is the block height
  the figures reflect (present as `null`, never omitted, when no height applies).
  The `asset` request field is an **`Asset`** (see "Asset" below). This result is a strict
  SUPERSET of dig-app's `BalanceResponse {balance}`: a consumer reading only `{balance}` deserializes
  it losslessly (unknown fields ignored), which is the no-consumer-change guarantee pinned by a KAT.

Proxied results (`control.updater.*`, `control.pairing.list`, `control.peerStatus`) carry the
underlying source's shape verbatim and are modelled as an opaque JSON value; consumers MUST NOT freeze
a struct over them.

- **`PeerSoftware`** — a peer's advertised SOFTWARE build, the one member of the otherwise-proxied
  `control.peerStatus` snapshot whose shape this contract owns. Every entry of the snapshot's
  `connected` array MUST carry a `software` member; a peer entry that omits it is a serialization
  defect, NOT a peer of unknown build. Two forms, tagged by `kind`:

  ```json
  {"kind": "unknown"}
  {"kind": "reported", "product": "dig-node", "version": "0.99.1", "raw": "dig-node/0.99.1"}
  ```

  `unknown` MUST carry no `version` member — never `"0.0.0"`, never `""`, never `null`.

  The node derives it from the peer's gossip `Handshake.software_version` string. The mapping is
  normative:

  | Advertised string | Result |
  |---|---|
  | `product/semver`, both parts non-empty, version parsing as semver | `reported` |
  | `""` (the peer advertised nothing, or coarsened its build off) | `unknown` |
  | any advertisement whose version is VERSION ZERO — the LEGACY SENTINEL | `unknown` |
  | anything else unparseable | `unknown` |

  The product/version split is at the LAST `/`, so a product name may itself contain one.
  Surrounding whitespace is trimmed before parsing.

  **Version zero is a CLASS, not a string.** The rule MUST be applied to the parsed
  major/minor/patch triple, ignoring pre-release and build metadata: the bare `0.0.0`, a
  product-qualified `dig-node/0.0.0`, and every decorated form (`0.0.0-rc.1`, `0.0.0+build`,
  `0.0.0-0`) are all `unknown`. A string comparison would let the decorated forms through as real
  builds at version zero.

  **Why version zero is `unknown` and not a version.** Every dig-node built before this contract
  advertises the literal `"0.0.0"`: three of dig-gossip's four handshake send sites hardcoded it. A
  reader that treated it as a version would classify the entire live network as running software
  0.0.0, and any `>=` comparison would call all of it ancient.

  **Version zero MUST NEVER BE ADVERTISED.** It is a value received from a legacy peer, never one a
  conforming node sends — see `SoftwareVersionDetail` below for the one place that constraint
  binds.

  **`PeerSoftware` MUST NOT implement `Ord`, `PartialOrd`, or `Default`.** `unknown` has no position
  on a version line, and most peers are `unknown` today; a comparison is reachable only after
  destructuring `reported`, which forces a caller to decide what `unknown` means for its question.

  **Privacy.** Reporting a peer's exact build is a fingerprinting aid — it identifies which peers run
  a version with a publicly disclosed defect. Accepted for the diagnostic value on a pre-release
  network. A node that declines to advertise sends an empty string, which reads as `unknown` here and
  is indistinguishable from a build predating the field.

- **`SoftwareVersionDetail`** — how much of its own build a node reveals when it advertises. Wire
  tokens `"full"` (default) | `"minor"` | `"off"`, rendering:

  | Mode | Advertised for version `0.99.1` | Read back as |
  |---|---|---|
  | `full` | `dig-node/0.99.1` | `reported`, exact |
  | `minor` | `dig-node/0.99.0` | `reported`, patch level hidden |
  | `off` | `""` | `unknown` |
  | `minor` of a `0.0.x` build | `""` | `unknown` |

  `minor` MUST render `MAJOR.MINOR.0`, never a bare `MAJOR.MINOR`: a two-part version is not valid
  semver, so the coarse setting would be read as `unknown` and become a confusing second spelling of
  `off`. For the same reason, `minor` of a `0.0.x` build MUST render the EMPTY STRING: its
  coarsening is version zero, which is the `unknown` sentinel, and there is no coarser representable
  value — so it advertises nothing rather than advertising the sentinel as if it were a report.

  The binding invariant: **every rendering is either the empty string or a value that reads back as
  `reported`.** Coarsening reduces precision; it never yields a value that reads as `unknown` while
  looking like a report. `minor` MUST also strip pre-release and build metadata — a nightly identifier is more
  precisely identifying than the patch number beside it, so retaining it would coarsen nothing for
  exactly the builds that most want it. A coarsened `1.4.0` is indistinguishable from a genuine
  `1.4.0`; that is the purpose of coarsening, not a defect in it.

  Rendering is specified here, beside the parsing, because they are two halves of one format. A node
  MUST NOT hand-roll its own `product/version` string.

- **`AutomatedSpend`** — one spend the node made WITHOUT per-transaction approval:
  `{id:string, revision:u32, kind:string, purpose:string, authority:{principal:string,
  grant:string}, asset:Asset, amount_mojos:string, fee_mojos:string, store_id:string|null,
  initiated_ms:u64, updated_ms:u64, status:SpendOutcome, funding_coin_ids:[string],
  chain_reference:{coin_id:string, confirmed:bool}|null}`.

  `amount_mojos` and `fee_mojos` are decimal STRINGS — they carry the full `u64` range, which a JSON
  number does not survive through an f64 parser. `chain_reference` MUST be PRESENT as `null` when
  the node knows no coin id yet (never omitted), and its `confirmed` flag says whether the node
  OBSERVED that coin: a client MUST render an unobserved id as an intention, never as a fact.
  `funding_coin_ids` names the coins CONSUMED and is never confirmation evidence — a competing spend
  of the same funding coin consumes it identically while the intended coin never exists.

- **`SpendOutcome`** — internally tagged on `state`. Exactly five forms are valid:

  | JSON | Meaning |
  |---|---|
  | `{"state":"pending"}` | recorded, not yet handed to the network |
  | `{"state":"submitted"}` | accepted by the mempool; NOT a claim that it will confirm |
  | `{"state":"confirmed","height":u32,"coin_id":string}` | the chain shows the coin this spend created |
  | `{"state":"failed","stage":"signing"\|"broadcast"\|"confirmation","reason":string}` | the attempt ended in an observed failure |
  | `{"state":"unresolved","reason":string}` | the node signed and does not know how it ended |

  The height and coin id live INSIDE the `confirmed` form, so a record cannot hold a confirmation
  height without a confirmation. `failed` MUST carry its `stage`, and `unresolved` MUST NOT be
  reported as `failed` — see §4.2d.

- **`StatusResult.version`** already reports THIS node's own build; there is no separate method for
  it, and `control.peerStatus` covers both the point lookup ("what is that peer running") and the
  census (a group-by over the returned array).

### 4.2 `UNAUTHORIZED` on an open read means an OLD NODE, not a permission problem

A client MUST branch on which method it called:

- On an OPEN read — every method the §4 table marks `no`, today `control.wallet.balance` / `.coins` /
  `.coinById` / `.coinSpend` / `.coinsByParent` / `.peak` / `.syncStatus` and `control.peerCounts` — `-32030 UNAUTHORIZED` can only
  come from a node build that predates the method and gates the whole `control.*` namespace. The
  truth is "this node cannot do that yet" and the remedy is an UPGRADE.
- On a GATED method — `control.wallet.broadcast`, `.arrivals`, `.watch`, `.unwatch`, `.watched` — `-32030 UNAUTHORIZED` means exactly what it says, and the remedy is
  the CONTROL TOKEN.

A client that maps both to the same outcome sends a person to fix the wrong thing. `-32601
METHOD_NOT_FOUND` always means the method is absent, on either.

### 4.2a Wallet enrolment (`control.wallet.watch` / `.unwatch` / `.watched`)

Enrolment is how an authorized local client tells the node WHICH addresses to follow, so that a
wallet whose keys live outside the node can still be synced and read.

- The unit of enrolment is a **BLS G1 PUBLIC KEY**, 48 bytes, on the wire as lowercase 96-hex,
  unprefixed; a `0x` prefix MUST be accepted on input and MUST NOT be emitted. A node MUST derive the
  addresses from an enrolled key using the SAME derivation it applies to keys in its own custody, so
  that exactly one key→address mapping exists in the ecosystem. Enrolling puzzle hashes instead would
  require every client to re-derive independently, and a client with a narrower derivation window
  would under-report the funds it owns.
- No private key material is ever carried: a public key is public, and enrolment confers no ability
  to sign. §4.3 is unaffected.
- `control.wallet.watch` MUST be IDEMPOTENT. Re-enrolling an enrolled key is a SUCCESS reporting
  `added: 0`; duplicates within one request count once. `control.wallet.unwatch` mirrors it: a key
  that was never enrolled reports `removed: 0` and is not an error.
- A node MUST refuse the WHOLE request as `-32602 INVALID_PARAMS` when ANY submitted key is
  malformed, never the well-formed subset — a partial enrolment leaves the node following fewer
  addresses than the client believes it asked for, and the client's next balance read would report
  the shortfall as though the money were absent.
- The enrolled set MUST PERSIST across node restarts, and `unwatch` MUST actually stop the following
  — the addresses leave the replica's watched set, not merely the list the node reports.
- `control.wallet.watched` MUST return exactly the keys enrolment added, in the wire form they were
  accepted in, and MUST NOT include the node's own custody keys: a caller reconciling against a
  superset would unwatch keys it never watched.
- **Privacy.** Enrolling makes this node query its peers for those addresses, so its peers can
  associate them with this machine. That is already true of the node's own custody keys; it becomes
  true of the enrolling client's keys too, and a client SHOULD say so where a person can see it.

### 4.2a Coin reservations (`control.wallet.reservations.held` / `.reserve` / `.release`)

A reservation records that a coin is already committed to a spend that has been built but has not
settled. It is BOOKKEEPING: it holds no key, signs nothing, authorizes nothing (§4.3), and only
narrows what a coin selector is willing to choose.

**The window it closes.** Between building a spend and that spend confirming, the chain still reports
its inputs as UNSPENT — the bundle is in a mempool, not a block. A second build in that window sees
the same coins, applies the same selection rule, and picks the same coin. The second bundle can never
be included, and it fails AFTER the money moved.

**Why the method exists rather than a per-process table.** A wallet key can be in use by more than
one process at once — dig-app holding the key, and a dig-node serving the same wallet. Two
independent reservation tables re-create exactly the double-select each of them fixes locally. These
methods let a client back its own reservation seam with the NODE's table, so both processes narrow
against ONE set.

**Authority.** Where a node is reachable, the NODE's set is authoritative and a client MUST defer to
it. A purely local set is a fallback for the no-node case only, and a client using one MUST NOT treat
it as covering another process.

- **All-or-none acquisition.** `reserve` MUST take every coin in `coin_ids` or none. Reading the held
  set, selecting, then reserving is check-then-act, and two callers racing it both take the same
  coin; atomic acquisition is what closes that. On a clash a node MUST have written NOTHING and MUST
  answer `-32046 WALLET_COINS_RESERVED`.
- **A conflict is a WAIT, never a shortfall.** `WALLET_COINS_RESERVED` is deliberately distinct from
  any insufficient-funds code. The user HAS the money; it is briefly committed and returns when that
  spend settles or its hold lapses. Reporting a shortfall sends a person to an exchange to solve a
  five-minute wait.
- **Reservation narrows SELECTION, never BALANCE.** A reserved coin is still the user's money and
  still counts toward what they hold. A client MUST NOT subtract `reserved` from a displayed balance.
- **Every hold expires.** `reserve` MUST apply a finite lifetime whether or not anyone releases, so
  an abandoned or crashed build cannot strand funds. A node clamps the requested `ttl_secs` to its own
  maximum, applies its default when none is given, and MUST return the lifetime it ACTUALLY applied —
  a caller told nothing would release on a schedule the node does not keep. The contract has no way
  to express a hold that never expires.
- **Explicit release, because the TTL alone is not enough.** `release` frees a hold the moment its
  spend is known settled or known dead, rather than holding a person's coins for the rest of a window
  over a question the chain has already answered. Releasing a handle that names no live reservation
  MUST be a SUCCESS reporting `released:false` — a caller releasing on confirmation cannot know
  whether the TTL got there first, and an error there teaches callers to discard the result. Release
  MUST free every coin the handle holds or none of them.
- **An empty `coin_ids` MUST succeed**, yielding a handle that releases nothing. An empty reservation
  can never conflict, so refusing it would make a legitimate no-op selection look malformed.
- **Fail direction: REFUSE.** A node that cannot read its reservation set MUST answer
  `-32047 WALLET_RESERVATIONS_UNAVAILABLE` and MUST NOT answer an empty list. `reserved: []` is a
  positive statement that nothing is held and permits a caller to spend; "I cannot tell" must stop
  one. Collapsing the two restores the double-select these methods exist to prevent.
- **The caller does not supply the time.** `held` takes no parameters. A caller-supplied `now` would
  be a lapse oracle — a far-future value makes every live hold read as expired. The node reads its
  own clock and reports it as `as_of_unix` so a client can SEE skew rather than impose it.
- **`reservation_id` is OPAQUE.** A client stores it and sends it back, and MUST NOT parse, derive or
  construct one. A handle a caller can guess lets it release a reservation it does not own, which is
  the double-select reached through the front door.
- **No key material (§4.3).** A coin id is a public chain fact. There is no seed, key, signature or
  bundle field on any of these methods and there never may be.
- All three are TOKEN-GATED, including `held`: the caller supplies nothing, so the answer names this
  node's OWN in-flight commitments — the same reasoning that gates `control.wallet.watched`.

### 4.2b dig-profile bodies (`control.profile.putBody` / `.getBody`)

A dig-profile is a chain-anchored ROOT plus the body that root commits to. The root is written on
chain by whoever holds the key — never by the node (§4.3). These two methods move only the BODY.

- **`control.profile.putBody` is a trust boundary the node MUST NOT skip.** On every call the node
  MUST independently resolve the profile's root on chain, recompute the root of the supplied body,
  and REFUSE the call unless the two agree and that root is CONFIRMED. The caller's `root` is a
  claim to be checked, never a fact to be trusted.
- **dig-app receives no exemption.** It signs and pushes the root, but the bytes it then hands over
  reach the node exactly as a peer's bytes do, and the same rule binds both: a body is checked
  against the on-chain root and anything that does not match is rejected. A node that stores what it
  is handed can be made to serve arbitrary bytes to the network under another party's profile id.
- **Refusal is an ERROR, never a success.** A rejected body MUST NOT return `Ok` with `stored:
  false`; reaching a successful result asserts both that the root was confirmed and that the body is
  persisted and servable.
- **Bodies are bounded at `MAX_BODY_BYTES` = 4 MiB, on the DECODED bytes.** A larger body MUST be
  refused as `-32602 INVALID_PARAMS` before it is persisted. The bound is half of dig-gossip's
  `WS_MAX_MESSAGE_BYTES` (8 MiB), the frame ceiling the body must fit inside when this node serves
  it to a peer over `PROFILE_BODY` (opcode 225); a body accepted here but unservable there would be
  stored and permanently unsyncable. The contract states the cap so a client can check before it
  sends rather than discovering it as a failed round trip.
- **`control.profile.getBody` answers at the root it was ASKED for.** A node MUST NOT substitute a
  newer body it holds. `body_b64: null` MUST mean "this node was consulted and holds no body at that
  root"; a read that FAILED MUST return a catalogued error instead.

### 4.2c Subscription `kind` is read tolerantly

`control.subscribe` takes an OPTIONAL `kind` of `"capsule"` or `"profile"`. A `profile` subscription
additionally follows the profile ROOT and syncs its body from peers.

- **An ABSENT `kind` MUST mean `"capsule"`,** on the wire and on disk. Every subscription written
  before the field existed is untagged, and a node MUST keep reading those rows: a node that refuses
  its own pre-existing `subscriptions.json` starts with an empty one, and the upgrade silently
  unsubscribes the user from everything they had.
- The same tolerance binds the RESULT: a client MUST parse a `control.subscribe` acknowledgement
  from a node build that predates the field, treating the absent `kind` as `"capsule"`.
- An UNRECOGNISED `kind` token is `-32602 INVALID_PARAMS`; absence is not.

### 4.2d The automated-spend audit record (`control.spends.list`)

`control.spends.list` is the ONE sanctioned way to read the spends a node made without
per-transaction approval. The record itself is node-private (dig-node SPEC §23): it is a file the
node owns, and every other view — dig-app's Activity tab included — reads it through this method. A
second process parsing that file would be a second implementation of a growing append-only format,
which is how two views of "what did the node spend" begin to disagree.

**The method is read-only, and the catalog offers no companion that is not.** A conforming node MUST
NOT let this call initiate, sign, retry, cancel or amend a spend, and MUST NOT expose a control
method that edits or deletes an entry. The record replaces authorization with accountability, and a
record that can be edited accounts for nothing.

**A failure MUST carry the stage it died at.** Only `stage: "signing"` means the money definitely did
not move: no signed bundle ever existed, so nothing could reach a mempool. `"broadcast"` and
`"confirmation"` both happen after a valid signed bundle exists, and neither observation proves
absence — a rejection this node saw does not bind a network it does not fully observe. A node MUST
NOT emit a bare `failed` without a stage, and a client MUST NOT render a `broadcast` or
`confirmation` failure as settled. Collapsing the distinction makes every surface structurally
unable to tell a person the truth about their own money.

**`unresolved` is a state, not a kind of failure.** It means the node signed and does not know how it
ended — a timeout, a restart mid-flight, a producer that dropped the spend. A node MUST NOT report it
as `failed`, and a client MUST NOT fold it into a failure bucket: saying "it did not happen" about a
spend that landed is the same class of lie as claiming an unconfirmed success.

**Money amounts are decimal STRINGS.** `amount_mojos` and `fee_mojos` carry the full `u64` range,
which a JSON number does not survive through an f64 parser.

**A page states its own completeness.** `spends` is bounded by 500 rows (default 50). `complete` MUST
be `false` whenever a matching row was withheld, and MUST NOT be inferred by a client from
`spends.len() < limit` — a node may return a short page for its own reasons, and a matching set that
is an exact multiple of the page size makes the last full page indistinguishable from a truncated
one. Without the flag a caller cannot tell "there are no more spends" from "we stopped telling you",
and on an audit record those read the same and mean opposite things. A `limit` of `0`, or above 500,
MUST be refused as `INVALID_PARAMS` rather than clamped: a silently shrunk page hands back a cursor
for a position the caller did not ask about.

**The order is part of the contract.** Rows are returned by DESCENDING `initiated_ms`, ties broken by
ASCENDING `id`, and the order MUST stay stable across the pages of one walk. `after_id` means
strictly after that row in that order. The tiebreak is required rather than incidental: automated
spends are issued by a cycle and several can share a millisecond, so a time-only order names no
position and a walk would repeat some rows and skip others.

**Unreadable entries are part of the answer.** `unreadable_lines` counts entries the node could not
parse, across the whole record rather than the page — a corrupt entry has no parsed timestamp and no
parsed id, so it can be attributed to neither. A client MUST surface a non-zero value: an audit trail
that lost rows and reads as a tidy shorter one is the same lie as a missing entry, told more
convincingly.

**An empty page is an answer; an unreadable record is an error.** `spends: []` with `complete: true`
means this node moved no money unattended matching the filters, and a record that was never written
answers exactly that way — a node that has never spent automatically is the ordinary case. A record
that could not be read AT ALL is `-32048 SPEND_AUDIT_UNREADABLE`, never an empty page: "nothing to
report" and "I could not look" are different answers, and the first is the one a person stops
investigating on.

**The read is token-gated although it is a read.** The caller supplies no identifier, so the answer
is this node's OWN spending history — the same rule that keeps `control.wallet.arrivals` gated.

### 4.2e Mirror collateral: the epoch requirement and the local safety margin

Two different kinds of value live in this category and MUST NOT be conflated. The **requirement** is
consensus-derived: every node derives the same per-store figure for an epoch from the same census, and
a mirror advertisement is counted in that epoch only if it posts at least that figure. The **safety
margin** is a LOCAL operator preference that changes only how much THIS node chooses to lock over the
requirement.

**The margin MUST NOT be a consensus input.** No value derived from the margin MUST reach a census, a
controller signal, or any value another node derives. `control.collateral.requirement` MUST return the
PRE-margin requirement; a node that returned the margined amount would present its own preference as
the network's price.

**The margin is an unsigned integer count of BASIS POINTS (`100` is +1%), and MUST NOT be converted.**
It is the unit `dig_mirror_collateral::apply_safety_margin` takes and the unit dig-app `SPEC.md` §3.7b
fixes for `AgentConfig.collateral.margin_bp`; the `dign` CLI persists the same integer under the same
key. A percentage or a float is not an alternative spelling of it — `1` bp (0.01%) is a legal margin
that any conversion to whole percent erases.

**The node is the authoritative home for the margin.** The flywheel is headless, so an install with no
GUI MUST be able to set this; `control.collateral.margin.set` is how a graphical client reaches the
same stored value rather than keeping one of its own.

**A margin above `MAX_SAFETY_MARGIN_BP` (10000 bp, +100%) MUST be refused as `-32602 INVALID_PARAMS`,
never clamped.** The bound exists because `.set` is a money-path mutation reachable with an ordinary
paired token, and the margin arithmetic saturates rather than failing, so an unbounded value produces a
silently enormous posting instead of an error. Refusal rather than clamping is required because the
caller is stating an intent now: applying a different number than the one requested would leave the
caller's stored intent and the node's behaviour disagreeing about money. `control.collateral.margin.set`
MUST return the margin actually in force, and for an accepted request that value MUST equal the
requested one.

**A node whose configuration predates the field MUST report `DEFAULT_SAFETY_MARGIN_BP` (100 bp, +1%),
never `0`.** A zero margin is a deliberate choice to post the requirement exactly; reporting it for a
configuration that never expressed one tells an operator they declined a cushion they never declined.
The default errs high because the failure is asymmetric — under-posting likely costs that epoch's
rewards, while over-posting costs only the opportunity cost of the locked $DIG.

**An unknown requirement MUST be stated as unknown, with its reason.** A node that has not censused the
epoch, or that sits inside `CENSUS_FINALITY_DEPTH_BLOCKS` of the chain tip, MUST return
`{state:"unknown", reason}` and MUST NOT return `0`, an error a client would render as "no collateral
required", or a previous epoch's figure presented as this epoch's. The four reasons —
`not_censused`, `behind_finality_depth`, `record_unreadable`, `no_chain_source` — name DIFFERENT missing
facts with different remedies, and MUST NOT be collapsed into one. `known` and `unknown` are variants of
one tagged union precisely so that no representable value carries a figure the node was not given; this
is what dig-app `SPEC.md` §3.7b requires when it forbids any path that renders an absent requirement as
a zero cost.

**A `known` requirement MUST declare the collateral protocol version that COMPUTED the epoch** — not
the newest version the node's build implements. The two differ exactly when a node upgraded
mid-schedule, which is the one case where a client needs to tell a rule change from a disagreement. A
requirement without its version MUST be rejected by a reader rather than defaulted.

**The census inputs travel with the figure.** `stores` counts qualifying `(owner, store, root)`
advertisements — one owner publishing two roots for one store id contributes two — and `owners` counts
distinct owner puzzle hashes. Neither is a node count or an operator count, and a surface displaying
`owners` MUST say "collateralised owners". `multiplier_micros` is in millionths and
`handicap_dig_base_units` is in DIG base units.

**These methods are TOKEN-GATED although two of them are reads.** The requirement's figure is derivable
from chain by anyone, but its `unknown` branch names this node's OWN census position and the caller
supplies no identifier, so the answer is a fact about this node rather than a relayed public one. They
are NOT open reads (§4.2), and they are NOT master-token methods (§2.1): setting a margin grants the
caller no authority that outlives the token, and the operator can revoke and reset it.

**The count of stores THIS node holds is not served here.** It is served by
`control.collateral.buffer` (§4.2f) as `pairs_served_by_this_node`, together with the buffer that
figure feeds; duplicating it in the requirement response would create a second source of truth for
a value on the money path.

### 4.2f The recommended $DIG buffer and the node's funding state

`control.collateral.buffer` states the $DIG a node recommends HOLDING and where that node stands
against the figure. It is a SEPARATE method from `control.collateral.requirement`, and MUST remain
one: the requirement is consensus-derived and identical on every node, whereas the buffer is LOCAL —
it rests on the `(owner, store, root)` pairs this node serves, on an operator preference (the safety
margin), on this node's unreclaimed collateral, and on a horizon this node chose. Folding it into the
requirement's result would make one node's local position look like a network figure, which is the
same conflation §4.2e forbids for the margin.

**A client MUST NOT derive this figure.** The buffer is
`pairs_served_by_this_node x required_per_store x (1 + margin)` plus the transition overlap plus the
escalation headroom. The first term is THIS node's served set, and the census `stores` figure returned
by `control.collateral.requirement` is a network-wide advertisement count that MUST NOT be substituted
for it; the overlap term needs reclaim state no other method exposes. A client multiplying the census
count by the requirement produces a confident, badly wrong number on a money surface. The node owns
the calculation for two further reasons: `dign` MUST answer the same question on a headless host where
no notification will ever fire, and two independent derivations of one money figure will disagree.

**All amounts are in DIG BASE UNITS**, `$DIG` carrying 3 decimals so that one base unit is
`0.001 DIG`. They are NOT mojos — a mojo is XCH's base unit at `1e-12` XCH, nine orders of magnitude
away. `margin_bp` is in BASIS POINTS (`100` is +1%) and MUST NOT be converted, per §4.2e.

**`recommended_buffer_dig_base_units` is authoritative and the other terms are the working.** A client
MUST render the node's total rather than re-adding the terms and preferring its own sum: the rounding
lives in the node's arithmetic. `pairs_served_by_this_node`, `required_per_store_dig_base_units`,
`margin_bp`, `overlap_dig_base_units` and `escalation_headroom_dig_base_units` exist so a surface can
show WHY the number is what it is; `spendable_dig_base_units` is the balance the verdict was reached
against, and carrying it is what makes `funding_state` checkable rather than merely asserted.

**The horizon MUST travel in the payload and MUST NOT be implied.** Escalation of the per-store
requirement is bounded at `+1/ESCALATION_UP_STEP_DENOM` (`+12.5%`) per epoch and COMPOUNDS — about
x1.12 at one epoch, x1.60 at four, x4.62 at thirteen — so the same buffer quoted over different
horizons answers different questions and neither can be checked without knowing which.
`horizon_epochs` states how many future epochs the headroom covers and `escalation_ceiling_micros`
states the compounded multiplier assumed, in millionths. A reader MUST reject a `known` payload
missing either rather than defaulting it. `escalation_ceiling_micros` is a WORST CASE and MUST NOT be
presented as a forecast: inside the controller's dead band the multiplier does not move at all.

**The node decides the funding state; a client MUST NOT re-derive it from thresholds.** Two clients
choosing their own thresholds will disagree, and the one that disagrees about a funding warning is the
one an operator acts on. The four states are:

| `funding_state` | meaning |
| --- | --- |
| `short_now` | cannot cover the CURRENT epoch; stores this node serves are already going uncollateralised |
| `dangerously_low` | covers now, could not cover the NEXT epoch at the escalation ceiling |
| `below_recommended_buffer` | covers every epoch in the horizon but holds less than the buffer: funded, no cushion |
| `funded` | holds at least the recommended buffer over the stated horizon |

`short_now` and `dangerously_low` leave an epoch uncovered. **`below_recommended_buffer` is a READOUT
and MUST NOT be raised as a recurring notification**: a healthy node sits there much of the time, and a
client that alerted on it would teach an operator to dismiss the two states that matter. Whether a
state warrants interrupting somebody is otherwise the client's decision; which state the node is in is
the node's.

**An undeterminable buffer MUST be stated as unknown, with its reason, and MUST NOT be a zero.** On the
requirement a fabricated zero reads as a free requirement; here it reads as *no buffer needed*, and an
operator acting on it posts nothing and loses the epoch. The four reasons — `requirement_unknown`,
`served_set_unknown`, `reclaim_state_unknown`, `balance_unknown` — name DIFFERENT missing facts with
different remedies and MUST NOT be collapsed. `requirement_unknown` deliberately does not restate
§4.2e's taxonomy; a client needing to know WHICH census fact is missing calls
`control.collateral.requirement`. `known` and `unknown` are variants of one tagged union so that no
representable value carries a figure the node was not given.

**The read is TOKEN-GATED although it is a read.** The caller supplies nothing, so the answer is this
node's own served set, operator preference and balance — an association, not a relayed public fact. It
is NOT an open read (§4.2) and NOT a master-token method (§2.1).

**Nothing on this contract claims a margin guarantees inclusion.** The requirement is re-derived every
epoch and can rise by more than any margin chosen.

### 4.3 The custody boundary (§908)

The node holds no user key and produces no signature. `control.wallet.broadcast` carries signed bytes
and nothing else. `control.wallet.watch` carries PUBLIC keys, which confer no ability to sign. There
`control.profile.putBody` carries body bytes whose root somebody else already signed and confirmed on
chain. There
is no private key, seed, phrase, or unsigned-spend-plus-key parameter in this catalog,
and none may be added. The node's role on the money path is to read chain state and to push what
somebody else signed.

## 5. Error taxonomy

The numeric codes are a published wire contract and never change once assigned. `origin` classifies
where the error was minted.

| Code | Symbol | Origin | Meaning |
|---|---|---|---|
| `-32700` | `PARSE_ERROR` | shell | request body was not valid JSON |
| `-32600` | `INVALID_REQUEST` | shell | not a single JSON-RPC object |
| `-32601` | `METHOD_NOT_FOUND` | boundary | control method is not resolved |
| `-32602` | `INVALID_PARAMS` | node | missing/malformed params |
| `-32000` | `DISPATCH_FAILED` | shell | the node failed to dispatch a well-formed call |
| `-32030` | `UNAUTHORIZED` | shell | a `control.*` method called without a valid token |
| `-32031` | `NOT_SUPPORTED` | shell | control op unsupported on this build (e.g. §21 sync with no identity) |
| `-32032` | `CONTROL_ERROR` | shell | a control op failed at runtime |
| `-32040` | `WALLET_NO_CHAIN_SOURCE` | node | a wallet chain read had no live chain source to answer |
| `-32041` | `WALLET_NOT_SYNCED` | node | a wallet chain read of the wallet's own address is still syncing, with no fallback |
| `-32042` | `WALLET_READ_FAILED` | node | a wallet chain read failed at the DB / chain-source layer |
| `-32043` | `WALLET_RATE_LIMITED` | node | a wallet chain read was refused: the open fallback rate bound is spent |
| `-32044` | `WALLET_NODE_SPEND_DISABLED` | node | `control.wallet.broadcast` refused: the bundle requires a signature from one of the NODE's OWN custodied keys while `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off. The node relays bundles somebody else signed on every install; sending its own money is a separate, default-OFF custody decision, and a caller could otherwise sign through the node and hand the bundle straight back. **Retrying cannot help**: the remedy is a bundle that does not spend the node's coins, or the flag. |
| `-32046` | `WALLET_COINS_RESERVED` | node | coins named by the call are committed to a live in-flight spend; nothing was reserved. A WAIT, never a shortfall |
| `-32047` | `WALLET_RESERVATIONS_UNAVAILABLE` | node | the node's coin-reservation set could not be read, so what is in flight is UNKNOWN |
| `-32048` | `SPEND_AUDIT_UNREADABLE` | shell | the automated-spend audit record could not be read at all, so what this node spent unattended is UNKNOWN. Never an empty page. A record that was never written is NOT this: it is an empty page |

The `-3204x` band began as the wallet's and now also carries the audit record's `-32048`; **this
document owns the whole band**. A node or client MUST NOT mint a
`-3204x` code that is not declared in the table above: a privately-minted code cannot be seen at
allocation time, and two implementations then disagree about what one number means.

The codes in the band do NOT share one disposition, so a client MUST branch on the symbol rather
than on the band. `-32040`..`-32043` and `-32047` say the answer is UNKNOWN — the node could not
look, not that the chain said no — so a client MUST NOT degrade them into an empty or zero result,
and MUST NOT report a mint, a spend or a balance as failed on their strength alone. `-32048` says
the same about the audit record: it could not be read, which a client MUST NOT render as "this node
has spent nothing". `-32046` is a
transient WAIT and a client SHOULD retry. `-32044` is TERMINAL: retrying cannot help, and a client
that treats it as a wait retries forever against a decision that will not change.

The `-32020..-32022` band is RESERVED for onion routing (dig-rpc-protocol); the control-plane errors
use `-32030..-32032`.

## 6. Conformance

The golden known-answer tests in `src/kats.rs` are normative: golden request vectors (typed call →
exact envelope), golden response vectors (node JSON decodes into the typed result and re-encodes
byte-identically), the golden error envelope, and an end-to-end route through the node-facing
`ControlHandler` dispatcher proving every method maps to its typed handler. The node side (T7) and
every client side (T8–T10) MUST pin against these vectors. A change that alters a wire shape MUST
fail a KAT.

## 7. Stability

1. `ControlMethod` and `ControlErrorCode` are `#[non_exhaustive]`; adding a method/code is an additive
   MINOR change.
2. Method wire names and error numeric values never change once assigned.
3. Result fields are additive: a new optional field is MINOR; removing/renaming/repurposing a field
   is a BREAKING change.
4. The catalog MUST mirror the live dig-node surface exactly (`dig-node-service/src/control.rs` owned
   methods + the `dig-node-core` delegated peer/subscription methods); a divergence is a drift bug.

## 8. wasm / JS byte-agreement

The catalog types are plain serde structs with no non-wasm dependencies, so a browser/extension client
(T5's `wasm-bindgen` binding) serializes them to identical JSON. The `serde_json::Value`-typed proxied
results and the `#[serde(untagged)]` `RequestId` are the only shapes needing a JS-side check; T5 adds a
Rust↔wasm/JS byte-identical KAT over the vectors in §6.
