# dig-node-control-interface

The canonical **client ⇄ dig-node CONTROL interface** contract. One ecosystem definition of the
management/query surface a client (the CLI `dign`, the browser extension, dig-app, hub) uses to
control and query a running dig-node — status, config, cache, hosted/pinned stores, §21 sync, the peer
network, subscriptions, the auto-update beacon, live log level, and control-token pairing — so the
client side and the node side can never silently drift. Transport-agnostic: rides the
`dig-ipc-protocol` local session, or loopback-mTLS + a signed control token over HTTP/WebSocket for
clients that aren't on the local pipe.

- **License:** Apache-2.0 OR MIT
- **Spec:** [`SPEC.md`](./SPEC.md) (normative) — this README is the at-a-glance interface reference.

```toml
[dependencies]
dig-node-control-interface = "0.2"
```

## Usage

Client side — build a typed request, carry it over your transport, parse the typed result:

```rust
use dig_node_control_interface::{
    params::SetCapParams,
    traits::{build_request, parse_response},
    envelope::JsonRpcResponse,
};

let call = SetCapParams { cap_bytes: 128 * 1024 * 1024 };
let request = build_request(1.into(), &call);          // → control.cache.setCap envelope
// ... send `request` over dig-ipc / loopback-mTLS, receive `response` ...
# let response = JsonRpcResponse::success(1.into(), serde_json::json!({ "cap_bytes": 134217728 }));
let result = parse_response::<SetCapParams>(response)?; // → SetCapResult { cap_bytes }
# Ok::<(), dig_node_control_interface::ControlError>(())
```

Node side — implement `ControlHandler` (one typed method per control method); the provided `dispatch`
routes a raw request to the right method and builds the response.

## Authorization

Every `control.*` method is token-gated unless the tables below mark it `—`: present the node's local
control token as the `X-Dig-Control-Token` header (preferred) or a `params._control_token` field.
Open today are `pairing.request` / `pairing.poll` (a token-less client uses them to obtain a scoped
token after local operator approval), the wallet CHAIN READS (they need only public chain data — an
address or a coin id, never a key), and `control.peerCounts` (three integers about this node's own
connectivity). The three `control.pairing.*` admin methods require the MASTER token specifically.

`UNAUTHORIZED` from an OPEN method means the node predates it — upgrade the node. From
a GATED method (`control.wallet.broadcast` / `.arrivals` / `.watch` / `.unwatch` / `.watched`) it means what it says — find the token. See `SPEC.md` §4.2.

## Full interface reference

Every control method, for LLM/agent lookup without reading code. `Auth`: **T** = requires the control
token, **M** = requires the MASTER token, **—** = open. `Route`: how the node resolves it — `own`
(service shell), `del` (engine), `open` (bootstrap).

### Status / config / log

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.status` | T | own | — | `{running, service, version, commit, protocol, uptime_secs, addr, upstream, cache:{cap_bytes,used_bytes,dir,shared}, hosted_store_count, cached_capsule_count, pinned_store_count, sync:{available}}` |
| `control.config.get` | T | own | — | `{addr, port, upstream, upstream_override:string\|null, cache_dir, cache_shared, config_path, sync_available}` |
| `control.config.setUpstream` | T | own | `{upstream:string}` | `{upstream, requires_restart:true}` |
| `control.log.setLevel` | T | own | `{filter:string}` (an EnvFilter directive) | `{filter}` |

### Cache

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.cache.get` | T | own | — | `{cap_bytes, used_bytes, dir, shared}` |
| `control.cache.setCap` | T | own | `{cap_bytes:u64}` | `{cap_bytes}` (floored at 64 MiB) |
| `control.cache.clear` | T | own | — | `{cleared:true}` |

### Hosted / pinned stores

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.hostedStores.list` | T | own | — | `{stores:[{store_id, pinned, capsule_count, total_bytes, capsules:[{capsule,root,size_bytes,last_used_unix_ms}]}]}` |
| `control.hostedStores.pin` | T | own | `{store:"storeId[:root]"}` | `{store_id, root:string\|null, pinned:true, fetch:{status,…}}` |
| `control.hostedStores.unpin` | T | own | `{store}` | `{store_id, unpinned:bool, evicted_capsules:u64}` |
| `control.hostedStores.status` | T | own | `{store}` | `{store_id, pinned, capsule_count, total_bytes, capsules}` |
| `control.capsule.fetch` | T | own | `{store, root}` | `{store, root, status}` (started/already_cached/unavailable) |

### §21 whole-store sync

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.sync.status` | T | own | — | `{available, method, pinned_total, pinned_synced, whole_store_trigger_supported}` |
| `control.sync.trigger` | T | own | `{store:"storeId:root"}` | `{store_id, root, status:"synced", size_bytes, served_root}` |

### Auto-update beacon (proxied to dig-updater)

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.updater.status` | T | own | — | (proxied beacon status) |
| `control.updater.setChannel` | T | own | `{channel:"nightly"\|"stable"}` | (proxied) |
| `control.updater.pause` | T | own | `{until?:u64}` (unix secs; omit = indefinite) | (proxied) |
| `control.updater.resume` | T | own | — | (proxied) |
| `control.updater.checkNow` | T | own | — | (proxied) |

### Pairing (control-token lifecycle)

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.pairing.list` | M | own | — | (pending requests + issued tokens) |
| `control.pairing.approve` | M | own | `{pairing_id:string}` | `{approved:true, client_name, token_id}` |
| `control.pairing.revoke` | M | own | `{token_id:string}` | `{revoked:bool, token_id}` |
| `pairing.request` | — | open | `{client_name:string}` | `{pairing_id, pairing_code, expires_ms}` |
| `pairing.poll` | — | open | `{pairing_id:string}` | `{status, token?}` (token present once, after approval) |

### Peers (delegated to the engine)

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.peerStatus` | T | del | — | (peer-pool + relay-reservation snapshot, incl. per-peer `peers[]`); its `relay.peer_count` counts THE RELAY's peers, not this node's |
| `control.peerCounts` | — | del | — | `{dig_peer_count:u32\|null, chia_peer_count:u32\|null, known_dig_peer_count:u32\|null}` — DIG content/gossip peers CONNECTED, CHIA full-node peers, and DIG peers this node KNOWS OF (its own address book — a local lower bound, never the network size); `0` is observed, `null` unobservable |
| `control.peers.connect` | T | del | `{peer:string}` (address or peer_id) | `{connected:true, peer_id}` |
| `control.peers.disconnect` | T | del | `{peer:string}` (peer_id) | `{disconnected:true, peer_id}` |
| `control.chiaPeers.add` | M | own | `{ip:string}` (bare IP literal, canonical) | `{added:true, ip, port, corroboration_bypassed, notice:string}` — trusting a peer means believing it WITHOUT corroboration, so it takes the MASTER token: the entry outlives the token that wrote it and `control.pairing.revoke` does not remove it |
| `control.chiaPeers.list` | T | own | none | `{peers:[{ip,port,peak_height:u32\|null,user_managed,banned}]}` — `peak_height` is that peer's CLAIM; `null` unobservable, never `0`. The only enumeration of the banned set |
| `control.chiaPeers.remove` | M | own | `{ip:string, ban?:bool}` | `{outcome:"removed"\|"no_such_peer", ip, banned}` — the ONLY un-trust remedy, so it reports when it matched nothing rather than always succeeding |

### Wallet chain transport (delegated to the engine)

The caller-addressed reads and the chain-position reads are OPEN; the arrival cursor and the push
are token-gated. The node never signs — it reads chain state
and pushes bytes somebody else signed.

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.wallet.balance` | — | del | `{address:string, asset:"xch"\|"dig"}` | `{balance, pending, source, synced, peak_height}` |
| `control.wallet.coins` | — | del | `{address:string, asset:"xch"\|"dig"}` | `{coins:[WalletCoinRecord], source, synced, peak_height}` |
| `control.wallet.coinById` | — | del | `{coin_id:string}` (64-hex, `0x` accepted) | `{coin:WalletCoinRecord\|null, source, synced, peak_height}`; `coin:null` = the chain holds no such coin |
| `control.wallet.coinSpend` | — | del | `{coin_id:string}` (64-hex, `0x` accepted) | `{spend:{coin,puzzle_reveal,solution}\|null, source, synced, peak_height}`; `spend:null` = the chain holds no spend of that coin (unspent, or unknown) — NEVER "could not answer", which is an error. `puzzle_reveal` MUST tree-hash to the coin's `puzzle_hash` |
| `control.wallet.coinsByParent` | — | del | `{parent_coin_id:string, after_coin_id?:string, limit?:u32}` (ids 64-hex, `0x` accepted; `limit` 1..=1000, default 100, REFUSED out of range — never clamped) | `{coins:[WalletCoinRecord], complete:bool, cursor:string\|null, source, synced, peak_height}`; ONE PAGE of the parent's DIRECT children, ascending by `coin_id`, ONE hop, never a recursive walk. `complete:false` = TRUNCATED, resume from `cursor` — never infer completeness from the page length. `coins:[]` = no known children, never an unreachable chain |
| `control.wallet.arrivals` | T | del | `{after_seq:u64=0, limit?:u32}` | `{arrivals:[WalletArrivalRecord], cursor, latest}`; TOKEN-GATED: the caller supplies only a cursor, so the answer names this node's own watched puzzle hashes. CONFIRMED incoming funds only, never the wallet's own change. Resume from `cursor`, never `latest` |
| `control.wallet.peak` | — | del | — | `{peak_height:u32\|null, synced:bool}`; `synced` = catch-up COMPLETED, weaker than `syncStatus`'s |
| `control.wallet.syncStatus` | — | del | — | `{phase:"not_started"\|"syncing"\|"synced"\|"no_wallet_enrolled"\|"wallet_not_unlocked", peak_height:u32\|null, chia_peer_count:u32\|null, watched_addresses:u32\|null, subscription_peer_count:u32\|null, chia_peer_peak_height:u32\|null}`; `synced` also requires a LIVE Chia peer. `no_wallet_enrolled` = nothing to watch and that is correct; `wallet_not_unlocked` = a wallet EXISTS and nothing is watching it — NEVER render it as settled. `subscription_peer_count` is the replica's 0-or-1 supervisor-fed peer, NOT `chia_peer_count` and MUST NOT be summed with it; `chia_peer_peak_height` is the height this node's own Chia peers announced, distinct from `peak_height`. Both are optional, absent on older nodes. An UNKNOWN token parses to `Unrecognized(token)`, never an error |
| `control.wallet.broadcast` | T | del | `{signed_bundle_hex:string}` | `{accepted, transaction_id, rejection}`; `accepted` = mempool admission, NOT confirmation |
| `control.wallet.watch` | T | del | `{public_keys:[string]}` (each a 48-byte G1 key, lowercase 96-hex, `0x` accepted; ANY malformed key refuses the WHOLE request) | `{added:u32, watched:u32}`; enrol PUBLIC keys for the node to follow. IDEMPOTENT — re-enrolling reports `added:0` and succeeds. Keys, never puzzle hashes: the node derives the addresses with the same derivation it uses for its own custody, so there is ONE mapping. Persisted across restarts |
| `control.wallet.unwatch` | T | del | `{public_keys:[string]}` | `{removed:u32, watched:u32}`; the following actually STOPS. A key that was never enrolled reports `removed:0` and is not an error |
| `control.wallet.watched` | T | del | — | `{public_keys:[string]}`; the enrolled keys only, never the node's own custody keys. TOKEN-GATED although it is a read — the caller supplies nothing, so the answer is this node's OWN key set |
| `control.wallet.reservations.held` | T | del | — | `{reserved:[{coin_id, reservation_id, expires_at_unix}], as_of_unix}`; the coins committed to in-flight spends. `reserved:[]` means NOTHING is held; a set that cannot be read is `-32047`, never an empty list. Narrows SELECTION, never a balance |
| `control.wallet.reservations.reserve` | T | del | `{coin_ids:[string], ttl_secs?:u64}` | `{reservation_id, coin_ids, expires_at_unix, ttl_secs}`; ALL the named coins or none. A clash is `-32046 WALLET_COINS_RESERVED` — a WAIT, never a shortfall — and reserves nothing. The returned `ttl_secs` is the lifetime the node APPLIED, which may be shorter than requested |
| `control.wallet.reservations.release` | T | del | `{reservation_id:string}` | `{released:bool, coin_ids:[string]}`; frees a hold ahead of its TTL. A handle naming no live reservation is a SUCCESS with `released:false`. Every hold also lapses on its own, so an abandoned one is never a permanent lockout |

### dig-profile bodies (delegated to the engine)

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.spends.list` | T | own | `{since_ms?, until_ms?, store_id?, kind?, status?, after_id?, limit?:u32}` | `{spends:[AutomatedSpend], complete:bool, cursor:string\|null, unreadable_lines:u32}`; READ-ONLY — the audit record of spends this node made WITHOUT per-transaction approval. It never initiates, signs, cancels or alters a spend. A `failed` row carries the STAGE it died at, because only `signing` means the money definitely did not move; `unresolved` is its own state and MUST NOT be folded into `failed`. `complete` states truncation explicitly — never infer it from the page length. A non-zero `unreadable_lines` means the trail is INCOMPLETE and must be surfaced; a record that cannot be read at all is `-32048`, never an empty page |
| `control.collateral.requirement` | T | own | — | `{state:"known", epoch, protocol_version, required_per_store_dig_base_units, stores, owners, multiplier_micros, handicap_dig_base_units}` \| `{state:"unknown", reason}`; this epoch's PRE-margin per-store collateral requirement with the census inputs that produced it, so a client can show why the figure moved. `unknown` is a first-class answer with a named reason (`not_censused` \| `behind_finality_depth` \| `record_unreadable` \| `no_chain_source`) — NEVER a zero, which would read as no collateral required. `protocol_version` is the version that COMPUTED the epoch, not the newest the build implements. `stores` counts advertisements and `owners` counts collateralised owners; neither is a node count |
| `control.collateral.margin.get` | T | own | — | `{margin_bp:u64}`; the node's LOCAL safety margin in BASIS POINTS (`100` = +1%), never a percentage. A config predating the field reports the `100` default, never `0` |
| `control.collateral.margin.set` | T | own | `{margin_bp:u64}` | `{margin_bp:u64}`; persists the margin and returns what is now in force. Bounded at `10000` bp (+100%) and REFUSED as `-32602` above it rather than clamped, so the applied value never differs silently from the requested one. The margin is local: it MUST NOT reach any census or signal, and it does not guarantee a store is counted |
| `control.collateral.buffer` | T | own | — | `{state:"known", epoch, protocol_version, funding_state, recommended_buffer_dig_base_units, spendable_dig_base_units, pairs_served_by_this_node, required_per_store_dig_base_units, margin_bp, overlap_dig_base_units, escalation_headroom_dig_base_units, horizon_epochs, escalation_ceiling_micros}` \| `{state:"unknown", reason}`; the $DIG this node recommends HOLDING and its position against that figure. Amounts are DIG base units (3 decimals, `0.001 DIG`), never mojos; `margin_bp` is basis points. A client MUST NOT derive this: `pairs_served_by_this_node` is THIS node's served set, not the census `stores` count, and the overlap term needs reclaim state nothing else exposes. The horizon travels in the payload and is never implied — escalation is capped at +12.5%/epoch and COMPOUNDS (x1.12 at 1, x1.60 at 4, x4.62 at 13) — and `escalation_ceiling_micros` is a worst case, not a forecast. `funding_state` is the node's verdict, not a threshold for a client to re-derive: `short_now` \| `dangerously_low` leave an epoch uncovered, `below_recommended_buffer` is a READOUT and never a recurring notification, `funded` holds the buffer. `unknown` is a first-class answer with a named reason (`requirement_unknown` \| `served_set_unknown` \| `reclaim_state_unknown` \| `balance_unknown`) — NEVER a zero, which here reads as no buffer needed |
| `control.profile.putBody` | T | del | `{store_id:string, root:string, body_b64:string}` | `{stored:true, store_id, root, body_bytes}`; the node INDEPENDENTLY resolves `root` on chain and REFUSES any body whose recomputed root is not the confirmed one — `root` is a claim to be checked, never a fact to be trusted, and dig-app is a caller like any other. Decoded bodies above `MAX_BODY_BYTES` (4 MiB) are refused as `INVALID_PARAMS` |
| `control.profile.getBody` | T | del | `{store_id:string, root:string}` | `{store_id, root, body_b64:string\|null, body_bytes}`; `body_b64:null` means this node holds no body at that root and NEVER that the body could not be read, which is an error. The answer is at the root that was ASKED for, never a newer one |

### Subscriptions (delegated to the engine)

| Method | Auth | Route | Params | Result |
|---|---|---|---|---|
| `control.subscribe` | T | del | `{store_id:string, kind?:"capsule"\|"profile"}` | `{subscribed:true, added:bool, store_id, kind}`; `kind` is OPTIONAL on the wire and ABSENT means `capsule` — the meaning every untagged row in an existing `subscriptions.json` already carries |
| `control.unsubscribe` | T | del | `{store_id:string}` | `{subscribed:false, removed:bool, store_id}` |
| `control.listSubscriptions` | T | del | — | `{subscriptions:[string], count}` |

### Error codes

Every control error is `{code:int, message:string, data:{code:SYMBOL, origin:string}}`. Branch on
`data.code` (the stable symbol), never the message.

| Code | Symbol | Origin | Meaning |
|---|---|---|---|
| `-32700` | `PARSE_ERROR` | shell | request body was not valid JSON |
| `-32600` | `INVALID_REQUEST` | shell | not a single JSON-RPC object |
| `-32601` | `METHOD_NOT_FOUND` | boundary | control method is not resolved |
| `-32602` | `INVALID_PARAMS` | node | missing/malformed params |
| `-32000` | `DISPATCH_FAILED` | shell | the node failed to dispatch a well-formed call |
| `-32030` | `UNAUTHORIZED` | shell | `control.*` called without a valid token |
| `-32031` | `NOT_SUPPORTED` | shell | control op unsupported on this build |
| `-32032` | `CONTROL_ERROR` | shell | control op failed at runtime |

## Boundary

- `dig-rpc-protocol` — node ⇄ node peer wire.
- `dig-ipc-protocol` — app ⇄ node local session/signing envelope (the transport this catalog rides
  over, for local clients).
- `dig-node-control-interface` (this crate) — the control METHOD CATALOG carried inside that
  authenticated channel, or over loopback-mTLS for remote-transport clients.

See `SPEC.md` for the normative contract and the superproject `SYSTEM.md` for the wider cross-repo map.

## Consumers

dig-node (server-side dispatch — implements `ControlHandler`), the CLI `dign`, dig-chrome-extension,
dig-app, hub — all consuming this one control contract per epic #1110 (dig-node adoption + the
dig-rpc Control-tier removal land in later tasks of the cascade).
