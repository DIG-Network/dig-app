//! Conformance known-answer tests (KATs) — the anti-drift layer.
//!
//! These pin the exact wire shapes both sides must agree on: golden JSON-RPC request vectors for
//! every method, golden response vectors that the typed results decode-then-re-encode byte-for-byte,
//! and an end-to-end route through a mock [`ControlHandler`] proving the dispatcher maps every
//! method to its typed handler and back. Any client (extension/CLI/hub, T8–T10) and the node side
//! (T7) pin against these; a change that alters a wire shape fails here first.

use futures::executor::block_on;
use serde_json::{json, Value};

use crate::envelope::{JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::error::{ControlError, ControlErrorCode};
use crate::method::ControlMethod;
use crate::params::*;
use crate::results;
use crate::traits::{build_request, parse_response, ControlHandler};

/// The one bundle [`MockNode`] refuses, so the accepted and rejected branches are both reachable
/// from the SAME handler — a mock that could only accept could not express a refusal at all.
const REJECTED_BUNDLE: &str = "beef";

/// The one upstream [`MockNode`] refuses, so a handler error stays reachable from the SAME handler
/// even though `every_catalog_method_dispatches_without_panicking` requires every method to SUCCEED
/// under its minimal params. The refusal has to hang off a value the minimal fixture never uses;
/// making a whole method unsupported instead would trip that test, and silencing it there would put
/// back the tolerate-any-error hole the test exists to close.
const UNSUPPORTED_UPSTREAM: &str = "__not_supported__";

/// The one coin id [`MockNode`] knows about — SPENT, which is the state `control.wallet.coins`
/// can never report and the state a mint observation turns on.
const SPENT_COIN: &str = "abababababababababababababababababababababababababababababababab";

/// A well-formed coin id [`MockNode`] has never heard of, so "absent" is reachable from the same
/// handler as "found" and the two answers can be told apart.
const ABSENT_COIN: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// The children [`SPENT_COIN`]'s spend created, ASCENDING by coin id — the order the contract fixes.
///
/// FOUR of them, and every id DISTINCT from the parent, so three different wrong implementations are
/// visible: one that echoes the id it was asked about, one that ignores `after_coin_id`, and one
/// that reports completeness from the page LENGTH. Four children paged two at a time is the fixture
/// that kills the last of those — both pages carry exactly two rows, and only one of them is the
/// last, so `complete` is the only thing that tells them apart.
const CHILD_COINS: [&str; 4] = [
    "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
    "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
    "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c",
    "4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d",
];

/// The two halves of a spend, given DIFFERENT values so a serialization that transposed the fields
/// cannot pass. Short stand-ins for serialized CLVM — the contract fixes the encoding (lowercase hex)
/// and not the programs, which belong to whatever puzzle was actually revealed.
const REVEAL_HEX: &str = "ff01ff8080";
const SOLUTION_HEX: &str = "ff8203e880";

const STORE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// A golden request vector: build the typed call, assert it serializes to the exact envelope bytes.
fn assert_request<C: crate::traits::ControlCall>(call: &C, expected: Value) {
    let req = build_request(RequestId::Number(1), call);
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        expected,
        "request wire shape drifted for {}",
        C::METHOD.name()
    );
}

/// A golden response vector: the typed result decodes from `wire` and re-encodes byte-identically.
fn assert_result_round_trips<T>(wire: Value)
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let parsed: T = serde_json::from_value(wire.clone()).expect("golden result must decode");
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        wire,
        "result wire shape is not byte-stable"
    );
}

#[test]
fn golden_request_vectors() {
    assert_request(
        &StatusParams {},
        json!({"jsonrpc":"2.0","id":1,"method":"control.status","params":{}}),
    );
    assert_request(
        &SetUpstreamParams {
            upstream: "https://rpc.dig.net".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.config.setUpstream","params":{"upstream":"https://rpc.dig.net"}}),
    );
    assert_request(
        &SetLevelParams {
            filter: "info,dig_node_core=debug".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.log.setLevel","params":{"filter":"info,dig_node_core=debug"}}),
    );
    assert_request(
        &SetCapParams {
            cap_bytes: 67108864,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.cache.setCap","params":{"cap_bytes":67108864}}),
    );
    assert_request(
        &PinParams {
            store: format!("{STORE}:{ROOT}"),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.hostedStores.pin","params":{"store":format!("{STORE}:{ROOT}")}}),
    );
    assert_request(
        &CapsuleFetchParams {
            store: STORE.into(),
            root: ROOT.into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.capsule.fetch","params":{"store":STORE,"root":ROOT}}),
    );
    assert_request(
        &SyncTriggerParams {
            store: format!("{STORE}:{ROOT}"),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.sync.trigger","params":{"store":format!("{STORE}:{ROOT}")}}),
    );
    assert_request(
        &PauseParams {
            until: Some(1_800_000_000),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.updater.pause","params":{"until":1800000000}}),
    );
    assert_request(
        &ApproveParams {
            pairing_id: "pid-1".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.pairing.approve","params":{"pairing_id":"pid-1"}}),
    );
    assert_request(
        &PeersConnectParams {
            peer: "1.2.3.4:9257".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.peers.connect","params":{"peer":"1.2.3.4:9257"}}),
    );
    assert_request(
        &SubscribeParams {
            store_id: STORE.into(),
            kind: SubscriptionKind::Capsule,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.subscribe","params":{"store_id":STORE,"kind":"capsule"}}),
    );
    assert_request(
        &RequestParams {
            client_name: "DIG extension".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"pairing.request","params":{"client_name":"DIG extension"}}),
    );
    assert_request(
        &WalletBalanceParams {
            address: "xch1exampleaddr".into(),
            asset: Asset::DIG,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.balance","params":{"address":"xch1exampleaddr","asset":"dig"}}),
    );
    assert_request(
        &WalletCoinsParams {
            address: "xch1exampleaddr".into(),
            asset: Asset::Xch,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coins","params":{"address":"xch1exampleaddr","asset":"xch"}}),
    );
    // The two vectors above are the ORIGINAL frozen bytes and stay untouched: $DIG and XCH keep
    // their bare legacy tokens, so a node built before asset ids were nameable still reads them.
    // The widening is what follows -- an ADDED case, never an edited one (CLAUDE.md §5.1).
    assert_request(
        &WalletBalanceParams {
            address: "xch1exampleaddr".into(),
            asset: Asset::Cat(AssetId::from_hex(&"3c".repeat(32)).unwrap()),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.balance","params":{"address":"xch1exampleaddr","asset":{"cat":"3c".repeat(32)}}}),
    );
    assert_request(
        &WalletCoinsParams {
            address: "xch1exampleaddr".into(),
            asset: Asset::Cat(AssetId::from_hex(&"3c".repeat(32)).unwrap()),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coins","params":{"address":"xch1exampleaddr","asset":{"cat":"3c".repeat(32)}}}),
    );
    assert_request(
        &WalletCoinByIdParams {
            coin_id: "ab".repeat(32),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coinById","params":{"coin_id":"ab".repeat(32)}}),
    );
    assert_request(
        &WalletCoinSpendParams {
            coin_id: "ab".repeat(32),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coinSpend","params":{"coin_id":"ab".repeat(32)}}),
    );
    // The by-parent read spells its field `parent_coin_id`, not `coin_id`: the coin named is the one
    // being asked ABOUT, never the one coming back. Pinned literally so the two by-coin reads cannot
    // drift into sharing a field name that reads as a request for the parent itself.
    // A first page names neither a cursor nor a size, and MUST NOT emit either key: an omitted
    // `limit` is the contract's default, and a `null` on the wire is a different thing to parse.
    assert_request(
        &WalletCoinsByParentParams::first_page("ab".repeat(32)),
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coinsByParent","params":{"parent_coin_id":"ab".repeat(32)}}),
    );
    // A resumed, bounded page carries both, and the cursor is spelled `after_coin_id` -- the id the
    // caller was HANDED, never a marker for where the chain got to.
    assert_request(
        &WalletCoinsByParentParams {
            parent_coin_id: "ab".repeat(32),
            after_coin_id: Some(CHILD_COINS[1].into()),
            limit: Some(2),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.coinsByParent","params":{"parent_coin_id":"ab".repeat(32),"after_coin_id":CHILD_COINS[1],"limit":2}}),
    );
    assert_request(
        &WalletPeakParams {},
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.peak","params":{}}),
    );
    assert_request(
        &PeerCountsParams {},
        json!({"jsonrpc":"2.0","id":1,"method":"control.peerCounts","params":{}}),
    );
    assert_request(
        &WalletSyncStatusParams {},
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.syncStatus","params":{}}),
    );
    assert_request(
        &WalletBroadcastParams {
            signed_bundle_hex: "deadbeef".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.broadcast","params":{"signed_bundle_hex":"deadbeef"}}),
    );
}

#[test]
fn golden_response_result_vectors_are_byte_stable() {
    assert_result_round_trips::<results::StatusResult>(json!({
        "running": true, "service": "dig-node", "version": "0.30.0", "commit": "deadbee",
        "protocol": "21", "uptime_secs": 42, "addr": "127.0.0.1:9256",
        "upstream": "https://rpc.dig.net",
        "cache": {"cap_bytes": 67108864, "used_bytes": 1024, "dir": "/var/cache/dig", "shared": true},
        "hosted_store_count": 3, "cached_capsule_count": 5, "pinned_store_count": 2,
        "sync": {"available": true}
    }));
    assert_result_round_trips::<results::ConfigResult>(json!({
        "addr": "127.0.0.1:9256", "port": "9256", "upstream": "https://rpc.dig.net",
        "upstream_override": null, "cache_dir": "/var/cache/dig", "cache_shared": true,
        "config_path": "/etc/dig/config.json", "sync_available": false
    }));
    assert_result_round_trips::<results::CacheView>(json!({
        "cap_bytes": 67108864, "used_bytes": 0, "dir": "/c", "shared": false
    }));
    assert_result_round_trips::<results::HostedStoresListResult>(json!({
        "stores": [{
            "store_id": STORE, "pinned": true, "capsule_count": 1, "total_bytes": 10,
            "capsules": [{"capsule": format!("{STORE}:{ROOT}"), "root": ROOT,
                          "size_bytes": 10, "last_used_unix_ms": 1700000000000u64}]
        }]
    }));
    assert_result_round_trips::<results::SyncStatusResult>(json!({
        "available": true, "method": "section-21-whole-store-sync",
        "pinned_total": 2, "pinned_synced": 1, "whole_store_trigger_supported": false
    }));
    assert_result_round_trips::<results::CapsuleFetchResult>(json!({
        "store": STORE, "root": ROOT, "status": "started"
    }));
    assert_result_round_trips::<results::SyncTriggerResult>(json!({
        "store_id": STORE, "root": ROOT, "status": "synced",
        "size_bytes": 2048, "served_root": ROOT
    }));
    assert_result_round_trips::<results::SubscribeResult>(json!({
        "subscribed": true, "added": true, "store_id": STORE, "kind": "profile"
    }));
    assert_result_round_trips::<results::ListSubscriptionsResult>(json!({
        "subscriptions": [STORE], "count": 1
    }));
    assert_result_round_trips::<results::PairingApproveResult>(json!({
        "approved": true, "client_name": "DIG extension", "token_id": "abcd1234"
    }));
    assert_result_round_trips::<results::PairingPollResult>(json!({
        "status": "approved", "token": "deadbeef"
    }));
    assert_result_round_trips::<results::WalletBalanceResult>(json!({
        "balance": 1234u64, "pending": 0u64,
        "source": "db", "synced": true, "peak_height": 5000000u32
    }));
    assert_result_round_trips::<results::WalletCoinsResult>(json!({
        "coins": [{
            "coin_id": "aa".repeat(32), "asset": "xch", "amount": 1_750_000_000_000u64,
            "parent_coin_info": "bb".repeat(32), "puzzle_hash": "cc".repeat(32),
            "created_height": 5_000_000u32, "spent_height": null
        }],
        "source": "db", "synced": true, "peak_height": 5_000_000u32
    }));
    // A chain that was consulted and holds nothing. It must be expressible as a SUCCESS, because
    // that is the only shape that leaves "unreachable" free to be an error.
    assert_result_round_trips::<results::WalletCoinsResult>(json!({
        "coins": [], "source": "fallback", "synced": false, "peak_height": null
    }));
    // `control.wallet.coinById` — the SPENT coin. No `.coins` vector can carry one: that method
    // answers with unspent coins only, which is exactly why observing a mint needs this method.
    // `asset` is null because a coin id alone does not classify a coin (see `WalletCoinRecord`).
    assert_result_round_trips::<results::WalletCoinByIdResult>(json!({
        "coin": {
            "coin_id": "ab".repeat(32), "asset": null, "amount": 1_000_000_000_000u64,
            "parent_coin_info": "bb".repeat(32), "puzzle_hash": "cc".repeat(32),
            "created_height": 5_000_000u32, "spent_height": 5_000_042u32
        },
        "source": "fallback", "synced": false, "peak_height": null
    }));
    // A chain that was consulted and holds no such coin. A SUCCESS, so that "unreachable" stays
    // free to be an error.
    assert_result_round_trips::<results::WalletCoinByIdResult>(json!({
        "coin": null, "source": "fallback", "synced": false, "peak_height": null
    }));
    // The DB tier, which every other by-id vector leaves unexercised. `source:"db"` means the node's
    // OWN replica answered, so it carries `synced:true` and that replica's peak — the same binding
    // the by-address reads have always had. A db answer reporting `synced:false` would be a stale
    // view issuing a verdict; see `WalletCoinByIdResult`.
    assert_result_round_trips::<results::WalletCoinByIdResult>(json!({
        "coin": {
            "coin_id": "ab".repeat(32), "asset": null, "amount": 1_000_000_000_000u64,
            "parent_coin_info": "bb".repeat(32), "puzzle_hash": "cc".repeat(32),
            "created_height": 5_000_000u32, "spent_height": null
        },
        "source": "db", "synced": true, "peak_height": 5_000_100u32
    }));
    // `control.wallet.coinSpend` — a spend, carrying the two programs a coin record cannot supply.
    // The spent coin's `spent_height` is non-null, because a spend exists only where one is.
    assert_result_round_trips::<results::WalletCoinSpendResult>(json!({
        "spend": {
            "coin": {
                "coin_id": "ab".repeat(32), "asset": null, "amount": 1_000_000_000_000u64,
                "parent_coin_info": "bb".repeat(32), "puzzle_hash": "cc".repeat(32),
                "created_height": 5_000_000u32, "spent_height": 5_000_042u32
            },
            "puzzle_reveal": REVEAL_HEX, "solution": SOLUTION_HEX
        },
        "source": "db", "synced": true, "peak_height": 5_000_100u32
    }));
    // A chain that was consulted and holds no spend of that coin — unspent, or unknown. A SUCCESS,
    // so that "could not answer" stays free to be an error.
    assert_result_round_trips::<results::WalletCoinSpendResult>(json!({
        "spend": null, "source": "fallback", "synced": false, "peak_height": null
    }));
    // `control.wallet.coinsByParent` — one hop. `asset` is null on the child, because naming a coin
    // by its parent classifies nothing.
    assert_result_round_trips::<results::WalletCoinsByParentResult>(json!({
        "coins": [{
            "coin_id": CHILD_COINS[0], "asset": null, "amount": 999_999_999_999u64,
            "parent_coin_info": "ab".repeat(32), "puzzle_hash": "33".repeat(32),
            "created_height": 5_000_042u32, "spent_height": null
        }],
        "complete": true, "cursor": CHILD_COINS[0],
        "source": "db", "synced": true, "peak_height": 5_000_100u32
    }));
    // A TRUNCATED page: same shape, `complete:false`, and a cursor to resume from. Pinned beside the
    // complete vector above so the two are visibly different payloads rather than one shape read two
    // ways.
    assert_result_round_trips::<results::WalletCoinsByParentResult>(json!({
        "coins": [{
            "coin_id": CHILD_COINS[0], "asset": null, "amount": 999_999_999_999u64,
            "parent_coin_info": "ab".repeat(32), "puzzle_hash": "33".repeat(32),
            "created_height": 5_000_042u32, "spent_height": null
        }],
        "complete": false, "cursor": CHILD_COINS[0],
        "source": "db", "synced": true, "peak_height": 5_000_100u32
    }));
    // A parent that created no known children. A SUCCESS, for the same reason an empty `.coins` is.
    // An empty page is COMPLETE and has no cursor: there was nothing to be handed.
    assert_result_round_trips::<results::WalletCoinsByParentResult>(json!({
        "coins": [], "complete": true, "cursor": null,
        "source": "fallback", "synced": false, "peak_height": null
    }));
    assert_result_round_trips::<results::WalletPeakResult>(json!({
        "peak_height": 5_000_000u32, "synced": true
    }));
    assert_result_round_trips::<results::WalletPeakResult>(json!({
        "peak_height": null, "synced": false
    }));
    // `control.wallet.syncStatus`, every phase. `not_started` carries a null height rather
    // than 0 -- a wallet that has never synced and a wallet synced to the genesis block must not
    // wear the same shape -- and `chia_peer_count` is present in every one of them, because the
    // count is what turns "syncing" into either "syncing" or "syncing, connected to nothing".
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "not_started", "peak_height": null, "chia_peer_count": 0u32,
        "watched_addresses": 0u32, "subscription_peer_count": null, "chia_peer_peak_height": null
    }));
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "syncing", "peak_height": 4_000_000u32, "chia_peer_count": 3u32,
        "watched_addresses": 12u32, "subscription_peer_count": 1u32,
        "chia_peer_peak_height": 4_000_200u32
    }));
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "synced", "peak_height": 5_000_000u32, "chia_peer_count": 5u32,
        "watched_addresses": 12u32, "subscription_peer_count": 1u32,
        "chia_peer_peak_height": 5_000_000u32
    }));
    // THE RESTART STATE: a height with no sync running. Not a contradiction -- the height is
    // persisted in the wallet DB while the phase describes this PROCESS -- so the contract permits
    // it explicitly and this vector pins that it stays expressible. A shape that forbade it would
    // force a restarted node to fabricate a phase or discard a height it genuinely has.
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "not_started", "peak_height": 4_900_000u32, "chia_peer_count": 0u32,
        "watched_addresses": 12u32, "subscription_peer_count": null, "chia_peer_peak_height": null
    }));
    // A node that cannot observe the peer count at all: `null`, which is NOT `0`. `0` is a measured
    // zero and licenses "syncing -- no peers"; `null` licenses no claim about connectivity.
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "syncing", "peak_height": null, "chia_peer_count": null,
        "watched_addresses": null, "subscription_peer_count": null, "chia_peer_peak_height": null
    }));
    // THE TWO IDLE STATES, which differ only in the phase token and mean opposite things. Pinned
    // adjacently and with an identical `watched_addresses: 0`, because the count alone cannot tell
    // them apart -- the token is the only thing carrying "and that is fine" versus "and it is not".
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "no_wallet_enrolled", "peak_height": null, "chia_peer_count": 0u32,
        "watched_addresses": 0u32, "subscription_peer_count": null, "chia_peer_peak_height": null
    }));
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "wallet_not_unlocked", "peak_height": 4_900_000u32, "chia_peer_count": 2u32,
        "watched_addresses": 0u32, "subscription_peer_count": null, "chia_peer_peak_height": null
    }));
    // A TOKEN FROM A NEWER NODE, round-tripping VERBATIM. This vector is the contract's promise that
    // an unrecognised phase survives a decode-re-encode unchanged: a consumer that relays or logs
    // the payload hands on what the node actually said, rather than a token this build invented.
    assert_result_round_trips::<results::WalletSyncStatusResult>(json!({
        "phase": "a_phase_from_a_newer_node", "peak_height": 5_000_000u32, "chia_peer_count": 3u32,
        "watched_addresses": 12u32, "subscription_peer_count": 1u32,
        "chia_peer_peak_height": 5_000_100u32
    }));
    // `control.peerCounts` — the three counts, each named. A node connected to both networks, and
    // knowing of more DIG peers than it holds connections to (the ordinary case).
    assert_result_round_trips::<results::PeerCountsResult>(json!({
        "dig_peer_count": 6u32, "chia_peer_count": 3u32, "known_dig_peer_count": 41u32
    }));
    // Observed zeros on every count: the node looked and found nothing. Pinned separately from the
    // null case below, because a node with no peer network RUNNING has an unknown count and must
    // not report it as a measured zero.
    assert_result_round_trips::<results::PeerCountsResult>(json!({
        "dig_peer_count": 0u32, "chia_peer_count": 0u32, "known_dig_peer_count": 0u32
    }));
    // Unobservable on every count. `null` is not `0` for any of them.
    assert_result_round_trips::<results::PeerCountsResult>(json!({
        "dig_peer_count": null, "chia_peer_count": null, "known_dig_peer_count": null
    }));
    // Three DIFFERENT values, and this vector is the one that matters: it varies all three counts
    // INDEPENDENTLY, so a serialization that transposed any pair of field names — the nearest wrong
    // implementation, and exactly the confusion this method exists to end — cannot survive it. The
    // `known` value is deliberately unequal to `dig_peer_count`, so an implementation that served
    // the connected count for both fails here rather than reading as plausible.
    assert_result_round_trips::<results::PeerCountsResult>(json!({
        "dig_peer_count": 6u32, "chia_peer_count": null, "known_dig_peer_count": 41u32
    }));
    // THE diagnostic vector (#2570): connected to nobody while knowing of many. This is the state
    // the field was added to make expressible — a reachability fault, which a client must be able
    // to tell apart from the discovery fault that the all-zero vector above describes.
    assert_result_round_trips::<results::PeerCountsResult>(json!({
        "dig_peer_count": 0u32, "chia_peer_count": 3u32, "known_dig_peer_count": 41u32
    }));
    assert_result_round_trips::<results::WalletBroadcastResult>(json!({
        "accepted": true, "transaction_id": "dd".repeat(32), "rejection": null
    }));
    assert_result_round_trips::<results::WalletBroadcastResult>(json!({
        "accepted": false, "transaction_id": null, "rejection": "DOUBLE_SPEND"
    }));
    // A fallback-tier answer: `synced` is false and `peak_height` is present as `null` (never
    // omitted), because neither describes a figure the node's own replica did not produce.
    assert_result_round_trips::<results::WalletBalanceResult>(json!({
        "balance": 0u64, "pending": 7u64,
        "source": "fallback", "synced": false, "peak_height": null
    }));
}

/// `source` is ADDITIVE in BOTH directions (dig_ecosystem#2233), which is the property that lets
/// this crate ship ahead of the nodes that emit the field.
///
/// The fixture that matters is the one WITHOUT the key: a node released before tier disclosure
/// emits no `source` at all, and 0.5.0 must still parse that payload. A test that only round-trips
/// a payload carrying the field cannot see a missing `#[serde(default)]` — the field is required on
/// deserialize, every fixture supplies it, and the break surfaces only against a real older node.
#[test]
fn a_pre_disclosure_nodes_payload_still_parses_with_the_tier_unknown() {
    let legacy = json!({
        "balance": 1234u64, "pending": 0u64, "synced": true, "peak_height": 5000000u32
    });
    let parsed: results::WalletBalanceResult =
        serde_json::from_value(legacy).expect("a node predating `source` must still deserialize");

    assert_eq!(parsed.balance, 1234);
    assert_eq!(
        parsed.source, None,
        "an absent tier is UNKNOWN -- never silently reported as one of the two tiers"
    );
}

/// The two tiers spell themselves on the wire as the lowercase tokens dig-node emits, pinned
/// literally so a Rust variant rename cannot silently change what a consumer must match on.
#[test]
fn the_tier_tokens_are_the_lowercase_wire_spellings() {
    for (src, wire) in [
        (results::WalletReadSource::Db, "db"),
        (results::WalletReadSource::Fallback, "fallback"),
    ] {
        assert_eq!(serde_json::to_value(src).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<results::WalletReadSource>(json!(wire)).unwrap(),
            src
        );
    }
}

/// The wallet-sync phases spell themselves on the wire as these exact snake_case tokens, pinned
/// literally so renaming a Rust variant cannot silently change what a consumer must match on.
///
/// [`results::WalletSyncPhase::ALL`] is checked against the pinned list in BOTH directions, because
/// it is the anchor the node side derives its own conformance assertion from: a variant missing from
/// `ALL` would quietly shrink that safety net, and a variant in `ALL` with no pinned spelling would
/// leave a real wire token unpinned.
#[test]
fn the_wallet_sync_phase_tokens_are_the_snake_case_wire_spellings() {
    let pinned: &[(results::WalletSyncPhase, &str)] = &[
        (results::WalletSyncPhase::NotStarted, "not_started"),
        (results::WalletSyncPhase::Syncing, "syncing"),
        (results::WalletSyncPhase::Synced, "synced"),
        (
            results::WalletSyncPhase::NoWalletEnrolled,
            "no_wallet_enrolled",
        ),
        (
            results::WalletSyncPhase::WalletNotUnlocked,
            "wallet_not_unlocked",
        ),
    ];
    for (phase, wire) in pinned {
        assert_eq!(serde_json::to_value(phase).unwrap(), json!(wire));
        assert_eq!(
            &serde_json::from_value::<results::WalletSyncPhase>(json!(wire)).unwrap(),
            phase
        );
        assert_eq!(phase.as_wire(), *wire, "as_wire must be the same spelling");
    }

    for phase in results::WalletSyncPhase::ALL {
        assert!(
            pinned.iter().any(|(pinned_phase, _)| pinned_phase == phase),
            "{phase:?} is in ALL but has no pinned wire spelling"
        );
        assert!(
            phase.is_recognized(),
            "ALL enumerates the KNOWN phases; Unrecognized is the absence of one"
        );
        assert_eq!(
            expected_wire(phase),
            Some(phase.as_wire()),
            "{phase:?} disagrees with the compiler-checked spelling table"
        );
    }

    // DISTINCT, or the length check below is satisfiable by a duplicate standing in for a dropped
    // variant — the pigeonhole hole in a bare count comparison.
    for (i, phase) in results::WalletSyncPhase::ALL.iter().enumerate() {
        assert!(
            !results::WalletSyncPhase::ALL[..i].contains(phase),
            "{phase:?} appears twice in ALL"
        );
    }
    assert_eq!(
        results::WalletSyncPhase::ALL.len(),
        pinned.len(),
        "every pinned phase must also appear in ALL — the node side derives its conformance \
         assertion from ALL, so a variant missing here disables that check silently"
    );
}

/// The wire spelling of every phase, as a match the COMPILER checks for exhaustiveness.
///
/// This is the guard the two hand-written tables above cannot provide for themselves. `ALL`, the
/// `pinned` list, and [`results::WalletSyncPhase::as_wire`] are three separate enumerations of the
/// same set; a sixth variant added to the enum and to `as_wire` but forgotten in the other two would
/// leave a real wire token unpinned, and every test would stay green while dig-node's derived
/// conformance assertion silently shrank.
///
/// Adding a variant fails to COMPILE here instead. Whoever fixes the compile error must give the new
/// phase a spelling, and the assertions above then force it into `ALL` and into `pinned` before the
/// suite can pass again.
fn expected_wire(phase: &results::WalletSyncPhase) -> Option<&'static str> {
    match phase {
        results::WalletSyncPhase::NotStarted => Some("not_started"),
        results::WalletSyncPhase::Syncing => Some("syncing"),
        results::WalletSyncPhase::Synced => Some("synced"),
        results::WalletSyncPhase::NoWalletEnrolled => Some("no_wallet_enrolled"),
        results::WalletSyncPhase::WalletNotUnlocked => Some("wallet_not_unlocked"),
        // Not a wire token: it is whatever a newer node said, and has no fixed spelling to pin.
        results::WalletSyncPhase::Unrecognized(_) => None,
    }
}

/// **No phase value can call itself unrecognised while spelling itself as a known token.**
///
/// The defect this pins was real and shipped in an earlier revision of this branch: with a public
/// `String` inside the variant, `Unrecognized("synced".to_owned())` was constructible by any
/// consumer. It reported `is_recognized() == false` locally, went onto the wire as the bare token
/// `"synced"`, and arrived at the far side as a confident `Synced` — the money-lie this family exists
/// to prevent, reintroduced by the very variant meant to prevent it. It was also the one value in
/// the type that did not round-trip.
///
/// [`results::UnknownPhaseToken`] now has a private field and no public constructor, so the only
/// route to `Unrecognized` from outside is the TOTAL `From<&str>`, which hands back a known variant
/// for a known spelling. The property below is what that buys, stated as an invariant over every
/// value the public API can produce: **decoding a phase's own wire spelling always returns that same
/// phase.**
#[test]
fn every_phase_decodes_back_to_itself_from_its_own_wire_spelling() {
    let unknown_spellings = [
        "no_addresses_to_watch",
        "a_newer_token",
        "",
        "SYNCED",
        " synced",
    ];

    let reachable = results::WalletSyncPhase::ALL
        .iter()
        .map(|phase| phase.as_wire().to_owned())
        .chain(unknown_spellings.iter().map(|s| (*s).to_owned()));

    for spelling in reachable {
        let phase = results::WalletSyncPhase::from(spelling.as_str());

        assert_eq!(
            results::WalletSyncPhase::from(phase.as_wire()),
            phase,
            "{spelling:?} produced a phase whose own spelling decodes to something else"
        );
        assert_eq!(
            phase.is_recognized(),
            results::WalletSyncPhase::ALL.contains(&phase),
            "{spelling:?}: is_recognized() must agree with membership of the known set"
        );
        // The decisive one: a value calling itself unrecognised must never spell itself as ANY
        // known token. Checking only synced/syncing would leave `no_wallet_enrolled` -- equally an
        // all-clear -- reachable by a future forging route.
        if !phase.is_recognized() {
            assert!(
                !results::WalletSyncPhase::ALL
                    .iter()
                    .any(|known| known.as_wire() == phase.as_wire()),
                "{spelling:?} is unrecognised locally but spells itself as a known phase"
            );
        }
    }
}

/// **`not_started` and a synced-at-genesis wallet are different values.** The fixture varies ONLY the
/// phase while holding the height at the one value a bool-plus-height shape would collapse, so an
/// implementation that reported progress as `synced: false` + `peak_height: 0` -- the nearest wrong
/// shape, and the one `WalletPeakResult` already has -- cannot pass.
#[test]
fn never_started_is_distinguishable_from_synced_at_height_zero() {
    let never_started = serde_json::to_value(results::WalletSyncStatusResult {
        phase: results::WalletSyncPhase::NotStarted,
        peak_height: None,
        chia_peer_count: Some(0),
        watched_addresses: Some(0),
        subscription_peer_count: None,
        chia_peer_peak_height: None,
    })
    .unwrap();
    let synced_at_genesis = serde_json::to_value(results::WalletSyncStatusResult {
        phase: results::WalletSyncPhase::Synced,
        peak_height: Some(0),
        chia_peer_count: Some(1),
        watched_addresses: Some(4),
        subscription_peer_count: Some(1),
        chia_peer_peak_height: Some(0),
    })
    .unwrap();

    assert_ne!(never_started, synced_at_genesis);
    assert_eq!(never_started["peak_height"], json!(null));
    assert_eq!(
        synced_at_genesis["peak_height"],
        json!(0),
        "height 0 is a real height and must survive the round trip as one"
    );
}

/// **The prose documents name every catalogued method.**
///
/// Prose has no compiler, so a method added to the catalog can leave `SPEC.md` and `README.md`
/// describing an older, smaller surface — and both documents CLAIM to be exhaustive, which is what
/// makes the drift harmful rather than merely untidy. `README.md` is read as the agent-facing
/// interface reference and `SPEC.md` §2.1/§4 as the normative token-gating rule, so a missing method
/// there is a reimplementer gating the wrong set.
///
/// This is deliberately a MEMBERSHIP check, not a count: a hardcoded number in prose drifts
/// silently, whereas an absent name fails here by construction the moment the catalog grows.
#[test]
fn the_spec_and_readme_name_every_catalogued_method() {
    for (doc, text) in [
        ("SPEC.md", include_str!("../SPEC.md")),
        ("README.md", include_str!("../README.md")),
    ] {
        for &m in ControlMethod::ALL {
            assert!(
                text.contains(m.name()),
                "{doc} never mentions `{}` -- the document claims to be exhaustive",
                m.name()
            );
        }
        // The phase tokens are normative wire contract too, and are spelled out by hand in BOTH
        // documents. A reimplementer reads them as the definitive set, so a token added to the enum
        // and forgotten in the prose is a real defect, not a tidiness one -- the same reason the
        // method names above are guarded rather than trusted.
        //
        // The QUOTED spelling is what is searched for, not the bare word. `synced` and `syncing`
        // occur throughout both documents as ordinary English and as the unrelated
        // `WalletPeakResult.synced` FIELD, so a bare `contains` would pass for those two even if the
        // token itself were deleted -- vacuous for exactly the tokens with the most prose around
        // them. Every token appears quoted, so requiring the quotes costs nothing and restores the
        // guard's teeth.
        for phase in results::WalletSyncPhase::ALL {
            let quoted = format!("{:?}", phase.as_wire());
            assert!(
                text.contains(&quoted),
                "{doc} never mentions the {quoted} phase token in its quoted wire spelling"
            );
        }
    }

    // The catalog's own summary string is the third hand-written copy, and the one a machine reads
    // when it introspects the surface (§6.2 self-describing).
    let summary = ControlMethod::WalletSyncStatus.summary();
    for phase in results::WalletSyncPhase::ALL {
        assert!(
            summary.contains(phase.as_wire()),
            "control.wallet.syncStatus's summary omits the `{}` token",
            phase.as_wire()
        );
    }
}

/// **Each count names its own network, and the two are not interchangeable.**
///
/// The wire keys are pinned as LITERALS rather than derived from the struct, because the whole
/// reason this method exists is that a consumer reaching for a bare `peers`/`connected_peers`/
/// `peer_count` eventually reaches for the wrong network and gets a plausible number. A rename that
/// dropped a network out of a key would be invisible to a derived assertion.
///
/// The fixture gives all three counts DIFFERENT values, so an implementation that transposed any
/// pair — the nearest wrong one — fails here rather than passing on a shape they share.
#[test]
fn each_peer_count_key_names_its_network() {
    let wire = serde_json::to_value(results::PeerCountsResult {
        dig_peer_count: Some(6),
        chia_peer_count: Some(3),
        known_dig_peer_count: Some(41),
    })
    .unwrap();

    assert_eq!(wire["dig_peer_count"], json!(6));
    assert_eq!(wire["chia_peer_count"], json!(3));
    assert_eq!(wire["known_dig_peer_count"], json!(41));
    // The KEY SET, exactly -- so a bare `peers` / `connected_peers` / `peer_count` cannot appear
    // alongside the named pair either. (`serde_json::Value` orders its map, so this is a set
    // assertion by construction; the emitted TEXT below is what a consumer actually parses.)
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["chia_peer_count", "dig_peer_count", "known_dig_peer_count"]
    );
    assert_eq!(
        serde_json::to_string(&results::PeerCountsResult {
            dig_peer_count: Some(6),
            chia_peer_count: Some(3),
            known_dig_peer_count: Some(41),
        })
        .unwrap(),
        r#"{"dig_peer_count":6,"chia_peer_count":3,"known_dig_peer_count":41}"#,
        "the emitted bytes name each network and give the two counts independently"
    );
}

/// **The two `chia_peer_count` fields are ONE observation under ONE key.**
///
/// The field is deliberately duplicated across `control.peerCounts` and
/// `control.wallet.syncStatus`, and the contract's answer to that duplication is that a conforming
/// node serves both from a single source. That is a node obligation this crate cannot execute — but
/// it can pin the half that makes the obligation expressible: the two payloads must spell the count
/// with the IDENTICAL key, so a node reading one type's field name and emitting the other's cannot
/// arise, and a consumer can compare the two answers at all.
#[test]
fn both_results_spell_the_chia_count_with_the_same_key() {
    const KEY: &str = "chia_peer_count";

    let counts = serde_json::to_value(results::PeerCountsResult {
        dig_peer_count: None,
        chia_peer_count: Some(3),
        known_dig_peer_count: None,
    })
    .unwrap();
    let sync = serde_json::to_value(results::WalletSyncStatusResult {
        phase: results::WalletSyncPhase::Syncing,
        peak_height: Some(4_000_000),
        chia_peer_count: Some(3),
        watched_addresses: Some(4),
        subscription_peer_count: Some(1),
        chia_peer_peak_height: Some(4_000_100),
    })
    .unwrap();

    assert_eq!(counts[KEY], json!(3));
    assert_eq!(sync[KEY], json!(3));
    assert_eq!(
        counts[KEY], sync[KEY],
        "a single node's two answers describe the same observation and must agree"
    );
}

/// **`null` and `0` are different answers for each count, independently.**
///
/// Varies ONE count at a time against a truthful control, so a shape that collapsed absent into zero
/// on either field alone is caught. A node with no peer network running has an UNKNOWN count; a
/// zero there would report "nothing is connected" about a network it never asked.
#[test]
fn an_unobservable_count_is_null_not_zero_on_either_network() {
    let dig_unknown = serde_json::to_value(results::PeerCountsResult {
        dig_peer_count: None,
        chia_peer_count: Some(0),
        known_dig_peer_count: Some(41),
    })
    .unwrap();
    assert_eq!(dig_unknown["dig_peer_count"], json!(null));
    assert_eq!(
        dig_unknown["chia_peer_count"],
        json!(0),
        "an observed zero must survive as a zero beside an unknown"
    );

    let chia_unknown = serde_json::to_value(results::PeerCountsResult {
        dig_peer_count: Some(0),
        chia_peer_count: None,
        known_dig_peer_count: Some(41),
    })
    .unwrap();
    assert_eq!(chia_unknown["dig_peer_count"], json!(0));
    assert_eq!(chia_unknown["chia_peer_count"], json!(null));

    assert_ne!(dig_unknown, chia_unknown);
}

/// The "no dig-app code change" guarantee, pinned: the node's richer `WalletBalanceResult` is a
/// strict SUPERSET of dig-app's frozen `BalanceResponse { balance }`, so dig-app deserializes the
/// node's payload losslessly (its struct does not deny unknown fields) and reads the confirmed
/// balance. This mirrors dig-app's `dig-app-core::wallet::engine::BalanceResponse` byte-for-byte.
#[test]
fn node_balance_superset_is_readable_by_dig_apps_balance_struct() {
    /// Byte-identical mirror of dig-app's frozen `BalanceResponse` — NO `deny_unknown_fields`, so the
    /// node's extra fields (`pending`/`source`/`synced`/`peak_height`) are ignored, not rejected.
    #[derive(serde::Deserialize)]
    struct DigAppBalanceResponse {
        balance: u64,
    }

    // The node emits the full superset...
    let node_payload = serde_json::to_value(results::WalletBalanceResult {
        balance: 9_999,
        pending: 42,
        source: Some(results::WalletReadSource::Db),
        synced: true,
        peak_height: Some(6_123_456),
    })
    .unwrap();

    // ...and dig-app's `{balance}` struct reads it without any code change on dig-app's side.
    let app: DigAppBalanceResponse =
        serde_json::from_value(node_payload).expect("dig-app must read the node's richer payload");
    assert_eq!(
        app.balance, 9_999,
        "dig-app must read the confirmed balance verbatim"
    );
}

#[test]
fn error_envelope_golden_vector() {
    let resp = JsonRpcResponse::error(
        RequestId::Number(1),
        ControlError::of(ControlErrorCode::Unauthorized, "control.* requires a token"),
    );
    assert_eq!(
        serde_json::to_value(&resp).unwrap(),
        json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {
                "code": -32030,
                "message": "control.* requires a token",
                "data": {"code": "UNAUTHORIZED", "origin": "shell"}
            }
        })
    );
}

/// Two well-formed enrolment keys (48-byte G1, lowercase 96-hex), and one that is malformed by
/// being a coin id's length rather than a key's — the nearest wrong spelling a caller reaches for
/// when it enrols puzzle hashes instead of keys, which is the exact confusion this method's key
/// form exists to prevent.
const ENROL_KEY_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const ENROL_KEY_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

// The enrolment registry `MockNode` serves from.
//
// THREAD-LOCAL rather than global: `cargo test` runs each test on its own thread, so every test
// sees an empty registry and one test's enrolment can never make another's idempotence assertion
// pass for the wrong reason. `MockNode` is a unit struct that every KAT constructs by name, so
// per-instance state is not available to it.
thread_local! {
    static ENROLLED: std::cell::RefCell<std::collections::BTreeSet<String>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

/// The instant [`MockNode`] answers at, pinned rather than read from the wall clock.
///
/// A reservation fixture that passes a small literal expiry through an API measured in unix seconds
/// tests only the already-lapsed path, because every such value is ~1.8 billion seconds in the past.
/// Pinning NOW keeps the live path live.
const MOCK_NOW_UNIX: u64 = 1_800_000_000;

/// The longest hold [`MockNode`] will grant, mirroring dig-node's `RESERVATION_TTL_MS` (600 s).
const MOCK_MAX_TTL_SECS: u64 = 600;

/// The hold [`MockNode`] grants when a caller names no TTL, mirroring dig-account's
/// `DEFAULT_RESERVATION_TTL_SECS` (300 s).
const MOCK_DEFAULT_TTL_SECS: u64 = 300;

/// Two DISTINCT coins, so an all-or-none acquisition can be told apart from a partial one.
///
/// A single-coin fixture cannot express the property at all: with one coin, "took none" and "took
/// every coin that was free" produce identical observable state.
const RESERVE_COIN_A: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const RESERVE_COIN_B: &str = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";

thread_local! {
    /// The margin `MockNode` currently holds, so `.set` then `.get` is a real round trip through
    /// stored state rather than two independent echoes of the same literal.
    static MARGIN_BP: std::cell::RefCell<u64> = const { std::cell::RefCell::new(crate::params::DEFAULT_SAFETY_MARGIN_BP) };
}

// The reservation table `MockNode` serves from: reservation_id -> (held coins, expiry).
//
// THREAD-LOCAL for the same reason the enrolment registry is: one test's hold must never satisfy
// another test's conflict assertion for the wrong reason.
thread_local! {
    static RESERVATIONS: std::cell::RefCell<
        std::collections::BTreeMap<String, (Vec<String>, u64)>,
    > = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

/// A mock node that serves canned typed results — exercises the [`ControlHandler`] dispatcher for
/// every method group without a running node.
struct MockNode;

/// The one Chia peer [`MockNode`] pretends to have trusted, canonical per
/// [`crate::params::canonical_peer_ip`].
pub const MOCK_TRUSTED_CHIA_PEER: &str = "203.0.113.7";

/// A peer [`MockNode`] holds as BANNED, so the un-ban-without-trust case is reachable.
///
/// It exists because that case is real, not hypothetical: an upsert that clears the ban flag and
/// leaves the trusted flag alone grants no corroboration bypass, and the result has to say so.
pub const MOCK_BANNED_CHIA_PEER: &str = "198.51.100.9";

/// The verbatim warning [`MockNode`] returns as `ChiaPeersAddResult::notice`.
///
/// A node authors its own wording; what the contract fixes is that the sentence EXISTS on the wire
/// and names the corroboration bypass, so a client quotes it instead of restating it.
/// What [`MockNode`] says when the entry was un-banned but NOT trusted.
pub const MOCK_UNBANNED_WITHOUT_TRUST_NOTICE: &str =
    "This peer is no longer banned, but it was NOT granted trust: chain answers from it still      require corroboration from other peers.";

pub const MOCK_CORROBORATION_BYPASS_NOTICE: &str =
    "This node will now believe 203.0.113.7 WITHOUT corroboration: chain answers from it are \
     accepted on their own, with no agreement from other peers. Add only a node you run yourself.";

#[async_trait::async_trait]
impl ControlHandler for MockNode {
    async fn status(&self) -> Result<results::StatusResult, ControlError> {
        Ok(results::StatusResult {
            running: true,
            service: "dig-node".into(),
            version: "0.30.0".into(),
            commit: "deadbee".into(),
            protocol: "21".into(),
            uptime_secs: 1,
            addr: "127.0.0.1:9256".into(),
            upstream: "https://rpc.dig.net".into(),
            cache: results::CacheView {
                cap_bytes: 67108864,
                used_bytes: 0,
                dir: "/c".into(),
                shared: false,
            },
            hosted_store_count: 0,
            cached_capsule_count: 0,
            pinned_store_count: 0,
            sync: results::SyncAvailability { available: false },
        })
    }
    async fn config_get(&self) -> Result<results::ConfigResult, ControlError> {
        Ok(results::ConfigResult {
            addr: "127.0.0.1".into(),
            port: "9256".into(),
            upstream: "https://rpc.dig.net".into(),
            upstream_override: None,
            cache_dir: "/tmp/cache".into(),
            cache_shared: false,
            config_path: "/tmp/config.json".into(),
            sync_available: true,
        })
    }
    async fn config_set_upstream(
        &self,
        params: SetUpstreamParams,
    ) -> Result<results::SetUpstreamResult, ControlError> {
        if params.upstream == UNSUPPORTED_UPSTREAM {
            return Err(unimpl("config_set_upstream"));
        }
        Ok(results::SetUpstreamResult {
            upstream: params.upstream,
            requires_restart: true,
        })
    }
    async fn log_set_level(
        &self,
        params: SetLevelParams,
    ) -> Result<results::SetLevelResult, ControlError> {
        Ok(results::SetLevelResult {
            filter: params.filter,
        })
    }
    async fn cache_get(&self) -> Result<results::CacheView, ControlError> {
        Ok(results::CacheView {
            cap_bytes: 64 * 1024 * 1024,
            used_bytes: 1024,
            dir: "/tmp/cache".into(),
            shared: false,
        })
    }
    async fn cache_set_cap(
        &self,
        params: SetCapParams,
    ) -> Result<results::SetCapResult, ControlError> {
        Ok(results::SetCapResult {
            cap_bytes: params.cap_bytes.max(64 * 1024 * 1024),
        })
    }
    async fn cache_clear(&self) -> Result<results::CacheClearResult, ControlError> {
        Ok(results::CacheClearResult { cleared: true })
    }
    async fn hosted_stores_list(&self) -> Result<results::HostedStoresListResult, ControlError> {
        Ok(results::HostedStoresListResult { stores: vec![] })
    }
    async fn hosted_stores_pin(
        &self,
        params: PinParams,
    ) -> Result<results::PinResult, ControlError> {
        Ok(results::PinResult {
            store_id: params.store,
            root: None,
            pinned: true,
            fetch: json!({"status": "skipped"}),
        })
    }
    async fn hosted_stores_unpin(
        &self,
        params: UnpinParams,
    ) -> Result<results::UnpinResult, ControlError> {
        Ok(results::UnpinResult {
            store_id: params.store,
            unpinned: true,
            evicted_capsules: 0,
        })
    }
    async fn hosted_stores_status(
        &self,
        params: HostedStoreStatusParams,
    ) -> Result<results::HostedStoreStatusResult, ControlError> {
        Ok(results::HostedStoreStatusResult {
            store_id: params.store,
            pinned: false,
            capsule_count: 0,
            total_bytes: 0,
            capsules: vec![],
        })
    }
    async fn capsule_fetch(
        &self,
        params: CapsuleFetchParams,
    ) -> Result<results::CapsuleFetchResult, ControlError> {
        Ok(results::CapsuleFetchResult {
            store: params.store,
            root: params.root,
            status: "started".into(),
        })
    }
    async fn sync_status(&self) -> Result<results::SyncStatusResult, ControlError> {
        Ok(results::SyncStatusResult {
            available: true,
            method: "dig-sync".into(),
            pinned_total: 0,
            pinned_synced: 0,
            whole_store_trigger_supported: true,
        })
    }
    async fn sync_trigger(
        &self,
        params: SyncTriggerParams,
    ) -> Result<results::SyncTriggerResult, ControlError> {
        let (store_id, root) = params.store.split_once(':').unwrap_or((&params.store, ""));
        Ok(results::SyncTriggerResult {
            store_id: store_id.into(),
            root: root.into(),
            status: "synced".into(),
            size_bytes: 1,
            served_root: root.into(),
        })
    }
    async fn updater_status(&self) -> Result<Value, ControlError> {
        Ok(json!({"channel": "stable"}))
    }
    async fn updater_set_channel(&self, params: SetChannelParams) -> Result<Value, ControlError> {
        Ok(json!({"channel": params.channel}))
    }
    async fn updater_pause(&self, params: PauseParams) -> Result<Value, ControlError> {
        Ok(json!({"paused": true, "until": params.until}))
    }
    async fn updater_resume(&self) -> Result<Value, ControlError> {
        Ok(json!({"paused": false}))
    }
    async fn updater_check_now(&self) -> Result<Value, ControlError> {
        Ok(json!({"checked": true}))
    }
    async fn pairing_list(&self) -> Result<Value, ControlError> {
        Ok(json!({"pending": [], "tokens": []}))
    }
    async fn pairing_approve(
        &self,
        params: ApproveParams,
    ) -> Result<results::PairingApproveResult, ControlError> {
        Ok(results::PairingApproveResult {
            approved: true,
            client_name: params.pairing_id,
            token_id: "abcd1234".into(),
        })
    }
    async fn pairing_revoke(
        &self,
        params: RevokeParams,
    ) -> Result<results::PairingRevokeResult, ControlError> {
        Ok(results::PairingRevokeResult {
            revoked: true,
            token_id: params.token_id,
        })
    }
    async fn peer_status(&self) -> Result<Value, ControlError> {
        Ok(json!({"running": false}))
    }
    async fn peers_connect(
        &self,
        params: PeersConnectParams,
    ) -> Result<results::PeersConnectResult, ControlError> {
        Ok(results::PeersConnectResult {
            connected: true,
            peer_id: params.peer,
        })
    }
    async fn peers_disconnect(
        &self,
        params: PeersDisconnectParams,
    ) -> Result<results::PeersDisconnectResult, ControlError> {
        Ok(results::PeersDisconnectResult {
            disconnected: true,
            peer_id: params.peer,
        })
    }
    async fn chia_peers_add(
        &self,
        params: ChiaPeersAddParams,
    ) -> Result<results::ChiaPeersAddResult, ControlError> {
        let ip = crate::params::canonical_peer_ip(&params.ip)?;
        // Adding a BANNED peer clears the ban and grants no trust, so the bypass did not happen
        // and the result must not claim it did.
        let trusted = ip != MOCK_BANNED_CHIA_PEER;
        Ok(results::ChiaPeersAddResult {
            added: true,
            ip,
            port: 8444,
            corroboration_bypassed: trusted,
            notice: if trusted {
                MOCK_CORROBORATION_BYPASS_NOTICE.to_string()
            } else {
                MOCK_UNBANNED_WITHOUT_TRUST_NOTICE.to_string()
            },
        })
    }
    async fn chia_peers_list(&self) -> Result<results::ChiaPeersListResult, ControlError> {
        Ok(results::ChiaPeersListResult {
            peers: vec![
                results::ChiaPeerEntry {
                    ip: MOCK_TRUSTED_CHIA_PEER.into(),
                    port: 8444,
                    peak_height: Some(6_000_010),
                    user_managed: true,
                    banned: false,
                },
                // A peer nobody has polled yet: `null`, never `0` — see `ChiaPeerEntry`.
                results::ChiaPeerEntry {
                    ip: "2001:db8::2".into(),
                    port: 8444,
                    peak_height: None,
                    user_managed: false,
                    banned: false,
                },
            ],
        })
    }
    async fn chia_peers_remove(
        &self,
        params: ChiaPeersRemoveParams,
    ) -> Result<results::ChiaPeersRemoveResult, ControlError> {
        let ip = crate::params::canonical_peer_ip(&params.ip)?;
        // The mock knows ONE peer, so it can answer the question honestly instead of asserting
        // success — which is the whole point of the outcome enum.
        let outcome = if ip == MOCK_TRUSTED_CHIA_PEER {
            results::ChiaPeerRemovalOutcome::Removed
        } else {
            results::ChiaPeerRemovalOutcome::NoSuchPeer
        };
        Ok(results::ChiaPeersRemoveResult {
            outcome,
            banned: params.ban && outcome == results::ChiaPeerRemovalOutcome::Removed,
            ip,
        })
    }
    async fn subscribe(
        &self,
        params: SubscribeParams,
    ) -> Result<results::SubscribeResult, ControlError> {
        Ok(results::SubscribeResult {
            subscribed: true,
            added: true,
            store_id: params.store_id,
            kind: params.kind,
        })
    }
    async fn unsubscribe(
        &self,
        params: UnsubscribeParams,
    ) -> Result<results::UnsubscribeResult, ControlError> {
        Ok(results::UnsubscribeResult {
            subscribed: false,
            removed: true,
            store_id: params.store_id,
        })
    }
    async fn list_subscriptions(&self) -> Result<results::ListSubscriptionsResult, ControlError> {
        Ok(results::ListSubscriptionsResult {
            subscriptions: vec![],
            count: 0,
        })
    }
    async fn wallet_balance(
        &self,
        _params: WalletBalanceParams,
    ) -> Result<results::WalletBalanceResult, ControlError> {
        Ok(results::WalletBalanceResult {
            balance: 1234,
            pending: 0,
            source: Some(results::WalletReadSource::Db),
            synced: true,
            peak_height: Some(5_000_000),
        })
    }
    /// Echoes the REQUEST into the coin so a mis-routed dispatch cannot look like a hit: the coin
    /// id carries the address and the amount carries the asset.
    async fn wallet_coins(
        &self,
        params: WalletCoinsParams,
    ) -> Result<results::WalletCoinsResult, ControlError> {
        Ok(results::WalletCoinsResult {
            coins: vec![results::WalletCoinRecord {
                coin_id: params.address,
                asset: Some(params.asset),
                amount: match params.asset {
                    Asset::Xch => 1,
                    a if a.is_dig() => 2,
                    Asset::Cat(_) => 3,
                },
                parent_coin_info: "11".repeat(32),
                puzzle_hash: "22".repeat(32),
                created_height: Some(5_000_000),
                spent_height: None,
            }],
            source: Some(results::WalletReadSource::Db),
            synced: true,
            peak_height: Some(5_000_000),
        })
    }
    /// Knows exactly one coin — [`SPENT_COIN`] — and reports every other id as absent. Two ids, not
    /// one, so a handler that answered `coin: null` unconditionally (or echoed whatever it was
    /// asked) could not pass the routing test below.
    async fn wallet_coin_by_id(
        &self,
        params: WalletCoinByIdParams,
    ) -> Result<results::WalletCoinByIdResult, ControlError> {
        let coin = (params.coin_id == SPENT_COIN).then(|| results::WalletCoinRecord {
            coin_id: SPENT_COIN.into(),
            asset: None,
            amount: 1_000_000_000_000,
            parent_coin_info: "11".repeat(32),
            puzzle_hash: "22".repeat(32),
            created_height: Some(5_000_000),
            spent_height: Some(5_000_042),
        });
        Ok(results::WalletCoinByIdResult {
            coin,
            source: Some(results::WalletReadSource::Fallback),
            synced: false,
            peak_height: None,
        })
    }
    /// Reports a spend ONLY for [`SPENT_COIN`], and absence for every other id — so a handler that
    /// answered `spend: null` unconditionally is distinguishable from a correct one. The reveal and
    /// the solution differ from each other, so a serialization that transposed the two fields fails
    /// the routing test below rather than passing on a shape they share.
    async fn wallet_coin_spend(
        &self,
        params: WalletCoinSpendParams,
    ) -> Result<results::WalletCoinSpendResult, ControlError> {
        let spend = (params.coin_id == SPENT_COIN).then(|| results::WalletCoinSpend {
            coin: results::WalletCoinRecord {
                coin_id: SPENT_COIN.into(),
                asset: None,
                amount: 1_000_000_000_000,
                parent_coin_info: "11".repeat(32),
                puzzle_hash: "22".repeat(32),
                created_height: Some(5_000_000),
                // A spend exists only because the coin was spent, so this is never null.
                spent_height: Some(5_000_042),
            },
            puzzle_reveal: REVEAL_HEX.into(),
            solution: SOLUTION_HEX.into(),
        });
        Ok(results::WalletCoinSpendResult {
            spend,
            source: Some(results::WalletReadSource::Fallback),
            synced: false,
            peak_height: None,
        })
    }
    /// Serves [`SPENT_COIN`]'s four children as a real PAGED read — honouring `after_coin_id` and
    /// the effective limit — and reports every other parent as childless.
    ///
    /// A mock that ignored the page bound could not express a truncated answer at all, so the
    /// truncation tests below would assert a property the fixture cannot exhibit. `complete` is
    /// computed from what REMAINS after the page rather than from the page's own length, which is
    /// the distinction those tests exist to pin.
    async fn wallet_coins_by_parent(
        &self,
        params: WalletCoinsByParentParams,
    ) -> Result<results::WalletCoinsByParentResult, ControlError> {
        let known: &[&str] = if params.parent_coin_id == SPENT_COIN {
            &CHILD_COINS
        } else {
            &[]
        };
        let remaining = known
            .iter()
            .skip_while(|id| params.after_coin_id.as_deref().is_some_and(|a| **id <= a));
        let limit = params.effective_limit() as usize;
        let page: Vec<&str> = remaining.take(limit + 1).copied().collect();
        let complete = page.len() <= limit;
        let coins: Vec<results::WalletCoinRecord> = page
            .into_iter()
            .take(limit)
            .map(|coin_id| results::WalletCoinRecord {
                coin_id: coin_id.into(),
                // Naming a coin by its parent classifies nothing.
                asset: None,
                amount: 999_999_999_999,
                parent_coin_info: SPENT_COIN.into(),
                puzzle_hash: "33".repeat(32),
                created_height: Some(5_000_042),
                spent_height: None,
            })
            .collect();
        Ok(results::WalletCoinsByParentResult {
            cursor: coins.last().map(|c| c.coin_id.clone()),
            coins,
            complete,
            source: Some(results::WalletReadSource::Fallback),
            synced: false,
            peak_height: None,
        })
    }
    /// Answers with a `seq` no neighbouring wallet handler produces, and a `latest` one ABOVE the
    /// page's own cursor — so a handler that collapsed the two, or a dispatch arm wired to another
    /// wallet read, is distinguishable from a correct one.
    async fn wallet_arrivals(
        &self,
        params: WalletArrivalsParams,
    ) -> Result<results::WalletArrivalsResult, ControlError> {
        let arrivals = vec![results::WalletArrivalRecord {
            seq: 4_242,
            coin_id: SPENT_COIN.into(),
            puzzle_hash: "22".repeat(32),
            amount: "1000000000000".into(),
            asset_id: None,
            confirmed_height: 5_000_000,
        }];
        let cursor = arrivals.last().map_or(params.after_seq, |a| a.seq);
        Ok(results::WalletArrivalsResult {
            arrivals,
            cursor,
            latest: 4_243,
        })
    }
    async fn wallet_peak(&self) -> Result<results::WalletPeakResult, ControlError> {
        Ok(results::WalletPeakResult {
            peak_height: Some(5_000_000),
            synced: true,
        })
    }
    /// Reports three DIFFERENT counts, so a handler that answered one number twice — or a dispatch
    /// arm wired to the wallet's sync status, whose chia count this deliberately matches — is
    /// distinguishable from a correct one by the DIG counts alone. The known count is unequal to
    /// the connected one for the same reason: aliasing the two must be visible here.
    async fn peer_counts(&self) -> Result<results::PeerCountsResult, ControlError> {
        Ok(results::PeerCountsResult {
            dig_peer_count: Some(6),
            chia_peer_count: Some(3),
            known_dig_peer_count: Some(41),
        })
    }
    /// Reports a phase and a height NEITHER neighbouring wallet read can produce — `syncing` beside
    /// a height the peak handler never returns — so a dispatch arm wired to `control.wallet.peak`
    /// (whose payload is otherwise a plausible sync status) fails the routing test below.
    async fn wallet_sync_status(&self) -> Result<results::WalletSyncStatusResult, ControlError> {
        Ok(results::WalletSyncStatusResult {
            phase: results::WalletSyncPhase::Syncing,
            peak_height: Some(4_999_000),
            chia_peer_count: Some(3),
            watched_addresses: Some(4),
            subscription_peer_count: Some(1),
            chia_peer_peak_height: Some(4_999_200),
        })
    }
    /// Accepts anything except [`REJECTED_BUNDLE`], which it refuses the way a mempool does — as a
    /// successful call reporting a refusal, never as an error.
    async fn wallet_broadcast(
        &self,
        params: WalletBroadcastParams,
    ) -> Result<results::WalletBroadcastResult, ControlError> {
        if params.signed_bundle_hex == REJECTED_BUNDLE {
            return Ok(results::WalletBroadcastResult {
                accepted: false,
                transaction_id: None,
                rejection: Some("DOUBLE_SPEND".into()),
            });
        }
        Ok(results::WalletBroadcastResult {
            accepted: true,
            transaction_id: Some("cc".repeat(32)),
            rejection: None,
        })
    }
    /// A real (if tiny) set-backed registry, because idempotence is the property the KATs assert and
    /// a handler that always reports `added: 1` would satisfy a shape-only mock.
    async fn wallet_watch(
        &self,
        params: WalletWatchParams,
    ) -> Result<results::WalletWatchResult, ControlError> {
        Ok(ENROLLED.with(|set| {
            let mut set = set.borrow_mut();
            let added = params
                .public_keys
                .into_iter()
                .filter(|key| set.insert(key.clone()))
                .count() as u32;
            results::WalletWatchResult {
                added,
                watched: set.len() as u32,
            }
        }))
    }
    async fn wallet_unwatch(
        &self,
        params: WalletUnwatchParams,
    ) -> Result<results::WalletUnwatchResult, ControlError> {
        Ok(ENROLLED.with(|set| {
            let mut set = set.borrow_mut();
            let removed = params
                .public_keys
                .iter()
                .filter(|key| set.remove(*key))
                .count() as u32;
            results::WalletUnwatchResult {
                removed,
                watched: set.len() as u32,
            }
        }))
    }
    async fn wallet_watched(&self) -> Result<results::WalletWatchedResult, ControlError> {
        Ok(ENROLLED.with(|set| results::WalletWatchedResult {
            public_keys: set.borrow().iter().cloned().collect(),
        }))
    }
    async fn wallet_reservations_held(
        &self,
    ) -> Result<results::WalletReservationsHeldResult, ControlError> {
        Ok(
            RESERVATIONS.with(|table| results::WalletReservationsHeldResult {
                reserved: table
                    .borrow()
                    .iter()
                    .filter(|(_, (_, expires))| *expires > MOCK_NOW_UNIX)
                    .flat_map(|(id, (coins, expires))| {
                        coins.iter().map(move |coin_id| results::ReservedCoin {
                            coin_id: coin_id.clone(),
                            reservation_id: id.clone(),
                            expires_at_unix: *expires,
                        })
                    })
                    .collect(),
                as_of_unix: MOCK_NOW_UNIX,
            }),
        )
    }
    async fn wallet_reservations_reserve(
        &self,
        params: WalletReservationsReserveParams,
    ) -> Result<results::WalletReservationsReserveResult, ControlError> {
        let params = params.validated()?;
        let ttl_secs = params
            .ttl_secs
            .unwrap_or(MOCK_DEFAULT_TTL_SECS)
            .min(MOCK_MAX_TTL_SECS);
        RESERVATIONS.with(|table| {
            let mut table = table.borrow_mut();
            // Every clash is found BEFORE anything is written, so a refusal leaves the table
            // exactly as it was — the property the all-or-none KAT observes from outside.
            let held: std::collections::BTreeSet<&String> = table
                .values()
                .filter(|(_, expires)| *expires > MOCK_NOW_UNIX)
                .flat_map(|(coins, _)| coins.iter())
                .collect();
            if let Some(clash) = params.coin_ids.iter().find(|id| held.contains(id)) {
                return Err(ControlError::of(
                    ControlErrorCode::WalletCoinsReserved,
                    format!("coin {clash} is already reserved by an in-flight spend"),
                ));
            }
            let reservation_id = format!("mock-res-{}", table.len() + 1);
            let expires_at_unix = MOCK_NOW_UNIX + ttl_secs;
            table.insert(
                reservation_id.clone(),
                (params.coin_ids.clone(), expires_at_unix),
            );
            Ok(results::WalletReservationsReserveResult {
                reservation_id,
                coin_ids: params.coin_ids,
                expires_at_unix,
                ttl_secs,
            })
        })
    }
    async fn wallet_reservations_release(
        &self,
        params: WalletReservationsReleaseParams,
    ) -> Result<results::WalletReservationsReleaseResult, ControlError> {
        Ok(RESERVATIONS.with(|table| {
            let freed = table.borrow_mut().remove(&params.reservation_id);
            match freed {
                Some((coin_ids, _)) => results::WalletReservationsReleaseResult {
                    released: true,
                    coin_ids,
                },
                None => results::WalletReservationsReleaseResult {
                    released: false,
                    coin_ids: Vec::new(),
                },
            }
        }))
    }
    async fn collateral_requirement(
        &self,
    ) -> Result<results::CollateralRequirementResult, ControlError> {
        Ok(results::CollateralRequirementResult::Known {
            epoch: 7,
            protocol_version: 1,
            required_per_store_dig_base_units: 1_036,
            stores: 4_200,
            owners: 310,
            multiplier_micros: 1_050_000,
            handicap_dig_base_units: 2_760,
        })
    }

    async fn collateral_margin_get(&self) -> Result<results::CollateralMarginResult, ControlError> {
        Ok(results::CollateralMarginResult {
            margin_bp: MARGIN_BP.with(|m| *m.borrow()),
        })
    }

    async fn collateral_margin_set(
        &self,
        params: crate::params::CollateralMarginSetParams,
    ) -> Result<results::CollateralMarginResult, ControlError> {
        // Stores what it was given, so a test can distinguish "persisted the request" from
        // "echoed the request" by reading it back through the OTHER method.
        MARGIN_BP.with(|m| *m.borrow_mut() = params.margin_bp);
        Ok(results::CollateralMarginResult {
            margin_bp: params.margin_bp,
        })
    }

    async fn spends_list(
        &self,
        params: SpendsListParams,
    ) -> Result<results::SpendsListResult, ControlError> {
        Ok(audit_page(&params))
    }
    async fn profile_put_body(
        &self,
        params: ProfilePutBodyParams,
    ) -> Result<results::ProfilePutBodyResult, ControlError> {
        Ok(results::ProfilePutBodyResult {
            stored: true,
            store_id: params.store_id,
            root: params.root,
            body_bytes: params.body_b64.len() as u64,
        })
    }
    async fn profile_get_body(
        &self,
        params: ProfileGetBodyParams,
    ) -> Result<results::ProfileGetBodyResult, ControlError> {
        Ok(results::ProfileGetBodyResult {
            store_id: params.store_id,
            root: params.root,
            body_b64: None,
            body_bytes: 0,
        })
    }
    async fn pairing_request(
        &self,
        _params: RequestParams,
    ) -> Result<results::PairingRequestResult, ControlError> {
        Ok(results::PairingRequestResult {
            pairing_id: "pid-1".into(),
            pairing_code: "012345".into(),
            expires_ms: 1_700_000_000_000,
        })
    }
    async fn pairing_poll(
        &self,
        _params: PollParams,
    ) -> Result<results::PairingPollResult, ControlError> {
        Ok(results::PairingPollResult {
            status: "pending".into(),
            token: None,
        })
    }
}

fn unimpl(what: &str) -> ControlError {
    ControlError::of(ControlErrorCode::NotSupported, format!("{what} not mocked"))
}

/// Route a typed call through the mock node's dispatcher and parse the typed result back.
fn round_trip<C: crate::traits::ControlCall>(call: &C) -> Result<C::Output, ControlError> {
    let node = MockNode;
    let req = build_request(RequestId::Number(1), call);
    let resp = block_on(node.dispatch(req));
    parse_response::<C>(resp)
}

#[test]
fn dispatcher_routes_every_taking_params_method_to_its_typed_handler() {
    assert!(round_trip(&StatusParams {}).unwrap().running);
    assert_eq!(
        round_trip(&SetCapParams { cap_bytes: 1 })
            .unwrap()
            .cap_bytes,
        64 * 1024 * 1024,
        "the node floors the cap"
    );
    assert!(round_trip(&CacheClearParams {}).unwrap().cleared);
    let pin = round_trip(&PinParams {
        store: STORE.into(),
    })
    .unwrap();
    assert_eq!(pin.store_id, STORE);
    let sync = round_trip(&SyncTriggerParams {
        store: format!("{STORE}:{ROOT}"),
    })
    .unwrap();
    assert_eq!(sync.root, ROOT);
    // Two DISTINCT stores through the same call site: a handler wired to the wrong arm (e.g.
    // sync_trigger's) would either error on the unjoined `store`/`root` shape or echo the wrong
    // pair, so this fails for the right reason rather than merely returning something.
    let fetch_a = round_trip(&CapsuleFetchParams {
        store: STORE.into(),
        root: ROOT.into(),
    })
    .unwrap();
    assert_eq!(
        (fetch_a.store.as_str(), fetch_a.root.as_str()),
        (STORE, ROOT)
    );
    let fetch_b = round_trip(&CapsuleFetchParams {
        store: "otherstore".into(),
        root: "otherroot".into(),
    })
    .unwrap();
    assert_eq!(
        (fetch_b.store.as_str(), fetch_b.root.as_str()),
        ("otherstore", "otherroot")
    );
    let sub = round_trip(&SubscribeParams {
        store_id: STORE.into(),
        kind: SubscriptionKind::Profile,
    })
    .unwrap();
    assert!(sub.added);
    assert_eq!(sub.kind, SubscriptionKind::Profile);
    let conn = round_trip(&PeersConnectParams { peer: "p".into() }).unwrap();
    assert_eq!(conn.peer_id, "p");
    assert_eq!(
        round_trip(&UpdaterStatusParams {}).unwrap(),
        json!({"channel": "stable"})
    );
    assert_eq!(
        round_trip(&PollParams {
            pairing_id: "x".into()
        })
        .unwrap()
        .status,
        "pending"
    );
}

#[test]
fn default_control_client_builds_and_parses_via_the_trait() {
    use crate::traits::{ControlClient, DefaultControlClient};
    let client = DefaultControlClient;
    let req = client.build_request(RequestId::Number(9), &SetCapParams { cap_bytes: 5 });
    assert_eq!(req.id, RequestId::Number(9));
    assert_eq!(req.method, "control.cache.setCap");
    let resp = JsonRpcResponse::success(RequestId::Number(9), json!({"cap_bytes": 5}));
    let out = client
        .parse_response::<SetCapParams>(resp)
        .expect("typed parse");
    assert_eq!(out.cap_bytes, 5);
}

#[test]
fn every_method_maps_to_a_category() {
    use crate::method::Category;
    // Touch the category of every method so the grouping table can't silently lose an arm.
    assert_eq!(ControlMethod::Status.category(), Category::Status);
    assert_eq!(ControlMethod::PeerStatus.category(), Category::Peers);
    for &m in ControlMethod::ALL {
        let _ = m.category();
    }
}

#[test]
fn dispatcher_rejects_an_unknown_method_with_method_not_found() {
    let node = MockNode;
    let req = JsonRpcRequest::new(RequestId::Number(1), "control.nope", json!({}));
    let resp = block_on(node.dispatch(req));
    let err = resp.into_result().unwrap_err();
    assert_eq!(err.code_enum(), Some(ControlErrorCode::MethodNotFound));
}

#[test]
fn dispatcher_maps_malformed_params_to_invalid_params() {
    let node = MockNode;
    // `control.cache.setCap` needs a numeric `cap_bytes`; a string is malformed.
    let req = JsonRpcRequest::new(
        RequestId::Number(1),
        ControlMethod::CacheSetCap.name(),
        json!({"cap_bytes": "not-a-number"}),
    );
    let resp = block_on(node.dispatch(req));
    let err = resp.into_result().unwrap_err();
    assert_eq!(err.code_enum(), Some(ControlErrorCode::InvalidParams));
}

#[test]
fn dispatcher_surfaces_a_handler_error_verbatim() {
    let node = MockNode;
    let req = build_request(
        RequestId::Number(1),
        &SetUpstreamParams {
            upstream: UNSUPPORTED_UPSTREAM.into(),
        },
    );
    let resp = block_on(node.dispatch(req));
    let err = resp.into_result().unwrap_err();
    assert_eq!(err.code_enum(), Some(ControlErrorCode::NotSupported));
}

#[test]
fn every_catalog_method_dispatches_without_panicking() {
    // The dispatcher must have an arm for EVERY catalog method, and each method's minimal params
    // fixture must be complete enough that the route succeeds rather than erroring.
    let node = MockNode;
    for &m in ControlMethod::ALL {
        let req = JsonRpcRequest::new(RequestId::Number(1), m.name(), minimal_params(m));
        let resp = block_on(node.dispatch(req));
        assert!(
            resp.error.is_none(),
            "{} errored under minimal_params: {:?}",
            m.name(),
            resp.error
        );
    }
}

/// **dig_ecosystem#2215** — the `software` member every `control.peerStatus` peer entry carries.
///
/// `control.peerStatus` is a PROXIED result: SPEC §4.1 forbids freezing a struct over the snapshot,
/// because its shape belongs to the node's peer pool. So this KAT pins the one member this contract
/// DOES own — `software` — in situ, inside a representative `connected` array, rather than pinning
/// the envelope around it.
///
/// The vector carries one REPORTED peer and one UNKNOWN peer together. A vector with only a
/// reported peer would pass against an implementation that omits `software` whenever it is Unknown,
/// which is precisely the bug the always-present rule exists to prevent.
#[test]
fn peer_status_software_member_golden_vector() {
    let snapshot = json!({
        "connected": [
            {
                "peer_id": "aa00",
                "address": "[2001:db8::1]:9444",
                "outbound": true,
                "software": {
                    "kind": "reported",
                    "product": "dig-node",
                    "version": "0.99.1",
                    "raw": "dig-node/0.99.1"
                }
            },
            {
                "peer_id": "bb11",
                "address": "[2001:db8::2]:9444",
                "outbound": false,
                "software": { "kind": "unknown" }
            }
        ]
    });

    let entries = snapshot["connected"].as_array().expect("connected array");

    // Always present: EVERY entry carries `software`, including the peer whose build is unknown.
    for entry in entries {
        assert!(
            entry.get("software").is_some(),
            "every peerStatus entry must carry `software`; omitting it is a serialization bug,              not an Unknown peer"
        );
    }

    // Each member decodes to the typed value and re-encodes byte-identically.
    for entry in entries {
        let wire = entry["software"].clone();
        let parsed: results::PeerSoftware =
            serde_json::from_value(wire.clone()).expect("software member must decode");
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            wire,
            "the software member is not byte-stable"
        );
    }

    // And the decoded values are the ones the vector names, so a decode that silently collapsed
    // both entries to the same value could not pass.
    let reported: results::PeerSoftware =
        serde_json::from_value(entries[0]["software"].clone()).unwrap();
    assert_eq!(reported, results::PeerSoftware::parse("dig-node/0.99.1"));
    let unknown: results::PeerSoftware =
        serde_json::from_value(entries[1]["software"].clone()).unwrap();
    assert_eq!(unknown, results::PeerSoftware::Unknown);
    assert_ne!(reported, unknown);
}

/// The legacy sentinel a peer is advertising RIGHT NOW must reach a reader as Unknown, not as a
/// version — the whole live fleet depends on this one mapping (dig_ecosystem#2215).
#[test]
fn a_legacy_peer_entry_reads_as_unknown_not_as_version_zero() {
    let software = results::PeerSoftware::parse("0.0.0");
    assert_eq!(software, results::PeerSoftware::Unknown);
    let wire = serde_json::to_value(&software).unwrap();
    assert_eq!(wire, json!({"kind": "unknown"}));
    assert_eq!(
        wire.to_string().find("0.0.0"),
        None,
        "no rendering of a legacy peer may contain the sentinel as a version"
    );
}

/// The smallest valid params object for a method, so the coverage sweep above never trips
/// `INVALID_PARAMS` for a param-taking method.
/// **A conflict on ANY coin reserves NONE of them.**
///
/// The nearest wrong implementation is not "reserves nothing" -- it is a writer that takes each free
/// coin as it goes and errors on reaching the clash, leaving the caller's other coins held by a
/// reservation whose handle it never received. That failure is INVISIBLE to an assertion about the
/// error, which both implementations return identically, so the load-bearing assertion here is the
/// SECOND one: the free coin must still be selectable afterwards.
///
/// The fixture needs two distinct coins for that reason -- with one coin, "took none" and "took
/// every free coin" produce the same observable state -- and orders the FREE coin FIRST, so a
/// write-as-you-go implementation has already written it by the time it sees the clash.
#[test]
fn a_conflicting_reserve_leaves_the_other_coins_free() {
    let node = MockNode;
    // B alone is held, so A is an honest control: a fixture where everything is already reserved
    // could not tell a partial writer from an atomic one.
    let first = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_B.into()],
            ttl_secs: None,
        }),
    )
    .expect("the first hold has nothing to clash with");

    let clash = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_A.into(), RESERVE_COIN_B.into()],
            ttl_secs: None,
        }),
    )
    .expect_err("a coin already held must refuse the whole call");
    assert_eq!(clash.data.code, "WALLET_COINS_RESERVED");
    assert_eq!(clash.code, -32046);

    let held = block_on(node.wallet_reservations_held()).unwrap();
    let held_coins: Vec<&str> = held.reserved.iter().map(|r| r.coin_id.as_str()).collect();
    assert_eq!(
        held_coins,
        vec![RESERVE_COIN_B],
        "the refused call must have written nothing: coin A was taken by a partial reservation"
    );
    assert_eq!(held.reserved[0].reservation_id, first.reservation_id);
    assert_eq!(held.as_of_unix, MOCK_NOW_UNIX);
}

/// **A conflict is reported as a WAIT, and never as a shortfall.**
///
/// Pinned as a distinct code rather than a message, because a message is not contract. Asserting
/// only that the call errored would pass for an implementation that answered with an
/// insufficient-funds code -- which is the money-lie: it sends a person to an exchange to solve a
/// five-minute wait.
#[test]
fn a_conflict_code_is_not_any_other_wallet_code() {
    assert_eq!(
        ControlErrorCode::WalletCoinsReserved.name(),
        "WALLET_COINS_RESERVED"
    );
    assert_eq!(ControlErrorCode::WalletCoinsReserved.origin(), "node");
    for &other in ControlErrorCode::ALL {
        if other != ControlErrorCode::WalletCoinsReserved {
            assert_ne!(other.code(), ControlErrorCode::WalletCoinsReserved.code());
            assert_ne!(other.name(), ControlErrorCode::WalletCoinsReserved.name());
        }
    }
}

/// **Every catalogued numeric code is unique across the WHOLE catalogue.**
///
/// The narrow per-variant assertions above only compare ONE code against the rest, so a collision
/// between two codes neither of which is the one under test is invisible to them. This asserts the
/// property the catalogue actually needs: `from_code` is a function, i.e. a wire number resolves to
/// at most one disposition.
///
/// This exists because the property FAILED in practice across the repo boundary. `-32044` was
/// minted here for a transient wait while dig-node had already shipped it for a permanent custody
/// refusal, and a client conflating the two either retries forever on a refusal or abandons a wait.
/// Uniqueness inside this crate is the half of that guard which is expressible here; the other half
/// is the `-3204x` range-ownership rule stated in the module docs, which only dig-node can honour.
#[test]
fn every_catalogued_code_is_numerically_unique() {
    for (i, &a) in ControlErrorCode::ALL.iter().enumerate() {
        for &b in &ControlErrorCode::ALL[i + 1..] {
            assert_ne!(
                a.code(),
                b.code(),
                "{} and {} both claim {}",
                a.name(),
                b.name(),
                a.code()
            );
            assert_ne!(
                a.name(),
                b.name(),
                "two variants share the symbol {}",
                a.name()
            );
        }
        assert_eq!(
            ControlErrorCode::from_code(a.code()),
            Some(a),
            "{} must resolve back to itself",
            a.name()
        );
    }
}

/// **The two `-3204x` dispositions that collided are opposites, and stay on distinct numbers.**
///
/// Asserting only that the numbers differ would pass for a catalogue that had quietly given both
/// variants the SAME meaning. Pinning each number together with its disposition is what makes a
/// future re-collapse visible: `WALLET_NODE_SPEND_DISABLED` is terminal, `WALLET_COINS_RESERVED` is
/// a retry, and no client may be asked to tell them apart from one integer.
#[test]
fn a_terminal_custody_refusal_and_a_transient_wait_never_share_a_code() {
    assert_eq!(ControlErrorCode::WalletNodeSpendDisabled.code(), -32044);
    assert_eq!(
        ControlErrorCode::WalletNodeSpendDisabled.name(),
        "WALLET_NODE_SPEND_DISABLED"
    );
    assert_eq!(ControlErrorCode::WalletCoinsReserved.code(), -32046);
    assert_eq!(
        ControlErrorCode::WalletReservationsUnavailable.code(),
        -32047
    );
    assert_ne!(
        ControlErrorCode::WalletNodeSpendDisabled.code(),
        ControlErrorCode::WalletCoinsReserved.code()
    );
    assert!(
        ControlErrorCode::WalletNodeSpendDisabled
            .description()
            .contains("Retrying cannot help"),
        "the terminal code must say so: a caller reads the disposition, not the number"
    );
}

/// **Release frees the hold, and releasing a handle that names nothing is a SUCCESS.**
///
/// Two properties in one sequence because the second is only meaningful after the first: an
/// idempotence assertion against a handle that was never live cannot tell "release is idempotent"
/// from "release never does anything". Releasing a REAL hold and then releasing it AGAIN makes both
/// visible.
#[test]
fn release_frees_the_hold_and_a_second_release_is_not_an_error() {
    let node = MockNode;
    let handle = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_A.into()],
            ttl_secs: None,
        }),
    )
    .unwrap();
    assert_eq!(
        block_on(node.wallet_reservations_held())
            .unwrap()
            .reserved
            .len(),
        1
    );

    let first = block_on(
        node.wallet_reservations_release(WalletReservationsReleaseParams {
            reservation_id: handle.reservation_id.clone(),
        }),
    )
    .unwrap();
    assert!(first.released);
    assert_eq!(first.coin_ids, vec![RESERVE_COIN_A.to_string()]);
    assert!(
        block_on(node.wallet_reservations_held())
            .unwrap()
            .reserved
            .is_empty(),
        "the coin must be selectable again once its hold is released"
    );

    let again = block_on(
        node.wallet_reservations_release(WalletReservationsReleaseParams {
            reservation_id: handle.reservation_id,
        }),
    )
    .expect("releasing an already-released handle is a success, not an error");
    assert!(!again.released);
    assert!(again.coin_ids.is_empty());
}

/// **The applied TTL is reported, and it is pinned from BOTH sides of the node's maximum.**
///
/// A test only of the over-the-cap case cannot tell a clamp from an implementation that ignores the
/// request and always returns its maximum; a test only under the cap cannot see a missing clamp at
/// all. Both directions are needed, so both are here, and the expiry is checked against the reported
/// clock rather than assumed.
#[test]
fn a_requested_ttl_is_clamped_above_the_cap_and_honoured_below_it() {
    let node = MockNode;
    let over = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_A.into()],
            ttl_secs: Some(MOCK_MAX_TTL_SECS + 1),
        }),
    )
    .unwrap();
    assert_eq!(
        over.ttl_secs, MOCK_MAX_TTL_SECS,
        "a hold longer than the cap must be clamped"
    );
    assert_eq!(over.expires_at_unix, MOCK_NOW_UNIX + MOCK_MAX_TTL_SECS);

    let under_secs = MOCK_MAX_TTL_SECS - 1;
    let under = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_B.into()],
            ttl_secs: Some(under_secs),
        }),
    )
    .unwrap();
    assert_eq!(
        under.ttl_secs, under_secs,
        "a hold within the cap must be honoured as asked"
    );
    assert_eq!(under.expires_at_unix, MOCK_NOW_UNIX + under_secs);
}

/// **Reserving nothing succeeds, and holds nothing.**
///
/// Asserting only that the call succeeded would pass for an implementation that stored an empty row
/// -- a reservation nothing can ever conflict with and only the TTL ever clears. So the handle is
/// released too, and must report freeing no coins.
#[test]
fn reserving_an_empty_list_yields_a_handle_that_holds_nothing() {
    let node = MockNode;
    let empty = block_on(
        node.wallet_reservations_reserve(WalletReservationsReserveParams {
            coin_ids: vec![],
            ttl_secs: None,
        }),
    )
    .expect("an empty selection is a legitimate no-op, not a malformed request");
    assert!(empty.coin_ids.is_empty());
    assert!(
        block_on(node.wallet_reservations_held())
            .unwrap()
            .reserved
            .is_empty(),
        "an empty reservation must hold no coins"
    );
    let freed = block_on(
        node.wallet_reservations_release(WalletReservationsReleaseParams {
            reservation_id: empty.reservation_id,
        }),
    )
    .unwrap();
    assert!(freed.coin_ids.is_empty());
}

/// **The request wire form, ENCODE direction.**
///
/// `held` carries no `now`, and that absence is the contract: a caller-supplied time would be a
/// lapse oracle. Pinned as an exact envelope so adding one is a failing test rather than a silent
/// widening.
#[test]
fn golden_reservation_request_vectors() {
    assert_request(
        &WalletReservationsHeldParams {},
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.reservations.held","params":{}}),
    );
    assert_request(
        &WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_A.into(), RESERVE_COIN_B.into()],
            ttl_secs: Some(300),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.reservations.reserve",
               "params":{"coin_ids":[RESERVE_COIN_A, RESERVE_COIN_B],"ttl_secs":300}}),
    );
    // An unnamed TTL is ABSENT from the wire, not `null`: a node reading `ttl_secs: null` as a
    // literal zero would grant a hold that lapses before the spend it guards.
    assert_request(
        &WalletReservationsReserveParams {
            coin_ids: vec![RESERVE_COIN_A.into()],
            ttl_secs: None,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.reservations.reserve",
               "params":{"coin_ids":[RESERVE_COIN_A]}}),
    );
    assert_request(
        &WalletReservationsReleaseParams {
            reservation_id: "res-7".into(),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.reservations.release",
               "params":{"reservation_id":"res-7"}}),
    );
}

/// **The request wire form, DECODE direction — the half an encode vector cannot see.**
///
/// `WalletReservationsReserveParams` has a hand-written `Deserialize`, so serializing a value this
/// crate built proves nothing about the bytes a FOREIGN client sends. These are literal wire bytes,
/// decoded: the `0x` spelling a block explorer prints is normalized away, an omitted `ttl_secs`
/// decodes as absent rather than failing, and a malformed id refuses the WHOLE request rather than
/// the well-formed subset.
#[test]
fn reservation_requests_decode_from_foreign_wire_bytes() {
    let prefixed: WalletReservationsReserveParams =
        serde_json::from_value(json!({"coin_ids":[format!("0x{RESERVE_COIN_A}"), RESERVE_COIN_B]}))
            .expect("a 0x-prefixed coin id is accepted on input");
    assert_eq!(
        prefixed.coin_ids,
        vec![RESERVE_COIN_A.to_string(), RESERVE_COIN_B.to_string()],
        "the prefix must be normalized away, never echoed"
    );
    assert_eq!(
        prefixed.ttl_secs, None,
        "an omitted ttl_secs decodes as absent"
    );

    // ONE bad id among good ones -- the fixture a subset-accepting implementation passes and an
    // all-or-nothing one fails. A fixture of only bad ids could not tell them apart.
    let mixed = serde_json::from_value::<WalletReservationsReserveParams>(
        json!({"coin_ids":[RESERVE_COIN_A, "not-a-coin-id"]}),
    );
    assert!(
        mixed.is_err(),
        "one malformed id must refuse the whole request"
    );

    // Uppercase is a DIFFERENT spelling of the same coin, and accepting it would let two spellings
    // of one id sit in the table as two coins.
    assert!(serde_json::from_value::<WalletReservationsReserveParams>(
        json!({"coin_ids":[RESERVE_COIN_A.to_ascii_uppercase()]})
    )
    .is_err());

    let release: WalletReservationsReleaseParams =
        serde_json::from_value(json!({"reservation_id":"res-7"})).unwrap();
    assert_eq!(release.reservation_id, "res-7");
}

/// **The result wire form, both directions.**
///
/// Each golden vector decodes into its typed result and re-encodes byte-identically, so a renamed,
/// dropped or reordered field fails here. The `held` vector carries TWO coins under DIFFERENT
/// reservations with DIFFERENT expiries: a one-row fixture could not see an implementation that
/// summarised one expiry across the whole set, which is the shape this result deliberately rejects.
#[test]
fn golden_reservation_result_vectors() {
    assert_result_round_trips::<results::WalletReservationsHeldResult>(json!({
        "reserved": [
            {"coin_id": RESERVE_COIN_A, "reservation_id": "res-1", "expires_at_unix": 1_800_000_300u64},
            {"coin_id": RESERVE_COIN_B, "reservation_id": "res-2", "expires_at_unix": 1_800_000_600u64}
        ],
        "as_of_unix": 1_800_000_000u64
    }));
    assert_result_round_trips::<results::WalletReservationsHeldResult>(json!({
        "reserved": [],
        "as_of_unix": 1_800_000_000u64
    }));
    assert_result_round_trips::<results::WalletReservationsReserveResult>(json!({
        "reservation_id": "res-1",
        "coin_ids": [RESERVE_COIN_A],
        "expires_at_unix": 1_800_000_300u64,
        "ttl_secs": 300u64
    }));
    assert_result_round_trips::<results::WalletReservationsReleaseResult>(json!({
        "released": true,
        "coin_ids": [RESERVE_COIN_A]
    }));
    assert_result_round_trips::<results::WalletReservationsReleaseResult>(json!({
        "released": false,
        "coin_ids": []
    }));
}

fn minimal_params(m: ControlMethod) -> Value {
    match m {
        ControlMethod::ConfigSetUpstream => json!({"upstream": ""}),
        ControlMethod::LogSetLevel => json!({"filter": "info"}),
        ControlMethod::CacheSetCap => json!({"cap_bytes": 0}),
        ControlMethod::HostedStoresPin
        | ControlMethod::HostedStoresUnpin
        | ControlMethod::HostedStoresStatus
        | ControlMethod::SyncTrigger => json!({"store": STORE}),
        ControlMethod::CapsuleFetch => json!({"store": STORE, "root": ROOT}),
        ControlMethod::UpdaterSetChannel => json!({"channel": "stable"}),
        ControlMethod::CollateralMarginSet => json!({"margin_bp": 100}),
        ControlMethod::UpdaterPause => json!({}),
        ControlMethod::PairingApprove => json!({"pairing_id": "x"}),
        ControlMethod::PairingRevoke => json!({"token_id": "x"}),
        ControlMethod::ChiaPeersAdd => json!({"ip": "203.0.113.7"}),
        ControlMethod::ChiaPeersRemove => json!({"ip": "203.0.113.7"}),
        ControlMethod::PeersConnect | ControlMethod::PeersDisconnect => json!({"peer": "p"}),
        ControlMethod::Subscribe | ControlMethod::Unsubscribe => json!({"store_id": STORE}),
        ControlMethod::PairingRequest => json!({"client_name": "c"}),
        ControlMethod::PairingPoll => json!({"pairing_id": "x"}),
        ControlMethod::WalletBalance | ControlMethod::WalletCoins => {
            json!({"address": "xch1abc", "asset": "dig"})
        }
        ControlMethod::WalletCoinById | ControlMethod::WalletCoinSpend => {
            json!({ "coin_id": ABSENT_COIN })
        }
        ControlMethod::WalletCoinsByParent => json!({ "parent_coin_id": ABSENT_COIN }),
        ControlMethod::WalletBroadcast => json!({"signed_bundle_hex": "deadbeef"}),
        ControlMethod::WalletWatch | ControlMethod::WalletUnwatch => {
            json!({ "public_keys": [ENROL_KEY_A] })
        }
        ControlMethod::ProfilePutBody => {
            json!({ "store_id": STORE, "root": ROOT, "body_b64": "" })
        }
        ControlMethod::ProfileGetBody => json!({ "store_id": STORE, "root": ROOT }),
        ControlMethod::WalletReservationsReserve => json!({ "coin_ids": [] }),
        ControlMethod::WalletReservationsRelease => json!({ "reservation_id": "mock-res-absent" }),
        _ => json!({}),
    }
}

/// **The three new methods reach their own handlers, over the real dispatcher.**
///
/// Each assertion is keyed to something only THAT handler could have produced — the coin echoes the
/// address and asset it was asked for — so an arm wired to the neighbouring method fails here
/// rather than passing on a shape both happen to share.
#[test]
fn the_dispatcher_routes_each_wallet_chain_method_to_its_own_handler() {
    let coins = round_trip(&WalletCoinsParams {
        address: "xch1mintfunder".into(),
        asset: Asset::DIG,
    })
    .expect("coins must route");
    assert_eq!(coins.coins[0].coin_id, "xch1mintfunder");
    assert_eq!(
        coins.coins[0].asset,
        Some(Asset::DIG),
        "an address+asset read KNOWS the asset and must keep reporting it concretely --          `null` is reserved for a read that classified nothing"
    );
    assert_eq!(
        coins.coins[0].amount, 2,
        "the DIG amount proves the ASSET reached the handler, not just the address"
    );

    assert_eq!(
        round_trip(&WalletPeakParams {})
            .expect("peak must route")
            .peak_height,
        Some(5_000_000)
    );

    // Keyed to what only the sync-status handler produces: `control.wallet.peak` answers with a
    // DIFFERENT height and carries no phase at all, so an arm wired to it cannot land here.
    let sync = round_trip(&WalletSyncStatusParams {}).expect("syncStatus must route");
    assert_eq!(sync.phase, results::WalletSyncPhase::Syncing);
    assert_eq!(sync.peak_height, Some(4_999_000));
    assert_eq!(sync.chia_peer_count, Some(3));

    // `control.peerCounts` reaches its OWN handler: it is the only one that produces a DIG count at
    // all, so an arm wired to the sync status (whose chia count is the same 3) cannot land here.
    let counts = round_trip(&PeerCountsParams {}).expect("peerCounts must route");
    assert_eq!(counts.dig_peer_count, Some(6));
    assert_eq!(
        counts.chia_peer_count,
        Some(3),
        "the same observation control.wallet.syncStatus reports"
    );

    let pushed = round_trip(&WalletBroadcastParams {
        signed_bundle_hex: "deadbeef".into(),
    })
    .expect("broadcast must route");
    assert!(pushed.accepted);
    assert_eq!(pushed.rejection, None);
}

/// **`control.wallet.coinById` reaches its own handler, and reports a SPENT coin.**
///
/// The assertion is keyed to something only this handler could produce: a non-null `spent_height`.
/// `control.wallet.coins` answers by address with unspent coins only, so an arm mis-wired to it
/// could not report a spend height at all — which is the fact `mint_status` needs.
#[test]
fn the_dispatcher_routes_coin_by_id_to_its_own_handler() {
    let found = round_trip(&WalletCoinByIdParams {
        coin_id: SPENT_COIN.into(),
    })
    .expect("coinById must route");

    let coin = found.coin.expect("the mock knows this coin");
    assert_eq!(coin.coin_id, SPENT_COIN);
    assert_eq!(
        coin.spent_height,
        Some(5_000_042),
        "the spend height is the whole reason this method exists"
    );
    assert_eq!(
        coin.asset, None,
        "a by-id read classifies nothing; `null` says so rather than asserting a class"
    );
}

/// **An absent coin is an ANSWER, not an error.**
///
/// The nearest wrong implementation maps "no such coin" onto the error channel, where a caller
/// cannot tell it from an unreachable chain — and `mint_status` would then report a mint whose coin
/// genuinely does not exist as merely pending, forever, with the money already gone.
///
/// The fixture varies ONE thing against the found case above: which coin id is asked for. Both
/// answers come from the same handler, so a handler that could only ever answer one way fails here.
#[test]
fn an_absent_coin_is_a_result_not_an_error() {
    let absent = round_trip(&WalletCoinByIdParams {
        coin_id: ABSENT_COIN.into(),
    })
    .expect("an unknown coin must arrive on the Ok channel, never as a control error");

    assert_eq!(absent.coin, None);

    // And it is distinguishable, on the wire, from every error envelope: an error response carries
    // no `result` at all, so a client can never read one as "the chain says no such coin".
    let ok = JsonRpcResponse::success(RequestId::Number(1), serde_json::to_value(&absent).unwrap());
    assert!(ok.error.is_none(), "an absent coin is not an error");
    assert_eq!(ok.into_result().unwrap()["coin"], json!(null));

    for code in [
        ControlErrorCode::WalletNoChainSource,
        ControlErrorCode::WalletReadFailed,
        ControlErrorCode::WalletRateLimited,
    ] {
        let failed =
            JsonRpcResponse::error(RequestId::Number(1), ControlError::of(code, "unreachable"));
        assert!(
            parse_response::<WalletCoinByIdParams>(failed).is_err(),
            "{} must not decode into an absent-coin result",
            code.name()
        );
    }
}

/// A coin id that is not lowercase 64-hex is refused BEFORE any chain is consulted, as
/// `-32602 INVALID_PARAMS` — a malformed request, never a "no such coin" answer.
///
/// The `0x` prefix is the one tolerated decoration, because callers hand-copy ids out of block
/// explorers that print it. It is normalized away, never echoed.
#[test]
fn a_malformed_coin_id_is_invalid_params_not_an_absent_coin() {
    for bad in [
        "",
        "ab",                              // too short
        &"ab".repeat(33),                  // too long
        &"AB".repeat(32),                  // uppercase is not the wire form
        &format!("{}zz", "ab".repeat(31)), // non-hex
        &format!("0x{}", "ab".repeat(31)), // 0x-prefixed but short
        &format!(" {} ", "ab".repeat(32)), // padded
    ] {
        let node = MockNode;
        let req = JsonRpcRequest::new(
            RequestId::Number(1),
            ControlMethod::WalletCoinById.name(),
            json!({ "coin_id": bad }),
        );
        let err = block_on(node.dispatch(req)).into_result().unwrap_err();
        assert_eq!(
            err.code_enum(),
            Some(ControlErrorCode::InvalidParams),
            "{bad:?} must be refused as malformed params"
        );
    }

    // The tolerated decoration: `0x` + 64 hex reaches the handler as the unprefixed id.
    let node = MockNode;
    let req = JsonRpcRequest::new(
        RequestId::Number(1),
        ControlMethod::WalletCoinById.name(),
        json!({ "coin_id": format!("0x{SPENT_COIN}") }),
    );
    let found: results::WalletCoinByIdResult =
        serde_json::from_value(block_on(node.dispatch(req)).into_result().unwrap()).unwrap();
    assert_eq!(
        found
            .coin
            .expect("the 0x form names a coin the mock knows")
            .coin_id,
        SPENT_COIN,
        "the prefix is normalized away and never emitted"
    );
}

/// **A verdict must be stated, never inferred from silence.** `coin:null` says the chain holds no
/// such coin, so an ABSENT `coin` key must not decode into one. Serde's default treatment of
/// `Option` makes the two indistinguishable, which would let almost any JSON object — including
/// three sibling wallet results — decode into a confident "your coin does not exist".
#[test]
fn an_omitted_coin_field_is_a_decode_error_not_a_null_verdict() {
    // Explicit null still decodes: the verdict is expressible, just not by omission.
    let stated = serde_json::from_value::<results::WalletCoinByIdResult>(json!({
        "coin": null, "source": "fallback", "synced": false, "peak_height": null
    }))
    .expect("an explicitly null coin is a valid verdict");
    assert_eq!(stated.coin, None);

    // Omission does not. Each of these decoded to a complete "no such coin" before the field was
    // made required; the last three are other methods' result shapes.
    for wire in [
        json!({ "source": "fallback", "synced": false, "peak_height": null }),
        json!({ "synced": false }),
        json!({ "peak_height": 5_000_000u32, "synced": true }),
        json!({ "coins": [], "source": "db", "synced": true, "peak_height": 5_000_000u32 }),
    ] {
        assert!(
            serde_json::from_value::<results::WalletCoinByIdResult>(wire.clone()).is_err(),
            "a payload without a `coin` key must not decode into a no-such-coin verdict: {wire}"
        );
    }
}

/// **The spend and the children reach their OWN handlers, over the real dispatcher.**
///
/// Each assertion is keyed to something only that handler could have produced. The spend carries a
/// puzzle reveal and a solution, which no other wallet read emits at all; the children answer names
/// [`CHILD_COIN`], an id no other handler here produces. So an arm wired to the neighbouring by-id
/// read — the nearest wrong wiring, since all three are asked with a 64-hex coin id — fails rather
/// than passing on a shape they share.
#[test]
fn the_dispatcher_routes_the_spend_and_the_children_to_their_own_handlers() {
    let found = round_trip(&WalletCoinSpendParams {
        coin_id: SPENT_COIN.into(),
    })
    .expect("coinSpend must route");

    let spend = found.spend.expect("the mock knows this coin's spend");
    assert_eq!(spend.coin.coin_id, SPENT_COIN);
    assert_eq!(
        spend.puzzle_reveal, REVEAL_HEX,
        "the reveal is the half a coin record cannot supply, and is why this method exists"
    );
    assert_eq!(
        spend.solution, SOLUTION_HEX,
        "reveal and solution hold DIFFERENT values, so a transposition cannot pass here"
    );
    assert!(
        spend.coin.spent_height.is_some(),
        "a spend exists only because the coin was spent -- an unspent coin here is a contradiction"
    );

    let children = round_trip(&WalletCoinsByParentParams::first_page(SPENT_COIN))
        .expect("coinsByParent must route");

    assert_eq!(children.coins.len(), CHILD_COINS.len());
    assert_eq!(
        children.coins[0].coin_id, CHILD_COINS[0],
        "the answer is the CHILD -- a handler echoing the parent it was asked about fails here"
    );
    assert_eq!(
        children.coins[0].parent_coin_info, SPENT_COIN,
        "and the child names the parent that was asked for, so the id reached the handler"
    );
    assert_eq!(
        children.coins[0].asset, None,
        "naming a coin by its parent classifies nothing; `null` says so rather than asserting"
    );
}

/// **An unspent coin and a childless parent are ANSWERS, not errors.**
///
/// The nearest wrong implementation maps "nothing there" onto the error channel, where a caller
/// cannot tell it from "the chain was unreachable" — and reads the failure as *this is the tip*.
///
/// The fixture varies ONE thing, the coin asked about, against a truthful control in the same test:
/// [`SPENT_COIN`] genuinely has a spend and genuinely has a child. Without that control a handler
/// that answered absent/empty for EVERY id would pass, which is a different implementation and one
/// that can see nothing at all.
#[test]
fn an_absent_spend_and_a_childless_parent_are_answers_not_errors() {
    let no_spend = round_trip(&WalletCoinSpendParams {
        coin_id: ABSENT_COIN.into(),
    })
    .expect("an absent spend is a SUCCESS -- the error channel is reserved for could-not-answer");
    assert_eq!(no_spend.spend, None);

    let no_children = round_trip(&WalletCoinsByParentParams::first_page(ABSENT_COIN))
        .expect("a childless parent is a SUCCESS, for the same reason an empty `.coins` is");
    assert!(no_children.coins.is_empty());
    assert!(
        no_children.complete,
        "a childless parent is COMPLETELY answered -- nothing was withheld"
    );
    assert_eq!(
        no_children.cursor, None,
        "an empty page hands back nothing, so there is nothing to resume from"
    );

    // The control: the same handlers DO answer positively for a coin they know, so neither
    // assertion above is passing on a handler that can only ever say nothing.
    assert!(round_trip(&WalletCoinSpendParams {
        coin_id: SPENT_COIN.into()
    })
    .unwrap()
    .spend
    .is_some());
    assert!(
        !round_trip(&WalletCoinsByParentParams::first_page(SPENT_COIN))
            .unwrap()
            .coins
            .is_empty()
    );
}

/// **An omitted `spend` key is a decode error, not a no-spend verdict.**
///
/// The same hazard [`results::WalletCoinByIdResult`] guards, on the read where it costs the most: a
/// caller following a singleton forward reads "no spend" as *this is the tip*. Serde's default
/// treatment of `Option` would let any unrelated or truncated payload carrying a `synced` field
/// decode into a confident "this coin was never spent".
///
/// The fixtures are the neighbouring methods' real result shapes, so the test proves the guard
/// against payloads a client could actually receive by mis-routing — not against invented rubbish.
#[test]
fn an_omitted_spend_field_is_a_decode_error_not_a_no_spend_verdict() {
    // Explicit null still decodes: the verdict is expressible, just not by omission.
    let stated = serde_json::from_value::<results::WalletCoinSpendResult>(json!({
        "spend": null, "source": "fallback", "synced": false, "peak_height": null
    }))
    .expect("an explicitly null spend is a valid verdict");
    assert_eq!(stated.spend, None);

    for wire in [
        json!({ "source": "fallback", "synced": false, "peak_height": null }),
        json!({ "synced": false }),
        // `control.wallet.peak`'s shape, and `control.wallet.coinsByParent`'s: both would decode
        // into "never spent" under serde's default.
        json!({ "peak_height": 5_000_000u32, "synced": true }),
        json!({ "coins": [], "source": "db", "synced": true, "peak_height": 5_000_000u32 }),
    ] {
        assert!(
            serde_json::from_value::<results::WalletCoinSpendResult>(wire.clone()).is_err(),
            "a payload without a `spend` key must not decode into a never-spent verdict: {wire}"
        );
    }
}

/// **The by-parent read enforces the SAME id rule as the by-id reads, under its own field name.**
///
/// The rule is shared by macro, and a macro applied to the wrong field name silently produces a type
/// that validates nothing — the field would simply be absent and the decode would fail for an
/// unrelated reason. So the test pins both directions: a malformed id is refused, and a well-formed
/// one is accepted and normalized, under the key `parent_coin_id` specifically.
#[test]
fn wallet_coins_by_parent_params_enforce_the_coin_id_rule_on_their_own_field() {
    for bad in [
        json!({"parent_coin_id": "AB".repeat(32)}),
        json!({"parent_coin_id": "abc"}),
    ] {
        assert!(
            serde_json::from_value::<WalletCoinsByParentParams>(bad.clone()).is_err(),
            "a malformed parent id must be refused at deserialization: {bad}"
        );
    }
    // A `coin_id` key is NOT this method's field, so it must not satisfy it either.
    assert!(
        serde_json::from_value::<WalletCoinsByParentParams>(json!({"coin_id": "ab".repeat(32)}))
            .is_err(),
        "the by-parent read is asked with `parent_coin_id`; `coin_id` is a different question"
    );

    let prefixed = serde_json::from_value::<WalletCoinsByParentParams>(
        json!({"parent_coin_id": format!("0x{}", "ab".repeat(32))}),
    )
    .expect("a 0x-prefixed id is tolerated on input");
    assert_eq!(
        prefixed.parent_coin_id,
        "ab".repeat(32),
        "the prefix is normalized away and never emitted"
    );
}

/// **A truncated page and a final page can carry the SAME number of rows.**
///
/// The fixture is four children read two at a time, so both pages hold exactly two records and only
/// one of them is the last. Every length-based inference of completeness — `coins.len() < limit`,
/// `coins.is_empty()`, "a full page means more" — gives the same answer for both, so this is the
/// fixture that makes `complete` load-bearing rather than decorative.
///
/// The dangerous direction is the one asserted first: reading page ONE as complete ends a lineage
/// walk at a branch that has more children, and presents a partial lineage as a whole one.
#[test]
fn a_truncated_page_and_a_final_page_are_told_apart_by_complete_not_by_length() {
    let first = round_trip(&WalletCoinsByParentParams {
        parent_coin_id: SPENT_COIN.into(),
        after_coin_id: None,
        limit: Some(2),
    })
    .expect("a bounded first page must route");

    assert_eq!(first.coins.len(), 2);
    assert!(
        !first.complete,
        "two of four children were withheld -- reporting this page as complete ends the walk early"
    );
    assert_eq!(
        first.cursor.as_deref(),
        Some(CHILD_COINS[1]),
        "the cursor is the last child actually HANDED over, never a chain-head marker"
    );

    let second = round_trip(&WalletCoinsByParentParams {
        parent_coin_id: SPENT_COIN.into(),
        after_coin_id: first.cursor.clone(),
        limit: Some(2),
    })
    .expect("resuming from the handed-back cursor must route");

    assert_eq!(
        second.coins.len(),
        first.coins.len(),
        "both pages carry the same row count -- which is exactly why length cannot decide          completeness"
    );
    assert!(
        second.complete,
        "the last two children fit, so this page IS the end of the hop"
    );

    // The two pages are different children, in ascending order, with nothing repeated and nothing
    // skipped -- so a handler ignoring `after_coin_id` (and re-serving page one) fails here.
    let walked: Vec<&str> = first
        .coins
        .iter()
        .chain(second.coins.iter())
        .map(|c| c.coin_id.as_str())
        .collect();
    assert_eq!(walked, CHILD_COINS.to_vec());
}

/// **The page bound is refused above its maximum, and pinned from BOTH sides.**
///
/// A bound tested only from below can only confirm itself. The at-maximum case MUST be accepted and
/// the one-over case MUST be refused, or the constant in the docs is not the constant in the code.
///
/// Zero is refused for a different reason than "too large": a page that can hold nothing makes no
/// progress, so a caller looping until a short page arrives would loop forever.
#[test]
fn the_page_bound_is_refused_out_of_range_rather_than_clamped() {
    let at_max = serde_json::from_value::<WalletCoinsByParentParams>(json!({
        "parent_coin_id": "ab".repeat(32), "limit": COINS_BY_PARENT_MAX_LIMIT
    }))
    .expect("the documented maximum must be ACCEPTED, or the constant is not the real bound");
    assert_eq!(at_max.limit, Some(COINS_BY_PARENT_MAX_LIMIT));
    assert_eq!(at_max.effective_limit(), COINS_BY_PARENT_MAX_LIMIT);

    for over in [COINS_BY_PARENT_MAX_LIMIT + 1, u32::MAX, 0] {
        let wire = json!({"parent_coin_id": "ab".repeat(32), "limit": over});
        assert!(
            serde_json::from_value::<WalletCoinsByParentParams>(wire).is_err(),
            "limit {over} must be REFUSED, never clamped: a silently shrunk page hands back a              cursor for a position the caller never asked about"
        );
        // ...and the same rule at the validation seam the dispatcher uses, not only at decode.
        assert!(WalletCoinsByParentParams {
            parent_coin_id: "ab".repeat(32),
            after_coin_id: None,
            limit: Some(over),
        }
        .validated()
        .is_err());
    }

    // An omitted limit is the contract's default -- resolved in ONE place so a node and a client
    // cannot page to two different boundaries.
    assert_eq!(
        WalletCoinsByParentParams::first_page("ab".repeat(32)).effective_limit(),
        COINS_BY_PARENT_DEFAULT_LIMIT
    );
}

/// **The maximum page still fits the transport, with room to spare.**
///
/// [`COINS_BY_PARENT_MAX_LIMIT`] is derived from dig-ipc-protocol's `MAX_FRAME_BYTES`, and a
/// constant derived from another crate's constant drifts the moment somebody raises it "because it
/// looked small". This pins the arithmetic instead of the folklore.
///
/// The record size is measured from a WORST-CASE record — every hash at full length, a `u64::MAX`
/// amount, both heights present — rather than from a typical one, because a bound proved against a
/// small fixture is not a bound.
#[test]
fn the_largest_legal_page_fits_inside_the_transport_frame() {
    /// dig-ipc-protocol `MAX_FRAME_BYTES` (its SPEC.md bounds table). Replicated rather than
    /// imported: dig-ipc-protocol sits at the SAME crate level as this one, so depending on it would
    /// be an illegal same-level edge.
    const MAX_FRAME_BYTES: usize = 1024 * 1024;

    let worst_case = serde_json::to_string(&results::WalletCoinRecord {
        coin_id: "f".repeat(64),
        asset: None,
        amount: u64::MAX,
        parent_coin_info: "f".repeat(64),
        puzzle_hash: "f".repeat(64),
        created_height: Some(u32::MAX),
        spent_height: Some(u32::MAX),
    })
    .unwrap()
    .len()
        + 1; // the comma joining it to the next record

    let largest_page = worst_case * COINS_BY_PARENT_MAX_LIMIT as usize;
    assert!(
        largest_page * 3 < MAX_FRAME_BYTES,
        "the maximum page ({largest_page} B) must fit the 1 MiB frame with 3x headroom for the          envelope and any future additive field; raising the cap past that puts a conforming          node's honest answer beyond what the transport can deliver"
    );
}

/// **An omitted `cursor` key is a decode error, not "there was nothing to resume from".**
///
/// The same guard `spend` and `coin` carry, on the field a paged walk resumes by. Under serde's
/// default treatment of `Option`, any payload carrying `coins` and `complete` would decode with
/// `cursor: None` — so a mis-routed or truncated response would tell a caller the page handed back
/// nothing, and the walk would restart from the beginning or stop, rather than fail loudly.
///
/// The fixtures are the neighbouring reads' REAL result shapes, so this proves the guard against
/// payloads a client could actually receive rather than against invented rubbish.
#[test]
fn an_omitted_cursor_field_is_a_decode_error_not_an_empty_page() {
    // Explicit null still decodes: an empty page genuinely has nothing to resume from.
    let empty = serde_json::from_value::<results::WalletCoinsByParentResult>(json!({
        "coins": [], "complete": true, "cursor": null,
        "source": "fallback", "synced": false, "peak_height": null
    }))
    .expect("an explicitly null cursor is a valid empty page");
    assert_eq!(empty.cursor, None);

    for wire in [
        json!({ "coins": [], "complete": true, "source": "fallback", "synced": false,
                "peak_height": null }),
        // `control.wallet.coins`' shape: same `coins` key, no cursor, no completeness.
        json!({ "coins": [], "source": "db", "synced": true, "peak_height": 5_000_000u32 }),
    ] {
        assert!(
            serde_json::from_value::<results::WalletCoinsByParentResult>(wire.clone()).is_err(),
            "a payload without a `cursor` key must not decode into a nothing-to-resume-from \
             page: {wire}"
        );
    }

    // And `complete` is required for the same reason -- it has no default, so a payload that omits
    // it MUST NOT decode into the dangerous reading that the page was whole.
    assert!(
        serde_json::from_value::<results::WalletCoinsByParentResult>(json!({
            "coins": [], "cursor": null, "source": "fallback", "synced": false,
            "peak_height": null
        }))
        .is_err(),
        "a payload without `complete` must not decode into a claim that the page is whole"
    );
}

/// **A caller-supplied page bound reaches the node instead of being silently dropped.**
#[test]
fn a_by_parent_request_carries_its_page_bound() {
    let params: WalletCoinsByParentParams =
        serde_json::from_value(json!({"parent_coin_id": "ab".repeat(32), "limit": 5}))
            .expect("a bounded request must decode");
    let wire = serde_json::to_value(&params).unwrap();
    assert_eq!(
        wire["limit"],
        json!(5),
        "a page bound the caller asked for must not be discarded on the way to the node"
    );
}

#[test]
fn wallet_coin_by_id_params_refuse_malformed_ids_at_deserialization() {
    let bad_id = "AB".repeat(32);
    let upper = serde_json::from_value::<WalletCoinByIdParams>(json!({"coin_id": bad_id}));
    assert!(
        upper.is_err(),
        "uppercase ids must fail during deserialization"
    );
}

/// **A mempool refusal is a successful call.** The nearest wrong implementation maps a refusal onto
/// the error channel, where it becomes indistinguishable from a network that could not be reached —
/// and the two demand opposite remedies (retry this bundle, versus build a different one).
///
/// The fixture varies ONE thing against the accepting case above: which bundle is pushed.
#[test]
fn a_mempool_refusal_arrives_as_a_value_not_as_an_error() {
    let outcome = round_trip(&WalletBroadcastParams {
        signed_bundle_hex: REJECTED_BUNDLE.into(),
    })
    .expect("a refusal must arrive on the Ok channel, never as a control error");

    assert!(!outcome.accepted);
    assert_eq!(outcome.rejection.as_deref(), Some("DOUBLE_SPEND"));
    assert_eq!(
        outcome.transaction_id, None,
        "a refused bundle has no transaction to report"
    );
}

/// **dig-app's frozen shapes read our results losslessly.** These local structs are transcribed
/// from `dig-app-core::wallet::engine` — the consumer's own types, which this crate cannot depend
/// on — so the superset relationship is proven here rather than assumed at adoption time.
///
/// Written as SEPARATE structs, not as a field-name string comparison: a name check would pass on a
/// field whose TYPE had drifted, and `amount: u64` versus a string is exactly the drift a
/// hand-copied contract produces.
#[test]
fn dig_apps_frozen_engine_shapes_deserialize_our_wallet_results() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct AppCoinRecord {
        coin_id: String,
        asset: Asset,
        amount: u64,
    }
    #[derive(Debug, Deserialize)]
    struct AppCoinsResponse {
        coins: Vec<AppCoinRecord>,
    }
    #[derive(Debug, Deserialize)]
    struct AppBroadcastResponse {
        accepted: bool,
        #[serde(default)]
        transaction_id: Option<String>,
    }

    let coins = serde_json::to_value(results::WalletCoinsResult {
        coins: vec![results::WalletCoinRecord {
            coin_id: "aa".repeat(32),
            asset: Some(Asset::DIG),
            amount: 2_000_000_000_000,
            parent_coin_info: "bb".repeat(32),
            puzzle_hash: "cc".repeat(32),
            created_height: Some(5_000_000),
            spent_height: None,
        }],
        source: Some(results::WalletReadSource::Db),
        synced: true,
        peak_height: Some(5_000_000),
    })
    .unwrap();
    let read: AppCoinsResponse =
        serde_json::from_value(coins).expect("dig-app must read our coins");
    assert_eq!(
        read.coins,
        vec![AppCoinRecord {
            coin_id: "aa".repeat(32),
            asset: Asset::DIG,
            amount: 2_000_000_000_000,
        }]
    );

    let pushed = serde_json::to_value(results::WalletBroadcastResult {
        accepted: true,
        transaction_id: Some("dd".repeat(32)),
        rejection: None,
    })
    .unwrap();
    let read: AppBroadcastResponse =
        serde_json::from_value(pushed).expect("dig-app must read our broadcast outcome");
    assert!(read.accepted);
    assert_eq!(read.transaction_id, Some("dd".repeat(32)));
}

#[test]
fn dig_apps_frozen_coin_shape_rejects_null_asset_in_wallet_coins() {
    use serde::Deserialize;

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct AppCoinRecord {
        coin_id: String,
        asset: Asset,
        amount: u64,
    }
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct AppCoinsResponse {
        coins: Vec<AppCoinRecord>,
    }

    let coins = serde_json::to_value(results::WalletCoinsResult {
        coins: vec![results::WalletCoinRecord {
            coin_id: "aa".repeat(32),
            asset: None,
            amount: 2_000_000_000_000,
            parent_coin_info: "bb".repeat(32),
            puzzle_hash: "cc".repeat(32),
            created_height: Some(5_000_000),
            spent_height: None,
        }],
        source: Some(results::WalletReadSource::Db),
        synced: true,
        peak_height: Some(5_000_000),
    })
    .unwrap();
    assert!(
        serde_json::from_value::<AppCoinsResponse>(coins).is_err(),
        "dig-app's frozen coin shape requires a non-null asset in control.wallet.coins"
    );
}

/// The wallet failure codes are the ones dig-node already emits, pinned by NUMBER and SYMBOL.
///
/// They live here so a client branches on the contract's constant instead of retyping the literal —
/// the drift dig-app's own review caught itself doing (dig-app#109), and which no fixture could
/// have caught, because the fixture would have retyped the same literal.
#[test]
fn the_wallet_failure_codes_match_the_nodes_catalogue() {
    for (code, number, symbol) in [
        (
            ControlErrorCode::WalletNoChainSource,
            -32040,
            "WALLET_NO_CHAIN_SOURCE",
        ),
        (
            ControlErrorCode::WalletNotSynced,
            -32041,
            "WALLET_NOT_SYNCED",
        ),
        (
            ControlErrorCode::WalletReadFailed,
            -32042,
            "WALLET_READ_FAILED",
        ),
        (
            ControlErrorCode::WalletRateLimited,
            -32043,
            "WALLET_RATE_LIMITED",
        ),
    ] {
        assert_eq!(code.code(), number, "{symbol} number drifted");
        assert_eq!(code.name(), symbol);
        assert_eq!(ControlErrorCode::from_code(number), Some(code));
        assert_eq!(
            code.origin(),
            "node",
            "a wallet read is served by the node's backend, not the shell"
        );
    }
}

// ---- control.wallet.arrivals (dig_ecosystem#2548) ------------------------------------------

/// **The arrival cursor's request and response shapes are pinned, in both node dialects.**
///
/// The node this contract describes already SERVES `control.wallet.arrivals`, so these vectors are
/// written against what it emits rather than against what would be tidy: `amount` is a decimal
/// STRING (the ledger stores the full `u64` range, which a JSON number cannot carry losslessly) and
/// `asset_id` is `null` for native XCH or the CAT's hex TAIL — never a ticker.
///
/// The empty page is a separate vector because it is the ordinary answer, not an edge case: it means
/// "the node consulted its own ledger and nothing has arrived since your cursor", and a client that
/// could not decode it would be blind exactly when nothing is wrong.
#[test]
fn the_arrival_cursor_wire_shapes_are_byte_stable() {
    assert_request(
        &WalletArrivalsParams {
            after_seq: 41,
            limit: Some(10),
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.arrivals","params":{"after_seq":41,"limit":10}}),
    );
    // An omitted `limit` is the node's default page size, so it is absent from the wire rather than
    // sent as a number this client invented.
    assert_request(
        &WalletArrivalsParams {
            after_seq: 0,
            limit: None,
        },
        json!({"jsonrpc":"2.0","id":1,"method":"control.wallet.arrivals","params":{"after_seq":0}}),
    );
    assert_result_round_trips::<results::WalletArrivalsResult>(json!({
        "arrivals": [{
            "seq": 7u64,
            "coin_id": "ab".repeat(32),
            "puzzle_hash": "cc".repeat(32),
            "amount": "18446744073709551615",
            "asset_id": null,
            "confirmed_height": 5_000_000u32
        }],
        "cursor": 7u64,
        "latest": 9u64
    }));
    assert_result_round_trips::<results::WalletArrivalsResult>(json!({
        "arrivals": [{
            "seq": 8u64,
            "coin_id": "ab".repeat(32),
            "puzzle_hash": "cc".repeat(32),
            "amount": "2500",
            "asset_id": "a406d3".to_string(),
            "confirmed_height": 5_000_001u32
        }],
        "cursor": 8u64,
        "latest": 8u64
    }));
    // The ordinary answer: nothing new. `cursor` echoes what the caller asked from, so a client
    // that stores it does not rewind.
    assert_result_round_trips::<results::WalletArrivalsResult>(json!({
        "arrivals": [], "cursor": 41u64, "latest": 41u64
    }));
}

/// **`latest` may run AHEAD of `cursor`, and the contract keeps that expressible.**
///
/// The node reads `latest` after materializing the page, so an arrival recorded in between sits
/// above the page and below `latest`. A client that resumed from `latest` would step over it. This
/// pins that the two are separate fields carrying separate facts — a shape that collapsed them, or
/// a result type that derived one from the other, fails here.
#[test]
fn the_arrival_page_cursor_is_the_last_row_handed_over_not_the_ledger_head() {
    let ahead: results::WalletArrivalsResult = serde_json::from_value(json!({
        "arrivals": [{
            "seq": 5u64, "coin_id": "ab".repeat(32), "puzzle_hash": "cc".repeat(32),
            "amount": "1", "asset_id": null, "confirmed_height": 100u32
        }],
        "cursor": 5u64,
        "latest": 12u64
    }))
    .expect("a page whose ledger has moved on is a valid answer");
    assert_eq!(
        ahead.cursor, 5,
        "the cursor must be the last row handed over"
    );
    assert_eq!(ahead.latest, 12, "the ledger head must survive the decode");
    assert_eq!(ahead.arrivals[0].amount, "1");
}

/// **The arrival cursor is TOKEN-GATED and reaches its own handler over the real dispatcher.**
///
/// The mock answers with a `seq` no neighbouring wallet handler produces, so an arm wired to the
/// wrong method is distinguishable rather than passing on a shape they happen to share.
#[test]
fn the_arrival_cursor_is_gated_and_routes_to_its_own_handler() {
    assert!(
        ControlMethod::WalletArrivals.requires_auth(),
        "the arrival cursor volunteers this node's own watched puzzle hashes, so it is gated \
         unlike the caller-addressed wallet reads"
    );
    let page = round_trip(&WalletArrivalsParams {
        after_seq: 0,
        limit: None,
    })
    .expect("arrivals must route");
    assert_eq!(page.arrivals[0].seq, 4_242);
    assert_eq!(page.cursor, 4_242);
    assert_eq!(page.latest, 4_243, "the ledger head must not be the cursor");
}

/// **An unknown phase token MUST NOT fail the parse.** This is the regression test for
/// dig_ecosystem#2609, and it is the whole reason [`results::WalletSyncPhase`] carries an
/// unrecognised arm.
///
/// The enum shipped as a closed three-variant `Deserialize`. When dig-node grew a fourth phase, the
/// unknown token did not degrade one field — serde aborted the WHOLE
/// [`results::WalletSyncStatusResult`], so dig-app's sync read returned `Err`, its chain-sync state
/// collapsed to `Unknown`, and the badge rendered nothing. A contract that fails closed on an
/// unrecognised token converts every future phase addition into a silent outage in every consumer
/// that has not been rebuilt yet.
#[test]
fn an_unknown_phase_token_deserializes_instead_of_erroring() {
    let parsed =
        serde_json::from_value::<results::WalletSyncPhase>(json!("a_phase_from_a_newer_node"))
            .expect("an unrecognised phase token must parse, not abort the response");

    assert_ne!(parsed, results::WalletSyncPhase::NotStarted);
    assert_ne!(parsed, results::WalletSyncPhase::Syncing);
    assert_ne!(
        parsed,
        results::WalletSyncPhase::Synced,
        "an unknown token coerced into a KNOWN phase is worse than the parse error it replaced: it \
         states a sync fact the node never sent"
    );
}

/// **One unknown token must not take the rest of the payload with it.** The height and the peer
/// count are still perfectly good observations, and a consumer that can read them renders a truthful
/// partial view instead of nothing at all.
#[test]
fn an_unknown_phase_token_does_not_kill_the_surrounding_result() {
    let parsed = serde_json::from_value::<results::WalletSyncStatusResult>(json!({
        "phase": "a_phase_from_a_newer_node",
        "peak_height": 5_000_000u32,
        "chia_peer_count": 3u32
    }))
    .expect("the unknown token must degrade the phase alone, not the whole result");

    assert_eq!(parsed.peak_height, Some(5_000_000));
    assert_eq!(parsed.chia_peer_count, Some(3));
}

/// **The unrecognised token is preserved verbatim, not normalised away.** Observability is the whole
/// point of the variant: a consumer that can name the token it did not understand turns a silent
/// mismatch into a one-line diagnosis, which is exactly what dig_ecosystem#2609 lacked — the break
/// was invisible until somebody built a probe against the published crate.
#[test]
fn an_unrecognized_phase_carries_the_token_it_did_not_understand() {
    let parsed =
        serde_json::from_value::<results::WalletSyncPhase>(json!("a_phase_from_a_newer_node"))
            .unwrap();

    assert_eq!(
        parsed.unrecognized_token(),
        Some("a_phase_from_a_newer_node")
    );
    assert!(!parsed.is_recognized());
    assert_eq!(parsed.as_wire(), "a_phase_from_a_newer_node");
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        json!("a_phase_from_a_newer_node"),
        "re-encoding must hand back the node's own token, never a placeholder"
    );

    // Every KNOWN phase reports no unrecognised token, so a consumer branching on the accessor
    // cannot mistake a phase it understands for one it does not.
    for phase in results::WalletSyncPhase::ALL {
        assert_eq!(phase.unrecognized_token(), None, "{phase:?}");
        assert!(phase.is_recognized(), "{phase:?}");
    }
}

/// **A phase is only ever a STRING.** Tolerating an unknown token must not slide into tolerating an
/// unknown SHAPE: a number, an object, or a null where a phase belongs is a malformed response, and
/// swallowing it as `Unrecognized` would let a genuinely broken payload read as a newer node.
#[test]
fn a_non_string_phase_is_still_a_type_error() {
    for malformed in [
        json!(3),
        json!(null),
        json!({"phase": "synced"}),
        json!(["synced"]),
    ] {
        assert!(
            serde_json::from_value::<results::WalletSyncPhase>(malformed.clone()).is_err(),
            "{malformed} is a malformed phase, not an unrecognised one"
        );
    }
}

/// **A payload from a node that predates `watched_addresses` still parses.** This is
/// dig_ecosystem#2609 in mirror image — a required new field would make every older node unreadable
/// to a client that has it, the same fail-closed break with the two sides swapped.
///
/// The absent field decodes to `None`, which means *the node did not report it* and NOT `Some(0)`.
/// Collapsing the two would have an old node silently assert that it watches no addresses, which is
/// the affirmative all-clear this whole family exists to stop being emitted by accident.
#[test]
fn a_payload_without_watched_addresses_parses_as_unreported() {
    let legacy = serde_json::from_value::<results::WalletSyncStatusResult>(json!({
        "phase": "synced", "peak_height": 5_000_000u32, "chia_peer_count": 5u32
    }))
    .expect("a node predating the field must stay readable");

    assert_eq!(
        legacy.watched_addresses, None,
        "absent means unreported; Some(0) would be a measurement the node never made"
    );
    assert_eq!(legacy.phase, results::WalletSyncPhase::Synced);
    assert_eq!(legacy.peak_height, Some(5_000_000));

    // An explicit null says the same thing as an absent key: the node cannot report the number.
    let explicit_null = serde_json::from_value::<results::WalletSyncStatusResult>(json!({
        "phase": "synced", "peak_height": 5_000_000u32, "chia_peer_count": 5u32,
        "watched_addresses": null
    }))
    .unwrap();
    assert_eq!(explicit_null, legacy);
}

/// **A payload from a node that predates `subscription_peer_count`/`chia_peer_peak_height` still
/// parses.** dig_ecosystem#2815 in mirror image with #2609/#2806: a node running before either key
/// existed omits both, and a client built against the newer contract must still read the rest of the
/// payload rather than fail closed on it.
///
/// Both absent fields decode to `None` — *not reported*, never `Some(0)`, since `0` is a real height/
/// count a conforming node can genuinely observe.
#[test]
fn a_payload_without_the_peer_fields_parses_as_unreported() {
    // The exact shape a pre-#2806 node emits: no `subscription_peer_count`, no
    // `chia_peer_peak_height`, both keys absent rather than null.
    let legacy = serde_json::from_value::<results::WalletSyncStatusResult>(json!({
        "phase": "syncing", "peak_height": 9_132_747u32, "chia_peer_count": 5u32,
        "watched_addresses": 0u32
    }))
    .expect("a node predating these fields must stay readable");

    assert_eq!(
        legacy.subscription_peer_count, None,
        "absent means unreported; Some(0) would claim no supervisor is attached, a stronger claim \
         than the node made"
    );
    assert_eq!(
        legacy.chia_peer_peak_height, None,
        "absent means unreported; Some(0) would be a real height, not the unobserved state"
    );
    assert_eq!(legacy.chia_peer_count, Some(5));

    // The current 0.115.x wire shape, measured live: both new keys present with real values.
    let current = serde_json::from_value::<results::WalletSyncStatusResult>(json!({
        "phase": "syncing", "peak_height": 9_132_747u32, "chia_peer_count": 5u32,
        "subscription_peer_count": 1u32, "chia_peer_peak_height": 9_140_469u32,
        "watched_addresses": 0u32
    }))
    .expect("the current wire shape must parse");

    assert_eq!(current.subscription_peer_count, Some(1));
    assert_eq!(current.chia_peer_peak_height, Some(9_140_469));
    assert_ne!(
        current.chia_peer_count, current.subscription_peer_count,
        "the two fields are different observations and must not collapse to the same reading"
    );
}

/// **`phase` is the one structurally mandatory field; every count decodes absence as unreported.**
///
/// Pins the real serde behaviour rather than an assumed one. `Option` fields have ALWAYS tolerated a
/// missing key here — `watched_addresses` needed no attribute to gain the property, and
/// `peak_height` and `chia_peer_count` have had it since this type shipped. The test exists because
/// the opposite was assumed while adding the new field, and a doc-comment asserting the three
/// original fields were required would have been simply false.
///
/// The value of pinning it: an absent count MUST decode to `None`, never to `Some(0)`. A truncated
/// response that read as a measured zero would be an affirmative claim the node never made.
#[test]
fn phase_is_required_and_absent_counts_decode_as_unreported() {
    let mut without_phase = json!({
        "peak_height": 5_000_000u32, "chia_peer_count": 5u32, "watched_addresses": 12u32
    });
    assert!(
        serde_json::from_value::<results::WalletSyncStatusResult>(without_phase.take()).is_err(),
        "a response with no phase is malformed — there is no honest default for it"
    );

    for missing in ["peak_height", "chia_peer_count", "watched_addresses"] {
        let mut payload = json!({
            "phase": "synced", "peak_height": 5_000_000u32, "chia_peer_count": 5u32,
            "watched_addresses": 12u32
        });
        payload.as_object_mut().unwrap().remove(missing);

        let parsed = serde_json::from_value::<results::WalletSyncStatusResult>(payload)
            .unwrap_or_else(|e| panic!("`{missing}` absent must stay readable: {e}"));
        let decoded = serde_json::to_value(&parsed).unwrap();

        assert_eq!(
            decoded[missing],
            json!(null),
            "`{missing}` absent must decode as unreported, never as a measured zero"
        );
    }
}

/// **The two idle phases are different values, and the count cannot tell them apart.** The fixture
/// varies ONLY the phase, holding `watched_addresses` at the `0` both states share, so an
/// implementation that folded "no wallet" and "wallet not unlocked" into one nothing-to-watch token
/// — the exact conflation dig_ecosystem#2609's fix nearly shipped — cannot pass.
#[test]
fn no_wallet_enrolled_is_distinguishable_from_a_wallet_that_is_not_unlocked() {
    let no_wallet = results::WalletSyncStatusResult {
        phase: results::WalletSyncPhase::NoWalletEnrolled,
        peak_height: None,
        chia_peer_count: Some(2),
        watched_addresses: Some(0),
        subscription_peer_count: None,
        chia_peer_peak_height: None,
    };
    // Inherits `watched_addresses: Some(0)` from the fixture above: the two states genuinely SHARE
    // the count, and only the phase differs. Setting it again here would weaken the claim.
    let locked = results::WalletSyncStatusResult {
        phase: results::WalletSyncPhase::WalletNotUnlocked,
        ..no_wallet.clone()
    };

    assert_ne!(no_wallet, locked);
    assert_ne!(
        serde_json::to_value(&no_wallet).unwrap(),
        serde_json::to_value(&locked).unwrap(),
        "an enrolled-but-unwatched wallet must not wear the all-clear's wire shape"
    );
    assert_eq!(
        serde_json::to_value(&locked).unwrap()["phase"],
        json!("wallet_not_unlocked")
    );
}

/// **Only two phases may be rendered as settled, and the compiler decides which.**
///
/// `Synced` and `NoWalletEnrolled` are the complete pictures. Everything else has something
/// outstanding, and `WalletNotUnlocked` most of all — a wallet exists and nothing is following it,
/// which is the one idle state that must never wear a green tick.
///
/// Pinned against a literal table rather than by calling the method on itself, so an implementation
/// that widened the predicate to "any idle phase" — the nearest wrong one, and the conflation this
/// family exists to prevent — fails here.
#[test]
fn only_a_complete_picture_may_render_as_settled() {
    let expected = [
        (results::WalletSyncPhase::NotStarted, false),
        (results::WalletSyncPhase::Syncing, false),
        (results::WalletSyncPhase::Synced, true),
        (results::WalletSyncPhase::NoWalletEnrolled, true),
        (results::WalletSyncPhase::WalletNotUnlocked, false),
    ];
    for (phase, settled) in &expected {
        assert_eq!(
            phase.may_render_as_settled(),
            *settled,
            "{phase:?} is on the wrong side of the settled line"
        );
    }
    assert_eq!(
        expected.len(),
        results::WalletSyncPhase::ALL.len(),
        "every known phase must be classified here"
    );

    // A phase this build cannot interpret is never settled: it has no idea what the node meant.
    for unknown in ["a_newer_token", "", "settled", "no_addresses_to_watch"] {
        assert!(
            !results::WalletSyncPhase::from(unknown).may_render_as_settled(),
            "{unknown:?} must not be settled — this build cannot know what it means"
        );
    }
}

/// **A token cannot forge a log line or a label.** The raw accessor stays raw for relaying, and both
/// display paths escape.
///
/// The fixture is the concrete attack: `ESC [ 2 K` erases the current terminal line and `\r` returns
/// the cursor, so `format!("unknown phase: {token}")` rendered RAW prints a line reading `synced` —
/// the prefix that said it was unknown is gone. A right-to-left override does the same to a UI
/// label. Both are node-supplied, and this contract's whole subject is a consumer not asserting
/// something false about a wallet.
#[test]
fn a_token_cannot_forge_a_log_line() {
    let hostile = "\u{1b}[2K\rsynced\u{202e}";
    let phase = results::WalletSyncPhase::from(hostile);
    let token = phase
        .unrecognized_token_value()
        .expect("a hostile token is not a known phase");

    // The RAW accessor is deliberately unchanged: a relay must hand on the exact bytes.
    assert_eq!(token.as_str(), hostile);
    assert_eq!(phase.as_wire(), hostile, "the wire form stays verbatim");

    // Every DISPLAY path escapes. No bare ESC, CR or bidi override survives.
    for rendered in [token.to_string(), token.display_bounded(200)] {
        for forbidden in ['\u{1b}', '\r', '\u{202e}'] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden:?} survived into a display rendering: {rendered:?}"
            );
        }
        assert!(
            rendered.contains("synced"),
            "escaping must stay legible, not redact"
        );
    }
}

/// **A bounded rendering is bounded, and says when it dropped something.**
///
/// Nothing caps a token's length on the wire — the contract is transport-agnostic, and rejecting an
/// over-long token would put back the fail-closed parse this type exists to remove — so the bound
/// lives at the point of display. A truncated rendering that looked complete would be its own small
/// lie, hence the marker.
#[test]
fn a_bounded_rendering_is_bounded_and_marked() {
    let long = results::WalletSyncPhase::from("a".repeat(10_000).as_str());
    let token = long.unrecognized_token_value().unwrap();

    let rendered = token.display_bounded(32);
    assert!(
        rendered.trim_end_matches('…').len() <= 32,
        "escaped content must respect the bound: {} bytes",
        rendered.len()
    );
    assert!(rendered.ends_with('…'), "a truncated rendering must say so");

    // A token that FITS is not marked, so the marker means something.
    let short = results::WalletSyncPhase::from("a_newer_token");
    let short_token = short.unrecognized_token_value().unwrap();
    assert_eq!(short_token.display_bounded(64), "a_newer_token");
    assert!(!short_token.display_bounded(64).ends_with('…'));

    // The pathological inputs, PINNED rather than proven once by hand. The bound is computed on the
    // ESCAPED bytes, and a control character expands about sixfold, so expansion is the case a naive
    // implementation overshoots on -- while slicing the raw string instead would panic on a char
    // boundary in the multi-byte rows below.
    for (raw, max) in [
        ("", 0usize),
        ("\u{1b}\u{1b}\u{1b}", 0),
        ("\u{1b}\u{1b}\u{1b}", 5),
        ("\u{1b}\u{1b}\u{1b}", 6),
        ("\u{1f600}\u{1f600}", 1),
        ("\u{1f600}\u{1f600}", 4),
        ("\u{202e}abc", 3),
        ("\u{7f}\u{9b}", 32),
    ] {
        let phase = results::WalletSyncPhase::from(raw);
        let Some(token) = phase.unrecognized_token_value() else {
            continue;
        };
        let rendered = token.display_bounded(max);

        assert!(
            rendered.trim_end_matches('…').len() <= max,
            "{raw:?} at max={max} rendered {rendered:?}, over the bound"
        );
        for forbidden in ['\u{1b}', '\r', '\u{202e}', '\u{7f}', '\u{9b}'] {
            assert!(
                !rendered.contains(forbidden) && !token.to_string().contains(forbidden),
                "{forbidden:?} survived rendering of {raw:?}"
            );
        }
    }
}
/// **An older node's `control.peerCounts` payload still decodes, and its silence stays silence
/// (dig_ecosystem#2570).**
///
/// The known-peer count was added to a shape that shipped without it, so every node predating it
/// answers with the two-field object below. Two things must hold, and they are different claims:
/// the payload must DECODE rather than be rejected for a missing field, and the absent count must
/// arrive as `None`. A `#[serde(default)]`-by-accident implementation that mapped the silence to
/// `Some(0)` would satisfy the first and fail the second — and would tell a client the old node had
/// looked at its address book and found it empty, which it never did.
///
/// The fixture keeps `dig_peer_count` at a NON-zero value so the two counts cannot be confused by
/// coincidence: a decoder that defaulted the new field from the old one would land on `Some(6)`,
/// which this catches for the same reason a `Some(0)` default does.
#[test]
fn an_older_nodes_peer_counts_decode_with_the_known_count_unknown_not_zero() {
    let legacy: results::PeerCountsResult = serde_json::from_value(json!({
        "dig_peer_count": 6u32, "chia_peer_count": 3u32
    }))
    .expect("a payload from a node predating the known-peer count must decode, not be rejected");
    assert_eq!(legacy.dig_peer_count, Some(6));
    assert_eq!(legacy.chia_peer_count, Some(3));
    assert_eq!(
        legacy.known_dig_peer_count, None,
        "a node that never reported a known-peer count has an UNKNOWN one; a zero here would \
         claim it consulted an address book it was never asked about"
    );
}

/// **The known count is carried independently of the connected count (dig_ecosystem#2570).**
///
/// The whole point of the field is to express the state `dig_peer_count` cannot: knowing of peers
/// while holding no connection to any of them. This pins the two as separate observations by
/// decoding the diagnostic vector and asserting each lands in its own field — an implementation
/// that aliased the two, the nearest wrong one, reports `0` known here.
#[test]
fn knowing_of_peers_while_connected_to_none_is_expressible() {
    let stranded: results::PeerCountsResult = serde_json::from_value(json!({
        "dig_peer_count": 0u32, "chia_peer_count": 3u32, "known_dig_peer_count": 41u32
    }))
    .expect("the diagnostic vector must decode");
    assert_eq!(stranded.dig_peer_count, Some(0), "connected to nobody");
    assert_eq!(
        stranded.known_dig_peer_count,
        Some(41),
        "while knowing of 41 — a reachability fault, not a discovery one"
    );
}

/// **Enrolment is idempotent, and the second call is distinguishable from the first.**
///
/// The fixture varies ONE key across three calls against a registry that already holds two, so the
/// two nearest wrong implementations both fail: one that reports `added` as the SUBMITTED count
/// (the re-enrolment would report 1) and one that reports 0 whenever the set is non-empty (the
/// genuinely new key would report 0). `watched` is asserted alongside each, because `added` alone
/// cannot show that a duplicate left the set the same size.
#[test]
fn re_enrolling_a_key_succeeds_and_changes_nothing() {
    let first = round_trip(&WalletWatchParams {
        public_keys: vec![ENROL_KEY_A.into(), ENROL_KEY_B.into()],
    })
    .expect("watch must route");
    assert_eq!((first.added, first.watched), (2, 2));

    let again = round_trip(&WalletWatchParams {
        public_keys: vec![ENROL_KEY_A.into()],
    })
    .expect("re-enrolment is a success, never an error");
    assert_eq!(
        (again.added, again.watched),
        (0, 2),
        "an already-enrolled key adds nothing and leaves the set the same size"
    );

    let novel = round_trip(&WalletWatchParams {
        public_keys: vec!["c3".repeat(48)],
    })
    .expect("watch must route");
    assert_eq!(
        (novel.added, novel.watched),
        (1, 3),
        "the control: a genuinely new key still enrols, so `added: 0` above is idempotence and \
         not a handler that never adds"
    );
}

/// **A `0x` prefix is normalized AT THE BOUNDARY, not merely tolerated.**
///
/// Enrolling the prefixed spelling and then the bare one must report `added: 0` the second time. A
/// node that accepted both spellings without normalizing would follow the same key twice under two
/// names, and a client unwatching the bare spelling would leave the prefixed one enrolled forever.
#[test]
fn the_prefixed_and_bare_spellings_are_the_same_key() {
    let prefixed = round_trip(&WalletWatchParams {
        public_keys: vec![format!("0x{ENROL_KEY_A}")],
    })
    .expect("a 0x-prefixed key is accepted");
    assert_eq!((prefixed.added, prefixed.watched), (1, 1));

    let bare = round_trip(&WalletWatchParams {
        public_keys: vec![ENROL_KEY_A.into()],
    })
    .expect("watch must route");
    assert_eq!(
        (bare.added, bare.watched),
        (0, 1),
        "the prefix is stripped before the key is stored, so the two spellings are one key"
    );
}

/// **One malformed key refuses the WHOLE request — the well-formed keys beside it are NOT enrolled.**
///
/// The fixture pairs a valid key with a malformed one, because asserting only the error code cannot
/// tell a whole-request refusal from a handler that enrolled the good key and then complained. The
/// follow-up `watched` read is what distinguishes them: after the refusal the registry must still be
/// empty. A partial enrolment is the dangerous outcome — the client believes it asked for two
/// addresses, the node follows one, and the next balance read reports the shortfall as absent money.
#[test]
fn a_single_malformed_key_refuses_the_whole_enrolment() {
    let node = MockNode;
    let req = JsonRpcRequest::new(
        RequestId::Number(1),
        ControlMethod::WalletWatch.name(),
        // 64-hex: the length of a coin id or a puzzle hash, which is the wrong-unit mistake this
        // method's key form exists to prevent.
        json!({ "public_keys": [ENROL_KEY_A, SPENT_COIN] }),
    );
    let err = block_on(node.dispatch(req)).into_result().unwrap_err();
    assert_eq!(err.code_enum(), Some(ControlErrorCode::InvalidParams));

    assert!(
        round_trip(&WalletWatchedParams {})
            .expect("watched must route")
            .public_keys
            .is_empty(),
        "the valid key submitted beside the malformed one must NOT have been enrolled"
    );
}

/// **Unwatch removes exactly the named keys, and `watched` reflects it.**
///
/// The unknown key in the same request is the control for idempotence, and the surviving key is the
/// control against a handler that clears the whole set — an implementation that would otherwise pass
/// an assertion on `removed` alone.
#[test]
fn unwatch_removes_only_what_it_names() {
    round_trip(&WalletWatchParams {
        public_keys: vec![ENROL_KEY_A.into(), ENROL_KEY_B.into()],
    })
    .expect("watch must route");

    let removed = round_trip(&WalletUnwatchParams {
        public_keys: vec![ENROL_KEY_A.into(), "d4".repeat(48)],
    })
    .expect("unwatching a key that was never enrolled is a success");
    assert_eq!(
        (removed.removed, removed.watched),
        (1, 1),
        "one of the two named keys was enrolled; the never-enrolled one is not an error"
    );

    assert_eq!(
        round_trip(&WalletWatchedParams {})
            .expect("watched must route")
            .public_keys,
        vec![ENROL_KEY_B.to_owned()],
        "the key that was not named survives -- unwatch is not a clear"
    );
}

/// **An `subscriptions.json` written before `kind` existed still reads, and still means capsule.**
///
/// The fixture is the untagged row a real machine already has on disk. The nearest wrong
/// implementation — a REQUIRED `kind` — fails to decode it, and a node that cannot read its own
/// subscription file starts with an empty one, so the upgrade silently unsubscribes the user.
///
/// The explicit `"profile"` case is the control. Without it this test would also pass on an
/// implementation that ignored the wire and always answered `Capsule`, which is a different (and
/// equally wrong) tolerance.
#[test]
fn an_untagged_subscription_decodes_as_a_capsule_and_a_tagged_one_is_honoured() {
    let legacy: SubscribeParams =
        serde_json::from_value(json!({ "store_id": STORE })).expect("an untagged row must decode");
    assert_eq!(legacy.kind, SubscriptionKind::Capsule);

    let tagged: SubscribeParams =
        serde_json::from_value(json!({ "store_id": STORE, "kind": "profile" }))
            .expect("a tagged row must decode");
    assert_eq!(tagged.kind, SubscriptionKind::Profile);
}

/// **A node build that predates `kind` still returns a parseable acknowledgement.**
///
/// The same tolerance, in the other direction: an app on the new contract talking to a node that
/// has not been updated yet. Without `#[serde(default)]` on the result the whole response fails to
/// parse and a subscription that SUCCEEDED is reported to the user as an error.
#[test]
fn a_subscribe_result_from_an_older_node_decodes_as_a_capsule() {
    let old: results::SubscribeResult =
        serde_json::from_value(json!({ "subscribed": true, "added": true, "store_id": STORE }))
            .expect("an older node's acknowledgement must decode");
    assert_eq!(old.kind, SubscriptionKind::Capsule);

    let new: results::SubscribeResult = serde_json::from_value(
        json!({ "subscribed": true, "added": true, "store_id": STORE, "kind": "profile" }),
    )
    .expect("a tagged acknowledgement must decode");
    assert_eq!(new.kind, SubscriptionKind::Profile);
}

/// **The body cap is 4 MiB, and it is half of dig-gossip's frame ceiling by construction.**
///
/// Pinned from BOTH sides on purpose. The absolute value alone would survive dig-gossip's ceiling
/// moving; the ratio alone would survive both numbers drifting together. A body accepted here but
/// too large for a `PROFILE_BODY` (opcode 225) frame is stored and then permanently unsyncable —
/// present on the node the app talks to and invisible to every other node.
#[test]
fn the_body_cap_is_four_mib_and_half_the_gossip_frame_ceiling() {
    /// dig-gossip's `WS_MAX_MESSAGE_BYTES`, written literally so a drift on either side is visible.
    const WS_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

    assert_eq!(MAX_BODY_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_BODY_BYTES, WS_MAX_MESSAGE_BYTES / 2);
}

/// **Each profile method reaches its OWN handler over the real dispatcher.**
///
/// Keyed to what only that handler can produce: the put echoes back the exact root it was handed
/// with a byte count derived from the body it received, while the read answers `body_b64: None` at
/// a DIFFERENT root. An arm wired to the neighbouring method fails here rather than passing on a
/// shape the two happen to share.
#[test]
fn the_dispatcher_routes_each_profile_method_to_its_own_handler() {
    let put = round_trip(&ProfilePutBodyParams {
        store_id: STORE.into(),
        root: ROOT.into(),
        body_b64: "QUJD".into(),
    })
    .expect("putBody must route");
    assert!(put.stored);
    assert_eq!(put.root, ROOT);
    assert_eq!(put.body_bytes, 4, "the body itself must reach the handler");

    let got = round_trip(&ProfileGetBodyParams {
        store_id: STORE.into(),
        root: ABSENT_COIN.into(),
    })
    .expect("getBody must route");
    assert_eq!(
        got.root, ABSENT_COIN,
        "a read answers at the root it was ASKED for, never a newer one the node happens to hold"
    );
    assert_eq!(got.body_b64, None);
}

// ---- control.chiaPeers.* (dig_ecosystem#2870) -----------------------------------------------

/// **Adding a trusted peer puts the WARNING TEXT on the wire, not merely a flag.**
///
/// `corroboration_bypassed` records that a cost was paid; it cannot be quoted. The whole reason
/// this result carries `notice` is so a client renders the node's own sentence instead of
/// restating the cost locally and drifting from it — so the KAT asserts a quotable, non-empty
/// string that NAMES the bypass reaches the caller through the real dispatcher.
#[test]
fn adding_a_trusted_peer_returns_the_bypass_warning_as_quotable_text() {
    let added = round_trip(&ChiaPeersAddParams {
        ip: " 203.0.113.7 ".into(),
    })
    .expect("chiaPeers.add must route");

    assert!(added.added);
    assert_eq!(
        added.ip, MOCK_TRUSTED_CHIA_PEER,
        "the stored address is the CANONICAL form, so remove and list can match it"
    );
    assert!(added.corroboration_bypassed);
    assert!(
        !added.notice.trim().is_empty(),
        "an empty notice discloses nothing"
    );
    assert!(
        added.notice.to_lowercase().contains("corroboration"),
        "the notice must name the cost it exists to disclose: {}",
        added.notice
    );
}

/// **Removing a peer that was never trusted reports that it removed NOTHING.**
///
/// The fixture varies ONE actor: the same call is made twice, once naming the peer the node
/// actually holds and once naming a peer it does not, with everything else identical. An
/// implementation that answers "removed" unconditionally passes the first and fails here — which
/// is the point, because `remove` is the only way to un-trust a peer that is believed without
/// corroboration, and an operator acts on its answer.
#[test]
fn removing_a_peer_the_node_never_had_is_not_reported_as_a_removal() {
    let hit = round_trip(&ChiaPeersRemoveParams {
        ip: MOCK_TRUSTED_CHIA_PEER.into(),
        ban: false,
    })
    .expect("chiaPeers.remove must route");
    assert_eq!(hit.outcome, results::ChiaPeerRemovalOutcome::Removed);

    let miss = round_trip(&ChiaPeersRemoveParams {
        ip: "198.51.100.4".into(),
        ban: false,
    })
    .expect("chiaPeers.remove must route");
    assert_eq!(
        miss.outcome,
        results::ChiaPeerRemovalOutcome::NoSuchPeer,
        "a peer the node never held must not be reported as un-trusted"
    );
    assert_ne!(
        hit.outcome, miss.outcome,
        "the two cases must be distinguishable at the call site"
    );
}

/// **An address that is not a bare IP literal is refused at the boundary.**
///
/// A rejected address is never written, which is what keeps the ban list — a persisted row keyed
/// by this string — from growing without bound on arbitrary text.
#[test]
fn a_peer_address_that_is_not_an_ip_literal_is_refused() {
    for bad in ["[203.0.113.7]", "203.0.113.7:8444", "peer.example.com", ""] {
        let err = round_trip(&ChiaPeersAddParams { ip: bad.into() })
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must be refused"));
        assert_eq!(err.code_enum(), Some(ControlErrorCode::InvalidParams));
    }
}

/// **A peer nobody has polled lists a `null` peak, and the trusted flag tells the sets apart.**
///
/// `peak_height` is the one signal for judging whether a peer trusted WITHOUT corroboration is
/// current or stuck, so "not polled" must not render as "stalled at genesis" — the two peers in
/// this fixture differ in exactly that, and in nothing else that could carry the distinction.
#[test]
fn the_peer_list_separates_an_unobserved_peak_from_a_real_one() {
    let listed = futures::executor::block_on(MockNode.chia_peers_list()).expect("list must answer");
    let trusted = listed
        .peers
        .iter()
        .find(|p| p.user_managed)
        .expect("the mock holds one trusted peer");
    let discovered = listed
        .peers
        .iter()
        .find(|p| !p.user_managed)
        .expect("and one discovered peer");

    assert!(
        trusted.peak_height.is_some(),
        "a polled peer reports its claimed height"
    );
    assert_eq!(
        discovered.peak_height, None,
        "a peer nobody polled is UNOBSERVABLE, never height zero"
    );
    assert!(!trusted.banned && !discovered.banned);
}

/// **The normative method table renders as ONE table, with the open bootstrap rows inside it.**
///
/// A blank line terminates a markdown table, so a paragraph placed between rows does not merely
/// look untidy — everything after it renders as literal pipe text. When that happened here the
/// rows that fell out were `pairing.request` and `pairing.poll`, the only TOKEN-LESS methods in
/// the catalog, so a reimplementer reading SPEC.md saw the gated surface and missed the bootstrap
/// entirely.
///
/// The check is anchored on the LAST row rather than on a row count, so adding a method is free
/// and interrupting the table is not.
#[test]
fn the_spec_method_table_is_not_interrupted_by_prose() {
    const SPEC: &str = include_str!("../SPEC.md");

    let mut rows = SPEC
        .lines()
        .skip_while(|l| !l.starts_with("| Method | Auth |"))
        .skip(2) // the header and its separator
        .take_while(|l| l.starts_with('|'));

    let table: Vec<&str> = rows.by_ref().collect();
    assert!(
        table.iter().any(|l| l.contains("`control.chiaPeers.add`")),
        "the trusted-peer rows belong in the table"
    );
    let last = table.last().expect("the catalog table has rows");
    assert!(
        last.contains("`pairing.poll`"),
        "the table stops early — the open bootstrap rows have fallen out of it. Last row: {last}"
    );
}

/// **The add result reports the trust state that RESULTED, not the one that was requested.**
///
/// A constant `true` is a claim about custody-grade authority that nothing checks. The fixture
/// varies ONE thing — whether the address was already held as banned — and the un-ban path is the
/// case that actually occurs: an upsert clears the ban flag and leaves the trusted flag alone, so
/// the peer ends up untrusted while the caller is told they configured a trusted node. An operator
/// who believes that is silently depending on corroboration they were told they had bypassed.
#[test]
fn adding_a_banned_peer_reports_that_no_bypass_was_granted() {
    let trusted = round_trip(&ChiaPeersAddParams {
        ip: MOCK_TRUSTED_CHIA_PEER.into(),
    })
    .expect("add must route");
    let unbanned = round_trip(&ChiaPeersAddParams {
        ip: MOCK_BANNED_CHIA_PEER.into(),
    })
    .expect("add must route");

    assert!(trusted.added && unbanned.added, "both calls succeed");
    assert!(trusted.corroboration_bypassed);
    assert!(
        !unbanned.corroboration_bypassed,
        "the entry did not end up trusted, so the result must not claim the bypass"
    );
    assert!(
        !unbanned.notice.trim().is_empty(),
        "the person still needs to be told what actually happened"
    );
}

// ---------------------------------------------------------------------------------------------
// control.spends.list — the automated-spend audit record
// ---------------------------------------------------------------------------------------------

/// The audit fixture, newest-initiated FIRST — the order the contract fixes.
///
/// Four spends, chosen so the three wrong implementations this method invites are each visible:
///
/// * a **confirmed** spend is the honest control. Without one, a fixture of nothing-but-failures
///   cannot tell "failures are listed" from "everything is listed", and cannot tell a client that
///   renders every row as unsettled from one that reads the status at all.
/// * the two **failures differ in exactly one field** — the stage — so an implementation that
///   flattens the stage into a bare "failed" produces two identical rows here and fails. A fixture
///   carrying only one failure could not see that collapse at all.
/// * **unresolved** sits beside them so a `status: "failed"` filter that swept unknown outcomes into
///   the failure bucket returns three rows instead of two.
///
/// Four rows paged two at a time is also what kills the completeness-by-length reading: BOTH pages
/// carry exactly two rows, and only `complete` tells them apart.
///
/// `initiated_ms` values are a pinned constant, never a wall clock — a fixture whose timestamps
/// drift with the run cannot pin an order.
const AUDIT_BASE_MS: u64 = 1_700_000_000_000;

/// Entries in the fixture's record that could not be parsed. NON-ZERO on purpose: a zero here would
/// pass identically for an implementation that never reports corruption at all.
const AUDIT_UNREADABLE: u32 = 2;

/// The SAME reason on both failing spends.
///
/// Deliberate: the two failure rows must differ in EXACTLY ONE field, the stage. Giving them
/// different reasons was the first version of this fixture, and it made the test pass against an
/// implementation that dropped the stage from the wire entirely — the rows still compared unequal,
/// on the reason. A shared reason removes that second signal, so only the stage can tell them apart.
const AUDIT_FAILURE_REASON: &str = "no chain source could be reached";

fn audit_fixture() -> Vec<results::AutomatedSpend> {
    fn spend(
        id: &str,
        initiated_ms: u64,
        status: results::SpendOutcome,
        chain: Option<results::SpendChainReference>,
    ) -> results::AutomatedSpend {
        results::AutomatedSpend {
            id: id.into(),
            revision: 2,
            kind: "mirror-coin".into(),
            purpose: "renew the mirror advertising this store".into(),
            authority: results::SpendAuthority {
                principal: "node".into(),
                grant: "auto_mirror_renewal".into(),
            },
            asset: results::SpendAsset::Xch,
            // Above 2^53, so a client parsing amounts as JSON numbers loses the value. That is the
            // whole reason the field is a string, and a fixture under the boundary could not see it.
            amount_mojos: "9007199254740993".into(),
            fee_mojos: "1000".into(),
            store_id: Some(STORE.into()),
            initiated_ms,
            updated_ms: initiated_ms + 10,
            status,
            funding_coin_ids: vec![SPENT_COIN.into()],
            chain_reference: chain,
        }
    }

    vec![
        spend(
            "sp_confirmed",
            AUDIT_BASE_MS + 400,
            results::SpendOutcome::Confirmed {
                height: 9_172_077,
                coin_id: CHILD_COINS[0].into(),
            },
            Some(results::SpendChainReference {
                coin_id: CHILD_COINS[0].into(),
                confirmed: true,
            }),
        ),
        spend(
            "sp_broadcast",
            AUDIT_BASE_MS + 300,
            results::SpendOutcome::Failed {
                stage: results::SpendFailureStage::Broadcast,
                reason: AUDIT_FAILURE_REASON.into(),
            },
            // An INTENDED coin, not an observed one: the node signed, so a coin id exists to check
            // even though nothing confirms it.
            Some(results::SpendChainReference {
                coin_id: CHILD_COINS[1].into(),
                confirmed: false,
            }),
        ),
        spend(
            "sp_signing",
            AUDIT_BASE_MS + 200,
            results::SpendOutcome::Failed {
                stage: results::SpendFailureStage::Signing,
                reason: AUDIT_FAILURE_REASON.into(),
            },
            None,
        ),
        spend(
            "sp_unresolved",
            AUDIT_BASE_MS + 100,
            results::SpendOutcome::Unresolved {
                reason: "the node restarted while the spend was in flight".into(),
            },
            Some(results::SpendChainReference {
                coin_id: CHILD_COINS[2].into(),
                confirmed: false,
            }),
        ),
    ]
}

/// Read the fixture the way a conforming node must: filter, then cursor, then page, then state
/// completeness from what was WITHHELD rather than from the page's length.
fn audit_page(params: &SpendsListParams) -> results::SpendsListResult {
    let mut rows = audit_fixture();
    if let Some(status) = params.status.as_deref() {
        rows.retain(|r| r.status.token() == status);
    }
    if let Some(kind) = params.kind.as_deref() {
        rows.retain(|r| r.kind == kind);
    }
    if let Some(since) = params.since_ms {
        rows.retain(|r| r.initiated_ms >= since);
    }
    if let Some(until) = params.until_ms {
        rows.retain(|r| r.initiated_ms < until);
    }
    if let Some(after) = params.after_id.as_deref() {
        match rows.iter().position(|r| r.id == after) {
            Some(i) => rows.drain(..=i).for_each(drop),
            None => rows.clear(),
        }
    }
    let limit = params.effective_limit() as usize;
    let complete = rows.len() <= limit;
    rows.truncate(limit);
    results::SpendsListResult {
        cursor: rows.last().map(|r| r.id.clone()),
        spends: rows,
        complete,
        unreadable_lines: AUDIT_UNREADABLE,
    }
}

/// **A broadcast failure and a signing failure MUST stay distinguishable on the wire.**
///
/// Both carry the token `failed`, so a client keying only on the token treats them identically —
/// and they mean opposite things about a person's money. The fixture varies exactly ONE field
/// between the two rows and keeps a confirmed spend beside them as an honest control, so the
/// nearest wrong implementation (flattening `Failed` to a bare token, which is the collapse dig-node
/// has had to undo twice) produces two rows that compare EQUAL here.
#[test]
fn a_broadcast_failure_is_not_the_same_answer_as_a_signing_failure() {
    let node = MockNode;
    let page = block_on(node.spends_list(SpendsListParams::default())).unwrap();

    let broadcast = page.spends.iter().find(|s| s.id == "sp_broadcast").unwrap();
    let signing = page.spends.iter().find(|s| s.id == "sp_signing").unwrap();
    let confirmed = page.spends.iter().find(|s| s.id == "sp_confirmed").unwrap();

    // The control: the read does distinguish outcomes at all.
    assert_eq!(confirmed.status.token(), "confirmed");

    // Same token — which is exactly why the token alone must never be the whole answer.
    assert_eq!(broadcast.status.token(), "failed");
    assert_eq!(signing.status.token(), "failed");

    // …and yet the two rows must not be equal, on the wire or in the type.
    assert_ne!(
        serde_json::to_value(&broadcast.status).unwrap(),
        serde_json::to_value(&signing.status).unwrap(),
        "a flattened `failed` makes these two identical, which is the money-lie this shape exists \
         to prevent"
    );

    // The load-bearing consequence: only the signing failure claims the money stayed put.
    assert!(broadcast.status.outcome_is_unknown());
    assert!(!signing.status.outcome_is_unknown());
    assert!(!confirmed.status.outcome_is_unknown());
}

/// **`unresolved` is a first-class state, never a flavour of `failed`.**
///
/// The `status: "failed"` filter is the placement-sensitive probe: an implementation that folds
/// unknown outcomes into the failure bucket — anywhere between the record and the wire — returns
/// three rows here instead of two, whichever layer it does it at.
#[test]
fn an_unresolved_spend_is_not_returned_as_a_failure() {
    let node = MockNode;
    let failed = block_on(node.spends_list(SpendsListParams {
        status: Some("failed".into()),
        ..SpendsListParams::default()
    }))
    .unwrap();
    let ids: Vec<&str> = failed.spends.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["sp_broadcast", "sp_signing"]);

    let unresolved = block_on(node.spends_list(SpendsListParams {
        status: Some("unresolved".into()),
        ..SpendsListParams::default()
    }))
    .unwrap();
    assert_eq!(unresolved.spends.len(), 1);
    assert!(unresolved.spends[0].status.outcome_is_unknown());
    assert!(matches!(
        unresolved.spends[0].status,
        results::SpendOutcome::Unresolved { .. }
    ));
}

/// **Truncation is STATED, never inferred from the page's length.**
///
/// Four rows paged two at a time: both pages carry exactly two rows, so `complete` is the only thing
/// that tells the middle of the walk from its end. A client inferring completeness from
/// `spends.len() < limit` stops after the first page and presents half the audit record as the whole
/// of it — "no more spends" and "we stopped telling you" rendered identically.
#[test]
fn a_truncated_spend_page_and_a_final_one_are_told_apart_only_by_complete() {
    let node = MockNode;

    let first = block_on(node.spends_list(SpendsListParams {
        limit: Some(2),
        ..SpendsListParams::default()
    }))
    .unwrap();
    assert_eq!(first.spends.len(), 2);
    assert!(
        !first.complete,
        "more rows were withheld, and it must say so"
    );
    assert_eq!(first.cursor.as_deref(), Some("sp_broadcast"));

    let second = block_on(node.spends_list(SpendsListParams {
        limit: Some(2),
        after_id: first.cursor.clone(),
        ..SpendsListParams::default()
    }))
    .unwrap();
    assert_eq!(second.spends.len(), first.spends.len());
    assert!(second.complete, "the walk is finished and must say so");
    assert_eq!(second.cursor.as_deref(), Some("sp_unresolved"));

    // The pages tile the record exactly: no row repeated, none skipped.
    let walked: Vec<&str> = first
        .spends
        .iter()
        .chain(second.spends.iter())
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(
        walked,
        vec![
            "sp_confirmed",
            "sp_broadcast",
            "sp_signing",
            "sp_unresolved"
        ]
    );
}

/// **Entries the node could not parse are part of the ANSWER.**
///
/// A trail that lost rows to corruption and reads as a tidy shorter one is the same lie as a missing
/// entry. The count rides on every page, including a page that was itself truncated, so a client can
/// never present a partial record as complete.
#[test]
fn unreadable_entries_are_reported_on_every_page() {
    let node = MockNode;
    let whole = block_on(node.spends_list(SpendsListParams::default())).unwrap();
    assert_eq!(whole.unreadable_lines, AUDIT_UNREADABLE);

    let page = block_on(node.spends_list(SpendsListParams {
        limit: Some(1),
        ..SpendsListParams::default()
    }))
    .unwrap();
    assert_eq!(page.unreadable_lines, AUDIT_UNREADABLE);
}

/// **An out-of-range page size is REFUSED, not clamped**, and the bound is pinned from BOTH sides.
///
/// At-bound must pass and one over must fail; a bound tested only from below confirms only itself.
/// Clamping would hand back a cursor for a position the caller never asked about, which is how a
/// paged walk loses rows.
#[test]
fn the_page_bound_is_refused_from_above_and_accepted_at_the_bound() {
    let at_bound = SpendsListParams {
        limit: Some(SPENDS_LIST_MAX_LIMIT),
        ..SpendsListParams::default()
    };
    assert!(at_bound.validated().is_ok(), "the cap itself must be legal");

    for bad in [0, SPENDS_LIST_MAX_LIMIT + 1] {
        let err = SpendsListParams {
            limit: Some(bad),
            ..SpendsListParams::default()
        }
        .validated()
        .expect_err("an out-of-range page size must be refused");
        assert_eq!(err.code_enum(), Some(ControlErrorCode::InvalidParams));
    }

    // And the refusal is enforced on the way IN, so a node cannot forget to validate.
    let over = serde_json::to_value(SPENDS_LIST_MAX_LIMIT + 1).unwrap();
    assert!(serde_json::from_value::<SpendsListParams>(json!({"limit": over})).is_err());
    assert!(serde_json::from_value::<SpendsListParams>(json!({"limit": 0})).is_err());
    // An omitted limit is not a refusal — it is the contract's own default.
    let defaulted: SpendsListParams = serde_json::from_value(json!({})).unwrap();
    assert_eq!(defaulted.effective_limit(), SPENDS_LIST_DEFAULT_LIMIT);
}

/// **`control.spends.list` is TOKEN-GATED and is not on the open surface.**
///
/// The caller names no identifier, so the answer is this node's OWN spending history — the same rule
/// that keeps `control.wallet.arrivals` gated. Asserted against the open-surface predicate rather
/// than by reading the summary, so widening the open set by analogy trips here.
#[test]
fn the_audit_read_is_gated_because_the_caller_names_nothing() {
    assert!(ControlMethod::SpendsList.requires_auth());
    assert!(!ControlMethod::SpendsList.is_open_read());
    assert!(!ControlMethod::SpendsList.requires_master_token());
    assert_eq!(ControlMethod::SpendsList.name(), "control.spends.list");
}

/// The golden wire vectors: the request envelope, and a response that decodes and re-encodes
/// byte-for-byte.
///
/// The result vector carries `cursor: null` on purpose — the key is REQUIRED even when empty, so a
/// truncated payload cannot decode into a confident "there was nothing to resume from".
#[test]
fn spends_list_wire_vectors_are_pinned() {
    assert_request(
        &SpendsListParams {
            status: Some("failed".into()),
            limit: Some(2),
            ..SpendsListParams::default()
        },
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "control.spends.list",
            "params": {"status": "failed", "limit": 2},
        }),
    );

    assert_result_round_trips::<results::SpendsListResult>(json!({
        "spends": [],
        "complete": true,
        "cursor": null,
        "unreadable_lines": 0,
    }));

    assert_result_round_trips::<results::SpendsListResult>(json!({
        "spends": [{
            "id": "sp_broadcast",
            "revision": 2,
            "kind": "mirror-coin",
            "purpose": "renew the mirror advertising this store",
            "authority": {"principal": "node", "grant": "auto_mirror_renewal"},
            "asset": {"asset": "xch"},
            "amount_mojos": "9007199254740993",
            "fee_mojos": "1000",
            "store_id": STORE,
            "initiated_ms": AUDIT_BASE_MS + 300,
            "updated_ms": AUDIT_BASE_MS + 310,
            "status": {"state": "failed", "stage": "broadcast", "reason": "mempool rejected the bundle"},
            "funding_coin_ids": [SPENT_COIN],
            "chain_reference": {"coin_id": CHILD_COINS[1], "confirmed": false},
        }],
        "complete": false,
        "cursor": "sp_broadcast",
        "unreadable_lines": 2,
    }));
}

/// **A missing `cursor` key must NOT decode as "nothing to resume from".**
///
/// `null` is meaningful here, so serde's default treatment of `Option` would let a truncated or
/// mis-routed payload decode into a confident end-of-walk. Same rule on a row's `chain_reference`,
/// where the absent key would read as "this spend has no coin to look up".
#[test]
fn an_absent_cursor_or_chain_reference_key_is_a_decode_error() {
    assert!(serde_json::from_value::<results::SpendsListResult>(json!({
        "spends": [],
        "complete": true,
        "unreadable_lines": 0,
    }))
    .is_err());

    assert!(serde_json::from_value::<results::AutomatedSpend>(json!({
        "id": "sp_signing",
        "revision": 1,
        "kind": "mirror-coin",
        "purpose": "p",
        "authority": {"principal": "node", "grant": "g"},
        "asset": {"asset": "dig"},
        "amount_mojos": "1",
        "fee_mojos": "0",
        "store_id": null,
        "initiated_ms": AUDIT_BASE_MS,
        "updated_ms": AUDIT_BASE_MS,
        "status": {"state": "failed", "stage": "signing", "reason": "insufficient funds"},
        "funding_coin_ids": [],
    }))
    .is_err());
}

/// **Every catalogued error code is declared as a ROW of an error-code TABLE, with its own symbol.**
///
/// `SPEC.md`'s error section is normative and states that a node or client MUST NOT mint a `-3204x`
/// code "that is not declared in the table above". That sentence makes TABLE MEMBERSHIP — not mere
/// presence in the file — the thing a reimplementer is entitled to rely on, and Markdown terminates
/// a table at the first blank line. A code whose row is separated from the table by one stray
/// newline therefore renders as an ordinary paragraph of pipe-delimited text, and the document then
/// forbids the very code this crate mints. That is exactly how `-32048` landed: the sibling guard
/// above covers method names and phase tokens, error codes had no equivalent, and 160 tests passed
/// over a split contract.
///
/// So this is a STRUCTURAL check, deliberately, on two axes a weaker one would miss:
///
/// * A `text.contains("-32048")` assertion passes against that exact defect — the number is in the
///   file, just not in a table. The row is therefore located inside a parsed table BLOCK (a run of
///   pipe lines carrying a `|---|` separator), never anywhere in the prose.
/// * A check on the number alone would accept a code mapped to the WRONG symbol. The row's first
///   TWO cells are pinned together, so a transposed or renamed symbol fails here.
///
/// `README.md` is held to a weaker bar ON PURPOSE: its table is an abbreviated agent-facing subset
/// that has never carried the `-3204x` band. Requiring exhaustiveness there would be a different
/// change. What IS required is that any code it does list is listed CORRECTLY — a wrong symbol in
/// the short table misleads exactly the reader it is written for.
#[test]
fn every_catalogued_error_code_is_a_row_of_an_error_code_table() {
    /// The maximal runs of consecutive pipe-prefixed lines that carry a `|---|` separator, i.e. the
    /// blocks Markdown actually renders as tables. A blank line ends a block, which is the whole
    /// point of parsing rather than scanning.
    fn table_rows(text: &str) -> Vec<&str> {
        fn flush<'a>(block: &mut Vec<&'a str>, rows: &mut Vec<&'a str>) {
            let is_table = block
                .iter()
                .any(|l| l.trim_start_matches('|').trim_start().starts_with("---"));
            if is_table {
                rows.extend(block.iter().copied());
            }
            block.clear();
        }

        let mut rows: Vec<&str> = Vec::new();
        let mut block: Vec<&str> = Vec::new();
        for line in text.lines() {
            if line.trim_start().starts_with('|') {
                block.push(line.trim());
            } else {
                flush(&mut block, &mut rows);
            }
        }
        flush(&mut block, &mut rows);
        rows
    }

    let spec_rows = table_rows(include_str!("../SPEC.md"));
    let readme_rows = table_rows(include_str!("../README.md"));

    for &code in ControlErrorCode::ALL {
        // The row as it must appear, both cells at once: the number cannot be declared beside some
        // other symbol, and the symbol cannot be declared beside some other number.
        let row = format!("| `{}` | `{}` |", code.code(), code.name());

        assert!(
            spec_rows.iter().any(|l| l.starts_with(&row)),
            "SPEC.md has no error-code TABLE ROW starting `{row}` -- either the code is undeclared, \
             it carries the wrong symbol, or a blank line has split its row out of the table (which \
             renders it as a paragraph, and SPEC.md's own MUST then forbids the code)"
        );

        // README lists a subset; whatever it lists must agree with the catalog.
        let number_cell = format!("| `{}` |", code.code());
        if let Some(listed) = readme_rows.iter().find(|l| l.starts_with(&number_cell)) {
            assert!(
                listed.starts_with(&row),
                "README.md declares `{}` with the wrong symbol: {listed}",
                code.code()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Collateral: the epoch requirement + the local safety margin (#32).
// ---------------------------------------------------------------------------------------------

/// **The three collateral methods carry their exact wire names, category, routing and auth tier.**
///
/// The names are pinned as LITERALS rather than derived from the enum, because every consumer that
/// must agree with them — `dign`, dig-app, the node dispatcher — spells them by hand somewhere.
///
/// The auth assertions are the load-bearing half. `control.collateral.requirement` is a READ of a
/// number every node derives identically, so the tempting judgement is to make it an OPEN read by
/// analogy with `control.wallet.peak`. It is NOT one, and the rule in
/// [`ControlMethod::is_open_read`] says why: its UNKNOWN branch discloses this node's own census
/// position, and the caller supplies no identifier. Asserting the gate here means a later widening
/// has to argue with a test rather than with a comment.
#[test]
fn the_collateral_methods_are_named_categorised_and_gated() {
    use crate::method::{Category, Routing};

    assert_eq!(
        ControlMethod::CollateralRequirement.name(),
        "control.collateral.requirement"
    );
    assert_eq!(
        ControlMethod::CollateralMarginGet.name(),
        "control.collateral.margin.get"
    );
    assert_eq!(
        ControlMethod::CollateralMarginSet.name(),
        "control.collateral.margin.set"
    );

    for m in [
        ControlMethod::CollateralRequirement,
        ControlMethod::CollateralMarginGet,
        ControlMethod::CollateralMarginSet,
    ] {
        assert_eq!(m.category(), Category::Collateral, "{}", m.name());
        assert_eq!(m.routing(), Routing::Owned, "{}", m.name());
        assert!(m.requires_auth(), "{} must be token-gated", m.name());
        assert!(!m.is_open_read(), "{} must not be an open read", m.name());
        assert!(
            !m.requires_master_token(),
            "{} grants no authority outliving its token, so it stays on the ordinary tier",
            m.name()
        );
        assert!(
            ControlMethod::ALL.contains(&m),
            "{} missing from ALL",
            m.name()
        );
    }
}

/// **The margin is BASIS POINTS on the wire, under the key `margin_bp`.**
///
/// The fixture is deliberately `1`, not `100`. `100` is +1% and survives a
/// basis-points-to-percent conversion as the plausible integer `1`, so a percent-converting
/// implementation could still round-trip a "reasonable-looking" value; `1` bp is
/// `SAFETY_MARGIN_BP_TIGHT` (0.01%) and any conversion to whole percent collapses it to `0` — the
/// exact silent no-margin the round-up in `apply_safety_margin` exists to prevent.
///
/// The KEY is pinned too. dig-app `SPEC.md` §3.7b fixes `collateral.margin_bp` and requires `dign`
/// to persist the same integer under the same key; a rename here is the drift that spec forbids.
#[test]
fn the_margin_is_basis_points_under_the_margin_bp_key() {
    let set = CollateralMarginSetParams { margin_bp: 1 };
    assert_eq!(
        serde_json::to_value(set).unwrap(),
        json!({ "margin_bp": 1 }),
        "a tight 1bp margin must stay 1 bp; converting to percent would render it as 0"
    );

    let read: results::CollateralMarginResult =
        serde_json::from_value(json!({ "margin_bp": 1 })).unwrap();
    assert_eq!(read.margin_bp, 1);

    // The default the contract publishes is the crate's own +1%, expressed in the same unit.
    assert_eq!(DEFAULT_SAFETY_MARGIN_BP, 100);
}

/// **The margin ceiling is pinned from BOTH sides.**
///
/// A bound tested only from below can only confirm itself: an implementation with no bound at all
/// passes an "at the ceiling is accepted" assertion. So the at-bound value MUST be accepted and the
/// one-over value MUST be refused, and the refusal must carry `-32602 INVALID_PARAMS` rather than
/// any code that would invite a retry.
#[test]
fn the_margin_ceiling_is_pinned_from_both_sides() {
    let at_bound = CollateralMarginSetParams {
        margin_bp: MAX_SAFETY_MARGIN_BP,
    };
    assert!(
        at_bound.validated().is_ok(),
        "the ceiling itself must be a legal margin"
    );

    let over = CollateralMarginSetParams {
        margin_bp: MAX_SAFETY_MARGIN_BP + 1,
    };
    let err = over
        .validated()
        .expect_err("one over the ceiling must be refused");
    assert_eq!(err.code, ControlErrorCode::InvalidParams.code());
}

/// **An unknown requirement can never be read as a zero cost.**
///
/// This is the guard dig-app `SPEC.md` §3.7b demands ("there MUST be no path that renders an absent
/// requirement as a zero cost"), enforced on the CONTRACT rather than on one client.
///
/// The fixture is a full `unknown` envelope, and the assertion is that it does not deserialize into
/// anything carrying a number. The nearest wrong shape is `required_per_store_dig_base_units:
/// Option<u64>` beside a `known: bool` — which happily accepts an unknown response and yields
/// `unwrap_or(0)` at the first careless call site. A tagged enum makes that state unrepresentable,
/// and the reason cannot be dropped: each unknown names WHICH fact is missing.
#[test]
fn an_unknown_requirement_carries_a_reason_and_no_number() {
    let unknown: results::CollateralRequirementResult = serde_json::from_value(json!({
        "state": "unknown",
        "reason": "not_censused",
    }))
    .unwrap();

    match unknown {
        results::CollateralRequirementResult::Unknown { reason } => {
            assert_eq!(reason, results::CollateralUnknownReason::NotCensused);
        }
        results::CollateralRequirementResult::Known { .. } => {
            panic!("an unknown requirement decoded as a known figure")
        }
    }

    // Every reason is a distinct wire token, so a client can tell "this node has not censused the
    // epoch" from "this node is inside the finality depth" -- different remedies, different waits.
    let tokens: std::collections::BTreeSet<&str> = results::CollateralUnknownReason::ALL
        .iter()
        .map(|r| r.as_wire())
        .collect();
    assert_eq!(tokens.len(), results::CollateralUnknownReason::ALL.len());
}

/// **A known requirement cannot omit the protocol version that produced it.**
///
/// The collateral model is versioned and upgradable, and the version that computed an epoch travels
/// with its record. A client shown a requirement without knowing the ruleset behind it cannot
/// detect that it and the node disagree — it can only render a number confidently and be wrong.
///
/// So the assertion is a REFUSAL: the same fixture minus `protocol_version` must fail to decode. An
/// `Option<u16>` or a `#[serde(default)]` would pass a "the field is present" test on the complete
/// fixture while silently accepting the incomplete one.
#[test]
fn a_known_requirement_must_declare_its_protocol_version() {
    let complete = json!({
        "state": "known",
        "epoch": 7,
        "protocol_version": 1,
        "required_per_store_dig_base_units": 1_036,
        "stores": 4_200,
        "owners": 310,
        "multiplier_micros": 1_050_000,
        "handicap_dig_base_units": 2_760,
    });
    let known: results::CollateralRequirementResult =
        serde_json::from_value(complete.clone()).unwrap();
    match known {
        results::CollateralRequirementResult::Known {
            epoch,
            protocol_version,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            handicap_dig_base_units,
        } => {
            // Every field carries a DIFFERENT value, so a transposition of any pair fails here
            // rather than passing on a shape they share.
            assert_eq!(epoch, 7);
            assert_eq!(protocol_version, 1);
            assert_eq!(required_per_store_dig_base_units, 1_036);
            assert_eq!(stores, 4_200);
            assert_eq!(owners, 310);
            assert_eq!(multiplier_micros, 1_050_000);
            assert_eq!(handicap_dig_base_units, 2_760);
        }
        results::CollateralRequirementResult::Unknown { .. } => panic!("known decoded as unknown"),
    }

    let mut missing = complete.as_object().unwrap().clone();
    missing.remove("protocol_version");
    assert!(
        serde_json::from_value::<results::CollateralRequirementResult>(Value::Object(missing))
            .is_err(),
        "a requirement without its protocol version must be REFUSED, not defaulted"
    );
}

/// **`.set` stores what it was given, and `.get` reads back the SAME number.**
///
/// `SPEC.md` §4.2e states as a MUST that `control.collateral.margin.set` returns the margin actually
/// in force and that, for an accepted request, it equals the requested one. That MUST is exactly the
/// one a clamping implementation breaks silently, so it is asserted here rather than left as prose.
///
/// The route is deliberately `.set` through the DISPATCHER and then `.get` through the dispatcher —
/// two separate calls — because a single call asserting `result.margin_bp == params.margin_bp` is
/// satisfied by a handler that echoes its input and stores nothing. Reading it back through the
/// other method is what distinguishes persistence from an echo.
///
/// The value is `1` bp rather than a preset: a preset is a value an implementation might special-case
/// or round to, and 1 bp is the smallest legal margin, so it also fails against anything that
/// quantises to whole percent.
#[test]
fn setting_the_margin_persists_it_and_getting_it_back_agrees() {
    let set = round_trip(&CollateralMarginSetParams { margin_bp: 1 })
        .expect("setting a legal margin must succeed");
    assert_eq!(set.margin_bp, 1);

    let got =
        round_trip(&CollateralMarginGetParams {}).expect("reading the margin back must succeed");
    assert_eq!(
        got.margin_bp, 1,
        "the margin read back must be the one set, not the default and not an echo"
    );
}

/// **The margin bound published in `SPEC.md` is the bound the code enforces.**
///
/// `SPEC.md` §4.2e names the ceiling as a NUMBER in normative prose, and a reimplementer is entitled
/// to build against that number. Prose has no compiler, so changing
/// [`MAX_SAFETY_MARGIN_BP`] without changing the sentence would ship a document that is false about
/// the code in the same repository — the failure mode the sibling method-name and error-code guards
/// exist to prevent, applied to the one figure here that is a money-path bound.
///
/// The same check covers the default, for the same reason: `SPEC.md` promises `100`, and a node that
/// reported `0` for a config predating the field would be telling an operator they declined a
/// cushion they never declined.
///
/// The figure is READ OUT of the sentence that names the constant — `` `NAME` (N bp`` — and compared
/// as a number, rather than asking whether the constant's digits occur somewhere in the document. A
/// substring probe over a 900-line file cannot distinguish a MISSING row from a WRONG one: `"10"`
/// occurs inside the `"100"` that is already there, so a default silently retuned to `10` reads as
/// published, and a §4.2e rewritten to teach `250 bp` reads as agreeing while being normatively false
/// about a money-path default. EVERY occurrence is checked, not the first, so a second sentence
/// naming a different figure is a failure rather than a shadowed one.
#[test]
fn the_published_margin_bounds_match_the_declared_constants() {
    let spec = include_str!("../SPEC.md");
    for (label, name, value) in [
        ("ceiling", "MAX_SAFETY_MARGIN_BP", MAX_SAFETY_MARGIN_BP),
        (
            "default",
            "DEFAULT_SAFETY_MARGIN_BP",
            DEFAULT_SAFETY_MARGIN_BP,
        ),
    ] {
        let published = published_bp_figures(spec, name);
        assert!(
            !published.is_empty(),
            "SPEC.md never states the margin {label} as `{name}` (<n> bp, …), so its normative prose \
             and the constant can drift apart unnoticed"
        );
        for figure in published {
            assert_eq!(
                figure, value,
                "SPEC.md publishes the margin {label} as {figure} bp while `{name}` is {value}; a \
                 reimplementer building against the document would enforce a different money-path \
                 bound than this crate does"
            );
        }
    }
}

/// Every basis-point figure `SPEC.md` attaches to `name`, read from the `` `NAME` (N bp`` shape §4.2e
/// uses to publish a constant.
///
/// Returns each occurrence rather than the first: a document that names a constant twice with two
/// different numbers is exactly as false as one that names it once with the wrong number, and taking
/// only the first would hide the second.
fn published_bp_figures(spec: &str, name: &str) -> Vec<u64> {
    spec.match_indices(name)
        .filter_map(|(at, _)| {
            let tail = spec[at + name.len()..].trim_start_matches(['`', ' ']);
            let digits = tail.strip_prefix('(')?;
            let end = digits.find(|c: char| !c.is_ascii_digit())?;
            if !digits[end..].starts_with(" bp") {
                return None;
            }
            digits[..end].parse().ok()
        })
        .collect()
}
