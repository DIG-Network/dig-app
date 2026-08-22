//! The engine-proxy seam: forward an engine-routed command over the identity-authenticated session.
//!
//! Engine-routed commands ([`Route::Engine`](super::Route::Engine)) are identity-agnostic node
//! work. The gateway does NOT implement them; it maps each to the engine's canonical `control.*`
//! JSON-RPC method + params ([`engine_call`]) and forwards it over an [`EngineProxy`]. The proxy is
//! the session client owned by the IPC layer (APP-1); the gateway depends only on this trait, so
//! the routing + mapping are unit-tested against a test double and the real session is wired in the
//! binary.
//!
//! # The mapping is TYPED, not hand-written
//!
//! Every arm below builds its call from a params struct in the published
//! [`dig_node_control_interface`] contract crate, via [`EngineCall::typed`]. The method name comes
//! from that struct's bound `ControlMethod` and the params object from the crate's own serializer —
//! so a rename or a field change IN THE CONTRACT is a compile error here rather than a silent
//! divergence between this transport and the tray shell's typed one ([`crate::control`]). The
//! hand-rolled method strings this module used to carry were a second copy of a published contract,
//! and a second copy is a future drift (dig-app#226).
//!
//! Exactly two calls remain untyped, via [`EngineCall::uncatalogued`]: `control.peers.setBan` and
//! `control.peers.setPoolConfig` are served by dig-node but not yet promoted into the shared
//! catalog. They are named as the gap they are, and pinned by the tests below.

use serde_json::{json, Value};

use dig_node_control_interface::envelope::RequestId;
use dig_node_control_interface::params;
use dig_node_control_interface::traits::{build_request, ControlCall};

use super::command::{
    CacheAction, Command, ConfigAction, PairAction, PeersAction, StoresAction, SubscriptionsAction,
    SyncAction,
};
use super::outcome::GatewayError;

/// A resolved engine JSON-RPC call: the `control.*` method and its params object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineCall {
    /// The canonical `control.*` method name (byte-matches the engine's control surface).
    pub method: &'static str,
    /// The JSON-RPC params (an empty object for the read / no-arg methods).
    pub params: Value,
}

impl EngineCall {
    /// The call for a TYPED contract params struct: its bound method name and its own serialization.
    ///
    /// This is the ordinary constructor. Nothing about the wire shape is restated here — the method
    /// comes from [`ControlCall::METHOD`] and the params from the contract crate's own
    /// [`build_request`], which is the same encoder the tray-shell transport uses. So the two
    /// transports cannot disagree about what a control call looks like.
    fn typed<C: ControlCall>(call: &C) -> Self {
        EngineCall {
            method: C::METHOD.name(),
            // The id is irrelevant to the mapping — the proxy stamps the real one — so the envelope
            // is built only to reuse the crate's params encoding rather than re-deriving it.
            params: build_request(RequestId::Null, call).params,
        }
    }

    /// The call for a method dig-node serves but the shared catalog does not yet declare.
    ///
    /// Kept separate from [`typed`](Self::typed) so the untyped set is visible at every call site
    /// and cannot quietly grow: `every_gateway_method_is_in_the_shared_catalog_or_a_known_gap`
    /// pins it to exactly the two methods below.
    fn uncatalogued(method: &'static str, params: Value) -> Self {
        EngineCall { method, params }
    }
}

/// `control.peers.setBan` — served by dig-node, absent from the shared catalog.
const METHOD_PEERS_SET_BAN: &str = "control.peers.setBan";

/// `control.peers.setPoolConfig` — served by dig-node, absent from the shared catalog.
const METHOD_PEERS_SET_POOL_CONFIG: &str = "control.peers.setPoolConfig";

/// The session client that forwards a `control.*` call to the engine and returns its result.
///
/// Implemented by the IPC session layer (APP-1) over the identity-authenticated per-user channel.
/// The gateway consumes ONLY this trait so the proxy transport is swappable and the routing is
/// testable without a live engine.
pub trait EngineProxy {
    /// Forward `method` with `params` to the engine and return the `control.*` result object, or a
    /// [`GatewayError`] (typically `NOT_CONNECTED` when no session is attached, or `ENGINE_ERROR`
    /// when the engine rejects the call).
    fn call(&self, method: &str, params: Value) -> Result<Value, GatewayError>;
}

/// Map an engine-routed [`Command`] to its canonical `control.*` [`EngineCall`].
///
/// Returns `None` for commands that are NOT a direct control-method proxy — the local commands
/// (which never reach the engine) and [`Command::Open`], whose engine interaction the gateway
/// composes itself (it resolves the serve endpoint via `control.status`). Every arm that DOES map
/// is faithful to the engine's control surface field-for-field, because the contract crate is what
/// builds it.
pub fn engine_call(command: &Command) -> Option<EngineCall> {
    let call = match command {
        Command::Info => EngineCall::typed(&params::StatusParams {}),

        Command::Config(ConfigAction::Get) => EngineCall::typed(&params::ConfigGetParams {}),
        Command::Config(ConfigAction::SetUpstream { url }) => {
            EngineCall::typed(&params::SetUpstreamParams {
                upstream: url.clone(),
            })
        }

        Command::Cache(CacheAction::Get) => EngineCall::typed(&params::CacheGetParams {}),
        Command::Cache(CacheAction::SetCap { bytes }) => {
            EngineCall::typed(&params::SetCapParams { cap_bytes: *bytes })
        }
        Command::Cache(CacheAction::Clear) => EngineCall::typed(&params::CacheClearParams {}),

        Command::Stores(StoresAction::List) => {
            EngineCall::typed(&params::HostedStoresListParams {})
        }
        Command::Stores(StoresAction::Pin { store }) => EngineCall::typed(&params::PinParams {
            store: store.clone(),
        }),
        Command::Stores(StoresAction::Unpin { store }) => EngineCall::typed(&params::UnpinParams {
            store: store.clone(),
        }),
        Command::Stores(StoresAction::Status { store }) => {
            EngineCall::typed(&params::HostedStoreStatusParams {
                store: store.clone(),
            })
        }

        Command::Sync(SyncAction::Status) => EngineCall::typed(&params::SyncStatusParams {}),
        Command::Sync(SyncAction::Trigger { store }) => {
            EngineCall::typed(&params::SyncTriggerParams {
                store: store.clone(),
            })
        }

        Command::Subscriptions(SubscriptionsAction::List) => {
            EngineCall::typed(&params::ListSubscriptionsParams {})
        }
        Command::Subscriptions(SubscriptionsAction::Add { store_id }) => {
            EngineCall::typed(&params::SubscribeParams {
                store_id: store_id.clone(),
                // The subscription this command builds follows ordinary store content, which is the
                // meaning every untagged subscription already carried before the contract named it.
                kind: params::SubscriptionKind::Capsule,
            })
        }
        Command::Subscriptions(SubscriptionsAction::Remove { store_id }) => {
            EngineCall::typed(&params::UnsubscribeParams {
                store_id: store_id.clone(),
            })
        }

        Command::Peers(PeersAction::List) => EngineCall::typed(&params::PeerStatusParams {}),
        Command::Peers(PeersAction::Connect { peer }) => {
            EngineCall::typed(&params::PeersConnectParams { peer: peer.clone() })
        }
        Command::Peers(PeersAction::Disconnect { peer }) => {
            EngineCall::typed(&params::PeersDisconnectParams { peer: peer.clone() })
        }
        Command::Peers(PeersAction::Ban { peer, state }) => EngineCall::uncatalogued(
            METHOD_PEERS_SET_BAN,
            json!({ "peer": peer, "state": state }),
        ),
        Command::Peers(PeersAction::PoolConfig { max_connections }) => EngineCall::uncatalogued(
            METHOD_PEERS_SET_POOL_CONFIG,
            json!({ "max_connections": max_connections }),
        ),

        Command::Pair(PairAction::List) => EngineCall::typed(&params::PairingListParams {}),
        Command::Pair(PairAction::Approve { pairing_id }) => {
            EngineCall::typed(&params::ApproveParams {
                pairing_id: pairing_id.clone(),
            })
        }
        Command::Pair(PairAction::Revoke { token_id }) => EngineCall::typed(&params::RevokeParams {
            token_id: token_id.clone(),
        }),

        // Local commands never reach the engine; `open` is composed by the gateway, not a direct
        // control-method proxy.
        Command::Open { .. } | Command::Profiles(_) | Command::Wallet(_) | Command::Sign { .. } => {
            return None
        }
    };
    Some(call)
}

/// Every engine-routed command, with a representative argument for the arg-bearing ones.
///
/// Visible to the crate because it is the ONE list of what the gateway will ever ask the engine
/// for, and [`proxyable_methods`] is derived from it rather than written a second time.
pub(crate) fn all_engine_routed_commands() -> Vec<Command> {
    vec![
        Command::Info,
        Command::Config(ConfigAction::Get),
        Command::Config(ConfigAction::SetUpstream {
            url: "https://up.example".into(),
        }),
        Command::Cache(CacheAction::Get),
        Command::Cache(CacheAction::SetCap {
            bytes: 2 * 1024 * 1024 * 1024,
        }),
        Command::Cache(CacheAction::Clear),
        Command::Stores(StoresAction::List),
        Command::Stores(StoresAction::Pin { store: "s".into() }),
        Command::Stores(StoresAction::Unpin { store: "s".into() }),
        Command::Stores(StoresAction::Status { store: "s".into() }),
        Command::Sync(SyncAction::Status),
        Command::Sync(SyncAction::Trigger { store: "s".into() }),
        Command::Subscriptions(SubscriptionsAction::List),
        Command::Subscriptions(SubscriptionsAction::Add {
            store_id: "s".into(),
        }),
        Command::Subscriptions(SubscriptionsAction::Remove {
            store_id: "s".into(),
        }),
        Command::Peers(PeersAction::List),
        Command::Peers(PeersAction::Connect { peer: "p".into() }),
        Command::Peers(PeersAction::Disconnect { peer: "p".into() }),
        Command::Peers(PeersAction::Ban {
            peer: "p".into(),
            state: "ban".into(),
        }),
        Command::Peers(PeersAction::PoolConfig { max_connections: 8 }),
        Command::Pair(PairAction::List),
        Command::Pair(PairAction::Approve {
            pairing_id: "pid".into(),
        }),
        Command::Pair(PairAction::Revoke {
            token_id: "tid".into(),
        }),
    ]
}

/// Every `control.*` method the gateway can ever emit, derived from [`all_engine_routed_commands`].
///
/// This is the proxy's allow-list source ([`crate::cli_session`]): a method absent from here is one
/// no `dign` command produces, so forwarding it would let the CLI reach a node surface the gateway
/// never routed to — the back-door shape dig_ecosystem#908 exists to make impossible.
pub(crate) fn proxyable_methods() -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = all_engine_routed_commands()
        .iter()
        .filter_map(|command| engine_call(command).map(|call| call.method))
        .collect();
    methods.sort_unstable();
    methods.dedup();
    methods
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_maps_to_control_status_with_empty_params() {
        let call = engine_call(&Command::Info).expect("info proxies");
        assert_eq!(call.method, "control.status");
        assert_eq!(call.params, json!({}));
    }

    #[test]
    fn arg_bearing_commands_carry_the_engine_field_names() {
        let cap = engine_call(&Command::Cache(CacheAction::SetCap { bytes: 4096 })).unwrap();
        assert_eq!(cap.method, "control.cache.setCap");
        assert_eq!(cap.params, json!({ "cap_bytes": 4096 }));

        let sub = engine_call(&Command::Subscriptions(SubscriptionsAction::Add {
            store_id: "abc".into(),
        }))
        .unwrap();
        assert_eq!(sub.method, "control.subscribe");
        assert_eq!(sub.params, json!({ "store_id": "abc", "kind": "capsule" }));

        let ban = engine_call(&Command::Peers(PeersAction::Ban {
            peer: "p1".into(),
            state: "ban".into(),
        }))
        .unwrap();
        assert_eq!(ban.method, "control.peers.setBan");
        assert_eq!(ban.params, json!({ "peer": "p1", "state": "ban" }));
    }

    #[test]
    fn pool_config_forwards_the_numeric_cap() {
        let call = engine_call(&Command::Peers(PeersAction::PoolConfig {
            max_connections: 32,
        }))
        .unwrap();
        assert_eq!(call.method, "control.peers.setPoolConfig");
        assert_eq!(call.params, json!({ "max_connections": 32 }));
    }

    #[test]
    fn open_and_local_commands_have_no_direct_control_mapping() {
        assert!(engine_call(&Command::Open {
            link: "chia://x".into()
        })
        .is_none());
        assert!(engine_call(&Command::Sign {
            message: "m".into()
        })
        .is_none());
    }

    /// The full engine-proxy contract: every engine-routed command maps to its exact canonical
    /// `control.*` method + params. This table is the cross-repo guard — a drift from the engine's
    /// control surface fails here.
    #[test]
    fn every_engine_command_maps_to_its_canonical_control_call() {
        let cases: Vec<(Command, &str, Value)> = vec![
            (Command::Info, "control.status", json!({})),
            (
                Command::Config(ConfigAction::Get),
                "control.config.get",
                json!({}),
            ),
            (
                Command::Config(ConfigAction::SetUpstream { url: "u".into() }),
                "control.config.setUpstream",
                json!({ "upstream": "u" }),
            ),
            (
                Command::Cache(CacheAction::Get),
                "control.cache.get",
                json!({}),
            ),
            (
                Command::Cache(CacheAction::Clear),
                "control.cache.clear",
                json!({}),
            ),
            (
                Command::Stores(StoresAction::List),
                "control.hostedStores.list",
                json!({}),
            ),
            (
                Command::Stores(StoresAction::Pin { store: "s".into() }),
                "control.hostedStores.pin",
                json!({ "store": "s" }),
            ),
            (
                Command::Stores(StoresAction::Unpin { store: "s".into() }),
                "control.hostedStores.unpin",
                json!({ "store": "s" }),
            ),
            (
                Command::Stores(StoresAction::Status { store: "s".into() }),
                "control.hostedStores.status",
                json!({ "store": "s" }),
            ),
            (
                Command::Sync(SyncAction::Status),
                "control.sync.status",
                json!({}),
            ),
            (
                Command::Sync(SyncAction::Trigger { store: "s".into() }),
                "control.sync.trigger",
                json!({ "store": "s" }),
            ),
            (
                Command::Subscriptions(SubscriptionsAction::List),
                "control.listSubscriptions",
                json!({}),
            ),
            (
                Command::Subscriptions(SubscriptionsAction::Remove {
                    store_id: "s".into(),
                }),
                "control.unsubscribe",
                json!({ "store_id": "s" }),
            ),
            (
                Command::Peers(PeersAction::List),
                "control.peerStatus",
                json!({}),
            ),
            (
                Command::Peers(PeersAction::Connect { peer: "p".into() }),
                "control.peers.connect",
                json!({ "peer": "p" }),
            ),
            (
                Command::Peers(PeersAction::Disconnect { peer: "p".into() }),
                "control.peers.disconnect",
                json!({ "peer": "p" }),
            ),
            (
                Command::Pair(PairAction::List),
                "control.pairing.list",
                json!({}),
            ),
            (
                Command::Pair(PairAction::Approve {
                    pairing_id: "p".into(),
                }),
                "control.pairing.approve",
                json!({ "pairing_id": "p" }),
            ),
            (
                Command::Pair(PairAction::Revoke {
                    token_id: "t".into(),
                }),
                "control.pairing.revoke",
                json!({ "token_id": "t" }),
            ),
        ];
        for (command, method, params) in cases {
            let call = engine_call(&command).unwrap_or_else(|| panic!("{command:?} must map"));
            assert_eq!(call.method, method, "method for {command:?}");
            assert_eq!(call.params, params, "params for {command:?}");
        }
    }

    /// #2019 — transport conformance, leg 1. Every method the `dign` GATEWAY transport emits must be a
    /// method in the SHARED `dig-node-control-interface` catalog ([`ControlMethod`]) — the same catalog
    /// the TRAY-SHELL transport (`control.rs`, via typed [`ControlCall`]s) is bound to at compile time.
    /// This is the drift the literal `every_engine_command_maps_*` test above cannot see: that test
    /// pins the gateway to hand-written strings, so a rename IN THE CONTRACT CRATE leaves it green while
    /// the two transports silently diverge. Anchoring to the catalog closes that gap.
    ///
    /// The two exceptions are pinned EXACTLY: `control.peers.setBan` / `control.peers.setPoolConfig`
    /// are served by dig-node's own `CONTROL_METHODS` list but not yet promoted into the shared
    /// `ControlMethod` enum (a tracked node-side gap). Pinning the set means a NEW gateway method absent
    /// from the catalog fails here until it is catalogued or consciously added to `KNOWN_GATEWAY_ONLY`.
    #[test]
    fn every_gateway_method_is_in_the_shared_catalog_or_a_known_gap() {
        use dig_node_control_interface::method::ControlMethod;

        const KNOWN_GATEWAY_ONLY: &[&str] =
            &["control.peers.setBan", "control.peers.setPoolConfig"];

        let mut gateway_only = Vec::new();
        for command in all_engine_routed_commands() {
            let call = engine_call(&command)
                .unwrap_or_else(|| panic!("{command:?} is engine-routed and must map to a call"));
            match ControlMethod::from_name(call.method) {
                Some(method) => assert_eq!(
                    method.name(),
                    call.method,
                    "gateway method {:?} must round-trip through the shared catalog",
                    call.method
                ),
                None => gateway_only.push(call.method),
            }
        }
        gateway_only.sort_unstable();
        let mut known = KNOWN_GATEWAY_ONLY.to_vec();
        known.sort_unstable();
        assert_eq!(
            gateway_only, known,
            "a gateway method is absent from the shared control catalog — catalogue it in \
             dig-node-control-interface, or (if it is a deliberate node-only method) add it to \
             KNOWN_GATEWAY_ONLY"
        );
    }

    /// #2019 — transport conformance, leg 2. For every shared method that carries a typed params struct
    /// in the contract crate, the GATEWAY transport's hand-encoded params must be BYTE-IDENTICAL to the
    /// crate's typed serialization, and its method string identical to the type's bound
    /// [`ControlMethod`]. So a field rename on e.g. `SetCapParams::cap_bytes` — which the tray-shell
    /// transport follows automatically, being typed — fails here until the gateway literal follows too.
    /// That is precisely the drift #2002's cache-cap control could suffer between the two transports.
    ///
    /// The expected values are built FROM the contract crate (never a second copy of the literals), so
    /// the crate is the single anchor both transports are checked against.
    #[test]
    fn gateway_params_byte_match_the_typed_contract_params() {
        use dig_node_control_interface::params;
        use dig_node_control_interface::traits::ControlCall;

        let cap = 2u64 * 1024 * 1024 * 1024;
        let cases: Vec<(Command, Value, &'static str)> = vec![
            (
                Command::Cache(CacheAction::SetCap { bytes: cap }),
                serde_json::to_value(params::SetCapParams { cap_bytes: cap }).unwrap(),
                <params::SetCapParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Config(ConfigAction::SetUpstream {
                    url: "https://up.example".into(),
                }),
                serde_json::to_value(params::SetUpstreamParams {
                    upstream: "https://up.example".into(),
                })
                .unwrap(),
                <params::SetUpstreamParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Subscriptions(SubscriptionsAction::Add {
                    store_id: "sid".into(),
                }),
                serde_json::to_value(params::SubscribeParams {
                    store_id: "sid".into(),
                    // The subscription this command builds follows ordinary store content, which is
                    // the meaning every untagged subscription already carried before the contract
                    // named it (dig-node-control-interface 0.16).
                    kind: params::SubscriptionKind::Capsule,
                })
                .unwrap(),
                <params::SubscribeParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Subscriptions(SubscriptionsAction::Remove {
                    store_id: "sid".into(),
                }),
                serde_json::to_value(params::UnsubscribeParams {
                    store_id: "sid".into(),
                })
                .unwrap(),
                <params::UnsubscribeParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Peers(PeersAction::Connect { peer: "p".into() }),
                serde_json::to_value(params::PeersConnectParams { peer: "p".into() }).unwrap(),
                <params::PeersConnectParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Peers(PeersAction::Disconnect { peer: "p".into() }),
                serde_json::to_value(params::PeersDisconnectParams { peer: "p".into() }).unwrap(),
                <params::PeersDisconnectParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Stores(StoresAction::Pin { store: "s".into() }),
                serde_json::to_value(params::PinParams { store: "s".into() }).unwrap(),
                <params::PinParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Stores(StoresAction::Unpin { store: "s".into() }),
                serde_json::to_value(params::UnpinParams { store: "s".into() }).unwrap(),
                <params::UnpinParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Stores(StoresAction::Status { store: "s".into() }),
                serde_json::to_value(params::HostedStoreStatusParams { store: "s".into() })
                    .unwrap(),
                <params::HostedStoreStatusParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Sync(SyncAction::Trigger { store: "s".into() }),
                serde_json::to_value(params::SyncTriggerParams { store: "s".into() }).unwrap(),
                <params::SyncTriggerParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Pair(PairAction::Approve {
                    pairing_id: "pid".into(),
                }),
                serde_json::to_value(params::ApproveParams {
                    pairing_id: "pid".into(),
                })
                .unwrap(),
                <params::ApproveParams as ControlCall>::METHOD.name(),
            ),
            (
                Command::Pair(PairAction::Revoke {
                    token_id: "tid".into(),
                }),
                serde_json::to_value(params::RevokeParams {
                    token_id: "tid".into(),
                })
                .unwrap(),
                <params::RevokeParams as ControlCall>::METHOD.name(),
            ),
        ];

        for (command, expected_params, method_name) in cases {
            let call = engine_call(&command)
                .unwrap_or_else(|| panic!("{command:?} must map to a control call"));
            assert_eq!(
                call.method, method_name,
                "gateway method for {command:?} must equal the typed twin's ControlMethod name"
            );
            assert_eq!(
                call.params, expected_params,
                "gateway params for {command:?} must byte-match the typed contract serialization"
            );
        }
    }
}
