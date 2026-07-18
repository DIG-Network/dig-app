//! The engine-proxy seam: forward an engine-routed command over the identity-authenticated session.
//!
//! Engine-routed commands ([`Route::Engine`]) are identity-agnostic node work. The gateway does NOT
//! implement them; it maps each to the engine's canonical `control.*` JSON-RPC method + params
//! ([`engine_call`]) and forwards it over an [`EngineProxy`]. The proxy is the session client owned
//! by the IPC layer (APP-1); the gateway depends only on this trait, so the routing + mapping are
//! unit-tested against a test double and the real session is wired in the binary.
//!
//! The method names + param field names here are a CROSS-REPO CONTRACT: they MUST byte-match the
//! engine's control surface (the `dig-node` `control.*` dispatch). Changing one without the other
//! breaks the proxy.

use serde_json::{json, Value};

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
    fn new(method: &'static str, params: Value) -> Self {
        EngineCall { method, params }
    }
}

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
/// is faithful to the engine's control surface, field-for-field.
pub fn engine_call(command: &Command) -> Option<EngineCall> {
    let call = match command {
        Command::Info => EngineCall::new("control.status", json!({})),

        Command::Config(ConfigAction::Get) => EngineCall::new("control.config.get", json!({})),
        Command::Config(ConfigAction::SetUpstream { url }) => {
            EngineCall::new("control.config.setUpstream", json!({ "upstream": url }))
        }

        Command::Cache(CacheAction::Get) => EngineCall::new("control.cache.get", json!({})),
        Command::Cache(CacheAction::SetCap { bytes }) => {
            EngineCall::new("control.cache.setCap", json!({ "cap_bytes": bytes }))
        }
        Command::Cache(CacheAction::Clear) => EngineCall::new("control.cache.clear", json!({})),

        Command::Stores(StoresAction::List) => {
            EngineCall::new("control.hostedStores.list", json!({}))
        }
        Command::Stores(StoresAction::Pin { store }) => {
            EngineCall::new("control.hostedStores.pin", json!({ "store": store }))
        }
        Command::Stores(StoresAction::Unpin { store }) => {
            EngineCall::new("control.hostedStores.unpin", json!({ "store": store }))
        }
        Command::Stores(StoresAction::Status { store }) => {
            EngineCall::new("control.hostedStores.status", json!({ "store": store }))
        }

        Command::Sync(SyncAction::Status) => EngineCall::new("control.sync.status", json!({})),
        Command::Sync(SyncAction::Trigger { store }) => {
            EngineCall::new("control.sync.trigger", json!({ "store": store }))
        }

        Command::Subscriptions(SubscriptionsAction::List) => {
            EngineCall::new("control.listSubscriptions", json!({}))
        }
        Command::Subscriptions(SubscriptionsAction::Add { store_id }) => {
            EngineCall::new("control.subscribe", json!({ "store_id": store_id }))
        }
        Command::Subscriptions(SubscriptionsAction::Remove { store_id }) => {
            EngineCall::new("control.unsubscribe", json!({ "store_id": store_id }))
        }

        Command::Peers(PeersAction::List) => EngineCall::new("control.peerStatus", json!({})),
        Command::Peers(PeersAction::Connect { peer }) => {
            EngineCall::new("control.peers.connect", json!({ "peer": peer }))
        }
        Command::Peers(PeersAction::Disconnect { peer }) => {
            EngineCall::new("control.peers.disconnect", json!({ "peer": peer }))
        }
        Command::Peers(PeersAction::Ban { peer, state }) => EngineCall::new(
            "control.peers.setBan",
            json!({ "peer": peer, "state": state }),
        ),
        Command::Peers(PeersAction::PoolConfig { max_connections }) => EngineCall::new(
            "control.peers.setPoolConfig",
            json!({ "max_connections": max_connections }),
        ),

        Command::Pair(PairAction::List) => EngineCall::new("control.pairing.list", json!({})),
        Command::Pair(PairAction::Approve { pairing_id }) => EngineCall::new(
            "control.pairing.approve",
            json!({ "pairing_id": pairing_id }),
        ),
        Command::Pair(PairAction::Revoke { token_id }) => {
            EngineCall::new("control.pairing.revoke", json!({ "token_id": token_id }))
        }

        // Local commands never reach the engine; `open` is composed by the gateway, not a direct
        // control-method proxy.
        Command::Open { .. } | Command::Profiles(_) | Command::Wallet(_) | Command::Sign { .. } => {
            return None
        }
    };
    Some(call)
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
        assert_eq!(sub.params, json!({ "store_id": "abc" }));

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
}
