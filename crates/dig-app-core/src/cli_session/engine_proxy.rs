//! The CLI lane's engine proxy: forward an engine-routed `dign` command to the running dig-node.
//!
//! The gateway resolves each engine-routed command to a canonical `control.*` call from the
//! published contract ([`crate::gateway::engine_call`]); this module carries that call to the node
//! over the same loopback control transport the tray shell uses ([`crate::control`]) and hands the
//! node's own answer back. Before this existed the lane served every engine verb with a refusal, so
//! `dign info`, `dign peers list`, `dign cache get` and twenty others could not be run at all
//! (dig-app#226).
//!
//! # Why the allow-list is not defence theatre
//!
//! The node's control surface is much wider than the gateway's router — it includes
//! `control.wallet.coinSpend`, the key-enrolment methods, and every other privileged verb. This
//! proxy forwards a method NAME it is handed, so without a gate it would be a general-purpose
//! tunnel from `dign` into the node rather than the tail of a routing decision.
//!
//! So a call is forwarded only if the method is one the gateway's own router can produce
//! ([`crate::gateway::proxyable_methods`], derived from the command list rather than written out a
//! second time). Anything else is `DENIED` and never dialled. This is what keeps dig_ecosystem#908's
//! boundary intact from BOTH sides: the local half refuses to sign
//! ([`super::host_identity::HostIdentity::sign`], [`super::host_identity::UnavailableConfirmer`]),
//! and this half cannot be talked into asking a node to do anything the router did not route.
//!
//! # What it never carries
//!
//! Nothing seed-derived. The proxy is handed a method and a params object built by the gateway from
//! a `Command` the CLI sent; no key material, master seed or profile DEK is in reach of this module,
//! and `crate::wallet::no_user_key_on_wire` holds that property for the lane's own socket.

use std::time::Duration;

use serde_json::Value;

use crate::control::{self, ControlCallError, ControlFailure};
use crate::gateway::{proxyable_methods, EngineProxy, ErrorCode, GatewayError};

/// How long ONE tier of the endpoint ladder may take to answer a proxied call.
///
/// Longer than the agent's liveness probe ([`control::DEFAULT_PROBE_TIMEOUT`]) because a person at a
/// terminal is waiting for an answer rather than a background loop sampling one, and some control
/// verbs (a sync trigger, a cache clear) do real work before replying. Short enough that an
/// unreachable tier does not feel like a hang.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The hint a "no node answered" refusal carries — the one thing that changes the answer.
const NO_NODE_HINT: &str = "start the DIG node (`dig-node start`), or set a node endpoint in the \
     DIG app's Settings if yours runs elsewhere";

/// The hint an authorization refusal carries: the node is running and will not talk to this app.
const NO_TOKEN_HINT: &str =
    "this app holds no usable node control token — restart the DIG app after the node is running";

/// Forwards the gateway's `control.*` calls to the local dig-node over the loopback control plane.
pub struct NodeEngineProxy {
    /// The user's configured node endpoint, if they set one. It wins the ladder outright (§5.3).
    configured_endpoint: Option<String>,
    /// How long one tier may take to answer.
    timeout: Duration,
    /// How the node's control token is obtained.
    ///
    /// Re-read on EVERY call, not captured once: a node installed or first started after this app
    /// launched mints its token only then, and re-reading is what lets the lane start working
    /// without the person restarting the app. A closure rather than a value so a test can supply a
    /// token without an installed node.
    read_token: Box<dyn Fn() -> Option<String> + Send + Sync>,
}

impl NodeEngineProxy {
    /// The production proxy: the §5.3 endpoint ladder under `configured_endpoint`, and the control
    /// token read from dig-node's own state directory.
    pub fn new(configured_endpoint: Option<String>) -> Self {
        Self {
            configured_endpoint,
            timeout: CALL_TIMEOUT,
            read_token: Box::new(control::load_control_token),
        }
    }

    /// A proxy that dials exactly `endpoint`, presenting `token` — the seam every test points at a
    /// fake node, so each rule below is exercised over a real socket rather than a mock.
    #[cfg(test)]
    pub(crate) fn dialling(endpoint: &str, token: Option<&str>, timeout: Duration) -> Self {
        let token = token.map(str::to_string);
        Self {
            configured_endpoint: Some(endpoint.to_string()),
            timeout,
            read_token: Box::new(move || token.clone()),
        }
    }

    /// Whether the gateway's router can produce `method` at all. See this module's header.
    fn is_proxyable(method: &str) -> bool {
        proxyable_methods().contains(&method)
    }
}

impl EngineProxy for NodeEngineProxy {
    /// Forward `method` to the first node tier that answers, returning the node's own result.
    ///
    /// # Why only an unreachable tier falls through
    ///
    /// [`control::resolve_status`] tries every tier because a status read is idempotent. Half of
    /// what travels here is NOT: a cache clear, a pin, a sync trigger and a subscribe all change
    /// node state. A tier that ACCEPTED the call and then refused or timed out may well have acted
    /// on it, so re-sending to the next tier could apply the same mutation twice. Only a refused
    /// connection — nothing there at all — is evidence that nothing happened, so only that falls
    /// through.
    fn call(&self, method: &str, params: Value) -> Result<Value, GatewayError> {
        if !Self::is_proxyable(method) {
            return Err(GatewayError::new(
                ErrorCode::Denied,
                format!("`{method}` is not a method the DIG app proxies on behalf of the CLI"),
            ));
        }
        let token = (self.read_token)();
        let ladder = control::endpoint_ladder(self.configured_endpoint.as_deref());
        let mut unreachable = Vec::new();

        for endpoint in &ladder {
            match control::call_control_raw(
                endpoint,
                method,
                params.clone(),
                token.as_deref(),
                self.timeout,
            ) {
                Ok(result) => return Ok(result),
                Err(ControlFailure::Transport(ControlCallError::Unreachable(why))) => {
                    unreachable.push(format!("{endpoint}: {why}"))
                }
                Err(failure) => return Err(answered_but_failed(method, failure)),
            }
        }
        Err(GatewayError::new(
            ErrorCode::NotConnected,
            format!(
                "no DIG node answered `{method}` ({})",
                unreachable.join("; ")
            ),
        )
        .with_hint(NO_NODE_HINT))
    }
}

/// Turn a failure from a node that DID answer into the catalogued error a person can act on.
///
/// The distinction each arm holds is the one a command line must never blur: a node that declined
/// is a different problem from no node, and an authorization fault is a different problem again —
/// each has its own remedy, and collapsing them sends someone hunting the wrong fault.
fn answered_but_failed(method: &str, failure: ControlFailure) -> GatewayError {
    match failure {
        ControlFailure::Rejected(error) => GatewayError::new(ErrorCode::EngineError, error.message),
        ControlFailure::Transport(ControlCallError::HttpRefused { code, detail }) => {
            let refusal = GatewayError::new(
                ErrorCode::EngineError,
                format!("the node refused `{method}`: HTTP {code} {detail}"),
            );
            match code {
                401 | 403 => refusal.with_hint(NO_TOKEN_HINT),
                _ => refusal,
            }
        }
        // A node that accepted the connection is demonstrably THERE, so a timeout or an unreadable
        // reply says something about this CALL and nothing about whether a node is running.
        ControlFailure::Transport(other) => GatewayError::new(
            ErrorCode::IoError,
            format!("`{method}` did not complete: {other}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{
        engine_call, CacheAction, Command, ConfigAction, PairAction, PeersAction, StoresAction,
        SubscriptionsAction, SyncAction,
    };
    use crate::test_support::node::{Behaviour, FakeNode};

    fn quick() -> Duration {
        Duration::from_secs(5)
    }

    /// An endpoint on loopback that nothing is listening on: bind an ephemeral port, learn its
    /// number, drop the listener. The port is real, held by nobody, and reliably refuses.
    fn dead_endpoint() -> String {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        format!("http://{addr}")
    }

    /// Forward `command` to a fake node that echoes what it was asked, and return the result.
    fn proxied(command: &Command) -> Result<Value, GatewayError> {
        let node = FakeNode::with_behaviour(Behaviour::EchoingControl);
        let proxy = NodeEngineProxy::dialling(&node.endpoint(), Some(FakeNode::TOKEN), quick());
        let call = engine_call(command).expect("an engine-routed command maps to a call");
        proxy.call(call.method, call.params)
    }

    /// One representative command per engine-routed FAMILY, with the family named so a failure says
    /// which surface broke rather than only which command did.
    fn one_per_family() -> Vec<(&'static str, Command)> {
        vec![
            ("info", Command::Info),
            ("config", Command::Config(ConfigAction::Get)),
            (
                "config-write",
                Command::Config(ConfigAction::SetUpstream {
                    url: "https://up.example".into(),
                }),
            ),
            ("cache", Command::Cache(CacheAction::Get)),
            (
                "cache-write",
                Command::Cache(CacheAction::SetCap {
                    bytes: 2 * 1024 * 1024 * 1024,
                }),
            ),
            ("stores", Command::Stores(StoresAction::List)),
            (
                "stores-write",
                Command::Stores(StoresAction::Pin { store: "s".into() }),
            ),
            ("sync", Command::Sync(SyncAction::Status)),
            (
                "sync-write",
                Command::Sync(SyncAction::Trigger { store: "s".into() }),
            ),
            (
                "subscriptions",
                Command::Subscriptions(SubscriptionsAction::List),
            ),
            (
                "subscriptions-write",
                Command::Subscriptions(SubscriptionsAction::Add {
                    store_id: "sid".into(),
                }),
            ),
            ("peers", Command::Peers(PeersAction::List)),
            (
                "peers-write",
                Command::Peers(PeersAction::Connect { peer: "p".into() }),
            ),
            (
                "peers-uncatalogued",
                Command::Peers(PeersAction::Ban {
                    peer: "p".into(),
                    state: "ban".into(),
                }),
            ),
            ("pair", Command::Pair(PairAction::List)),
            (
                "pair-write",
                Command::Pair(PairAction::Approve {
                    pairing_id: "pid".into(),
                }),
            ),
        ]
    }

    /// Every engine-routed family reaches a REAL node over a REAL socket and returns THAT node's
    /// answer.
    ///
    /// The fixture is an echoing node rather than a canned one on purpose. "It stopped saying
    /// NOT_CONNECTED" is satisfied by a proxy that returns a fabricated constant, and a canned node
    /// answering every method with the same body is satisfied by a proxy that sends the WRONG
    /// method. So the node echoes the method and params it actually received, and stamps its own
    /// `served_by` marker — a value the client never holds — so a fabricated result cannot pass and
    /// a misdirected call names the wrong method.
    #[test]
    fn every_engine_family_reaches_the_node_and_returns_its_answer() {
        for (family, command) in one_per_family() {
            let call = engine_call(&command).expect("engine-routed");
            let result = proxied(&command)
                .unwrap_or_else(|e| panic!("{family} must reach the node, got {e:?}"));
            assert_eq!(
                result["served_by"],
                serde_json::json!(FakeNode::VERSION),
                "{family}: the result must be the NODE's, not one this proxy made up"
            );
            assert_eq!(
                result["method"],
                serde_json::json!(call.method),
                "{family}: the node must have been asked for the method the gateway resolved"
            );
            assert_eq!(
                result["params"], call.params,
                "{family}: the params the gateway built must arrive unaltered"
            );
        }
    }

    /// A method the gateway's router cannot produce is refused, and no socket is dialled.
    ///
    /// `control.wallet.coinSpend` is the pointed case: it is a real method a real node serves, and
    /// it is the one a tunnel into the node would be wanted for. The assertion pairs the refusal
    /// with the node's OWN request count, because "it returned an error" is also true of a proxy
    /// that sent the call first and disliked the answer.
    #[test]
    fn a_method_the_router_never_produces_is_denied_without_dialling() {
        let node = FakeNode::with_behaviour(Behaviour::EchoingControl);
        let proxy = NodeEngineProxy::dialling(&node.endpoint(), Some(FakeNode::TOKEN), quick());
        for forbidden in [
            "control.wallet.coinSpend",
            "control.wallet.broadcast",
            "control.wallet.watch",
            "control.profile.putBody",
            "control.log.setLevel",
        ] {
            let refusal = proxy
                .call(forbidden, serde_json::json!({}))
                .expect_err("a method outside the router must be refused");
            assert_eq!(
                refusal.code,
                ErrorCode::Denied,
                "{forbidden} must be DENIED, not merely fail"
            );
        }
        assert_eq!(
            node.request_count(),
            0,
            "a denied method must never reach the wire"
        );
    }

    /// The allow-list IS the router's output, not a second list that could drift from it.
    ///
    /// Written as an equality both ways: a method the router produces but the list omits would make
    /// a shipped `dign` verb refuse, and a method the list carries but the router cannot produce is
    /// exactly the widened surface the header warns about.
    #[test]
    fn the_allow_list_is_exactly_what_the_router_can_produce() {
        for command in crate::gateway::all_engine_routed_commands() {
            let call = engine_call(&command).expect("engine-routed");
            assert!(
                NodeEngineProxy::is_proxyable(call.method),
                "{:?} is routed to the engine but its method is not proxyable",
                command
            );
        }
        for method in proxyable_methods() {
            assert!(
                crate::gateway::all_engine_routed_commands()
                    .iter()
                    .filter_map(engine_call)
                    .any(|call| call.method == method),
                "{method} is proxyable but no command produces it"
            );
        }
    }

    /// Nothing listening anywhere on the ladder is NOT_CONNECTED, and the message names what was
    /// tried — so a person is told where to look rather than only that it failed.
    #[test]
    fn no_node_anywhere_is_not_connected_and_names_the_ladder() {
        let endpoint = dead_endpoint();
        let proxy = NodeEngineProxy::dialling(&endpoint, None, quick());
        let failure = proxy
            .call("control.status", serde_json::json!({}))
            .expect_err("nothing is listening");
        assert_eq!(failure.code, ErrorCode::NotConnected);
        assert!(
            failure.message.contains(&endpoint),
            "the refusal must name the endpoint it tried; got {}",
            failure.message
        );
        assert_eq!(failure.hint.as_deref(), Some(NO_NODE_HINT));
    }

    /// A node that ANSWERS with a JSON-RPC error is an ENGINE_ERROR carrying the node's own words —
    /// never NOT_CONNECTED, which would send a person hunting an absent node that is right there.
    #[test]
    fn a_node_that_declines_is_an_engine_error_not_an_absent_node() {
        let node = FakeNode::with_behaviour(Behaviour::JsonRpcError("no such store".into()));
        let proxy = NodeEngineProxy::dialling(&node.endpoint(), Some(FakeNode::TOKEN), quick());
        let failure = proxy
            .call("control.sync.status", serde_json::json!({}))
            .expect_err("the node declined");
        assert_eq!(failure.code, ErrorCode::EngineError);
        assert!(
            failure.message.contains("no such store"),
            "the node's own message must survive; got {}",
            failure.message
        );
    }

    /// An unrecognized control token draws the node's `401`, which is a permission fault on a
    /// RUNNING node — reported as such, with the remedy, rather than as no node.
    #[test]
    fn an_unauthorized_call_names_the_permission_fault_and_its_remedy() {
        let node = FakeNode::with_behaviour(Behaviour::EchoingControl);
        let proxy = NodeEngineProxy::dialling(&node.endpoint(), None, quick());
        let failure = proxy
            .call("control.status", serde_json::json!({}))
            .expect_err("an untokened call is refused");
        assert_eq!(failure.code, ErrorCode::EngineError);
        assert!(failure.message.contains("401"), "got {}", failure.message);
        assert_eq!(failure.hint.as_deref(), Some(NO_TOKEN_HINT));
    }

    /// The control token travels as its own header, asserted from the SERVER's copy of the request.
    #[test]
    fn the_proxied_call_carries_the_control_token() {
        let node = FakeNode::with_behaviour(Behaviour::EchoingControl);
        let proxy = NodeEngineProxy::dialling(&node.endpoint(), Some(FakeNode::TOKEN), quick());
        proxy
            .call("control.status", serde_json::json!({}))
            .expect("served");
        let request = node.received();
        assert!(
            request.contains(&format!(
                "{}: {}",
                control::CONTROL_TOKEN_HEADER,
                FakeNode::TOKEN
            )),
            "the control token must travel as its own header; got:\n{request}"
        );
    }
}
