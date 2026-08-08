//! The agent's link to the DIG node — the state a person actually sees.
//!
//! The agent's run loop asks an [`EngineConnector`] for the current link on every tick and publishes
//! the answer as the status surface the tray menu and the CLI read. There are two honest answers,
//! and [`EngineState`] is both:
//!
//! - **connected** — a node answered, and the link carries the node's own snapshot;
//! - **disconnected** — nothing answered (or nothing has been tried yet), with the reason and the
//!   endpoints that were tried.
//!
//! [`NodeConnector`] is the production connector: it walks the §5.3 endpoint ladder and calls
//! `control.status` over the loopback JSON-RPC surface dig-node actually serves (see
//! [`crate::control`]). [`NullConnector`] is a **test double** that never connects — it is what the
//! agent's own lifecycle tests drive the disconnected branch with, and it is deliberately no longer
//! what the shipped binary uses.

use std::time::Duration;

use dig_node_control_interface::results::StatusResult;

use crate::control::{self, ControlCallError};

/// The agent's view of its link to the DIG node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineState {
    /// No node is currently reachable, with a human-readable reason for the status surface.
    Disconnected {
        /// Why no node is reachable — or that no connection has been attempted yet.
        reason: String,
    },
    /// A node answered `control.status`, and this is what it said.
    Connected {
        /// The endpoint that answered, so the surface can name the node it is talking to.
        endpoint: String,
        /// The node's own status snapshot — version, uptime, cache, hosted stores, sync.
        status: Box<StatusResult>,
    },
}

impl EngineState {
    /// The initial state before the first probe: nothing attempted yet.
    pub fn initial() -> Self {
        EngineState::Disconnected {
            reason: "not yet connected".to_string(),
        }
    }

    /// Whether a node is currently reachable.
    pub fn is_connected(&self) -> bool {
        matches!(self, EngineState::Connected { .. })
    }

    /// The node's status snapshot, when connected.
    pub fn status(&self) -> Option<&StatusResult> {
        match self {
            EngineState::Connected { status, .. } => Some(status),
            EngineState::Disconnected { .. } => None,
        }
    }

    /// A single line describing the link, for the tray menu / CLI / startup log.
    ///
    /// Connected reads as the node's real identity and shape (`Node v0.64.0 · 9 capsule(s) cached`);
    /// disconnected reads as the reason it is not, never as a bare "error" a person cannot act on.
    pub fn summary(&self) -> String {
        match self {
            EngineState::Connected { status, .. } => format!(
                "Node v{} · {} capsule(s) cached · {} store(s) hosted",
                status.version, status.cached_capsule_count, status.hosted_store_count
            ),
            EngineState::Disconnected { reason } => format!("No node: {reason}"),
        }
    }
}

/// Reports the current link to the node. The agent's run loop calls this each tick and publishes the
/// result, so a connector MUST return promptly rather than block the loop.
///
/// Abstracting it keeps the loop pure and testable: the production [`NodeConnector`] talks to a real
/// node, while a test double drives any branch on demand.
pub trait EngineConnector: Send {
    /// Probe for a node and report the resulting link state.
    ///
    /// `configured_endpoint` is the user's explicit node setting (§5.3), which wins over the
    /// auto-resolution ladder. Empty means "resolve automatically".
    fn probe(&self, configured_endpoint: &str) -> EngineState;
}

/// The production connector: finds a running dig-node and asks it how it is doing.
///
/// Each probe walks the §5.3 ladder ([`control::endpoint_ladder`]) and returns the first tier that
/// answers `control.status`. Nothing is cached between ticks, so a node that starts (or stops) while
/// the app is running is picked up on the next tick without the user restarting anything.
#[derive(Debug, Clone)]
pub struct NodeConnector {
    timeout: Duration,
    /// Called on every probe to obtain the node's control token. Injected so a test can present a
    /// token for its own fake node instead of whatever this machine's real node happens to hold.
    read_token: fn() -> Option<String>,
}

impl Default for NodeConnector {
    fn default() -> Self {
        Self::new(control::DEFAULT_PROBE_TIMEOUT)
    }
}

impl NodeConnector {
    /// A connector allowing `timeout` per ladder tier, reading the control token from where
    /// dig-node writes it.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            read_token: control::load_control_token,
        }
    }

    /// A connector that obtains its token from `read_token` instead of the on-disk install.
    #[cfg(test)]
    fn with_token_reader(timeout: Duration, read_token: fn() -> Option<String>) -> Self {
        Self {
            timeout,
            read_token,
        }
    }
}

impl EngineConnector for NodeConnector {
    fn probe(&self, configured_endpoint: &str) -> EngineState {
        // The token is re-read every probe on purpose: a node installed or first started AFTER this
        // app was launched mints its token only then, and re-reading is what lets the app connect
        // without the user restarting it.
        let token = (self.read_token)();
        let ladder = control::endpoint_ladder(Some(configured_endpoint));
        match control::resolve_status(&ladder, token.as_deref(), self.timeout) {
            Ok((endpoint, status)) => EngineState::Connected {
                endpoint,
                status: Box::new(status),
            },
            Err(failures) => EngineState::Disconnected {
                reason: disconnected_reason(&failures, token.is_some()),
            },
        }
    }
}

/// Turn every tier's failure into the one sentence a person needs.
///
/// A node that ANSWERED but refused us is a completely different problem from no node at all — the
/// first is a permissions/pairing fault on a running node, the second means nothing is installed or
/// running. Collapsing both into "not connected" would send someone hunting the wrong fault, so a
/// refusal is reported as a refusal and names the missing token when that is the cause.
fn disconnected_reason(failures: &[(String, ControlCallError)], had_token: bool) -> String {
    if let Some((endpoint, error)) = failures
        .iter()
        // Both refusal shapes: a node that declined in JSON-RPC, and one that refused at the HTTP
        // layer (the `401` an absent control token draws). They are the same fault to a person —
        // a node is running and will not talk to this app — and the sentence below says so.
        .find(|(_, e)| {
            matches!(
                e,
                ControlCallError::Refused(_) | ControlCallError::HttpRefused { .. }
            )
        })
    {
        return if had_token {
            format!("the node at {endpoint} refused this app ({error})")
        } else {
            format!(
                "a node is running at {endpoint} but this app has no control token for it — start \
                 the node as this user, or grant read access to its control-token file"
            )
        };
    }
    // A tier that CONNECTED and then ran out of time is evidence that something is listening, so
    // the same sentence cannot be used: "no DIG node is running" would contradict the socket that
    // just opened (dig_ecosystem#2325).
    if let Some((endpoint, _)) = failures
        .iter()
        .find(|(_, e)| matches!(e, ControlCallError::TimedOut(_)))
    {
        return format!("the node at {endpoint} did not answer in time");
    }
    if failures.is_empty() {
        return "no node endpoint to try".to_string();
    }
    let tried: Vec<&str> = failures.iter().map(|(e, _)| e.as_str()).collect();
    format!("no DIG node is running (tried {})", tried.join(", "))
}

/// A **test double** that never connects, for driving the disconnected branch of the agent's
/// lifecycle without touching the network.
///
/// This is not what the shipped binary uses — [`NodeConnector`] is (dig_ecosystem#949).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullConnector;

impl EngineConnector for NullConnector {
    fn probe(&self, _configured_endpoint: &str) -> EngineState {
        EngineState::Disconnected {
            reason: "this build has no node connector wired (test double)".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node::{Behaviour, FakeNode};

    /// The token [`FakeNode`] authorizes, as an injectable reader.
    fn fake_node_token() -> Option<String> {
        Some(FakeNode::TOKEN.to_string())
    }

    /// A connector holding the fake node's token, so the fixture exercises the AUTHORIZED path
    /// rather than whatever token this machine's real dig-node install happens to hold.
    fn connector_for_fake_node() -> NodeConnector {
        NodeConnector::with_token_reader(control::DEFAULT_PROBE_TIMEOUT, fake_node_token)
    }

    /// A loopback endpoint nothing is listening on: bind to learn a real port, then drop it, so the
    /// address is genuine and reliably refuses.
    fn dead_endpoint() -> String {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        drop(listener);
        endpoint
    }

    #[test]
    fn initial_state_is_disconnected_and_not_connected() {
        let s = EngineState::initial();
        assert!(!s.is_connected());
        assert!(s.status().is_none());
        assert!(matches!(s, EngineState::Disconnected { .. }));
    }

    #[test]
    fn the_real_connector_connects_to_a_node_that_is_answering() {
        // The headline behaviour of #949: a REAL socket, a real HTTP/JSON-RPC exchange, and the
        // node's own numbers arriving in the state the UI paints.
        let node = FakeNode::serving_status();
        let state = connector_for_fake_node().probe(&node.endpoint());
        let EngineState::Connected { endpoint, status } = &state else {
            panic!("a node that answers control.status must be reported connected, got {state:?}");
        };
        assert_eq!(endpoint, &node.endpoint());
        assert_eq!(status.version, FakeNode::VERSION);
        assert!(state.is_connected());
        assert!(state.summary().contains(FakeNode::VERSION));
    }

    #[test]
    fn the_real_connector_reports_no_node_when_nothing_answers() {
        let endpoint = dead_endpoint();
        let state = NodeConnector::with_token_reader(Duration::from_millis(300), fake_node_token)
            .probe(&endpoint);
        let EngineState::Disconnected { reason } = &state else {
            panic!("nothing is listening, so this must not be Connected: {state:?}");
        };
        assert!(
            reason.contains("no DIG node is running") && reason.contains(&endpoint),
            "the reason must say what was tried; got {reason:?}"
        );
        assert!(state.status().is_none());
    }

    #[test]
    fn a_node_that_refuses_is_distinguished_from_no_node_at_all() {
        // These are different faults with different remedies, so they must not collapse into one
        // message. A test that only asserted "disconnected" would pass on the collapsed version.
        let node = FakeNode::with_behaviour(Behaviour::JsonRpcError("unauthorized".into()));
        let state = connector_for_fake_node().probe(&node.endpoint());
        let EngineState::Disconnected { reason } = &state else {
            panic!("a refusal is not a connection: {state:?}");
        };
        assert!(
            reason.contains("refused") || reason.contains("no control token"),
            "a refusal must be reported as one, not as 'no node'; got {reason:?}"
        );
        assert!(
            !reason.contains("no DIG node is running"),
            "a node that ANSWERED must not be reported as absent; got {reason:?}"
        );
    }

    /// **A tier that connected and then timed out is not an absent node** (dig_ecosystem#2325).
    ///
    /// The second tier is genuinely unreachable, so a reason derived from "the last thing that
    /// happened" would still say no node is running — the timeout must win, because it is the tier
    /// that proved something is there.
    #[test]
    fn a_tier_that_answered_too_slowly_is_not_reported_as_an_absent_node() {
        let failures = vec![
            (
                "http://dig.local".to_string(),
                ControlCallError::TimedOut("no reply".to_string()),
            ),
            (
                "http://localhost:9778".to_string(),
                ControlCallError::Unreachable("nothing there".to_string()),
            ),
        ];
        let reason = disconnected_reason(&failures, true);
        assert!(reason.contains("did not answer in time"), "{reason}");
        assert!(
            !reason.contains("no DIG node is running"),
            "a socket that opened contradicts this: {reason}"
        );
    }

    #[test]
    fn a_refusal_without_a_token_names_the_token_as_the_cause() {
        let failures = vec![(
            "http://localhost:9778".to_string(),
            ControlCallError::HttpRefused {
                code: 401,
                detail: "unauthorized".to_string(),
            },
        )];
        let reason = disconnected_reason(&failures, false);
        assert!(
            reason.contains("no control token"),
            "the actionable cause must be named; got {reason:?}"
        );
        // With a token in hand the SAME failure is a different diagnosis.
        assert!(disconnected_reason(&failures, true).contains("refused this app"));
    }

    #[test]
    fn a_refusal_is_surfaced_even_when_it_is_not_the_last_tier_tried() {
        // Ladder order must not bury the informative failure: an answering-but-refusing node is the
        // fault worth reporting even when a later tier merely found nothing.
        let failures = vec![
            (
                "http://dig.local".to_string(),
                ControlCallError::HttpRefused {
                    code: 401,
                    detail: "unauthorized".to_string(),
                },
            ),
            (
                "http://localhost:9778".to_string(),
                ControlCallError::Unreachable("nothing there".to_string()),
            ),
        ];
        assert!(disconnected_reason(&failures, true).contains("refused this app"));
    }

    #[test]
    fn the_summary_reads_as_a_sentence_in_both_states() {
        assert_eq!(
            EngineState::initial().summary(),
            "No node: not yet connected"
        );
        let node = FakeNode::serving_status();
        let summary = connector_for_fake_node().probe(&node.endpoint()).summary();
        assert!(summary.starts_with("Node v"), "got {summary:?}");
        assert!(summary.contains("9 capsule(s) cached"), "got {summary:?}");
    }

    #[test]
    fn the_null_connector_is_a_test_double_that_never_connects() {
        let state = NullConnector.probe("http://localhost:9778");
        assert!(!state.is_connected());
        assert!(matches!(state, EngineState::Disconnected { .. }));
    }
}
