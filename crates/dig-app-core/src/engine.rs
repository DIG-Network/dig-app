//! The agent's connection to the identity-agnostic engine (the dig-node service).
//!
//! The agent core reaches the engine over the per-user IPC endpoint ([`crate::ipc`]). The full
//! **identity-authenticated session** — the challenge/response handshake, `control.session.attach`,
//! and the `sign` callback — is U6 (security-critical). U3's job is the layer beneath that: model
//! the connection *state* and probe reachability, so the agent has a real, honest status to surface
//! ("engine reachable / not reachable") and a seam U6 slots the real handshake into.
//!
//! Reachability is abstracted behind [`EngineConnector`] so the run loop is pure and testable: U3
//! ships [`NullConnector`] (the endpoint is not yet answered — the real listener + handshake land in
//! U6), and tests inject fakes to drive every branch of the state machine.

/// The agent's view of its link to the engine. This is a *connection* state, not yet an
/// *authenticated session* state (sessions are U6); it answers "can the agent talk to the engine?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineState {
    /// Not (yet) connected, with a human-readable reason for the status surface.
    Disconnected {
        /// Why the engine is not currently reachable (or that connection hasn't been attempted).
        reason: String,
    },
    /// The engine endpoint answered a reachability probe.
    Connected,
}

impl EngineState {
    /// The initial state before the first probe: nothing attempted yet.
    pub fn initial() -> Self {
        EngineState::Disconnected {
            reason: "not yet connected".to_string(),
        }
    }

    /// Whether the engine is currently reachable.
    pub fn is_connected(&self) -> bool {
        matches!(self, EngineState::Connected)
    }
}

/// The outcome of a single reachability probe against the engine endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The endpoint answered.
    Reachable,
    /// The endpoint did not answer, with a reason for the status surface.
    Unreachable(String),
}

/// Probes the engine endpoint for reachability. The agent's run loop calls this each tick and maps
/// the outcome onto [`EngineState`]. Abstracting it keeps the loop pure and lets U6 replace the
/// implementation with the real identity-authenticated attach without touching the loop.
pub trait EngineConnector: Send {
    /// Probe `endpoint` (the resolved IPC address, or a configured node URL). MUST NOT block for
    /// long — the run loop calls it on every tick.
    fn probe(&self, endpoint: &str) -> Probe;
}

/// The U3 default connector: reports the engine as unreachable because the engine-side listener and
/// the identity-authenticated session handshake are implemented in U6. It carries the endpoint it
/// *would* dial, so the status surface is still informative pre-U6.
///
/// This is an honest stub, not a fake success: until U6 stands up the listener there is genuinely
/// nothing to connect to, and the status must say so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullConnector;

impl EngineConnector for NullConnector {
    fn probe(&self, _endpoint: &str) -> Probe {
        Probe::Unreachable(
            "engine session handshake not yet available (lands in U6 of epic #908)".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_disconnected_and_not_connected() {
        let s = EngineState::initial();
        assert!(!s.is_connected());
        assert!(matches!(s, EngineState::Disconnected { .. }));
    }

    #[test]
    fn connected_reports_connected() {
        assert!(EngineState::Connected.is_connected());
    }

    #[test]
    fn null_connector_reports_unreachable_with_a_u6_reason() {
        let probe = NullConnector.probe(r"\\.\pipe\dignetwork-alice");
        match probe {
            Probe::Unreachable(reason) => assert!(reason.contains("U6")),
            Probe::Reachable => panic!("the U3 null connector must not report reachable"),
        }
    }
}
