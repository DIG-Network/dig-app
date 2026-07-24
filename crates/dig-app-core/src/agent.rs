//! The per-user identity agent — lifecycle, run loop, and status surface.
//!
//! [`Agent`] is the headless heart of dig-app: it resolves the user's AppData, loads its config,
//! and runs a reconcile loop that keeps a live [`AgentStatus`] (running? engine reachable? which
//! profile is active?). The tray shell and the `dign` CLI are thin observers of this core — the
//! tray reads [`Agent::status_handle`] to paint its menu and trips [`Agent::shutdown_handle`] on
//! "Quit"; a headless host runs the very same [`Agent::run`] with no shell attached.
//!
//! U3 delivers this lifecycle. The security-critical custody it drives — unlocking the master-HD
//! account ([`crate::account`]), the credential-store seam ([`crate::keystore`]), and the
//! identity-authenticated session + `sign` callback ([`crate::engine`]/[`crate::ipc`]) — is reached
//! through seams; the agent connects to the engine through the [`EngineConnector`] seam so the real
//! handshake slots in without reshaping the loop.

use crate::config::AgentConfig;
use crate::engine::{EngineConnector, EngineState};
use crate::environment::AppEnvironment;
use crate::shutdown::Shutdown;
use crate::Result;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A lightweight reference to the active profile — the DID the status surface and the tray menu
/// display. The full custody state lives behind the
/// [`AccountResidency`](crate::account::residency::AccountResidency); this handle carries only the
/// public DID, so the agent status can be read without unlocking anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRef {
    /// The profile's `did:chia:` decentralized identifier.
    pub did: String,
}

/// The agent's live status — a cheap, cloneable snapshot the tray shell and CLI read to show what
/// the agent is doing. Updated in place by the run loop under a shared lock ([`SharedStatus`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    /// Whether the run loop is active — set for the duration of [`Agent::run`].
    pub running: bool,
    /// The current link to the engine.
    pub engine: EngineState,
    /// The active profile, if one is selected. A placeholder in U3 (derived from the config's last
    /// active DID); real profile management is U5.
    pub active_profile: Option<ProfileRef>,
}

/// A shared, thread-safe handle to the agent's [`AgentStatus`], so an observer (the tray shell) can
/// read the latest status while the run loop updates it.
pub type SharedStatus = Arc<RwLock<AgentStatus>>;

/// The per-user identity agent. Generic over its [`EngineConnector`] so the run loop is pure and
/// the connection mechanism (the U3 null stub, a test fake, the real U6 session) is swappable.
pub struct Agent<C: EngineConnector> {
    endpoint: String,
    config_path: PathBuf,
    config: AgentConfig,
    connector: C,
    tick_interval: Duration,
    status: SharedStatus,
    shutdown: Shutdown,
}

impl<C: EngineConnector> Agent<C> {
    /// Build an agent from already-resolved parts. Prefer [`Agent::from_env`] at the process edge;
    /// this constructor keeps the wiring pure and testable.
    pub fn new(endpoint: String, config_path: PathBuf, config: AgentConfig, connector: C) -> Self {
        let active_profile = config.active_profile.clone().map(|did| ProfileRef { did });
        let tick_interval = Duration::from_secs(config.tick_secs.max(1));
        let status = Arc::new(RwLock::new(AgentStatus {
            running: false,
            engine: EngineState::initial(),
            active_profile,
        }));
        Self {
            endpoint,
            config_path,
            config,
            connector,
            tick_interval,
            status,
            shutdown: Shutdown::new(),
        }
    }

    /// Build an agent for a resolved host [`AppEnvironment`]: load the config from the user's
    /// AppData (a missing file yields defaults), resolve the engine endpoint with the §5.3 override
    /// precedence, and wire the connector.
    pub fn from_env(env: &AppEnvironment, connector: C) -> Result<Self> {
        let config_path = env.config_path()?;
        let config = AgentConfig::load(&config_path)?;
        let endpoint = env.endpoint(&config);
        Ok(Self::new(endpoint, config_path, config, connector))
    }

    /// The engine endpoint this agent dials.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The agent's loaded config.
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// A snapshot of the current status.
    pub fn status(&self) -> AgentStatus {
        self.read_status().clone()
    }

    /// A shared handle to the status, for an observer (the tray shell) to poll.
    pub fn status_handle(&self) -> SharedStatus {
        Arc::clone(&self.status)
    }

    /// A handle to trip shutdown from elsewhere (a tray "Quit", a signal handler, a service stop).
    pub fn shutdown_handle(&self) -> Shutdown {
        self.shutdown.clone()
    }

    /// Run one reconcile step: probe the engine and update the status. Public so a shell can drive a
    /// single tick in a custom loop, and so it is directly testable.
    pub fn tick(&self) {
        let probe = self.connector.probe(&self.endpoint);
        let next = match probe {
            crate::engine::Probe::Reachable => EngineState::Connected,
            crate::engine::Probe::Unreachable(reason) => EngineState::Disconnected { reason },
        };
        self.write_status().engine = next;
    }

    /// Run the agent to completion: mark running, reconcile on each tick until shutdown is
    /// requested, then stop cleanly. Blocks the calling thread; run it on a background thread when a
    /// tray shell owns the main thread, or on the main thread when headless.
    ///
    /// Shutdown is prompt: [`Shutdown`] wakes the inter-tick wait immediately, so "Quit" does not
    /// wait out a tick interval.
    pub fn run(&self) {
        self.start();
        while !self.shutdown.is_triggered() {
            self.tick();
            self.shutdown.wait_timeout(self.tick_interval);
        }
        self.stop();
    }

    /// Mark the agent running.
    fn start(&self) {
        self.write_status().running = true;
    }

    /// Stop cleanly: persist the config and mark the agent stopped. A failed config save is not
    /// fatal to shutdown — the status still flips to stopped so callers can exit.
    fn stop(&self) {
        let _ = self.config.save(&self.config_path);
        self.write_status().running = false;
    }

    fn read_status(&self) -> std::sync::RwLockReadGuard<'_, AgentStatus> {
        self.status.read().expect("status lock poisoned")
    }

    fn write_status(&self) -> std::sync::RwLockWriteGuard<'_, AgentStatus> {
        self.status.write().expect("status lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{NullConnector, Probe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// A connector that always reports the engine reachable and counts how many times it was
    /// probed — enough to exercise the loop deterministically.
    #[derive(Clone, Default)]
    struct CountingConnector {
        probes: Arc<AtomicUsize>,
    }

    impl EngineConnector for CountingConnector {
        fn probe(&self, _endpoint: &str) -> Probe {
            self.probes.fetch_add(1, Ordering::SeqCst);
            Probe::Reachable
        }
    }

    fn agent_with<C: EngineConnector>(
        connector: C,
        tick_secs: u64,
    ) -> (Agent<C>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            active_profile: Some("did:chia:abc".to_string()),
            tick_secs,
            ..AgentConfig::default()
        };
        let path = dir.path().join("agent.json");
        let agent = Agent::new("endpoint".to_string(), path, config, connector);
        (agent, dir)
    }

    #[test]
    fn new_seeds_status_from_config() {
        let (agent, _dir) = agent_with(NullConnector, 5);
        let status = agent.status();
        assert!(!status.running);
        assert!(!status.engine.is_connected());
        assert_eq!(
            status.active_profile,
            Some(ProfileRef {
                did: "did:chia:abc".to_string()
            })
        );
    }

    #[test]
    fn tick_reflects_a_reachable_engine() {
        let (agent, _dir) = agent_with(CountingConnector::default(), 5);
        agent.tick();
        assert!(agent.status().engine.is_connected());
    }

    #[test]
    fn tick_reflects_an_unreachable_engine() {
        let (agent, _dir) = agent_with(NullConnector, 5);
        agent.tick();
        assert!(!agent.status().engine.is_connected());
    }

    #[test]
    fn run_returns_immediately_when_shutdown_is_pre_triggered() {
        let (agent, _dir) = agent_with(CountingConnector::default(), 5);
        agent.shutdown_handle().trigger();
        agent.run();
        // Started then stopped; the loop body never ran, so the engine stayed at its initial state.
        assert!(!agent.status().running);
        assert!(!agent.status().engine.is_connected());
    }

    #[test]
    fn run_loops_until_shutdown_then_stops_cleanly() {
        let connector = CountingConnector::default();
        let probes = Arc::clone(&connector.probes);
        let (agent, _dir) = agent_with(connector, 5);
        let shutdown = agent.shutdown_handle();
        let status_handle = agent.status_handle();

        let handle = thread::spawn(move || agent.run());
        // Let at least one tick happen, then ask it to stop.
        while probes.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(status_handle.read().unwrap().running);
        shutdown.trigger();
        handle.join().unwrap();

        assert!(probes.load(Ordering::SeqCst) >= 1);
        let status = status_handle.read().unwrap();
        assert!(!status.running);
        assert!(status.engine.is_connected());
    }

    #[test]
    fn stop_persists_the_config() {
        let (agent, dir) = agent_with(CountingConnector::default(), 5);
        let path = dir.path().join("agent.json");
        assert!(!path.exists());
        agent.shutdown_handle().trigger();
        agent.run();
        assert!(path.exists());
        assert_eq!(AgentConfig::load(&path).unwrap(), *agent.config());
    }

    #[test]
    fn from_env_loads_config_and_resolves_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let env = AppEnvironment {
            os: crate::Os::Linux,
            app_data_root: dir.path().to_string_lossy().into_owned(),
            user: "alice".to_string(),
            runtime_dir: "/run/user/1000".to_string(),
            has_display: false,
        };
        // Persist a config the agent should pick up.
        let cfg = AgentConfig {
            node_url: Some("https://configured.node".to_string()),
            ..AgentConfig::default()
        };
        cfg.save(&env.config_path().unwrap()).unwrap();

        let agent = Agent::from_env(&env, NullConnector).unwrap();
        // The configured node_url wins over the IPC endpoint (§5.3 override precedence).
        assert_eq!(agent.endpoint(), "https://configured.node");
        assert_eq!(
            agent.config().node_url.as_deref(),
            Some("https://configured.node")
        );
    }
}
