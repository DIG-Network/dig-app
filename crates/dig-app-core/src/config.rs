//! The agent's on-disk runtime configuration.
//!
//! [`AgentConfig`] is the small set of settings the agent core needs to start: the optional
//! custom engine/node endpoint override (§5.3 of the ecosystem contract — the user-facing setting
//! that wins over the auto-resolution ladder), the last active profile's DID, and the run-loop
//! reconcile interval. It lives in the user's AppData (see [`crate::storage`]).
//!
//! **At-rest sealing is deferred to U4.** Today this config round-trips as plaintext JSON. The
//! per-profile *sealed* blobs (identity keys, wallet, subscriptions) are U4's DIGOP1 work; this
//! agent-level config is deliberately the non-secret runtime settings so the agent can boot before
//! any profile is unlocked. When U4 lands, secret-bearing config moves under the sealed per-profile
//! store; these boot settings stay readable pre-unlock.

use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The default number of seconds between run-loop reconcile ticks (each tick re-probes the engine
/// connection). A few seconds keeps the status surface fresh without meaningful idle cost.
pub const DEFAULT_TICK_SECS: u64 = 5;

/// The agent config file name under the brand data directory.
const CONFIG_FILE: &str = "agent.json";

/// The agent's non-secret runtime settings, persisted as JSON in the user's AppData.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    /// An explicitly-configured engine/node endpoint that overrides the auto-resolution ladder
    /// (§5.3). `None` means "resolve the local dig-app IPC endpoint automatically". Exposing this
    /// setting satisfies the ecosystem "custom node MUST be user-facing on every client" rule.
    #[serde(default)]
    pub node_url: Option<String>,

    /// The DID of the profile to activate on start, if the user has selected one. `None` until a
    /// profile exists (profiles are U5). Recorded here so the agent restores the last active
    /// profile across restarts.
    #[serde(default)]
    pub active_profile: Option<String>,

    /// Seconds between run-loop reconcile ticks.
    #[serde(default = "default_tick_secs")]
    pub tick_secs: u64,
}

fn default_tick_secs() -> u64 {
    DEFAULT_TICK_SECS
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            node_url: None,
            active_profile: None,
            tick_secs: DEFAULT_TICK_SECS,
        }
    }
}

impl AgentConfig {
    /// The config file path under a resolved brand data directory.
    pub fn path_in(brand_dir: &Path) -> PathBuf {
        brand_dir.join(CONFIG_FILE)
    }

    /// Load the config from `path`. A **missing** file yields [`AgentConfig::default`] — a fresh
    /// install has no config yet and must still boot — while a present-but-unreadable or malformed
    /// file is a real error the caller must see rather than silently overwrite.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the config to `path`, creating the parent directory if needed. Written pretty so a
    /// human can read/edit it (per the agent-friendly baseline).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_no_override_and_the_default_interval() {
        let cfg = AgentConfig::default();
        assert_eq!(cfg.node_url, None);
        assert_eq!(cfg.active_profile, None);
        assert_eq!(cfg.tick_secs, DEFAULT_TICK_SECS);
    }

    #[test]
    fn missing_file_loads_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());
        assert!(!path.exists());
        assert_eq!(AgentConfig::load(&path).unwrap(), AgentConfig::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        // A nested brand dir that does not exist yet — save must create it.
        let path = AgentConfig::path_in(&dir.path().join("DigNetwork"));
        let cfg = AgentConfig {
            node_url: Some("https://node.example".to_string()),
            active_profile: Some("did:chia:abc".to_string()),
            tick_secs: 42,
        };
        cfg.save(&path).unwrap();
        assert!(path.exists());
        assert_eq!(AgentConfig::load(&path).unwrap(), cfg);
    }

    #[test]
    fn malformed_file_is_an_error_not_a_silent_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(AgentConfig::load(&path).is_err());
    }

    #[test]
    fn absent_fields_fall_back_to_defaults() {
        // Forwards-compatible: an older/minimal config file still parses.
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());
        std::fs::write(&path, b"{}").unwrap();
        let cfg = AgentConfig::load(&path).unwrap();
        assert_eq!(cfg, AgentConfig::default());
    }
}
