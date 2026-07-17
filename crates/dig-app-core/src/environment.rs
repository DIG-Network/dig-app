//! The resolved per-user environment the agent boots from.
//!
//! [`AppEnvironment`] bundles the handful of host facts the agent needs — the OS, the AppData
//! root, the login user, the per-user runtime directory, and whether a desktop display is present —
//! and derives everything downstream from them: the brand data directory ([`crate::storage`]), the
//! config path ([`crate::config`]), the IPC endpoint ([`crate::ipc`]), and the form factor
//! ([`crate::form_factor`]).
//!
//! It is split deliberately: the *derivation* methods here are pure and fully tested; reading the
//! real process environment (env vars, display detection) is the impure edge and lives in the
//! binary shells, which pass the facts in. That keeps every boot decision unit-testable.

use crate::config::AgentConfig;
use crate::form_factor::FormFactor;
use crate::{ipc, storage, Os, Result};
use std::path::PathBuf;

/// The resolved facts about the host the agent runs on. Construct it at the process edge (from real
/// env vars) and hand it to the agent; the derivation methods below are pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEnvironment {
    /// The operating system.
    pub os: Os,
    /// The AppData root: `%LOCALAPPDATA%` (Windows), `$HOME` (macOS), `$XDG_DATA_HOME` (Linux).
    pub app_data_root: String,
    /// The login user identifier — namespaces the per-user IPC endpoint.
    pub user: String,
    /// The per-user runtime directory for the Unix socket (`$XDG_RUNTIME_DIR` on Linux). Ignored on
    /// Windows, where the pipe namespace carries the user.
    pub runtime_dir: String,
    /// Whether a usable desktop display is present (drives the tray-vs-headless form factor).
    pub has_display: bool,
}

impl AppEnvironment {
    /// The per-user brand data directory (`.../DigNetwork`). Fails loudly if the AppData root is
    /// unset — an agent with nowhere to store user data must not guess a location.
    pub fn brand_dir(&self) -> Result<PathBuf> {
        storage::brand_data_dir(self.os, &self.app_data_root)
    }

    /// The agent config file path under the brand data directory.
    pub fn config_path(&self) -> Result<PathBuf> {
        Ok(AgentConfig::path_in(&self.brand_dir()?))
    }

    /// The per-user IPC endpoint address (named pipe / Unix socket) the agent uses to reach the
    /// engine. A configured `node_url` in [`AgentConfig`] overrides this (§5.3); [`Self::endpoint`]
    /// applies that precedence.
    pub fn ipc_endpoint(&self) -> String {
        ipc::channel_endpoint(self.os, &self.user, &self.runtime_dir)
    }

    /// The engine endpoint the agent should dial, applying the §5.3 override precedence: an
    /// explicitly-configured `node_url` wins over the auto-resolved local IPC endpoint.
    pub fn endpoint(&self, config: &AgentConfig) -> String {
        match &config.node_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => self.ipc_endpoint(),
        }
    }

    /// The form factor for this host: a tray shell when a display is present, else headless.
    pub fn form_factor(&self) -> FormFactor {
        FormFactor::detect(self.has_display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_env() -> AppEnvironment {
        AppEnvironment {
            os: Os::Linux,
            app_data_root: "/home/alice/.local/share".to_string(),
            user: "alice".to_string(),
            runtime_dir: "/run/user/1000".to_string(),
            has_display: true,
        }
    }

    #[test]
    fn derives_brand_dir_and_config_path() {
        let env = linux_env();
        let brand = env.brand_dir().unwrap();
        assert!(brand.ends_with("dignetwork"));
        assert_eq!(env.config_path().unwrap(), brand.join("agent.json"));
    }

    #[test]
    fn ipc_endpoint_is_the_per_user_socket() {
        assert_eq!(linux_env().ipc_endpoint(), "/run/user/1000/dignetwork.sock");
    }

    #[test]
    fn configured_node_url_overrides_the_ipc_endpoint() {
        let env = linux_env();
        let cfg = AgentConfig {
            node_url: Some("https://my.node".to_string()),
            ..AgentConfig::default()
        };
        assert_eq!(env.endpoint(&cfg), "https://my.node");
    }

    #[test]
    fn absent_or_empty_node_url_falls_back_to_ipc() {
        let env = linux_env();
        assert_eq!(env.endpoint(&AgentConfig::default()), env.ipc_endpoint());
        let empty = AgentConfig {
            node_url: Some(String::new()),
            ..AgentConfig::default()
        };
        assert_eq!(env.endpoint(&empty), env.ipc_endpoint());
    }

    #[test]
    fn form_factor_follows_display_presence() {
        let mut env = linux_env();
        assert_eq!(env.form_factor(), FormFactor::Tray);
        env.has_display = false;
        assert_eq!(env.form_factor(), FormFactor::Headless);
    }

    #[test]
    fn missing_app_data_root_is_an_error() {
        let mut env = linux_env();
        env.app_data_root = String::new();
        assert!(env.brand_dir().is_err());
        assert!(env.config_path().is_err());
    }
}
