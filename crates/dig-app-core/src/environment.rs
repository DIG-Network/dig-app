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
    /// Resolve the real per-user host facts from the process environment.
    ///
    /// This is the impure process edge, and it lives here — not in a binary — because **both** shells
    /// need the identical answer: `dig-app` boots the account from this directory, and `diga` must
    /// address the SAME one when it restores or inspects that account. Two copies of this resolution
    /// would be two subtly different directories, and a restore that writes where the app does not look
    /// is worse than no restore at all.
    pub fn from_host() -> Self {
        let os = current_os();
        Self {
            os,
            app_data_root: app_data_root(os),
            user: current_user(),
            runtime_dir: std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
            has_display: has_display(os),
        }
    }

    /// The per-user brand data directory (`.../DigNetwork`). Fails loudly if the AppData root is
    /// unset — an agent with nowhere to store user data must not guess a location.
    pub fn brand_dir(&self) -> Result<PathBuf> {
        storage::brand_data_dir(self.os, &self.app_data_root)
    }

    /// The agent config file path under the brand data directory.
    pub fn config_path(&self) -> Result<PathBuf> {
        Ok(AgentConfig::path_in(&self.brand_dir()?))
    }

    /// The per-user OS IPC endpoint address (named pipe / Unix socket) described by
    /// [`ipc::channel_endpoint`].
    ///
    /// **Nothing answers this today** — dig-node serves its control plane over loopback HTTP and has
    /// no pipe/socket listener (see [`crate::control`]), so the agent does NOT dial this. It is kept
    /// because the address scheme is specified (`SPEC.md` §5.1) and both sides must agree on it if
    /// that listener is ever built.
    pub fn ipc_endpoint(&self) -> String {
        ipc::channel_endpoint(self.os, &self.user, &self.runtime_dir)
    }

    /// The user's explicitly-configured node endpoint (§5.3), or an empty string when there is none.
    ///
    /// Empty means "auto-resolve", which is the connector's job: it walks the §5.3 ladder
    /// ([`crate::control::endpoint_ladder`]) rather than guessing one address here, because only the
    /// connector can tell which tier actually answers.
    pub fn endpoint(&self, config: &AgentConfig) -> String {
        config
            .node_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or_default()
            .to_string()
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
    fn a_configured_node_url_is_carried_through_as_the_override() {
        let env = linux_env();
        let cfg = AgentConfig {
            node_url: Some("https://my.node".to_string()),
            ..AgentConfig::default()
        };
        assert_eq!(env.endpoint(&cfg), "https://my.node");
    }

    #[test]
    fn no_configured_node_url_means_auto_resolve() {
        // Empty is the connector's signal to walk the §5.3 ladder. It must NOT be the OS pipe path:
        // nothing answers there, so handing it over would report "no node" against a healthy node.
        let env = linux_env();
        assert_eq!(env.endpoint(&AgentConfig::default()), "");
        for blank in ["", "   "] {
            let cfg = AgentConfig {
                node_url: Some(blank.to_string()),
                ..AgentConfig::default()
            };
            assert_eq!(env.endpoint(&cfg), "");
        }
        assert_ne!(env.endpoint(&AgentConfig::default()), env.ipc_endpoint());
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
    /// XDG BASEDIR: "If `$XDG_DATA_HOME` is either not set **or empty**, a default equal to
    /// `$HOME/.local/share` should be used." The nearest wrong implementation reads the variable
    /// with `env::var` and falls back only on `Err`, so a variable that is SET AND EMPTY sails
    /// through as the root and the app reports its AppData directory missing while `HOME` is
    /// perfectly well set.
    ///
    /// That is not a hypothetical: it is precisely the state an operator reaches by following the
    /// old error message (dig-app#310), because `Environment=XDG_DATA_HOME=` in a systemd unit sets
    /// the variable to the empty string.
    #[test]
    fn an_empty_xdg_data_home_falls_back_to_home_per_the_xdg_spec() {
        // The distinguishing fixture: SET AND EMPTY, with a usable HOME beside it.
        assert_eq!(
            linux_data_root(Some(""), Some("/home/alice")),
            "/home/alice/.local/share"
        );
        // Unset behaves the same way.
        assert_eq!(
            linux_data_root(None, Some("/home/alice")),
            "/home/alice/.local/share"
        );
        // The control: a real XDG_DATA_HOME still WINS, so the fix above is not "ignore XDG".
        assert_eq!(linux_data_root(Some("/custom/data"), Some("/home/alice")), "/custom/data");
        // Whitespace is a value, not emptiness -- only the spec's "empty" case falls back.
        assert_eq!(linux_data_root(Some(" "), Some("/home/alice")), " ");
        // Neither set: empty, which `brand_data_dir` turns into the loud MissingEnv error naming
        // HOME. An empty root on Linux therefore means HOME, and nothing else, is missing.
        assert_eq!(linux_data_root(None, None), "");
        assert_eq!(linux_data_root(Some(""), Some("")), "");
    }
}

/// The OS this build is running on. Unknown targets are treated as Linux (the Unix-socket + XDG
/// conventions), which is the only sane default for a POSIX-like host.
pub(crate) fn current_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}

/// The per-OS AppData root env var: `%LOCALAPPDATA%` (Windows), `$HOME` (macOS), `$XDG_DATA_HOME`
/// (Linux, falling back to `$HOME/.local/share` per the XDG default).
fn app_data_root(os: Os) -> String {
    match os {
        Os::Windows => std::env::var("LOCALAPPDATA").unwrap_or_default(),
        Os::MacOs => std::env::var("HOME").unwrap_or_default(),
        Os::Linux => linux_data_root(
            std::env::var("XDG_DATA_HOME").ok().as_deref(),
            std::env::var("HOME").ok().as_deref(),
        ),
    }
}

/// The Linux AppData root, as a PURE function of the two variables that decide it, so both of its
/// arms are reachable from a test on any platform.
/// Per the XDG Base Directory specification, `$XDG_DATA_HOME` falls back to `$HOME/.local/share`
/// when it is "either not set or empty" — so `Some("")` and `None` MUST behave identically. Reading
/// it with `env::var` and falling back only on `Err` misses the empty case, which is the exact state
/// `Environment=XDG_DATA_HOME=` in a systemd unit produces (dig-app#310).
///
/// The consequence is that an EMPTY root on Linux means `HOME` was missing, and nothing else — which
/// is what lets [`crate::storage::brand_data_dir`] name the one variable worth setting.
fn linux_data_root(xdg_data_home: Option<&str>, home: Option<&str>) -> String {
    match xdg_data_home {
        Some(x) if !x.is_empty() => x.to_string(),
        _ => home
            .filter(|h| !h.is_empty())
            .map(|h| format!("{h}/.local/share"))
            .unwrap_or_default(),
    }
}

/// The current login user, used to namespace the per-user IPC endpoint.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

/// Whether a usable desktop display is present. On Linux this is a real check (`$DISPLAY` /
/// `$WAYLAND_DISPLAY`); on Windows/macOS an interactive desktop is assumed, and a tray that still
/// cannot mount degrades at runtime.
fn has_display(os: Os) -> bool {
    match os {
        Os::Linux => {
            !std::env::var("DISPLAY").unwrap_or_default().is_empty()
                || !std::env::var("WAYLAND_DISPLAY")
                    .unwrap_or_default()
                    .is_empty()
        }
        Os::Windows | Os::MacOs => true,
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;

    /// `from_host` must agree with the compile target and produce a usable, non-guessed layout. The
    /// assertion is on the OS mapping because that is the one field a wrong answer would silently
    /// redirect every path in the app.
    #[test]
    fn from_host_reports_this_platform() {
        let env = AppEnvironment::from_host();
        assert_eq!(env.os, current_os());
        assert!(
            !env.user.is_empty(),
            "the user must never resolve to nothing"
        );
    }

    /// Both shells must resolve the SAME brand directory — the property that makes a `diga` restore
    /// land where `dig-app` will look for it. Two independent calls stand in for the two processes.
    #[test]
    fn two_resolutions_address_the_same_brand_directory() {
        let (a, b) = (AppEnvironment::from_host(), AppEnvironment::from_host());
        assert_eq!(a.brand_dir().ok(), b.brand_dir().ok());
    }
}
