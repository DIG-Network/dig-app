//! Per-user autostart artifacts for the `dig-app` shell.
//!
//! SPEC §4's form-factor table calls for the shell to start itself at login on every desktop OS.
//! Windows autostart is wired by the dig-installer packaging (U8, out of this crate's scope); this
//! module covers the two residual per-user mechanisms dig-app itself owns:
//!
//! - **macOS** — a `launchd` **LaunchAgent** plist under `~/Library/LaunchAgents`.
//! - **Linux** — a systemd **user** unit under `$XDG_CONFIG_HOME/systemd/user` (falls back to
//!   `~/.config/systemd/user` when `$XDG_CONFIG_HOME` is unset, per the XDG base-directory spec).
//!
//! Each platform exposes the same three-function shape: render the artifact's content (pure, so it's
//! trivially unit-tested), resolve where it belongs on disk, and install it (create the parent
//! directory + write the file). Installing does NOT call `launchctl`/`systemctl` — loading the unit
//! is the caller's job (the installer, or a first-run helper), so this stays a pure filesystem
//! operation the unit tests can exercise without a real service manager.

use std::io;
use std::path::{Path, PathBuf};

/// The reverse-DNS label every autostart artifact is named/labelled with, so "is dig-app's autostart
/// installed" has one answer across both platforms.
pub const AUTOSTART_LABEL: &str = "net.dig.dig-app";

/// macOS: `launchd` LaunchAgent autostart.
pub mod macos {
    use super::*;

    /// Render the LaunchAgent plist that runs `binary_path` at login and restarts it if it exits.
    pub fn launch_agent_plist(binary_path: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AUTOSTART_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
        )
    }

    /// The per-user LaunchAgent file path: `<home>/Library/LaunchAgents/<label>.plist`.
    pub fn launch_agent_path(home: &Path) -> PathBuf {
        home.join("Library/LaunchAgents")
            .join(format!("{AUTOSTART_LABEL}.plist"))
    }

    /// Write the LaunchAgent plist for `binary_path` under `home`, creating `LaunchAgents/` if it
    /// doesn't exist yet. Returns the path written.
    pub fn install_launch_agent(home: &Path, binary_path: &str) -> io::Result<PathBuf> {
        let path = launch_agent_path(home);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, launch_agent_plist(binary_path))?;
        Ok(path)
    }
}

/// Linux: systemd **user** service autostart (the SPEC's `XDG autostart .desktop` alternative is
/// covered equally well by a user unit, which additionally gets restart-on-failure supervision).
pub mod linux {
    use super::*;

    const UNIT_NAME: &str = "dig-app.service";

    /// Render the systemd user unit that runs `binary_path` at login and restarts it on failure.
    pub fn systemd_user_unit(binary_path: &str) -> String {
        format!(
            r#"[Unit]
Description=DIG user identity agent

[Service]
ExecStart={binary_path}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#
        )
    }

    /// The per-user systemd unit file path: `<xdg_config_home>/systemd/user/dig-app.service`.
    pub fn systemd_user_unit_path(xdg_config_home: &Path) -> PathBuf {
        xdg_config_home.join("systemd/user").join(UNIT_NAME)
    }

    /// Resolve `$XDG_CONFIG_HOME`, falling back to `<home>/.config` per the XDG base-directory spec
    /// when the env var is unset or empty.
    pub fn xdg_config_home(env_value: Option<&str>, home: &Path) -> PathBuf {
        match env_value {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => home.join(".config"),
        }
    }

    /// Write the systemd user unit for `binary_path` under `xdg_config_home`, creating
    /// `systemd/user/` if it doesn't exist yet. Returns the path written.
    pub fn install_systemd_user_unit(
        xdg_config_home: &Path,
        binary_path: &str,
    ) -> io::Result<PathBuf> {
        let path = systemd_user_unit_path(xdg_config_home);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, systemd_user_unit(binary_path))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_plist_carries_the_label_and_binary_path() {
        let plist = macos::launch_agent_plist("/Applications/DigApp.app/Contents/MacOS/dig-app");
        assert!(plist.contains(AUTOSTART_LABEL));
        assert!(plist.contains("/Applications/DigApp.app/Contents/MacOS/dig-app"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<true/>"));
    }

    #[test]
    fn macos_agent_path_is_under_home_library_launch_agents() {
        let home = Path::new("/Users/alice");
        let path = macos::launch_agent_path(home);
        assert_eq!(
            path,
            Path::new("/Users/alice/Library/LaunchAgents/net.dig.dig-app.plist")
        );
    }

    #[test]
    fn macos_install_writes_the_plist_and_creates_missing_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let written = macos::install_launch_agent(tmp.path(), "/usr/local/bin/dig-app")
            .expect("install succeeds");
        assert_eq!(written, macos::launch_agent_path(tmp.path()));
        let contents = std::fs::read_to_string(&written).expect("plist written");
        assert!(contents.contains("/usr/local/bin/dig-app"));
    }

    #[test]
    fn linux_unit_carries_the_binary_path_and_restarts_on_failure() {
        let unit = linux::systemd_user_unit("/usr/bin/dig-app");
        assert!(unit.contains("ExecStart=/usr/bin/dig-app"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn linux_unit_path_is_under_xdg_config_home_systemd_user() {
        let xdg_config_home = Path::new("/home/alice/.config");
        let path = linux::systemd_user_unit_path(xdg_config_home);
        assert_eq!(
            path,
            Path::new("/home/alice/.config/systemd/user/dig-app.service")
        );
    }

    #[test]
    fn linux_xdg_config_home_prefers_the_env_var_when_set() {
        let home = Path::new("/home/alice");
        let resolved = linux::xdg_config_home(Some("/custom/config"), home);
        assert_eq!(resolved, Path::new("/custom/config"));
    }

    #[test]
    fn linux_xdg_config_home_falls_back_to_home_dot_config_when_unset_or_empty() {
        let home = Path::new("/home/alice");
        assert_eq!(
            linux::xdg_config_home(None, home),
            Path::new("/home/alice/.config")
        );
        assert_eq!(
            linux::xdg_config_home(Some(""), home),
            Path::new("/home/alice/.config")
        );
    }

    #[test]
    fn linux_install_writes_the_unit_and_creates_missing_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let written = linux::install_systemd_user_unit(tmp.path(), "/usr/bin/dig-app")
            .expect("install succeeds");
        assert_eq!(written, linux::systemd_user_unit_path(tmp.path()));
        let contents = std::fs::read_to_string(&written).expect("unit written");
        assert!(contents.contains("/usr/bin/dig-app"));
    }
}
