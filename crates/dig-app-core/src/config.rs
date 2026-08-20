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

use crate::hotkey::HotkeyError;
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

    /// The global shortcut that opens the URN bar, written as a chord (`"Alt+Space"`,
    /// `"Ctrl+Shift+D"`). `None` means [`DEFAULT_SHORTCUT`](crate::hotkey::DEFAULT_SHORTCUT).
    ///
    /// User-configurable on purpose: the default displaces the Windows window menu
    /// ([`hotkey`](crate::hotkey) explains why that trade is taken), and a user who wants that chord
    /// back must be able to have it without editing source.
    #[serde(default)]
    pub open_bar_shortcut: Option<String>,

    /// The user's auto-update preference — on or off, and which feed to follow
    /// (dig_ecosystem#2293).
    ///
    /// Non-secret boot-time settings, so this is the right home: the Settings tab must be able to
    /// show a meaningful, persisted choice before any profile is unlocked. The AUTHORITY for what
    /// actually happens is the beacon's own config, which only an administrator can write; see
    /// [`crate::auto_update`] for why the remembered preference and the observed state are different
    /// facts rather than two sources of truth.
    ///
    /// Defaults to enabled, including for an `agent.json` written before this field existed — see
    /// [`AutoUpdate`](crate::auto_update::AutoUpdate).
    #[serde(default)]
    pub auto_update: crate::auto_update::AutoUpdate,

    /// Whether DIG raises an OS notification when money arrives (dig_ecosystem#2548).
    ///
    /// A notification interrupts, so it must be refusable somewhere a person can find — this is the
    /// stored side of that switch, and the Settings tab is where it is turned off. Defaults to ON,
    /// including for an `agent.json` written before this field existed; see
    /// [`Notifications`](crate::notifications::Notifications) for why that needs a default function
    /// rather than `#[serde(default)]` alone.
    #[serde(default)]
    pub notifications: crate::notifications::Notifications,

    /// Whether this computer has already been shown the "DIG made you a wallet" welcome
    /// (dig_ecosystem#3139).
    ///
    /// A one-shot latch, not a preference: nothing offers it in Settings and nothing turns it back
    /// on. It lives here anyway because this is the file that already survives a restart without
    /// needing a profile unlocked, and the welcome is drawn at start-up before any profile is open —
    /// a second persistence mechanism for one boolean would be the parallel pattern
    /// `professional-ui`'s reuse rule exists to prevent.
    ///
    /// `false` for an `agent.json` written before this field existed, which is correct rather than
    /// merely convenient: an existing install's wallet was not created this run, so
    /// [`should_welcome`](crate::account::wallet_welcome::should_welcome) refuses it on provenance
    /// and the latch is never consulted.
    #[serde(default)]
    pub wallet_welcomed: bool,
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
            open_bar_shortcut: None,
            auto_update: crate::auto_update::AutoUpdate::default(),
            notifications: crate::notifications::Notifications::default(),
            wallet_welcomed: false,
        }
    }
}

impl AgentConfig {
    /// The global shortcut to register for the URN bar.
    ///
    /// A **malformed** setting is an `Err` the caller reports rather than a silent fall-back to the
    /// default: a user who wrote `Ctrl+Banana` and got Alt+Space would conclude their setting was
    /// ignored, with nothing anywhere saying why. An ABSENT setting is not malformed — it is the
    /// ordinary case, and yields [`crate::hotkey::DEFAULT_SHORTCUT`].
    pub fn open_bar_shortcut(&self) -> std::result::Result<crate::hotkey::Hotkey, HotkeyError> {
        match self.open_bar_shortcut.as_deref() {
            None => Ok(crate::hotkey::Hotkey::default()),
            Some(text) => crate::hotkey::Hotkey::parse(text),
        }
    }
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
            open_bar_shortcut: Some("Ctrl+Shift+D".to_string()),
            auto_update: crate::auto_update::AutoUpdate {
                enabled: false,
                channel: crate::auto_update::UpdateChannel::Nightly,
            },
            notifications: crate::notifications::Notifications {
                funds_received: false,
            },
            wallet_welcomed: true,
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

    /// The ordinary case — no setting at all — yields the documented default chord.
    #[test]
    fn an_unset_shortcut_is_the_documented_default() {
        assert_eq!(
            AgentConfig::default().open_bar_shortcut().unwrap(),
            crate::hotkey::Hotkey::default()
        );
    }

    /// A configured chord WINS over the default — the whole point of the setting.
    #[test]
    fn a_configured_shortcut_replaces_the_default() {
        let cfg = AgentConfig {
            open_bar_shortcut: Some("Ctrl+Shift+D".to_string()),
            ..AgentConfig::default()
        };
        assert_eq!(
            cfg.open_bar_shortcut().unwrap(),
            crate::hotkey::Hotkey::parse("Ctrl+Shift+D").unwrap()
        );
    }

    /// A typo is an ERROR the shell can report, never a silent fall-back to the default — which would
    /// look to the user exactly like their setting being ignored for no reason.
    #[test]
    fn a_malformed_shortcut_is_an_error_not_a_silent_default() {
        let cfg = AgentConfig {
            open_bar_shortcut: Some("Ctrl+Banana".to_string()),
            ..AgentConfig::default()
        };
        assert_eq!(
            cfg.open_bar_shortcut(),
            Err(crate::hotkey::HotkeyError::UnknownKey("Banana".to_string()))
        );
    }

    /// **An `agent.json` written before auto-update existed loads as auto-update ON.**
    ///
    /// The upgrade path this feature ships on, and the one a naive implementation inverts: a plain
    /// `#[serde(default)]` on a `bool` yields `false`, which would silently opt every existing install
    /// OUT of updates on the version that added the switch. Pinned at BOTH levels a real file can be
    /// missing the setting at — the whole object absent (an older file), and the object present but
    /// missing the flag (a file written by a build with a differently-shaped preference).
    #[test]
    fn a_config_written_before_auto_update_existed_loads_as_enabled() {
        use crate::auto_update::UpdateChannel;
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());

        std::fs::write(&path, br#"{"tick_secs":7}"#).unwrap();
        let older = AgentConfig::load(&path).unwrap();
        assert!(
            older.auto_update.enabled,
            "an older config must update itself"
        );
        assert_eq!(older.auto_update.channel, UpdateChannel::Stable);
        assert_eq!(
            older.tick_secs, 7,
            "the rest of the file must still be read"
        );

        std::fs::write(&path, br#"{"auto_update":{"channel":"nightly"}}"#).unwrap();
        let partial = AgentConfig::load(&path).unwrap();
        assert!(partial.auto_update.enabled);
        assert_eq!(partial.auto_update.channel, UpdateChannel::Nightly);

        // The other side: a file that explicitly says OFF stays off across a load, or "default on"
        // would be a value that cannot be changed rather than a default.
        std::fs::write(&path, br#"{"auto_update":{"enabled":false}}"#).unwrap();
        assert!(!AgentConfig::load(&path).unwrap().auto_update.enabled);
    }

    /// **The preference survives a restart** — saved by one run, read back by the next.
    ///
    /// Distinct from [`save_then_load_round_trips`] in what it proves: that test round-trips one
    /// struct, while this one writes a NON-default choice and re-reads it through a fresh load, which
    /// is the only shape that can fail if `save` silently dropped the field.
    #[test]
    fn the_auto_update_choice_survives_a_restart() {
        use crate::auto_update::{AutoUpdate, UpdateChannel};
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());

        let chosen = AutoUpdate {
            enabled: false,
            channel: UpdateChannel::Nightly,
        };
        assert_ne!(
            chosen,
            AutoUpdate::default(),
            "the fixture must differ from the default, or a save that wrote nothing would pass"
        );

        AgentConfig {
            auto_update: chosen,
            ..AgentConfig::default()
        }
        .save(&path)
        .unwrap();

        assert_eq!(AgentConfig::load(&path).unwrap().auto_update, chosen);
    }

    /// **The notification switch survives a restart, and an older file loads as ON.**
    ///
    /// Both halves in one test because they are the two ways the setting can be wrong on disk: a
    /// save that dropped the field (the person turns notifications off, restarts, and is
    /// interrupted anyway), and a default that reads an absent field as OFF (every existing install
    /// silently loses the feature on the version that adds it).
    #[test]
    fn the_notification_switch_persists_and_older_files_load_as_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = AgentConfig::path_in(dir.path());

        std::fs::write(&path, br#"{"tick_secs":7}"#).unwrap();
        assert!(
            AgentConfig::load(&path)
                .unwrap()
                .notifications
                .funds_received,
            "a config written before this setting existed must keep notifications on"
        );

        AgentConfig {
            notifications: crate::notifications::Notifications {
                funds_received: false,
            },
            ..AgentConfig::default()
        }
        .save(&path)
        .unwrap();
        assert!(
            !AgentConfig::load(&path)
                .unwrap()
                .notifications
                .funds_received,
            "the choice to turn notifications off did not survive the write"
        );
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
