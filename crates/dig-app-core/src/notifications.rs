//! The user's notification preference (dig_ecosystem#2548) — the off switch, and where it lives.
//!
//! A toast interrupts. `professional-ui`'s never-trap rule means anything that interrupts has to be
//! refusable, and refusable somewhere a person can find without editing JSON — so this is a field of
//! [`AgentConfig`](crate::config::AgentConfig), shown on the Settings tab beside the update channel.
//!
//! # Why the default is ON, and why that needs saying
//!
//! The whole feature is "tell me when I am paid", so a default of OFF would ship a switch nobody
//! knows to turn on. The trap in writing that is the same one
//! [`AutoUpdate`](crate::auto_update::AutoUpdate) documents: a bare `#[serde(default)]` on a `bool`
//! yields `false`, which would read every `agent.json` written before this field existed as an
//! explicit opt-OUT. The default function below is what keeps an older file loading as ON, and there
//! is a test pinned to exactly that.
//!
//! # What OFF means, precisely
//!
//! No toast is drawn. Detection still runs and the arrival ledger still advances, because the ledger
//! is a record of what has been ACCOUNTED FOR, not of what has been shown — see
//! [`crate::arrivals`]. If turning the setting off also stopped the ledger, turning it back on would
//! announce every payment received in between, which is the first-sync flood in a slower form.

use serde::{Deserialize, Serialize};

/// Which notifications the user wants drawn.
///
/// One field today. It is a struct rather than a bare `bool` so a second class of notification does
/// not have to reshape `agent.json` — the same reason [`AutoUpdate`](crate::auto_update::AutoUpdate)
/// is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notifications {
    /// Whether a confirmed incoming payment raises an OS notification. Defaults to ON, including
    /// for a config file written before this setting existed.
    #[serde(default = "default_enabled")]
    pub funds_received: bool,
}

/// Notifications are on unless somebody said otherwise — see the module docs.
fn default_enabled() -> bool {
    true
}

impl Default for Notifications {
    fn default() -> Self {
        Self {
            funds_received: default_enabled(),
        }
    }
}

impl Notifications {
    /// The word this preference is shown and stored as. Used by the Settings chooser so the label
    /// and the stored value cannot drift apart.
    pub fn word(enabled: bool) -> &'static str {
        match enabled {
            true => "On",
            false => "Off",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The feature is on by default**, or the switch would be one nobody finds.
    #[test]
    fn notifications_are_on_by_default() {
        assert!(Notifications::default().funds_received);
    }

    /// **A file written before the setting existed loads as ON, at both levels it can be missing.**
    ///
    /// The defect this pins is a plain `#[serde(default)]` on the `bool`, which yields `false` and
    /// silently opts every existing install out on the version that adds the switch.
    #[test]
    fn a_config_written_before_this_setting_existed_loads_as_on() {
        let whole_object_absent: Notifications =
            serde_json::from_str("{}").expect("an empty object is a valid Notifications");
        assert!(whole_object_absent.funds_received);

        // And the other side: an explicit OFF stays off, or the default would be a value nobody
        // could change.
        let explicit: Notifications =
            serde_json::from_str(r#"{"funds_received":false}"#).expect("valid");
        assert!(!explicit.funds_received);
    }

    #[test]
    fn the_word_matches_the_stored_value() {
        assert_eq!(Notifications::word(true), "On");
        assert_eq!(Notifications::word(false), "Off");
    }
}
