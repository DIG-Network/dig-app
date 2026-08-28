//! The two text settings this pane writes, and the file they live in.
//!
//! # Why the pane writes `agent.json` itself
//!
//! Every other verb in this window is a [`TrayAction`](crate::tray_menu::TrayAction) the model
//! decided and the shell runs on a worker. These two are not verbs: they are FIELDS of
//! [`AgentConfig`], which the tray has never offered and which §5.3 requires be reachable without a
//! text editor. Inventing menu actions for them would put a form into a vocabulary of rows, so the
//! pane writes the file — through the same brand-directory resolution the window's own theme
//! preference uses ([`ThemeChoice::for_host`](crate::confirm::gui::theme::ThemeChoice::for_host)).
//!
//! The line this does not cross is unchanged: nothing here decides whether a VERB is offered. A
//! setting is a value, and the file is its only authority.
//!
//! # The honesty rule, generalised from PR #120
//!
//! That gate found a privileged change that could exit zero having changed nothing, and its answer
//! was to re-read the beacon and report what it now says. [`save`] follows it exactly: it writes,
//! then RE-READS, and returns the config the file now holds. So a write that silently did not land
//! shows the old value — never the value the person typed.

use std::path::PathBuf;
use std::time::Duration;

use crate::collateral::node::{
    self as collateral_node, BufferReading, BufferUnknown, CollateralUnknown, MarginReading,
    RequirementReading,
};
use crate::config::AgentConfig;

/// How long a margin read or write waits on the node.
///
/// The same budget the connection test uses, and for the same reason: this runs on the UI thread in
/// response to a press, so it must be short enough that a stalled node cannot freeze the pane, and
/// long enough that a busy local node still answers.
const MARGIN_TIMEOUT: Duration = Duration::from_secs(3);

/// One text setting a person can edit on this pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// [`AgentConfig::node_url`] — the §5.3 override.
    NodeUrl,
    /// [`AgentConfig::open_bar_shortcut`] — the chord that opens the address bar.
    Shortcut,
}

impl Setting {
    /// What is stored today, as the text a person would type to get it. Empty means "not set",
    /// which for both settings means DIG chooses.
    pub(crate) fn stored(self, config: &AgentConfig) -> String {
        let value = match self {
            Self::NodeUrl => config.node_url.as_deref(),
            Self::Shortcut => config.open_bar_shortcut.as_deref(),
        };
        value.unwrap_or_default().trim().to_string()
    }

    /// Put `typed` into `config`, or say what is wrong with it.
    ///
    /// Blank clears the setting rather than storing an empty string: "" and absent must not be two
    /// different ways to say the same thing in a file a person may also edit by hand.
    pub(crate) fn apply(self, config: &mut AgentConfig, typed: &str) -> Result<(), String> {
        let typed = typed.trim();
        let value = match typed.is_empty() {
            true => None,
            false => Some(self.validate(typed)?),
        };
        match self {
            Self::NodeUrl => config.node_url = value,
            Self::Shortcut => config.open_bar_shortcut = value,
        }
        Ok(())
    }

    /// Whether `typed` is a value this setting can hold, and the sentence saying why not.
    ///
    /// Never called with a blank string — that is [`apply`](Self::apply)'s "clear it" case, which is
    /// valid for both settings and is not a value to check.
    fn validate(self, typed: &str) -> Result<String, String> {
        match self {
            Self::NodeUrl => validate_node_url(typed),
            // The parser the agent itself will run at start-up, so a chord this accepts is a chord
            // that registers — and its errors already name the remedy, which is why they are shown
            // as written rather than re-worded here.
            Self::Shortcut => crate::hotkey::Hotkey::parse(typed)
                .map(|_| typed.to_string())
                .map_err(|e| e.to_string()),
        }
    }

    /// What DIG will actually do with what is stored, in the words of the code that will do it.
    ///
    /// For the node this is [`crate::control::endpoint_ladder`] — the SAME function the connector
    /// walks — so the sentence cannot drift from the behaviour, and a person who typed
    /// `localhost:9778` is shown the `http://localhost:9778` DIG will dial. For the shortcut it is
    /// [`AgentConfig::open_bar_shortcut`], the parse the agent performs at start-up.
    pub(crate) fn effective(self, config: &AgentConfig) -> String {
        match self {
            Self::NodeUrl => crate::control::endpoint_ladder(config.node_url.as_deref()).join(", "),
            Self::Shortcut => match config.open_bar_shortcut() {
                Ok(hotkey) => hotkey.to_string(),
                // Unreachable through this pane, which will not save a chord that does not parse —
                // and reachable through a hand-edited file, which is exactly why it is not an
                // `expect`: the honest answer is the parser's own complaint.
                Err(e) => e.to_string(),
            },
        }
    }
}

/// Whether `typed` is something DIG could dial.
///
/// Deliberately shallow. The only claims made here are the ones that are certainly wrong — a scheme
/// DIG does not speak, or an address with no host — because the real question ("is a node there?")
/// cannot be answered by looking at the string, and a validator that pretended otherwise would
/// reject working addresses. That question has its own control: the connection test.
fn validate_node_url(typed: &str) -> Result<String, String> {
    if typed.split_whitespace().count() > 1 {
        return Err("A node address is one word, with no spaces in it.".to_string());
    }
    let host = match typed.split_once("://") {
        None => typed,
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return Err(format!(
                    "DIG talks to a node over http or https, not {scheme}."
                ));
            }
            rest
        }
    };
    match host.trim_matches('/').is_empty() {
        true => Err("This address names no host, so DIG would not know what to dial.".to_string()),
        false => Ok(typed.to_string()),
    }
}

/// Where the settings this pane edits are read from and written to.
///
/// A trait so the pane's behaviour around a write — including a write that does not land — is
/// testable without a filesystem, which is the whole point of the read-back in [`save`].
pub(crate) trait ConfigStore: Send + Sync {
    /// The config as it is stored right now.
    fn read(&self) -> Result<AgentConfig, String>;
    /// Store `config`.
    fn write(&self, config: &AgentConfig) -> Result<(), String>;
}

/// `agent.json`, under this host's brand data directory.
pub(crate) struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// The store for this host, or `None` when the brand directory cannot be resolved.
    ///
    /// `None` is a real state and the pane draws it as one: an unusual environment or a locked-down
    /// service account has nowhere to keep settings, and a form that saved into nothing would be
    /// worse than a card that says so.
    pub(crate) fn for_host() -> Option<Self> {
        let path = crate::environment::AppEnvironment::from_host()
            .config_path()
            .ok()?;
        Some(Self { path })
    }
}

impl ConfigStore for FileStore {
    fn read(&self) -> Result<AgentConfig, String> {
        AgentConfig::load(&self.path).map_err(|e| e.to_string())
    }

    fn write(&self, config: &AgentConfig) -> Result<(), String> {
        config.save(&self.path).map_err(|e| e.to_string())
    }
}

/// Write `typed` into `setting`, then report what the file NOW says.
///
/// The read-back is the point, not a formality (see the module docs): the returned config is
/// evidence rather than an assumption, so a pane that renders it can never show a change that did
/// not happen.
pub(crate) fn save(
    store: &dyn ConfigStore,
    setting: Setting,
    typed: &str,
) -> Result<AgentConfig, String> {
    let mut config = store.read()?;
    setting.apply(&mut config, typed)?;
    store.write(&config)?;
    store.read()
}

/// Turn the funds-arrived notification on or off, then report what the file NOW says.
///
/// A separate function from [`save`] because this setting is a CHOICE and not typed text: there is
/// nothing to validate and nothing to clear, so routing it through [`Setting`] would mean inventing
/// a string form for a boolean and parsing it back. The read-back rule is identical and is the whole
/// point — a chooser showing "Off" over a file that still says on is the defect PR #120 named.
pub(crate) fn save_notifications(
    store: &dyn ConfigStore,
    funds_received: bool,
) -> Result<AgentConfig, String> {
    let mut config = store.read()?;
    config.notifications.funds_received = funds_received;
    store.write(&config)?;
    store.read()
}

/// Set the node's collateral safety margin, and report **the margin now in force**.
///
/// # Why this does not touch `agent.json`
///
/// It used to (dig-app#298). The margin now lives in the node and only in the node (dig-app#302),
/// because the node is the process that actually posts the collateral: when two copies of a money
/// setting disagree, the node's is what a person's $DIG does and the app's is merely what they were
/// shown. So this walks the control-path endpoint ladder and calls `control.collateral.margin.set`.
///
/// The returned [`MarginReading`] is the node's OWN answer, not an echo of the request — a node
/// clamps a value above its ceiling, and displaying the request would leave the two surfaces
/// disagreeing. It is the same read-back discipline the config write had, moved to the seam that now
/// owns the value.
///
/// A write that reached nobody is [`MarginReading::Unknown`], never a stale `Known`: a press that
/// did not land must not leave a confident figure on screen.
pub(crate) fn write_margin(configured: Option<&str>, margin_bp: u64) -> MarginReading {
    let token = crate::control::load_control_token();
    let ladder = crate::control::endpoint_ladder(configured);
    // The first tier that gives a definite answer wins. A tier that is simply not there must not end
    // the walk — `dig.local` and `localhost` are normally the same node, and stopping at the first
    // absent one would refuse a write a running node would have accepted.
    let mut last = MarginReading::Unknown(CollateralUnknown::NoNode);
    for endpoint in &ladder {
        let answer =
            collateral_node::write_margin(endpoint, margin_bp, token.as_deref(), MARGIN_TIMEOUT);
        match &answer {
            MarginReading::Unknown(CollateralUnknown::NoNode)
            | MarginReading::Unknown(CollateralUnknown::Unreachable(_)) => last = answer,
            _ => return answer,
        }
    }
    last
}

/// Read this epoch's collateral requirement, over the same ladder the margin is read on.
///
/// The requirement is a CONSENSUS value: every node derives it identically from the same chain
/// census, and dig-app never derives it for itself — a second derivation of a consensus rule is a
/// fork. So this asks, and is prepared to be told the node does not know, which is a first-class
/// answer rather than an error.
pub(crate) fn read_requirement(configured: Option<&str>) -> RequirementReading {
    let token = crate::control::load_control_token();
    let mut last = RequirementReading::Unknown(CollateralUnknown::NoNode);
    for endpoint in &crate::control::endpoint_ladder(configured) {
        let answer = collateral_node::read_requirement(endpoint, token.as_deref(), MARGIN_TIMEOUT);
        match &answer {
            RequirementReading::Unknown(CollateralUnknown::NoNode)
            | RequirementReading::Unknown(CollateralUnknown::Unreachable(_)) => last = answer,
            _ => return answer,
        }
    }
    last
}

/// Read the node's recommended $DIG buffer and funding position, over the same ladder.
///
/// **This is the only way dig-app learns how much $DIG an operator should hold.** The figure rests
/// on the `(owner, store, root)` pairs this node serves, on collateral still locked against
/// positions it has not reclaimed, and on a horizon it chose — none of which a client can see. A
/// client that assembled it from the census requirement and its own store count would produce a
/// strictly smaller number, and understating a funding warning is the direction that costs an
/// operator an epoch.
///
/// So there is no local fallback, and a node that cannot answer leaves [`BufferReading::Unknown`],
/// which shows no figure at all.
pub(crate) fn read_buffer(configured: Option<&str>) -> BufferReading {
    let token = crate::control::load_control_token();
    let mut last = BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NoNode));
    for endpoint in &crate::control::endpoint_ladder(configured) {
        let answer = collateral_node::read_buffer(endpoint, token.as_deref(), MARGIN_TIMEOUT);
        match &answer {
            // A tier that is simply not there must not end the walk: `dig.local` and `localhost`
            // are normally the same node, and stopping at the first absent one would report a
            // running node as unreachable.
            BufferReading::Unknown(BufferUnknown::ReadFailed(
                CollateralUnknown::NoNode | CollateralUnknown::Unreachable(_),
            )) => last = answer,
            _ => return answer,
        }
    }
    last
}

/// Read the node's collateral safety margin, over the same ladder [`write_margin`] writes on.
///
/// Separate from the write for the reason every read/write pair here is: a surface that has not been
/// touched still has to SHOW the margin, and it must show the node's, not a remembered one.
pub(crate) fn read_margin(configured: Option<&str>) -> MarginReading {
    let token = crate::control::load_control_token();
    let mut last = MarginReading::Unknown(CollateralUnknown::NoNode);
    for endpoint in &crate::control::endpoint_ladder(configured) {
        let answer = collateral_node::read_margin(endpoint, token.as_deref(), MARGIN_TIMEOUT);
        match &answer {
            MarginReading::Unknown(CollateralUnknown::NoNode)
            | MarginReading::Unknown(CollateralUnknown::Unreachable(_)) => last = answer,
            _ => return answer,
        }
    }
    last
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A store in memory, which can be told to lose writes.
    pub(crate) struct FakeStore {
        held: Mutex<AgentConfig>,
        /// When true, [`write`](ConfigStore::write) reports success and changes nothing — the shape
        /// of the defect PR #120's gate found on a real machine.
        pub(crate) writes_are_lost: bool,
        /// When set, reads fail with this message.
        pub(crate) unreadable: Option<String>,
    }

    impl FakeStore {
        pub(crate) fn holding(config: AgentConfig) -> Self {
            Self {
                held: Mutex::new(config),
                writes_are_lost: false,
                unreadable: None,
            }
        }
    }

    impl ConfigStore for FakeStore {
        fn read(&self) -> Result<AgentConfig, String> {
            match &self.unreadable {
                Some(why) => Err(why.clone()),
                None => Ok(self.held.lock().expect("not poisoned").clone()),
            }
        }
        fn write(&self, config: &AgentConfig) -> Result<(), String> {
            if !self.writes_are_lost {
                *self.held.lock().expect("not poisoned") = config.clone();
            }
            Ok(())
        }
    }

    /// **A write that silently does nothing is reported as the OLD value, never as the new one.**
    ///
    /// This is PR #120's rule in this pane's form, and it is the one test here that is about
    /// honesty rather than about validation. The fixture is a store that reports success and keeps
    /// the old value — the exact shape of a privileged change exiting zero having changed nothing —
    /// and the property is that `save` returns evidence read back from the store rather than the
    /// config it just built. A `save` that returned its own in-memory copy passes every other test
    /// in this file and fails this one.
    #[test]
    fn a_write_that_did_not_land_is_read_back_as_the_value_that_is_still_stored() {
        let mut store = FakeStore::holding(AgentConfig::default());
        store.writes_are_lost = true;

        let after = save(&store, Setting::NodeUrl, "http://my.node:9778")
            .expect("the store reported the write succeeded");
        assert_eq!(
            after.node_url, None,
            "the pane would have shown an address the settings file does not hold"
        );

        // The control: the SAME call against a store that keeps its writes must show the new value,
        // or the assertion above would pass on a `save` that always reported the old one.
        let honest = FakeStore::holding(AgentConfig::default());
        let after = save(&honest, Setting::NodeUrl, "http://my.node:9778").expect("saved");
        assert_eq!(after.node_url.as_deref(), Some("http://my.node:9778"));
    }

    /// **Blank clears the setting rather than storing an empty string.**
    ///
    /// Both directions, because the escape hatch out of a bad address depends on it: a person who
    /// empties the field must end up on the automatic ladder, not on an endpoint of `""`.
    #[test]
    fn emptying_a_field_removes_the_setting() {
        let store = FakeStore::holding(AgentConfig {
            node_url: Some("http://my.node".to_string()),
            open_bar_shortcut: Some("Ctrl+Shift+D".to_string()),
            ..AgentConfig::default()
        });
        assert_eq!(
            save(&store, Setting::NodeUrl, "   ").unwrap().node_url,
            None
        );
        assert_eq!(
            save(&store, Setting::Shortcut, "")
                .unwrap()
                .open_bar_shortcut,
            None
        );
    }

    /// **A rejected value is not written, and the reason names what to do.**
    ///
    /// The second half matters as much as the first: an error that only says "invalid" leaves a
    /// person with a field they cannot fix.
    #[test]
    fn a_value_the_agent_could_not_use_is_refused_before_it_reaches_the_file() {
        let store = FakeStore::holding(AgentConfig::default());
        for (setting, bad) in [
            (Setting::NodeUrl, "ftp://my.node"),
            (Setting::NodeUrl, "http://"),
            (Setting::NodeUrl, "my node"),
            (Setting::Shortcut, "Ctrl+Banana"),
        ] {
            let problem = save(&store, setting, bad).expect_err(&format!("{bad} was accepted"));
            assert!(
                problem.len() > 10 && problem.contains(' '),
                "{bad} was refused with {problem:?}, which does not tell anyone what to type"
            );
        }
        let untouched = store.read().unwrap();
        assert_eq!(untouched.node_url, None);
        assert_eq!(untouched.open_bar_shortcut, None);
    }

    /// **A bare host is accepted, and shown back as the address DIG will actually dial.**
    ///
    /// The value is stored as typed and the DISPLAY comes from `endpoint_ladder`, so the `http://`
    /// a person did not type is the connector's own normalisation rather than a second copy of it
    /// here. Asserted against that function's output rather than a literal, so the day the ladder
    /// changes this describes the new behaviour instead of failing on the old text.
    #[test]
    fn what_dig_will_dial_is_taken_from_the_connectors_own_ladder() {
        let store = FakeStore::holding(AgentConfig::default());
        let saved = save(&store, Setting::NodeUrl, "localhost:9778").unwrap();
        assert_eq!(saved.node_url.as_deref(), Some("localhost:9778"));
        assert_eq!(
            Setting::NodeUrl.effective(&saved),
            crate::control::endpoint_ladder(Some("localhost:9778")).join(", ")
        );

        let automatic = AgentConfig::default();
        assert_eq!(
            Setting::NodeUrl.effective(&automatic),
            crate::control::endpoint_ladder(None).join(", "),
            "an unset address must describe the ladder DIG really walks, not a remembered sentence"
        );
    }

    /// **The shortcut readout is the chord the agent will register, and the default when unset.**
    #[test]
    fn the_shortcut_readout_is_what_the_agent_will_register() {
        let store = FakeStore::holding(AgentConfig::default());
        assert_eq!(
            Setting::Shortcut.effective(&AgentConfig::default()),
            crate::hotkey::DEFAULT_SHORTCUT
        );
        let saved = save(&store, Setting::Shortcut, "ctrl+shift+d").unwrap();
        assert_eq!(
            Setting::Shortcut.effective(&saved),
            crate::hotkey::Hotkey::parse("ctrl+shift+d")
                .unwrap()
                .to_string()
        );
    }

    /// **A store that cannot be read refuses the save instead of writing a default over it.**
    ///
    /// The dangerous shape is a `save` that treats an unreadable file as an empty one: it would
    /// replace a config it could not parse — including settings this pane does not edit — with
    /// defaults. The stored value is checked afterwards to prove nothing was written.
    #[test]
    fn an_unreadable_config_is_never_overwritten_with_defaults() {
        let mut store = FakeStore::holding(AgentConfig {
            node_url: Some("http://kept".to_string()),
            ..AgentConfig::default()
        });
        store.unreadable = Some("agent.json is not valid JSON".to_string());
        let refused = save(&store, Setting::Shortcut, "Ctrl+Shift+D").expect_err("must refuse");
        assert!(refused.contains("agent.json"));

        store.unreadable = None;
        assert_eq!(
            store.read().unwrap().node_url.as_deref(),
            Some("http://kept"),
            "the settings file was replaced by defaults after a failed read"
        );
    }

    /// **The notification switch moves both ways, and a lost write is reported as the OLD value.**
    ///
    /// Both directions because a switch that can only be turned off is not a switch, and the
    /// lost-write half because this is the control that stops an interruption: a person who turned
    /// notifications off and was shown "Off" over a file still saying on would be interrupted
    /// anyway, with the settings page insisting they would not be.
    #[test]
    fn the_notification_switch_moves_both_ways_and_never_lies_about_a_lost_write() {
        let store = FakeStore::holding(AgentConfig::default());
        assert!(
            store.read().unwrap().notifications.funds_received,
            "the fixture must start ON, or turning it off proves nothing"
        );
        assert!(
            !save_notifications(&store, false)
                .unwrap()
                .notifications
                .funds_received
        );
        assert!(
            save_notifications(&store, true)
                .unwrap()
                .notifications
                .funds_received
        );

        let mut lossy = FakeStore::holding(AgentConfig::default());
        lossy.writes_are_lost = true;
        assert!(
            save_notifications(&lossy, false)
                .expect("the store reported success")
                .notifications
                .funds_received,
            "the pane would have shown notifications off while the file still says on"
        );
    }

    /// **Turning notifications off leaves every other setting alone.**
    #[test]
    fn saving_the_notification_switch_preserves_the_rest_of_the_config() {
        let store = FakeStore::holding(AgentConfig {
            node_url: Some("http://kept".to_string()),
            active_profile: Some("did:dig:abc".to_string()),
            ..AgentConfig::default()
        });
        let after = save_notifications(&store, false).unwrap();
        assert_eq!(after.node_url.as_deref(), Some("http://kept"));
        assert_eq!(after.active_profile.as_deref(), Some("did:dig:abc"));
    }

    /// **Saving one setting leaves every other field of the config alone.**
    ///
    /// A read-modify-write that rebuilt the config from the form would silently drop the remembered
    /// auto-update preference and the active profile — neither of which this pane shows.
    #[test]
    fn saving_one_setting_preserves_the_rest_of_the_config() {
        let store = FakeStore::holding(AgentConfig {
            active_profile: Some("did:dig:abc".to_string()),
            tick_secs: 41,
            auto_update: crate::auto_update::AutoUpdate {
                enabled: false,
                channel: crate::auto_update::UpdateChannel::Nightly,
            },
            ..AgentConfig::default()
        });
        let after = save(&store, Setting::NodeUrl, "http://my.node").unwrap();
        assert_eq!(after.active_profile.as_deref(), Some("did:dig:abc"));
        assert_eq!(after.tick_secs, 41);
        assert!(!after.auto_update.enabled);
        assert_eq!(
            after.auto_update.channel,
            crate::auto_update::UpdateChannel::Nightly
        );
    }
}
