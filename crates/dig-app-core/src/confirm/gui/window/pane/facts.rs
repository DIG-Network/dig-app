//! The FACTS a content pane displays, projected from the same snapshot the rows come from.
//!
//! # Why this is not a second model
//!
//! [`crate::window_model`] decides which verbs exist and whether each is enabled. It decides that
//! ONCE, and nothing here reopens it: [`PaneFacts`] holds no `enabled`, no action, and no rule. It
//! holds readings — is the agent running, what did the node say about itself, how full is the cache
//! — which the tray renders as row LABELS and a window can render as readouts, meters and badges.
//!
//! The test for whether something belongs here: could the tray show it as a label without deciding
//! anything? If yes it is a fact. If showing it requires answering "should this be offered", it is a
//! rule, and it belongs upstream.
//!
//! # Why a projection at all, rather than handing panes the whole view
//!
//! A pane given `TrayView` can reach `account`, and from `account` it is one short step to
//! re-deriving an enablement. Narrowing the input to the readings makes the boundary structural
//! instead of a comment asking people to be careful.

use crate::tray_menu::{AccountState, TrayView};

/// Everything a content pane may READ about this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaneFacts {
    /// Whether the background agent loop is running.
    pub(crate) agent_running: bool,
    /// Whether the agent is talking to a node right now.
    pub(crate) node_connected: bool,
    /// The node's own summary of what it is doing, already written by the engine.
    pub(crate) node_summary: String,
    /// The account's state in one word, for a badge. `None` on a host that cannot hold an account.
    pub(crate) account_word: Option<&'static str>,
    /// Whether a second factor is enrolled.
    pub(crate) second_factor: bool,
    /// The node's cache cap and usage, or `None` when no node has reported one.
    pub(crate) cache: Option<crate::cache::CacheSnapshot>,
    /// The account's `xch1…` receive address, when there is an unlocked account to derive one from.
    pub(crate) receive_address: Option<String>,
    /// The installed version of this app.
    pub(crate) version: &'static str,
    /// What the update beacon says about itself, or `None` when it could not be asked.
    ///
    /// A READING, and the only honest source for what this machine will do about updates: the
    /// remembered preference in `agent.json` is what somebody once asked for, which is a different
    /// fact and is wrong precisely when a privileged change did not take
    /// ([`crate::auto_update::BeaconStatus`]).
    pub(crate) update: Option<crate::auto_update::BeaconStatus>,
}

impl PaneFacts {
    /// Project the readings out of the snapshot the tray and the window are both built from.
    pub(crate) fn of_tray(view: &TrayView) -> Self {
        Self {
            agent_running: view.running,
            node_connected: view.node_connected,
            node_summary: view.node.clone(),
            account_word: view.account.as_ref().map(account_word),
            second_factor: view.second_factor,
            cache: view.cache,
            receive_address: view.receive_address.clone(),
            version: env!("CARGO_PKG_VERSION"),
            update: view.update,
        }
    }

    /// The node's connection as a badge: one word, and how worried to be about it.
    ///
    /// # Why three words and two tones
    ///
    /// "Not connected" covers two different situations — the agent has not started yet, or it has
    /// and has not reached a node — and they deserve different WORDS, because the remedy differs.
    /// They do not deserve different SEVERITIES: `window_model` reports a not-yet-running agent as
    /// `PaneNote::Waiting("The DIG agent is still starting.")`, so it is a wait, not a fault, and a
    /// badge calling it a fault would contradict the banner drawn directly above it.
    pub(crate) fn node_state(&self) -> (&'static str, super::data::Tone) {
        match (self.agent_running, self.node_connected) {
            (_, true) => (NODE_CONNECTED, super::data::Tone::Good),
            (true, false) => (NODE_SEARCHING, super::data::Tone::Warn),
            (false, false) => (NODE_STARTING, super::data::Tone::Warn),
        }
    }
}

/// The badge word for a node the agent is talking to.
pub(crate) const NODE_CONNECTED: &str = "Connected";
/// The badge word for a running agent that has not reached a node yet.
pub(crate) const NODE_SEARCHING: &str = "Looking for a node";
/// The badge word for an agent that has not started yet, so nothing is looking.
///
/// Worded to agree with `window_model`'s own `The DIG agent is still starting.`, which is drawn as
/// this pane's banner: two sentences on one screen describing the same fact must not disagree.
pub(crate) const NODE_STARTING: &str = "Agent still starting";

/// The word for an account that is open and usable.
pub(crate) const ACCOUNT_READY: &str = "Unlocked";
/// The word for an account that exists but is sealed.
pub(crate) const ACCOUNT_LOCKED: &str = "Locked";
/// The word for an account that will not open at all.
pub(crate) const ACCOUNT_UNREADABLE: &str = "Unreadable";
/// The word for an account still sealed under a machine-generated password.
pub(crate) const ACCOUNT_NO_PASSWORD: &str = "No password set";
/// The word for a host with no account on it.
pub(crate) const ACCOUNT_NONE: &str = "None";
/// The word for a host that cannot hold an account at all.
pub(crate) const ACCOUNT_UNSUPPORTED: &str = "Not supported here";

/// One word naming the account's state.
///
/// # This decides nothing
///
/// It is a NAME for a state the model already chose, in an exhaustive match so a new state cannot
/// silently inherit another's word. It reads no enablement and offers no verb — the Account tab's
/// rows are still the model's, unchanged, and this word appears beside them rather than instead of
/// them.
fn account_word(state: &AccountState) -> &'static str {
    match state {
        AccountState::Unsupported => ACCOUNT_UNSUPPORTED,
        AccountState::Absent => ACCOUNT_NONE,
        AccountState::Locked => ACCOUNT_LOCKED,
        AccountState::Unopenable => ACCOUNT_UNREADABLE,
        AccountState::NeedsPassword => ACCOUNT_NO_PASSWORD,
        AccountState::Unlocked { .. } => ACCOUNT_READY,
    }
}

#[cfg(test)]
mod tests {
    use super::super::data::Tone;
    use super::*;

    /// **Every account state gets its own word.**
    ///
    /// Two states sharing a word is a state the reader cannot distinguish from another — and the
    /// two that matter most, `Locked` and `Unopenable`, differ precisely in whether there is a way
    /// back in. Asserted over the whole set rather than a sample, so a new variant forces a new word.
    #[test]
    fn no_two_account_states_share_a_word() {
        let states = [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
        ];
        let mut words: Vec<&str> = states.iter().map(account_word).collect();
        let total = words.len();
        words.sort_unstable();
        words.dedup();
        assert_eq!(
            words.len(),
            total,
            "two account states are shown the same word: {words:?}"
        );
    }

    /// A recoverable and an unrecoverable unlocked account read the same, because both are unlocked.
    ///
    /// Deliberate: `recoverable` decides which management verbs the MODEL offers, and re-reading it
    /// here to alter the badge would be this module reaching into a rule.
    #[test]
    fn recoverability_does_not_change_the_word_for_an_unlocked_account() {
        assert_eq!(
            account_word(&AccountState::Unlocked { recoverable: true }),
            account_word(&AccountState::Unlocked { recoverable: false })
        );
    }

    /// **A starting agent and a searching one get different words at the same severity.**
    ///
    /// Three actors, because a badge returning one constant — or collapsing the two not-connected
    /// cases — satisfies any two-case test. The words must differ, because the remedy differs; the
    /// tones must NOT, because `window_model` calls a not-yet-running agent a wait, and a badge
    /// that called it a fault would contradict the banner above it.
    #[test]
    fn a_starting_agent_and_a_searching_one_differ_in_words_but_not_in_severity() {
        let state = |running: bool, connected: bool| {
            PaneFacts::of_tray(&TrayView {
                running,
                node_connected: connected,
                ..TrayView::default()
            })
            .node_state()
        };
        assert_eq!(state(true, true), (NODE_CONNECTED, Tone::Good));
        assert_eq!(state(true, false), (NODE_SEARCHING, Tone::Warn));
        assert_eq!(state(false, false), (NODE_STARTING, Tone::Warn));

        let words = [NODE_CONNECTED, NODE_SEARCHING, NODE_STARTING];
        let mut unique = words.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            words.len(),
            "two node states are shown the same word: {words:?}"
        );
        assert_eq!(
            state(false, false).1,
            state(true, false).1,
            "a starting agent is drawn as more severe than a searching one, which contradicts the              model's own 'still starting' banner"
        );
    }

    /// **The projection carries the readings across unchanged, including the absent ones.**
    ///
    /// The `None`s are the point: a projection that quietly substituted a zero cache or an empty
    /// address would defeat the honesty rule before a pane ever saw the data.
    #[test]
    fn the_projection_preserves_absent_readings_as_absent() {
        let bare = PaneFacts::of_tray(&TrayView::default());
        assert_eq!(bare.cache, None);
        assert_eq!(bare.receive_address, None);

        let full = PaneFacts::of_tray(&TrayView {
            running: true,
            node_connected: true,
            node: "Connected to dig.local".to_string(),
            second_factor: true,
            cache: Some(crate::cache::CacheSnapshot {
                cap_bytes: 1024,
                used_bytes: 512,
            }),
            receive_address: Some("xch1abc".to_string()),
            ..TrayView::default()
        });
        assert!(full.agent_running && full.node_connected && full.second_factor);
        assert_eq!(full.node_summary, "Connected to dig.local");
        assert_eq!(full.receive_address.as_deref(), Some("xch1abc"));
        assert_eq!(full.cache.map(|c| c.used_bytes), Some(512));
    }

    /// The version reported is this build's own, never a literal that can drift from the manifest.
    #[test]
    fn the_version_comes_from_the_manifest() {
        assert_eq!(
            PaneFacts::of_tray(&TrayView::default()).version,
            env!("CARGO_PKG_VERSION")
        );
    }
}
