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
    /// What the app can honestly say about the account's money: a reading, a read in flight, or the
    /// reason there is no figure.
    ///
    /// Carried as the WHOLE reading rather than as two numbers plus a flag, because the three states
    /// are what keep an unknown balance from being drawn as a zero — see
    /// [`crate::wallet::overview::BalanceReading`].
    pub(crate) balance: crate::wallet::overview::BalanceReading,
    /// The installed version of this app.
    pub(crate) version: &'static str,
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
            // Through `WalletOverview::of_tray`, never `view.balance` directly: that mapping is what
            // decides a figure is not shown at all when there is no address for it to be ABOUT, and
            // a pane reading the raw field would skip it.
            balance: crate::wallet::overview::WalletOverview::of_tray(view).balance,
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// The node's connection as a badge: one word, and how worried to be about it.
    ///
    /// # Why three states and not two
    ///
    /// "Not connected" covers two very different situations. If the agent is not running, nothing on
    /// this machine is even trying. If the agent IS running and has not reached a node, it is
    /// retrying — worth flagging, not broken. Collapsing the two told a person with a dead agent
    /// exactly what it told a person on a slow network.
    pub(crate) fn node_state(&self) -> (&'static str, super::data::Tone) {
        match (self.agent_running, self.node_connected) {
            (_, true) => (NODE_CONNECTED, super::data::Tone::Good),
            (true, false) => (NODE_SEARCHING, super::data::Tone::Warn),
            (false, false) => (NODE_AGENT_DOWN, super::data::Tone::Bad),
        }
    }
}

/// The badge word for a node the agent is talking to.
pub(crate) const NODE_CONNECTED: &str = "Connected";
/// The badge word for a running agent that has not reached a node yet.
pub(crate) const NODE_SEARCHING: &str = "Looking for a node";
/// The badge word for an agent that is not running, so nothing is looking.
pub(crate) const NODE_AGENT_DOWN: &str = "Agent not running";

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

    /// **A dead agent and a searching one are told apart, and both from a connected one.**
    ///
    /// Three actors, because a badge returning one constant — or collapsing the two not-connected
    /// cases — satisfies any two-case test. The pair that matters is the two `false` rows: they
    /// differ only in whether anything on this machine is still trying, which is the entire reason
    /// the third state exists.
    #[test]
    fn the_node_badge_separates_a_dead_agent_from_one_still_looking() {
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
        assert_eq!(state(false, false), (NODE_AGENT_DOWN, Tone::Bad));

        let words = [NODE_CONNECTED, NODE_SEARCHING, NODE_AGENT_DOWN];
        let mut unique = words.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            words.len(),
            "two node states are shown the same word: {words:?}"
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
