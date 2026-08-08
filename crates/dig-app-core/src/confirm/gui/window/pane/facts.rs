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
    /// Which state the account is in, as a NAME. `None` on a host that has never reported one.
    ///
    /// Carried alongside [`account_word`](Self::account_word) rather than instead of it: a pane whose
    /// copy differs per state needs to match EXHAUSTIVELY, and matching on a display word is a match
    /// a new state falls silently through.
    pub(crate) account: Option<AccountKind>,
    /// The account's state in one word, for a badge. `None` on a host that cannot hold an account.
    pub(crate) account_word: Option<&'static str>,
    /// The root profile's stable id — the DIG ID a person hands to someone else, or `None` when this
    /// computer has no profile to identify.
    pub(crate) profile_id: Option<String>,
    /// Whether a second factor is enrolled.
    pub(crate) second_factor: bool,
    /// The node's cache cap and usage, or `None` when no node has reported one.
    pub(crate) cache: Option<crate::cache::CacheSnapshot>,
    /// The account's `xch1…` receive address, when there is an unlocked account to derive one from.
    pub(crate) receive_address: Option<String>,
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
            account: view.account.as_ref().map(AccountKind::of),
            account_word: view.account.as_ref().map(account_word),
            profile_id: view.profile_id.clone(),
            second_factor: view.second_factor,
            cache: view.cache,
            receive_address: view.receive_address.clone(),
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

/// Which state the account is in — the state's NAME, and deliberately nothing else.
///
/// # Why a second enum rather than handing panes [`AccountState`]
///
/// A pane whose sentence differs per state has to match on the state, and it must match
/// exhaustively — copy chosen by a display word is copy a seventh state inherits by accident. But
/// [`AccountState::Unlocked`] carries `recoverable`, which is precisely the fact the MODEL branches
/// on when it decides which management verbs to offer. Dropping that payload here is what keeps
/// "this pane cannot re-derive an enablement" a property of the types rather than a request in a
/// comment: the pane can name the state and cannot reconstruct the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountKind {
    /// This host cannot hold an account at all.
    Unsupported,
    /// No account exists here yet.
    Absent,
    /// An account exists and is sealed, with a way back in.
    Locked,
    /// An account exists and its seal will not open at all.
    Unopenable,
    /// An account exists, sealed under a password the machine generated rather than one its owner
    /// chose.
    NeedsPassword,
    /// An account is open.
    Unlocked,
}

impl AccountKind {
    /// Name the state the model reported, in an exhaustive match.
    pub(crate) fn of(state: &AccountState) -> Self {
        match state {
            AccountState::Unsupported => Self::Unsupported,
            AccountState::Absent => Self::Absent,
            AccountState::Locked => Self::Locked,
            AccountState::Unopenable => Self::Unopenable,
            AccountState::NeedsPassword => Self::NeedsPassword,
            AccountState::Unlocked { .. } => Self::Unlocked,
        }
    }

    /// One word naming this state, for a badge.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Unsupported => ACCOUNT_UNSUPPORTED,
            Self::Absent => ACCOUNT_NONE,
            Self::Locked => ACCOUNT_LOCKED,
            Self::Unopenable => ACCOUNT_UNREADABLE,
            Self::NeedsPassword => ACCOUNT_NO_PASSWORD,
            Self::Unlocked => ACCOUNT_READY,
        }
    }

    /// How worried to be about this state.
    ///
    /// # Neither reassuring state is coloured for comfort
    ///
    /// [`Self::Locked`] and [`Self::Unlocked`] are both ordinary working states, so both read as
    /// good. The two that are NOT fine are coloured as such however calm their one word sounds:
    /// `No password set` is a lock anyone at this keyboard can open, and `Unreadable` is an account
    /// that can no longer be used at all. A custody surface that painted either of them green would
    /// be telling its owner the account is safer than it is.
    pub(crate) fn tone(self) -> super::data::Tone {
        use super::data::Tone;
        match self {
            Self::Unsupported | Self::Absent => Tone::Neutral,
            Self::Locked | Self::Unlocked => Tone::Good,
            Self::NeedsPassword | Self::Unopenable => Tone::Bad,
        }
    }

    /// Every state, for the tests and screenshots that must cover all of them.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::Unsupported,
        Self::Absent,
        Self::Locked,
        Self::Unopenable,
        Self::NeedsPassword,
        Self::Unlocked,
    ];
}

/// One word naming the account's state.
///
/// # This decides nothing
///
/// It is a NAME for a state the model already chose, in an exhaustive match so a new state cannot
/// silently inherit another's word. It reads no enablement and offers no verb — the Account tab's
/// rows are still the model's, unchanged, and this word appears beside them rather than instead of
/// them.
fn account_word(state: &AccountState) -> &'static str {
    AccountKind::of(state).word()
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

    /// **Naming a state loses nothing but `recoverable`, and `ALL` really is all of them.**
    ///
    /// Both halves matter. If two states collapsed onto one [`AccountKind`], a pane's per-state copy
    /// would silently serve one of them the other's sentence — which is dig_ecosystem#2059 exactly.
    /// And `ALL` is what the pane tests and the screenshot set enumerate, so a seventh state that
    /// nobody added to it would go unphotographed and untested while every test still passed.
    #[test]
    fn every_account_state_gets_its_own_kind_and_all_covers_them() {
        let states = [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
        ];
        let kinds: Vec<AccountKind> = states.iter().map(AccountKind::of).collect();
        for (i, left) in kinds.iter().enumerate() {
            for right in &kinds[i + 1..] {
                assert_ne!(
                    left, right,
                    "two account states share one kind, so a pane cannot tell them apart"
                );
            }
        }
        assert_eq!(
            AccountKind::ALL.len(),
            kinds.len(),
            "AccountKind::ALL does not enumerate every state, so the pane tests and the screenshot \
             set are covering fewer states than exist"
        );
        for kind in AccountKind::ALL {
            assert!(
                kinds.contains(&kind),
                "{kind:?} is in ALL but no AccountState produces it"
            );
        }
    }

    /// The projection carries the profile id across, absent stays absent.
    #[test]
    fn the_projection_carries_the_profile_id() {
        assert_eq!(PaneFacts::of_tray(&TrayView::default()).profile_id, None);
        assert_eq!(
            PaneFacts::of_tray(&TrayView {
                profile_id: Some("abc123".to_string()),
                ..TrayView::default()
            })
            .profile_id
            .as_deref(),
            Some("abc123")
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
