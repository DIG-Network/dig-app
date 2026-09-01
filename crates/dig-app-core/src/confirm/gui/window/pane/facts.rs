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

use crate::account::second_factor::vault::EnrolmentState;
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
    /// What is enrolled for a second factor — three-valued, so an unreadable probe renders as
    /// unknown rather than as protected (dig-app#288).
    pub(crate) second_factor: EnrolmentState,
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
    /// What the node says about ITSELF — version, build, address, uptime and its three content
    /// counts — or `None` when no node answered (dig_ecosystem#2330).
    ///
    /// Carried BESIDE [`node_summary`](Self::node_summary), not instead of it. The summary is the
    /// engine's pre-joined sentence, which a row can show as a label but a pane cannot lay out: a
    /// pane wanting to draw the cached-capsule count as its own readout would have to parse prose
    /// the engine is free to reword. These are the same facts as fields.
    ///
    /// `None` means nobody has spoken to a node, never "a node holding nothing" — the difference a
    /// zeroed struct here would erase.
    pub(crate) node_facts: Option<crate::node_facts::NodeFacts>,
    /// The stores this node holds, or why they are not known.
    ///
    /// A [`HostedStoresReading`](crate::hosted_stores::HostedStoresReading) and not a `Vec`, because
    /// an empty vector is the claim *this node holds nothing* and a read that has not answered has
    /// made no claim at all.
    pub(crate) hosted_stores: crate::hosted_stores::HostedStoresReading,
    /// Which sibling DIG apps this install can open, or that nobody has been able to look.
    ///
    /// Same shape and same reason as [`hosted_stores`](Self::hosted_stores): an empty list is a
    /// finding, and [`AppPresence::Unknown`](crate::apps::AppPresence::Unknown) is the absence of
    /// one. It is what lets the Apps pane draw an "Installed" chip from a fact rather than a guess.
    pub(crate) installed_apps: crate::apps::AppPresence,
    /// What the update beacon says about itself, or `None` when it could not be asked.
    ///
    /// A READING, and the only honest source for what this machine will do about updates: the
    /// remembered preference in `agent.json` is what somebody once asked for, which is a different
    /// fact and is wrong precisely when a privileged change did not take
    /// ([`crate::auto_update::BeaconStatus`]).
    pub(crate) update: Option<crate::auto_update::BeaconStatus>,
    /// This account's dig-profiles, or why they are not known (dig_ecosystem#2403).
    ///
    /// A [`ProfilesReading`](crate::profiles::ProfilesReading) and not a `Vec`, for the reason
    /// [`hosted_stores`](Self::hosted_stores) is a reading: every real account's answer today is an
    /// empty list, so *"you have no profiles"* and *"nobody has read them"* are the two states this
    /// pane is most likely to confuse, and only one of them is a fact about the reader.
    pub(crate) profiles: crate::profiles::ProfilesReading,
    /// Whether a profile can be created here, and which missing piece stops it.
    ///
    /// A FACT, not a rule: it says what this build can do, and the pane renders the sentence for it.
    /// It decides no verb, because there is no verb to decide — nothing in this shell can mint a
    /// profile (see [`crate::tray_menu::TrayAction::AboutProfiles`]).
    pub(crate) profile_creation: crate::profiles::ProfileCreation,
    /// Whether a profile can be EDITED here, and when it cannot, which piece is missing
    /// (dig_ecosystem#2993). The editor card's four-state banner is drawn from this and from the
    /// profile reading the edit service holds.
    pub(crate) profile_editing: crate::profile_edit::ProfileEditing,
    /// Where this node stands on the DIG and Chia networks — the header strip's three right-hand
    /// readings (dig_ecosystem#2569).
    ///
    /// A whole [`NetworkStanding`](crate::network::NetworkStanding) rather than three numbers,
    /// because every one of its readings distinguishes *nobody asked* from *the node answered* —
    /// which is what keeps an unknown peer count from being drawn as a zero.
    pub(crate) network: crate::network::NetworkStanding,
    /// How the send this app is running is going, or that there is none (dig_ecosystem#2819).
    ///
    /// A reading, exactly like [`balance`](Self::balance): it says what HAPPENED, and the pane draws
    /// each state as itself. It decides no verb — whether **Send** can be pressed is
    /// [`SendDraft::assess`](crate::wallet::sending::SendDraft::assess)'s answer, and this is one of
    /// the facts that answer is derived from.
    pub(crate) send: crate::wallet::sending::SendProgress,
    /// The automated-spend audit record the Activity pane draws (dig-app#289).
    ///
    /// A reading, exactly like [`balance`](Self::balance) — it says what was MEASURED, and the pane
    /// draws each state as itself. In particular an unread record is never rendered as an empty one:
    /// "your node has spent nothing" is a claim, and only a `Known` empty ledger has measured it.
    pub(crate) activity: crate::activity::ActivityReading,
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
            // Through `WalletOverview::of_tray`, never `view.balance` directly: that mapping is what
            // decides a figure is not shown at all when there is no address for it to be ABOUT, and
            // a pane reading the raw field would skip it.
            balance: crate::wallet::overview::WalletOverview::of_tray(view).balance,
            node_facts: view.node_facts.clone(),
            hosted_stores: view.hosted_stores.clone(),
            installed_apps: view.installed_apps.clone(),
            version: env!("CARGO_PKG_VERSION"),
            update: view.update,
            profiles: view.profiles.clone(),
            profile_creation: view.profile_creation,
            profile_editing: view.profile_editing,
            network: view.network.clone(),
            send: view.send.clone(),
            activity: view.activity.clone(),
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
            Self::NeedsPassword | Self::Unopenable => Tone::Warn,
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
    use crate::apps::AppPresence;
    use crate::hosted_stores::{HostedStoresReading, HostedStoresUnknown};

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
            second_factor: EnrolmentState::Enrolled,
            cache: Some(crate::cache::CacheSnapshot {
                cap_bytes: 1024,
                used_bytes: 512,
            }),
            receive_address: Some("xch1abc".to_string()),
            ..TrayView::default()
        });
        assert!(full.agent_running && full.node_connected);
        assert_eq!(full.second_factor, EnrolmentState::Enrolled);
        assert_eq!(full.node_summary, "Connected to dig.local");
        assert_eq!(full.receive_address.as_deref(), Some("xch1abc"));
        assert_eq!(full.cache.map(|c| c.used_bytes), Some(512));
    }

    /// **A pane can read the node's counts as NUMBERS, and an unasked node stays absent**
    /// (dig_ecosystem#2330).
    ///
    /// The pane layer could previously reach only [`PaneFacts::node_summary`] — the engine's
    /// pre-joined sentence (`"Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted"`). A pane
    /// cannot lay out a sentence: drawing the counts as separate readouts means parsing prose the
    /// engine is free to rewrite. So the projection must carry the numbers themselves.
    ///
    /// The fixture is the fake node's real snapshot, whose three counts all DIFFER, so a projection
    /// that read one count and reused it for the others cannot pass. The absent half is the honesty
    /// control: a projection substituting a zeroed `NodeFacts` for an unasked node would draw
    /// "0 capsules cached" about a node nobody has spoken to, which is the placeholder-that-reads-as-
    /// real-data this surface exists to keep out.
    #[test]
    fn the_projection_carries_the_node_s_counts_as_numbers_not_as_a_sentence() {
        assert_eq!(
            PaneFacts::of_tray(&TrayView::default()).node_facts,
            None,
            "a node nobody has asked must stay absent, never a zeroed set of counts"
        );

        let status = crate::test_support::node::fake_status_result();
        let facts = PaneFacts::of_tray(&TrayView {
            node_facts: Some(crate::node_facts::NodeFacts::of_status(&status)),
            ..TrayView::default()
        })
        .node_facts
        .expect("a reported node must survive the projection");

        assert_eq!(facts.hosted_store_count, status.hosted_store_count);
        assert_eq!(facts.cached_capsule_count, status.cached_capsule_count);
        assert_eq!(facts.pinned_store_count, status.pinned_store_count);
        assert_ne!(
            facts.hosted_store_count, facts.cached_capsule_count,
            "the fixture must keep the counts distinguishable, or this test cannot see a swap"
        );
        assert_eq!(facts.version, status.version);
    }

    /// **An unread list and an empty one stay different types through the projection**
    /// (dig_ecosystem#2330).
    ///
    /// Both readings default to a not-yet-known state precisely because an empty vector is a CLAIM —
    /// "this node holds nothing", "no sibling app is installed". A projection that flattened either
    /// to a `Vec` would make that claim on behalf of a read that never happened, and every pane
    /// downstream would render it as fact.
    ///
    /// Three states each rather than two: `Pending` and `Unknown` are both "no list", so a
    /// projection collapsing every non-`Known` reading into one variant still passes a two-state
    /// test. The `Unknown` case carries a specific reason so that collapse is visible here.
    #[test]
    fn the_projection_keeps_an_unread_list_apart_from_an_empty_one() {
        let bare = PaneFacts::of_tray(&TrayView::default());
        assert_eq!(bare.hosted_stores, HostedStoresReading::Pending);
        assert_eq!(bare.installed_apps, AppPresence::Unknown);

        let no_node = PaneFacts::of_tray(&TrayView {
            hosted_stores: HostedStoresReading::Unknown(HostedStoresUnknown::NoNode),
            ..TrayView::default()
        });
        assert_eq!(
            no_node.hosted_stores,
            HostedStoresReading::Unknown(HostedStoresUnknown::NoNode),
            "the REASON a list is missing is what tells a person whether to start their node"
        );

        let answered = PaneFacts::of_tray(&TrayView {
            hosted_stores: HostedStoresReading::Known(Vec::new()),
            installed_apps: AppPresence::Known(Vec::new()),
            ..TrayView::default()
        });
        assert_eq!(
            answered.hosted_stores,
            HostedStoresReading::Known(Vec::new())
        );
        assert_eq!(answered.installed_apps, AppPresence::Known(Vec::new()));
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
