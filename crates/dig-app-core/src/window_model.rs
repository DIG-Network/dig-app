//! The tabbed app window's model — the same verbs the tray offers, arranged as tabs
//! (dig_ecosystem#2253).
//!
//! # Why this exists beside [`crate::tray_menu`] rather than inside it
//!
//! A native tray menu and a tabbed window are two RENDERINGS of one set of rules. Which rows exist,
//! which are enabled, and what their labels say is decided once — by the six group builders in
//! [`crate::tray_menu`] — and composed here into tabs instead of submenus. Nothing in this module
//! decides whether a verb is offered; it decides only where it is shown. A rule re-derived here would
//! be a second implementation of the account state machine, and the two would drift.
//!
//! So: no [`TrayAction`] variant is defined here, no enablement is computed here, and
//! [`MenuRow`] is reused verbatim. [`MenuRow::Submenu`] simply never appears in a window section — a
//! tab is already the nesting a submenu provided.
//!
//! # The invariant this module exists to make machine-checkable
//!
//! The window is only safe to build a tray trim on if **no verb becomes unreachable**. Some hosts have
//! no window at all (`WindowHost::Unavailable` — macOS today, and any Linux session with no display
//! server), so the tray must stay complete there. Every action the tray offers on such a host must
//! still be reachable on a host that HAS a window, from the trimmed tray spine
//! ([`TRAY_SPINE`]), this model, or the explicit [`SUBSUMED_BY_TAB`] map. That is
//! `every_action_survives_the_trim_on_every_host` below, and it is what turns "no user loses their
//! escape hatch" into a signal a build can fail on.
//!
//! # Rendering owns none of this
//!
//! This module has no dependency on egui, no `cfg!(target_os = ...)`, and no I/O. Whether a window can
//! be opened at all arrives as [`TrayView::window_host`], a plain field, so both values are exercised
//! by `cargo test` on every platform — a `cfg!` here would leave one host's behaviour unfalsifiable on
//! CI.

use crate::tray_menu::{
    profile_edit_actions,
    apps_actions, auto_update_actions, auto_update_label, cache_actions, cache_label,
    management_actions, profile_actions, security_actions, view_account_actions, wallet_actions,
    MenuRow, TrayAction, TrayView,
};

/// One tab of the app window — five destinations, in the order a person meets them.
///
/// # Why five, and why these five (dig_ecosystem#2358)
///
/// Seven tabs held three duplications and one dead pane. Each merge below removes a reason for two
/// surfaces to disagree about one fact, which is the only kind of tidying worth a breaking change to
/// a navigation set.
///
/// * **Security folded into [`Account`](Self::Account).** "Is my account safe" and "I want a
///   different account" is a real distinction between CARDS, not between destinations — and the
///   split cost a genuine defect: two hand-maintained six-arm sentence sets over one account state
///   machine, each tested only against itself, free to drift indefinitely while both suites stayed
///   green. One pane draws the lead once and reads as one narrative: who you are, whether it is
///   protected, whether you can get it back, and the destroying verbs last.
/// * **Status became [`Home`](Self::Home).** Its account rows and its second copy of the cache meter
///   are gone, and the facts a person needs wherever they are standing — the agent and the node —
///   moved into a header strip the whole window carries. A person on Wallet should not have to
///   change tabs to learn the node is down, especially when a down node is frequently WHY the
///   balance reads "Not known".
/// * **Apps became a launcher strip on [`Home`](Self::Home).** One card and half a pane of void; a
///   dedicated tab advertised emptiness.
/// * **Cache became [`Content`](Self::Content).** "Cache" is implementation jargon, and with the
///   reshare flywheel this is where a person sees they are CONTRIBUTING — a better reason for a tab
///   to exist than a disk quota.
/// * **Advanced was deleted.** It declared room for the node-endpoint override and the global
///   shortcut; both shipped inside the Settings pane instead, so the variant held nothing, rendered
///   never, and only widened every sweep written over the tab set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum TabId {
    /// What DIG is doing on this computer, the way to the logs, and the other DIG apps it can open.
    ///
    /// In that order, which is the order [`build`] emits: the diagnostics first because a person
    /// who opens this tab because something is wrong came for them, the launcher under them because
    /// that is what they browse when nothing is.
    Home,
    /// The account: what it is, how it is protected, and how to create, restore, replace or remove
    /// it.
    Account,
    /// What the account can do with money, which today is receive and understand.
    Wallet,
    /// What this computer keeps on disk for the network, and how much of it to give up.
    Content,
    /// How DIG behaves: whether it keeps itself up to date, which node it reads through, and the
    /// chord that opens it.
    Settings,
}

impl TabId {
    /// Every tab this window can emit, in the order a person meets them.
    ///
    /// # Generated, because the hand-written version was not exhaustive and three sweeps relied on it
    ///
    /// This used to be a `[Self; N]` array literal whose own docs admitted the gap: adding a variant
    /// forced it to be given a LABEL and nothing forced it to be added HERE, so a new tab would
    /// compile, be absent from the list, and escape every guard written over it — the copy-voice
    /// sweep, the lead sweep and the pane-state sweep all iterate this. Stable Rust has no way to
    /// make an array literal exhaustive over an enum, so the list is now derived
    /// ([`strum::EnumIter`]) and a new variant arrives in every sweep without anyone remembering.
    ///
    /// The order is the enum's declaration order, which is also the sidebar's order, so there is one
    /// place to change a tab's position rather than two that can disagree.
    pub fn all() -> Vec<Self> {
        use strum::IntoEnumIterator;
        Self::iter().collect()
    }

    /// The tab's user-facing label.
    ///
    /// Visible to the crate because it is also the vocabulary the COPY may use: a sentence that
    /// sends a reader to a named tab is only true while that name is one of these, so the copy
    /// sweep checks itself against this function rather than against a second hand-kept list.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Account => "Account",
            Self::Wallet => "Wallet",
            Self::Content => "Content",
            Self::Settings => "Settings",
        }
    }
}

/// The stable element id the sidebar gives `tab`.
///
/// Derived from the variant rather than generated, for the same reason
/// [`crate::tray_menu::action_id`] is (dig_ecosystem#2074): the window rebuilds whenever the view
/// changes — and the view carries the node's own description, rewritten by a five-second poll — so a
/// generated id would be replaced under a user mid-click, and the click would resolve to nothing. The
/// variant name is already the stable, unique, legible thing an id wants to be.
pub fn tab_element_id(tab: TabId) -> String {
    format!("dig-window-tab:{tab:?}")
}

/// A run of rows under one optional heading.
///
/// The heading is CONTENT, not decoration: the Wallet tab's heading is the balance sentence, and the
/// Cache tab's is the live usage against the cap. Both are facts a person opened the tab to read, and
/// both come from the same functions that label the tray's rows, so the two surfaces cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The heading above the rows, or `None` when the rows speak for themselves.
    pub heading: Option<String>,
    /// The rows, in render order. Never a [`MenuRow::Submenu`].
    pub rows: Vec<MenuRow>,
}

/// What a pane says about its own completeness, so every tab answers all four async questions.
///
/// # Why this is model data and not a rendering decision
///
/// "Loading, error, empty, success" is a `professional-ui` HARD RULE, and a rule enforced only by
/// looking at screenshots is a rule that rots on the first refactor. Deciding it here means each state
/// is chosen by a testable function of the same [`TrayView`] the rows come from, and the shell's job
/// shrinks to painting whichever note it is handed.
///
/// Every variant is reachable from a real view, and each is asserted from BOTH sides — a view that
/// produces it and a view that does not. A variant no view can produce would be a state nobody has
/// ever seen drawn, which is how an "empty state" ships broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneNote {
    /// Everything this tab has to show is present and final. The success state.
    Ready,
    /// The figures are still arriving. Names what is being waited for, so the wait is not a mystery.
    Waiting(&'static str),
    /// The node could not be asked, so this tab's figures are absent rather than merely late. Names
    /// the remedy, because an error state with no way forward is the dead end dig_ecosystem#1800
    /// removed.
    Unreachable(&'static str),
    /// The tab renders, and has nothing for this person to act on. Names what would change that.
    Empty(&'static str),
}

/// One tab of the window: an id, a label, how complete its content is, and that content.
///
/// # There is deliberately no `unavailable` field
///
/// An earlier shape carried `unavailable: Option<String>` — a whole-tab reason string. It was deleted
/// because the model never set it and could not: every tab that looked like a candidate is the sole
/// route to something (the Wallet tab on a host with no credential store still carries the explanation
/// of why there is no wallet), so greying one takes that route away. The reachability invariant fails
/// when it is tried.
///
/// Per-row `enabled` is what remains, and it is strictly better: it disables the one thing that cannot
/// be done while leaving everything around it usable, and its LABEL carries the reason — which is why
/// [`label_names_a_remedy`] moved onto row labels rather than being deleted with the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab {
    /// Which tab this is. Also the source of its sidebar id — see [`tab_element_id`].
    pub id: TabId,
    /// The sidebar label.
    pub label: String,
    /// How complete this tab's content is — see [`PaneNote`].
    pub note: PaneNote,
    /// The tab's content, in render order.
    pub sections: Vec<Section>,
}

impl Tab {
    /// Every action this tab offers as a clickable row, in render order.
    pub fn actions(&self) -> Vec<TrayAction> {
        self.sections
            .iter()
            .flat_map(|section| &section.rows)
            .filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            })
            .collect()
    }

    /// Whether this tab shows the user anything at all — a clickable row, or a heading carrying a fact.
    ///
    /// A tab that SUBSUMES an action gets no exemption here, and that is the whole correction: the
    /// exemption used to make a subsuming tab "non-empty" by definition, so the Wallet tab survived the
    /// emptiness filter while rendering nothing, and the map's promise that it explains the absence of a
    /// wallet went unkept. A tab must now PROVE it renders something; claiming to is not enough.
    pub fn has_content(&self) -> bool {
        self.sections
            .iter()
            .any(|section| !section.rows.is_empty() || section.heading.is_some())
    }
}

/// The whole window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowModel {
    /// The tabs to render, in sidebar order. Only non-empty tabs appear.
    pub tabs: Vec<Tab>,
}

impl WindowModel {
    /// Every action reachable anywhere in the window, as a clickable row.
    pub fn actions(&self) -> Vec<TrayAction> {
        self.tabs.iter().flat_map(Tab::actions).collect()
    }

    /// The tab with this id, if it is rendered.
    pub fn tab(&self, id: TabId) -> Option<&Tab> {
        self.tabs.iter().find(|tab| tab.id == id)
    }
}

/// Actions whose CONTENT a tab renders as the page itself, so they carry no row of their own.
///
/// [`TrayAction::AboutWallet`] is the only entry. On the tray it renders two rows — the balance line
/// and `My wallet…` — that both open the same window. Inside a Wallet tab the balance is the page's
/// own heading and "open the wallet window" is meaningless, because the tab IS that window.
///
/// This is explicit, reviewed data rather than an implicit "the tab covers it" for one reason: the
/// reachability invariant reads it. An implicit version would let any action be waved through as
/// "covered" and make the invariant vacuous.
pub const SUBSUMED_BY_TAB: [(TrayAction, TabId); 1] = [(TrayAction::AboutWallet, TabId::Wallet)];

/// The tab that renders `action` as page content, if any.
fn subsuming_tab(action: TrayAction) -> Option<TabId> {
    SUBSUMED_BY_TAB
        .iter()
        .find(|(subsumed, _)| *subsumed == action)
        .map(|(_, tab)| *tab)
}

/// The rows that stay on the tray once the window ships, whatever else moves into it.
///
/// The first five are `urgent_account_row`'s whole range — the one thing the account needs right now,
/// which differs by state — plus `LockNow`, which joins them so the row is present in the unlocked
/// state too. [`TrayAction::Open`] and [`TrayAction::Quit`] stay because reading content and leaving
/// must never require a window to be open first. [`TrayAction::OpenWindow`] is the route to everything
/// else, so a trimmed tray without it would be a tray with no way in.
///
/// This is what the trim keeps. It lives here because the reachability invariant is stated against it:
/// everything NOT in this set must be reachable from [`build`]'s output, or the trim strands it.
///
/// Eight actions, **four rows**: the first five share one polymorphic slot (`urgent_account_row` emits
/// exactly one of them, decided by the account's state), and the remaining three are a row each.
pub const TRAY_SPINE: [TrayAction; 8] = [
    TrayAction::SetUpAccount,
    TrayAction::Unlock,
    TrayAction::SetAccountPassword,
    TrayAction::ExplainUnopenable,
    TrayAction::LockNow,
    TrayAction::Open,
    TrayAction::OpenWindow,
    TrayAction::Quit,
];

/// The heading over the Account tab's protection rows.
///
/// # Why the model and the pane share the literal rather than each writing one
///
/// The merged Account pane draws its protection rows differently from its other rows: they carry the
/// window's ONE promoted verb, and its second-factor and paired-app machinery hangs off them. So the
/// pane has to find that section — and finding it by POSITION would make the pane's layout depend on
/// the order this function happens to list sections in, which is the coupling
/// the merged Account pane exists to avoid. Naming the section once, here,
/// means the two cannot drift: there is one string, not two that must stay equal.
pub const PROTECTION_HEADING: &str = "How this account is protected";

/// The heading over the Home tab's app launcher, shared for the same reason as
/// [`PROTECTION_HEADING`].
pub const APPS_HEADING: &str = "Other DIG apps";

/// The heading over the Account tab's profile rows, shared for the same reason as
/// [`PROTECTION_HEADING`] (dig_ecosystem#2403).
///
/// The Account pane draws these rows as a LIST — one row per profile, with its DID and its state —
/// rather than as a run of buttons, so it has to find the section. Finding it by position would make
/// the pane's layout depend on the order this module happens to list sections in, which is exactly
/// the coupling the merged Account pane exists to avoid.
pub const PROFILES_HEADING: &str = "Profiles on this account";

/// The heading over the Account tab's profile-editor row, shared for the same reason as
/// [`PROTECTION_HEADING`] (dig_ecosystem#2993).
///
/// The editor draws its one verb at the foot of a FORM rather than in a run of buttons, so the pane
/// has to find the section; finding it by position would couple the pane's layout to the order this
/// module happens to list sections in.
pub const PROFILE_EDIT_HEADING: &str = "What your profile says about you";

/// The note for a tab whose whole content is a statement about the account.
///
/// `view.account` is `None` until the first boot report arrives — NOT "there is no account". The
/// difference matters because [`TrayView::account`] defaults `None` to
/// [`AccountState::Absent`](crate::tray_menu::AccountState::Absent), so a pane reading through that
/// default asserts a machine has no account while the agent is still starting. That is a wrong claim
/// about someone's custody, and it is the shape dig_ecosystem#2326 exists to keep out of these panes.
///
/// Single-sourced here rather than left to each pane, so a third account-bearing tab inherits the
/// honesty instead of remembering it.
fn account_note(view: &TrayView) -> PaneNote {
    match view.account {
        Some(_) => PaneNote::Ready,
        None => PaneNote::Waiting("DIG is still reading this computer's account."),
    }
}

/// Words that turn a statement of fact into a remedy — see [`label_names_a_remedy`].
const REMEDY_VERBS: [&str; 10] = [
    "set up", "unlock", "connect", "install", "restore", "choose", "open", "start", "add", "set a",
];

/// Whether `label` tells the user what to DO, rather than only that something cannot be done.
///
/// # What this is the bar for, and why it moved
///
/// It was written for a whole-tab `unavailable` reason string. That field is gone (see [`Tab`]) — but
/// the rule it enforced is the reason the field could be deleted safely, so it moved down one level
/// rather than out. **A DISABLED ROW is now what must clear it.** A control a person cannot use, whose
/// label does not name the act that would make it usable, is the dead end dig_ecosystem#1800 removed
/// from this menu: "Show my recovery phrase" greyed out says only *no*, while "Show my recovery phrase
/// (unlock first)" says *no, and here is the door*.
///
/// Checkably: the label contains a remedy verb (`REMEDY_VERBS`). Unlike the tab-level version this does
/// NOT require a full sentence, because a menu label is not one — requiring a trailing period would
/// have rejected every real label in the app and the rule would have been dropped instead of applied.
///
/// It is deliberately a rule about the STRING and not a category: a remedy is written per situation,
/// not per rough class of problem. "Unlock first" is wrong for an account that has never had a password
/// and actively misleading for one that cannot be opened at all — three situations, three remedies.
pub fn label_names_a_remedy(label: &str) -> bool {
    let lowered = label.trim().to_lowercase();
    !lowered.is_empty() && REMEDY_VERBS.iter().any(|verb| lowered.contains(verb))
}

/// Build the window from the same snapshot the tray is built from.
///
/// Every tab composes the shared group builders; see the module docs for why nothing is re-derived
/// here. Only non-empty tabs are emitted.
pub fn build(view: &TrayView) -> WindowModel {
    let account = view.account();

    let tabs = vec![
        // The launcher sits under the diagnostics rather than above them: a person who opens this
        // tab because something is wrong came for the log folder, and the apps are what they browse
        // when nothing is. `OpenLogs` is the escape hatch for when the app cannot say what is wrong.
        tab(
            TabId::Home,
            home_note(view),
            vec![
                Section {
                    heading: None,
                    rows: vec![
                        row(TrayAction::ShowStatus, "Status and details"),
                        row(TrayAction::OpenLogs, "Open the log folder"),
                    ],
                },
                Section {
                    heading: Some(APPS_HEADING.to_string()),
                    rows: apps_actions(),
                },
            ],
        ),
        // One pane, in the order the two panes already read in when they were two: what this account
        // IS, then whether it is protected, then the verbs that change which account this computer
        // has — destroying last. See [`TabId::Account`] for why they merged.
        tab(
            TabId::Account,
            account_note(view),
            vec![
                Section {
                    heading: Some("What this account is".to_string()),
                    rows: view_account_actions(view, &account),
                },
                // Between "what this account is" and "how it is protected", because that is where
                // it reads: a profile is WHICH identity this account is presenting, so a person
                // who has just read their DIG ID is in exactly the right place to be told which
                // profile that ID belongs to (dig_ecosystem#2403).
                Section {
                    heading: Some(PROFILES_HEADING.to_string()),
                    rows: profile_actions(view),
                },
                // Directly under the list, because it is about the profile the list says is in
                // use: a person who has just read which identity they are presenting is in exactly
                // the right place to change what it says (dig_ecosystem#2993).
                Section {
                    heading: Some(PROFILE_EDIT_HEADING.to_string()),
                    rows: profile_edit_actions(view),
                },
                Section {
                    heading: Some(PROTECTION_HEADING.to_string()),
                    rows: security_actions(&account, view.second_factor),
                },
                Section {
                    heading: Some("Manage this account".to_string()),
                    rows: management_actions(&account),
                },
            ],
        ),
        // The heading IS the balance sentence — the content `AboutWallet` would otherwise have opened
        // a window to show. That is what makes subsuming it honest rather than a quiet deletion.
        tab(
            TabId::Wallet,
            PaneNote::Ready,
            vec![Section {
                heading: Some({
                    let overview = crate::wallet::overview::WalletOverview::of_tray(view);
                    crate::wallet::overview::menu_balance_label(
                        &overview.balance,
                        overview.peers_peak,
                    )
                }),
                rows: wallet_actions(view, &account),
            }],
        ),
        // Same reasoning as Wallet's heading: the tray puts the live usage-against-cap on the submenu's
        // parent label, so the tab that replaces that submenu carries the same figure.
        tab(
            TabId::Content,
            // The cap and the usage both come from the node. With no node connected they are not late,
            // they are absent — so this is the error state, not the loading one, and it names the act
            // that changes the answer.
            match view.cache {
                Some(_) => PaneNote::Ready,
                None => PaneNote::Unreachable(
                    "No node is connected, so the size limit cannot be read or changed. Start the DIG node and this tab will fill in.",
                ),
            },
            vec![Section {
                heading: Some(cache_label(view.cache.as_ref())),
                rows: cache_actions(view.cache.as_ref()),
            }],
        ),
        // Same reasoning as the Cache and Wallet headings: the group's parent label carries the live
        // fact — updates on or off, and which channel — so the answer is read, not hunted for.
        tab(
            TabId::Settings,
            // Three honest cases. Before the agent has ticked, the beacon has not been asked yet, so
            // the figures are LATE. Once it has, a missing status means the beacon is absent or would
            // not answer, so they are ABSENT — the error state, naming the act that changes it.
            match (view.running, &view.update) {
                (false, _) => PaneNote::Waiting("The auto-update settings are still being read."),
                (true, None) => PaneNote::Unreachable(
                    "The DIG updater could not be asked, so auto-update cannot be changed here. Install DIG with the DIG installer and this tab will fill in.",
                ),
                (true, Some(_)) => PaneNote::Ready,
            },
            vec![Section {
                heading: Some(auto_update_label(view.update.as_ref())),
                rows: auto_update_actions(view.update.as_ref()),
            }],
        ),
    ];

    WindowModel {
        tabs: tabs.into_iter().filter(Tab::has_content).collect(),
    }
}

/// How complete the **Home** tab is (dig_ecosystem#2330).
///
/// Three honest cases, in the order a launch passes through them. The agent starts asynchronously,
/// so a window opened during boot has no figures yet — saying so is the loading state, and saying
/// nothing leaves a person reading stale defaults as though they were the answer. Once the agent is
/// running, a node that did not answer means the tab's figures are ABSENT rather than late, so it
/// names the act that changes the answer — the same shape the Cache tab already uses, for the same
/// reason.
fn home_note(view: &TrayView) -> PaneNote {
    match (view.running, view.node_connected) {
        (false, _) => PaneNote::Waiting("The DIG agent is still starting."),
        (true, false) => PaneNote::Unreachable(
            "No node is connected, so there is nothing to report about it yet. Start the DIG node \
             and this tab will fill in.",
        ),
        (true, true) => PaneNote::Ready,
    }
}

/// An enabled window row. Only the two Status rows need this — every other row arrives already built,
/// with its enablement already decided, from a shared group builder.
fn row(action: TrayAction, label: &str) -> MenuRow {
    MenuRow::Action {
        action,
        label: label.to_string(),
        enabled: true,
    }
}

/// The empty-state note for a tab whose sections carry headings but nothing to click.
///
/// One sentence per tab rather than one shared sentence, because "nothing here" is only useful when it
/// says what would put something here — and that differs. This is reached today by the Wallet tab on a
/// host with no account: subsumption takes both `AboutWallet` rows into the page itself and
/// `wallet_actions` offers nothing else, so the balance heading stands alone.
fn nothing_to_do(id: TabId) -> &'static str {
    match id {
        TabId::Wallet => "Set up a DIG Account to get a receive address.",
        TabId::Account => "Set up a DIG Account to manage one here.",
        TabId::Content => "Start the DIG node to choose a size limit.",
        // Unreachable by construction: the explainer row is offered in every state, so this tab always
        // has something to click. Written honestly anyway rather than left to a catch-all, because the
        // day a refactor makes it reachable is the day a wrong sentence would ship unnoticed.
        TabId::Settings => "Install the DIG updater to choose how DIG updates itself.",
        // Also unreachable: the two diagnostic rows are unconditional, so this tab always has
        // something to click whatever the account or the node is doing.
        TabId::Home => "Open the log folder to find out what DIG is doing.",
    }
}

/// Assemble one tab: drop the rows this tab renders as page content, then tidy the separators.
///
/// `note` is the caller's answer for the loading and error states, which only the view can decide. The
/// EMPTY state is decided here instead, from the assembled result: a tab is empty when it ends up with
/// no clickable row, and that is a fact about what came out rather than about what went in. Computing
/// it at the call sites would mean six predicates that each had to stay in step with subsumption.
fn tab(id: TabId, note: PaneNote, sections: Vec<Section>) -> Tab {
    let mut seen: Vec<(TrayAction, String)> = Vec::new();
    let sections: Vec<Section> = sections
        .into_iter()
        .map(|section| Section {
            heading: section.heading,
            rows: tidy(drop_repeats(drop_subsumed(section.rows, id), &mut seen)),
        })
        // A heading-only section SURVIVES. The heading is content, not decoration: the Wallet tab's
        // is the balance reading and the Cache tab's is the live usage. Dropping a section for having
        // no rows discarded it with them, and on a host with no credential store — where subsumption
        // removes both `AboutWallet` rows and `wallet_actions` emits nothing else — that left the
        // Wallet tab an EMPTY PANE while the subsumption map still promised it explained the absence.
        .filter(|section| !section.rows.is_empty() || section.heading.is_some())
        .collect();

    let clickable = |section: &Section| {
        section
            .rows
            .iter()
            .any(|row| matches!(row, MenuRow::Action { .. }))
    };
    let note = match (&note, sections.iter().any(clickable)) {
        // A tab that cannot be filled in at all outranks a tab that merely has nothing to click: the
        // person needs to know the node is missing, not that the list is short.
        (PaneNote::Ready, false) => PaneNote::Empty(nothing_to_do(id)),
        _ => note,
    };

    Tab {
        id,
        label: id.label().to_string(),
        note,
        sections,
    }
}

/// Remove rows offering an action an earlier section of the SAME tab already offered.
///
/// # Why a tab needs this and the tray does not
///
/// Two group builders may legitimately both offer a verb: `view_account_actions` and
/// `management_actions` each end with `AboutDid`, because in the tray they render as two separate
/// SUBMENUS and a person opening either one needs the way to the explanation from there. One instance
/// per popup is wayfinding.
///
/// A tab flattens both builders onto one scrolling pane, so the same two rows land about 210 px apart
/// with byte-identical labels, and the second reads as a bug rather than a signpost
/// (dig_ecosystem#2253).
///
/// The de-dupe lives here rather than in the builders on purpose: filtering upstream would fork rules
/// the tray and the window are required to share, which is the whole reason
/// [`crate::tray_menu`] owns them. This is one more pass beside [`drop_subsumed`] and [`tidy`] — the
/// window deciding where a verb is SHOWN, never whether it is offered.
///
/// First occurrence wins, so a verb keeps the section whose heading gives it the most context.
/// Cross-TAB repetition is untouched: `seen` is per-tab, and `ExplainUnopenable` appearing under both
/// Account and Security is one instance per pane, which is the wayfinding case.
///
/// # The key is (action, label), and the action alone is NOT enough
///
/// Sharing an action is normal and deliberate here. The Cache tab with no node connected offers
/// "Change the size limit (connect a node first)…" and "About the cache and your privacy…", both
/// [`TrayAction::AboutCache`], because they genuinely open the same window and
/// [`crate::tray_menu`] chose to admit that rather than invent a second action doing the identical
/// thing. Those are two different sentences a person might want, and de-duping on the action would
/// silently delete one.
///
/// What looks like a bug is a repeated LABEL: the same words twice on one pane. So a row is a repeat
/// only when it says the same thing AND does the same thing.
fn drop_repeats(rows: Vec<MenuRow>, seen: &mut Vec<(TrayAction, String)>) -> Vec<MenuRow> {
    rows.into_iter()
        .filter(|row| match row {
            MenuRow::Action { action, label, .. } => {
                let key = (*action, label.clone());
                if seen.contains(&key) {
                    false
                } else {
                    seen.push(key);
                    true
                }
            }
            // A separator carries no verb, so it cannot repeat one. `tidy` collapses any that this
            // leaves stranded.
            _ => true,
        })
        .collect()
}

/// Remove the rows whose content `tab` renders as the page itself.
fn drop_subsumed(rows: Vec<MenuRow>, tab: TabId) -> Vec<MenuRow> {
    rows.into_iter()
        .filter(|row| match row {
            MenuRow::Action { action, .. } => subsuming_tab(*action) != Some(tab),
            _ => true,
        })
        .collect()
}

/// Drop leading, trailing and doubled separators, which dropping a row can leave behind.
fn tidy(rows: Vec<MenuRow>) -> Vec<MenuRow> {
    let mut tidied: Vec<MenuRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let separator = matches!(row, MenuRow::Separator);
        if separator && matches!(tidied.last(), None | Some(MenuRow::Separator)) {
            continue;
        }
        tidied.push(row);
    }
    if matches!(tidied.last(), Some(MenuRow::Separator)) {
        tidied.pop();
    }
    tidied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::APPS;
    use crate::auto_update::{BeaconStatus, UpdateChannel};
    use crate::cache::{CacheSnapshot, CACHE_PRESETS};
    use crate::tray_menu::{AccountState, WindowHost};
    use std::collections::BTreeSet;

    /// Every `TrayAction` this shell can build, as concrete values.
    ///
    /// Payload-carrying variants are expanded, not sampled: `SetCacheCap` contributes one value per
    /// [`CACHE_PRESETS`] entry and `LaunchApp` one per [`APPS`] row, because those are the values that
    /// actually reach a menu. `assert_exhaustive` below fails to COMPILE if a variant is added without
    /// being listed here.
    fn every_action() -> Vec<TrayAction> {
        let mut all = vec![
            TrayAction::ShowStatus,
            TrayAction::Open,
            TrayAction::SetUpAccount,
            TrayAction::RestoreFromPhrase,
            TrayAction::ReplaceWithNewAccount,
            TrayAction::ReplaceFromPhrase,
            TrayAction::RemoveAccount,
            TrayAction::Unlock,
            TrayAction::SetAccountPassword,
            TrayAction::LockNow,
            TrayAction::ShowRecoveryPhrase,
            TrayAction::CopyRecoveryPhrase,
            TrayAction::SaveRecoveryPhrase,
            TrayAction::ExplainUnopenable,
            TrayAction::FixMissingPhrase,
            TrayAction::SetUpTwoFactor,
            TrayAction::TurnOffTwoFactor,
            TrayAction::PairAnApp,
            TrayAction::ManagePairedApps,
            TrayAction::CopyDigId,
            TrayAction::AboutDid,
            TrayAction::AboutProfiles,
            TrayAction::CopyReceiveAddress,
            TrayAction::AboutWallet,
            TrayAction::SetCustomCacheCap,
            TrayAction::AboutCache,
            TrayAction::AboutAutoUpdate,
            TrayAction::OpenWindow,
            TrayAction::OpenLogs,
            TrayAction::Quit,
        ];
        all.extend(CACHE_PRESETS.map(|bytes| TrayAction::SetCacheCap { bytes }));
        all.extend(APPS.iter().map(|app| TrayAction::LaunchApp(app.id)));
        all.extend([true, false].map(|enabled| TrayAction::SetAutoUpdate { enabled }));
        all.push(TrayAction::RearmUpdateSchedule);
        all.extend(UpdateChannel::ALL.map(TrayAction::SetUpdateChannel));
        // Two distinct indices, and both visibilities of each: the id of a payload-carrying variant
        // has to separate every value that can reach a menu, and `hidden` is part of the payload —
        // an id derived from the index alone would give one profile's "hide" and "show" rows one id,
        // which egui reports as a duplicate and which leaves one of them unclickable.
        all.extend([0_u32, 1].map(|ix| TrayAction::SetActiveProfile { ix }));
        all.extend(
            [(0_u32, true), (0, false), (1, true), (1, false)]
                .map(|(ix, hidden)| TrayAction::SetProfileVisibility { ix, hidden }),
        );
        // A real menu row now (dig_ecosystem#2939), offered only where creation is possible.
        all.push(TrayAction::CreateProfile);
        // Offered only where editing is measured possible, on the Account tab beneath the list.
        all.push(TrayAction::PublishProfileEdits);
        all
    }

    /// A compile-time guard: adding a `TrayAction` variant breaks this match, which is the prompt to
    /// add it to `every_action` and decide which tab it belongs on.
    #[allow(dead_code)]
    fn assert_exhaustive(action: TrayAction) {
        match action {
            TrayAction::PublishProfileEdits
            | TrayAction::ShowStatus
            | TrayAction::Open
            | TrayAction::SetUpAccount
            | TrayAction::RestoreFromPhrase
            | TrayAction::ReplaceWithNewAccount
            | TrayAction::ReplaceFromPhrase
            | TrayAction::RemoveAccount
            | TrayAction::Unlock
            | TrayAction::SetAccountPassword
            | TrayAction::LockNow
            | TrayAction::ShowRecoveryPhrase
            | TrayAction::CopyRecoveryPhrase
            | TrayAction::SaveRecoveryPhrase
            | TrayAction::ExplainUnopenable
            | TrayAction::FixMissingPhrase
            | TrayAction::SetUpTwoFactor
            | TrayAction::TurnOffTwoFactor
            | TrayAction::PairAnApp
            | TrayAction::ManagePairedApps
            | TrayAction::CopyDigId
            | TrayAction::AboutDid
            | TrayAction::SetActiveProfile { .. }
            | TrayAction::SetProfileVisibility { .. }
            | TrayAction::AboutProfiles
            | TrayAction::CreateProfile
            | TrayAction::CopyReceiveAddress
            | TrayAction::AboutWallet
            | TrayAction::SetCacheCap { .. }
            | TrayAction::SetCustomCacheCap
            | TrayAction::AboutCache
            | TrayAction::SetAutoUpdate { .. }
            | TrayAction::RearmUpdateSchedule
            | TrayAction::SetUpdateChannel(_)
            | TrayAction::AboutAutoUpdate
            | TrayAction::LaunchApp(_)
            // Never a menu ROW, so deliberately absent from `every_action`: a send is a form the
            // Wallet pane draws, and a native menu cannot hold one. It is listed here because this
            // match is the compile-time prompt to make exactly that decision about a new variant.
            | TrayAction::SendXch(_)
            // Never a menu ROW either, and for a stronger reason than `SendXch`: nobody clicks it
            // at all. The state loop raises it on a schedule (dig_ecosystem#2950), which is the
            // whole of what the user asked for — an *automatic* popout — so a row offering it would
            // be a second, manual way in that the daily cadence knows nothing about.
            | TrayAction::CreateFirstProfile
            // Never a menu ROW: releasing a stuck send is a control the Wallet pane draws beside
            // the transfer it refers to, and a menu row would offer it with nothing to point at.
            | TrayAction::ReleaseUnknownSend
            | TrayAction::OpenWindow
            | TrayAction::OpenLogs
            | TrayAction::Quit => {}
        }
    }

    /// Every account state the menu can be in, including both recoverability readings of `Unlocked`.
    fn every_account_state() -> Vec<AccountState> {
        vec![
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
            AccountState::Unlocked { recoverable: false },
        ]
    }

    /// Every answer the beacon can give: absent, running, paused, and opted out of the schedule.
    ///
    /// More than two on purpose. `None` alone would exercise only the error state, and a single `Some`
    /// would leave the on/off row and the "current channel" mark stuck on one value across every view
    /// — so a group builder that ignored its input would look identical to one that read it.
    ///
    /// The FOURTH reading is the one that matters most, and it is the case a two-value fixture cannot
    /// express: **not paused, yet not updating**. Everything derived from `paused` alone reports that
    /// host as "auto-update — on" and offers it a `resume` that succeeds while changing nothing
    /// (dig_ecosystem#2324). It is deliberately `paused: false`, because a fixture that set both flags
    /// would be satisfied by code still reading only the pause.
    const EVERY_BEACON_READING: [Option<BeaconStatus>; 4] = [
        None,
        Some(BeaconStatus {
            paused: false,
            schedule_opted_out: false,
            channel: UpdateChannel::Stable,
        }),
        Some(BeaconStatus {
            paused: true,
            schedule_opted_out: false,
            channel: UpdateChannel::Nightly,
        }),
        Some(BeaconStatus {
            paused: false,
            schedule_opted_out: true,
            channel: UpdateChannel::Stable,
        }),
    ];

    /// Every view the model can be built from, driven from the state types rather than a hand-written
    /// list of interesting cases — a hand-written list silently stops covering states added later.
    fn every_view() -> Vec<TrayView> {
        let mut views = Vec::new();
        for account in every_account_state() {
            for host in [WindowHost::Available, WindowHost::Unavailable] {
                for second_factor in [false, true] {
                    for cache in [
                        None,
                        Some(CacheSnapshot {
                            cap_bytes: CACHE_PRESETS[2],
                            used_bytes: 1,
                        }),
                    ] {
                        for profile_id in [None, Some("dig1abc".to_string())] {
                            for receive_address in [None, Some("xch1abc".to_string())] {
                                for running in [false, true] {
                                    for update in EVERY_BEACON_READING {
                                        views.push(TrayView {
                                            account: Some(account.clone()),
                                            window_host: host,
                                            second_factor,
                                            cache,
                                            profile_id: profile_id.clone(),
                                            receive_address: receive_address.clone(),
                                            running,
                                            update,
                                            ..TrayView::default()
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        views
    }

    /// A one-line description of a view, so a failure names the case that produced it.
    fn describe(view: &TrayView) -> String {
        format!(
            "account={:?} host={:?} second_factor={} running={} cache={} profile_id={} address={} update={:?}",
            view.account,
            view.window_host,
            view.second_factor,
            view.running,
            view.cache.is_some(),
            view.profile_id.is_some(),
            view.receive_address.is_some(),
            view.update,
        )
    }

    /// Whether a tab puts anything on screen, computed from the RENDERED structure alone.
    ///
    /// Deliberately not [`Tab::has_content`]. Asserting a tab is non-empty by calling the predicate
    /// that DECIDES whether it is emitted is circular: a bug in that predicate — an exemption, say —
    /// makes both the code and the test agree, and the test proves nothing. This walks the sections a
    /// renderer would walk instead, so the assertion has an opinion of its own.
    fn renders_something(tab: &Tab) -> bool {
        tab.sections
            .iter()
            .any(|section| !section.rows.is_empty() || section.heading.is_some())
    }

    fn names(actions: impl IntoIterator<Item = TrayAction>) -> BTreeSet<String> {
        actions
            .into_iter()
            .map(|action| format!("{action:?}"))
            .collect()
    }

    /// Everything the TRAY offers in this view, submenus included.
    fn tray_actions(view: &TrayView) -> Vec<TrayAction> {
        crate::tray_menu::action_ids(&crate::tray_menu::build(view).rows)
            .into_iter()
            .map(|(_, action)| action)
            .collect()
    }

    /// Everything still reachable after the trim: the tray spine, the window, and the tabs that render
    /// an action as page content.
    ///
    /// Takes the model rather than building it, so a test can hand it a model the builder would never
    /// produce and check that this rejects it — see `a_subsuming_tab_that_renders_nothing_is_not_a_route`.
    /// A helper that always built its own input could only ever agree with the builder.
    ///
    /// # What replaced the `unavailable.is_none()` filters, and why it is not merely a deletion
    ///
    /// Both legs below used to exclude a tab whose `Tab::unavailable` reason was set: a greyed tab is
    /// not a route, so neither its rows nor anything it claimed to subsume counted. That field is gone,
    /// and dropping the filters with it would have made this invariant quietly WEAKER while every test
    /// stayed green — the exact hazard the field's own doc comment warned about.
    ///
    /// So they are REPLACED, by the thing the filters were a proxy for: **a tab counts as a route only
    /// if it actually renders something.** `SUBSUMED_BY_TAB` is the single place this invariant takes a
    /// human's word that a tab carries an action's content instead of a row, and an empty tab making
    /// that claim is precisely how a verb goes missing with the suite green.
    ///
    /// **Measured, so the claim is not an assumption.** Deleting the SUBSUMPTION filter is killed by
    /// `a_subsuming_tab_that_renders_nothing_is_not_a_route`. Deleting the ROW filter above it
    /// SURVIVES, and that is expected rather than a hole: a tab with rows renders them by
    /// construction, so the filter cannot currently discriminate. It is kept because it states the
    /// rule the leg is subject to, and a future tab that carries actions without drawing them would
    /// otherwise be counted as a route silently. Whoever finds it non-load-bearing should reach for a
    /// fixture that makes it bite, not for a deletion — that is exactly the reasoning the deleted
    /// field's own comment asked for.
    fn reachable_after_trim_of(view: &TrayView, model: &WindowModel) -> BTreeSet<String> {
        let mut reachable = names(
            tray_actions(view)
                .into_iter()
                .filter(|action| TRAY_SPINE.contains(action)),
        );
        reachable.extend(names(
            model
                .tabs
                .iter()
                .filter(|tab| renders_something(tab))
                .flat_map(Tab::actions),
        ));
        reachable.extend(names(
            SUBSUMED_BY_TAB
                .iter()
                .filter(|(_, tab)| model.tab(*tab).is_some_and(renders_something))
                .map(|(action, _)| *action),
        ));
        reachable
    }

    /// [`reachable_after_trim_of`] against the model this view really produces.
    fn reachable_after_trim(view: &TrayView) -> BTreeSet<String> {
        reachable_after_trim_of(view, &build(view))
    }

    /// The subsumption leg is load-bearing: a tab claiming to render an action's content, while
    /// rendering nothing, must not make that action count as reachable.
    ///
    /// Hand-built because `build` cannot produce it — which is the point. Without this the replacement
    /// for the deleted `unavailable` filters would be an assertion nothing could ever fail.
    /// **Proves:** before the first boot report, the account-bearing tabs say they are still reading
    /// rather than asserting the machine has no account.
    /// **Catches:** a pane reading `view.account` through `TrayView::account()`, whose `None` default
    /// is `Absent` — which would tell a person with an account that they have none (#2326).
    #[test]
    fn an_unreported_account_is_a_wait_not_a_claim_that_there_is_none() {
        let unreported = TrayView {
            account: None,
            ..TrayView::default()
        };
        // One tab, since dig_ecosystem#2358 merged Security into Account: there is now a single
        // destination that speaks about the account, which is the whole reason the two panes could
        // no longer disagree about how to describe a state nothing had reported.
        let note = build(&unreported)
            .tab(TabId::Account)
            .map(|t| t.note.clone())
            .expect("the Account tab is emitted");
        assert!(
            matches!(note, PaneNote::Waiting(_)),
            "Account claimed {note:?} about an account nothing has reported yet"
        );
    }

    /// The control the test above needs: a machine that genuinely HAS no account must still be told
    /// so plainly. Without this, a permanent "still reading" would pass.
    #[test]
    fn a_genuinely_absent_account_is_still_stated_plainly() {
        let absent = TrayView {
            account: Some(AccountState::Absent),
            ..TrayView::default()
        };
        let note = build(&absent)
            .tab(TabId::Account)
            .map(|t| t.note.clone())
            .expect("the Account tab is emitted");
        assert!(
            !matches!(note, PaneNote::Waiting(_)),
            "Account said it was still reading about a machine that reported no account"
        );
    }

    #[test]
    fn a_subsuming_tab_that_renders_nothing_is_not_a_route() {
        let view = TrayView::default();
        let (subsumed, tab_id) = SUBSUMED_BY_TAB[0];
        let hollow = WindowModel {
            tabs: vec![Tab {
                id: tab_id,
                label: "Wallet".to_string(),
                note: PaneNote::Ready,
                sections: vec![Section {
                    heading: None,
                    rows: Vec::new(),
                }],
            }],
        };
        assert!(
            !reachable_after_trim_of(&view, &hollow).contains(&format!("{subsumed:?}")),
            "an empty tab claiming to carry {subsumed:?} was counted as a route to it"
        );

        let filled = WindowModel {
            tabs: vec![Tab {
                sections: vec![Section {
                    heading: Some("You have 3 DIG.".to_string()),
                    rows: Vec::new(),
                }],
                ..hollow.tabs[0].clone()
            }],
        };
        assert!(
            reachable_after_trim_of(&view, &filled).contains(&format!("{subsumed:?}")),
            "a tab that DOES render {subsumed:?}'s content is a route to it"
        );
    }

    /// **The invariant this PR exists for.** No verb becomes unreachable when the tray is trimmed.
    ///
    /// Stated as a set difference over NAMES, not a count: a count says something vanished, a name says
    /// which escape hatch a user just lost.
    #[test]
    fn every_action_survives_the_trim_on_every_host() {
        for view in every_view() {
            let offered = names(tray_actions(&view));
            let reachable = reachable_after_trim(&view);
            let missing: Vec<_> = offered.difference(&reachable).cloned().collect();
            assert!(
                missing.is_empty(),
                "these actions become unreachable after the trim: {missing:?}\n  view: {}",
                describe(&view)
            );
        }
    }

    /// The decision's own wording: a host with no window loses nothing a host with one has.
    #[test]
    fn a_windowless_host_offers_nothing_a_windowed_host_cannot_reach() {
        for view in every_view() {
            let windowless = TrayView {
                window_host: WindowHost::Unavailable,
                ..view.clone()
            };
            let windowed = TrayView {
                window_host: WindowHost::Available,
                ..view.clone()
            };
            let offered = names(tray_actions(&windowless));
            let mut reachable = names(tray_actions(&windowed));
            reachable.extend(names(build(&windowed).actions()));
            reachable.extend(names(SUBSUMED_BY_TAB.iter().map(|(action, _)| *action)));
            let missing: Vec<_> = offered.difference(&reachable).cloned().collect();
            assert!(
                missing.is_empty(),
                "unreachable on a windowed host: {missing:?}\n  view: {}",
                describe(&view)
            );
        }
    }

    /// The window must open without an unlocked account, because `TurnOffTwoFactor` — the way out of a
    /// permanently unreplaceable account — lives in it.
    #[test]
    fn the_window_builds_in_every_account_state() {
        for view in every_view() {
            let model = build(&view);
            assert!(
                !model.tabs.is_empty(),
                "the window must have content in every state\n  view: {}",
                describe(&view)
            );
        }
    }

    /// Security must never demand an unlock to be shown. An `Unopenable` account can never answer a
    /// second-factor challenge, so a Security tab gated on unlock would make that account permanently
    /// unreplaceable and unremovable — the trap `two_factor_row` exists to prevent.
    ///
    /// Asserted as "it renders something the person can act on", not as "it is not greyed": greying is
    /// no longer expressible, so the old form would pass on a tab that had been emptied instead.
    #[test]
    fn the_protections_are_usable_without_an_unlocked_account() {
        for view in every_view() {
            let locked_out = matches!(
                view.account,
                Some(AccountState::Locked)
                    | Some(AccountState::NeedsPassword)
                    | Some(AccountState::Unopenable)
            );
            if !locked_out {
                continue;
            }
            let tab = build(&view)
                .tab(TabId::Account)
                .cloned()
                .unwrap_or_else(|| panic!("Account must render\n  view: {}", describe(&view)));
            assert!(
                !tab.actions().is_empty(),
                "Account must offer something without an unlock\n  view: {}",
                describe(&view)
            );
        }
    }

    /// `TurnOffTwoFactor` is reachable in all FOUR states that offer it, with no unlock.
    ///
    /// The four are `Unlocked`, `Locked`, `NeedsPassword` and `Unopenable` — every state in which an
    /// account exists. A host with no credential store (`Unsupported`) and a host with no account
    /// (`Absent`) are excluded because no enrolment can exist there to turn off, not because the rule
    /// is relaxed for them.
    #[test]
    fn turning_off_the_second_factor_needs_no_unlock() {
        let enrolled = |view: &TrayView| {
            view.second_factor
                && !matches!(
                    view.account,
                    Some(AccountState::Unsupported) | Some(AccountState::Absent) | None
                )
        };
        let candidates: Vec<TrayView> = every_view().into_iter().filter(enrolled).collect();
        assert_eq!(
            candidates.len(),
            // five account readings (Unlocked counts twice, recoverable or not) x host x cache
            // x profile_id x address x running x beacon reading
            5 * 2 * 2 * 2 * 2 * 2 * EVERY_BEACON_READING.len(),
            "the enrolled-account cases must all be covered"
        );
        for view in candidates {
            let reachable = reachable_after_trim(&view);
            assert!(
                reachable.contains("TurnOffTwoFactor"),
                "the way out of a wedged account vanished\n  view: {}",
                describe(&view)
            );
        }
    }

    /// **The Settings tab renders in every state, and always offers the way to the explanation.**
    ///
    /// The floor the tab must never drop below: whatever the beacon says or fails to say, a person
    /// opening Settings finds a tab that is there and a row they can click. A surface whose only
    /// content depends on another program answering is a surface that is blank on the machines that
    /// need it most.
    #[test]
    fn settings_renders_and_offers_a_route_in_every_state() {
        for view in every_view() {
            let tab = build(&view)
                .tab(TabId::Settings)
                .cloned()
                .unwrap_or_else(|| panic!("Settings must render\n  view: {}", describe(&view)));
            assert!(
                tab.actions().contains(&TrayAction::AboutAutoUpdate),
                "Settings must always offer the explainer\n  view: {}",
                describe(&view)
            );
        }
    }

    /// **The heading tells the three beacon states apart, and never calls a stopped machine "on".**
    ///
    /// Every heading here is derived from the same reading the rows are, so a heading that reported
    /// only `paused` would sit above a correct row saying the opposite. The opted-out case is asserted
    /// against the RUNNING case's wording rather than by matching a phrase, so re-wording the feature
    /// cannot make this pass by accident: what is pinned is that the two states do not read the same.
    #[test]
    fn the_auto_update_heading_names_which_thing_is_off() {
        let status = |paused, schedule_opted_out| crate::auto_update::BeaconStatus {
            paused,
            schedule_opted_out,
            channel: UpdateChannel::Stable,
        };
        let heading = |status| auto_update_label(Some(&status));

        let live = heading(status(false, false));
        let paused = heading(status(true, false));
        let opted_out = heading(status(false, true));

        assert!(
            live.contains("on,"),
            "a running beacon's heading must say so: {live}"
        );
        for stopped in [&paused, &opted_out] {
            assert!(
                stopped.contains("off,"),
                "a machine that does not update itself must not read as on: {stopped}"
            );
        }
        assert_ne!(
            opted_out, paused,
            "a removed daily check and a pause need different remedies, so they cannot share a \
             heading"
        );
        assert_ne!(
            opted_out, live,
            "the state that reports `paused: false` while never updating must not read as running"
        );
        // The channel names a person reads, not the beacon's wire tokens.
        assert!(
            live.contains(UpdateChannel::Stable.display_name()),
            "the heading uses the channel's display name: {live}"
        );
    }

    /// **The auto-update controls appear exactly when the beacon has answered, and they follow it.**
    ///
    /// Pinned from both sides. With a status, the on/off row names the state it moves TO — the
    /// opposite of the one reported — and exactly one channel row is offered per channel. Without one,
    /// neither control exists, because a switch drawn for a beacon nobody heard from is a switch that
    /// lies about its position.
    #[test]
    fn the_auto_update_controls_track_the_beacon_and_vanish_without_it() {
        for view in every_view() {
            let actions = build(&view)
                .tab(TabId::Settings)
                .map(Tab::actions)
                .unwrap_or_default();
            let case = describe(&view);

            let Some(status) = view.update else {
                // Two rows, both the explainer: one states the precondition, one is the concept's own
                // "About…". They survive de-duplication because they say DIFFERENT things, exactly as
                // the Cache tab's two `AboutCache` rows do. What must not survive is a control.
                assert!(
                    actions.iter().all(|a| *a == TrayAction::AboutAutoUpdate),
                    "with no beacon there is nothing to set, only something to read\n  view: {case}"
                );
                assert!(
                    actions.contains(&TrayAction::AboutAutoUpdate),
                    "with no beacon the explainer is the whole route\n  view: {case}"
                );
                continue;
            };

            // Derived from the beacon's own account of what is BLOCKING updates, not from a single
            // flag: on an opted-out host the row must be the schedule re-arm, and asserting against
            // `paused` alone would have accepted the `resume` that silently does nothing (#2324).
            let expected = match status.blocking_updates() {
                None => TrayAction::SetAutoUpdate { enabled: false },
                Some(crate::auto_update::Change::Enable(_)) => {
                    TrayAction::SetAutoUpdate { enabled: true }
                }
                Some(crate::auto_update::Change::RearmSchedule) => TrayAction::RearmUpdateSchedule,
                Some(crate::auto_update::Change::Channel { .. }) => {
                    unreachable!("not a way to turn updates on")
                }
            };
            assert!(
                actions.contains(&expected),
                "the on/off row must offer {expected:?}, the change that actually unblocks \
                 updates\n  view: {case}"
            );
            let contradiction = match expected {
                TrayAction::SetAutoUpdate { enabled } => {
                    TrayAction::SetAutoUpdate { enabled: !enabled }
                }
                // The re-arm has no opposite row to confuse it with; assert the resume that would
                // have been the silent no-op is NOT offered instead.
                _ => TrayAction::SetAutoUpdate { enabled: true },
            };
            assert!(
                !actions.contains(&contradiction),
                "a row that re-applies the state already in force does nothing\n  view: {case}"
            );
            for channel in UpdateChannel::ALL {
                assert!(
                    actions.contains(&TrayAction::SetUpdateChannel(channel)),
                    "{channel:?} must be choosable\n  view: {case}"
                );
            }
        }
    }

    /// **The channel in force is marked, and only it.** A chooser that shows no current value asks a
    /// person to change a setting they cannot read.
    #[test]
    fn exactly_one_channel_row_is_marked_current() {
        for view in every_view() {
            let Some(status) = view.update else { continue };
            let tab = build(&view)
                .tab(TabId::Settings)
                .cloned()
                .expect("Settings");
            let marked: Vec<&str> = tab
                .sections
                .iter()
                .flat_map(|section| &section.rows)
                .filter_map(|row| match row {
                    MenuRow::Action {
                        action: TrayAction::SetUpdateChannel(channel),
                        label,
                        ..
                    } if label.contains("current") => Some(channel.display_name()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                marked,
                vec![status.channel.display_name()],
                "the marked channel must be the one the beacon reports\n  view: {}",
                describe(&view)
            );
        }
    }

    /// **Settings answers all four async questions**, each from a view that produces it and a view
    /// that does not.
    ///
    /// `Empty` is the fourth, and it is asserted as UNREACHABLE rather than demonstrated: the
    /// explainer row is offered in every state, so the tab always has something to click. That is a
    /// claim about the builder, so it is checked across every view rather than asserted once — if a
    /// refactor ever drops the explainer, this fails and `nothing_to_do(Settings)` becomes real.
    #[test]
    fn the_settings_pane_states_are_each_reachable_and_none_is_universal() {
        let note = |view: &TrayView| build(view).tab(TabId::Settings).map(|tab| tab.note.clone());
        let reading = BeaconStatus {
            paused: false,
            schedule_opted_out: false,
            channel: UpdateChannel::Stable,
        };

        let booting = TrayView {
            running: false,
            update: Some(reading),
            ..TrayView::default()
        };
        let no_beacon = TrayView {
            running: true,
            update: None,
            ..TrayView::default()
        };
        let up = TrayView {
            running: true,
            update: Some(reading),
            ..TrayView::default()
        };

        // Loading — and note the booting view HAS a reading, so this cannot be passing merely because
        // the beacon was absent.
        assert_eq!(
            note(&booting),
            Some(PaneNote::Waiting(
                "The auto-update settings are still being read."
            ))
        );
        // Error, and its absence once the beacon has answered.
        assert!(matches!(note(&no_beacon), Some(PaneNote::Unreachable(_))));
        assert_eq!(note(&up), Some(PaneNote::Ready));

        for view in every_view() {
            assert!(
                !matches!(note(&view), Some(PaneNote::Empty(_))),
                "Settings became empty, so its empty-state sentence is now live and untested\n  view: {}",
                describe(&view)
            );
        }
    }

    /// **Every declared tab is actually emitted, in every view.**
    ///
    /// The inverse of the guard it replaces. `Advanced` was declared and never constructed, and the
    /// old test pinned that absence; the five-tab reshape deleted it, and what is worth pinning now
    /// is the opposite property — a tab a person can see in the sidebar is a tab the model always
    /// has content for. Swept over [`TabId::all`], which is derived from the enum, so a sixth tab
    /// that nobody wired into [`build`] fails here rather than shipping as a name with no pane
    /// (dig_ecosystem#2358).
    #[test]
    fn every_declared_tab_is_emitted_in_every_view() {
        for view in every_view() {
            let model = build(&view);
            for id in TabId::all() {
                assert!(
                    model.tab(id).is_some(),
                    "{id:?} is declared but was not emitted
  view: {}",
                    describe(&view)
                );
            }
            assert_eq!(
                model.tabs.len(),
                TabId::all().len(),
                "the model emitted a different number of tabs than are declared
  view: {}",
                describe(&view)
            );
        }
    }

    #[test]
    fn a_window_section_never_holds_a_submenu() {
        for view in every_view() {
            for tab in &build(&view).tabs {
                for section in &tab.sections {
                    for row in &section.rows {
                        assert!(
                            !matches!(row, MenuRow::Submenu { .. }),
                            "{:?} holds a submenu; a tab is already the nesting\n  view: {}",
                            tab.id,
                            describe(&view)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_subsumed_action_never_appears_as_a_row() {
        for view in every_view() {
            let model = build(&view);
            for (action, tab) in SUBSUMED_BY_TAB {
                if let Some(rendered) = model.tab(tab) {
                    assert!(
                        !rendered.actions().contains(&action),
                        "{action:?} is page content on {tab:?}, not a row\n  view: {}",
                        describe(&view)
                    );
                }
            }
        }
    }

    /// Subsumption is the one place the invariant takes a human's word for it, so bound what it can
    /// excuse: a subsuming tab must actually render CONTENT, in every view, or the promise that it
    /// carries the action's own material is void and the invariant has waved through an unreachable
    /// verb.
    ///
    /// This asserted `.is_some()` once — presence, not content — and that shape is why the Wallet tab
    /// could render as an empty pane in 96 views with this test green. An assertion bounds what any
    /// amount of testing beneath it can find, so the assertion is the thing that had to change.
    #[test]
    fn a_subsuming_tab_always_renders_content() {
        for view in every_view() {
            let model = build(&view);
            for (action, tab) in SUBSUMED_BY_TAB {
                let rendered = model.tab(tab).unwrap_or_else(|| {
                    panic!(
                        "{tab:?} claims to render {action:?} but is not shown\n  view: {}",
                        describe(&view)
                    )
                });
                assert!(
                    renders_something(rendered),
                    "{tab:?} claims to render {action:?} and is an EMPTY PANE\n  view: {}",
                    describe(&view)
                );
            }
        }
    }

    /// **Every tab that renders shows the user something.** The assertion that would have caught the
    /// empty Wallet pane, so it is the one that must exist.
    ///
    /// It also closes a second hole for free: `SUBSUMED_BY_TAB` was guarded against a MISSING entry but
    /// not a WRONG one — an action mapped to a tab that renders nothing of it would have passed. A tab
    /// cannot claim to carry content it does not show.
    #[test]
    fn every_rendered_tab_has_content() {
        for view in every_view() {
            for tab in &build(&view).tabs {
                assert!(
                    renders_something(tab),
                    "{:?} rendered as an empty pane\n  view: {}",
                    tab.id,
                    describe(&view)
                );
                for section in &tab.sections {
                    assert!(
                        !section.rows.is_empty() || section.heading.is_some(),
                        "{:?} holds a section with neither rows nor a heading\n  view: {}",
                        tab.id,
                        describe(&view)
                    );
                }
            }
        }
    }

    /// **Every disabled row names the act that would enable it.** The rule the deleted
    /// `Tab::unavailable` field carried, now applied where disabling actually happens.
    ///
    /// The count assertion is not decoration: without it this passes vacuously the moment a refactor
    /// stops producing disabled rows, and it would then be a green test guarding nothing.
    #[test]
    fn every_disabled_row_in_the_window_names_a_remedy() {
        let mut disabled = 0usize;
        for view in every_view() {
            for tab in &build(&view).tabs {
                for section in &tab.sections {
                    for row in &section.rows {
                        let MenuRow::Action {
                            label,
                            enabled: false,
                            ..
                        } = row
                        else {
                            continue;
                        };
                        disabled += 1;
                        assert!(
                            label_names_a_remedy(label),
                            "{:?} disables {label:?}, which names no remedy\n  view: {}",
                            tab.id,
                            describe(&view)
                        );
                    }
                }
            }
        }
        assert!(
            disabled > 0,
            "no disabled row was examined, so this proves nothing"
        );
    }

    /// The remedy rule must be able to tell an instruction from a refusal, or asserting it proves
    /// nothing. Pinned from BOTH sides, because a rule tested only on what it accepts can only confirm
    /// itself.
    #[test]
    fn the_remedy_rule_rejects_a_bare_refusal() {
        // Every shape the app really ships.
        assert!(label_names_a_remedy(
            "Show my recovery phrase (unlock first)"
        ));
        assert!(label_names_a_remedy(
            "Copy my receive address (set a password first)"
        ));
        assert!(label_names_a_remedy(
            "Set up my DIG Account (not supported on this system yet)"
        ));
        assert!(label_names_a_remedy(
            "Change the size limit (connect a node first)…"
        ));
        // Refusals that name nothing to do.
        assert!(!label_names_a_remedy("Not available"));
        assert!(!label_names_a_remedy("Show my recovery phrase"));
        assert!(!label_names_a_remedy("This cannot be used right now"));
        assert!(!label_names_a_remedy(""));
        assert!(!label_names_a_remedy("   "));
    }

    /// Each of the four async states is produced by a real view, and each is ABSENT from a real view
    /// that should not have it. A state no view produces is a state nobody has seen drawn.
    #[test]
    fn every_pane_state_is_reachable_and_is_not_universal() {
        let note = |view: &TrayView, id: TabId| build(view).tab(id).map(|tab| tab.note.clone());
        let booting = TrayView {
            running: false,
            ..TrayView::default()
        };
        let up = TrayView {
            running: true,
            // A node that ANSWERED — the Home tab reports on the node, so a healthy fixture must
            // have one (dig_ecosystem#2330).
            node_connected: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some("xch1abc".to_string()),
            cache: Some(CacheSnapshot {
                cap_bytes: CACHE_PRESETS[2],
                used_bytes: 1,
            }),
            ..TrayView::default()
        };

        // Loading, and its absence once the agent is up.
        assert_eq!(
            note(&booting, TabId::Home),
            Some(PaneNote::Waiting("The DIG agent is still starting."))
        );
        assert_eq!(note(&up, TabId::Home), Some(PaneNote::Ready));

        // Error, and its absence once a node has reported.
        assert!(matches!(
            note(&booting, TabId::Content),
            Some(PaneNote::Unreachable(_))
        ));
        assert_eq!(note(&up, TabId::Content), Some(PaneNote::Ready));

        // Empty, and its absence once the tab has something to click. With no account the Wallet tab
        // keeps its balance heading and no row, because subsumption takes both `AboutWallet` rows.
        assert!(matches!(
            note(&booting, TabId::Wallet),
            Some(PaneNote::Empty(_))
        ));
        assert_eq!(note(&up, TabId::Wallet), Some(PaneNote::Ready));

        // Success. The Account tab, because it is `Ready` the moment an account has been REPORTED
        // — Settings would need a beacon in the fixture and would otherwise be `Unreachable`, which
        // is a different state wearing this assertion's name.
        assert_eq!(note(&up, TabId::Account), Some(PaneNote::Ready));
    }

    /// **A running agent with no node reports an unreachable node, not a ready one**
    /// (dig_ecosystem#2330).
    ///
    /// The Home tab reports on the node, so `Ready` with nothing connected is the same shape of
    /// false claim the Content tab already avoids. The two controls either side keep the assertion
    /// from being satisfied by a note that is always `Unreachable` or always `Waiting`.
    #[test]
    fn the_home_tab_names_the_missing_node_rather_than_reporting_ready() {
        let note = |view: &TrayView| build(view).tab(TabId::Home).map(|tab| tab.note.clone());
        let booting = TrayView {
            running: false,
            node_connected: false,
            ..TrayView::default()
        };
        let no_node = TrayView {
            running: true,
            node_connected: false,
            ..TrayView::default()
        };
        let connected = TrayView {
            running: true,
            node_connected: true,
            ..TrayView::default()
        };

        assert!(matches!(note(&booting), Some(PaneNote::Waiting(_))));
        assert!(
            matches!(note(&no_node), Some(PaneNote::Unreachable(_))),
            "a started agent with no node must say the node is missing: {:?}",
            note(&no_node)
        );
        assert_eq!(note(&connected), Some(PaneNote::Ready));
    }

    /// A pane note is a complete sentence, and the two that state a PROBLEM also state the way out.
    #[test]
    fn every_pane_note_is_a_sentence_and_the_problems_name_a_remedy() {
        let mut seen = 0usize;
        for view in every_view() {
            for tab in &build(&view).tabs {
                let sentence = match &tab.note {
                    PaneNote::Ready => continue,
                    PaneNote::Waiting(text)
                    | PaneNote::Unreachable(text)
                    | PaneNote::Empty(text) => *text,
                };
                seen += 1;
                assert!(
                    sentence.trim().ends_with('.'),
                    "{:?} says {sentence:?}, which is not a complete sentence\n  view: {}",
                    tab.id,
                    describe(&view)
                );
            }
        }
        assert!(
            seen > 0,
            "no pane note was examined, so this proves nothing"
        );
        // `Waiting` is exempt: waiting has no remedy other than waiting.
        assert!(label_names_a_remedy(nothing_to_do(TabId::Wallet)));
        assert!(label_names_a_remedy(nothing_to_do(TabId::Content)));
    }

    /// dig_ecosystem#2257 — the property `action_id`'s doc claims, tested for real at last.
    #[test]
    fn stable_ids_are_unique_across_every_variant_this_shell_can_build() {
        let actions = every_action();
        let ids: BTreeSet<String> = actions
            .iter()
            .map(|action| crate::tray_menu::action_id(*action))
            .collect();
        assert_eq!(
            ids.len(),
            actions.len(),
            "two variants share one id, so a click cannot say which was meant"
        );
    }

    /// A payload-carrying variant must not collapse to one id — six cache presets are six verbs.
    #[test]
    fn a_payload_carrying_variant_has_one_id_per_value() {
        let cache_ids: BTreeSet<String> = CACHE_PRESETS
            .iter()
            .map(|bytes| crate::tray_menu::action_id(TrayAction::SetCacheCap { bytes: *bytes }))
            .collect();
        assert_eq!(cache_ids.len(), CACHE_PRESETS.len());

        let app_ids: BTreeSet<String> = APPS
            .iter()
            .map(|app| crate::tray_menu::action_id(TrayAction::LaunchApp(app.id)))
            .collect();
        assert_eq!(app_ids.len(), APPS.len());
    }

    #[test]
    fn a_sidebar_id_is_derived_from_the_variant_and_is_unique() {
        let tabs = TabId::all();
        let ids: BTreeSet<String> = tabs.iter().map(|tab| tab_element_id(*tab)).collect();
        assert_eq!(ids.len(), tabs.len());
        assert_eq!(tab_element_id(TabId::Wallet), "dig-window-tab:Wallet");
    }

    /// **The Home tab's launcher is the registry, whatever the registry becomes.**
    ///
    /// Asserted on the LAUNCHER SECTION rather than on the tab's whole action list, because Home
    /// also carries the two diagnostic verbs: counting every action would pass on a build whose
    /// registry had emptied and whose diagnostics had grown by one.
    #[test]
    fn the_home_launcher_renders_one_row_per_registry_entry() {
        let model = build(&TrayView::default());
        let home = model.tab(TabId::Home).expect("Home renders");
        let launched: Vec<TrayAction> = home
            .sections
            .iter()
            .filter(|section| section.heading.as_deref() == Some(APPS_HEADING))
            .flat_map(|section| &section.rows)
            .filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            })
            .collect();
        assert_eq!(launched.len(), APPS.len());
        for app in APPS {
            assert!(launched.contains(&TrayAction::LaunchApp(app.id)));
        }
    }

    /// A tab composes the shared builders rather than re-deriving them: the rows it shows are exactly
    /// the rows the tray's own group builder produced, minus anything the tab subsumes and minus a
    /// label the pane has already shown ([`drop_repeats`]).
    ///
    /// The expectation applies the window's own passes to the builder output rather than hard-coding
    /// a row list, so this stays a test that the window does not RE-DERIVE rules — not a transcript of
    /// today's rows, which would have to be edited every time a builder legitimately changed.
    #[test]
    fn each_tab_is_the_shared_group_builder_verbatim() {
        for view in every_view() {
            let account = view.account();
            let model = build(&view);
            let expect = |tab: TabId, rows: Vec<MenuRow>| {
                let mut seen = Vec::new();
                let expected: Vec<TrayAction> =
                    tidy(drop_repeats(drop_subsumed(rows, tab), &mut seen))
                        .into_iter()
                        .filter_map(|row| match row {
                            MenuRow::Action { action, .. } => Some(action),
                            _ => None,
                        })
                        .collect();
                let actual = model.tab(tab).map(Tab::actions).unwrap_or_default();
                assert_eq!(
                    actual,
                    expected,
                    "{tab:?} diverged from its group builder\n  view: {}",
                    describe(&view)
                );
            };
            expect(TabId::Content, cache_actions(view.cache.as_ref()));
            expect(TabId::Wallet, wallet_actions(&view, &account));
            expect(TabId::Settings, auto_update_actions(view.update.as_ref()));
            // The Account tab composes FOUR builders onto a single pane, so it is the one where a
            // label can repeat across a section boundary — `AboutDid` ends two of them. The de-dupe
            // runs across the whole tab, so `seen` is shared here rather than per-section.
            let mut seen = Vec::new();
            let mut account_rows = drop_repeats(view_account_actions(&view, &account), &mut seen);
            account_rows.extend(drop_repeats(profile_actions(&view), &mut seen));
            account_rows.extend(drop_repeats(
                security_actions(&account, view.second_factor),
                &mut seen,
            ));
            account_rows.extend(drop_repeats(management_actions(&account), &mut seen));
            let account_tab: Vec<TrayAction> = account_rows
                .into_iter()
                .filter_map(|row| match row {
                    MenuRow::Action { action, .. } => Some(action),
                    _ => None,
                })
                .collect();
            assert_eq!(
                model
                    .tab(TabId::Account)
                    .map(Tab::actions)
                    .unwrap_or_default(),
                account_tab,
                "Account diverged from its group builders\n  view: {}",
                describe(&view)
            );
        }
    }
}
