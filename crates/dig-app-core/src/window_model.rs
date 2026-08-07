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
//! no window at all ([`WindowHost::Unavailable`] — macOS today, and any Linux session with no display
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
    apps_actions, cache_actions, cache_label, management_actions, security_actions,
    view_account_actions, wallet_actions, MenuRow, TrayAction, TrayView,
};

/// One tab of the app window.
///
/// [`Advanced`](Self::Advanced) currently holds nothing: every candidate for it has a better home, and
/// a one-row tab is a `professional-ui` failure. It stays in the enum as declared room for later, and
/// [`build`] emits only non-empty tabs, so it does not render today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TabId {
    /// What the app is doing right now, and the way to the logs when it cannot say.
    Status,
    /// The account: what it is, and how to create, restore, replace or remove it.
    Account,
    /// Is my account safe right now — locking, the second factor, and paired apps.
    Security,
    /// What the account can do with money, which today is receive and understand.
    Wallet,
    /// The other DIG apps this install can open.
    Apps,
    /// The node's content-cache size limit.
    Cache,
    /// Declared room for later. Holds nothing today, so it is never rendered.
    Advanced,
}

impl TabId {
    /// The tab's user-facing label.
    fn label(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Account => "Account",
            Self::Security => "Security",
            Self::Wallet => "Wallet",
            Self::Apps => "Apps",
            Self::Cache => "Cache",
            Self::Advanced => "Advanced",
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
/// Checkably: the label contains a [remedy verb](REMEDY_VERBS). Unlike the tab-level version this does
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
        // The two rows that are not any group builder's: both are unconditional and always enabled on
        // the tray, so there is no rule to share. `OpenLogs` is the escape hatch for when the app
        // cannot say what is wrong, which is why it leads the window rather than hiding in Advanced.
        tab(
            TabId::Status,
            // The agent starts asynchronously, so a window opened during boot shows a Status tab whose
            // figures are still being gathered. Saying so is the loading state; saying nothing leaves a
            // person reading stale defaults as though they were the answer.
            match view.running {
                true => PaneNote::Ready,
                false => PaneNote::Waiting("The DIG agent is still starting."),
            },
            vec![Section {
                heading: None,
                rows: vec![
                    row(TrayAction::ShowStatus, "Status and details"),
                    row(TrayAction::OpenLogs, "Open the log folder"),
                ],
            }],
        ),
        tab(
            TabId::Account,
            PaneNote::Ready,
            vec![
                Section {
                    heading: Some("What this account is".to_string()),
                    rows: view_account_actions(view, &account),
                },
                Section {
                    heading: Some("Manage this account".to_string()),
                    rows: management_actions(&account),
                },
            ],
        ),
        tab(
            TabId::Security,
            PaneNote::Ready,
            vec![Section {
                heading: None,
                rows: security_actions(&account, view.second_factor),
            }],
        ),
        // The heading IS the balance sentence — the content `AboutWallet` would otherwise have opened
        // a window to show. That is what makes subsuming it honest rather than a quiet deletion.
        tab(
            TabId::Wallet,
            PaneNote::Ready,
            vec![Section {
                heading: Some(crate::wallet::overview::menu_balance_label(
                    &crate::wallet::overview::WalletOverview::of_tray(view).balance,
                )),
                rows: wallet_actions(view, &account),
            }],
        ),
        tab(
            TabId::Apps,
            PaneNote::Ready,
            vec![Section {
                heading: None,
                rows: apps_actions(),
            }],
        ),
        // Same reasoning as Wallet's heading: the tray puts the live usage-against-cap on the submenu's
        // parent label, so the tab that replaces that submenu carries the same figure.
        tab(
            TabId::Cache,
            // The cap and the usage both come from the node. With no node connected they are not late,
            // they are absent — so this is the error state, not the loading one, and it names the act
            // that changes the answer.
            match view.cache {
                Some(_) => PaneNote::Ready,
                None => PaneNote::Unreachable(
                    "No node is connected, so the size limit cannot be read or changed. Start the                      DIG node and this tab will fill in.",
                ),
            },
            vec![Section {
                heading: Some(cache_label(view.cache.as_ref())),
                rows: cache_actions(view.cache.as_ref()),
            }],
        ),
    ];

    WindowModel {
        tabs: tabs.into_iter().filter(Tab::has_content).collect(),
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
        TabId::Security => "Set up a DIG Account to choose how it is protected.",
        TabId::Apps => "Install another DIG app and it will appear here.",
        TabId::Cache => "Start the DIG node to choose a size limit.",
        TabId::Status | TabId::Advanced => "There is nothing to do here right now.",
    }
}

/// Assemble one tab: drop the rows this tab renders as page content, then tidy the separators.
///
/// `note` is the caller's answer for the loading and error states, which only the view can decide. The
/// EMPTY state is decided here instead, from the assembled result: a tab is empty when it ends up with
/// no clickable row, and that is a fact about what came out rather than about what went in. Computing
/// it at the call sites would mean six predicates that each had to stay in step with subsumption.
fn tab(id: TabId, note: PaneNote, sections: Vec<Section>) -> Tab {
    let sections: Vec<Section> = sections
        .into_iter()
        .map(|section| Section {
            heading: section.heading,
            rows: tidy(drop_subsumed(section.rows, id)),
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
            TrayAction::CopyReceiveAddress,
            TrayAction::AboutWallet,
            TrayAction::SetCustomCacheCap,
            TrayAction::AboutCache,
            TrayAction::OpenWindow,
            TrayAction::OpenLogs,
            TrayAction::Quit,
        ];
        all.extend(CACHE_PRESETS.map(|bytes| TrayAction::SetCacheCap { bytes }));
        all.extend(APPS.iter().map(|app| TrayAction::LaunchApp(app.id)));
        all
    }

    /// A compile-time guard: adding a `TrayAction` variant breaks this match, which is the prompt to
    /// add it to `every_action` and decide which tab it belongs on.
    #[allow(dead_code)]
    fn assert_exhaustive(action: TrayAction) {
        match action {
            TrayAction::ShowStatus
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
            | TrayAction::CopyReceiveAddress
            | TrayAction::AboutWallet
            | TrayAction::SetCacheCap { .. }
            | TrayAction::SetCustomCacheCap
            | TrayAction::AboutCache
            | TrayAction::LaunchApp(_)
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
                                    views.push(TrayView {
                                        account: Some(account.clone()),
                                        window_host: host,
                                        second_factor,
                                        cache,
                                        profile_id: profile_id.clone(),
                                        receive_address: receive_address.clone(),
                                        running,
                                        ..TrayView::default()
                                    });
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
            "account={:?} host={:?} second_factor={} running={} cache={} profile_id={} address={}",
            view.account,
            view.window_host,
            view.second_factor,
            view.running,
            view.cache.is_some(),
            view.profile_id.is_some(),
            view.receive_address.is_some(),
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
    fn security_is_usable_without_an_unlocked_account() {
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
                .tab(TabId::Security)
                .cloned()
                .unwrap_or_else(|| panic!("Security must render\n  view: {}", describe(&view)));
            assert!(
                !tab.actions().is_empty(),
                "Security must offer something without an unlock\n  view: {}",
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
            // x profile_id x address x running
            5 * 2 * 2 * 2 * 2 * 2,
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

    #[test]
    fn advanced_never_renders_because_it_holds_nothing() {
        for view in every_view() {
            for tab in &build(&view).tabs {
                assert_ne!(tab.id, TabId::Advanced, "Advanced holds nothing yet");
            }
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
            note(&booting, TabId::Status),
            Some(PaneNote::Waiting("The DIG agent is still starting."))
        );
        assert_eq!(note(&up, TabId::Status), Some(PaneNote::Ready));

        // Error, and its absence once a node has reported.
        assert!(matches!(
            note(&booting, TabId::Cache),
            Some(PaneNote::Unreachable(_))
        ));
        assert_eq!(note(&up, TabId::Cache), Some(PaneNote::Ready));

        // Empty, and its absence once the tab has something to click. With no account the Wallet tab
        // keeps its balance heading and no row, because subsumption takes both `AboutWallet` rows.
        assert!(matches!(
            note(&booting, TabId::Wallet),
            Some(PaneNote::Empty(_))
        ));
        assert_eq!(note(&up, TabId::Wallet), Some(PaneNote::Ready));

        // Success.
        assert_eq!(note(&up, TabId::Apps), Some(PaneNote::Ready));
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
        assert!(label_names_a_remedy(nothing_to_do(TabId::Cache)));
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
        let tabs = [
            TabId::Status,
            TabId::Account,
            TabId::Security,
            TabId::Wallet,
            TabId::Apps,
            TabId::Cache,
            TabId::Advanced,
        ];
        let ids: BTreeSet<String> = tabs.iter().map(|tab| tab_element_id(*tab)).collect();
        assert_eq!(ids.len(), tabs.len());
        assert_eq!(tab_element_id(TabId::Wallet), "dig-window-tab:Wallet");
    }

    /// The Apps tab is the registry, whatever the registry becomes.
    #[test]
    fn the_apps_tab_renders_one_row_per_registry_entry() {
        let model = build(&TrayView::default());
        let apps = model.tab(TabId::Apps).expect("Apps renders");
        assert_eq!(apps.actions().len(), APPS.len());
        for app in APPS {
            assert!(apps.actions().contains(&TrayAction::LaunchApp(app.id)));
        }
    }

    /// A tab composes the shared builders rather than re-deriving them: the rows it shows are exactly
    /// the rows the tray's own group builder produced, minus anything the tab subsumes.
    #[test]
    fn each_tab_is_the_shared_group_builder_verbatim() {
        for view in every_view() {
            let account = view.account();
            let model = build(&view);
            let expect = |tab: TabId, rows: Vec<MenuRow>| {
                let expected: Vec<TrayAction> = tidy(drop_subsumed(rows, tab))
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
            expect(
                TabId::Security,
                security_actions(&account, view.second_factor),
            );
            expect(TabId::Apps, apps_actions());
            expect(TabId::Cache, cache_actions(view.cache.as_ref()));
            expect(TabId::Wallet, wallet_actions(&view, &account));
            let mut account_rows = view_account_actions(&view, &account);
            account_rows.extend(management_actions(&account));
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
