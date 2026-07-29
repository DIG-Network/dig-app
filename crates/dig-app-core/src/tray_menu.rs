//! The tray menu **model** — what the user can see and do, as data (dig_ecosystem#1752).
//!
//! # Why the menu is a model and not just code in the shell
//!
//! Before this module the tray offered two actions, "Lock now" and "Quit DIG", so a person who
//! installed DIG had no way to create an account, see their recovery phrase, or find out what state
//! they were in. Growing that into a real menu means real rules — *which* items appear, which are
//! enabled, and what each one says — and rules that live inside a platform event loop cannot be tested.
//!
//! So the shell ([`dig-app`'s `tray` module](../../dig_app/index.html)) asks [`build`] for a
//! [`MenuModel`] and does nothing but render it and dispatch the [`TrayAction`]s back. Every rule below
//! is unit-tested here.
//!
//! # The two craft rules this module enforces (§6.1 `professional-ui`)
//!
//! - **Never trap the user.** Every state offers a way forward AND a way out: "Quit DIG" and the log
//!   folder are always enabled, no matter how badly the account or node is doing, and no action is ever
//!   the *only* thing on the menu.
//! - **Say the true state, including the unflattering one.** An account with no recovery phrase is
//!   labelled as such, in the menu, permanently — not silently treated as safe. A DID that costs money
//!   to create says so before the user clicks it.

use std::fmt;

/// The widest a status row may be, in characters.
///
/// A native tray menu sizes itself to its widest item, so ONE long row stretches the whole menu —
/// past the screen edge on a real desktop, where it is unreadable and can push the action rows out of
/// reach. The engine's disconnected reasons are deliberately verbose and actionable (a real one
/// observed in the field runs to ~700 characters: the control-token explanation, complete with a
/// reinstall recipe), which is exactly right for a log or a details window and impossible in a menu
/// row.
///
/// 72 is chosen to sit inside the narrowest surface that must render it — a macOS menu-bar dropdown
/// near the right edge of a 1280-pt display — with the full text always one click away via
/// [`TrayAction::ShowNodeDetails`], so nothing is lost by bounding it.
pub const MAX_STATUS_ROW_CHARS: usize = 72;

/// Where the account is, as far as the user is concerned. This is the four-state async surface for the
/// account: not-possible-here, none-yet, locked, and live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountState {
    /// This host cannot hold an account yet — no per-application credential store (today: Linux). The
    /// user is told why rather than shown a button that silently does nothing.
    Unsupported,
    /// No account exists yet. The first-run path is open.
    Absent,
    /// An account exists but is locked, so nothing can be signed or revealed until it unlocks.
    Locked,
    /// An account is live.
    Unlocked {
        /// Whether a recovery phrase is stored for it. `false` = enrolled before recovery phrases
        /// existed, so **it cannot be recovered from words** and the menu says so.
        recoverable: bool,
    },
}

/// Everything the menu is rendered from — one snapshot, read once per repaint.
#[derive(Debug, Clone, Default)]
pub struct TrayView {
    /// Whether the agent loop is running.
    pub running: bool,
    /// The node connection line, already summarized by the engine (connecting / connected+detail /
    /// the actionable reason it is not).
    pub node: String,
    /// The account's user-visible state.
    pub account: Option<AccountState>,
    /// The root profile's stable id (the hex identity public key until the on-chain DID mint lands).
    pub profile_id: Option<String>,
    /// The profile's **minted on-chain** `did:chia:` DID, or `None` when it has none.
    ///
    /// This must be set from evidence that a DID was actually minted on chain — never from a local
    /// profile reference that merely has DID-shaped text in it. The shell previously filled it from
    /// `config.active_profile`, a locally-written string; that field is never populated today so the row
    /// was inert, but the moment profile selection began writing it the tray would have claimed an
    /// on-chain identity that does not exist. Since minting is unimplemented, the honest value is
    /// always `None` (see the `never_claims_an_on_chain_did_from_a_local_profile_reference` test).
    pub did: Option<String>,
}

impl TrayView {
    /// The account state, defaulting to [`AccountState::Absent`] before the first boot has reported.
    fn account(&self) -> AccountState {
        self.account.clone().unwrap_or(AccountState::Absent)
    }
}

/// What a live tray session knows about its account — the two facts the state derivation needs.
///
/// `keys_unlocked` is read FRESH from the residency, never inferred from the session existing: a session
/// outlives its key material by design (lock-now and the idle auto-lock drop the keys and keep the
/// session, so the sign path can re-unlock into it). Confusing "we have a session" with "the account is
/// unlocked" is what made the menu report `unlocked` after Lock now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFacts {
    /// Whether the residency still holds key material RIGHT NOW.
    pub keys_unlocked: bool,
    /// Whether a recovery phrase is stored for this account.
    pub recoverable: bool,
}

impl SessionFacts {
    /// Read the facts off a live residency.
    ///
    /// This lives here, beside the rules that consume it, so the `is_any_unlocked` call itself is covered
    /// by tests rather than sitting untested in a binary.
    pub fn of(residency: &crate::account::residency::AccountResidency, recoverable: bool) -> Self {
        use crate::session_lock::SessionKeys;

        Self {
            keys_unlocked: residency.is_any_unlocked(),
            recoverable,
        }
    }
}

/// Derive the account state the menu shows.
///
/// - `host_supports_accounts` — whether this OS can hold an account at all (a per-application-ACL
///   credential store exists).
/// - `enrolled` — whether an account exists at rest.
/// - `session` — the live session's facts, or `None` when the shell holds no session.
///
/// A session whose KEYS have been dropped reports [`AccountState::Locked`] — deliberately the same state
/// as a not-yet-unlocked account, because the way back in is the same (`Unlock…`). Anything else would
/// report a lock that is not there and offer no route out of it (`SPEC.md` §3.1c).
pub fn account_state(
    host_supports_accounts: bool,
    enrolled: bool,
    session: Option<SessionFacts>,
) -> AccountState {
    if !host_supports_accounts {
        return AccountState::Unsupported;
    }
    match session {
        Some(SessionFacts {
            keys_unlocked: true,
            recoverable,
        }) => AccountState::Unlocked { recoverable },
        // A session with no keys, or no session at all: locked if there is something to unlock.
        Some(_) => AccountState::Locked,
        None if enrolled => AccountState::Locked,
        None => AccountState::Absent,
    }
}

/// One thing the user can click. The shell maps each to its handler; the model never performs an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrayAction {
    /// Create a brand-new account: generate a recovery phrase, show it once, confirm, enrol.
    SetUpAccount,
    /// Restore an existing account from its recovery phrase.
    RestoreFromPhrase,
    /// Unlock the existing account.
    Unlock,
    /// Re-seal the session now.
    LockNow,
    /// Re-display the account's recovery phrase, behind unlock + a native confirm.
    ShowRecoveryPhrase,
    /// Offered ONLY to an account that has no recovery phrase: EXPLAIN the situation and what the one
    /// remedy would be (creating a new account, which yields a new identity and address).
    ///
    /// It informs and nothing more — it does NOT replace or delete anything. Destroying an existing
    /// custody root is not something to reach in one click from a tray menu, so it is deliberately not
    /// wired here (see [`explain_missing_phrase`](crate::account::journey::explain_missing_phrase),
    /// whose copy states "Nothing has changed yet").
    FixMissingPhrase,
    /// Copy the profile's DIG ID to the clipboard.
    CopyDigId,
    /// Mint the profile's on-chain `did:chia:` DID — spends real XCH, so never automatic.
    CreateDid,
    /// Show the node status line in full, in a window that can hold it.
    ///
    /// The menu row is bounded to [`MAX_STATUS_ROW_CHARS`], and the engine's reason for not being
    /// connected is the one status text that regularly exceeds it — and is also the most actionable
    /// thing the app can tell a user, since it names what to start or reinstall. This is where the
    /// bounded row hands back the part it had to cut.
    ShowNodeDetails,
    /// Open the log folder, the escape hatch when something is wrong and the menu cannot say why.
    OpenLogs,
    /// Stop the agent and exit.
    Quit,
}

/// A row of the rendered menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuRow {
    /// Non-clickable status text.
    Status(String),
    /// A visual divider.
    Separator,
    /// A clickable item.
    Action {
        /// What clicking it does.
        action: TrayAction,
        /// Its user-facing label.
        label: String,
        /// Whether it is clickable right now. A disabled item still SHOWS, so the menu's shape is
        /// stable and the user can see the capability exists.
        enabled: bool,
    },
}

impl MenuRow {
    /// A convenience for building an enabled/disabled action row.
    fn action(action: TrayAction, label: impl Into<String>, enabled: bool) -> Self {
        MenuRow::Action {
            action,
            label: label.into(),
            enabled,
        }
    }
}

/// The complete menu, in render order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuModel {
    /// The rows, top to bottom.
    pub rows: Vec<MenuRow>,
}

impl MenuModel {
    /// The row for `action`, if the menu offers it. Used by the shell to bind handlers, and by the
    /// tests to assert on one item without indexing into a list.
    pub fn find(&self, wanted: TrayAction) -> Option<&MenuRow> {
        self.rows
            .iter()
            .find(|row| matches!(row, MenuRow::Action { action, .. } if *action == wanted))
    }

    /// Whether `action` is present AND clickable.
    pub fn is_enabled(&self, action: TrayAction) -> bool {
        matches!(
            self.find(action),
            Some(MenuRow::Action { enabled: true, .. })
        )
    }

    /// Whether `action` appears at all.
    pub fn offers(&self, action: TrayAction) -> bool {
        self.find(action).is_some()
    }

    /// The label `action` is rendered with, if present.
    pub fn label_of(&self, action: TrayAction) -> Option<&str> {
        match self.find(action) {
            Some(MenuRow::Action { label, .. }) => Some(label.as_str()),
            _ => None,
        }
    }
}

/// Build the menu for `view`.
///
/// The order is deliberate: **what is true** (status), then **what to do about the account**, then
/// **identity**, then the always-available escapes. A person opening the tray reads their state before
/// they are offered a choice.
pub fn build(view: &TrayView) -> MenuModel {
    let account = view.account();
    let mut rows = vec![
        MenuRow::Status(running_label(view.running).to_string()),
        MenuRow::Status(status_row_text(&view.node)),
        MenuRow::Status(format!("Account: {account}")),
        MenuRow::Status(format!(
            "DIG ID: {}",
            dig_id_label(view.profile_id.as_deref())
        )),
        MenuRow::Status(format!("On-chain DID: {}", did_label(view.did.as_deref()))),
        MenuRow::Separator,
    ];
    rows.extend(account_actions(&account));
    rows.push(MenuRow::Separator);
    rows.extend(identity_actions(view, &account));
    rows.push(MenuRow::Separator);
    // The diagnostics block. `Node details…` is enabled only when the bounded row actually cut
    // something — otherwise the row already says everything the window would, and an enabled item that
    // re-shows visible text is noise.
    rows.push(MenuRow::action(
        TrayAction::ShowNodeDetails,
        "Node details…",
        was_truncated(&view.node),
    ));
    // The two escapes, always clickable: whatever else has gone wrong, a person can read the logs and
    // leave (§6.1 "never trap the user").
    rows.push(MenuRow::action(
        TrayAction::OpenLogs,
        "Open the log folder",
        true,
    ));
    rows.push(MenuRow::action(TrayAction::Quit, "Quit DIG", true));
    MenuModel { rows }
}

/// The set-up / unlock / lock block, which depends only on where the account is.
fn account_actions(account: &AccountState) -> Vec<MenuRow> {
    let can_create = matches!(account, AccountState::Absent);
    let unlocked = matches!(account, AccountState::Unlocked { .. });
    vec![
        MenuRow::action(
            TrayAction::SetUpAccount,
            "Set up my DIG Account…",
            can_create,
        ),
        // The label names the TERMINAL because that is where restore actually happens. A tray menu has
        // no text field, so this item cannot take 24 words itself — it explains and hands over the exact
        // `dign account restore` command. Labelling it plainly "Restore from a recovery phrase…" promised
        // an action the item does not perform, which reads as a broken menu entry even though a window
        // does open (dig_ecosystem#1773). Tray-native restore needs a real per-OS input dialog; until
        // that exists the label tells the truth rather than the intention.
        MenuRow::action(
            TrayAction::RestoreFromPhrase,
            "Restore from a recovery phrase (in a terminal)…",
            can_create,
        ),
        MenuRow::action(
            TrayAction::Unlock,
            "Unlock…",
            matches!(account, AccountState::Locked),
        ),
        MenuRow::action(TrayAction::LockNow, "Lock now", unlocked),
    ]
}

/// The identity block: the recovery phrase, the DIG ID, and the on-chain DID.
///
/// The recovery-phrase row is *either* "show it" or "you don't have one" — never both, because offering
/// a disabled "show my recovery phrase" to someone who has none tells them nothing about why.
fn identity_actions(view: &TrayView, account: &AccountState) -> Vec<MenuRow> {
    let mut rows = match account {
        AccountState::Unlocked { recoverable: false } => vec![MenuRow::action(
            TrayAction::FixMissingPhrase,
            "This account has NO recovery phrase — what to do…",
            true,
        )],
        _ => vec![MenuRow::action(
            TrayAction::ShowRecoveryPhrase,
            "Show my recovery phrase…",
            matches!(account, AccountState::Unlocked { recoverable: true }),
        )],
    };
    rows.push(MenuRow::action(
        TrayAction::CopyDigId,
        "Copy my DIG ID",
        view.profile_id.is_some(),
    ));
    // On-chain minting is not implemented (`dig-account`'s minter is a Phase-2 stub), so this row is
    // DISABLED and says why, right in the label.
    //
    // It was previously enabled whenever the account was unlocked, and clicking it opened a dialog whose
    // own text admitted the feature does not exist — an enabled control for a capability that cannot
    // run, which is the precise defect dig_ecosystem#1773 closes. The row still SHOWS, because the
    // capability is real and coming and a person is entitled to know it exists; what it must not do is
    // invite a click it cannot honour (§6.1).
    //
    // The cost stays in the label rather than only in a dialog: when this does light up, a person
    // deciding whether to click should know it spends money before they click (§3.7 — mainnet is real
    // money).
    rows.push(MenuRow::action(
        TrayAction::CreateDid,
        "Create my on-chain DID (spends XCH) — not in this version yet",
        false,
    ));
    rows
}

/// Fit `full` into one status row: its first line, bounded to [`MAX_STATUS_ROW_CHARS`].
///
/// Counts and cuts by CHARACTER, not by byte — the connected summary contains `·`, so a byte-indexed
/// slice would panic on a multi-byte boundary. The ellipsis is what tells the reader there is more,
/// and [`TrayAction::ShowNodeDetails`] is where they get it.
fn status_row_text(full: &str) -> String {
    let first_line = full.lines().next().unwrap_or("");
    if first_line.chars().count() <= MAX_STATUS_ROW_CHARS && first_line == full {
        return full.to_string();
    }
    let kept: String = first_line.chars().take(MAX_STATUS_ROW_CHARS).collect();
    format!("{}…", kept.trim_end())
}

/// Whether [`status_row_text`] would have to leave something out of the row — i.e. whether a details
/// window has anything to add.
fn was_truncated(full: &str) -> bool {
    status_row_text(full) != full
}

/// The agent's own liveness line.
fn running_label(running: bool) -> &'static str {
    if running {
        "DIG — running"
    } else {
        "DIG — starting…"
    }
}

/// A DIG ID abbreviated for a menu row. The full value goes to the clipboard; a 64-character hex key
/// pasted into a tray menu is unreadable and would push the menu off the screen.
fn dig_id_label(profile_id: Option<&str>) -> String {
    match profile_id {
        Some(id) if id.len() > 16 => format!("{}…{}", &id[..8], &id[id.len() - 8..]),
        Some(id) => id.to_string(),
        None => "(not set up yet)".to_string(),
    }
}

/// The DID line. Absent is the NORMAL state — minting one costs money and is never automatic — so it is
/// phrased as a choice not yet made, not as an error.
fn did_label(did: Option<&str>) -> String {
    did.unwrap_or("not created yet (optional)").to_string()
}

/// What to tell a user whose tray icon never appeared, for `os`, given the shell's `reason`.
///
/// # Why this exists (an invisible failure is the worst kind)
///
/// On Linux the AppIndicator library is **dlopened, not linked**, so on a desktop without
/// `libayatana-appindicator3-1` the process starts, reports itself healthy, and the icon simply never
/// appears. The user is left with an app that is running and unreachable — and every account surface
/// (setup, the recovery phrase, unlock) lives behind that icon.
///
/// So a tray that fails to mount MUST say so somewhere a person will find, name the likely cause, and
/// point at the way in that still works. This function is that message; it is pure so the wording is
/// tested rather than trusted.
pub fn tray_unavailable_advice(reason: &str, os: crate::Os) -> String {
    let cause = match os {
        // The overwhelmingly common cause, and one the user can act on in one command.
        crate::Os::Linux => {
            "\n\nOn Linux this is almost always a missing system tray library. Install \
             `libayatana-appindicator3-1` (Debian/Ubuntu) or `libappindicator-gtk3` (Fedora), then \
             start DIG again. Some desktops (GNOME) also need a tray extension such as \
             AppIndicator Support."
        }
        crate::Os::Windows | crate::Os::MacOs => "",
    };
    format!(
        "DIG is running, but its menu-bar icon could not be shown ({reason}), so the DIG menu is \
         not reachable on this desktop.{cause}\n\nUntil that is fixed, use the `dign` command-line \
         tool for your account: `dign account status` and `dign account restore`."
    )
}

impl fmt::Display for AccountState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AccountState::Unsupported => "not available on this system yet",
            AccountState::Absent => "not set up yet",
            AccountState::Locked => "locked",
            AccountState::Unlocked { recoverable: true } => "unlocked",
            AccountState::Unlocked { recoverable: false } => "unlocked — NO recovery phrase",
        };
        f.write_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(account: AccountState) -> TrayView {
        TrayView {
            running: true,
            node: "Node: connected".to_string(),
            account: Some(account),
            profile_id: Some("a".repeat(96)),
            did: None,
        }
    }

    /// The regression this whole module exists for: the tray must offer the account journey, not just
    /// lock + quit. Named for the gap so it is obvious what breaks if these rows disappear.
    #[test]
    fn the_menu_offers_the_account_journey_not_just_lock_and_quit() {
        let menu = build(&view(AccountState::Absent));
        for action in [
            TrayAction::SetUpAccount,
            TrayAction::RestoreFromPhrase,
            TrayAction::Unlock,
            TrayAction::LockNow,
            TrayAction::CopyDigId,
            TrayAction::CreateDid,
            TrayAction::OpenLogs,
            TrayAction::Quit,
        ] {
            assert!(menu.offers(action), "the menu must offer {action:?}");
        }
    }

    /// Never trap the user: from EVERY account state, the escapes stay clickable. Iterating all states
    /// is the point — a single-state fixture could not catch an escape that is disabled in one of them.
    #[test]
    fn the_escapes_are_enabled_in_every_account_state() {
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unlocked { recoverable: true },
            AccountState::Unlocked { recoverable: false },
        ] {
            let menu = build(&view(account.clone()));
            assert!(
                menu.is_enabled(TrayAction::Quit),
                "quit must work in {account:?}"
            );
            assert!(
                menu.is_enabled(TrayAction::OpenLogs),
                "the logs escape must work in {account:?}"
            );
        }
    }

    /// **Regression (#1773).** Every ENABLED row must be able to perform what its label says. Restore
    /// cannot take 24 words from a menu, so its label must say where restore happens instead of promising
    /// an action the row does not carry out.
    #[test]
    fn the_restore_row_says_where_restoring_actually_happens() {
        let menu = build(&view(AccountState::Absent));
        let label = menu.label_of(TrayAction::RestoreFromPhrase).unwrap();
        assert!(
            label.contains("terminal"),
            "an enabled row must not promise more than it does: {label}"
        );
    }

    #[test]
    fn setup_and_restore_are_offered_only_when_no_account_exists() {
        let absent = build(&view(AccountState::Absent));
        assert!(absent.is_enabled(TrayAction::SetUpAccount));
        assert!(absent.is_enabled(TrayAction::RestoreFromPhrase));

        for account in [
            AccountState::Locked,
            AccountState::Unlocked { recoverable: true },
        ] {
            let menu = build(&view(account.clone()));
            assert!(
                !menu.is_enabled(TrayAction::SetUpAccount),
                "{account:?} must not offer a second enrolment — that would overwrite a custody root"
            );
            assert!(!menu.is_enabled(TrayAction::RestoreFromPhrase));
        }
    }

    #[test]
    fn unlock_is_offered_only_while_locked_and_lock_only_while_unlocked() {
        let locked = build(&view(AccountState::Locked));
        assert!(locked.is_enabled(TrayAction::Unlock));
        assert!(!locked.is_enabled(TrayAction::LockNow));

        let unlocked = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(!unlocked.is_enabled(TrayAction::Unlock));
        assert!(unlocked.is_enabled(TrayAction::LockNow));
    }

    /// The reveal gate: the phrase is offered ONLY to an unlocked, recoverable account. The fixture
    /// varies ONE thing at a time across the four combinations, so a rule that ignored either
    /// `unlocked` or `recoverable` fails here.
    #[test]
    fn showing_the_phrase_requires_both_unlocked_and_recoverable() {
        assert!(build(&view(AccountState::Unlocked { recoverable: true }))
            .is_enabled(TrayAction::ShowRecoveryPhrase));

        for account in [
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unsupported,
        ] {
            assert!(
                !build(&view(account.clone())).is_enabled(TrayAction::ShowRecoveryPhrase),
                "{account:?} must not reveal a recovery phrase"
            );
        }
        // The recoverable=false case swaps the row entirely; see the next test.
        assert!(!build(&view(AccountState::Unlocked { recoverable: false }))
            .is_enabled(TrayAction::ShowRecoveryPhrase));
    }

    /// A phrase-less account is told so, plainly, in two places — the status line and its own action
    /// row — and is NOT shown a dead "show my recovery phrase" item.
    #[test]
    fn a_phrase_less_account_is_named_and_offered_the_remedy() {
        let menu = build(&view(AccountState::Unlocked { recoverable: false }));

        assert!(menu.is_enabled(TrayAction::FixMissingPhrase));
        assert!(
            !menu.offers(TrayAction::ShowRecoveryPhrase),
            "a dead reveal row explains nothing; the remedy row replaces it"
        );
        assert!(
            menu.rows.contains(&MenuRow::Status(
                "Account: unlocked — NO recovery phrase".to_string()
            )),
            "the status line must state the risk: {:?}",
            menu.rows
        );
    }

    /// A recoverable account must NOT be nagged with the remedy row — the control that proves the test
    /// above is reading `recoverable` and not simply always showing the warning.
    #[test]
    fn a_recoverable_account_is_not_shown_the_remedy_row() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(!menu.offers(TrayAction::FixMissingPhrase));
        assert!(menu
            .rows
            .contains(&MenuRow::Status("Account: unlocked".to_string())));
    }

    /// **Regression (#1773).** DID minting is not implemented, so the row must be DISABLED and must say
    /// why — never an enabled control whose handler can only apologise.
    ///
    /// Iterating EVERY account state is what makes this load-bearing: the defect was
    /// `enabled: unlocked && did.is_none()`, which a fixture in only the locked state would have scored
    /// as already-correct. The unlocked state is the one that was wrong.
    #[test]
    fn creating_a_did_is_disabled_everywhere_because_minting_does_not_exist_yet() {
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unlocked { recoverable: true },
            AccountState::Unlocked { recoverable: false },
        ] {
            let menu = build(&view(account.clone()));
            assert!(
                menu.offers(TrayAction::CreateDid),
                "{account:?}: the row must still SHOW — the capability is real and coming"
            );
            assert!(
                !menu.is_enabled(TrayAction::CreateDid),
                "{account:?}: an enabled control for an unimplemented capability is the #1773 defect"
            );
        }
    }

    /// The label must carry BOTH facts a person needs before they reach for it: that it is unavailable
    /// (so a disabled row is not a mystery) and that it costs money (§3.7 — mainnet is real money), so the
    /// cost is legible before the click on the day the row lights up.
    #[test]
    fn the_did_label_states_both_its_unavailability_and_its_cost() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        let label = menu.label_of(TrayAction::CreateDid).unwrap();
        assert!(
            label.contains("XCH"),
            "the label must name the cost, not hide it in a dialog: {label}"
        );
        assert!(
            label.contains("not in this version yet"),
            "a disabled row must say WHY it is disabled: {label}"
        );
    }

    /// With no minted DID the row must say so rather than showing something DID-shaped.
    ///
    /// The model's job is to render what it is given (that is what will display a real minted DID the day
    /// one exists — `a_minted_did_is_shown_in_full` covers that direction). The rule this pins is the
    /// other direction: an ABSENT DID must read as an unmade choice, and the shell is what must never
    /// supply a locally-written profile reference here — see [`TrayView::did`], which is now documented as
    /// requiring chain evidence, and `snapshot` in the shell, which passes `None` for that reason.
    #[test]
    fn an_absent_did_is_never_dressed_up_as_a_minted_one() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(
            menu.rows.contains(&MenuRow::Status(
                "On-chain DID: not created yet (optional)".to_string()
            )),
            "with no minted DID the row must say so: {:?}",
            menu.rows
        );
    }

    /// An absent DID reads as an unmade choice, not a failure — it is the normal state.
    #[test]
    fn a_missing_did_reads_as_optional_not_broken() {
        let rows = build(&view(AccountState::Unlocked { recoverable: true })).rows;
        assert!(rows.contains(&MenuRow::Status(
            "On-chain DID: not created yet (optional)".to_string()
        )));
    }

    #[test]
    fn a_minted_did_is_shown_in_full() {
        let did = "did:chia:1abcdef";
        let menu = build(&TrayView {
            did: Some(did.to_string()),
            ..view(AccountState::Unlocked { recoverable: true })
        });
        assert!(menu
            .rows
            .contains(&MenuRow::Status(format!("On-chain DID: {did}"))));
    }

    /// A 96-character hex key must be abbreviated — but must keep BOTH ends, so a user can eyeball that
    /// the id in the menu matches the one they pasted. A prefix-only rendering would fail this.
    #[test]
    fn a_long_dig_id_is_abbreviated_at_both_ends() {
        let id = format!("{}{}{}", "1".repeat(8), "0".repeat(80), "9".repeat(8));
        let label = dig_id_label(Some(&id));
        assert_eq!(label, "11111111…99999999");
        assert!(label.len() < id.len());
    }

    #[test]
    fn a_short_dig_id_is_shown_verbatim_and_an_absent_one_is_named() {
        assert_eq!(dig_id_label(Some("abcd")), "abcd");
        assert_eq!(dig_id_label(None), "(not set up yet)");
    }

    #[test]
    fn copying_the_dig_id_needs_a_profile() {
        let mut v = view(AccountState::Unlocked { recoverable: true });
        assert!(build(&v).is_enabled(TrayAction::CopyDigId));
        v.profile_id = None;
        assert!(!build(&v).is_enabled(TrayAction::CopyDigId));
    }

    /// A host that cannot hold an account says so instead of offering a button that would fail — and
    /// still offers nothing destructive.
    #[test]
    fn an_unsupported_host_explains_itself_and_offers_no_account_action() {
        let menu = build(&view(AccountState::Unsupported));
        assert!(menu.rows.contains(&MenuRow::Status(
            "Account: not available on this system yet".to_string()
        )));
        for action in [
            TrayAction::SetUpAccount,
            TrayAction::RestoreFromPhrase,
            TrayAction::Unlock,
            TrayAction::LockNow,
            TrayAction::ShowRecoveryPhrase,
            TrayAction::CreateDid,
        ] {
            assert!(!menu.is_enabled(action), "{action:?} must be inert here");
        }
    }

    /// A node line that fits is passed through unmodified, and needs no details window — the control
    /// that proves the bounding below is reading the length rather than always truncating.
    #[test]
    fn a_node_line_that_fits_is_passed_through_verbatim_and_needs_no_details() {
        let mut v = view(AccountState::Absent);
        v.node = "Node: not connected — no node is running on this machine".to_string();
        assert!(
            v.node.chars().count() <= MAX_STATUS_ROW_CHARS,
            "fixture guard"
        );

        let menu = build(&v);
        assert!(menu.rows.contains(&MenuRow::Status(v.node.clone())));
        assert!(
            !menu.is_enabled(TrayAction::ShowNodeDetails),
            "the row already says everything; a details window would add nothing"
        );
    }

    /// **Regression (#1773).** The row is bounded, because ONE long item stretches the whole native menu
    /// past the screen edge.
    ///
    /// The fixture is the REAL disconnected reason observed from a live run — the control-token
    /// explanation with its reinstall recipe — not a synthetic `"x".repeat(n)`, because its actual length
    /// (~700 chars, an order of magnitude over the bound) is the fact that makes this a defect rather
    /// than a nicety.
    #[test]
    fn a_long_node_line_is_bounded_and_hands_the_rest_to_a_details_window() {
        let observed_reason = "No node: the node at http://dig.local refused this app (the node \
             refused the request: control.* requires the local control token (X-Dig-Control-Token \
             header or params._control_token, from C:\\ProgramData\\DigNode\\control-token), or a \
             paired controller token (see `dig-node pair`). no control token found at \
             C:\\ProgramData\\DigNode\\control-token. Start the node so it mints one (`dig-node run`, \
             or `dig-node start` for the installed service), then retry.)";
        assert!(
            observed_reason.chars().count() > MAX_STATUS_ROW_CHARS * 4,
            "fixture guard: the point is that real reasons are FAR over the bound, got {}",
            observed_reason.chars().count()
        );

        let mut v = view(AccountState::Absent);
        v.node = observed_reason.to_string();
        let menu = build(&v);

        let row = menu
            .rows
            .iter()
            .find_map(|row| match row {
                MenuRow::Status(text) if text.starts_with("No node") => Some(text),
                _ => None,
            })
            .expect("the node row must still be present");

        assert!(
            row.chars().count() <= MAX_STATUS_ROW_CHARS + 1,
            "the row must fit the bound (+1 for the ellipsis), got {}: {row}",
            row.chars().count()
        );
        assert!(
            row.ends_with('…'),
            "the reader must be told there is more: {row}"
        );
        assert!(
            menu.is_enabled(TrayAction::ShowNodeDetails),
            "the cut text must be reachable — never trap the user with a truncated diagnosis"
        );
    }

    /// The bound pinned from BOTH sides. A bound tested only from above can only confirm itself: an
    /// implementation that truncated at 40 would pass the long-line test and fail here.
    #[test]
    fn the_row_bound_holds_exactly_at_the_limit_and_cuts_one_character_over() {
        let at_bound = "a".repeat(MAX_STATUS_ROW_CHARS);
        assert_eq!(
            status_row_text(&at_bound),
            at_bound,
            "a line exactly at the bound must not be touched"
        );
        assert!(!was_truncated(&at_bound));

        let one_over = "a".repeat(MAX_STATUS_ROW_CHARS + 1);
        assert_ne!(
            status_row_text(&one_over),
            one_over,
            "one character over the bound must be cut"
        );
        assert!(was_truncated(&one_over));
    }

    /// Cutting must count CHARACTERS, not bytes: the connected summary contains `·`, so a byte-indexed
    /// slice would panic on a multi-byte boundary. The fixture puts multi-byte characters exactly ACROSS
    /// the cut point, which an all-ASCII fixture could never exercise.
    #[test]
    fn bounding_never_splits_a_multi_byte_character() {
        let line = "·".repeat(MAX_STATUS_ROW_CHARS * 2);
        assert!(
            line.len() > line.chars().count(),
            "fixture guard: multi-byte"
        );

        let row = status_row_text(&line);
        assert!(row.chars().count() <= MAX_STATUS_ROW_CHARS + 1);
        // Reaching here without a panic is half the assertion; the other half is that we kept real
        // characters rather than mangling them.
        assert!(row.starts_with('·'), "{row}");
    }

    /// A multi-line status collapses to its first line — a menu row cannot show a paragraph, and the
    /// remaining lines are what the details window is for.
    #[test]
    fn a_multi_line_status_shows_only_its_first_line_and_offers_the_rest() {
        let mut v = view(AccountState::Absent);
        v.node = "No node: not running\nStart it with `dig-node start`.".to_string();
        let menu = build(&v);

        assert!(menu
            .rows
            .contains(&MenuRow::Status("No node: not running…".to_string())));
        assert!(
            menu.is_enabled(TrayAction::ShowNodeDetails),
            "the second line must be reachable"
        );
    }

    #[test]
    fn a_not_yet_running_agent_says_starting() {
        let mut v = view(AccountState::Absent);
        v.running = false;
        assert!(build(&v)
            .rows
            .contains(&MenuRow::Status("DIG — starting…".to_string())));
        v.running = true;
        assert!(build(&v)
            .rows
            .contains(&MenuRow::Status("DIG — running".to_string())));
    }

    /// The advice must name the fix, not merely the symptom — a user told only "the tray failed" has
    /// nowhere to go, which is the failure this message exists to prevent.
    #[test]
    fn linux_tray_advice_names_the_missing_library_and_a_way_in() {
        let advice = tray_unavailable_advice("no display", crate::Os::Linux);
        assert!(advice.contains("libayatana-appindicator3-1"), "{advice}");
        assert!(
            advice.contains("dign"),
            "the CLI fallback must be offered: {advice}"
        );
        assert!(
            advice.contains("no display"),
            "the real reason must survive: {advice}"
        );
    }

    /// The Linux-specific package advice must NOT be shown on Windows/macOS, where it is wrong and
    /// would send the user chasing a library their OS does not have. Two platforms are needed to see
    /// this at all — a Linux-only fixture would pass for a function that always appended it.
    #[test]
    fn desktop_platforms_get_no_linux_package_advice() {
        for os in [crate::Os::Windows, crate::Os::MacOs] {
            let advice = tray_unavailable_advice("tray build failed", os);
            assert!(!advice.contains("appindicator"), "{os:?}: {advice}");
            assert!(
                advice.contains("dign"),
                "{os:?} still needs the way in: {advice}"
            );
        }
    }

    /// **Regression (#1752 security gate).** After `Lock now` — or an idle auto-lock — the session is
    /// still held but its KEYS are gone. The menu previously keyed on the session's existence, so it
    /// reported `Account: unlocked`, kept the reveal enabled, and left `Unlock…` disabled: a false state
    /// report AND a dead end (`SPEC.md` §3.1c).
    ///
    /// The fixture varies ONLY `keys_unlocked` across two otherwise identical sessions, because that is
    /// the single input the bug ignored — a fixture with no session, or with a different `recoverable`,
    /// could not tell the two apart.
    #[test]
    fn a_session_whose_keys_were_dropped_reports_locked() {
        let unlocked = SessionFacts {
            keys_unlocked: true,
            recoverable: true,
        };
        let after_lock = SessionFacts {
            keys_unlocked: false,
            ..unlocked
        };

        assert_eq!(
            account_state(true, true, Some(unlocked)),
            AccountState::Unlocked { recoverable: true }
        );
        assert_eq!(
            account_state(true, true, Some(after_lock)),
            AccountState::Locked,
            "a session that has dropped its keys is LOCKED, not unlocked"
        );
    }

    /// The user-visible consequence of the state above, asserted on the MENU rather than the enum: after
    /// Lock now the reveal must be gone and `Unlock…` must be the way back in. This is the assertion that
    /// would have caught the defect on stage.
    #[test]
    fn the_menu_after_lock_now_offers_unlock_and_no_reveal() {
        let after_lock = account_state(
            true,
            true,
            Some(SessionFacts {
                keys_unlocked: false,
                recoverable: true,
            }),
        );
        let menu = build(&view(after_lock));

        assert!(
            menu.is_enabled(TrayAction::Unlock),
            "the way back in must be clickable"
        );
        assert!(
            !menu.is_enabled(TrayAction::ShowRecoveryPhrase),
            "a locked account must not offer to reveal its phrase"
        );
        assert!(
            !menu.is_enabled(TrayAction::LockNow),
            "there is nothing left to lock"
        );
        assert!(
            menu.rows
                .contains(&MenuRow::Status("Account: locked".to_string())),
            "the status line must say locked: {:?}",
            menu.rows
        );
    }

    /// A locked session must NOT be mistaken for an absent account — that would offer `Set up my DIG
    /// Account…` over an account that already exists, and enrolment refuses on an existing custody root.
    #[test]
    fn a_locked_session_is_never_reported_as_absent() {
        let state = account_state(
            true,
            true,
            Some(SessionFacts {
                keys_unlocked: false,
                recoverable: false,
            }),
        );
        assert_eq!(state, AccountState::Locked);
        assert!(!build(&view(state)).is_enabled(TrayAction::SetUpAccount));
    }

    /// With no session, `enrolled` is what separates "locked" from "not set up yet".
    #[test]
    fn with_no_session_enrolment_separates_locked_from_absent() {
        assert_eq!(account_state(true, true, None), AccountState::Locked);
        assert_eq!(account_state(true, false, None), AccountState::Absent);
    }

    /// An unsupported host wins over everything else — it cannot hold an account, so no amount of
    /// session or enrolment state changes what the user is told.
    #[test]
    fn an_unsupported_host_overrides_every_other_input() {
        for enrolled in [true, false] {
            for session in [
                None,
                Some(SessionFacts {
                    keys_unlocked: true,
                    recoverable: true,
                }),
            ] {
                assert_eq!(
                    account_state(false, enrolled, session),
                    AccountState::Unsupported
                );
            }
        }
    }

    /// `recoverable` must survive the derivation — it is what selects the reveal row over the warning.
    #[test]
    fn an_unlocked_state_carries_the_recoverable_flag_through() {
        for recoverable in [true, false] {
            assert_eq!(
                account_state(
                    true,
                    true,
                    Some(SessionFacts {
                        keys_unlocked: true,
                        recoverable
                    })
                ),
                AccountState::Unlocked { recoverable }
            );
        }
    }

    /// Before the first boot reports, the menu must render — defaulting to "no account" rather than
    /// panicking or showing a blank row.
    #[test]
    fn an_unreported_account_defaults_to_absent() {
        let menu = build(&TrayView::default());
        assert!(menu
            .rows
            .contains(&MenuRow::Status("Account: not set up yet".to_string())));
        assert!(menu.is_enabled(TrayAction::SetUpAccount));
    }
}
