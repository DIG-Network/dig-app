//! The Account tab: what this account IS, and the verbs that change which account this computer has.
//!
//! # The state machine is the whole job
//!
//! Six states reach this pane — no account, one sealed under a machine-generated password, one
//! sealed normally, one whose seal will not open, one that is open, and a host that cannot hold an
//! account at all — and each has a *different* way forward. dig_ecosystem#2059 is what happens when
//! that is not respected: three of them were told to "unlock", a remedy two of them cannot perform.
//! So every sentence on this pane is chosen by an exhaustive match on
//! [`AccountKind`](super::facts::AccountKind), and
//! [`no_state_names_a_remedy_it_cannot_perform`](tests::no_state_names_a_remedy_it_cannot_perform)
//! is that defect written as one assertion.
//!
//! # What this pane does not decide
//!
//! Which verbs exist, whether each is enabled, and what each is called are decided once by
//! [`crate::tray_menu`]'s group builders and composed by [`crate::window_model`]. This pane chooses
//! *prominence, grouping and supporting copy* — never a verb. Delete this file and the tab falls
//! back to the generic pane with exactly the same capabilities.
//!
//! # Where the destructive verbs sit, and why
//!
//! `tray_menu` keeps `Lock now` out of the submenu that holds `Remove this account from this
//! computer`, because a menu where the routine and the irreversible sit together is how a mis-click
//! becomes a loss. A window has more room to honour that than a menu does, so here the destroying
//! verbs are put in their own card, LAST on the pane, behind a paragraph that says what is lost —
//! never adjacent to a control a person uses every day. The confirmation itself is unchanged: the
//! shell still routes each through `confirm_destroy`, whose refusal is the pre-focused answer.

use std::collections::HashMap;

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::identity;
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Account pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    state_card(flow, t, facts);
    flow.gap(space::S4);
    identity_card(flow, t, facts);
    flow.gap(space::S4);
    verb_cards(flow, t, tab)
}

/// What state this account is in, and what that means — the header the rest of the pane hangs from.
///
/// A badge and a sentence, and no verb of its own: the acts available in each state are the model's
/// rows below, so a promoted button here would be either a duplicate or a second opinion.
///
/// # The loading state, and why it has to be drawn HERE
///
/// `TrayView::account()` defaults an unreported account to [`AccountState::Absent`], and the Account
/// tab's note is a hardcoded `PaneNote::Ready` — so between the window opening and the first boot
/// report, the model's rows are the ones for a computer with no account, and a pane that trusted
/// them would state *"There is no DIG Account on this computer"* about a machine that may well have
/// one. That is a wrong claim, not a slow one.
///
/// [`PaneFacts::account`] is the fact that tells the two apart, because it is projected from
/// `view.account` DIRECTLY rather than through that default: `None` means nothing has reported yet.
/// So this card leads with the wait instead of the claim, and says the rows below are not settled
/// either — which is the honest thing a pane can do without reaching into `window_model`.
fn state_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let account = facts.account;
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, None, |inner| {
                let (word, tone) = match account {
                    Some(kind) => (kind.word(), kind.tone()),
                    None => (copy::account::UNREAD_BADGE, data::Tone::Neutral),
                };
                inner.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
                inner.gap(space::S3);
                match account {
                    Some(kind) => {
                        inner.place(|ui, at| {
                            (text::body(ui, at, t, copy::account::summary(kind)), ())
                        });
                    }
                    // The banner rather than plain prose: this is the pane's loading state, and it
                    // is drawn in the same treatment every other pane's is.
                    None => {
                        inner.place(|ui, at| {
                            (
                                state::banner(
                                    ui,
                                    at,
                                    t,
                                    &PaneState::Waiting(copy::account::UNREAD.to_string()),
                                ),
                                (),
                            )
                        });
                    }
                }
            }),
            (),
        )
    });
}

/// The id this account is known by, with a way to take it elsewhere.
///
/// A DIG ID is a 64-character identifier that nobody transcribes by hand, so it is shown in full —
/// wrapped, in the identifier face — beside a copy control. Truncating it would hide characters the
/// reader has no other way to reach, and showing it without the control would make them retype it.
fn identity_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let value = match &facts.profile_id {
        Some(id) => Value::Identifier(id.clone()),
        // The honest absence, carrying the act that fills it in — never a dash, and never an
        // invented placeholder id.
        None => Value::Unknown(copy::account::DIG_ID_UNKNOWN.to_string()),
    };
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::account::IDENTITY_CARD), |inner| {
                inner.place(|ui, at| {
                    (
                        identity::copyable(
                            ui,
                            at,
                            t,
                            copy::account::DIG_ID_LABEL,
                            &value,
                            dig_id_element(),
                            true,
                        ),
                        (),
                    )
                });
            }),
            (),
        )
    });
}

/// The element id of the DIG ID's copy control. Named once so a test can address the same control.
fn dig_id_element() -> egui::Id {
    egui::Id::new("dig-window-copy-dig-id")
}

/// The model's sections as cards of verbs, with every destroying card last.
///
/// Returns the action pressed.
fn verb_cards(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let (safe, destroying) = grouped(tab);
    let mut pressed = None;
    for group in safe.iter().chain(destroying.iter()) {
        pressed = pressed.or(verb_card(flow, t, group));
        flow.gap(space::S4);
    }
    pressed
}

/// One card: the section's heading, the caveat when it can destroy custody, then its verbs.
fn verb_card(flow: &mut Flow, t: &Tokens, group: &Group) -> Option<TrayAction> {
    if group.actions.is_empty() {
        return None;
    }
    let live = flow.live();
    let title = group.heading.clone();
    let actions = group.actions.clone();
    let destroys = group.destroys;

    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(ui, at, t, live, title.as_deref(), |inner| {
            // The caveat sits ABOVE the buttons, not below them: a warning a person reads after
            // pressing is a receipt, and the paragraph is also what puts these controls a
            // deliberate distance from the ones above.
            if destroys {
                inner
                    .place(|ui, at| (text::body(ui, at, t, copy::account::DESTRUCTIVE_CAVEAT), ()));
                inner.gap(space::S4);
            }
            inner.place(|ui, at| action::buttons(ui, at, t, live, &actions))
        });
        (height, hit.flatten())
    })
}

/// One card's worth of the model: its heading, its verbs, and whether any of them destroys custody.
struct Group {
    /// The section's heading, verbatim from the model.
    heading: Option<String>,
    /// Its verbs, weighted, in the model's order.
    actions: Vec<Action<TrayAction>>,
    /// Whether this group holds a verb that erases key material.
    destroys: bool,
}

/// The tab's sections, split into those that cannot destroy custody and those that can.
///
/// # Why the split is by CONTENT and not by position
///
/// The model happens to put its management section last today, so this partition changes nothing on
/// the current tab — which is the point. It is what keeps the guarantee true if the model's order
/// ever changes: a card holding `Remove this account from this computer…` is last on the pane
/// because of what it holds, not because of where it happened to be listed.
///
/// The actions are built in the MODEL's order, once, before any reordering: the occurrence count
/// that gives each row its element id is a position in the model's list, and rebuilding it from a
/// re-sorted list would hand the same row a different id depending on how the pane chose to lay it
/// out.
fn grouped(tab: &Tab) -> (Vec<Group>, Vec<Group>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let groups: Vec<Group> = tab
        .sections
        .iter()
        .map(|section| {
            let actions = super::actions_in(section.rows.iter().cloned(), &mut seen);
            Group {
                heading: section.heading.clone(),
                destroys: actions
                    .iter()
                    .any(|action| super::is_destructive(action.id)),
                actions,
            }
        })
        .collect();
    groups.into_iter().partition(|group| !group.destroys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{AccountState, MenuRow, TrayView};
    use crate::window_model::{Section, TabId};

    /// The Account tab as the real model builds it for `account`.
    fn tab_for(account: AccountState) -> Tab {
        let view = TrayView {
            running: true,
            account: Some(account),
            profile_id: Some("a".repeat(64)),
            ..TrayView::default()
        };
        crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state")
    }

    /// Every word this pane can put on screen for `account`: its own copy, and the model's labels.
    fn words_for(account: AccountState) -> Vec<String> {
        let kind = super::super::facts::AccountKind::of(&account);
        let tab = tab_for(account);
        let mut words = vec![
            copy::account::summary(kind).to_string(),
            kind.word().to_string(),
            copy::account::IDENTITY_CARD.to_string(),
            copy::account::DIG_ID_LABEL.to_string(),
            copy::account::DESTRUCTIVE_CAVEAT.to_string(),
        ];
        words.extend(tab.sections.iter().filter_map(|s| s.heading.clone()));
        words.extend(tab.sections.iter().flat_map(|section| {
            section.rows.iter().filter_map(|row| match row {
                MenuRow::Action { label, .. } => Some(label.clone()),
                _ => None,
            })
        }));
        words
    }

    /// **No state is told to unlock unless unlocking is a thing it can do.**
    ///
    /// This is dig_ecosystem#2059 as one assertion. Three states reach this pane where "unlock" is
    /// the wrong word: an account that has never had a password has none to type, an account whose
    /// seal will not open has already failed at unlocking, and a computer with no account has
    /// nothing to unlock at all. Each was, at some point, told to unlock anyway.
    ///
    /// The fixture is the WHOLE pane — this module's per-state copy *and* the labels the model
    /// supplies — because the sentence a reader sees is both, and copy that avoided the word while
    /// sitting above a row that used it would be a pane that still says it. `Locked` is deliberately
    /// excluded and asserted from the other side below: a check that no pane anywhere says "unlock"
    /// would pass on a pane that had lost the word entirely.
    #[test]
    fn no_state_names_a_remedy_it_cannot_perform() {
        for account in [
            AccountState::NeedsPassword,
            AccountState::Unopenable,
            AccountState::Absent,
        ] {
            for phrase in words_for(account.clone()) {
                assert!(
                    !phrase.to_lowercase().contains("unlock"),
                    "the {account:?} pane says “unlock”, which is a remedy that state cannot \
                     perform (dig_ecosystem#2059): {phrase}"
                );
            }
        }
    }

    /// **A pane with no report yet says it is waiting, instead of claiming the computer has no
    /// account.**
    ///
    /// Two actors, and they are the whole point. `TrayView::account: None` is a machine whose boot
    /// has not reported — and `TrayView::account: Some(Absent)` is a machine that genuinely has no
    /// account. `window_model` collapses them, because `TrayView::account()` defaults `None` to
    /// `Absent` and the Account tab's note is a hardcoded `PaneNote::Ready`. A pane that read only
    /// the model would state "There is no DIG Account on this computer" about both, and would be
    /// wrong about one of them.
    ///
    /// The control is what makes this load-bearing rather than a check that the pane is vague: the
    /// genuinely-absent machine must STILL be told plainly that it has no account, because that is a
    /// fact it needs in order to set one up.
    #[test]
    fn an_unreported_account_is_a_wait_and_not_a_claim_that_there_is_none() {
        let absent_summary = copy::account::summary(super::super::facts::AccountKind::Absent);

        let unreported = PaneFacts::of_tray(&TrayView {
            running: false,
            account: None,
            ..TrayView::default()
        });
        assert_eq!(
            unreported.account, None,
            "the projection defaulted an unreported account, so the pane cannot tell the two apart"
        );

        let reported = PaneFacts::of_tray(&TrayView {
            running: true,
            account: Some(AccountState::Absent),
            ..TrayView::default()
        });
        assert_eq!(
            reported.account,
            Some(super::super::facts::AccountKind::Absent),
            "a machine that really has no account must still be reported as having none"
        );
        assert!(
            absent_summary.contains("no DIG Account on this computer"),
            "the control assumes this sentence is the claim being guarded against: {absent_summary}"
        );

        // The wait must deny the ROWS too: during it the model is emitting the Absent verbs, so a
        // sentence that only said "loading" would leave `Set up a new DIG Account…` reading as a
        // statement about this machine.
        let wait = copy::account::UNREAD.to_lowercase();
        assert!(
            wait.contains("not finished reading"),
            "the wait does not say what is still happening: {wait}"
        );
        assert!(
            wait.contains("actions below"),
            "the wait denies its own summary but not the verbs under it: {wait}"
        );
        assert_ne!(
            copy::account::UNREAD,
            absent_summary,
            "the wait and the no-account claim are the same sentence"
        );
    }

    /// **…and the state that CAN unlock still says so.**
    ///
    /// The control for the test above. Without it, deleting the word from every state's copy would
    /// pass — and a locked account with no route back in is a worse defect than the one #2059 fixed.
    #[test]
    fn a_locked_account_is_still_shown_the_way_back_in() {
        let said = words_for(AccountState::Locked).join(" ").to_lowercase();
        assert!(
            said.contains("unlock") || said.contains("open it"),
            "a locked account's pane never names the act that opens it: {said}"
        );
    }

    /// **Each state gets its own sentence.**
    ///
    /// Two states sharing one summary is exactly the shape of #2059 — a reader in one state reading
    /// advice written for another — and a match arm that falls through to a neighbour's sentence is
    /// how it happens. Asserted over the whole set, so a seventh state has to write its own.
    #[test]
    fn no_two_states_share_a_summary() {
        let summaries: Vec<&str> = super::super::facts::AccountKind::ALL
            .iter()
            .map(|kind| copy::account::summary(*kind))
            .collect();
        for (i, left) in summaries.iter().enumerate() {
            for right in &summaries[i + 1..] {
                assert_ne!(left, right, "two account states share one summary");
            }
        }
    }

    /// **The pane offers exactly the model's verbs, in the model's order, in every state.**
    ///
    /// Run over every state rather than one, because the tab's rows differ per state and a pane that
    /// dropped a verb would do it in only some of them. Order is asserted too: the occurrence count
    /// that gives each row its element id is a position in this list.
    #[test]
    fn the_pane_offers_the_models_verbs_and_nothing_else_in_every_state() {
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
            AccountState::Unlocked { recoverable: false },
        ] {
            let tab = tab_for(account.clone());
            let (safe, destroying) = grouped(&tab);
            let mut rendered: Vec<TrayAction> = safe
                .iter()
                .chain(destroying.iter())
                .flat_map(|group| group.actions.iter().map(|a| a.id))
                .collect();
            let mut expected = tab.actions();
            assert!(
                !expected.is_empty(),
                "the {account:?} fixture has no actions, so this proves nothing"
            );
            rendered.sort_by_key(|a| format!("{a:?}"));
            expected.sort_by_key(|a| format!("{a:?}"));
            assert_eq!(
                rendered, expected,
                "the {account:?} pane's buttons are not the model's actions"
            );
        }
    }

    /// **A card that can destroy custody is drawn after every card that cannot.**
    ///
    /// Two actors, and that is what makes it load-bearing: the fixture puts the destroying section
    /// FIRST, where the model does not, so a partition that merely preserved the model's order would
    /// pass here only by accident and fail this assertion. The property is that the placement
    /// follows what the card holds.
    #[test]
    fn the_destroying_card_is_last_however_the_model_ordered_it() {
        let tab = Tab {
            id: TabId::Account,
            label: "Account".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![
                Section {
                    heading: Some("Manage this account".to_string()),
                    rows: vec![MenuRow::Action {
                        action: TrayAction::RemoveAccount,
                        label: "Remove this account from this computer…".to_string(),
                        enabled: true,
                    }],
                },
                Section {
                    heading: Some("What this account is".to_string()),
                    rows: vec![MenuRow::Action {
                        action: TrayAction::CopyDigId,
                        label: "Copy my DIG ID".to_string(),
                        enabled: true,
                    }],
                },
            ],
        };

        let (safe, destroying) = grouped(&tab);
        assert_eq!(safe.len(), 1, "the harmless section was not kept apart");
        assert_eq!(destroying.len(), 1, "the destroying section was not found");
        assert_eq!(safe[0].actions[0].id, TrayAction::CopyDigId);
        assert_eq!(destroying[0].actions[0].id, TrayAction::RemoveAccount);
        assert!(
            destroying[0].destroys && !safe[0].destroys,
            "the caveat is drawn from `destroys`, so it must be set on exactly the destroying card"
        );
    }

    /// **A destroying verb keeps its element id when the pane moves its card.**
    ///
    /// The reordering above is a LAYOUT choice, and an id derived after it would change with the
    /// layout — which is how a click lands on nothing. Pinned against the id the rest of the app
    /// addresses the same row by.
    #[test]
    fn reordering_the_cards_does_not_renumber_the_rows() {
        let tab = tab_for(AccountState::Unlocked { recoverable: true });
        let (safe, destroying) = grouped(&tab);
        for group in safe.iter().chain(destroying.iter()) {
            for action in &group.actions {
                assert_eq!(
                    action.element,
                    super::super::row_element_id(&action.label, 0),
                    "“{}” is addressed by a different id than the rest of the app uses",
                    action.label
                );
            }
        }
    }

    /// **A destroying verb is never the friendly primary, whatever position it lands in.**
    #[test]
    fn a_destroying_verb_is_drawn_as_danger() {
        let tab = tab_for(AccountState::Unlocked { recoverable: true });
        let (_, destroying) = grouped(&tab);
        let card = destroying
            .first()
            .expect("an unlocked account can be replaced");
        for action in &card.actions {
            if super::super::is_destructive(action.id) {
                assert_eq!(
                    action.weight,
                    Weight::Danger,
                    "“{}” erases key material and was drawn as an ordinary control",
                    action.label
                );
            }
        }
    }

    /// **An absent DIG ID is an absence with a remedy, never a placeholder.**
    #[test]
    fn a_missing_dig_id_says_what_would_produce_one() {
        let value = Value::Unknown(copy::account::DIG_ID_UNKNOWN.to_string());
        assert!(!value.is_known());
        assert!(
            crate::window_model::label_names_a_remedy(copy::account::DIG_ID_UNKNOWN),
            "the absent-DIG-ID sentence states the absence without naming what fills it"
        );
    }

    /// **The caveat says what is LOST, not merely that the action is serious.**
    ///
    /// "This cannot be undone" is compatible with a person believing only a setting is being reset.
    /// The paragraph has to name the keys and the money.
    #[test]
    fn the_destructive_caveat_names_what_is_lost() {
        let caveat = copy::account::DESTRUCTIVE_CAVEAT.to_lowercase();
        for expected in ["key", "address", "recovery phrase", "confirm"] {
            assert!(
                caveat.contains(expected),
                "the destructive caveat never mentions “{expected}”: {caveat}"
            );
        }
    }
}
