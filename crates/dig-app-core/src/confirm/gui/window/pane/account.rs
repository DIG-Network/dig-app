//! The Account tab: what this account IS, whether it is protected, and the verbs that change which
//! account this computer has.
//!
//! # One pane, three beats, in the order they already read in (dig_ecosystem#2358)
//!
//! Account and Security used to be two tabs. The stated distinction — "is my account safe" versus
//! "I want a different account" — is real, but it is a distinction between CARDS, not between
//! destinations, and splitting it cost a genuine defect: two hand-maintained six-arm sentence sets
//! over one account state machine, each tested only against itself, free to drift apart while both
//! suites stayed green (dig_ecosystem#2357). Merged, the lead is drawn once and the pane reads as
//! one narrative:
//!
//! 1. **Who you are** — the state badge, its one sentence, and the verb the model says this account
//!    needs right now, promoted. Then the DIG ID, with a way to take it elsewhere.
//! 2. **Whether it is protected** — the second factor and the apps that have been let in.
//! 3. **How to change which account this is** — and the destroying verbs LAST, behind a paragraph
//!    saying what is lost.
//!
//! That ordering already existed; it was just split across two panes.
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
    let protection = Protection::of(tab);

    let mut pressed = state_card(flow, t, facts, &protection);
    flow.gap(space::S4);
    identity_card(flow, t, facts);
    flow.gap(space::S4);
    // Third beat, between "who you are" and "whether it is protected": a profile is WHICH identity
    // this account is presenting, so a person who has just read their DIG ID is in the right place
    // to be told which profile it belongs to (dig_ecosystem#2403).
    pressed = pressed.or(super::profiles::card(flow, t, tab, facts));
    flow.gap(space::S4);
    // Directly under the list, because it is about the profile the list says is in use
    // (dig_ecosystem#2993).
    pressed = pressed.or(super::profile_edit::card(flow, t, tab, facts));
    flow.gap(space::S4);
    // After the two cards about THIS account's profiles, because it is the same subject seen from
    // the other side: what somebody else publishes (dig_ecosystem#3008). It reads the process-wide
    // lookup service rather than the tray view, since a lookup is started by this card and answered
    // seconds later on a worker — a fact the tray snapshot has no reason to carry.
    super::profile_view::card(
        flow,
        t,
        &crate::profile_view::LookupService::app().reading(),
    );
    flow.gap(space::S4);
    pressed = pressed.or(second_factor_card(flow, t, facts, &protection));
    flow.gap(space::S4);
    pressed = pressed.or(paired_apps_card(flow, t, &protection));
    flow.gap(space::S4);
    // The identity card above draws `Copy` beside the DIG ID whenever there IS one, so the model's
    // own `Copy my DIG ID` row would be the same verb a second time. See [`spare_verbs`].
    pressed.or(verb_cards(flow, t, tab, drew_copy_control(facts)))
}

/// Whether the identity card drew a copy control this frame — the condition [`spare_verbs`] turns on.
///
/// Derived from the same field [`identity_card`] renders from, so the two cannot come to disagree
/// about whether the control is on screen.
fn drew_copy_control(facts: &PaneFacts) -> bool {
    facts.profile_id.is_some()
}

/// The tab's verbs minus the one the identity card has already drawn beside the DIG ID.
///
/// The rule itself is [`action::without_the_one_already_drawn`], shared with the Wallet tab, so the
/// two tabs cannot come to disagree about whether a copy control beside a value retires the model's
/// separate copy verb.
fn spare_verbs(
    actions: Vec<Action<TrayAction>>,
    drew_copy_control: bool,
) -> Vec<Action<TrayAction>> {
    action::without_the_one_already_drawn(
        actions,
        drew_copy_control.then_some(TrayAction::CopyDigId),
    )
}

/// What state this account is in, what that means, and the one act that changes it.
///
/// The promoted control is the model's LEADING protection row, verbatim — the row `security_actions`
/// puts first in every state, which is the same verb `urgent_account_row` promotes on the tray. The
/// pane chooses that it is drawn large and first; it does not choose which verb it is, and
/// [`action::promote`] is the only producer of a primary anywhere in the window
/// (dig_ecosystem#2354).
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
fn state_card(
    flow: &mut Flow,
    t: &Tokens,
    facts: &PaneFacts,
    protection: &Protection,
) -> Option<TrayAction> {
    let live = flow.live();
    let account = facts.account;
    let lead = protection.lead.clone();

    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::protection::PROTECTION_CARD),
            |inner| {
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
                inner.gap(space::S4);
                inner.place(|ui, at| action::buttons(ui, at, t, live, &lead))
            },
        );
        (height, hit.flatten())
    })
}

/// The second factor: its control when there is one to offer, and its reason when there is not.
fn second_factor_card(
    flow: &mut Flow,
    t: &Tokens,
    facts: &PaneFacts,
    protection: &Protection,
) -> Option<TrayAction> {
    if !protection.has_account {
        return None;
    }
    let hint = match protection.second_factor.first() {
        Some(_) if facts.second_factor => copy::protection::SECOND_FACTOR_ON.to_string(),
        Some(_) => copy::protection::SECOND_FACTOR_OFF.to_string(),
        // The absence the model decided, rendered as an absence: no control at all, and the way
        // forward quoted from the row above rather than written here, where it would eventually
        // name the wrong one.
        None => copy::protection::second_factor_needs(&protection.lead_label()),
    };
    line_card(
        flow,
        t,
        copy::protection::SECOND_FACTOR_CARD,
        &hint,
        &protection.second_factor,
    )
}

/// The apps this computer has let in.
fn paired_apps_card(flow: &mut Flow, t: &Tokens, protection: &Protection) -> Option<TrayAction> {
    if !protection.has_account {
        return None;
    }
    let hint = match protection.paired_apps.is_empty() {
        false => copy::protection::PAIRED_APPS_HINT.to_string(),
        true => copy::protection::pairing_needs(&protection.lead_label()),
    };
    line_card(
        flow,
        t,
        copy::protection::PAIRED_APPS_CARD,
        &hint,
        &protection.paired_apps,
    )
}

/// One titled card: a sentence, then whatever controls the model supplied — possibly none.
///
/// The sentence comes FIRST so a card with no controls is still a card that explains itself, rather
/// than a heading over empty space.
fn line_card(
    flow: &mut Flow,
    t: &Tokens,
    title: &str,
    hint: &str,
    actions: &[Action<TrayAction>],
) -> Option<TrayAction> {
    let live = flow.live();
    let hint = hint.to_string();
    let actions = actions.to_vec();
    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(ui, at, t, live, Some(title), |inner| {
            inner.place(|ui, at| (text::body(ui, at, t, &hint), ()));
            if actions.is_empty() {
                return None;
            }
            inner.gap(space::S4);
            inner.place(|ui, at| action::buttons(ui, at, t, live, &actions))
        });
        (height, hit.flatten())
    })
}

/// The protection section's rows, sorted into the three things those cards are about.
///
/// # Found by the model's own heading, not by position
///
/// The pane must tell the protection rows from the identity and management rows, and which rows
/// `security_actions` emits differs by state — an unlocked account gets four, a locked one two, a
/// computer with no account one — so no index into the tab means the same thing twice. Matching the
/// section on [`crate::window_model::PROTECTION_HEADING`] asks the model which section this IS, from
/// the one string both sides read, so reordering the sections upstream cannot silently reclassify a
/// row. Within the section the sort is by [`TrayAction`], which asks what a row IS rather than where
/// it sits.
struct Protection {
    /// The leading row: the one thing this account needs from the user right now, promoted.
    lead: Vec<Action<TrayAction>>,
    /// The second-factor row, or empty where the model offered none.
    second_factor: Vec<Action<TrayAction>>,
    /// The paired-app rows, or empty where the model offered none.
    paired_apps: Vec<Action<TrayAction>>,
    /// Whether there is an account here for the lower cards to be about.
    has_account: bool,
}

impl Protection {
    /// Sort the protection section's rows, keeping the model's order and its element ids.
    fn of(tab: &Tab) -> Self {
        let actions = protection_actions(tab);

        let mut parts = Self {
            lead: Vec::new(),
            second_factor: Vec::new(),
            paired_apps: Vec::new(),
            // `ShowStatus` is the row `security_actions` emits for a computer with NO account, and
            // it is the only row it emits there. Its presence is the model saying there is nothing
            // to protect yet — so the cards about protecting it are omitted rather than filled with
            // sentences about an account that does not exist.
            has_account: !actions
                .iter()
                .any(|action| action.id == TrayAction::ShowStatus),
        };
        for action in actions {
            match action.id {
                TrayAction::SetUpTwoFactor | TrayAction::TurnOffTwoFactor => {
                    parts.second_factor.push(action)
                }
                TrayAction::PairAnApp | TrayAction::ManagePairedApps => {
                    parts.paired_apps.push(action)
                }
                _ => parts.lead.push(action),
            }
        }

        // The one promotion in the whole window (dig_ecosystem#2354). The MODEL designates this
        // lead: `security_actions` puts the thing this account needs from the user right now at the
        // top in every state, and `urgent_account_row` promotes the same verb on the tray. So this
        // pane is naming a decision made upstream, not making one from a position — which is
        // precisely the distinction the positional rule could not draw.
        if let Some(lead) = parts.lead.first().map(|action| action.id) {
            parts.lead = action::promote(std::mem::take(&mut parts.lead), &lead);
        }
        parts
    }

    /// The verb this pane promotes, already weighted — the window's one promotion.
    ///
    /// Exposed so the cross-pane guard in [`super`] can name it without rebuilding the sort.
    #[cfg(test)]
    pub(crate) fn lead_action(&self) -> Option<&Action<TrayAction>> {
        self.lead.first()
    }

    /// The leading row's label, for a sentence that must name the way forward exactly.
    fn lead_label(&self) -> String {
        self.lead
            .first()
            .map(|action| action.label.clone())
            .unwrap_or_default()
    }
}

/// The rows of the model's protection section, weighted through the ONE shared derivation.
///
/// Ids are assigned over the WHOLE tab before the narrowing, for the reason [`grouped`] records: the
/// occurrence count is a position in the model's complete list, and deriving it from a filtered one
/// would address these rows differently from the rest of the app.
fn protection_actions(tab: &Tab) -> Vec<Action<TrayAction>> {
    let mut seen = HashMap::new();
    tab.sections
        .iter()
        .flat_map(|section| {
            let drawn = super::actions_in(section.rows.iter().cloned(), &mut seen);
            match section.heading.as_deref() == Some(crate::window_model::PROTECTION_HEADING) {
                true => drawn,
                false => Vec::new(),
            }
        })
        .collect()
}

/// The verb this pane promotes on `tab`, as it will be drawn.
///
/// The single-source answer to "which control on this window is the primary", for the guard in
/// [`super`] that checks nothing else is (dig_ecosystem#2354). Test-only, because production code
/// gets the same answer from [`Protection::of`] on its way to drawing it.
#[cfg(test)]
pub(crate) fn promoted_lead(tab: &Tab) -> Option<Action<TrayAction>> {
    Protection::of(tab).lead_action().cloned()
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
fn verb_cards(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    drew_copy_control: bool,
) -> Option<TrayAction> {
    let (safe, destroying) = grouped(tab, drew_copy_control);
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
fn grouped(tab: &Tab, drew_copy_control: bool) -> (Vec<Group>, Vec<Group>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let groups: Vec<Group> = tab
        .sections
        .iter()
        .filter_map(|section| {
            // Ids are assigned for EVERY section, including the one this pane goes on to skip: the
            // occurrence count that gives each row its element id is a position in the model's
            // complete list, so passing over a section before `actions_in` sees it would renumber
            // every row after it. Filtering the row list happens after, for the same reason.
            let actions = spare_verbs(
                super::actions_in(section.rows.iter().cloned(), &mut seen),
                drew_copy_control,
            );
            // Every section this pane draws with a card of its own is skipped here — protection as
            // the state card and the two cards under it, profiles as the list card, and the profile
            // editor as the form — because a group for any of them would put its verbs on the pane
            // a second time.
            //
            // The second copy is not merely redundant, it DISABLES the first: both are addressed by
            // `row_element_id(label, occurrence)`, both get occurrence 0, and to egui two widgets
            // with one id are one widget. That is what left `Publish my profile changes…`
            // unpressable however much was typed into the form above it (dig_ecosystem#3057) — and
            // the editor's copy is the one that must survive, because it is the only one that knows
            // whether the draft has anything in it to publish.
            if matches!(
                section.heading.as_deref(),
                Some(crate::window_model::PROTECTION_HEADING)
                    | Some(crate::window_model::PROFILES_HEADING)
                    | Some(crate::window_model::PROFILE_EDIT_HEADING)
            ) {
                return None;
            }
            Some(Group {
                heading: section.heading.clone(),
                destroys: actions
                    .iter()
                    .any(|action| super::is_destructive(action.id)),
                actions,
            })
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
    fn view_for(account: AccountState) -> TrayView {
        TrayView {
            running: true,
            account: Some(account),
            profile_id: Some("a".repeat(64)),
            ..TrayView::default()
        }
    }

    /// The Account tab as the real model builds it for `account`.
    fn tab_for(account: AccountState) -> Tab {
        let view = view_for(account);
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

    /// **The pane offers exactly the model's verbs, in every state — protection rows included.**
    ///
    /// Run over every state rather than one, because the tab's rows differ per state and a pane that
    /// dropped a verb would do it in only some of them.
    ///
    /// The two halves are summed deliberately. Merging Security into this pane
    /// (dig_ecosystem#2358) split its rendering in two — [`Protection`] draws the protection
    /// section, [`grouped`] draws the rest and SKIPS that section so nothing is drawn twice — and
    /// the risk that split introduces is a row falling down the gap between them. Asserting either
    /// half alone would miss it in the direction that matters: `grouped` on its own is happily
    /// short by exactly the rows it was told to skip.
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
            let (safe, destroying) = grouped(&tab, false);
            let protection = Protection::of(&tab);
            // The profiles card is the fourth renderer on this pane, and `grouped` skips its
            // section for the same reason it skips protection's — so its verbs have to be summed in
            // here, or a row falling down the gap between the two would read as the pane simply
            // having fewer verbs than the model.
            let mut rendered: Vec<TrayAction> = safe
                .iter()
                .chain(destroying.iter())
                .flat_map(|group| group.actions.iter().map(|a| a.id))
                .chain(protection.lead.iter().map(|a| a.id))
                .chain(protection.second_factor.iter().map(|a| a.id))
                .chain(protection.paired_apps.iter().map(|a| a.id))
                .chain(super::super::profiles::drawn_actions(
                    &tab,
                    &PaneFacts::of_tray(&view_for(account.clone())),
                ))
                // The editor's card is the fifth renderer, and `grouped` now skips its section for
                // the same reason it skips the other two — so its verbs are summed in here, or a row
                // falling down that gap would read as the pane simply having fewer verbs than the
                // model.
                .chain(
                    super::super::profile_edit::save_verbs(&tab)
                        .iter()
                        .map(|a| a.id),
                )
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

    /// **No two controls on the Account pane share an element id** (dig_ecosystem#3057).
    ///
    /// # Why this is about a dead button and not about tidiness
    ///
    /// egui identifies a widget by its id, so two controls sharing one are ONE control to it: the
    /// second claims the interaction and the first stops responding to clicks entirely. That is what
    /// happened to `Publish my profile changes…`. The editor's card drew it — gated on whether the
    /// draft holds anything to publish — and [`grouped`] drew it a second time in a card of its own,
    /// because the skip list named the protection and profiles sections and not the editor's. Both
    /// copies were addressed as occurrence 0 of the same label, so the one people typed above never
    /// became pressable no matter what they typed.
    ///
    /// # Why the fixture must set `ProfileEditing::Possible`
    ///
    /// The model builds the editor's row ONLY when editing is possible, so every other fixture in
    /// this module has an empty profile-edit section — and a duplicate of nothing is not a
    /// duplicate. A pane-wide id sweep on the default view passes with the defect fully present.
    ///
    /// The sweep is over every renderer on the pane rather than over the editor alone: the property
    /// is that the pane draws each control once, and a check scoped to the two cards that collided
    /// this time would not see the next pair.
    #[test]
    fn no_two_controls_on_the_account_pane_share_an_element_id() {
        use crate::profile_edit::ProfileEditing;

        let view = TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            profile_id: Some("a".repeat(64)),
            profile_editing: ProfileEditing::Possible,
            ..TrayView::default()
        };
        let tab = crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state");
        let facts = PaneFacts::of_tray(&view);

        let editor = super::super::profile_edit::save_verbs(&tab);
        assert!(
            editor
                .iter()
                .any(|action| action.id == TrayAction::PublishProfileEdits),
            "the editor's card draws no publish control in this fixture, so this proves nothing"
        );

        let protection = Protection::of(&tab);
        let (safe, destroying) = grouped(&tab, drew_copy_control(&facts));
        let drawn: Vec<Action<TrayAction>> = safe
            .iter()
            .chain(destroying.iter())
            .flat_map(|group| group.actions.iter().cloned())
            .chain(protection.lead.iter().cloned())
            .chain(protection.second_factor.iter().cloned())
            .chain(protection.paired_apps.iter().cloned())
            .chain(editor.iter().cloned())
            .collect();

        let mut seen: HashMap<egui::Id, String> = HashMap::new();
        for action in &drawn {
            if let Some(first) = seen.insert(action.element, action.label.clone()) {
                panic!(
                    "“{}” and “{}” are drawn with the same element id, so egui treats them as one \
                     control and the first one a person reaches stops responding",
                    first, action.label
                );
            }
        }
    }

    /// **`Copy my DIG ID` is dropped from the verb cards only where the identity card drew a copy
    /// control of its own — and kept where it did not.**
    ///
    /// Both halves, because they are the two ways to get this wrong and only one of them is visible
    /// in a screenshot. Filtering unconditionally deletes the SOLE way to copy a DIG ID on an
    /// account that has none to show yet; not filtering at all is the duplication the Wallet tab
    /// already removed, which is what made the two tabs disagree about the rule.
    ///
    /// The fixtures are a real account with an id and the same state without one, and the guard
    /// below refuses to run unless they genuinely differ in whether the identity card draws a
    /// control — a pair that did not could not tell a conditional filter from an unconditional one.
    #[test]
    fn the_dig_id_copy_verb_is_dropped_only_where_the_identity_card_drew_one() {
        let with_id = PaneFacts::of_tray(&TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            profile_id: Some("a".repeat(64)),
            ..TrayView::default()
        });
        let without_id = PaneFacts::of_tray(&TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            profile_id: None,
            ..TrayView::default()
        });
        assert!(
            drew_copy_control(&with_id) && !drew_copy_control(&without_id),
            "the fixtures do not differ in whether the identity card draws a copy control, so this \
             test cannot tell a conditional filter from an unconditional one"
        );

        let tab = tab_for(AccountState::Unlocked { recoverable: true });
        let offered: Vec<TrayAction> = tab.actions();
        assert!(
            offered.contains(&TrayAction::CopyDigId),
            "the model stopped offering the row this test is about"
        );

        let rendered = |drew: bool| -> Vec<TrayAction> {
            let (safe, destroying) = grouped(&tab, drew);
            safe.iter()
                .chain(destroying.iter())
                .flat_map(|group| group.actions.iter().map(|a| a.id))
                .collect()
        };
        assert!(
            !rendered(true).contains(&TrayAction::CopyDigId),
            "an account showing its DIG ID is offered two ways to copy it, one of them in a card \
             that exists only to hold the duplicate"
        );
        assert!(
            rendered(false).contains(&TrayAction::CopyDigId),
            "an account with no id on screen lost the only way to copy it"
        );
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

        let (safe, destroying) = grouped(&tab, false);
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
        let (safe, destroying) = grouped(&tab, false);
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
        let (_, destroying) = grouped(&tab, false);
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

    /// The single character the fixture's 64-character DIG ID is built from.
    const FIXTURE_DIG_ID: &str = "a";

    /// Every string the drawn Account pane paints for `account`, at the shipping width.
    ///
    /// The REAL pane through the REAL model, because the property below is about what reaches a
    /// reader's eye — a sentence that exists in a `match` and is never drawn is not a second
    /// presentation of anything, and one drawn from a constant this test never names is exactly what
    /// it has to be able to see.
    fn painted_for(account: AccountState) -> Vec<String> {
        let view = TrayView {
            running: true,
            account: Some(account),
            profile_id: Some(FIXTURE_DIG_ID.repeat(64)),
            ..TrayView::default()
        };
        let tab = crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state");
        let facts = PaneFacts::of_tray(&view);

        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(960.0, 8_000.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("account-copy-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(screen.width() - space::S5 * 2.0, f32::INFINITY),
                            );
                            super::super::draw_tab(
                                ui,
                                column,
                                &t,
                                &tab,
                                &facts,
                                Default::default(),
                                true,
                            );
                        });
                },
            );
        }

        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut said = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut said);
        }
        said
    }

    /// Every fixed word this pane can paint, named one by one.
    ///
    /// # Why an explicit list is the point rather than a weakness
    ///
    /// The guard below asks whether anything on screen is UNACCOUNTED for, so it needs to know what
    /// is accounted for. Everything here is a `const` — one string, the same in all six states — so
    /// no entry can be a per-state sentence set hiding in the list. A second six-arm match over
    /// `AccountKind` returns a DIFFERENT string per state, so laundering one through this list would
    /// mean adding six entries by hand, in the diff, on purpose. That is not the failure
    /// dig_ecosystem#2357 was: two sets drifting silently, each green against itself, with nothing
    /// in the repository comparing them.
    const FIXED_WORDS: &[&str] = &[
        copy::protection::PROTECTION_CARD,
        copy::protection::SECOND_FACTOR_CARD,
        copy::protection::SECOND_FACTOR_ON,
        copy::protection::SECOND_FACTOR_OFF,
        copy::protection::PAIRED_APPS_CARD,
        copy::protection::PAIRED_APPS_HINT,
        copy::account::UNREAD,
        copy::account::UNREAD_BADGE,
        copy::account::IDENTITY_CARD,
        copy::account::DIG_ID_LABEL,
        copy::account::DIG_ID_UNKNOWN,
        copy::account::DESTRUCTIVE_CAVEAT,
        copy::clipboard::COPY,
        copy::clipboard::COPIED,
        // The profiles card. Every one of these is a `const` or is keyed on a fact that is held
        // FIXED across the six account states — `cannot_create` varies with the BUILD's mint seam,
        // not with the account — so none of them can be a per-state sentence set laundered through
        // this list.
        copy::profiles::CARD,
        copy::profiles::CREATE_PANEL,
        copy::profiles::PENDING,
        copy::profiles::EMPTY,
        copy::profiles::ACTIVE_BADGE,
        copy::profiles::HIDDEN_BADGE,
        copy::profiles::DID_LABEL,
        copy::profiles::SWITCH_CAUTION,
        copy::profiles::HIDE_NOTE,
        copy::profiles::ACTIVE_CANNOT_HIDE,
        copy::profiles::ONE_PROFILE,
        // The profile-VIEWER card (dig_ecosystem#3008). Every one is a `const` keyed on the LOOKUP
        // reading, which is a fact about a store somebody typed and not about this account — so
        // none of them can vary with the six account states, and none can launder a per-state set.
        // The state sentences below the box are not listed because the fixture installs no lookup
        // service, so the card draws only its invitation and its box.
        copy::profile_view::CARD,
        copy::profile_view::INVITATION,
        copy::profile_view::FIELD_LABEL,
        copy::profile_view::FIELD_PLACEHOLDER,
        copy::profile_view::FIELD_HELP,
        copy::profile_view::LOOK_UP,
        // An empty text box paints an empty galley. Not prose, and admitted as itself rather than
        // by relaxing the check: a rule that ignored short strings would ignore a real word.
        "",
    ];

    /// Every string the pane is accounted for painting in `account`'s state.
    ///
    /// Four sources, and none of them is a parallel sentence set: the fixed words above, the ONE
    /// summary, the badge word, and everything the MODEL supplies — the tab's own title and lead,
    /// its section headings and its row labels, which differ by state because the VERBS do. The two
    /// "way forward" sentences are included because they are `format!`ed FROM the model's own lead
    /// label, which makes them derived from a single source rather than a second one.
    fn accounted_for(account: &AccountState) -> Vec<String> {
        let kind = super::super::facts::AccountKind::of(account);
        let tab = tab_for(account.clone());
        let lead = Protection::of(&tab).lead_label();

        let mut allowed: Vec<String> = FIXED_WORDS.iter().map(|word| word.to_string()).collect();
        allowed.push(copy::account::summary(kind).to_string());
        allowed.push(kind.word().to_string());
        // Every sentence the create panel can draw, keyed on the node READING rather than on the
        // account's state — the same string in all six — so none of them is a second per-state
        // sentence set. All of them are admitted because the fixture holds the reading fixed and
        // any one of them could be the one drawn.
        //
        // DERIVED rather than hand-listed, because the hand-listed version drifted the moment a
        // third arm arrived: `CHECKING_CREATION` (dig_ecosystem#2690) was absent from the list, so
        // this test failed for a sentence that was never a parallel set at all. Walking
        // `CreationBlocked::EVERY` stops a new blocked arm doing the same thing again.
        allowed.push(copy::profiles::CHECKING_CREATION.to_string());
        allowed.extend(
            crate::profiles::CreationBlocked::EVERY
                .into_iter()
                .map(|blocked| {
                    copy::profiles::cannot_create(blocked, crate::profiles::ProfileNames::NONE)
                        .to_string()
                }),
        );
        // Every sentence the profile editor's card can draw, keyed on the EDITING reading rather
        // than on the account's state — so none of them is a second per-state sentence set. All
        // are admitted because the fixture holds that reading fixed and any one could be the one
        // drawn. Derived from `EditBlocked`'s own list for `CreationBlocked`'s reason: a
        // hand-listed version drifts the moment a fourth blocker arrives.
        allowed.push(copy::profile_edit::MEASURING.to_string());
        allowed.push(copy::profile_edit::READING.to_string());
        allowed.push(copy::profile_edit::EMPTY.to_string());
        allowed.push(copy::profile_edit::COST.to_string());
        allowed.push(copy::profile_edit::PUBLIC.to_string());
        allowed.push(copy::profile_edit::NOTHING_CHANGED.to_string());
        allowed.push(copy::profile_edit::ALL_OPTIONAL.to_string());
        allowed.push(copy::profile_edit::RETRY.to_string());
        allowed.extend(
            crate::profile_edit::EditBlocked::EVERY
                .into_iter()
                .map(|blocked| blocked.sentence().to_string()),
        );
        allowed.push(copy::protection::second_factor_needs(&lead));
        allowed.push(copy::protection::pairing_needs(&lead));
        allowed.push(tab.label.clone());
        allowed.push(copy::lead(TabId::Account).to_string());
        // The identity card's VALUE, which is a reading and not prose. It is the same in every
        // state here because the fixture holds it fixed — which is the point: what varies between
        // two captures must be the account's state and nothing else.
        allowed.push(FIXTURE_DIG_ID.repeat(64));
        allowed.extend(tab.sections.iter().filter_map(|s| s.heading.clone()));
        allowed.extend(tab.sections.iter().flat_map(|section| {
            section.rows.iter().filter_map(|row| match row {
                MenuRow::Action { label, .. } => Some(label.clone()),
                _ => None,
            })
        }));
        allowed
    }

    /// **There is exactly ONE per-state sentence set on this pane** (dig_ecosystem#2357).
    ///
    /// # Why this shape, and not "both sets are internally consistent"
    ///
    /// The defect was two hand-maintained six-arm matches over one `AccountKind` —
    /// `account::summary` and `security::protection` — each with a test asserting only its OWN
    /// distinctness. Nothing compared them, so they were free to drift apart indefinitely while both
    /// suites stayed green, and a reader who visited both tabs would eventually be told two
    /// different things about one state. A THIRD such set would have passed both suites too. So the
    /// property asserted here is not "each set is tidy" but "there is one".
    ///
    /// It is asserted on what the pane PAINTS, in every state, and it is a CLOSURE check: every
    /// string on screen must be the one summary, the badge word, one of the fixed words named above,
    /// or something the model supplied. A second per-state set produces, in each of the six states,
    /// a sentence that is none of those — and fails here six times over.
    ///
    /// Drawn rather than read off the `match`, deliberately: a sentence that exists in code and
    /// never reaches a reader is not a second presentation of anything, and one drawn from a
    /// constant this test never names is exactly the case it has to be able to see.
    ///
    /// The vacuity guard is load-bearing. If the pane painted nothing, or `accounted_for` grew to
    /// allow everything, the unexplained set would be empty in every state and this would pass
    /// loudest of all. So each state is first asserted to genuinely PAINT its summary, and the
    /// distinctness of those summaries is the separate control below.
    #[test]
    fn the_account_pane_has_exactly_one_per_state_sentence() {
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
        ] {
            let said = painted_for(account.clone());
            let kind = super::super::facts::AccountKind::of(&account);
            assert!(
                said.iter().any(|line| line == copy::account::summary(kind)),
                "{account:?}: the one summary never reached the screen, so the check below is \
                 examining a pane that says nothing about its state: {said:?}"
            );

            let allowed = accounted_for(&account);
            let unexplained: Vec<&String> =
                said.iter().filter(|line| !allowed.contains(line)).collect();
            assert!(
                unexplained.is_empty(),
                "the {account:?} pane paints prose that is neither the one summary, the badge \
                 word, a named fixed word, nor anything the model supplied. A string chosen by the \
                 account's state and sourced from somewhere else is a SECOND per-state sentence \
                 set — the drift dig_ecosystem#2357 removed: {unexplained:?}"
            );
        }
    }

    /// **The control: the one summary really does differ between every pair of states.**
    ///
    /// Without it the sweep above is satisfied by a pane whose copy does not vary at all, which is
    /// the failure mode a "there is only one set" assertion cannot see on its own — one set and no
    /// sets look identical to a difference check.
    #[test]
    fn the_one_summary_differs_between_every_pair_of_states() {
        let said: Vec<&str> = super::super::facts::AccountKind::ALL
            .iter()
            .map(|kind| copy::account::summary(*kind))
            .collect();
        for (i, left) in said.iter().enumerate() {
            for right in &said[i + 1..] {
                assert_ne!(left, right, "two account states share one summary");
            }
        }
    }

    /// **The merged sentence still does BOTH jobs the two sets did.**
    ///
    /// Collapsing two sentence sets into one is only honest if nothing the reader needed was dropped
    /// in the merge, and the half at risk is the protection half — the summaries were this pane's own
    /// copy, while the protection sentences were the ones that refused to flatter. So the three
    /// claims that were load-bearing on the deleted `security::protection` are asserted here, on the
    /// surviving source: the two states that read calmly at a glance say plainly that they are not
    /// safe, and the open one says it is open rather than that it is safe.
    #[test]
    fn a_weakly_protected_account_is_never_described_as_protected() {
        use super::super::facts::AccountKind;

        let machine_password = copy::account::summary(AccountKind::NeedsPassword);
        assert!(
            machine_password.contains("Anyone who can use this computer can open it"),
            "the machine-password state does not say who else can open the account: \
             {machine_password}"
        );
        assert_ne!(
            AccountKind::NeedsPassword.tone(),
            data::Tone::Good,
            "an account anyone at this keyboard can open was coloured as though it were fine"
        );

        let unopenable = copy::account::summary(AccountKind::Unopenable);
        assert!(
            unopenable.contains("not protection"),
            "the unopenable state is allowed to read as though the account were locked safely: \
             {unopenable}"
        );
        assert_ne!(
            AccountKind::Unopenable.tone(),
            data::Tone::Good,
            "an account nobody can open was coloured as though it were fine"
        );

        let open = copy::account::summary(AccountKind::Unlocked);
        assert!(
            open.contains("open right now"),
            "the unlocked state does not say the account is currently open: {open}"
        );

        // The control: the two ordinary working states are NOT painted as problems, so the two above
        // are a real distinction rather than a pane that alarms about everything.
        assert_eq!(AccountKind::Locked.tone(), data::Tone::Good);
        assert_eq!(AccountKind::Unlocked.tone(), data::Tone::Good);
    }
}
