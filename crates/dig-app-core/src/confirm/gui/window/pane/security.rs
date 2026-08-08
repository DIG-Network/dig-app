//! The Security tab: is my account safe right now, and what protects it.
//!
//! # One question, answered in one glance
//!
//! Someone opens this tab to find out whether their account is safe *this minute*. So the pane leads
//! with that answer — a badge and one sentence — and everything under it is the machinery that
//! produced the answer: the lock, the second factor, the apps that have been let in.
//!
//! The sentences never flatter the state. Two of the six read calmly at a glance and are not calm at
//! all: an account sealed under a password the machine invented is a lock anyone at this keyboard
//! can open, and an account whose seal will not open is not protected, it is unusable. A custody
//! surface that implied either was fine would be lying about custody, which is the one defect this
//! pane cannot ship with.
//!
//! # What this pane does not decide
//!
//! `tray_menu::security_actions` decides which rows exist in each state — including the two absences
//! that matter here. `two_factor_row` returns `None` when nothing is enrolled and there is no open
//! account to enrol under, and `paired_app_rows` are offered only while the account is open. This
//! pane RENDERS those absences rather than reinterpreting them: it draws the line with **no
//! control** and a sentence pointing at the row the model itself put at the top of the pane. It does
//! not invent a disabled button — a greyed control that cannot say when it will work is the dead end
//! dig_ecosystem#1800 removed from this surface.

use std::collections::HashMap;

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data;
use super::facts::PaneFacts;
use super::flow::Flow;
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Security pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    let parts = Parts::of(tab);
    let mut pressed = protection_card(flow, t, facts, &parts);
    flow.gap(space::S4);
    pressed = pressed.or(second_factor_card(flow, t, facts, &parts));
    flow.gap(space::S4);
    pressed = pressed.or(paired_apps_card(flow, t, facts, &parts));
    pressed
}

/// The answer to "is my account safe right now", and the one act that changes it.
///
/// The promoted control is the model's LEADING row, verbatim — the row `security_actions` puts first
/// in every state, which is the same verb `urgent_account_row` promotes on the tray. The pane
/// chooses that it is drawn large and first; it does not choose which verb it is.
fn protection_card(
    flow: &mut Flow,
    t: &Tokens,
    facts: &PaneFacts,
    parts: &Parts,
) -> Option<TrayAction> {
    let live = flow.live();
    let badge = facts.account.map(|kind| (kind.word(), kind.tone()));
    let sentence = facts.account.map(copy::security::protection);
    let lead = parts.lead.clone();

    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::security::PROTECTION_CARD),
            |inner| {
                if let Some((word, tone)) = badge {
                    inner.place(|ui, at| {
                        (data::badge(ui, at.left_top(), t, word, tone).height(), ())
                    });
                    inner.gap(space::S3);
                }
                if let Some(sentence) = sentence {
                    inner.place(|ui, at| (text::body(ui, at, t, sentence), ()));
                    inner.gap(space::S4);
                }
                inner
                    .place(|ui, at| action::buttons(ui, at, t, live, &lead))
                    .flatten()
            },
        );
        (height, hit.flatten())
    })
    .flatten()
}

/// The second factor: its control when there is one to offer, and its reason when there is not.
fn second_factor_card(
    flow: &mut Flow,
    t: &Tokens,
    facts: &PaneFacts,
    parts: &Parts,
) -> Option<TrayAction> {
    if !parts.has_account {
        return None;
    }
    let hint = match parts.second_factor.first() {
        Some(_) if facts.second_factor => copy::security::SECOND_FACTOR_ON.to_string(),
        Some(_) => copy::security::SECOND_FACTOR_OFF.to_string(),
        // The absence the model decided, rendered as an absence: no control at all, and the way
        // forward quoted from the row above rather than written here, where it would eventually
        // name the wrong one.
        None => copy::security::second_factor_needs(&parts.lead_label()),
    };
    line_card(
        flow,
        t,
        copy::security::SECOND_FACTOR_CARD,
        &hint,
        &parts.second_factor,
    )
}

/// The apps this computer has let in.
fn paired_apps_card(
    flow: &mut Flow,
    t: &Tokens,
    _facts: &PaneFacts,
    parts: &Parts,
) -> Option<TrayAction> {
    if !parts.has_account {
        return None;
    }
    let hint = match parts.paired_apps.is_empty() {
        false => copy::security::PAIRED_APPS_HINT.to_string(),
        true => copy::security::pairing_needs(&parts.lead_label()),
    };
    line_card(
        flow,
        t,
        copy::security::PAIRED_APPS_CARD,
        &hint,
        &parts.paired_apps,
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
            inner
                .place(|ui, at| action::buttons(ui, at, t, live, &actions))
                .flatten()
        });
        (height, hit.flatten())
    })
    .flatten()
}

/// The tab's rows, sorted into the three things this pane is about.
///
/// # Sorting by action, not by position
///
/// Which rows `security_actions` emits differs by state — an unlocked account gets four, a locked
/// one gets two, and a computer with no account gets one — so an index into that list means
/// something different in each state. Matching on the [`TrayAction`] asks what a row IS, which is
/// stable across every state, and it reads the model's answer rather than recomputing it.
struct Parts {
    /// The leading row: the one thing this account needs from the user right now.
    lead: Vec<Action<TrayAction>>,
    /// The second-factor row, or empty where the model offered none.
    second_factor: Vec<Action<TrayAction>>,
    /// The paired-app rows, or empty where the model offered none.
    paired_apps: Vec<Action<TrayAction>>,
    /// Whether there is an account here for the lower cards to be about.
    has_account: bool,
}

impl Parts {
    /// Sort `tab`'s rows, keeping the model's order and its element ids.
    fn of(tab: &Tab) -> Self {
        let mut seen: HashMap<String, usize> = HashMap::new();
        let actions = super::actions_in(
            tab.sections
                .iter()
                .flat_map(|section| section.rows.iter().cloned()),
            &mut seen,
            &super::status::is_destructive,
        );

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
        parts
    }

    /// The leading row's label, for a sentence that must name the way forward exactly.
    fn lead_label(&self) -> String {
        self.lead
            .first()
            .map(|action| action.label.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{AccountState, TrayView};
    use crate::window_model::TabId;

    /// The Security tab as the real model builds it.
    fn tab_for(account: AccountState, second_factor: bool) -> Tab {
        let view = TrayView {
            running: true,
            account: Some(account),
            second_factor,
            ..TrayView::default()
        };
        crate::window_model::build(&view)
            .tab(TabId::Security)
            .cloned()
            .expect("the Security tab is emitted in every account state")
    }

    /// **The pane offers exactly the model's verbs, in every state, with nothing dropped.**
    ///
    /// The sort is the risk this pins: a row whose action fell through none of the arms would be
    /// silently unreachable, and the states differ in which rows exist, so it is checked in all of
    /// them and with the second factor both on and off.
    #[test]
    fn sorting_the_rows_loses_none_of_them() {
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
        ] {
            for second_factor in [false, true] {
                let tab = tab_for(account.clone(), second_factor);
                let parts = Parts::of(&tab);
                let mut rendered: Vec<TrayAction> = parts
                    .lead
                    .iter()
                    .chain(&parts.second_factor)
                    .chain(&parts.paired_apps)
                    .map(|a| a.id)
                    .collect();
                let mut expected = tab.actions();
                assert!(
                    !expected.is_empty(),
                    "the {account:?}/{second_factor} fixture has no rows, so this proves nothing"
                );
                rendered.sort_by_key(|a| format!("{a:?}"));
                expected.sort_by_key(|a| format!("{a:?}"));
                assert_eq!(
                    rendered, expected,
                    "the {account:?}/{second_factor} pane lost or invented a verb"
                );
            }
        }
    }

    /// **The promoted control is the model's leading row, verbatim, in every state.**
    ///
    /// Not a verb this pane picked: the row `security_actions` puts first differs by state — and the
    /// three that are easy to get wrong are checked by name, because each was at some point given
    /// another state's remedy (dig_ecosystem#2059).
    #[test]
    fn the_promoted_verb_is_the_models_own_leading_row() {
        let cases = [
            (AccountState::Locked, TrayAction::Unlock),
            (AccountState::NeedsPassword, TrayAction::SetAccountPassword),
            (AccountState::Unopenable, TrayAction::ExplainUnopenable),
            (
                AccountState::Unlocked { recoverable: true },
                TrayAction::LockNow,
            ),
        ];
        for (account, expected) in cases {
            let tab = tab_for(account.clone(), false);
            let parts = Parts::of(&tab);
            let lead = parts.lead.first().expect("every state leads with a row");
            assert_eq!(
                lead.id, expected,
                "the {account:?} pane promoted the wrong verb"
            );
            assert_eq!(
                lead.id,
                tab.actions()[0],
                "the promoted verb is not the model's first row"
            );
            assert_eq!(
                lead.weight,
                Weight::Primary,
                "the {account:?} pane's answer to “what do I do now” is not its loudest control"
            );
        }
    }

    /// **Where the model offers no second factor, the pane draws no control — and says why.**
    ///
    /// Two actors, deliberately. A locked account with nothing enrolled is the case
    /// `two_factor_row` answers `None` for, and the same locked account WITH a factor enrolled still
    /// gets its "turn off" row — so a pane that simply never drew a second-factor control would pass
    /// a one-actor test and fail this one.
    ///
    /// The sentence is checked to quote the model's own leading row, which is what keeps it from
    /// naming a remedy the state cannot perform: on a `NeedsPassword` account it must say "set a
    /// password", never "unlock".
    #[test]
    fn an_unofferable_second_factor_is_a_sentence_not_a_greyed_button() {
        let locked = Parts::of(&tab_for(AccountState::Locked, false));
        assert!(
            locked.second_factor.is_empty(),
            "the model offered no second-factor row here, so the pane must not draw a control"
        );
        let sentence = copy::security::second_factor_needs(&locked.lead_label());
        assert!(
            sentence.contains("Unlock…"),
            "the sentence does not quote the model's own way forward: {sentence}"
        );

        let enrolled = Parts::of(&tab_for(AccountState::Locked, true));
        assert_eq!(
            enrolled.second_factor.len(),
            1,
            "a locked account with a factor enrolled must still be able to turn it off"
        );
        assert_eq!(enrolled.second_factor[0].id, TrayAction::TurnOffTwoFactor);
    }

    /// **The way-forward sentence never names a remedy the state cannot perform.**
    ///
    /// The `NeedsPassword` half is dig_ecosystem#2059 on this pane: the account has no password to
    /// type, so a sentence saying "unlock" would be advice it cannot follow. Quoting the model's row
    /// is what makes that structural, and this is the assertion that proves the quoting works.
    #[test]
    fn the_second_factor_sentence_follows_the_state() {
        let needs_password = Parts::of(&tab_for(AccountState::NeedsPassword, false));
        let sentence = copy::security::second_factor_needs(&needs_password.lead_label());
        assert!(
            !sentence.to_lowercase().contains("unlock"),
            "a NeedsPassword account was told to unlock (dig_ecosystem#2059): {sentence}"
        );
        assert!(
            sentence.contains("Set a password for my DIG Account…"),
            "the sentence does not name the act that actually opens this account: {sentence}"
        );
    }

    /// **Pairing is offered only where the model offers it, and its absence explains itself.**
    #[test]
    fn paired_apps_appear_only_where_the_model_offers_them() {
        let unlocked = Parts::of(&tab_for(
            AccountState::Unlocked { recoverable: true },
            false,
        ));
        assert_eq!(
            unlocked.paired_apps.len(),
            2,
            "an open account can pair an app and review the ones it has"
        );

        let locked = Parts::of(&tab_for(AccountState::Locked, false));
        assert!(locked.paired_apps.is_empty());
        let sentence = copy::security::pairing_needs(&locked.lead_label());
        assert!(
            sentence.contains("Unlock…"),
            "the pairing sentence does not name the way forward: {sentence}"
        );
    }

    /// **A computer with no account gets the answer, and not the machinery.**
    ///
    /// Both states are checked, and against the row the model actually emits: cards headed
    /// "Two-factor codes" and "Paired apps" on a machine with no account would be an interface for
    /// protecting something that does not exist.
    #[test]
    fn a_computer_with_no_account_is_not_shown_the_protections() {
        for account in [AccountState::Absent, AccountState::Unsupported] {
            let parts = Parts::of(&tab_for(account.clone(), false));
            assert!(
                !parts.has_account,
                "{account:?} was treated as having an account to protect"
            );
            assert_eq!(parts.lead.len(), 1, "{account:?} should say one thing");
            assert_eq!(parts.lead[0].id, TrayAction::ShowStatus);
        }

        let locked = Parts::of(&tab_for(AccountState::Locked, false));
        assert!(
            locked.has_account,
            "a locked account IS an account, and its protections must still be shown"
        );
    }

    /// **Each state's protection sentence is its own.**
    ///
    /// The same rule as the Account pane's summaries, for the same reason: a shared sentence is a
    /// reader being told about a state they are not in.
    #[test]
    fn no_two_states_share_a_protection_sentence() {
        let said: Vec<&str> = super::super::facts::AccountKind::ALL
            .iter()
            .map(|kind| copy::security::protection(*kind))
            .collect();
        for (i, left) in said.iter().enumerate() {
            for right in &said[i + 1..] {
                assert_ne!(left, right, "two states share one protection sentence");
            }
        }
    }

    /// **The two states that read calmly are not described as safe.**
    ///
    /// This is the custody-honesty rule as an assertion. `No password set` and `Unreadable` both
    /// sound unalarming, and both are states where the account is NOT protected — one because
    /// anybody at this keyboard can open it, the other because nobody can. A sentence that let
    /// either pass for fine would be the pane lying about custody.
    #[test]
    fn a_weakly_protected_account_is_never_described_as_protected() {
        use super::super::facts::AccountKind;

        let machine_password = copy::security::protection(AccountKind::NeedsPassword);
        assert!(
            machine_password.contains("Anyone who can use this computer can open it"),
            "the machine-password state does not say who else can open the account: \
             {machine_password}"
        );
        assert_eq!(
            AccountKind::NeedsPassword.tone(),
            data::Tone::Bad,
            "an account anyone at this keyboard can open was coloured as though it were fine"
        );

        let unopenable = copy::security::protection(AccountKind::Unopenable);
        assert!(
            unopenable.contains("not protection"),
            "the unopenable state is allowed to read as though the account were locked safely: \
             {unopenable}"
        );
        assert_eq!(AccountKind::Unopenable.tone(), data::Tone::Bad);

        // The control: the two ordinary working states are NOT painted as problems, so the two
        // above are a real distinction rather than a pane that alarms about everything.
        assert_eq!(AccountKind::Locked.tone(), data::Tone::Good);
        assert_eq!(AccountKind::Unlocked.tone(), data::Tone::Good);
    }

    /// **An open account is told it is open, rather than told it is safe.**
    #[test]
    fn an_open_account_is_described_as_open() {
        use super::super::facts::AccountKind;
        let said = copy::security::protection(AccountKind::Unlocked);
        assert!(
            said.contains("open right now"),
            "the unlocked state does not say the account is currently open: {said}"
        );
    }
}
