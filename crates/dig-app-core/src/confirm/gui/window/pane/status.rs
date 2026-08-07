//! The Status tab, built on the pane vocabulary — the reference every other tab is written against.
//!
//! # Why Status is the exemplar
//!
//! It is the tab a person lands on, it is the most data-rich one that needs no new plumbing, and it
//! exercises the parts of the vocabulary a Phase-2 tab will reach for first: cards grouping facts,
//! readouts with units, a meter against a cap, a badge, an action group with a hierarchy, and both
//! honest absences — a figure the node has not reported, and a card whose data is not wired up.
//!
//! # What it does NOT do
//!
//! It does not decide which actions exist. `tab.sections` arrives already decided by
//! [`crate::window_model`], and this module renders those rows as buttons — same verbs, same
//! enablement, same labels, different weight. Delete this file and the Status tab falls back to the
//! generic pane with exactly the same capabilities.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::identity;
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Status pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    machine_card(flow, t, facts);
    flow.gap(space::S4);
    node_card(flow, t, facts);
    flow.gap(space::S4);
    // Verbs before figures-with-no-figures. The sharing card is the least urgent thing on the tab
    // and the diagnostics are what a person on a broken machine came here for, so an unwired card
    // must not push the log-folder button below the fold at the default window size.
    let pressed = diagnostics_card(flow, t, tab);
    flow.gap(space::S4);
    sharing_card(flow, t);
    flow.gap(space::S4);
    receiving_card(flow, t, facts);
    pressed
}

/// What this computer is running: the agent, the version, the account, the second factor.
fn machine_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let items = vec![
        Readout::new(
            copy::status::AGENT_LABEL,
            Value::Word(copy::agent_state(facts.agent_running).to_string()),
        ),
        Readout::new(
            copy::status::VERSION_LABEL,
            Value::Word(facts.version.to_string()),
        ),
        Readout::new(
            copy::status::ACCOUNT_LABEL,
            match facts.account_word {
                Some(word) => Value::Word(word.to_string()),
                // The honest absence: a host that cannot hold an account has no account state, and
                // showing "None" would claim one was merely missing.
                None => Value::Unknown(
                    "This computer cannot hold a DIG Account. Install DIG on a supported system to \
                     set one up."
                        .to_string(),
                ),
            },
        ),
        Readout::new(
            copy::status::SECOND_FACTOR_LABEL,
            Value::Word(copy::second_factor_state(facts.second_factor).to_string()),
        ),
    ];
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::status::AGENT_CARD), |inner| {
                inner.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
            }),
            (),
        )
    });
}

/// What the node is doing, and how full the content cache is.
fn node_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let summary = facts.node_summary.clone();
    let (word, tone) = facts.node_state();
    let cache = facts.cache;

    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::status::NODE_CARD), |inner| {
                // The badge sits on its own line above the summary rather than beside the card's
                // title: at 480 px a title plus a badge is two things competing for one row, and the
                // badge is the one that loses its padding first.
                inner.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
                inner.gap(space::S3);
                // The engine already writes this as a sentence ("connected to ..." or the
                // actionable reason it is not), so it is prose under the badge rather than a
                // labelled figure — a label reading "What the node is doing" above a sentence that
                // says what the node is doing is the label saying it twice.
                inner.place(|ui, at| (text::body(ui, at, t, &summary), ()));
                inner.gap(space::S4);
                inner.place(|ui, at| {
                    let height = match &cache {
                        Some(snapshot) => data::meter(
                            ui,
                            at,
                            t,
                            copy::status::CACHE_METER_LABEL,
                            snapshot.used_bytes,
                            snapshot.cap_bytes,
                        ),
                        // No node has reported a cache, so there is no meter to draw — and a meter
                        // at zero would say the cache is empty, which is a different claim.
                        None => data::readout(
                            ui,
                            at,
                            t,
                            &Readout::new(
                                copy::status::CACHE_CARD,
                                Value::Unknown(copy::status::CACHE_UNKNOWN.to_string()),
                            ),
                        ),
                    };
                    (height, ())
                });
            }),
            (),
        )
    });
}

/// What this computer is sharing with the network — DESIGNED, and not yet wired to the node.
///
/// # Why a card with no data in it is worth shipping
///
/// These four figures come from the node's `control.status`, which this window does not read yet.
/// The card exists so the Phase-2 implementer inherits a worked example of the honest skeleton: the
/// layout is finished, every value is an explicit absence carrying its reason, and the pane SAYS the
/// figures are not readings. A card of plausible zeroes would look finished and be a lie; an absent
/// card would hide that the work is planned.
fn sharing_card(flow: &mut Flow, t: &Tokens) {
    // Every value is `Unknown`, which is the only way this card can be written: `Value` has no
    // variant that could hold a placeholder number here even if somebody wanted one.
    let items: Vec<Readout> = copy::status::SHARING_LABELS
        .iter()
        .map(|label| {
            Readout::new(
                *label,
                Value::Unknown(copy::status::SHARING_UNKNOWN.to_string()),
            )
        })
        .collect();

    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::status::SHARING_CARD), |inner| {
                // The glance-level half of what the banner spells out. A reader skimming the pane
                // must not have to read a paragraph to learn that this card is not reporting on
                // their machine.
                inner.place(|ui, at| {
                    (
                        data::badge(
                            ui,
                            at.left_top(),
                            t,
                            copy::unwired::BADGE,
                            data::Tone::Neutral,
                        )
                        .height(),
                        (),
                    )
                });
                inner.gap(space::S3);
                inner.place(|ui, at| (state::banner(ui, at, t, &PaneState::Unwired), ()));
                inner.gap(space::S4);
                inner.place(|ui, at| {
                    (
                        card::panel(ui, at, t, None, |panel| {
                            panel.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
                        }),
                        (),
                    )
                });
            }),
            (),
        )
    });
}

/// The tab's own verbs, as a weighted button group.
fn diagnostics_card(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let actions = actions_of(tab);
    if actions.is_empty() {
        return None;
    }
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::status::ACTIONS_CARD), |inner| {
                let hit = inner
                    .place(|ui, at| action::buttons(ui, at, t, live, &actions))
                    .flatten();
                inner.gap(space::S3);
                inner
                    .place(|ui, at| (text::caption(ui, at, t, copy::status::DIAGNOSTICS_HINT), ()));
                hit
            });
        (height, pressed.flatten())
    })
    .flatten()
}

/// The account's receive address, as a scannable code — the vocabulary's QR block, demonstrated on
/// the one value in this snapshot a person genuinely takes to another device.
///
/// Drawn only when there IS an address. Without one the card is omitted rather than showing an empty
/// plate: a code nobody can scan is a broken image with extra steps.
fn receiving_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let Some(address) = facts.receive_address.clone() else {
        return;
    };
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some("Receive"), |inner| {
                inner.place(|ui, at| {
                    (
                        identity::scannable(ui, at, t, &address, copy::qr::RECEIVE_CAPTION),
                        (),
                    )
                });
                inner.gap(space::S3);
                inner.place(|ui, at| {
                    (
                        identity::copyable(
                            ui,
                            at,
                            t,
                            "Receive address",
                            &Value::Identifier(address.clone()),
                            egui::Id::new("dig-window-copy-receive-address"),
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

/// The tab's rows as weighted actions, in the model's order.
///
/// Every section's rows, through the ONE derivation in [`super::actions_in`] — including the
/// occurrence counting that gives each row its stable element id. A second copy of that derivation
/// here is what previously addressed `Open the log folder` by its index and made it unclickable.
fn actions_of(tab: &Tab) -> Vec<Action<TrayAction>> {
    let mut seen = std::collections::HashMap::new();
    super::actions_in(
        tab.sections
            .iter()
            .flat_map(|section| section.rows.iter().cloned()),
        &mut seen,
        &is_destructive,
    )
}

/// Whether an action destroys something the user cannot get back.
///
/// A closed list rather than a guess from the label: a destructive control must be told apart from a
/// save by more than the words on it, and inferring that from prose would make the danger colour
/// depend on how a label happens to be phrased.
fn is_destructive(action: TrayAction) -> bool {
    matches!(
        action,
        TrayAction::RemoveAccount
            | TrayAction::ReplaceWithNewAccount
            | TrayAction::ReplaceFromPhrase
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{MenuRow, TrayView};

    /// **The pane renders exactly the verbs the model put on the tab — no more, no fewer.**
    ///
    /// This is the single-source rule, made checkable. A pane that filtered a verb out, or added one
    /// of its own, fails; and it is asserted against the REAL `window_model::build` output rather
    /// than a hand-written fixture, so a change to the Status tab upstream is reflected here without
    /// this test being edited.
    #[test]
    fn the_pane_offers_the_models_verbs_and_nothing_else() {
        let view = TrayView {
            running: true,
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tab(crate::window_model::TabId::Status)
            .expect("the Status tab is always emitted");

        let rendered: Vec<TrayAction> = actions_of(tab).into_iter().map(|a| a.id).collect();
        assert_eq!(
            rendered,
            tab.actions(),
            "the pane's buttons are not the model's actions, in the model's order"
        );
        assert!(
            !rendered.is_empty(),
            "the fixture has no actions, so this proves nothing"
        );
    }

    /// **A disabled verb stays disabled, and a disabled row does not become the primary button.**
    ///
    /// Two actors: the fixture keeps one enabled action beside the disabled one, so a weighting that
    /// simply never produced a primary would be indistinguishable from one that respects the order.
    #[test]
    fn enablement_passes_through_untouched_and_never_promotes_a_disabled_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Status,
            label: "Status".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![crate::window_model::Section {
                heading: None,
                rows: vec![
                    MenuRow::Action {
                        action: TrayAction::ShowStatus,
                        label: "Show my recovery phrase (unlock first)".to_string(),
                        enabled: false,
                    },
                    MenuRow::Action {
                        action: TrayAction::OpenLogs,
                        label: "Open the log folder".to_string(),
                        enabled: true,
                    },
                ],
            }],
        };

        let actions = actions_of(&tab);
        assert!(!actions[0].enabled, "the model said disabled");
        assert!(actions[1].enabled, "the model said enabled");
        assert_eq!(
            actions[0].weight,
            Weight::Ghost,
            "a disabled leading verb was drawn as the pane's primary control"
        );
        assert_eq!(
            actions[1].weight,
            Weight::Ghost,
            "the second verb was promoted to primary because the first was disabled"
        );
    }

    /// **A destructive verb is drawn as destructive wherever the model puts it.**
    ///
    /// Pinned on the action, never on its label: a danger colour that depended on the wording would
    /// change the moment somebody rephrased a menu entry.
    #[test]
    fn a_destructive_verb_is_coloured_by_what_it_does_not_by_what_it_says() {
        assert!(is_destructive(TrayAction::RemoveAccount));
        assert!(is_destructive(TrayAction::ReplaceWithNewAccount));
        assert!(is_destructive(TrayAction::ReplaceFromPhrase));
        assert!(!is_destructive(TrayAction::OpenLogs));
        assert_eq!(
            action::weigh(0, true, is_destructive(TrayAction::RemoveAccount)),
            Weight::Danger,
            "a destroy in the leading position must not be drawn as the friendly primary"
        );
        assert_eq!(
            action::weigh(5, true, is_destructive(TrayAction::RemoveAccount)),
            Weight::Danger
        );
    }

    /// **A separator never becomes a button.**
    #[test]
    fn a_separator_is_not_rendered_as_a_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Status,
            label: "Status".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![crate::window_model::Section {
                heading: None,
                rows: vec![
                    MenuRow::Separator,
                    MenuRow::Action {
                        action: TrayAction::OpenLogs,
                        label: "Open the log folder".to_string(),
                        enabled: true,
                    },
                    MenuRow::Separator,
                ],
            }],
        };
        assert_eq!(actions_of(&tab).len(), 1);
    }
}
