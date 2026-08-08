//! The Home tab: what DIG is doing on this computer, the other DIG apps it can open, and the way to
//! the logs when it cannot say.
//!
//! # Why Home is the exemplar
//!
//! It is the tab a person lands on, it is the most data-rich one that needs no new plumbing, and it
//! exercises the parts of the vocabulary a Phase-2 tab will reach for first: cards grouping facts,
//! readouts with units, a badge, an action group with a hierarchy, a launcher, and both honest
//! absences — a figure the node has not reported, and a card whose data is not wired up.
//!
//! # What it deliberately no longer holds (dig_ecosystem#2358)
//!
//! **The account rows.** `Account`, `Second factor` and the receive-address code all described the
//! account, which now has a whole tab of its own — and the receive card was a byte-identical second
//! copy of the Wallet tab's. A figure repeated is a figure that will eventually disagree with
//! itself, and a QR code repeated is that plus a person wondering which one is the real address.
//!
//! **The cache METER.** The Content tab owns it; this tab carries the one-line reading, from the
//! same [`crate::cache::CacheSnapshot`], so the two cannot report different disks.
//!
//! # What it does NOT do
//!
//! It does not decide which actions exist. `tab.sections` arrives already decided by
//! [`crate::window_model`], and this module renders those rows as buttons — same verbs, same
//! enablement, same labels, different weight. If you find yourself asking here whether a verb
//! should be shown, the model already answered.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Home pane's content into `flow`, and report the action pressed.
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
    let mut pressed = diagnostics_card(flow, t, tab);
    flow.gap(space::S4);
    // The launcher LAST, because it is what a person browses when nothing is wrong.
    pressed = pressed.or(super::apps::launcher(flow, t, tab));
    flow.gap(space::S4);
    sharing_card(flow, t);
    pressed
}

/// What this computer is running: the agent, and the version of it.
///
/// The agent's state also sits in the window's header strip, one word wide. That is not the
/// duplication dig_ecosystem#2357 removed: both come from [`copy::agent_state`] applied to the same
/// [`PaneFacts::agent_running`], so there is one derivation and two presentations of it — where the
/// cache meter was one FIGURE laid out twice, in two files, either editable without the other.
fn machine_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let items = vec![
        Readout::new(
            copy::home::AGENT_LABEL,
            Value::Word(copy::agent_state(facts.agent_running).to_string()),
        ),
        Readout::new(
            copy::home::VERSION_LABEL,
            Value::Word(facts.version.to_string()),
        ),
    ];
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::home::AGENT_CARD), |inner| {
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
            card::card(ui, at, t, Some(copy::home::NODE_CARD), |inner| {
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
                // A one-line READOUT of what the cache holds, not the meter — the meter lives on
                // the Content tab and is drawn once (dig_ecosystem#2357). This card used to redraw it
                // byte-identically, so the same bar appeared on two tabs and either could be edited
                // without the other. A figure repeated is a figure that will eventually disagree
                // with itself.
                inner.place(|ui, at| {
                    (
                        data::readout(
                            ui,
                            at,
                            t,
                            &Readout::new(copy::home::CACHE_CARD, cache_reading(cache)),
                        ),
                        (),
                    )
                });
            }),
            (),
        )
    });
}

/// What the cache holds, as one line — or the reason there is no figure.
///
/// A summary, deliberately, and not the meter. The Content tab owns the meter and the limit; Home
/// says only how much is in use, which is what a person scanning this tab is asking. Both figures
/// come from the same [`crate::cache::CacheSnapshot`], so the two tabs cannot disagree.
///
/// With no snapshot this is an `Unknown` carrying its reason, never a zero: nobody has reported a
/// cache, and "0 B" is the claim that the cache is empty.
fn cache_reading(cache: Option<crate::cache::CacheSnapshot>) -> Value {
    match cache {
        Some(snapshot) => Value::Word(format!(
            "{} of {}",
            crate::cache::format_cap(snapshot.used_bytes),
            crate::cache::format_cap(snapshot.cap_bytes)
        )),
        None => Value::Unknown(copy::home::CACHE_UNKNOWN.to_string()),
    }
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
    // Every value is `Unknown` — not because the type forces it (it does not, see `data`), but
    // because none of these four figures has been read from anything. The card is the worked
    // example: a finished layout whose every figure names its own absence.
    let items: Vec<Readout> = copy::home::SHARING_LABELS
        .iter()
        .map(|label| {
            Readout::new(
                *label,
                Value::Unknown(copy::home::SHARING_UNKNOWN.to_string()),
            )
        })
        .collect();

    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::home::SHARING_CARD), |inner| {
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

/// The tab's diagnostic verbs, as a weighted button group.
///
/// The launcher's rows are excluded: they are drawn as cards by [`super::apps::launcher`], and a
/// verb rendered twice on one tab is two controls a person has to tell apart before pressing either.
/// The split reads the model's own [`crate::window_model::APPS_HEADING`] rather than a position, so
/// reordering the sections upstream cannot silently move a launch row into this card.
fn diagnostics_card(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let actions = actions_of(tab);
    if actions.is_empty() {
        return None;
    }
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::home::ACTIONS_CARD), |inner| {
                let hit = inner.place(|ui, at| action::buttons(ui, at, t, live, &actions));
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::home::DIAGNOSTICS_HINT), ()));
                hit
            });
        (height, pressed.flatten())
    })
}

/// The tab's diagnostic rows as weighted actions, in the model's order.
///
/// Built from the WHOLE tab through the ONE derivation in [`super::actions_in`] — including the
/// occurrence counting that gives each row its stable element id — and only then filtered. A second
/// copy of that derivation here is what previously addressed `Open the log folder` by its index and
/// made it unclickable, and filtering FIRST would renumber every row after a dropped one.
fn actions_of(tab: &Tab) -> Vec<Action<TrayAction>> {
    let launchers = super::apps::launch_actions(tab);
    super::actions_of(tab)
        .into_iter()
        .filter(|action| {
            !launchers
                .iter()
                .any(|launch| launch.element == action.element)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{MenuRow, TrayView};

    /// **Between the diagnostics card and the launcher, every verb the model offers is drawn — each
    /// exactly once.**
    ///
    /// This is the single-source rule, made checkable, in the shape the merge requires
    /// (dig_ecosystem#2358). Home draws its verbs in two places now, so there are two ways to get
    /// it wrong and each has its own assertion: a row in NEITHER is a verb the tab claims to offer
    /// and does not, and a row in BOTH is two controls a person has to tell apart before pressing
    /// either. Checking only that the diagnostics card is a subset of the model would pass on both.
    ///
    /// Asserted against the REAL `window_model::build` output rather than a hand-written fixture,
    /// so a change to the Home tab upstream is reflected here without this test being edited.
    #[test]
    fn every_verb_is_drawn_once_across_the_diagnostics_card_and_the_launcher() {
        let view = TrayView {
            running: true,
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tab(crate::window_model::TabId::Home)
            .expect("the Home tab is always emitted");

        let diagnostics: Vec<TrayAction> = actions_of(tab).into_iter().map(|a| a.id).collect();
        let launched: Vec<TrayAction> = super::super::apps::launch_actions(tab)
            .into_iter()
            .map(|a| a.id)
            .collect();

        assert!(
            !diagnostics.is_empty() && !launched.is_empty(),
            "one of the two groups is empty, so this cannot see a row moving between them:              {diagnostics:?} / {launched:?}"
        );
        for action in &diagnostics {
            assert!(
                !launched.contains(action),
                "{action:?} is drawn by the diagnostics card AND by the launcher"
            );
        }

        let mut drawn: Vec<TrayAction> = diagnostics.into_iter().chain(launched).collect();
        let mut offered = tab.actions();
        drawn.sort_by_key(|a| format!("{a:?}"));
        offered.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(
            drawn, offered,
            "the pane's buttons are not the model's actions"
        );
    }

    /// **A disabled verb stays disabled, and a disabled row does not become the primary button.**
    ///
    /// Two actors: the fixture keeps one enabled action beside the disabled one, so a weighting that
    /// simply never produced a primary would be indistinguishable from one that respects the order.
    #[test]
    fn enablement_passes_through_untouched_and_never_promotes_a_disabled_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Home,
            label: "Home".to_string(),
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

    /// **Status summarises the cache; it does not redraw the Cache tab's meter.**
    ///
    /// dig_ecosystem#2357's first duplication: the same meter was drawn byte-identically on two
    /// tabs, so either could be changed without the other and one screen would eventually contradict
    /// the other about one number.
    ///
    /// The absence half is asserted with a snapshot PRESENT, which is the only state in which a
    /// meter could be drawn — with none there is nothing to draw either way, and a test run against
    /// that would pass on any implementation. The unknown case is asserted separately, because the
    /// summary must not become a zero when nobody has reported: `0 B of 0 B` is the claim that this
    /// computer has a cache and it is empty.
    #[test]
    fn the_cache_is_summarised_here_and_metered_only_on_its_own_tab() {
        let snapshot = crate::cache::CacheSnapshot {
            cap_bytes: 10 * crate::cache::GIB,
            used_bytes: 407 * crate::cache::MIB,
        };
        let reading = cache_reading(Some(snapshot));
        assert!(
            reading.is_known(),
            "a reported cache came back as an absence: {reading:?}"
        );
        let shown = reading.shown().to_string();
        for figure in [
            crate::cache::format_cap(snapshot.used_bytes),
            crate::cache::format_cap(snapshot.cap_bytes),
        ] {
            assert!(
                shown.contains(&figure),
                "the summary does not carry {figure}, so it is not reporting the same disk the \
                 Cache tab meters: {shown}"
            );
        }

        let unread = cache_reading(None);
        assert!(
            !unread.is_known(),
            "an unreported cache was drawn as a figure, which claims a cache that is empty"
        );
        assert!(
            !unread.shown().chars().any(|c| c.is_ascii_digit()),
            "the unreported sentence carries a numeral where a person reads a size: {}",
            unread.shown()
        );
    }

    /// **A separator never becomes a button.**
    #[test]
    fn a_separator_is_not_rendered_as_a_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Home,
            label: "Home".to_string(),
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
