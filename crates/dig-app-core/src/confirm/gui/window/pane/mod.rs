//! The content-pane design system: the vocabulary a tab's content is written in.
//!
//! # The problem this exists to solve
//!
//! Content panes used to render `Vec<MenuRow>` — the tray menu's own row type — whose entire
//! vocabulary is *separator, labelled action, submenu*. A pane could not look like an application
//! because it had no words for one, so every tab read as a menu inside a window
//! (dig_ecosystem#2326).
//!
//! # The line this system does not cross
//!
//! **The rules stay single-sourced; the presentation vocabulary gets richer.** Which verbs exist and
//! whether each is enabled is decided ONCE, by the group builders in [`crate::tray_menu`], composed
//! into tabs by [`crate::window_model`]. This layer may render a decided verb as a prominent primary
//! button with supporting copy where the tray renders it as a row. It may not decide for itself
//! whether that verb is offered.
//!
//! The check, when writing a pane: if you find yourself asking *"should this be shown?"*, the model
//! already answered — go read its answer. Facts a pane may display are projected into
//! [`facts::PaneFacts`], which deliberately holds no enablement to re-derive.
//!
//! # The vocabulary
//!
//! | Module | What it is for | When NOT to use it |
//! |---|---|---|
//! | [`flow`] | The vertical cursor blocks are placed through | Never place a block by computing a `y` yourself |
//! | [`text`] | Four prose roles: title, heading, body, caption | Anything that is a value — that is [`data`] |
//! | [`card`] | Grouping related facts under a title | A single self-describing thing; three levels of nesting |
//! | [`data`] | Readouts, measures, meters, badges | Prose; an unbounded count in a meter |
//! | [`action`] | Verbs, with primary/ghost/danger weight | Anything not decided by the model |
//! | [`state`] | The five pane states, banner-drawn | A success banner — success shows itself |
//! | [`identity`] | Values a person takes elsewhere: copy, QR | A value nobody transcribes |
//! | [`copy`] | Every string, named | A literal inside a paint call |
//! | [`facts`] | The readings a pane may display | Anything that decides a verb |
//!
//! # The scales
//!
//! Nothing here picks a pixel or a hex value. Spacing is `render::space` (hub's `--space-*`, a 4 px
//! rhythm), type is `render::size` (hub's `--text-*`), radii are `render::radius`, and every colour
//! comes from [`super::super::theme::Tokens`], which is the hub design system ported once.
//!
//! **[`Tokens`](super::super::theme::Tokens) is EXTENDED, not superseded.** It is a field-by-field
//! mirror of `hub.dig.net`'s CSS custom properties, kept that way so the two copies can be diffed by
//! eye — a pane-specific palette would break that and give the product two looks. What this layer
//! adds on top is *roles*: [`data::Tone`] asks for a meaning ("bad") rather than a colour ("amber"),
//! so the meaning-to-token mapping lives in one place instead of at every call site.
//!
//! # Honesty
//!
//! A skeleton must never imply a fact it does not have. Two mechanisms enforce it rather than a
//! review checklist: [`data::Value`] has no variant that can hold a plausible-looking placeholder —
//! an absent figure is [`data::Value::Unknown`] carrying the sentence saying why — and
//! [`state::PaneState::Unwired`] is a state every pane must handle, so a designed-but-unplumbed
//! surface says so in the pane, in plain words.

pub(crate) mod action;
pub(crate) mod card;
pub(crate) mod copy;
pub(crate) mod data;
pub(crate) mod facts;
pub(crate) mod flow;
pub(crate) mod identity;
pub(crate) mod state;
pub(crate) mod status;
pub(crate) mod text;

use egui::{Rect, Ui};

use super::super::render::space;
use super::super::theme::Tokens;
use crate::tray_menu::{MenuRow, TrayAction};
use crate::window_model::{Tab, TabId};
use facts::PaneFacts;
use flow::Flow;
use state::PaneState;

/// A row's element id: its label, plus which occurrence of that label this is on the tab.
///
/// # Why the label, and not the action or the position
///
/// Not the ACTION, because several actions render two rows each (dig_ecosystem#2257) — an action
/// alone cannot address one row. Not the pixel POSITION, for the reason dig_ecosystem#2074 records:
/// this pane rebuilds every frame and rows above it change height as text rewraps, so a `y` in the
/// id would be a generated id wearing a stable name, replaced under a user mid-click.
///
/// The count of PRECEDING rows with the same label is stable for a given model — it is a position in
/// a list, not a position on screen — which is what separates the Account tab's two
/// `About on-chain DIDs…` rows without reintroducing that hazard.
pub(crate) fn row_element_id(label: &str, occurrence: usize) -> egui::Id {
    egui::Id::new(("dig-window-row", label, occurrence))
}

/// Draw a tab's content into `at`, and report the verb pressed.
///
/// Status has a bespoke pane; every other tab renders through the generic one, which is itself
/// written in this vocabulary — so a tab that has not been designed yet still looks like the rest of
/// the application rather than like a menu.
pub(crate) fn draw_tab(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
    live: bool,
) -> (f32, Option<TrayAction>) {
    let mut flow = Flow::new(ui, at, live);

    flow.place(|ui, at| (text::title(ui, at, t, &tab.label), ()));
    flow.gap(space::S4);

    let state = PaneState::of_note(&tab.note);
    if !state.is_silent() {
        flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
        flow.gap(space::S4);
    }

    let pressed = match tab.id {
        TabId::Status => status::draw(&mut flow, t, tab, facts),
        _ => generic(&mut flow, t, tab),
    };
    (flow.cursor() - at.top(), pressed)
}

/// Every tab that has not been individually designed yet: one card per section, its heading as the
/// card's title, and its rows as a weighted button group.
///
/// This is a floor, not a target. Phase 2 replaces each of these with a pane written for its own
/// content — but until then a tab renders as cards of grouped verbs rather than as a list of rows,
/// which is the difference between an application and a menu.
fn generic(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let mut pressed = None;
    let mut drew_anything = false;

    // Counted across the WHOLE tab, not per section: the Account tab's two `About on-chain DIDs…`
    // rows sit in different sections, and a per-section count would give both occurrence zero.
    let mut seen = std::collections::HashMap::<String, usize>::new();

    for section in &tab.sections {
        let actions = actions_in(section.rows.iter().cloned(), &mut seen, &never_destructive);
        if actions.is_empty() && section.heading.is_none() {
            continue;
        }
        drew_anything = true;
        let live = flow.live();
        let title = section.heading.clone();
        let hit = flow
            .place(|ui, at| {
                let (height, hit) =
                    card::interactive_card(ui, at, t, live, title.as_deref(), |inner| {
                        inner
                            .place(|ui, at| action::buttons(ui, at, t, live, &actions))
                            .flatten()
                    });
                (height, hit.flatten())
            })
            .flatten();
        pressed = pressed.or(hit);
        flow.gap(space::S4);
    }

    if !drew_anything {
        // Never a blank region: an empty list rendering as void is a bug, and on a window whose tabs
        // come and go with the account's state it is a bug a person will hit.
        flow.place(|ui, at| (state::nothing_here(ui, at, t), ()));
    }
    pressed
}

/// The verbs in a run of rows, as weighted actions, in the model's order.
///
/// # Why `seen` is a parameter and not a local
///
/// The occurrence count that makes an element id unique must be counted across the WHOLE TAB, not
/// per section: the Account tab's two `About on-chain DIDs…` rows sit in different sections, and a
/// per-section counter gives both occurrence zero — which egui reports as a duplicate id and which
/// leaves one of the two rows unclickable. So the caller owns the counter and threads it through
/// every section of one tab.
///
/// # Why this is the only place a pane derives a row's identity
///
/// It was not, briefly, and that cost a working control: the Status pane grew its own copy that
/// used the row's INDEX where this uses its occurrence, so `Open the log folder` — the second verb
/// on the tab, and the first with that label — was addressed as occurrence 1 while every other
/// caller looked for occurrence 0. Two derivations of one identity is a bug with a delay on it.
pub(crate) fn actions_in(
    rows: impl IntoIterator<Item = MenuRow>,
    seen: &mut std::collections::HashMap<String, usize>,
    destructive: &dyn Fn(TrayAction) -> bool,
) -> Vec<action::Action<TrayAction>> {
    rows.into_iter()
        .filter_map(|row| match row {
            MenuRow::Action {
                action,
                label,
                enabled,
            } => Some((action, label, enabled)),
            // A tab is already the nesting a submenu provided, and `window_model` never emits one.
            // Separators divide a LIST; a group of buttons is not one.
            MenuRow::Separator | MenuRow::Submenu { .. } => None,
        })
        .enumerate()
        .map(|(index, (act, label, enabled))| {
            let occurrence = seen.entry(label.clone()).or_insert(0);
            let element = row_element_id(&label, *occurrence);
            *occurrence += 1;
            action::Action {
                weight: action::weigh(index, enabled, destructive(act)),
                element,
                label,
                enabled,
                id: act,
            }
        })
        .collect()
}

/// Nothing in the generic pane is destructive-by-position: a section it renders may hold a destroy,
/// and [`status`] is the pane that knows which verbs those are. Passed explicitly so the generic
/// pane's lack of danger colouring is a stated choice rather than a forgotten one.
fn never_destructive(_: TrayAction) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Two rows with the same label on one tab get different element ids.**
    ///
    /// The gallery disproved the label-alone version on its first screenshot: the Account tab draws
    /// `About on-chain DIDs…` twice, from two different sections, and egui painted its duplicate-id
    /// warning across the pane. The occurrence count is what separates them, and it must be counted
    /// across the whole TAB — so the fixture puts the duplicates in two sections, which is where a
    /// per-section counter gives both occurrence zero and the bug returns.
    #[test]
    fn a_label_repeated_across_two_sections_still_gets_two_ids() {
        let repeated = "About on-chain DIDs…";
        let section = |label: &str| crate::window_model::Section {
            heading: None,
            rows: vec![MenuRow::Action {
                action: TrayAction::OpenLogs,
                label: label.to_string(),
                enabled: true,
            }],
        };
        let mut seen = std::collections::HashMap::new();
        let first = actions_in(section(repeated).rows, &mut seen, &never_destructive);
        let second = actions_in(section(repeated).rows, &mut seen, &never_destructive);

        assert_ne!(
            first[0].element, second[0].element,
            "the same label in two sections produced one id, which egui reports as a duplicate and \
             which makes one of the two rows unclickable"
        );
        assert_eq!(first[0].element, row_element_id(repeated, 0));
        assert_eq!(second[0].element, row_element_id(repeated, 1));
    }

    /// An id is derived from the label and occurrence only — never from a position on screen.
    #[test]
    fn a_row_id_does_not_depend_on_where_the_row_was_drawn() {
        assert_eq!(row_element_id("Unlock…", 0), row_element_id("Unlock…", 0));
        assert_ne!(row_element_id("Unlock…", 0), row_element_id("Unlock…", 1));
        assert_ne!(row_element_id("Unlock…", 0), row_element_id("Lock now", 0));
    }
}
