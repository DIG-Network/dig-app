//! The app window's body: a sidebar of tabs on the left, the selected tab's content on the right.
//!
//! # Why this is a function of the model and not a widget tree
//!
//! Everything about WHAT is shown — which tabs exist, which rows they hold, which rows are disabled
//! and what their labels say — is decided by [`crate::window_model`] and tested there. This module
//! decides only where the pixels go, and it reports what was clicked rather than acting on it. The
//! shell turns a [`Click`] into a dispatch on the worker; nothing here can run a verb, which is the
//! structural half of the rule that a window row must never call the blocking `ask` inline.
//!
//! # Narrow mode
//!
//! Below [`NARROW_AT`] the sidebar becomes a strip of tab chips across the top. A 208 px column out
//! of a 480 px window leaves 272 px of content, which is not a content pane, it is a margin — and the
//! window can legitimately be dragged that small ([`super::shell::SHELL_MIN`]).

use std::collections::HashMap;

use egui::{Rect, Sense, Ui, Vec2};

use super::super::paint;
use super::super::render::{radius, regular, rgba, semibold, size, space};
use super::super::theme::Tokens;
use crate::tray_menu::{MenuRow, TrayAction};
use crate::window_model::{tab_element_id, PaneNote, Section, Tab, TabId, WindowModel};

/// How wide the sidebar is when there is room for one.
const SIDEBAR_WIDTH: f32 = 208.0;
/// Below this window width the sidebar becomes a strip of chips across the top.
///
/// Chosen from the layout rather than by taste: the sidebar plus two content gutters plus a readable
/// content column is about this wide, and under it the content column is the thing that loses.
const NARROW_AT: f32 = 760.0;
/// The height of the tab strip in narrow mode.
const STRIP_HEIGHT: f32 = 44.0;
/// The smallest a row may be. A row with a wrapped label grows past it.
const ROW_HEIGHT: f32 = 38.0;
/// A sidebar entry's height.
const TAB_HEIGHT: f32 = 36.0;
/// The gap between a heading and the rows beneath it.
const HEADING_GAP: f32 = 6.0;

/// What the person clicked, for the shell to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Click {
    /// A sidebar entry: show this tab.
    Tab(TabId),
    /// A content row: run this verb, on the worker.
    Act(TrayAction),
}

/// Draw the sidebar and the selected tab into `body`, and report what was clicked.
///
/// `live` is false while a prompt is up. Everything is still DRAWN then — a window that emptied
/// itself behind a prompt would read as broken rather than busy — but nothing senses a click and no
/// control shows a pointing hand, so the scrim's "you cannot use this right now" is not contradicted
/// by the cursor.
pub(super) fn draw(
    ui: &mut Ui,
    body: Rect,
    t: &Tokens,
    model: &WindowModel,
    selected: TabId,
    live: bool,
) -> Option<Click> {
    if model.tabs.is_empty() {
        // Unreachable from `window_model::build`, which always emits at least the Status tab, and
        // handled anyway: an empty window that painted nothing would be a blank rectangle with no
        // explanation, which is the one thing a window must never be.
        return no_tabs(ui, body, t);
    }

    let narrow = body.width() < NARROW_AT;
    let (nav, content) = split(body, narrow);
    let clicked = match narrow {
        true => strip(ui, nav, t, model, selected, live),
        false => sidebar(ui, nav, t, model, selected, live),
    };
    let tab = model.tab(selected).or_else(|| model.tabs.first());
    let in_content = tab.and_then(|tab| pane(ui, content, t, tab, live));
    clicked.or(in_content)
}

/// Where the navigation goes and where the content goes.
fn split(body: Rect, narrow: bool) -> (Rect, Rect) {
    match narrow {
        true => (
            Rect::from_min_size(body.left_top(), Vec2::new(body.width(), STRIP_HEIGHT)),
            Rect::from_min_max(
                egui::Pos2::new(body.left(), body.top() + STRIP_HEIGHT),
                body.right_bottom(),
            ),
        ),
        false => (
            Rect::from_min_size(body.left_top(), Vec2::new(SIDEBAR_WIDTH, body.height())),
            Rect::from_min_max(
                egui::Pos2::new(body.left() + SIDEBAR_WIDTH, body.top()),
                body.right_bottom(),
            ),
        ),
    }
}

/// The vertical sidebar.
fn sidebar(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    model: &WindowModel,
    selected: TabId,
    live: bool,
) -> Option<Click> {
    ui.painter().rect_filled(at, 0, rgba(t.surface));
    ui.painter().vline(
        at.right(),
        at.top()..=at.bottom(),
        egui::Stroke::new(1.0, rgba(t.border)),
    );

    let mut clicked = None;
    let mut y = at.top() + space::S3;
    for tab in &model.tabs {
        let entry = Rect::from_min_size(
            egui::Pos2::new(at.left() + space::S2, y),
            Vec2::new(at.width() - space::S2 * 2.0, TAB_HEIGHT),
        );
        if tab_entry(ui, entry, t, tab, tab.id == selected, live) {
            clicked = Some(Click::Tab(tab.id));
        }
        y += TAB_HEIGHT + 2.0;
    }
    clicked
}

/// The horizontal tab strip used when the window is too narrow for a sidebar.
fn strip(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    model: &WindowModel,
    selected: TabId,
    live: bool,
) -> Option<Click> {
    ui.painter().rect_filled(at, 0, rgba(t.surface));
    paint::rule(ui, at, at.bottom(), t);

    let mut clicked = None;
    let mut x = at.left() + space::S2;
    for tab in &model.tabs {
        let width = chip_width(ui, &tab.label);
        let entry = Rect::from_min_size(
            egui::Pos2::new(x, at.top() + (at.height() - TAB_HEIGHT) / 2.0),
            Vec2::new(width, TAB_HEIGHT),
        );
        // A chip that would run off the edge is not drawn rather than drawn half off it. The tabs
        // that fit still work, and the alternative — a control clipped mid-word — looks like damage.
        if entry.right() > at.right() - space::S2 {
            break;
        }
        if tab_entry(ui, entry, t, tab, tab.id == selected, live) {
            clicked = Some(Click::Tab(tab.id));
        }
        x += width + space::S2 / 2.0;
    }
    clicked
}

/// How wide a narrow-mode chip needs to be for its label.
fn chip_width(ui: &Ui, label: &str) -> f32 {
    let galley =
        ui.painter()
            .layout_no_wrap(label.to_owned(), semibold(size::SM), egui::Color32::WHITE);
    galley.size().x + space::S4
}

/// One navigation entry, in either orientation. Returns whether it was clicked.
fn tab_entry(ui: &mut Ui, at: Rect, t: &Tokens, tab: &Tab, current: bool, live: bool) -> bool {
    let response = ui.interact(at, egui::Id::new(tab_element_id(tab.id)), sense(live));
    let hovered = live && response.hovered();

    if current {
        // The selected entry is filled with the accent wash rather than merely bolded: a person
        // returning to the window after a while must be able to see which tab they are on without
        // comparing two weights of the same word.
        ui.painter()
            .rect_filled(at, radius::BASE, rgba(t.dig_wash.over(t.surface)));
    } else if hovered {
        ui.painter()
            .rect_filled(at, radius::BASE, rgba(t.surface_2));
    }

    let colour = match current {
        true => t.text,
        false => t.muted,
    };
    let font = match current {
        true => semibold(size::SM),
        false => regular(size::SM),
    };
    ui.painter().text(
        egui::Pos2::new(at.left() + space::S3, at.center().y),
        egui::Align2::LEFT_CENTER,
        &tab.label,
        font,
        rgba(colour),
    );
    response.clicked()
}

/// The selected tab's content: its note, then its sections.
fn pane(ui: &mut Ui, at: Rect, t: &Tokens, tab: &Tab, live: bool) -> Option<Click> {
    let inner = Rect::from_min_max(
        at.left_top() + Vec2::splat(space::S5),
        at.right_bottom() - Vec2::splat(space::S5),
    );
    if inner.width() <= 0.0 || inner.height() <= 0.0 {
        return None;
    }

    let mut clicked = None;
    let mut y = inner.top();
    // Counted across the WHOLE tab, not per section: the Account tab's two `About on-chain DIDs…`
    // rows sit in different sections, and a per-section count would give both occurrence zero.
    let mut seen: HashMap<String, usize> = HashMap::new();

    ui.painter().text(
        egui::Pos2::new(inner.left(), y),
        egui::Align2::LEFT_TOP,
        &tab.label,
        semibold(size::HEADING),
        rgba(t.text),
    );
    y += size::HEADING + space::S4;

    if let Some(height) = note(ui, inner, y, t, &tab.note) {
        y += height + space::S4;
    }

    for section in &tab.sections {
        let (height, hit) = draw_section(ui, inner, y, t, section, live, &mut seen);
        clicked = clicked.or(hit);
        y += height + space::S4;
        // Everything below the fold is not drawn. The window is resizable and the sections are
        // short, so this is a clamp rather than a scroll — and a half-drawn row hanging off the
        // bottom edge would be a control nobody can tell is unreachable.
        if y >= inner.bottom() {
            break;
        }
    }
    clicked
}

/// The pane's four-state note, or `None` when the tab is ready and has nothing to say.
///
/// Returns the height it drew, so the sections below start beneath it.
fn note(ui: &mut Ui, inner: Rect, y: f32, t: &Tokens, note: &PaneNote) -> Option<f32> {
    let (text, problem) = match note {
        PaneNote::Ready => return None,
        PaneNote::Waiting(text) => (*text, false),
        PaneNote::Empty(text) => (*text, false),
        // Only the state that means something is WRONG gets the amber treatment. Painting a
        // still-loading pane in warning colours teaches people to ignore the warning colour.
        PaneNote::Unreachable(text) => (*text, true),
    };

    let galley = ui.painter().layout(
        text.to_owned(),
        regular(size::SM),
        rgba(match problem {
            true => t.amber,
            false => t.muted,
        }),
        inner.width() - space::S4 * 2.0,
    );
    let height = galley.size().y + space::S3 * 2.0;
    let at = Rect::from_min_size(
        egui::Pos2::new(inner.left(), y),
        Vec2::new(inner.width(), height),
    );
    match problem {
        true => paint::warning_panel(ui, at, t),
        false => paint::panel(ui, at, t),
    }
    ui.painter().galley(
        at.left_top() + Vec2::new(space::S4, space::S3),
        galley,
        egui::Color32::PLACEHOLDER,
    );
    Some(height)
}

/// One section: its heading, then its rows. Returns the height drawn and anything clicked.
fn draw_section(
    ui: &mut Ui,
    inner: Rect,
    top: f32,
    t: &Tokens,
    section: &Section,
    live: bool,
    seen: &mut HashMap<String, usize>,
) -> (f32, Option<Click>) {
    let mut y = top;
    if let Some(heading) = &section.heading {
        // Wrapped, not truncated: a heading is the Wallet tab's balance sentence and the Cache tab's
        // usage reading, and half of either is worse than none.
        let galley = ui.painter().layout(
            heading.clone(),
            semibold(size::SM),
            rgba(t.muted),
            inner.width(),
        );
        let height = galley.size().y;
        ui.painter().galley(
            egui::Pos2::new(inner.left(), y),
            galley,
            egui::Color32::PLACEHOLDER,
        );
        y += height + HEADING_GAP;
    }

    let mut clicked = None;
    for row in &section.rows {
        match row {
            MenuRow::Separator => {
                paint::rule(ui, inner, y + space::S2, t);
                y += space::S3;
            }
            MenuRow::Action {
                action,
                label,
                enabled,
            } => {
                let occurrence = seen.entry(label.clone()).or_insert(0);
                let at = *occurrence;
                *occurrence += 1;
                let (height, hit) = action_row(ui, inner, y, t, label, at, *enabled, live);
                if hit {
                    clicked = Some(Click::Act(*action));
                }
                y += height + 2.0;
            }
            // A tab is already the nesting a submenu provided, and `window_model` never emits one —
            // pinned by `a_window_section_never_holds_a_submenu`. Drawing nothing keeps that true
            // here rather than inventing a rendering for a case the model forbids.
            MenuRow::Submenu { .. } => {}
        }
    }
    (y - top, clicked)
}

/// A row's element id: its label, plus which occurrence of that label this is on the tab.
///
/// # Why the label, and not the action or the position
///
/// Not the ACTION, because eight actions render two rows each (dig_ecosystem#2257) — an action alone
/// cannot address one row. Not the pixel POSITION, for the reason dig_ecosystem#2074 records: a
/// rebuilt surface must name its controls exactly as the previous one did, and this pane rebuilds
/// every frame while rows above can change height as text rewraps, so a `y` in the id would be a
/// generated id wearing a stable name.
///
/// # Why `occurrence` exists
///
/// An earlier version used the label alone, on the reasoning that no tab repeats one. **The gallery
/// disproved it on the first screenshot:** the Account tab draws `About on-chain DIDs…` twice, once
/// from `view_account_actions` and once from `management_actions`, and egui painted its duplicate-id
/// warning across the pane. No headless test caught it, because none of them looked for an id clash.
/// The count of PRECEDING rows with the same label is stable for a given model — it is a position in
/// a list, not a position on screen — so it separates the two without reintroducing the #2074 hazard.
pub(super) fn row_id(label: &str, occurrence: usize) -> egui::Id {
    egui::Id::new(("dig-window-row", label, occurrence))
}

/// Paint one row and return the height it took and whether it was clicked.
///
/// One `interact` call, not two: a hover test and a click test over the same rectangle would be two
/// controls stacked on one another, and only the topmost would see the pointer.
#[allow(clippy::too_many_arguments)]
fn action_row(
    ui: &mut Ui,
    inner: Rect,
    y: f32,
    t: &Tokens,
    label: &str,
    occurrence: usize,
    enabled: bool,
    live: bool,
) -> (f32, bool) {
    // A disabled row is DIMMER, never hidden and never re-worded here: its label already carries the
    // remedy (`window_model::label_names_a_remedy`), and a row that vanished when it could not be
    // used would take that explanation with it.
    let colour = match enabled {
        true => t.text,
        false => t.faint,
    };
    let galley = ui.painter().layout(
        label.to_owned(),
        regular(size::BASE),
        rgba(colour),
        inner.width() - space::S4 * 2.0,
    );
    let height = (galley.size().y + space::S3).max(ROW_HEIGHT);
    let at = Rect::from_min_size(
        egui::Pos2::new(inner.left(), y),
        Vec2::new(inner.width(), height),
    );

    // A disabled row still SENSES hover, so it can carry a tooltip later, but it never senses a
    // click — the row is not clickable, rather than clickable-and-ignored.
    let clickable = enabled && live;
    let response = ui.interact(
        at,
        row_id(label, occurrence),
        match clickable {
            true => Sense::click(),
            false => Sense::hover(),
        },
    );
    if clickable && response.hovered() {
        ui.painter()
            .rect_filled(at, radius::BASE, rgba(t.surface_2));
    }
    ui.painter().galley(
        egui::Pos2::new(at.left() + space::S3, at.center().y - galley.size().y / 2.0),
        galley,
        egui::Color32::PLACEHOLDER,
    );
    (height, response.clicked())
}

/// Nothing to show at all — drawn rather than left blank, and never silently.
fn no_tabs(ui: &mut Ui, body: Rect, t: &Tokens) -> Option<Click> {
    ui.painter().text(
        body.left_top() + Vec2::splat(space::S6),
        egui::Align2::LEFT_TOP,
        NO_TABS,
        regular(size::BASE),
        rgba(t.muted),
    );
    None
}

/// What an empty window says. A complete sentence naming the way out, like every other dead end here.
pub(super) const NO_TABS: &str =
    "This window has nothing to show yet. Open the log folder from the tray to find out why.";

/// What a control senses right now.
///
/// While a prompt is up everything falls back to `hover`, which is what keeps the pointer an arrow
/// over the scrimmed surface: a pointing hand says *clickable* louder than any amount of dimming
/// says *inert*.
fn sense(live: bool) -> Sense {
    match live {
        true => Sense::click(),
        false => Sense::hover(),
    }
}
